using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ArcanaGuardian;

/// <summary>
/// <c>using-secrets --self-check</c>: the check the release pipeline runs on the PUBLISHED program. It starts the host service in this process over a throwaway folder, software keys and a free loopback
/// port (it touches no user application state or trust store), asks it over HTTPS for the administration web application and the API, and prints one JSON line: the backend version
/// (<c>/api/v1/status</c>), the frontend version (the <c>version.json</c> embedded with the page), the embedded files, and whether the page, its script and stylesheet and the API answer from the one origin.
/// Exit code 0 only when everything is consistent.
/// </summary>
public static class SelfCheck
{
    public static async Task<int> RunAsync(TextWriter output)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-self-check-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(folder);
        List<string> problems = [];
        string backend = "";
        string? frontend = null;
        string apiVersion = "";
        AdminWebAssets embedded = AdminWebAssets.FromAssembly();
        int origin = 0;
        BrowserCertificates certificates = new(folder);
        try
        {
            certificates.Run("prepare", false, null, null, TextWriter.Null);
            using X509Certificate2 browserKey = certificates.OpenPreparedForTest();
            using X509Certificate2 publicLeaf = X509CertificateLoader.LoadCertificate(browserKey.RawData);
            using SoftwareSigningKey machineKey = new();
            Dictionary<int, SoftwareSigningKey> authorityKeys = [];
            LocalDeployment deployment = LocalDeployment.Create(folder, machineKey, generation =>
            {
                if (!authorityKeys.TryGetValue(generation, out SoftwareSigningKey? key))
                {
                    authorityKeys[generation] = key = new SoftwareSigningKey();
                }

                return key;
            }, "self-check");
            StateDatabase state = StateDatabase.InFolder(folder);
            using HostService service = HostService.Start(new HostServiceOptions { State = state, Store = new SecretStore(state), Deployment = deployment, Port = 0, BrowserCertificateFixture = browserKey });
            origin = service.Port;
            using HttpClient http = BrowserProbe(publicLeaf, service.Port);

            using (JsonDocument status = JsonDocument.Parse(await http.GetStringAsync("/api/v1/status")))
            {
                backend = status.RootElement.GetProperty("version").GetString() ?? "";
                apiVersion = status.RootElement.GetProperty("apiVersion").GetString() ?? "";
            }

            using (HttpResponseMessage page = await http.GetAsync("/admin/"))
            {
                string html = await page.Content.ReadAsStringAsync();
                if (!page.IsSuccessStatusCode || page.Content.Headers.ContentType?.MediaType != "text/html" || !html.Contains("id=\"root\"", StringComparison.Ordinal))
                {
                    problems.Add("/admin/ is not the web application page (" + (int)page.StatusCode + ")");
                }

                if (!page.Headers.TryGetValues("Content-Security-Policy", out IEnumerable<string>? csp) || csp.Single() != AdminWebAssets.ContentSecurityPolicy)
                {
                    problems.Add("the page has no strict Content-Security-Policy");
                }

                MatchCollection references = Regex.Matches(html, "(?:src|href)=\"(/admin/[^\"]+)\"");
                if (references.Count < 2)
                {
                    problems.Add("the page names fewer than a script and a stylesheet");
                }

                foreach (Match reference in references)
                {
                    using HttpResponseMessage file = await http.GetAsync(reference.Groups[1].Value);
                    if (!file.IsSuccessStatusCode || (file.Content.Headers.ContentLength ?? 0) == 0)
                    {
                        problems.Add("the embedded file " + reference.Groups[1].Value + " is not served (" + (int)file.StatusCode + ")");
                    }
                }
            }

            using (HttpResponseMessage versionFile = await http.GetAsync("/admin/version.json"))
            {
                if (versionFile.IsSuccessStatusCode)
                {
                    using JsonDocument document = JsonDocument.Parse(await versionFile.Content.ReadAsStringAsync());
                    frontend = document.RootElement.GetProperty("version").GetString();
                }
                else
                {
                    problems.Add("the frontend carries no version.json");
                }
            }

            if (frontend != backend)
            {
                problems.Add($"the frontend version ({frontend}) is not the backend version ({backend})");
            }

            using (HttpResponseMessage missing = await http.GetAsync("/admin/assets/does-not-exist.js"))
            {
                if ((int)missing.StatusCode != 404 || (await missing.Content.ReadAsStringAsync()).Length != 0)
                {
                    problems.Add("a missing asset is not a plain 404");
                }
            }

            using (HttpResponseMessage unknown = await http.GetAsync("/api/v1/does-not-exist"))
            {
                if ((int)unknown.StatusCode != 404 || unknown.Content.Headers.ContentType?.MediaType != "application/problem+json")
                {
                    problems.Add("an unknown API path is not a JSON 404 (it must never fall through to the page)");
                }
            }

            using (HttpResponseMessage contract = await http.GetAsync("/api/v1/openapi.json"))
            {
                if (!contract.IsSuccessStatusCode)
                {
                    problems.Add("the OpenAPI document is not served");
                }
            }
        }
        catch (Exception error) when (error is HttpRequestException or TaskCanceledException or JsonException or KeyNotFoundException or IOException)
        {
            problems.Add("the check could not complete: " + error.GetType().Name);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try
            {
                certificates.Run("remove", false, null, null, TextWriter.Null);
                Directory.Delete(folder, true);
            }
            catch (IOException)
            {
                // A stray temp folder is harmless.
            }
        }

        if (!embedded.Available)
        {
            problems.Add("no administration web application is embedded in this program");
        }

        string[] files = [.. embedded.Paths.Order(StringComparer.Ordinal)];
        await output.WriteLineAsync(JsonSerializer.Serialize(new
        {
            ok = problems.Count == 0,
            backendVersion = backend,
            apiVersion,
            frontendVersion = frontend,
            embeddedFileCount = files.Length,
            embeddedFiles = files,
            oneOrigin = origin != 0,
            problems,
        }));

        return problems.Count == 0 ? 0 : 1;
    }

    internal static HttpClient BrowserProbe(X509Certificate2 publicLeaf, int port)
    {
        var chain = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
        };
        chain.CustomTrustStore.Add(publicLeaf);
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            SslOptions = new() { CertificateChainPolicy = chain },
            ConnectCallback = async (_, stop) =>
            {
                var client = new TcpClient();
                try
                {
                    await client.ConnectAsync(IPAddress.Loopback, port, stop);
                    return client.GetStream();
                }
                catch
                {
                    client.Dispose();
                    throw;
                }
            },
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30), BaseAddress = new Uri(BrowserAddress.Origin(port)) };
    }
}
