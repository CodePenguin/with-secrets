using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace LocalHttpsLeaf;

internal static partial class BrowserTests
{
    private static readonly string LeafUrl = $"https://{SpikeCertificates.Host}:{SpikeCertificates.LeafPort}/";
    private static readonly string ReissuedUrl = $"https://{SpikeCertificates.Host}:{SpikeCertificates.ReissuedPort}/";
    private static readonly string LocalhostUrl = $"http://localhost:{SpikeCertificates.HttpPort}/";
    private static readonly StoreName[] Stores = [StoreName.TrustedPeople, StoreName.Root];

    [SupportedOSPlatform("windows")]
    public static async Task RunWindowsAsync(
        X509Certificate2 leaf, X509Certificate2? child, X509Certificate2? reissued, string[] requested, CancellationToken stop)
    {
        string[] storeOptions = requested.Where(arg => arg.StartsWith("--store=", StringComparison.Ordinal)).ToArray();
        StoreName[] selectedStores = storeOptions switch
        {
            [] => Stores,
            ["--store=TrustedPeople"] => [StoreName.TrustedPeople],
            ["--store=Root"] => [StoreName.Root],
            _ => throw new ArgumentException("Choose --store=TrustedPeople or --store=Root, or omit to test both."),
        };
        bool replaceTrust = requested.Contains("--replace-trust", StringComparer.Ordinal);
        if (replaceTrust && (reissued is null || !selectedStores.Contains(StoreName.Root)))
        {
            throw new ArgumentException("--replace-trust requires a local Windows server and a CurrentUser Root phase.");
        }

        string[] channels = requested.Except(storeOptions).Where(arg => arg != "--replace-trust").ToArray();
        if (channels.Any(channel => channel is not ("msedge" or "chrome" or "firefox")))
        {
            throw new ArgumentException("Browser channels are msedge, chrome and firefox.");
        }

        Console.WriteLine(RuntimeInformation.OSDescription + "; " + RuntimeInformation.FrameworkDescription);
        if (channels.Length == 0)
        {
            channels = ["msedge", "chrome", "firefox"];
        }

        using var playwright = await Playwright.CreateAsync();
        VerifyAbsent(leaf);
        var rootVerifiedChannels = new List<string>();
        foreach (var storeName in selectedStores)
        {
            stop.ThrowIfCancellationRequested();
            var sessions = new Dictionary<string, IBrowser>();
            var sessionsAfterInstall = new Dictionary<string, IBrowser>();
            try
            {
                foreach (string channel in channels.Distinct())
                {
                    try
                    {
                        var browser = await LaunchAsync(playwright, channel);
                        sessions.Add(channel, browser);
                        Console.WriteLine($"{channel} {browser.Version}");
                        await ProbeAsync(browser, channel, storeName, "Before trust", LeafUrl, accept: false);
                        if (replaceTrust && storeName == StoreName.Root)
                        {
                            await ProbeAsync(browser, channel, storeName, "Reissued leaf before trust", ReissuedUrl, accept: false);
                        }

                        if (storeName == selectedStores[0])
                        {
                            await RunCeremonyAsync(browser, channel, "HTTP localhost control", LocalhostUrl);
                        }
                    }
                    catch (PlaywrightException error)
                    {
                        Report(channel, storeName.ToString(), "Browser setup", "BLOCKED", error.Message);
                    }
                }

                if (sessions.Count == 0)
                {
                    continue;
                }

                stop.ThrowIfCancellationRequested();
                using var store = new X509Store(storeName, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                try
                {
                    Console.WriteLine($"Adding public-only certificate {leaf.Thumbprint} to CurrentUser/{storeName}.");
                    try
                    {
                        store.Add(leaf);
                    }
                    catch (CryptographicException error)
                    {
                        Report("Windows", storeName.ToString(), "Install trust", "BLOCKED", error.Message);
                        continue;
                    }

                    if (!Contains(store, leaf))
                    {
                        Report("Windows", storeName.ToString(), "Install trust", "BLOCKED", "Certificate absent after Add.");
                        continue;
                    }

                    Report("Windows", storeName.ToString(), "Install trust", "PASS", $"Exact DER found in CurrentUser/{storeName}.");
                    CheckWindowsChain(leaf, "leaf");
                    if (child is not null)
                    {
                        CheckWindowsChain(child, "child");
                    }
                    foreach (var (channel, warm) in sessions)
                    {
                        stop.ThrowIfCancellationRequested();
                        await ProbeAsync(warm, channel, storeName, "After install (same browser process)", LeafUrl, accept: true);
                        try
                        {
                            var cold = await LaunchAsync(playwright, channel);
                            sessionsAfterInstall.Add(channel, cold);
                            await using var context = await cold.NewContextAsync();
                            if (await RunTrustedAsync(context, channel, storeName.ToString()) && storeName == StoreName.Root)
                            {
                                rootVerifiedChannels.Add(channel);
                            }
                        }
                        catch (PlaywrightException error)
                        {
                            Report(channel, storeName.ToString(), "Fresh browser", "BLOCKED", error.Message);
                        }
                    }
                }
                finally
                {
                    if (Contains(store, leaf))
                    {
                        Console.WriteLine($"Removing exact certificate {leaf.Thumbprint} from CurrentUser/{storeName}.");
                        store.Remove(leaf);
                    }
                }

                VerifyAbsent(leaf);
                foreach (var (channel, warm) in sessions)
                {
                    var sameProcess = sessionsAfterInstall.GetValueOrDefault(channel, warm);
                    await ProbeAsync(sameProcess, channel, storeName, "After removal (browser used after installation)", LeafUrl, accept: false);
                    try
                    {
                        await using var cold = await LaunchAsync(playwright, channel);
                        await ProbeAsync(cold, channel, storeName, "After removal (fresh browser)", LeafUrl, accept: false);
                    }
                    catch (PlaywrightException error)
                    {
                        Report(channel, storeName.ToString(), "Fresh browser after removal", "BLOCKED", error.Message);
                    }
                }
            }
            finally
            {
                // Verify cleanup even if a browser operation or Add failed.
                try
                {
                    VerifyAbsent(leaf);
                }
                finally
                {
                    foreach (var browser in sessions.Values.Concat(sessionsAfterInstall.Values))
                    {
                        await browser.DisposeAsync();
                    }
                }
            }
        }

        if (replaceTrust && reissued is not null)
        {
            if (rootVerifiedChannels.Count == 0)
            {
                Report("Windows", "Root replacement", "Install replacement", "BLOCKED", "No working original Root trust baseline.");
                return;
            }

            using var publicReissue = X509CertificateLoader.LoadCertificate(reissued.RawData);
            await RunReplacementAsync(playwright, leaf, publicReissue, rootVerifiedChannels, stop);
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task RunReplacementAsync(IPlaywright playwright, X509Certificate2 original,
        X509Certificate2 reissued, IEnumerable<string> channels, CancellationToken stop)
    {
        const string stage = "Root replacement";
        VerifyAbsent(original);
        VerifyAbsent(reissued);
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        try
        {
            stop.ThrowIfCancellationRequested();
            Console.WriteLine($"Adding reissued public-only certificate {reissued.Thumbprint} to CurrentUser/Root.");
            try
            {
                store.Add(reissued);
            }
            catch (CryptographicException error)
            {
                Report("Windows", stage, "Install replacement", "BLOCKED", error.Message);
                return;
            }

            if (!Contains(store, reissued))
            {
                Report("Windows", stage, "Install replacement", "BLOCKED", "Certificate absent after Add.");
                return;
            }

            Report("Windows", stage, "Install replacement", "PASS", "Exact DER found in CurrentUser/Root.");
            foreach (string channel in channels)
            {
                await using var browser = await LaunchAsync(playwright, channel);
                await ProbeAsync(browser, channel, StoreName.Root, "Replacement leaf after trust", ReissuedUrl, accept: true);
                await ProbeAsync(browser, channel, StoreName.Root, "Original leaf after replacement", LeafUrl, accept: false);
            }
        }
        finally
        {
            if (Contains(store, reissued))
            {
                Console.WriteLine($"Removing exact reissued test certificate {reissued.Thumbprint} from CurrentUser/Root.");
                store.Remove(reissued);
            }

            VerifyAbsent(reissued);
        }

        foreach (string channel in channels)
        {
            await using var browser = await LaunchAsync(playwright, channel);
            await ProbeAsync(browser, channel, StoreName.Root, "Replacement leaf after removal", ReissuedUrl, accept: false);
        }
    }

    private static async Task<bool> RunTrustedAsync(IBrowserContext context, string channel, string stage)
    {
        bool accepted = await ProbeAsync(context, channel, stage, "After trust", LeafUrl, accept: true);
        Report(channel, stage, "Ten-year validity accepted", accepted ? "PASS" : "BLOCKED",
            accepted ? "Accepted verified ten-year leaf" : "Primary HTTPS navigation failed; duration was not isolated.");
        await ProbeAsync(context, channel, stage, "Wrong hostname", $"https://localhost:{SpikeCertificates.LeafPort}/", accept: false, baseline: accepted);
        await ProbeAsync(context, channel, stage, "Leaf-issued child", $"https://localhost:{SpikeCertificates.ChildPort}/", accept: false, baseline: accepted);
        await ProbeAsync(context, channel, stage, "Same subject / different key", $"https://{SpikeCertificates.Host}:{SpikeCertificates.OtherKeyPort}/", accept: false, baseline: accepted);
        await ProbeAsync(context, channel, stage, "Same key / different SAN", $"https://localhost:{SpikeCertificates.OtherSanPort}/", accept: false, baseline: accepted);
        await ProbeAsync(context, channel, stage, "Reissued leaf / same key and SAN", ReissuedUrl, accept: false, baseline: accepted);
        if (accepted)
        {
            await RunCeremonyAsync(context, channel, stage, LeafUrl);
        }
        else
        {
            Report(channel, stage, "Secure context and WebAuthn", "BLOCKED", "HTTPS did not load.");
        }

        return accepted;
    }

    public static async Task RunLinuxAsync(X509Certificate2 leaf, string[] requested, CancellationToken stop)
    {
        if (requested.Length == 0 || requested.Skip(1).Any(browser => browser is not ("chromium" or "firefox" or "firefox-anchor")))
        {
            throw new ArgumentException("Pass the path to NSS certutil, then optional chromium, firefox and firefox-anchor modes.");
        }

        Console.WriteLine(RuntimeInformation.OSDescription + "; " + RuntimeInformation.FrameworkDescription);
        string executable = requested[0];
        string[] browsers = requested.Length == 1 ? ["chromium", "firefox"] : requested[1..];
        using var playwright = await Playwright.CreateAsync();
        foreach (string mode in browsers.Distinct())
        {
            stop.ThrowIfCancellationRequested();
            string browser = mode == "chromium" ? mode : "firefox";
            string trust = mode == "firefox-anchor" ? "C,," : "P,,";
            string stage = mode == "firefox-anchor" ? "NSS profile anchor C,," : "NSS trusted peer P,,";
            var work = Directory.CreateTempSubdirectory("with-secrets-leaf-");
            try
            {
                string profile = Directory.CreateDirectory(Path.Combine(work.FullName, "profile")).FullName;
                string database = browser == "firefox" ? profile :
                    Directory.CreateDirectory(Path.Combine(work.FullName, ".pki", "nssdb")).FullName;
                string certPath = Path.Combine(work.FullName, "leaf.cer");
                File.WriteAllBytes(certPath, leaf.RawData);
                var browserType = browser == "firefox" ? playwright.Firefox : playwright.Chromium;
                var options = new BrowserTypeLaunchPersistentContextOptions
                {
                    Channel = browser == "chromium" ? "chromium" : null,
                    Env = new Dictionary<string, string> { ["HOME"] = work.FullName, ["XDG_DATA_HOME"] = Path.Combine(work.FullName, ".local", "share") },
                    Timeout = 15000,
                };

                await NssAsync("-N", "--empty-password");
                await using (var context = await browserType.LaunchPersistentContextAsync(profile, options))
                {
                    Console.WriteLine($"{browser} {context.Browser?.Version ?? await context.Pages[0].EvaluateAsync<string>("navigator.userAgent")}");
                    await ProbeAsync(context, browser, stage, "Before trust", LeafUrl, accept: false);
                    await RunCeremonyAsync(context, browser, "HTTP localhost control", LocalhostUrl);
                }

                try
                {
                    await NssAsync("-A", "-t", trust, "-n", leaf.Thumbprint, "-i", certPath);
                    string listing = await NssAsync("-L");
                    Report(browser, stage, "Install trust", "PASS", listing.Trim().ReplaceLineEndings(" "));
                    bool accepted;
                    await using (var context = await browserType.LaunchPersistentContextAsync(profile, options))
                    {
                        accepted = await RunTrustedAsync(context, browser, stage);
                    }

                    if (accepted && browser == "firefox")
                    {
                        await FirefoxCeremony.RunAsync(LeafUrl, stage, profile);
                    }
                }
                finally
                {
                    if ((await NssAsync("-L")).Contains(leaf.Thumbprint, StringComparison.Ordinal))
                    {
                        await NssAsync("-D", "-n", leaf.Thumbprint);
                    }

                    if ((await NssAsync("-L")).Contains(leaf.Thumbprint, StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException("Exact spike leaf remains in disposable NSS database.");
                    }
                }

                await using (var context = await browserType.LaunchPersistentContextAsync(profile, options))
                {
                    await ProbeAsync(context, browser, stage, "After removal (fresh browser)", LeafUrl, accept: false);
                }

                async Task<string> NssAsync(params string[] arguments)
                {
                    var start = new ProcessStartInfo(executable) { RedirectStandardOutput = true, RedirectStandardError = true };
                    start.ArgumentList.Add("-d");
                    start.ArgumentList.Add($"sql:{database}");
                    foreach (string argument in arguments)
                    {
                        start.ArgumentList.Add(argument);
                    }

                    using var process = Process.Start(start) ?? throw new InvalidOperationException("Failed to run NSS certutil.");
                    var output = process.StandardOutput.ReadToEndAsync();
                    var error = process.StandardError.ReadToEndAsync();
                    await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
                    return process.ExitCode == 0 ? await output : throw new InvalidOperationException(await error);
                }
            }
            catch (PlaywrightException error)
            {
                Report(browser, stage, "Browser setup", "BLOCKED", error.Message);
            }
            finally
            {
                work.Delete(recursive: true);
                Report(browser, stage, "Disposable NSS/profile cleanup", "PASS", "Directory removed");
            }
        }
    }

    private static async Task<IBrowser> LaunchAsync(IPlaywright playwright, string channel) =>
        channel == "firefox"
            ? await playwright.Firefox.LaunchAsync(new() { Timeout = 15000 })
            : await playwright.Chromium.LaunchAsync(new() { Channel = channel, Timeout = 15000 });

    private static async Task<bool> ProbeAsync(
        IBrowser browser, string channel, StoreName store, string test, string url, bool accept, bool baseline = true)
    {
        await using var context = await browser.NewContextAsync();
        return await ProbeAsync(context, channel, store.ToString(), test, url, accept, baseline);
    }

    private static async Task<bool> ProbeAsync(
        IBrowserContext context, string channel, string stage, string test, string url, bool accept, bool baseline = true)
    {
        var page = await context.NewPageAsync();
        var result = await NavigateAsync(page, url);
        await page.CloseAsync();
        bool matched = accept ? result.Loaded : result.CertificateError;
        if (test == "Wrong hostname" && baseline && result.CertificateError)
        {
            matched = result.Detail.Contains("COMMON_NAME_INVALID", StringComparison.Ordinal) ||
                result.Detail.Contains("BAD_CERT_DOMAIN", StringComparison.Ordinal);
        }

        string status = !matched ? "FAIL" : !baseline ? "BLOCKED" : "PASS";
        Report(channel, stage, test, status, result.Detail);
        return result.Loaded;
    }

    private static async Task<(bool Loaded, bool CertificateError, string Detail)> NavigateAsync(IPage page, string url)
    {
        try
        {
            var response = await page.GotoAsync(url, new() { Timeout = 12000 });
            bool loaded = response?.Status == 200 && page.Url == url &&
                await page.TitleAsync() == "Local TLS spike";
            return (loaded, false, loaded ? "HTTP 200, spike page and exact URL" : $"Unexpected response {response?.Status}, page {page.Url}");
        }
        catch (PlaywrightException error)
        {
            string detail = error.Message.Split('\n')[0].TrimEnd();
            return (false, CertificateError().IsMatch(detail), detail);
        }
    }

    private static async Task RunCeremonyAsync(IBrowser browser, string channel, string stage, string url)
    {
        await using var context = await browser.NewContextAsync();
        await RunCeremonyAsync(context, channel, stage, url);
    }

    private static async Task RunCeremonyAsync(IBrowserContext context, string channel, string stage, string url)
    {
        var page = await context.NewPageAsync();
        var navigation = await NavigateAsync(page, url);
        if (!navigation.Loaded)
        {
            Report(channel, stage, "Secure context and WebAuthn", "BLOCKED", navigation.Detail);
            return;
        }

        bool secure = await page.EvaluateAsync<bool>("window.isSecureContext && !!window.PublicKeyCredential");
        Report(channel, stage, "Secure context / WebAuthn API", secure ? "PASS" : "FAIL", url);
        if (!secure)
        {
            Report(channel, stage, "Registration and authentication", "BLOCKED", "Secure context or WebAuthn API is missing.");
            return;
        }

        if (channel == "firefox")
        {
            if (OperatingSystem.IsWindows())
            {
                await FirefoxCeremony.RunAsync(url, stage);
            }

            return;
        }

        var cdp = await context.NewCDPSessionAsync(page);
        await cdp.SendAsync("WebAuthn.enable");
        JsonElement? reply = await cdp.SendAsync("WebAuthn.addVirtualAuthenticator", new Dictionary<string, object>
        {
            ["options"] = new
            {
                protocol = "ctap2",
                transport = "internal",
                hasResidentKey = true,
                hasUserVerification = true,
                isUserVerified = true,
                automaticPresenceSimulation = true,
            },
        });

        string authenticator = reply?.GetProperty("authenticatorId").GetString() ??
            throw new InvalidOperationException("CDP did not return an authenticator ID.");
        try
        {
            bool registered = await ClickAsync("register", "registration");
            if (registered)
            {
                await ClickAsync("auth", "authentication");
            }
            else
            {
                Report(channel, stage, "authentication", "BLOCKED", "Registration did not verify.");
            }

            if (url == LocalhostUrl)
            {
                string error = await page.EvaluateAsync<string>("""
                    async rpId => {
                        try {
                            await navigator.credentials.get({publicKey: {rpId, challenge: new Uint8Array(32), timeout: 2000}});
                            return 'Unexpected credential';
                        } catch (error) { return error.name + ': ' + error.message; }
                    }
                    """, SpikeCertificates.Host);
                Report(channel, stage, "Use with-secrets.localhost RP ID from localhost",
                    error.StartsWith("SecurityError:", StringComparison.Ordinal) ? "PASS" : "FAIL", error);
            }
        }
        finally
        {
            await cdp.SendAsync("WebAuthn.removeVirtualAuthenticator", new Dictionary<string, object>
            {
                ["authenticatorId"] = authenticator,
            });
            Report(channel, stage, "Virtual authenticator cleanup", "PASS", "Removed");
        }

        async Task<bool> ClickAsync(string button, string operation)
        {
            await page.Locator("#" + button).ClickAsync(new() { Timeout = 5000 });
            var result = page.Locator($"#result:is([data-state='{operation}-pass'], [data-state='{operation}-fail'])");
            await result.WaitForAsync(new() { Timeout = 35000 });
            bool passed = await result.GetAttributeAsync("data-state") == operation + "-pass";
            Report(channel, stage, operation, passed ? "PASS" : "FAIL", await result.InnerTextAsync());
            return passed;
        }
    }

    private static void CheckWindowsChain(X509Certificate2 certificate, string name)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        bool valid = chain.Build(certificate);
        Console.WriteLine($"Windows system chain {name}: {valid}; {string.Join(", ", chain.ChainStatus.Select(status => status.Status))}");
    }

    private static bool Contains(X509Store store, X509Certificate2 expected)
    {
        bool found = false;
        foreach (var certificate in store.Certificates)
        {
            using (certificate)
            {
                found |= certificate.RawData.AsSpan().SequenceEqual(expected.RawData);
            }
        }

        return found;
    }

    private static void VerifyAbsent(X509Certificate2 leaf)
    {
        foreach (var name in Stores)
        {
            using var store = new X509Store(name, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            if (Contains(store, leaf))
            {
                throw new InvalidOperationException($"Exact test certificate {leaf.Thumbprint} remains in CurrentUser/{name}.");
            }
        }

        Console.WriteLine($"Cleanup verified: {leaf.Thumbprint} absent from both CurrentUser stores.");
    }

    private static void Report(string channel, string stage, string test, string status, string detail) =>
        Console.WriteLine($"RESULT | {channel} | {stage} | {test} | {status} | {detail}");

    [GeneratedRegex(@"net::ERR_(?:CERT_[A-Z_]+|SSL_PINNED_KEY_NOT_IN_CERT_CHAIN)|(?:SEC|SSL|MOZILLA_PKIX)_ERROR_[A-Z_]+")]
    private static partial Regex CertificateError();
}
