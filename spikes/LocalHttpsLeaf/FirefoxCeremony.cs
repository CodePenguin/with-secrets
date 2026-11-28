using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;

namespace LocalHttpsLeaf;

internal static class FirefoxCeremony
{
    public static async Task RunAsync(string origin, string stage, string? profile = null)
    {
        string? driver = Environment.GetEnvironmentVariable("SPIKE_GECKODRIVER");
        string? firefox = Environment.GetEnvironmentVariable("SPIKE_FIREFOX_BINARY");
        if (driver is null || firefox is null)
        {
            Report(stage, "Registration and authentication", "BLOCKED", "Set SPIKE_GECKODRIVER and SPIKE_FIREFOX_BINARY to use a disposable Firefox authenticator.");
            return;
        }

        var start = new ProcessStartInfo(driver) { RedirectStandardOutput = true, CreateNoWindow = true };
        start.ArgumentList.Add("--port");
        start.ArgumentList.Add("0");
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start GeckoDriver.");
        try
        {
            const string prefix = "Listening on 127.0.0.1:";
            using var startupTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            string? line;
            do
            {
                line = await process.StandardOutput.ReadLineAsync(startupTimeout.Token);
                if (line is null)
                {
                    throw new InvalidOperationException("GeckoDriver exited before opening its loopback endpoint.");
                }
            }
            while (!line.Contains(prefix, StringComparison.Ordinal));

            int port = int.Parse(line[(line.IndexOf(prefix, StringComparison.Ordinal) + prefix.Length)..],
                System.Globalization.CultureInfo.InvariantCulture);
            _ = process.StandardOutput.ReadToEndAsync();
            using var client = new HttpClient(new HttpClientHandler { UseProxy = false })
            {
                BaseAddress = new Uri($"http://127.0.0.1:{port}/"),
                Timeout = TimeSpan.FromSeconds(45),
            };

            string[] firefoxArgs = profile is null ? ["-headless"] : ["-headless", "-profile", profile];
            var session = await SendAsync(HttpMethod.Post, "session", new
            {
                capabilities = new
                {
                    alwaysMatch = new Dictionary<string, object>
                    {
                        ["browserName"] = "firefox",
                        ["acceptInsecureCerts"] = false,
                        ["moz:firefoxOptions"] = new
                        {
                            binary = firefox,
                            args = firefoxArgs,
                            // Firefox otherwise routes Windows requests to native WebAuthn instead of its virtual authenticator.
                            prefs = new Dictionary<string, bool>
                            {
                                ["security.webauth.webauthn_enable_softtoken"] = true,
                                ["security.webauth.webauthn_enable_usbtoken"] = false,
                            },
                        },
                    },
                },
            });
            string path = $"session/{session.GetProperty("sessionId").GetString()}";
            try
            {
                var capabilities = session.GetProperty("capabilities");
                if (capabilities.GetProperty("acceptInsecureCerts").GetBoolean())
                {
                    throw new InvalidOperationException("WebDriver accepted insecure certificates.");
                }

                await SendAsync(HttpMethod.Post, $"{path}/timeouts", new { script = 40000 });
                await SendAsync(HttpMethod.Post, $"{path}/url", new { url = origin });
                var authenticator = await SendAsync(HttpMethod.Post, $"{path}/webauthn/authenticator", new
                {
                    protocol = "ctap2",
                    transport = "usb",
                    hasResidentKey = true,
                    hasUserVerification = true,
                    isUserConsenting = true,
                    isUserVerified = true,
                });
                string authPath = $"{path}/webauthn/authenticator/{authenticator}";
                try
                {
                    bool registered = await ClickAsync("#register", "registration");
                    if (registered)
                    {
                        await ClickAsync("#auth", "authentication");
                    }
                    else
                    {
                        Report(stage, "authentication", "BLOCKED", "Registration did not verify.");
                    }
                }
                finally
                {
                    await SendAsync(HttpMethod.Delete, authPath);
                    Report(stage, "Virtual authenticator cleanup", "PASS", "Removed with GeckoDriver");
                }
            }
            finally
            {
                await SendAsync(HttpMethod.Delete, path);
            }

            async Task<JsonElement> SendAsync(HttpMethod method, string endpoint, object? data = null)
            {
                using var request = new HttpRequestMessage(method, endpoint);
                if (data is not null)
                {
                    request.Content = JsonContent.Create(data);
                }

                using var response = await client.SendAsync(request);
                using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                var value = json.RootElement.GetProperty("value");
                if (!response.IsSuccessStatusCode)
                {
                    throw new InvalidOperationException($"{value.GetProperty("error")}: {value.GetProperty("message")}");
                }

                return value.Clone();
            }

            async Task<bool> ClickAsync(string selector, string operation)
            {
                var element = await SendAsync(HttpMethod.Post, $"{path}/element", new { @using = "css selector", value = selector });
                string id = element.GetProperty("element-6066-11e4-a52e-4f735466cecf").GetString()!;
                await SendAsync(HttpMethod.Post, $"{path}/element/{id}/click", new { });
                var result = await SendAsync(HttpMethod.Post, $"{path}/execute/async", new
                {
                    script = """
                        const [operation, done] = arguments;
                        const output = document.querySelector('#result');
                        const observer = new MutationObserver(check);
                        observer.observe(output, {attributes: true});
                        check();
                        function check() {
                            const state = output.dataset.state;
                            if (state === operation + '-pass' || state === operation + '-fail') {
                                observer.disconnect();
                                done({ passed: state.endsWith('-pass'), detail: output.textContent });
                            }
                        }
                        """,
                    args = new[] { operation },
                });
                bool passed = result.GetProperty("passed").GetBoolean();
                Report(stage, operation, passed ? "PASS" : "FAIL", result.GetProperty("detail").GetString());
                return passed;
            }
        }
        catch (Exception error) when (error is InvalidOperationException or HttpRequestException or OperationCanceledException)
        {
            Report(stage, "GeckoDriver ceremony", "BLOCKED", error.Message.Split('\n')[0].TrimEnd());
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
    }

    private static void Report(string stage, string test, string status, string? detail) =>
        Console.WriteLine($"RESULT | firefox | {stage} | {test} | {status} | {detail}");
}
