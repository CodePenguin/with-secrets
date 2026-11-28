using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using Microsoft.Playwright;

namespace ArcanaGuardian.E2E;

/// <summary>A TextWriter that keeps what was written (thread safe), for the terminal of one command.</summary>
internal sealed class Terminal : TextWriter
{
    private readonly StringBuilder _text = new();
    private Action<string>? _onWrite;

    public override Encoding Encoding => Encoding.UTF8;

    public void SetObserver(Action<string> onWrite) => _onWrite = onWrite;

    public string Text
    {
        get
        {
            lock (_text)
            {
                return _text.ToString();
            }
        }
    }

    public override void Write(char value)
    {
        lock (_text)
        {
            _text.Append(value);
        }

        _onWrite?.Invoke(value.ToString());
    }

    public override void Write(string? value)
    {
        lock (_text)
        {
            _text.Append(value);
        }

        if (value is not null) _onWrite?.Invoke(value);
    }
}

/// <summary>One scenario's state: a temp state folder (never the real .ArcanaGuardian), the store and a free port per command.</summary>
internal sealed class Rig(bool trusted = true) : IDisposable
{
    public string Folder { get; } = Path.Combine(Path.GetTempPath(), "ws-e2e-" + Guid.NewGuid().ToString("N"));
    public string Work { get; } = Directory.CreateTempSubdirectory("ws-e2e-work-").FullName;
    public StateDatabase State => StateDatabase.InFolder(Folder);
    public SecretStore Store => new(State);

    private E2EMachine? _machine;

    /// <summary>The machine of this rig: enrolled and approved once, kept for every run of the rig.</summary>
    public E2EMachine Machine => _machine ??= new E2EMachine(Folder, trusted);

    /// <summary>The name of a small script that prints a line holding the secret: NAME.cmd on Windows (run by cmd), NAME.sh elsewhere (run by sh).</summary>

    /// <summary>The inline code of a run that has none in a file: PowerShell on Windows, the shell elsewhere. It prints inline- and the secret.</summary>
    public static string InlineCode => OperatingSystem.IsWindows() ? "Write-Output ('inline-' + $env:E2E_SECRET)" : "echo inline-$E2E_SECRET";

    public static string[] InlineCommand => OperatingSystem.IsWindows() ? ["powershell", "-NoProfile", "-NonInteractive", "-Command", InlineCode] : ["sh", "-c", InlineCode];

    public static string ScriptFile(string name) => name + (OperatingSystem.IsWindows() ? ".cmd" : ".sh");

    /// <summary>The command that runs the script: <c>cmd /d /c NAME.cmd</c> on Windows, <c>sh NAME.sh</c> elsewhere.</summary>
    public static string[] ScriptCommand(string name) => OperatingSystem.IsWindows() ? ["cmd", "/d", "/c", ScriptFile(name)] : ["sh", ScriptFile(name)];

    /// <summary>The line of the script: it prints LABEL=value of the secret variable.</summary>
    public static string ScriptEcho(string label) => OperatingSystem.IsWindows() ? $"echo {label}=%E2E_SECRET%" : $"echo {label}=$E2E_SECRET";

    /// <summary>Writes the script into the work folder; <paramref name="runnable" /> makes it a file that can be run directly (a first line for the shell, the executable bit). Returns its path.</summary>
    public string WriteScript(string name, string label, bool runnable = false)
    {
        string path = Path.Combine(Work, ScriptFile(name));
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllLines(path, ["@echo off", ScriptEcho(label)]);
        }
        else
        {
            File.WriteAllLines(path, runnable ? ["#!/bin/sh", ScriptEcho(label)] : [ScriptEcho(label)]);
            if (runnable)
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }

        return path;
    }

    public static int FreePort()
    {
        TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        return port;
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        _machine?.Dispose();
        foreach (string dir in new[] { Folder, Work })
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }
}

/// <summary>
/// One real command, run in-process through <see cref="CommandWiring" /> (the same wiring as the program) with the terminal
/// replaced: everything the command writes to the terminal is kept, the one link is read from it, and the code the person types
/// is fed from the test (it is read from the page DOM and never printed). Runs are sequential (the terminal hooks are static).
/// </summary>
internal sealed class Cmd<T> : IDisposable
{
    private readonly BlockingCollection<string?> _typed = [];
    public Terminal Err { get; } = new();
    public Terminal Out { get; } = new();
    public Task<T> Result { get; }
    public int Port { get; } = Rig.FreePort();

    public Cmd(Func<int, Terminal, Terminal, T> run)
    {
        TerminalPrompt.Output = Err;
        TerminalPrompt.Input = () => _typed.TryTake(out string? code, TimeSpan.FromSeconds(90)) ? code : null;
        Ctx.Last?.AttachTerminal(Out, Err);
        Result = Task.Run(() => run(Port, Out, Err));
    }

    public async Task<string> LinkAsync()
    {
        DateTime stop = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < stop)
        {
            Match m = Regex.Match(Err.Text, @"https?://\S+");
            if (m.Success)
            {
                return m.Value;
            }

            await Task.Delay(20);
        }

        throw new TimeoutException("no link on the terminal: " + Err.Text);
    }

    /// <summary>How many links the command printed (a flow must print exactly one).</summary>
    public int LinkCount => Regex.Matches(Err.Text, @"https?://\S+").Count;

    public void Type(string? code) => _typed.Add(code);

    public async Task WaitPromptAsync(string prompt = TerminalPrompt.Waiting)
    {
        DateTime stop = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < stop)
        {
            if (Err.Text.EndsWith(prompt, StringComparison.Ordinal))
            {
                return;
            }

            await Task.Delay(20);
        }

        throw new TimeoutException("the prompt was not the last thing on the terminal");
    }

    public void Dispose()
    {
        TerminalPrompt.Output = null;
        TerminalPrompt.Input = null;
    }
}

internal sealed record DemoStep(string Path, string Caption);

internal sealed class Host : IAsyncDisposable
{
    private int _contextNumber;
    public IPlaywright Pw { get; private set; } = null!;
    public IBrowser Browser { get; private set; } = null!;
    public string? DemoDirectory { get; }
    public string? CurrentScenarioDirectory { get; private set; }
    public bool IsDemo => DemoDirectory is not null;
    private readonly List<DemoStep> _steps = [];
    private readonly object _stepGate = new();
    private readonly List<(string Scenario, string Path)> _consoleLogs = [];
    private readonly List<Ctx> _scenarioContexts = [];

    private Host(string? demoDirectory) => DemoDirectory = demoDirectory;

    public static async Task<Host> StartAsync(string? demoDirectory = null)
    {
        Host host = new(demoDirectory) { Pw = await Playwright.CreateAsync() };
        // The same Chromium build is used for tests and demos; Playwright records the actual browser viewport.
        // Slow motion is a demo-only pacing aid: normal runs keep their timing and semantics unchanged.
        host.Browser = await host.Pw.Chromium.LaunchAsync(new() { Headless = true });

        return host;
    }

    public void BeginScenario(string name)
    {
        Ctx.ResetLast();
        _contextNumber = 0;
        lock (_stepGate) _steps.Clear();
        _scenarioContexts.Clear();
        CurrentScenarioDirectory = DemoDirectory is null ? null : Path.Combine(DemoDirectory, "videos", name);
        if (CurrentScenarioDirectory is not null) Directory.CreateDirectory(CurrentScenarioDirectory);
    }

    public void RegisterContext(Ctx context) => _scenarioContexts.Add(context);

    public async Task CloseScenarioAsync()
    {
        foreach (Ctx context in _scenarioContexts) await context.CloseAsync();
        _scenarioContexts.Clear();
    }

    /// <summary>Captures every open context of a failed demo scenario before the runner closes them.</summary>
    public async Task<(string[] Screenshots, string? Diagnostics)> CaptureFailureAsync(string scenario, S checks)
    {
        if (DemoDirectory is null) return ([], null);
        string directory = Path.Combine(DemoDirectory, "failures", scenario);
        Directory.CreateDirectory(directory);
        List<string> screenshots = [];
        StringBuilder diagnostics = new();
        diagnostics.AppendLine("Scenario: " + scenario);
        diagnostics.AppendLine($"Checks: {checks.Passed} passed, {checks.Failed} failed");
        foreach (string line in checks.Lines.Where(line => line.StartsWith("  FAIL", StringComparison.Ordinal)))
        {
            diagnostics.AppendLine(line);
        }

        for (int index = 0; index < _scenarioContexts.Count; index++)
        {
            Ctx context = _scenarioContexts[index];
            diagnostics.AppendLine($"Context {index + 1}:");
            try
            {
                string screenshot = Path.Combine(directory, $"context-{index + 1}.png");
                await context.CaptureScreenshotAsync(screenshot);
                if (File.Exists(screenshot)) screenshots.Add(screenshot);
                diagnostics.AppendLine("  " + await context.Dump());
            }
            catch (Exception failure)
            {
                diagnostics.AppendLine("  screenshot failed: " + failure.GetType().Name + ": " + failure.Message.Split('\n')[0]);
                try
                {
                    diagnostics.AppendLine("  " + await context.Dump());
                }
                catch (Exception dumpFailure)
                {
                    diagnostics.AppendLine("  page dump failed: " + dumpFailure.GetType().Name + ": " + dumpFailure.Message.Split('\n')[0]);
                }
            }
        }

        string path = Path.Combine(directory, "diagnostics.txt");
        await File.WriteAllTextAsync(path, diagnostics.ToString());
        return (screenshots.ToArray(), path);
    }

    public string? NextVideoName()
    {
        if (CurrentScenarioDirectory is null) return null;
        _contextNumber++;
        return Path.Combine(CurrentScenarioDirectory, $"browser-{_contextNumber}.webm");
    }

    /// <summary>The next screenshot of this scenario: its file, in order, and what the caption said.</summary>
    public string NextStepPath(out int number)
    {
        lock (_stepGate)
        {
            number = _steps.Count + 1;
        }

        string folder = Path.Combine(DemoDirectory!, "steps", Path.GetFileName(CurrentScenarioDirectory!));
        Directory.CreateDirectory(folder);

        return Path.Combine(folder, number.ToString("000", System.Globalization.CultureInfo.InvariantCulture) + ".png");
    }

    public void AddStep(string path, string caption)
    {
        lock (_stepGate) _steps.Add(new DemoStep(path, caption));
    }

    /// <summary>Drops the steps so far (the shared setup is over: the scenario's own steps start here).</summary>
    public void ClearSteps()
    {
        lock (_stepGate) _steps.Clear();
    }

    /// <summary>Writes the page that steps through this scenario's screenshots (Back, Next, the arrow keys) and gives its path, or none when nothing was captured.</summary>
    public IEnumerable<string> WriteViewer(string scenario)
    {
        DemoStep[] steps;
        lock (_stepGate) steps = [.. _steps];
        if (DemoDirectory is null || steps.Length == 0) return [];
        string page = Path.Combine(DemoDirectory, "viewer-" + scenario + ".html");
        var data = steps.Select(step => new { image = Path.GetRelativePath(DemoDirectory, step.Path).Replace(Path.DirectorySeparatorChar, '/'), caption = step.Caption });
        string json = JsonSerializer.Serialize(data).Replace("</", "<\\/", StringComparison.Ordinal);
        File.WriteAllText(page, DemoViewer.Page(scenario, json));

        return [page];
    }

    public void AddConsoleLog(string scenario, string path) => _consoleLogs.Add((scenario, path));

    public IEnumerable<string> ConsoleLogsFor(string scenario) =>
        _consoleLogs.Where(x => x.Scenario == scenario).Select(x => x.Path).OrderBy(path => path, StringComparer.Ordinal);

    public async ValueTask DisposeAsync()
    {
        await Browser.CloseAsync();
        Pw.Dispose();
    }
}

/// <summary>One browser context (one scenario) with a virtual authenticator, and a record of every console error, page error and CSP violation.</summary>
internal sealed class Ctx : IAsyncDisposable
{
    private const string InitScript = """
        window.__credCalls = 0;
        // The browser's error page (a refused connection) is an insecure document with no navigator.credentials: nothing to count there.
        if (navigator.credentials) ['get', 'create'].forEach(function (m) {
            var o = navigator.credentials[m].bind(navigator.credentials);
            navigator.credentials[m] = function () { window.__credCalls++; return o.apply(null, arguments); };
        });
        document.addEventListener('securitypolicyviolation', function (e) { console.error('CSP violation: ' + e.violatedDirective + ' ' + e.blockedURI); });
        """;

    private readonly List<string> _ignore = [];

    public IBrowserContext Context { get; private set; } = null!;
    public IPage Page { get; private set; } = null!;
    public ICDPSession Cdp { get; private set; } = null!;
    public string AuthId { get; private set; } = "";
    private Host _host = null!;
    private string _scenario = "";
    private string? _videoPath;
    private bool _closed;
    private readonly StringBuilder _demoTranscript = new();
    private readonly object _demoTranscriptGate = new();
    private string _lastCaption = "";
    public List<string> Problems { get; } = [];
    public List<string> Console { get; } = [];

    public static Ctx? Last { get; private set; }

    public static void ResetLast() => Last = null;

    public bool IsDemo => _host.DemoDirectory is not null;

    public void AttachTerminal(Terminal output, Terminal error)
    {
        if (!IsDemo) return;
        lock (_demoTranscriptGate)
        {
            // The first command of a scenario starts the pane; a later one is told apart from the one before it.
            if (_demoTranscript.Length > 0) _demoTranscript.Append(Environment.NewLine + "--- next command ---" + Environment.NewLine);
        }

        output.SetObserver(AppendDemoTranscript);
        error.SetObserver(AppendDemoTranscript);
    }

    private void AppendDemoTranscript(string text)
    {
        lock (_demoTranscriptGate)
        {
            _demoTranscript.Append(text);
        }
    }

    public string DemoTerminalJson
    {
        get
        {
            lock (_demoTranscriptGate)
            {
                return JsonSerializer.Serialize(new { transcript = _demoTranscript.ToString() });
            }
        }
    }

    /// <summary>Demo only: puts the caption in the caption area and saves a screenshot of the whole screen (terminal, caption and page) as the next step. It is not part of the application DOM or test assertions.</summary>
    /// <summary>Waits for the terminal prompt, shows it (demo), types the code from the page and waits for the command to finish: the last step of every flow that ends in the terminal.</summary>
    public async Task<int> TypeCodeAsync(Cmd<int> cmd, string code)
    {
        await cmd.WaitPromptAsync();
        await DemoSnapAsync("The terminal waits for the code from the page.");
        cmd.Type(code);
        int exit = await cmd.Result.WaitAsync(TimeSpan.FromSeconds(30));
        await DemoSnapAsync("The person types the code in the terminal and the command finishes.");

        return exit;
    }

    /// <summary>Waits until the page has drawn the changes made so far (two animation frames), for a screenshot taken right after a resize or a change.</summary>
    public Task SettledAsync() => Page.EvaluateAsync("() => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done)))");

    /// <summary>
    /// Waits until the page has made no request for <paramref name="quiet" />, and none is still in flight. For checks that something did not happen.
    /// </summary>
    public async Task QuietAsync(int quiet = 500, int timeout = 10000)
    {
        ConcurrentDictionary<IRequest, bool> inFlight = [];
        long last = Environment.TickCount64;
        void Started(object? _, IRequest request)
        {
            inFlight[request] = true;
            last = Environment.TickCount64;
        }

        void Ended(object? _, IRequest request)
        {
            inFlight.TryRemove(request, out bool _);
            last = Environment.TickCount64;
        }

        Page.Request += Started;
        Page.RequestFinished += Ended;
        Page.RequestFailed += Ended;
        try
        {
            long deadline = Environment.TickCount64 + timeout;
            while (!inFlight.IsEmpty || Environment.TickCount64 - Interlocked.Read(ref last) < quiet)
            {
                if (Environment.TickCount64 > deadline) throw new TimeoutException("The page kept making requests.");
                await Task.Delay(20);
            }
        }
        finally
        {
            Page.Request -= Started;
            Page.RequestFinished -= Ended;
            Page.RequestFailed -= Ended;
        }
    }

    /// <summary>Demo only: scrolls to the control, outlines it and takes the screenshot, so the picture shows the control that is about to be pressed.</summary>
    public async Task DemoPressAsync(ILocator target, string message)
    {
        if (!IsDemo) return;
        try
        {
            await target.ScrollIntoViewIfNeededAsync(new() { Timeout = 2000 });
            // The page may have focused another control (a safe default such as Deny): only the control about to be pressed is marked.
            await target.EvaluateAsync("(control) => { if (document.activeElement && document.activeElement !== control && document.activeElement.blur) document.activeElement.blur(); window.__wsDemoMark(control); }");
            await DemoCaptionAsync(message);
            await Page.EvaluateAsync("() => window.__wsDemoClear()");
        }
        catch (Exception)
        {
            // A control that cannot be outlined is still pressed; the step is simply not pictured.
        }
    }

    public async Task DemoCaptionAsync(string message)
    {
        if (!IsDemo || _host.CurrentScenarioDirectory is null) return;
        try
        {
            _lastCaption = message;
            await Page.EvaluateAsync<bool>(@"(message) => {
                const caption = document.getElementById('__ws_demo_caption');
                if (!caption) return false;
                caption.textContent = message;
                return true;
            }", message);
            // The terminal pane updates only here: bring it up to date, so the picture shows what the command has printed so far.
            await Page.EvaluateAsync("() => window.__wsDemoTerminalRefresh ? window.__wsDemoTerminalRefresh() : null");
            await SettledAsync();
            string path = _host.NextStepPath(out _);
            await Page.ScreenshotAsync(new() { Path = path, FullPage = false });
            _host.AddStep(path, message);
        }
        catch (Exception)
        {
            // A page that is navigating cannot be captured; the next step will be.
        }
    }

    /// <summary>
    /// Demo only: the title step of a scenario. The page behind it is only what the shared setup left, so it is hidden for
    /// the picture (the terminal pane stays), and shown again after.
    /// </summary>
    public async Task DemoIntroAsync(string message)
    {
        if (!IsDemo) return;
        const string hide = "() => { document.body.style.setProperty('visibility', 'hidden', 'important'); const t = document.getElementById('__ws_demo_terminal'); if (t) t.style.setProperty('visibility', 'visible', 'important'); }";
        await Page.EvaluateAsync(hide);
        await DemoCaptionAsync(message);
        await Page.EvaluateAsync("() => document.body.style.removeProperty('visibility')");
    }

    /// <summary>Demo only: another step with a new caption, for a state the page has just reached (the result, the code, the status).</summary>
    public Task DemoSnapAsync(string message) => DemoCaptionAsync(message);

    public async Task StartDemoAsync()
    {
        MarkScenarioStart();
        await DemoIntroAsync(ScenarioIntroduction());
    }

    public string ScenarioIntroduction() => _scenario switch
    {
        "a-first-run-setup" => "First-time setup: create the authority's initial passkey and recovery code.",
        "a2-first-run-security" => "Setup security checks: see what happens when a passkey prompt is cancelled, refused, or interrupted. For everyday setup, open the Quick Start demo.",
        "b-spa-secrets" => "Add a secret, approve a run that uses it, then move, replace, and remove the secret.",
        "b-set-remove" => "Secret management: add a secret, verify it can be used, then remove it.",
        "c-run-approval" => "Secret use: review a command's request, approve it, and see that its output is redacted.",
        "c2-run-code-changes" => "Command review: identify environment changes that could load code or redirect network traffic.",
        "d-rotate-key" => "Key rotation: replace the encryption keys while preserving stored secrets.",
        "e-recover" => "Recovery: restore access after every passkey has been lost.",
        "g-enroll-cross-host" => "Add a passkey for another host name. This demo shows what happens when that address uses HTTP.",
        "h1-refusal-and-cancel" => "Safe failure: refuse or cancel a passkey operation without changing protected state.",
        "h2-resend-after-abort" => "Retry behavior: recover cleanly when a confirmation attempt is abandoned.",
        "h3-lost-reply" => "Lost response: verify that a completed operation is not accidentally repeated.",
        "h4-continue-fallback" => "Fallback behavior: continue safely when the preferred confirmation path is unavailable.",
        "h5-tap-rule" => "Passkey safety: verify that authentication starts only after a deliberate user gesture.",
        "i1-spa-sign-in-out" => "Sign in with a passkey, then sign out to end this browser session.",
        "i1b-spa-sign-in-cancel" => "Sign-in cancel: back out of the passkey prompt, then sign in again.",
        "i2-spa-approve-machine" => "Machine trust: review a newly enrolled machine and explicitly approve it.",
        "f-enroll-same-host" => "Add a second passkey on this device, then use it to approve a run and extend a grant.",
        "i3-spa-revoke-grant" => "Grant management: revoke previously approved access to a secret.",
        "i4-spa-audit-search" => "Audit history: search recorded administrative and secret-use events.",
        "i5-spa-lock-unlock" => "Authority lock: lock the authority and unlock it again with a passkey.",
        "i6-spa-settings-change" => "Settings: change authority policy through the authenticated administration UI.",
        "i7-spa-refused-without-authorization" => "See what happens when you leave an approval without confirming it with a passkey.",
        "i8-spa-accept-host-name" => "Machine identity: review and accept a machine's friendly name.",
        "i9-spa-reload-between-tap-and-result" => "Reloading before confirmation keeps the request pending. Reloading after an approved change preserves the result.",
        "i10a-provider-bitwarden" => "Set up Bitwarden Secrets Manager, edit its configuration, and manage a mount.",
        "i10b-provider-1password" => "Set up 1Password with a service-account token.",
        "i10c-provider-vault" => "Set up HashiCorp Vault with a token for the authority’s configured Vault server.",
        "i10d-provider-lastpass" => "Set up LastPass with an account email and region.",
        "j1-spa-accessibility" => "Accessibility: check keyboard navigation, focus management, and responsive layout.",
        "k1-spa-pair-machine" => "Machine pairing: create a one-time invitation, pair another host, then review its trust request.",
        _ => "End-to-end scenario: follow the browser workflow and verify its security outcome."
    };

    /// <summary>For a failure report: the page title, address, buttons, status line (never the code) and console.</summary>
    public async Task<string> Dump()
    {
        try
        {
            string status = "";
            try
            {
                status = await Page.Locator("#status").TextContentAsync(new() { Timeout = 500 }) ?? "";
            }
            catch (Exception)
            {
                // The administration application has no #status element.
            }

            string buttons = string.Join(",", await Page.EvaluateAsync<string[]>("() => [...document.querySelectorAll('button')].map(b => b.id + (b.hidden ? '(h)' : '') + (b.disabled ? '(d)' : '') + '=' + b.textContent)"));
            string alerts = string.Join("; ", await Page.Locator("[role=alert]").AllTextContentsAsync());
            string credentialCalls = await Page.EvaluateAsync<string>("() => String(window.__credCalls || 0)");

            string dialog = "";
            try
            {
                // The administration application: what an open dialog says (an error shows here).
                dialog = " | dialog: " + Regex.Replace((await Page.Locator("dialog[open]").First.TextContentAsync(new() { Timeout = 500 }) ?? "").Trim(), @"\s+", " ");
            }
            catch (Exception)
            {
                // No dialog.
            }

            return "    page: " + await Page.TitleAsync() + " | " + Regex.Replace(Page.Url, "/[A-Za-z0-9_-]{20,}", "/<token>") + " | buttons " + buttons + " | credential calls: " + credentialCalls + " | alerts: " + alerts + " | status: " + status + dialog + " | console: " + string.Join(" // ", Console);
        }
        catch (Exception e)
        {
            return "    (no page dump: " + e.Message.Split((char)10)[0] + " url=" + Page.Url + " console: " + string.Join(" // ", Console) + ")";
        }
    }

    /// <summary>Calls of navigator.credentials.create/get made by the page scripts on the current document.</summary>
    public async Task<int> PasskeyCalls() => await Page.EvaluateAsync<int>("() => window.__credCalls || 0");

    /// <summary>Console errors that contain this text are expected in this scenario (for example an aborted request).</summary>
    public void Ignore(string consoleSubstring) => _ignore.Add(consoleSubstring);

    public static async Task<Ctx> NewAsync(Host host, bool hasPrf = true)
    {
        Ctx c = new();
        Last = c;
        c._host = host;
        c._scenario = Path.GetFileName(host.CurrentScenarioDirectory ?? "");
        string? videoPath = host.NextVideoName();
        c.Context = videoPath is null
            ? await host.Browser.NewContextAsync()
            : await host.Browser.NewContextAsync(new BrowserNewContextOptions { ViewportSize = new ViewportSize { Width = 1440, Height = 900 } });
        await c.Context.AddInitScriptAsync(InitScript);
        if (host.IsDemo)
        {
            await c.Context.AddInitScriptAsync("(" + DemoOutline.Script + ")()");
            await c.Context.AddInitScriptAsync("(" + DemoTerminal.Script + ")()");
            await c.Context.RouteAsync("**/__ws_demo_terminal", route => route.FulfillAsync(new()
            {
                Status = 200,
                ContentType = "application/json",
                Body = c.DemoTerminalJson
            }));
        }
        c.Page = await c.Context.NewPageAsync();
        c.AttachPage(c.Page);
        c.Cdp = await c.Context.NewCDPSessionAsync(c.Page);
        await c.Cdp.SendAsync("WebAuthn.enable");
        c.AuthId = await c.AddAuthenticator(hasPrf);
        c._videoPath = videoPath;
        host.RegisterContext(c);

        return c;
    }

    /// <summary>
    /// Demo-only: the shared first-run setup is over. The video keeps recording the same page, but the recording is
    /// trimmed at this point when the context closes, so the published video starts at the scenario's own steps.
    /// (The virtual authenticator's PRF secret cannot be moved to another page, so the page itself must stay.)
    /// </summary>
    public void MarkScenarioStart()
    {
        if (!IsDemo) return;
        _host.ClearSteps();
        // The setup command's output goes with the setup: the pane shows only what the scenario's own commands print.
        lock (_demoTranscriptGate) _demoTranscript.Clear();
    }

    /// <summary>Records console errors, page errors and failed requests of a page for the scenario's checks.</summary>
    private void AttachPage(IPage page)
    {
        page.Console += (_, m) =>
        {
            Console.Add(m.Type + ": " + m.Text);
            bool bad = m.Type == "error" || m.Text.Contains("Content Security Policy", StringComparison.OrdinalIgnoreCase) || m.Text.Contains("Refused to", StringComparison.OrdinalIgnoreCase);
            if (bad && !_ignore.Any(i => m.Text.Contains(i, StringComparison.Ordinal)))
            {
                // The location names the request of a "Failed to load resource" error (ids shortened like the failed-request lines).
                Problems.Add("console " + m.Type + ": " + m.Text + " at " + Regex.Replace(m.Location, "/[A-Za-z0-9_-]{20,}", "/<token>"));
            }
        };
        page.PageError += (_, e) => Problems.Add("pageerror: " + e);
        page.RequestFailed += (_, r) => Console.Add("requestfailed: " + Regex.Replace(r.Url, "/[A-Za-z0-9_-]{20,}", "/<token>") + " " + r.Failure);
    }

    /// <summary>The person lost every passkey: the virtual authenticator forgets all its credentials.</summary>
    public Task ClearCredentials() => Cdp.SendAsync("WebAuthn.clearCredentials", new Dictionary<string, object> { ["authenticatorId"] = AuthId });

    /// <summary>Adds a virtual authenticator (ctap2, internal, resident keys, user verification, automatic presence) and gives its id.</summary>
    public async Task<string> AddAuthenticator(bool hasPrf = true, string transport = "internal")
    {
        System.Text.Json.JsonElement? reply = await Cdp.SendAsync("WebAuthn.addVirtualAuthenticator", new Dictionary<string, object>
        {
            ["options"] = new Dictionary<string, object>
            {
                ["protocol"] = "ctap2",
                ["transport"] = transport,
                ["hasResidentKey"] = true,
                ["hasUserVerification"] = true,
                ["isUserVerified"] = true,
                ["automaticPresenceSimulation"] = true,
                ["hasPrf"] = hasPrf,
            },
        });

        return reply!.Value.GetProperty("authenticatorId").GetString()!;
    }

    public Task Presence(bool on, string? id = null) => Cdp.SendAsync("WebAuthn.setAutomaticPresenceSimulation", new Dictionary<string, object> { ["authenticatorId"] = id ?? AuthId, ["enabled"] = on });


    public Task Verified(bool on) => Cdp.SendAsync("WebAuthn.setUserVerified", new Dictionary<string, object> { ["authenticatorId"] = AuthId, ["isUserVerified"] = on });

    public async Task<string> Text(string selector) => (await Page.Locator(selector).TextContentAsync() ?? "").Trim();

    /// <summary>Waits until the element has text and gives it.</summary>
    public async Task<string> TextAppears(string selector, int ms = 20000)
    {
        await Page.WaitForFunctionAsync("s => { var e = document.querySelector(s); return !!e && e.textContent.trim().length > 0; }", selector, new() { Timeout = ms });
        if (IsDemo)
        {
            // The one-shot pages are long, so the revealed code, request or recovery box can be below the viewport.
            // Scroll it into view for the recording; scrolling changes nothing the scenario asserts.
            try { await Page.Locator(selector).ScrollIntoViewIfNeededAsync(new() { Timeout = 2000 }); }
            catch (Exception) { /* A hidden or detached element is simply not shown. */ }
        }

        await DemoSnapAsync(selector switch
        {
            "#code" => "The page shows the code to type in the terminal.",
            "#recovery" => "The page shows the recovery code, once.",
            "#request" => "The page shows the request to review.",
            _ => "The page shows the result.",
        });

        return await Text(selector);
    }

    public async Task StatusContains(string part, int ms = 20000)
    {
        await Page.WaitForFunctionAsync("p => { var e = document.getElementById('status'); return !!e && e.textContent.indexOf(p) >= 0; }", part, new() { Timeout = ms });
        await DemoSnapAsync("The page says: " + part + ".");
    }

    public async Task Click(string selector, int ms = 20000)
    {
        ILocator target = Page.Locator(selector);
        string label = "";
        try { label = Regex.Replace((await target.First.InnerTextAsync(new() { Timeout = 500 }) ?? "").Trim(), @"\s+", " "); }
        catch (Exception) { }
        await DemoPressAsync(target, label.Length > 0 ? $"The person selects “{label}”." : "The person advances this step in the browser workflow.");
        await target.ClickAsync(new() { Timeout = ms });
    }

    /// <summary>Captures a failure screenshot of this context.</summary>
    public async Task CaptureScreenshotAsync(string path)
    {
        if (_closed) return;
        await Page.ScreenshotAsync(new() { Path = path, FullPage = true });
    }

    /// <summary>The context stays open until the runner closed it (a failure report reads the page first).</summary>
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    public async Task CloseAsync()
    {
        if (_closed) return;
        _closed = true;
        await Context.CloseAsync();
        if (IsDemo && _videoPath is not null)
        {
            string transcript;
            lock (_demoTranscriptGate) transcript = _demoTranscript.ToString();
            if (transcript.Length > 0)
            {
                string logPath = Path.Combine(Path.GetDirectoryName(_videoPath)!, "console-" + Path.GetFileNameWithoutExtension(_videoPath) + ".txt");
                await File.WriteAllTextAsync(logPath, "Everything the commands printed (standard output and standard error), in the order it appeared." + Environment.NewLine + Environment.NewLine + transcript);
                _host.AddConsoleLog(_scenario, logPath);
            }
        }
    }
}

/// <summary>
/// Demo-only outline that marks the control about to be pressed (<c>DemoPressAsync</c>). The recordings are judged by eye,
/// and the outline shows which control the step is about. It uses the CSS object model (not a &lt;style&gt; element)
/// because the one-shot pages send a strict Content-Security-Policy; scripted style changes are allowed. A manual popover
/// keeps the outline above modal dialogs, which live in the browser's top layer.
/// </summary>
internal static class DemoOutline
{
    public const string Script = """
        () => {
          if (window.__wsDemoMark) return;
          const start = () => {
            if (window.__wsDemoMark || !document.documentElement) return;
            let marked = null;
            const clear = () => {
              if (marked) marked.remove();
              marked = null;
            };
            window.__wsDemoClear = clear;
            window.__wsDemoMark = (control) => {
              clear();
              // A control at the edge of the screen would have its outline cut off: bring it to the middle.
              let box = control.getBoundingClientRect();
              if (box.top < 12 || box.bottom > window.innerHeight - 12) {
                control.scrollIntoView({ block: 'center' });
                box = control.getBoundingClientRect();
              }
              marked = document.createElement('div');
              marked.setAttribute('aria-hidden', 'true');
              marked.setAttribute('popover', 'manual');
              const style = {
                margin: '0', padding: '0', inset: 'auto', overflow: 'visible', background: 'transparent',
                position: 'fixed', left: (box.left - 3) + 'px', top: (box.top - 3) + 'px',
                width: (box.width + 6) + 'px', height: (box.height + 6) + 'px', 'box-sizing': 'border-box',
                'border-radius': '6px', border: '3px solid #e11d48', 'box-shadow': '0 0 0 2px rgba(255, 255, 255, 0.9)',
                'pointer-events': 'none', 'z-index': '2147483647'
              };
              for (const [name, value] of Object.entries(style)) marked.style.setProperty(name, value, 'important');
              document.documentElement.appendChild(marked);
              try { marked.showPopover(); } catch (error) { /* An older browser without popovers still shows the outline beneath any open dialog. */ }
            };
          };
          if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
          else start();
        }
        """;
}

/// <summary>A scenario's checks: each is shown as PASS or FAIL; a thrown exception is a failure too.</summary>
internal sealed class S(string name)
{
    public string Name { get; } = name;
    public int Failed { get; private set; }
    public int Passed { get; private set; }
    public List<string> Lines { get; } = [];

    public void Check(bool ok, string what)
    {
        Lines.Add((ok ? "  PASS " : "  FAIL ") + what);
        if (ok)
        {
            Passed++;
        }
        else
        {
            Failed++;
        }
    }

    public void NoProblems(Ctx c)
    {
        Check(c.Problems.Count == 0, "no CSP violation, console error or page error");
        foreach (string p in c.Problems)
        {
            Lines.Add("    problem: " + p);
        }
    }
}

internal static class CtxExtensions
{
    /// <summary>The virtual authenticator's credentials and their sign counts: every create and every assertion changes this.</summary>
    public static async Task<(int Credentials, long Signs)> AuthOps(this Ctx c, string? id = null)
    {
        System.Text.Json.JsonElement? reply = await c.Cdp.SendAsync("WebAuthn.getCredentials", new Dictionary<string, object> { ["authenticatorId"] = id ?? c.AuthId });
        System.Text.Json.JsonElement list = reply!.Value.GetProperty("credentials");
        long signs = 0;
        foreach (System.Text.Json.JsonElement item in list.EnumerateArray())
        {
            signs += item.GetProperty("signCount").GetInt64();
        }

        return (list.GetArrayLength(), signs);
    }
}
