using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace WithSecrets.E2E;

/// <summary>A TextWriter that keeps what was written (thread safe), for the terminal of one command.</summary>
internal sealed class Terminal : TextWriter
{
    private readonly StringBuilder _text = new();

    public override Encoding Encoding => Encoding.UTF8;

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
    }

    public override void Write(string? value)
    {
        lock (_text)
        {
            _text.Append(value);
        }
    }
}

/// <summary>One scenario's state: a temp state folder (never the real .with-secrets), the store and a free port per command.</summary>
internal sealed class Rig : IDisposable
{
    public string Folder { get; } = Path.Combine(Path.GetTempPath(), "ws-e2e-" + Guid.NewGuid().ToString("N"));
    public string Work { get; } = Path.Combine(Path.GetTempPath(), "ws-e2e-work-" + Guid.NewGuid().ToString("N"));
    public StateDatabase State => StateDatabase.InFolder(Folder);
    public SecretStore Store => new(State);
    public GrantStore Grants => new(State);

    private E2EMachine? _machine;

    /// <summary>The machine of this rig: enrolled and approved once, kept for every run of the rig.</summary>
    public E2EMachine Machine => _machine ??= new E2EMachine(Folder);

    public Rig() => Directory.CreateDirectory(Work);

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

internal sealed class Host : IAsyncDisposable
{
    public IPlaywright Pw { get; private set; } = null!;
    public IBrowser Browser { get; private set; } = null!;

    public static async Task<Host> StartAsync()
    {
        Host host = new() { Pw = await Playwright.CreateAsync() };
        // Headless: the chromium headless shell (installed with `install --only-shell chromium`).
        host.Browser = await host.Pw.Chromium.LaunchAsync(new() { Headless = true });

        return host;
    }

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
    public List<string> Problems { get; } = [];
    public List<string> Console { get; } = [];

    public static Ctx? Last { get; private set; }

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

            return "    page: " + await Page.TitleAsync() + " | " + Regex.Replace(Page.Url, "/[A-Za-z0-9_-]{20,}", "/<token>") + " | buttons " + buttons + " | status: " + status + dialog + " | console: " + string.Join(" // ", Console);
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
        c.Context = await host.Browser.NewContextAsync();
        await c.Context.AddInitScriptAsync(InitScript);
        c.Page = await c.Context.NewPageAsync();
        c.Page.Console += (_, m) =>
        {
            c.Console.Add(m.Type + ": " + m.Text);
            bool bad = m.Type == "error" || m.Text.Contains("Content Security Policy", StringComparison.OrdinalIgnoreCase) || m.Text.Contains("Refused to", StringComparison.OrdinalIgnoreCase);
            if (bad && !c._ignore.Any(i => m.Text.Contains(i, StringComparison.Ordinal)))
            {
                c.Problems.Add("console " + m.Type + ": " + m.Text);
            }
        };
        c.Page.PageError += (_, e) => c.Problems.Add("pageerror: " + e);
        c.Page.RequestFailed += (_, r) => c.Console.Add("requestfailed: " + Regex.Replace(r.Url, "/[A-Za-z0-9_-]{20,}", "/<token>") + " " + r.Failure);
        c.Cdp = await c.Context.NewCDPSessionAsync(c.Page);
        await c.Cdp.SendAsync("WebAuthn.enable");
        c.AuthId = await c.AddAuthenticator(hasPrf);

        return c;
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

        return await Text(selector);
    }

    public async Task StatusContains(string part, int ms = 20000)
    {
        await Page.WaitForFunctionAsync("p => { var e = document.getElementById('status'); return !!e && e.textContent.indexOf(p) >= 0; }", part, new() { Timeout = ms });
    }

    public Task Click(string selector, int ms = 20000) => Page.Locator(selector).ClickAsync(new() { Timeout = ms });

    /// <summary>The context stays open until the runner closed it (a failure report reads the page first).</summary>
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    public Task CloseAsync() => Context.CloseAsync();
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
