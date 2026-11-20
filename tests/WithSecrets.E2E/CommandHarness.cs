using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Microsoft.Playwright;

namespace WithSecrets.E2E;

/// <summary>
/// Runs one real command (here: first-run setup) in-process against a temp state folder, with the terminal replaced by the test:
/// lines the program writes are captured (the link is read from them) and the typed confirmation code is fed from the test.
/// Never touches ~/.with-secrets.
/// </summary>
internal sealed class CommandRun : IDisposable
{
    private readonly StringWriter _stderr = new();
    private readonly TaskCompletionSource<string> _link = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<string> _typed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public string Folder { get; } = Path.Combine(Path.GetTempPath(), "ws-e2e-" + Guid.NewGuid().ToString("N"));
    public StateDatabase State { get; }
    public Task<ConfigChange> Result { get; }
    public int Port { get; } = FreePort();

    public CommandRun()
    {
        State = StateDatabase.InFolder(Folder);
        TerminalPrompt.Output = _stderr;
        TerminalPrompt.Input = () => _typed.Task.GetAwaiter().GetResult();
        Result = Task.Run(Config);
    }

    private static int FreePort()
    {
        TcpListener l = new(IPAddress.Loopback, 0);
        l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();

        return p;
    }

    // The same wiring as HumanCommands.Config in src/WithSecrets/Program.cs.
    private ConfigChange Config()
    {
        ToolSettings settings = ToolSettings.Load(State, out _);
        ApprovalSettings approval = settings.Approval with { Port = Port };
        int asked = 0;
        Func<string?> readCode = () => TerminalPrompt.ReadCode(asked++ > 0);
        void Announce(string line)
        {
            TerminalPrompt.Line(line);
            Match m = Regex.Match(line, @"https?://\S+");
            if (m.Success)
            {
                _link.TrySetResult(m.Value);
            }
        }

        PasskeyStore passkeys = new(State);
        EnrollmentTarget Target(ApprovalSettings s)
        {
            PasskeyMethod method = new(passkeys, s, readCode);

            return EnrollmentTarget.For(method, new WebApprover(method, s, Announce));
        }

        return new FirstRunPage(State, Target(approval), Target(approval with { BaseUrl = null }), Announce, readCode).Run();
    }

    public async Task<string> LinkAsync() => await _link.Task.WaitAsync(TimeSpan.FromSeconds(30));

    /// <summary>Test code only: feeds the confirmation code read from the page to the process input. Never printed.</summary>
    public void Type(string code) => _typed.TrySetResult(code);

    public void Dispose()
    {
        TerminalPrompt.Output = null;
        TerminalPrompt.Input = null;
        try { Directory.Delete(Folder, true); } catch { }
    }
}

/// <summary>A headless Chromium page with a CDP virtual authenticator and a record of console messages and page errors.</summary>
internal sealed class BrowserSession : IAsyncDisposable
{
    private IPlaywright _pw = null!;
    private IBrowser _browser = null!;
    public IPage Page { get; private set; } = null!;
    public ICDPSession Cdp { get; private set; } = null!;
    public List<string> Problems { get; } = [];
    public List<string> Console { get; } = [];
    public string BrowserVersion => _browser.Version;

    public static async Task<BrowserSession> StartAsync(bool hasPrf)
    {
        BrowserSession s = new() { _pw = await Playwright.CreateAsync() };
        s._browser = await s._pw.Chromium.LaunchAsync(new() { Headless = true });
        IBrowserContext ctx = await s._browser.NewContextAsync();
        s.Page = await ctx.NewPageAsync();
        s.Page.Console += (_, m) =>
        {
            s.Console.Add($"{m.Type}: {m.Text}");
            if (m.Type is "error" || m.Text.Contains("Content Security Policy", StringComparison.OrdinalIgnoreCase) || m.Text.Contains("Refused to", StringComparison.OrdinalIgnoreCase))
            {
                s.Problems.Add("console " + m.Type + ": " + m.Text);
            }
        };
        s.Page.PageError += (_, e) => s.Problems.Add("pageerror: " + e);
        s.Cdp = await ctx.NewCDPSessionAsync(s.Page);
        await s.Cdp.SendAsync("WebAuthn.enable");
        await s.Cdp.SendAsync("WebAuthn.addVirtualAuthenticator", new Dictionary<string, object>
        {
            ["options"] = new Dictionary<string, object>
            {
                ["protocol"] = "ctap2",
                ["transport"] = "internal",
                ["hasResidentKey"] = true,
                ["hasUserVerification"] = true,
                ["isUserVerified"] = true,
                ["automaticPresenceSimulation"] = true,
                ["hasPrf"] = hasPrf,
            },
        });

        return s;
    }

    public async ValueTask DisposeAsync()
    {
        await _browser.CloseAsync();
        _pw.Dispose();
    }
}
