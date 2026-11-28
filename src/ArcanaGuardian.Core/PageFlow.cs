using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace ArcanaGuardian;

/// <summary>
/// One command's pages. A command prints ONE link; every step after the first is reached from the page itself: when a step has
/// verified, its reply carries <c>next</c>, the address of the next step's page, which is made at that moment (a new random token on
/// the same server and port). The page navigates to it.
/// <para>
/// The command's code stays sequential (ask, then build the next step). Before a step that is followed by another, the code calls
/// <see cref="Plan" /> with the prefix and the settings of the next page. When the step verifies, <see cref="TakeNext" /> reserves
/// that page (its token exists, its handler does not) and gives its address; the step's reply carries it. A request for the reserved
/// page waits until the command has built the next step and opened it with <see cref="Open" />, which binds the reservation instead
/// of printing a link. Without a reservation, <see cref="Open" /> makes a page of its own and the caller prints its link, as a single
/// page always did. All pages of a flow share one server, so a fixed port works for every step, and one time limit: what a step
/// used is gone for the next.
/// </para>
/// A flow is per command, found through <see cref="Current" /> by the steps that run inside it. The handlers (which run on other
/// threads) are given what they need when they are made.
/// </summary>
internal sealed class PageFlow : IDisposable
{
    private static readonly AsyncLocal<PageFlow?> Active = new();

    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly Lock _gate = new();
    private OneShotServer? _server;
    private (string Prefix, ApprovalSettings Settings)? _plan;
    private PageRoute? _reserved;
    private readonly List<Action> _ends = [];

    private readonly X509Certificate2? _certificate;
    private readonly BrowserPageRouter? _router;

    private PageFlow(X509Certificate2? certificate, BrowserPageRouter? router)
    {
        _certificate = certificate;
        _router = router;
    }

    /// <summary>The flow of the command running on this thread (and the tasks it starts), or null.</summary>
    public static PageFlow? Current => Active.Value;

    /// <summary>Joins the running flow, or starts one that ends (servers closed) when the returned scope is disposed.</summary>
    public static IDisposable Enter(X509Certificate2? certificate = null, BrowserPageRouter? router = null)
    {
        if (Active.Value is not null)
        {
            return new Scope(null);
        }

        PageFlow flow = new(certificate, router);
        Active.Value = flow;

        return new Scope(flow);
    }

    private string? _finalCode;

    /// <summary>
    /// The confirmation code that the next signature page shows once its signature verified (the last page of a command that ends
    /// with a code typed in the terminal). Set by the step that made the code; taken once by the page.
    /// </summary>
    public static void OfferCode(string code)
    {
        if (Current is { } flow)
        {
            lock (flow._gate)
            {
                flow._finalCode = code;
            }
        }
    }

    public string? TakeCode()
    {
        lock (_gate)
        {
            string? code = _finalCode;
            _finalCode = null;

            return code;
        }
    }

    /// <summary>What is left of <paramref name="limit" /> for the command: the time the earlier steps took is gone.</summary>
    public static TimeSpan Left(TimeSpan limit) => Current?.Remaining(limit) ?? limit;

    public TimeSpan Remaining(TimeSpan limit)
    {
        TimeSpan used = _clock.Elapsed;

        return limit > used ? limit - used : TimeSpan.Zero;
    }

    /// <summary>The page after the step that runs now: its path prefix and the settings of the place it is served at (they give its host).</summary>
    public static void Plan(string prefix, ApprovalSettings settings)
    {
        if (Current is { } flow)
        {
            lock (flow._gate)
            {
                flow._plan = (prefix, settings);
            }
        }
    }

    /// <summary>
    /// Called by a step at the moment it verified: reserves the planned page and gives its address, once. Null when no page is
    /// planned (the step is the last one) or the server is not up.
    /// </summary>
    public string? TakeNext()
    {
        lock (_gate)
        {
            if (_plan is not { } plan || _server is null)
            {
                return null;
            }

            _plan = null;
            PageRoute route = _server.Reserve(plan.Prefix);
            _reserved = route;

            return plan.Settings.PageOrigin(_server.Port) + "/" + plan.Prefix + "/" + route.Token;
        }
    }

    /// <summary>Opens a step's page: on the page reserved for it when there is one, else on a new page of the flow's server.</summary>
    private PageSlot OpenCore(string prefix, int port, Func<string, string, string, OneShotResponse> handle)
    {
        lock (_gate)
        {
            if (_server is null)
            {
                _server = _router is { } router ? new OneShotServer(prefix, router, handle) :
                    new OneShotServer(prefix, port, handle, _certificate);

                return new PageSlot(this, _server, null, _server.Token, _server.Port, false);
            }

            if (_reserved is { } route && route.Prefix == prefix)
            {
                _reserved = null;

                return new PageSlot(this, _server, route, route.Token, _server.Port, true, handle);
            }

            PageRoute added = _server.Add(prefix, handle);

            return new PageSlot(this, _server, added, added.Token, _server.Port, false);
        }
    }

    /// <summary>A page for a step: on the running flow's server, or, without a flow, on a server of its own that ends with the slot.</summary>
    public static PageSlot Open(string prefix, int port, Func<string, string, string, OneShotResponse> handle)
    {
        if (Current is { } flow)
        {
            return flow.OpenCore(prefix, port, handle);
        }

        OneShotServer own = new(prefix, port, handle);

        return new PageSlot(null, own, null, own.Token, own.Port, false);
    }

    /// <summary>Runs <paramref name="end" /> when the flow ends (at once when there is no flow, never: the step then has its own server that ends with its slot). For a step to drop what it kept for a resend.</summary>
    public static void OnEnd(Action end)
    {
        if (Current is { } flow)
        {
            lock (flow._gate)
            {
                flow._ends.Add(end);
            }
        }
    }

    internal void Close(OneShotServer server, PageRoute? route)
    {
        if (route is not null)
        {
            server.Remove(route);
        }
        else
        {
            // The first page of the server: it is taken away too, so its token finds nothing; the server stays for the next step.
            server.RemoveFirst();
        }
    }

    public void Dispose()
    {
        OneShotServer? server;
        Action[] ends;
        lock (_gate)
        {
            server = _server;
            _server = null;
            _plan = null;
            _reserved = null;
            ends = [.. _ends];
            _ends.Clear();
        }

        foreach (Action end in ends)
        {
            end();
        }

        server?.Dispose();
    }

    private sealed class Scope(PageFlow? owned) : IDisposable
    {
        public void Dispose()
        {
            if (owned is not null)
            {
                Active.Value = null;
                owned.Dispose();
            }
        }
    }
}

/// <summary>
/// A step's page on a server. <see cref="Reserved" /> is true when the page was reserved by the step before: the person is on
/// it already, so no link is printed. Disposing takes the page away (and, without a flow, closes the server).
/// </summary>
internal sealed class PageSlot(PageFlow? flow, OneShotServer server, PageRoute? route, string token, int port, bool reserved, Func<string, string, string, OneShotResponse>? pending = null) : IDisposable
{
    /// <summary>
    /// Call when the step's session is ready for requests. A reserved page starts answering only now (its requests wait until then),
    /// so a browser that arrived early never meets a session that is not set up. A page made new answers at once.
    /// </summary>
    public void Ready()
    {
        if (pending is not null)
        {
            route?.Bind(pending);
        }
    }

    public string Token => token;

    public int Port => port;

    private bool _keep;

    /// <summary>
    /// Keeps the page on the flow's server after the step ended, until the flow ends. The step's handler then answers the one request that
    /// is still allowed (the same verified body sent again, when its reply was lost); everything else it answers 404.
    /// </summary>
    public PageSlot Keep()
    {
        _keep = flow is not null;

        return this;
    }

    public bool Reserved => reserved;

    public void Dispose()
    {
        if (_keep)
        {
            return;
        }

        if (flow is null)
        {
            server.Dispose();
        }
        else
        {
            flow.Close(server, route);
        }
    }
}

/// <summary>
/// The page side of <see cref="PageFlow" />. The scripts have the line <c>//@FOLLOW@</c> where <c>follow(next)</c> goes (it uses the
/// page's <c>finish</c> and <c>show</c>) and the page has the box <see cref="Box" />. A step that verified answers with <c>next</c>;
/// the page says "Step done. Continuing..." and navigates with <c>location.assign</c>. That is no passkey prompt, so no tap is
/// needed. If the page is still here after 2 seconds (the navigation was blocked), it shows the same address as a link and a
/// Continue button. The address is checked to be http or https and is put in with <c>textContent</c> and <c>href</c>, never as HTML.
/// </summary>
internal static class PageContinue
{
    public const string Token = "//@FOLLOW@";

    /// <summary>The box the link and the button go in, hidden until they are needed.</summary>
    public const string Box = "<div id=\"next\" hidden></div>\n";

    public const string Script = """
        function follow(next) {
                if (typeof next !== "string" || !/^https?:\/\//.test(next)) {
                    finish("The program gave a next step that is not a web address. Nothing more can be done on this page.");
                    return;
                }
                var move = function () { location.assign(next); };
                finish("Step done. Continuing...");
                setTimeout(function () {
                    var box = document.getElementById("next");
                    if (!box || !box.hidden) {
                        return;
                    }
                    var link = document.createElement("a");
                    link.href = next;
                    link.textContent = next;
                    var go = document.createElement("button");
                    go.type = "button";
                    go.textContent = "Continue";
                    go.addEventListener("click", move);
                    box.appendChild(link);
                    box.appendChild(document.createTextNode(" "));
                    box.appendChild(go);
                    box.hidden = false;
                    show("Step done. The next step did not open by itself: use the link or the Continue button.");
                }, 2000);
                move();
            }
        """;

    /// <summary>The script with <c>follow</c> in place of the token. Line endings are the caller's business.</summary>
    public static string Fill(string script) => script.Replace(Token, Script, StringComparison.Ordinal);
}
