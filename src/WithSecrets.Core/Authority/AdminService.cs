using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>What the admin page and <c>GET /v1/status</c> report. Nothing here is sensitive.</summary>
public sealed record AuthorityStatus(bool Locked, UnlockMethod? How, UnlockPolicy Policy);

/// <summary>The answer to a request to start an operation: a link to the one-use passkey page, or why none was made.</summary>
public sealed record AdminStart(string? Link, string? Error, int Status = 200);

/// <summary>
/// The authority's minimal administration, served by the service on its own loopback port: <c>GET /admin</c> (status: running, locked or unlocked, the unlock mode shown
/// visibly) and <c>POST /admin/op</c> to start Unlock, Lock or a change of the unlock policy. Each operation is its own fresh passkey ceremony: the call returns the link to a
/// one-use page whose signed text names the operation and its parameters (<see cref="AdminAuthorizer" />), and the operation is applied only after an enrolled admin key's
/// verified assertion for exactly that page. Opening this page, being unlocked, or having tapped for something else authorizes nothing. This is the seed of the full
/// admin interface (Phase 6): more operations are added to <see cref="Start" /> the same way.
/// </summary>
public sealed class AdminService(AuthorityStore store, AuthorityLock lockState, AdminAuthorizer authorizer, Func<Action<string>, IAdminAsker> askers, IUnlockProtection protection, Action onUnlocked, int port)
{
    public const string OpUnlock = "unlock";
    public const string OpLock = "lock";
    public const string OpPolicyManual = "policy-manual";
    public const string OpPolicyUnattended = "policy-unattended";

    private const string Heading = "Check this change to the authority. Nothing is changed unless you approve here with your passkey.";
    private static readonly TimeSpan LinkWait = TimeSpan.FromSeconds(30);

    /// <summary>How long a second operation waits for the one whose passkey page is still open before it is told to try again.</summary>
    private static readonly TimeSpan BusyWait = TimeSpan.FromSeconds(8);

    private readonly SemaphoreSlim _busy = new(1, 1);

    /// <summary>The authority's page, for the message of a refused run and the startup lines. Public; it carries nothing.</summary>
    public string PageUrl => $"http://localhost:{port}/admin";

    public AuthorityStatus Status() => new(lockState.IsLocked, lockState.How, store.GetUnlockPolicy());

    /// <summary>Starts an operation. The returned link is the page that asks for the passkey; the operation runs in the background and is applied only after that page's verified tap.</summary>
    public async Task<AdminStart> StartAsync(string op, CancellationToken cancel)
    {
        (string Operation, string Sentence, IReadOnlyList<(string Name, string Value)> Parameters, Func<VerifiedAdmin, string?> Apply, byte[]? Material)? plan = Plan(op, out string? refusal);
        if (plan is null)
        {
            return new AdminStart(null, refusal, refusal is "unknown operation" ? 400 : 409);
        }

        if (!await _busy.WaitAsync(BusyWait, cancel))
        {
            return new AdminStart(null, "another administrator operation is waiting for its passkey page; finish or let it time out first", 409);
        }

        TaskCompletionSource<string> link = new(TaskCreationOptions.RunContinuationsAsynchronously);
        IAdminAsker asker = askers(text => link.TrySetResult(text));
        (string operation, string sentence, IReadOnlyList<(string, string)> parameters, Func<VerifiedAdmin, string?> apply, byte[]? material) = plan.Value;
        Task done = Task.Run(() =>
        {
            try
            {
                AdminAuthorization authorized = authorizer.Authorize(asker, Heading, sentence, operation, parameters);
                if (authorized.Admin is { } admin)
                {
                    string? failure = null;
                    try
                    {
                        failure = apply(admin);
                    }
                    catch (Exception error) when (error is not OutOfMemoryException)
                    {
                        failure = error is AuthorityDatabaseException ? error.Message : "the change failed (" + error.GetType().Name + ")";
                    }

                    authorizer.Outcome(admin, failure is null ? "applied" : "failed: " + failure);
                }

                link.TrySetResult("done: " + authorized.Detail);
            }
            finally
            {
                if (material is not null)
                {
                    CryptographicOperations.ZeroMemory(material);
                }

                _busy.Release();
            }
        }, CancellationToken.None);

        Task first = await Task.WhenAny(link.Task, Task.Delay(LinkWait, cancel));
        if (first != link.Task)
        {
            return new AdminStart(null, "the passkey page was not made in time", 504);
        }

        string text = link.Task.Result;
        if (text.StartsWith("done: ", StringComparison.Ordinal))
        {
            // Finished without a page: the asker refused (for example no passkey is enrolled), so nothing changed.
            _ = done;

            return new AdminStart(null, text["done: ".Length..], 409);
        }

        int at = text.IndexOf("http", StringComparison.Ordinal);

        return at < 0 ? new AdminStart(null, "the passkey page was not made", 500) : new AdminStart(text[at..], null);
    }

    private (string Operation, string Sentence, IReadOnlyList<(string Name, string Value)> Parameters, Func<VerifiedAdmin, string?> Apply, byte[]? Material)? Plan(string op, out string? refusal)
    {
        refusal = null;
        string key = store.ActiveKey()?.Fingerprint is { } fingerprint ? KeyIdentity.Display(fingerprint) : "(none yet)";
        switch (op)
        {
            case OpUnlock:
                if (!lockState.IsLocked)
                {
                    refusal = "the authority is already unlocked";

                    return null;
                }

                return ("unlock-authority",
                    "unlock the authority so that it serves secret requests again. It creates no grant and widens none; every sensitive change still needs its own passkey tap",
                    [("authority-key", key)],
                    _ =>
                    {
                        lockState.Unlock(UnlockMethod.Manual);
                        onUnlocked();

                        return null;
                    },
                    null);

            case OpLock:
                if (lockState.IsLocked)
                {
                    refusal = "the authority is already locked";

                    return null;
                }

                return ("lock-authority",
                    "lock the authority now: secret requests stop, the held keys, the offline lease and the synchronized grants are discarded",
                    [("authority-key", key)],
                    _ =>
                    {
                        lockState.Lock("locked by an administrator");

                        return null;
                    },
                    null);

            case OpPolicyManual:
                if (store.GetUnlockPolicy() == UnlockPolicy.Manual)
                {
                    refusal = "unlock is manual already";

                    return null;
                }

                return Policy(UnlockPolicy.Manual, "make unlock manual again: after a start an administrator unlocks with a passkey tap, and the unattended-unlock material is deleted", null, null);

            case OpPolicyUnattended:
                if (store.GetUnlockPolicy() == UnlockPolicy.Unattended)
                {
                    refusal = "unlock is unattended already";

                    return null;
                }

                if (protection.Unavailable is { } unavailable)
                {
                    refusal = unavailable;

                    return null;
                }

                byte[] material = RandomNumberGenerator.GetBytes(32);
                try
                {
                    byte[] sealedBlob = protection.Seal(material);

                    return Policy(UnlockPolicy.Unattended,
                        "let the authority unlock itself after it starts, using material that " + protection.Name + " protects for this user. This is WEAKER than manual unlock: anything that can run as this user can unlock the service the same way. It does not remove the passkey tap for sensitive changes and creates no grant",
                        sealedBlob, Convert.ToHexString(SHA256.HashData(material)), material);
                }
                catch (Exception error) when (error is CryptographicException or InvalidOperationException)
                {
                    CryptographicOperations.ZeroMemory(material);
                    refusal = "the platform could not protect the unlock material (" + error.GetType().Name + ")";

                    return null;
                }

            default:
                refusal = "unknown operation";

                return null;
        }

        (string, string, IReadOnlyList<(string, string)>, Func<VerifiedAdmin, string?>, byte[]?)? Policy(UnlockPolicy policy, string sentence, byte[]? sealedBlob, string? verifier, byte[]? material = null)
        {
            (string operation, IReadOnlyList<(string Name, string Value)> parameters) = AuthorityStore.PolicyOperation(policy);

            return (operation, sentence, parameters, admin =>
            {
                store.SetUnlockPolicy(policy, sealedBlob, verifier, admin);

                return null;
            }, material);
        }
    }

    /// <summary>The routes of the admin web app (GET): path, title. Phase 6 adds machines, grants and the rest here; each sensitive action on them is a fresh operation-bound passkey tap like the three here.</summary>
    public static readonly IReadOnlyList<(string Path, string Title)> Pages = [("/admin", "Status"), ("/admin/audit", "Audit")];

    /// <summary>The page of a GET route, or null when there is none. <paramref name="nonce" /> is the script nonce of the response.</summary>
    public string? Page(string path, string nonce) => path switch
    {
        "/admin" => Layout("/admin", Root(), nonce, Script),
        "/admin/audit" => Layout("/admin/audit", AuditBody(), nonce, null),
        _ => null,
    };

    /// <summary>Back-compatible name for the root page.</summary>
    public string Html(string nonce) => Page("/admin", nonce)!;

    private string Layout(string current, string body, string nonce, string? script)
    {
        StringBuilder html = new();
        html.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>with-secrets authority</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
            .Append("<style>body{font:16px system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}.weak{color:#8a3b00;font-weight:600}button{font:inherit;margin:.25rem .5rem .25rem 0;padding:.5rem 1rem}#msg{margin-top:1rem;min-height:1.5rem}nav a{margin-right:1rem}table{border-collapse:collapse;width:100%;font-size:.9rem}td,th{border-bottom:1px solid #ccc;padding:.25rem .5rem;text-align:left;vertical-align:top}</style></head><body>")
            .Append("<h1>with-secrets authority</h1><nav>");
        foreach ((string path, string title) in Pages)
        {
            html.Append("<a href=\"").Append(path).Append("\"").Append(path == current ? " aria-current=\"page\"" : "").Append('>').Append(WebUtility.HtmlEncode(title)).Append("</a>");
        }

        html.Append("</nav>").Append(body);
        if (script is not null)
        {
            html.Append("<script nonce=\"").Append(nonce).Append("\">").Append(script).Append("</script>");
        }

        return html.Append("</body></html>").ToString();
    }

    private const string Script = "for(const b of document.querySelectorAll('button')){b.onclick=async()=>{const m=document.getElementById('msg');m.textContent='';"
        + "try{const r=await fetch('/admin/op',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({op:b.dataset.op})});"
        + "const j=await r.json();if(j.link){location.href=j.link}else{m.textContent=j.error||'Not started.'}}catch(e){m.textContent='Not started.'}}}";

    private string Root()
    {
        AuthorityStatus status = Status();
        string state = status.Locked ? "LOCKED" : "Unlocked" + (status.How is { } how ? " (" + how.ToString().ToLowerInvariant() + ")" : "");
        string weaker = status.Policy == UnlockPolicy.Unattended ? " class=\"weak\"" : "";
        StringBuilder html = new();
        html.Append("<p>Status: running, <strong id=\"state\">").Append(WebUtility.HtmlEncode(state)).Append("</strong></p>")
            .Append("<p>Unlock mode: <span").Append(weaker).Append('>').Append(WebUtility.HtmlEncode(UnlockPolicies.Describe(status.Policy))).Append("</span></p>")
            .Append("<p>Every button below opens a one-use page where you approve that one change with your passkey. Nothing changes without it.</p>")
            .Append(status.Locked ? "<button data-op=\"unlock\">Unlock</button>" : "<button data-op=\"lock\">Lock now</button>")
            .Append(status.Policy == UnlockPolicy.Unattended
                ? "<button data-op=\"policy-manual\">Make unlock manual</button>"
                : "<button data-op=\"policy-unattended\">Allow unattended unlock (weaker)</button>")
            .Append("<div id=\"msg\" role=\"status\"></div>");

        return html.ToString();
    }

    /// <summary>Read-only: the authority's own audit history, newest first (machine and grant changes, key changes, and every attempt at a sensitive administrator operation with its outcome). No proof, code, key or secret is in it.</summary>
    private string AuditBody()
    {
        StringBuilder html = new("<h2>Authority audit history</h2><p>Read-only. Newest first, at most 200.</p><table><tr><th>Time (UTC)</th><th>Event</th><th>Actor</th><th>Detail</th></tr>");
        foreach (AuditEntry entry in store.Audit(200))
        {
            html.Append("<tr><td>").Append(WebUtility.HtmlEncode(entry.Time.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture)))
                .Append("</td><td>").Append(WebUtility.HtmlEncode(ApprovalSummary.Clean(entry.Event)))
                .Append("</td><td>").Append(WebUtility.HtmlEncode(ApprovalSummary.Clean(entry.Actor)))
                .Append("</td><td>").Append(WebUtility.HtmlEncode(ApprovalSummary.Clean(entry.Detail))).Append("</td></tr>");
        }

        return html.Append("</table>").ToString();
    }
}
