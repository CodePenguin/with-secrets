using System.Globalization;
using System.Net;
using System.Text;

namespace WithSecrets;

/// <summary>
/// The pages of the admin web app: plain server-rendered HTML, one small script (with the response's nonce), no external asset, no secret value anywhere. Every view but the public status
/// page is served only to a caller with a session (see <see cref="AdminWeb" />). A button never changes anything by itself: it asks the service to start an operation, which then
/// asks for its own fresh passkey tap on a one-use page.
/// </summary>
public sealed partial class AdminService
{
    /// <summary>The routes of the admin web app (GET): path, title. <c>/admin</c> is the only one that answers without a session (public status, sign in, unlock).</summary>
    public static readonly IReadOnlyList<(string Path, string Title)> Pages = [("/admin", "Status"), ("/admin/machines", "Machines"), ("/admin/grants", "Grants"), ("/admin/audit", "Audit"), ("/admin/settings", "Settings"), ("/admin/passkeys", "Passkeys")];

    /// <summary>The page of a GET route for a caller, or null when there is none. Views other than the status page need <paramref name="session" />. <paramref name="query" /> reads a query parameter.</summary>
    internal string? Page(string path, string nonce, AdminSession? session, string csrf, Func<string, string?> query, string? loginProblem = null)
    {
        if (path == "/admin")
        {
            return Layout("/admin", session, Root(session, loginProblem), nonce, csrf);
        }

        if (session is null)
        {
            return null;
        }

        string? body = path switch
        {
            "/admin/machines" => MachinesBody(),
            "/admin/grants" => GrantsBody(),
            "/admin/audit" => AuditBody(query),
            "/admin/settings" => SettingsBody(),
            "/admin/passkeys" => PasskeysBody(),
            _ => null,
        };

        return body is null ? null : Layout(path, session, body, nonce, csrf);
    }

    /// <summary>The page shown to a request with no session for a view that needs one.</summary>
    internal string SignInRequired(string nonce) => Layout("", null, "<p>This view needs an administrator session. <a href=\"/admin\">Sign in on the status page</a> with your passkey.</p>", nonce, "");

    private static string E(string? text) => WebUtility.HtmlEncode(ApprovalSummary.Clean(text ?? ""));

    private static string Time(DateTimeOffset time) => time.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    private string Layout(string current, AdminSession? session, string body, string nonce, string csrf)
    {
        StringBuilder html = new();
        html.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>with-secrets authority</title><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        if (csrf.Length > 0)
        {
            html.Append("<meta name=\"anti-forgery\" content=\"").Append(WebUtility.HtmlEncode(csrf)).Append("\">");
        }

        html.Append("<style>body{font:16px system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem}.weak{color:#8a3b00;font-weight:600}button{font:inherit;margin:.25rem .5rem .25rem 0;padding:.35rem .8rem}input,select{font:inherit;padding:.25rem}#msg{margin-top:1rem;min-height:1.5rem}nav a{margin-right:1rem}table{border-collapse:collapse;width:100%;font-size:.9rem}td,th{border-bottom:1px solid #ccc;padding:.25rem .5rem;text-align:left;vertical-align:top}code{word-break:break-all}.who{float:right;font-size:.9rem}</style></head><body>")
            .Append("<h1>with-secrets authority</h1>");
        if (session is not null)
        {
            html.Append("<div class=\"who\">Signed in as ").Append(E(session.Admin)).Append(" (read-only session) <button id=\"logout\">Sign out</button></div>");
        }

        html.Append("<nav>");
        foreach ((string path, string title) in Pages)
        {
            if (path != "/admin" && session is null)
            {
                continue;
            }

            html.Append("<a href=\"").Append(path).Append("\"").Append(path == current ? " aria-current=\"page\"" : "").Append('>').Append(WebUtility.HtmlEncode(title)).Append("</a>");
        }

        html.Append("</nav>").Append(body);
        if (csrf.Length > 0)
        {
            html.Append("<script nonce=\"").Append(nonce).Append("\">").Append(Script).Append("</script>");
        }

        return html.Append("</body></html>").ToString();
    }

    /// <summary>
    /// The page's one script. A button with <c>data-op</c> asks <c>POST /admin/op</c> with its other data-* values (and the values of the inputs named in <c>data-inputs</c>) and the page's
    /// anti-forgery value, then goes to the one-use passkey page the answer names. Sign-in and sign-out are the same kind of request. It sends nothing else anywhere.
    /// </summary>
    private const string Script = "(function(){const csrf=document.querySelector('meta[name=anti-forgery]').content;const m=document.getElementById('msg');"
        + "async function post(url,body){try{const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Token':csrf},body:JSON.stringify(body)});const j=await r.json();return {s:r.status,j:j}}catch(e){return {s:0,j:{error:'Not started.'}}}}"
        + "function show(t){if(m){m.textContent=t}}"
        + "for(const b of document.querySelectorAll('button[data-op]')){b.onclick=async()=>{show('');const body={op:b.dataset.op};for(const k of Object.keys(b.dataset)){if(k!=='op'&&k!=='inputs'){body[k]=b.dataset[k]}}"
        + "if(b.dataset.inputs){for(const id of b.dataset.inputs.split(',')){const el=document.getElementById(id);if(el){body[el.name]=el.type==='checkbox'?String(el.checked):el.value}}}"
        + "const a=await post('/admin/op',body);if(a.j.link){location.href=a.j.link}else{show(a.j.error||'Not started.')}}}"
        + "const li=document.getElementById('login');if(li){li.onclick=async()=>{show('');const a=await post('/admin/login',{});if(a.j.link){location.href=a.j.link}else{show(a.j.error||'Not started.')}}}"
        + "const lo=document.getElementById('logout');if(lo){lo.onclick=async()=>{await post('/admin/logout',{});location.href='/admin'}}})();";

    private string Root(AdminSession? session, string? loginProblem)
    {
        AuthorityStatus status = Status();
        string state = status.Locked ? "LOCKED" : "Unlocked" + (status.How is { } how ? " (" + how.ToString().ToLowerInvariant() + ")" : "");
        string weaker = status.Policy == UnlockPolicy.Unattended ? " class=\"weak\"" : "";
        StringBuilder html = new();
        html.Append("<p>Status: running, <strong id=\"state\">").Append(WebUtility.HtmlEncode(state)).Append("</strong></p>")
            .Append("<p>Unlock mode: <span").Append(weaker).Append('>').Append(WebUtility.HtmlEncode(UnlockPolicies.Describe(status.Policy))).Append("</span></p>");
        if (loginProblem is not null)
        {
            html.Append("<p id=\"login-problem\" class=\"weak\">Sign-in did not complete: ").Append(E(loginProblem)).Append("</p>");
        }

        if (status.Locked)
        {
            html.Append("<p>The authority is locked: it serves nothing secret-related and no session can start. Unlocking opens a one-use page where you approve that one change with your passkey.</p><button data-op=\"unlock\">Unlock</button>");
        }
        else if (session is null)
        {
            html.Append("<p>Sign in with one passkey tap to read machines, grants, the audit history and the settings. A session only reads: every change asks for its own passkey tap on its own page.</p><button id=\"login\">Sign in with passkey</button>");
        }
        else
        {
            (int idle, int absolute) = _p.Store.SessionTimeouts();
            html.Append("<p>Your session reads only. It ends after ").Append(idle.ToString(CultureInfo.InvariantCulture)).Append(" minutes without use, ").Append(absolute.ToString(CultureInfo.InvariantCulture)).Append(" minutes after it started, on lock, on sign out and when the service restarts. Every button on these pages opens a one-use page where you approve that one change with your passkey.</p>")
                .Append("<button data-op=\"lock\">Lock now</button>");
            IReadOnlyList<string> recent = Recent;
            if (recent.Count > 0)
            {
                html.Append("<h2>Recent operations</h2><ul id=\"recent\">");
                foreach (string line in recent)
                {
                    html.Append("<li>").Append(E(line)).Append("</li>");
                }

                html.Append("</ul>");
            }
        }

        return html.Append("<div id=\"msg\" role=\"status\"></div>").ToString();
    }

    // ---- machines ----

    private string MachinesBody()
    {
        IReadOnlyList<MachineRecord> machines = _p.Store.Machines();
        StringBuilder html = new("<h2>Machines</h2>");
        if (machines.Count == 0)
        {
            html.Append("<p>No machine has contacted the authority yet. Start the host service (with-secrets service); it enrolls this machine as Pending.</p>");
        }
        else
        {
            html.Append("<table id=\"machines\"><tr><th>Fingerprint</th><th>Status</th><th>Rev</th><th>Host name</th><th>Name</th><th>Change</th></tr>");
            int row = 0;
            foreach (MachineRecord machine in machines)
            {
                row++;
                string fp = machine.Fingerprint;
                html.Append("<tr data-fingerprint=\"").Append(fp).Append("\"><td><code>").Append(WebUtility.HtmlEncode(KeyIdentity.Display(fp))).Append("</code></td><td>").Append(machine.Status).Append("</td><td>")
                    .Append(machine.SecurityRevision.ToString(CultureInfo.InvariantCulture)).Append("</td><td>").Append(E(machine.HostName));
                if (machine.PendingHostName is not null)
                {
                    html.Append("<br>host name change waiting: <strong>").Append(E(machine.PendingHostName)).Append("</strong>");
                }

                html.Append("</td><td>").Append(machine.FriendlyName is null ? "(none)" : E(machine.FriendlyName)).Append("</td><td>");
                bool repin = machine.Status == MachineStatus.Trusted && machine.Fingerprint == _p.LocalFingerprint;
                if (machine.Status == MachineStatus.Pending)
                {
                    html.Append("<input id=\"name").Append(row).Append("\" name=\"name\" placeholder=\"friendly name\" maxlength=\"40\"> <button data-op=\"machine-approve\" data-fingerprint=\"").Append(fp).Append("\" data-inputs=\"name").Append(row).Append("\">Approve</button>");
                }

                if (repin)
                {
                    html.Append("<button data-op=\"machine-approve\" data-fingerprint=\"").Append(fp).Append("\">Re-pin authority key</button>");
                }

                foreach ((string verb, string label) in new[] { ("disable", "Disable"), ("enable", "Enable"), ("untrust", "Untrust") })
                {
                    if (AuthorityStore.TransitionProblem(verb, machine) is null)
                    {
                        html.Append("<button data-op=\"machine-").Append(verb).Append("\" data-fingerprint=\"").Append(fp).Append("\">").Append(label).Append("</button>");
                    }
                }

                if (machine.Status == MachineStatus.Untrusted)
                {
                    html.Append("<br><input id=\"confirm").Append(row).Append("\" name=\"confirm\" size=\"72\" placeholder=\"type the full fingerprint to confirm\" autocomplete=\"off\"> <button data-op=\"machine-trust\" data-fingerprint=\"").Append(fp).Append("\" data-inputs=\"confirm").Append(row).Append("\">Trust again</button>");
                }

                if (machine.PendingHostName is not null)
                {
                    html.Append("<br><button data-op=\"machine-host-change\" data-fingerprint=\"").Append(fp).Append("\">Approve host name change</button>");
                }

                html.Append("<br><input id=\"rename").Append(row).Append("\" name=\"name\" placeholder=\"new friendly name\" maxlength=\"40\"> <button data-op=\"machine-rename\" data-fingerprint=\"").Append(fp).Append("\" data-inputs=\"rename").Append(row).Append("\">Rename</button>");
                html.Append("</td></tr>");
            }

            html.Append("</table>");
        }

        return html.Append("<div id=\"msg\" role=\"status\"></div>").ToString();
    }

    // ---- grants ----

    private string GrantsBody()
    {
        DateTimeOffset now = _clock.GetUtcNow();
        IReadOnlyList<GrantRecord> grants = _p.Store.Grants();
        StringBuilder html = new("<h2>Grants</h2>");
        if (grants.Count == 0)
        {
            html.Append("<p>No grants. A person makes one with: with-secrets approve --secrets NAME --reason TEXT -- PROGRAM [ARGS...]</p>");
        }
        else
        {
            html.Append("<table id=\"grants\"><tr><th>Id</th><th>State</th><th>Rev</th><th>Ends</th><th>Machine</th><th>Secrets</th><th>Program</th><th>Folder</th><th>Change</th></tr>");
            int row = 0;
            foreach (GrantRecord grant in grants)
            {
                row++;
                MachineRecord? machine = _p.Store.Find(grant.Fingerprint);
                html.Append("<tr data-grant=\"").Append(E(grant.Id)).Append("\"><td><code>").Append(E(grant.Id)).Append("</code></td><td>").Append(GrantState(grant, now)).Append("</td><td>").Append(grant.Revision.ToString(CultureInfo.InvariantCulture)).Append("</td><td>")
                    .Append(E(GrantEnds(grant, now))).Append("</td><td>").Append(WebUtility.HtmlEncode(KeyIdentity.Display(grant.Fingerprint)[..19])).Append(' ').Append(machine?.FriendlyName is { } friendly ? E(friendly) : "(machine)").Append("</td><td>")
                    .Append(E(grant.SecretNames)).Append("</td><td>").Append(E(grant.Program)).Append("</td><td>").Append(E(grant.WorkingDirectory)).Append("</td><td>");
                foreach ((string verb, string label) in new[] { ("extend", "Extend"), ("renew", "Renew") })
                {
                    if (GrantProblem(verb, grant, now) is null)
                    {
                        html.Append("<input id=\"min").Append(verb).Append(row).Append("\" name=\"minutes\" size=\"5\" value=\"30\" inputmode=\"numeric\"> min <button data-op=\"grant-").Append(verb).Append("\" data-id=\"").Append(E(grant.Id)).Append("\" data-inputs=\"min").Append(verb).Append(row).Append("\">").Append(label).Append("</button><button data-op=\"grant-")
                            .Append(verb).Append("\" data-id=\"").Append(E(grant.Id)).Append("\" data-indefinite=\"true\">").Append(label).Append(": no end</button><br>");
                    }
                }

                if (GrantProblem("revoke", grant, now) is null)
                {
                    html.Append("<button data-op=\"grant-revoke\" data-id=\"").Append(E(grant.Id)).Append("\">Revoke</button>");
                }

                html.Append("</td></tr>");
            }

            html.Append("</table>");
        }

        return html.Append("<div id=\"msg\" role=\"status\"></div>").ToString();
    }

    // ---- audit ----

    /// <summary>The audit filters of a request, or why not. All optional. <c>last</c> is 1 to 1000 (default 100). A time is ISO 8601 (UTC when no zone is given).</summary>
    internal static (AuditQuery? Query, bool Gaps, string? Error) ParseAuditQuery(Func<string, string?> get)
    {
        static string? Text(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        DateTimeOffset? since = null;
        DateTimeOffset? until = null;
        foreach (string name in new[] { "since", "until" })
        {
            if (Text(get(name)) is { } value)
            {
                if (!DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset parsed))
                {
                    return (null, false, name + " takes a time in ISO 8601 form, for example 2026-11-01 or 2026-11-01T09:30:00Z");
                }

                if (name == "since")
                {
                    since = parsed;
                }
                else
                {
                    until = parsed;
                }
            }
        }

        int last = 100;
        if (Text(get("last")) is { } lastText && (!int.TryParse(lastText, NumberStyles.None, CultureInfo.InvariantCulture, out last) || last < 1 || last > AuditQuery.MaxLimit))
        {
            return (null, false, "last takes a number from 1 to " + AuditQuery.MaxLimit);
        }

        string? type = Text(get("type"));
        if (type is not null && !AuditEventTypes.All.Contains(type))
        {
            return (null, false, "type is authorization, launch or execution");
        }

        bool gaps = Text(get("gaps")) is "1" or "true" or "on";

        return (new AuditQuery(Text(get("machine")), since, until, type, Text(get("outcome")), Text(get("grant")), Text(get("folder")), Text(get("text")), last), gaps, null);
    }

    private string AuditBody(Func<string, string?> query)
    {
        (AuditQuery? parsed, bool gaps, string? error) = ParseAuditQuery(query);
        StringBuilder html = new("<h2>Audit history</h2><p>Read-only. The host events the authority holds (every run's authorization, launch and execution outcome), the holes in a machine's numbering, and the authority's own changes. No secret value, proof or key is in any of it.</p>");
        html.Append("<form method=\"get\" action=\"/admin/audit\" id=\"audit-filter\">");
        foreach ((string name, string label) in new[] { ("machine", "Machine (fingerprint start)"), ("since", "Since (UTC)"), ("until", "Until (UTC)"), ("outcome", "Outcome"), ("grant", "Grant id"), ("folder", "Folder contains"), ("text", "Text"), ("last", "Most (1-1000)") })
        {
            html.Append("<label>").Append(label).Append(' ').Append("<input name=\"").Append(name).Append("\" value=\"").Append(E(query(name))).Append("\" size=\"14\"></label> ");
        }

        html.Append("<label>Type <select name=\"type\">");
        foreach (string option in new List<string> { "" }.Concat(AuditEventTypes.All))
        {
            html.Append("<option value=\"").Append(option).Append('"').Append(query("type") == option ? " selected" : "").Append('>').Append(option.Length == 0 ? "(any)" : option).Append("</option>");
        }

        html.Append("</select></label> <label><input type=\"checkbox\" name=\"gaps\" value=\"1\"").Append(gaps ? " checked" : "").Append("> Show sequence gaps instead</label> <button type=\"submit\">Search</button></form>");
        if (error is not null || parsed is null)
        {
            return html.Append("<p id=\"audit-error\" class=\"weak\">").Append(E(error)).Append("</p>").ToString();
        }

        try
        {
            if (gaps)
            {
                IReadOnlyList<AuditGap> found = _p.Store.AuditGaps(parsed.MachinePrefix, openOnly: true);
                html.Append("<h3>Sequence gaps</h3><table id=\"gaps\"><tr><th>Detected (UTC)</th><th>Machine</th><th>Kind</th><th>Numbers</th></tr>");
                foreach (AuditGap gap in found)
                {
                    html.Append("<tr><td>").Append(Time(gap.Detected)).Append("</td><td>").Append(WebUtility.HtmlEncode(KeyIdentity.Display(gap.Fingerprint)[..19])).Append("</td><td>").Append(E(gap.Kind)).Append("</td><td>")
                        .Append(gap.From == gap.To ? gap.From.ToString(CultureInfo.InvariantCulture) : gap.From.ToString(CultureInfo.InvariantCulture) + "-" + gap.To.ToString(CultureInfo.InvariantCulture)).Append("</td></tr>");
                }

                html.Append("</table>");
                if (found.Count == 0)
                {
                    html.Append("<p>No open gaps in any machine's audit sequence.</p>");
                }
            }
            else
            {
                IReadOnlyList<AuditHistoryRecord> records = _p.Store.AuditHistory(parsed);
                html.Append("<h3>Host events</h3><table id=\"events\"><tr><th>Time (UTC)</th><th>Machine</th><th>No.</th><th>Type</th><th>Outcome</th><th>Reason</th><th>Grant</th><th>Exit</th><th>Command</th><th>Folder</th></tr>");
                foreach (AuditHistoryRecord record in records)
                {
                    AuditEvent item = record.Event;
                    html.Append("<tr><td>").Append(Time(item.Time)).Append("</td><td>").Append(WebUtility.HtmlEncode(KeyIdentity.Display(item.MachineFingerprint)[..19])).Append("</td><td>").Append(item.Sequence.ToString(CultureInfo.InvariantCulture)).Append("</td><td>").Append(E(item.Type))
                        .Append("</td><td>").Append(E(item.Outcome)).Append("</td><td>").Append(E(item.Reason)).Append("</td><td>").Append(E(item.GrantId)).Append("</td><td>").Append(item.ExitCode is { } code ? code.ToString(CultureInfo.InvariantCulture) : "")
                        .Append("</td><td>").Append(E(item.Program + (item.Arguments.Count == 0 ? "" : " " + string.Join(' ', item.Arguments)))).Append("</td><td>").Append(E(item.Folder)).Append("</td></tr>");
                }

                html.Append("</table>");
                if (records.Count == 0)
                {
                    html.Append("<p id=\"no-events\">No audit events match.</p>");
                }

                string? needle = parsed.Text;
                html.Append("<h3>Authority changes</h3><table id=\"changes\"><tr><th>Time (UTC)</th><th>Event</th><th>Actor</th><th>Detail</th></tr>");
                foreach (AuditEntry entry in _p.Store.Audit(1000).Where(entry => needle is null || (entry.Event + " " + entry.Actor + " " + entry.Detail).Contains(needle, StringComparison.OrdinalIgnoreCase)
                    && (parsed.From is null || entry.Time >= parsed.From) && (parsed.To is null || entry.Time <= parsed.To)).Take(100))
                {
                    html.Append("<tr><td>").Append(Time(entry.Time)).Append("</td><td>").Append(E(entry.Event)).Append("</td><td>").Append(E(entry.Actor)).Append("</td><td>").Append(E(entry.Detail)).Append("</td></tr>");
                }

                html.Append("</table>");
            }
        }
        catch (AuthorityDatabaseException failure)
        {
            html.Append("<p class=\"weak\">").Append(E(failure.Message)).Append("</p>");
        }

        return html.ToString();
    }

    // ---- settings ----

    private string SettingsBody()
    {
        AuthorityStatus status = Status();
        (int idle, int absolute) = _p.Store.SessionTimeouts();
        int retention = _p.Store.AuditRetentionDays();
        StringBuilder html = new("<h2>Authority settings</h2><p>Each change opens a one-use page where you approve that one change with your passkey.</p>");
        html.Append("<h3>Lock and unlock policy</h3><p>Status: <strong>").Append(status.Locked ? "LOCKED" : "Unlocked").Append("</strong>. Unlock mode: <span").Append(status.Policy == UnlockPolicy.Unattended ? " class=\"weak\"" : "").Append('>').Append(WebUtility.HtmlEncode(UnlockPolicies.Describe(status.Policy))).Append("</span></p>")
            .Append(status.Policy == UnlockPolicy.Unattended
                ? "<button data-op=\"policy-manual\">Make unlock manual</button>"
                : "<button data-op=\"policy-unattended\">Allow unattended unlock (weaker)</button>");
        html.Append("<h3>Audit retention</h3><p>Audit events are kept <strong id=\"retention\">").Append(retention == 0 ? "forever" : retention.ToString(CultureInfo.InvariantCulture) + " days").Append("</strong> (0 keeps everything).</p>")
            .Append("<input id=\"days\" name=\"days\" size=\"6\" value=\"").Append(retention.ToString(CultureInfo.InvariantCulture)).Append("\" inputmode=\"numeric\"> days <button data-op=\"set-audit-retention\" data-inputs=\"days\">Set retention</button>");
        html.Append("<h3>Administrator session timeouts</h3><p>A session ends after <strong id=\"idle\">").Append(idle.ToString(CultureInfo.InvariantCulture)).Append("</strong> minutes without use and at most <strong id=\"absolute\">").Append(absolute.ToString(CultureInfo.InvariantCulture)).Append("</strong> minutes after it started.</p>")
            .Append("<label>Idle <input id=\"idle-in\" name=\"idle\" size=\"5\" value=\"").Append(idle.ToString(CultureInfo.InvariantCulture)).Append("\" inputmode=\"numeric\"></label> <label>Absolute <input id=\"absolute-in\" name=\"absolute\" size=\"5\" value=\"").Append(absolute.ToString(CultureInfo.InvariantCulture))
            .Append("\" inputmode=\"numeric\"></label> minutes <button data-op=\"set-session-timeouts\" data-inputs=\"idle-in,absolute-in\">Set timeouts</button>");
        html.Append("<h3>Authority signing key</h3><p>Current key: <code>").Append(WebUtility.HtmlEncode(CurrentKey())).Append("</code></p>")
            .Append("<button data-op=\"authority-key-rotate\">Rotate key</button><button data-op=\"authority-key-recover\">Recover key (no transition; other hosts must enroll again)</button>");

        return html.Append("<div id=\"msg\" role=\"status\"></div>").ToString();
    }

    // ---- passkeys ----

    private string PasskeysBody()
    {
        StringBuilder html = new("<h2>Passkeys</h2><p>The passkeys that can approve runs. Admin passkeys can also change the authority. Adding and removing one opens the same pages as with-secrets --enroll and --unenroll; the terminal that runs the service may ask for a code that those pages show.</p>");
        if (_p.Passkeys is not { } passkeys)
        {
            return html.Append("<p>Not available in this service.</p>").ToString();
        }

        try
        {
            IReadOnlyList<EnrolledEntry> entries = passkeys.List();
            html.Append("<table id=\"passkeys\"><tr><th>Name</th><th>For host</th><th>Added</th><th>Admin</th><th>Change</th></tr>");
            int row = 0;
            foreach (EnrolledEntry entry in entries)
            {
                row++;
                html.Append("<tr><td>").Append(E(entry.Name)).Append("</td><td>").Append(E(entry.Detail)).Append("</td><td>").Append(entry.Created.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)).Append("</td><td>").Append(entry.Admin ? "admin" : "").Append("</td><td><button data-op=\"passkey-unenroll\" data-name=\"")
                    .Append(E(entry.Name)).Append("\">Remove</button></td></tr>");
            }

            html.Append("</table>");
        }
        catch (ProofUnavailableException failure)
        {
            html.Append("<p class=\"weak\">").Append(E(failure.Message)).Append("</p>");
        }

        return html.Append("<button data-op=\"passkey-enroll\">Add a passkey</button><div id=\"msg\" role=\"status\"></div>").ToString();
    }
}
