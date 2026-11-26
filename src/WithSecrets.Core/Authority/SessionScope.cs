namespace WithSecrets;

/// <summary>Server-derived browser session scope from the trusted enrolled credential that signed in. Never accepted from the client.</summary>
public enum SessionScope
{
    /// <summary>Full administration reads plus Approvals.</summary>
    Admin,

    /// <summary>Approvals, administration reads and grant changes.</summary>
    Approval,
}

/// <summary>Capability strings exposed on the session and enforced at each Approvals or admin endpoint.</summary>
public static class SessionCapabilities
{
    public const string ApprovalsRead = "approvals.read";
    public const string ApprovalsDecide = "approvals.decide";
    public const string AdminRead = "admin.read";
    public const string AdminDecide = "admin.decide";
    public const string GrantsDecide = "grants.decide";

    public static IReadOnlyList<string> For(SessionScope scope) => scope switch
    {
        SessionScope.Admin => [AdminRead, AdminDecide, ApprovalsRead, ApprovalsDecide, GrantsDecide],
        SessionScope.Approval => [ApprovalsRead, ApprovalsDecide, AdminRead, GrantsDecide],
        _ => [],
    };

    public static string WireName(SessionScope scope) => scope switch
    {
        SessionScope.Admin => "admin",
        SessionScope.Approval => "approval",
        _ => "approval",
    };

    public static SessionScope FromAdminFlag(bool admin) => admin ? SessionScope.Admin : SessionScope.Approval;
}
