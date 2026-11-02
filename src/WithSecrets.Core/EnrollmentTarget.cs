namespace WithSecrets;

/// <summary>
/// One place where a change can be made and approved: a proof method, the approver that serves its page, and the host name
/// that entries must be enrolled for to work there.
/// </summary>
public sealed record EnrollmentTarget(IProofMethod Method, WebApprover Approver, string Host)
{
    /// <summary>A target whose host name is the host of the approver's page origin.</summary>
    public static EnrollmentTarget For(IProofMethod method, WebApprover approver)
    {
        string origin = approver.Origin;

        return new EnrollmentTarget(method, approver, Uri.TryCreate(origin, UriKind.Absolute, out Uri? uri) ? uri.IdnHost : origin);
    }

    /// <summary>
    /// The same place for a change to the state: a passkey method there accepts only admin keys, on its pages and its
    /// approval page alike. Other methods are returned as they are.
    /// </summary>
    public EnrollmentTarget Admin()
    {
        if (Method is not PasskeyMethod { AdminOnly: false } passkey)
        {
            return this;
        }

        PasskeyMethod admin = passkey.ForAdmin();

        return this with { Method = admin, Approver = Approver.With(admin) };
    }

    /// <summary>The first of primary and local whose host an enrolled entry can prove for, or null when neither works.</summary>
    public static EnrollmentTarget? FirstThatCanProve(EnrollmentTarget primary, EnrollmentTarget local)
    {
        return primary.Method.CanProve(primary.Host) ? primary
            : local.Method.CanProve(local.Host) ? local
            : null;
    }
}
