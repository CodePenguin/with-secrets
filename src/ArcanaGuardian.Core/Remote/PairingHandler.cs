namespace ArcanaGuardian;

/// <summary>
/// The pairing route's handler: the ONLY thing an unenrolled client certificate can reach. It does exactly two things, named by the body's <c>step</c>: <c>bootstrap</c> (the authority proves it holds the invitation, over its public identity
/// certificate) and <c>register</c> (create or refresh a Pending record). It returns only public material and the minimal registration result; it never reads, returns or changes a machine record, a grant, a secret, a lock or a setting
/// beyond what <see cref="PairingService" /> does, and it has no other operation to ask for.
/// </summary>
internal sealed class PairingHandler(PairingService service) : IPairingHandler
{
    public Task<PairingReply> HandleAsync(PairingContext context, CancellationToken cancel)
    {
        service.SeenPeer?.Invoke(context.Peer.Fingerprint);
        string peer = context.Http.Connection.RemoteIpAddress?.ToString() ?? "";

        PairingReply reply = PairingWire.StepOf(context.Body) switch
        {
            "bootstrap" => PairingWire.TryReadBootstrap(context.Body, out PairingBootstrapRequest? bootstrap) && bootstrap is not null ? service.Bootstrap(bootstrap, peer) : PairingReply.BadRequest,
            "register" => PairingWire.TryReadRegistration(context.Body, out PairingRegistrationRequest? registration) && registration is not null ? service.Register(registration, context.Peer.Fingerprint, context.Certificate, peer) : PairingReply.BadRequest,
            _ => PairingReply.BadRequest,
        };

        return Task.FromResult(reply);
    }
}
