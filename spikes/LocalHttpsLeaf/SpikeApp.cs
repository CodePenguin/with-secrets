using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using WithSecrets;

namespace LocalHttpsLeaf;

internal static class SpikeApp
{
    public static WebApplication BuildSpike(this WebApplicationBuilder builder, SpikeCertificates certificates)
    {
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.ListenLocalhost(SpikeCertificates.LeafPort, listen => listen.UseHttps(certificates.Leaf));
            kestrel.ListenLocalhost(SpikeCertificates.ChildPort, listen => listen.UseHttps(certificates.Child));
            kestrel.ListenLocalhost(SpikeCertificates.OtherKeyPort, listen => listen.UseHttps(certificates.OtherKey));
            kestrel.ListenLocalhost(SpikeCertificates.OtherSanPort, listen => listen.UseHttps(certificates.OtherSan));
            kestrel.ListenLocalhost(SpikeCertificates.HttpPort);
            kestrel.ListenLocalhost(SpikeCertificates.ReissuedPort, listen => listen.UseHttps(certificates.Reissued));
        });

        var app = builder.Build();
        var pending = new ConcurrentDictionary<string, Ceremony>();
        app.MapGet("/", () => Results.Content(Page, "text/html"));
        app.MapPost("/ceremony/{operation}", (string operation, HttpContext context) =>
        {
            // Only the primary HTTPS origin and the explicit HTTP localhost comparison can enroll.
            var (origin, rpId) = context.Connection.LocalPort switch
            {
                SpikeCertificates.LeafPort => ($"https://{SpikeCertificates.Host}:{SpikeCertificates.LeafPort}", SpikeCertificates.Host),
                SpikeCertificates.HttpPort => ($"http://localhost:{SpikeCertificates.HttpPort}", "localhost"),
                _ => ("", ""),
            };
            if (origin.Length == 0 || context.Request.Headers.Origin != origin)
            {
                return Results.BadRequest(new { detail = "Unexpected origin" });
            }

            byte[] challenge = RandomNumberGenerator.GetBytes(32);
            var expires = DateTimeOffset.UtcNow.AddMinutes(2);
            foreach (var entry in pending)
            {
                if (entry.Value.Expires <= DateTimeOffset.UtcNow)
                {
                    pending.TryRemove(entry.Key, out _);
                }
            }

            if (operation == "register")
            {
                string ticket = Guid.NewGuid().ToString("N");
                pending[ticket] = new(challenge, origin, rpId, expires);
                return Results.Ok(new { ticket, challenge = Base64Url.EncodeToString(challenge) });
            }

            if (operation == "authenticate" &&
                pending.TryRemove(context.Request.Query["ticket"].ToString(), out var previous) &&
                previous.Origin == origin && previous.Key is not null)
            {
                string ticket = Guid.NewGuid().ToString("N");
                pending[ticket] = previous with { Challenge = challenge, Expires = expires };
                return Results.Ok(new { ticket, challenge = Base64Url.EncodeToString(challenge) });
            }

            return Results.BadRequest(new { detail = "Missing registered credential" });
        });
        app.MapPost("/verify/{operation}", (string operation, Proof proof, HttpContext context) =>
        {
            if (!pending.TryRemove(proof.Ticket, out var ceremony) ||
                context.Request.Headers.Origin != ceremony.Origin || ceremony.Expires <= DateTimeOffset.UtcNow)
            {
                return Results.BadRequest(new { detail = "Missing or expired challenge" });
            }

            if (operation == "register" && ceremony.Key is null)
            {
                var result = WebAuthn.VerifyRegistration(ceremony.Challenge, ceremony.Origin, ceremony.RpId,
                    "Disposable TLS spike", proof.Credential.GetRawText());
                if (!result.Ok)
                {
                    return Results.BadRequest(new { detail = result.Detail });
                }

                string ticket = Guid.NewGuid().ToString("N");
                pending[ticket] = ceremony with { Key = result.Key };
                return Results.Ok(new { ticket });
            }

            if (operation == "authenticate" && ceremony.Key is not null)
            {
                var result = WebAuthn.VerifyAssertion(ceremony.Key, ceremony.Challenge, ceremony.Origin,
                    ceremony.RpId, proof.Credential.GetRawText());
                return result.Ok ? Results.Ok() : Results.BadRequest(new { detail = result.Detail });
            }

            return Results.BadRequest(new { detail = "Unexpected ceremony operation" });
        });
        return app;
    }

    private sealed record Ceremony(byte[] Challenge, string Origin, string RpId, DateTimeOffset Expires, PasskeyRecord? Key = null);
    private sealed record Proof(string Ticket, JsonElement Credential);

    private const string Page = """
        <!doctype html>
        <meta charset="utf-8">
        <title>Local TLS spike</title>
        <h1>Local TLS spike</h1>
        <p id="status"></p>
        <button id="register">Register disposable passkey</button>
        <button id="auth" disabled>Authenticate</button>
        <pre id="result"></pre>
        <script>
        const rpId = location.hostname;
        const output = document.querySelector('#result');
        const register = document.querySelector('#register');
        const auth = document.querySelector('#auth');
        document.querySelector('#status').textContent = location.origin + ' secureContext=' + isSecureContext;
        let credentialId, registrationTicket;

        function encode(bytes) {
            return btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
        }

        function decode(text) {
            return Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0));
        }

        async function post(path, data) {
            const response = await fetch(path, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
            });
            if (!response.ok) throw Error((await response.json()).detail);
            if (response.headers.get('Content-Type')?.includes('application/json')) return response.json();
        }

        async function run(name, ceremony) {
            output.dataset.state = name + '-running';
            output.textContent = '';
            try {
                await ceremony();
                output.textContent = name + ' verified by server';
                output.dataset.state = name + '-pass';
            } catch (error) {
                output.textContent = error.name + ': ' + error.message;
                output.dataset.state = name + '-fail';
            }
        }

        register.onclick = () => run('registration', async () => {
            const options = await post('/ceremony/register');
            const credential = await navigator.credentials.create({ publicKey: {
                rp: { id: rpId, name: 'with-secrets TLS spike' },
                user: { id: crypto.getRandomValues(new Uint8Array(32)), name: 'spike-' + Date.now(), displayName: 'Disposable TLS spike' },
                challenge: decode(options.challenge), pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
                authenticatorSelection: { userVerification: 'required' }, attestation: 'none', timeout: 30000
            } });
            const { ticket } = await post('/verify/register', { ticket: options.ticket, credential: {
                id: encode(credential.rawId), clientDataJSON: encode(credential.response.clientDataJSON),
                attestationObject: encode(credential.response.attestationObject)
            } });
            credentialId = credential.rawId;
            registrationTicket = ticket;
            auth.disabled = false;
        });

        auth.onclick = () => run('authentication', async () => {
            auth.disabled = true;
            const options = await post('/ceremony/authenticate?ticket=' + registrationTicket);
            const credential = await navigator.credentials.get({ publicKey: {
                rpId, challenge: decode(options.challenge), allowCredentials: [{ type: 'public-key', id: credentialId }],
                userVerification: 'required', timeout: 30000
            } });
            const { authenticatorData, clientDataJSON, signature } = credential.response;
            await post('/verify/authenticate', { ticket: options.ticket, credential: {
                id: encode(credential.rawId), authenticatorData: encode(authenticatorData),
                clientDataJSON: encode(clientDataJSON), signature: encode(signature)
            } });
        });
        </script>
        """;
}
