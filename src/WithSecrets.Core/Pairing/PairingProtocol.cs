using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace WithSecrets;

/// <summary>
/// The invitation a new machine is paired with, as the administrator gets it from the admin app: the authority's address, a unique invitation identifier and a random 128-bit pairing code. It is a LOCAL credential
/// bundle, never a network message: it is parsed on the machine, the code is used only as key material and is never sent. <see cref="ToString" /> says nothing about the content, so a log line or an exception that
/// formats the object cannot leak the code.
/// </summary>
public sealed class PairingBundle
{
    /// <summary>The first word of the text form; the version of the bundle.</summary>
    public const string Prefix = "wsp1";

    private readonly byte[] _code;

    private PairingBundle(string authority, string invitationId, byte[] code)
    {
        Authority = authority;
        InvitationId = invitationId;
        _code = code;
    }

    /// <summary>The authority's machine endpoint (<c>https://host:port</c>): routing information; the authority is identified by the proof, never by this address.</summary>
    public string Authority { get; }

    /// <summary>The unique invitation identifier (22 base64url characters). It is sent to the authority; it is not secret.</summary>
    public string InvitationId { get; }

    public static PairingBundle Create(string authority, string invitationId, byte[] code) => new(authority, invitationId, [.. code]);

    /// <summary>The key material the proofs use (derived from the code; see <see cref="PairingProtocol.DeriveKey" />). The code itself is never returned.</summary>
    public byte[] DeriveKey() => PairingProtocol.DeriveKey(_code, InvitationId);

    /// <summary>The text form: <c>wsp1;ADDRESS;ID;CODE</c> (what the administrator copies once). Contains the code: show it to the administrator and nowhere else.</summary>
    public string Format() => string.Join(';', Prefix, Authority, InvitationId, Base64Url.EncodeToString(_code));

    /// <summary>Parses the text form. Null when it is not one (nothing about the input is reported: it may hold a code).</summary>
    public static PairingBundle? TryParse(string? text)
    {
        if (text is null)
        {
            return null;
        }

        string[] parts = text.Trim().Split(';');
        if (parts.Length != 4 || parts[0] != Prefix || RemoteTarget.Address(parts[1], out Uri? endpoint) is not null || endpoint is null || !PairingProtocol.IsToken(parts[2], PairingProtocol.IdBytes))
        {
            return null;
        }

        byte[] code = new byte[PairingProtocol.CodeBytes];
        if (!PairingProtocol.IsToken(parts[3], PairingProtocol.CodeBytes) || Base64Url.DecodeFromChars(parts[3], code, out _, out int written) != System.Buffers.OperationStatus.Done || written != code.Length)
        {
            return null;
        }

        return new PairingBundle(endpoint.GetLeftPart(UriPartial.Authority), parts[2], code);
    }

    public override string ToString() => "pairing invitation (content hidden)";
}

/// <summary>
/// The pairing protocol of architecture 10.2: what is derived from the code, the two HMAC-SHA-256 proofs, the proof of possession, the fixed limits and the wire forms.
/// <para>
/// Key derivation: <c>K = HKDF-SHA-256(ikm = code, salt = invitation id (UTF-8), info = "with-secrets pairing key v1")</c>, 32 bytes. The authority keeps only K (protected, see <see cref="PairingService" />); verifying a proof needs K,
/// not the code. Every proof is <c>HMAC-SHA-256(K, frame(label, field, ...))</c> where a frame is the length-prefixed (4 bytes, big endian) concatenation of its fields, so no two different field lists share an encoding, and each proof has its
/// own domain-separation label, so one can never be used as the other.
/// </para>
/// </summary>
public static class PairingProtocol
{
    public const int Version = 1;

    /// <summary>How long an invitation can be used after the administrator created it. Fixed; not configurable.</summary>
    public static readonly TimeSpan InvitationLifetime = TimeSpan.FromMinutes(10);

    public const int CodeBytes = 16;
    public const int IdBytes = 16;
    public const int NonceBytes = 16;
    public const int KeyBytes = 32;

    // ---- fixed limits (built in; none is a setting) ----

    /// <summary>Wrong proofs on one invitation before it is withdrawn.</summary>
    public const int MaxFailedPerInvitation = 5;

    /// <summary>Refused attempts, in all, within <see cref="FailureWindow" />, before the route refuses everything for the rest of the window.</summary>
    public const int MaxFailedOverall = 30;

    public static readonly TimeSpan FailureWindow = TimeSpan.FromMinutes(10);

    /// <summary>Registrations being processed at once (the others are refused, not queued).</summary>
    public const int MaxConcurrentRegistrations = 4;

    /// <summary>Invitations an administrator may have open (pending and not expired) at once.</summary>
    public const int MaxOpenInvitations = 8;

    /// <summary>The largest request body of the pairing route.</summary>
    public const int MaxBodyBytes = 16 * 1024;

    // ---- domain separation ----

    public const string KeyInfo = "with-secrets pairing key v1";
    public const string BootstrapLabel = "with-secrets pairing authority proof v1";
    public const string RegistrationLabel = "with-secrets pairing registration proof v1";
    public const string PossessionLabel = "with-secrets pairing possession v1";

    public static bool IsToken(string text, int bytes) => text.Length == Base64Url.GetEncodedLength(bytes) && text.All(letter => char.IsAsciiLetterOrDigit(letter) || letter is '-' or '_');

    public static string NewToken(int bytes) => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(bytes));

    /// <summary>The key material derived from a code for one invitation (see the class remarks).</summary>
    public static byte[] DeriveKey(byte[] code, string invitationId) => HKDF.DeriveKey(HashAlgorithmName.SHA256, code, KeyBytes, Encoding.UTF8.GetBytes(invitationId), Encoding.UTF8.GetBytes(KeyInfo));

    private static byte[] Frame(string label, params byte[][] fields)
    {
        using MemoryStream stream = new();
        void Put(byte[] part)
        {
            byte[] length = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, part.Length);
            stream.Write(length);
            stream.Write(part);
        }

        Put(Encoding.UTF8.GetBytes(label));
        foreach (byte[] field in fields)
        {
            Put(field);
        }

        return stream.ToArray();
    }

    private static byte[] Text(string text) => Encoding.UTF8.GetBytes(text);

    /// <summary>The authority's proof that it holds the invitation: bound to the invitation, the authority's identity fingerprint and both nonces.</summary>
    public static byte[] BootstrapProof(byte[] key, string invitationId, string authorityFingerprint, byte[] clientNonce, byte[] serverNonce)
        => HMACSHA256.HashData(key, Frame(BootstrapLabel, Text(invitationId), Text(authorityFingerprint), clientNonce, serverNonce));

    /// <summary>The machine's registration proof: bound to the invitation, the authority it verified, the machine's fingerprint, its host name and a fresh nonce.</summary>
    public static byte[] RegistrationProof(byte[] key, string invitationId, string authorityFingerprint, string machineFingerprint, string hostName, byte[] nonce)
        => HMACSHA256.HashData(key, Frame(RegistrationLabel, Text(invitationId), Text(authorityFingerprint), Text(machineFingerprint), Text(hostName), nonce));

    /// <summary>The bytes the machine's identity key signs to prove it holds the key behind its certificate.</summary>
    public static byte[] PossessionMessage(string invitationId, string authorityFingerprint, string machineFingerprint, string hostName, byte[] nonce)
        => Frame(PossessionLabel, Text(invitationId), Text(authorityFingerprint), Text(machineFingerprint), Text(hostName), nonce);

    /// <summary>Constant-time comparison of two proofs.</summary>
    public static bool Same(byte[] expected, byte[] given) => expected.Length == given.Length && CryptographicOperations.FixedTimeEquals(expected, given);
}

/// <summary>What the machine tells the authority first: the invitation id and a fresh nonce, nothing else.</summary>
public sealed record PairingBootstrapRequest(string InvitationId, byte[] Nonce);

/// <summary>The authority's answer to the first request: its public identity certificate, a fresh nonce and the proof.</summary>
public sealed record PairingBootstrapReply(byte[] AuthorityCertificate, byte[] ServerNonce, byte[] Proof);

/// <summary>The registration: the machine's public identity (certificate and fingerprint), its host name, a fresh nonce, the proof of possession of its persistent key and the registration proof.</summary>
public sealed record PairingRegistrationRequest(string InvitationId, byte[] MachineCertificate, string MachineFingerprint, string HostName, byte[] Nonce, byte[] Possession, byte[] Proof)
{
    /// <summary>A digest of the whole request, to recognize the same request again after a lost answer (public data and proofs only; stored hashed).</summary>
    public string Digest() => Convert.ToHexString(SHA256.HashData(Frame()));

    private byte[] Frame() => PairingWire.Registration(this);
}

/// <summary>The registration result: the machine's fingerprint and where it stands (Pending). Nothing else leaves the authority.</summary>
public sealed record PairingRegistrationReply(string MachineFingerprint, string Status);

/// <summary>The wire forms of the pairing route: small JSON objects with exactly the members named here, the protocol version, and nothing else. Strict: an unknown, missing or repeated member is an error.</summary>
public static class PairingWire
{
    private static string B(byte[] bytes) => Convert.ToBase64String(bytes);

    public static string Write(PairingBootstrapRequest request) => "{\"v\":1,\"step\":\"bootstrap\",\"invitation\":" + Q(request.InvitationId) + ",\"nonce\":" + Q(B(request.Nonce)) + "}";

    public static string Write(PairingBootstrapReply reply) => "{\"v\":1,\"ok\":true,\"authorityCertificate\":" + Q(B(reply.AuthorityCertificate)) + ",\"serverNonce\":" + Q(B(reply.ServerNonce)) + ",\"proof\":" + Q(B(reply.Proof)) + "}";

    public static string Write(PairingRegistrationRequest request) => Encoding.UTF8.GetString(Registration(request));

    internal static byte[] Registration(PairingRegistrationRequest request) => Encoding.UTF8.GetBytes("{\"v\":1,\"step\":\"register\",\"invitation\":" + Q(request.InvitationId) + ",\"machineCertificate\":" + Q(B(request.MachineCertificate)) + ",\"fingerprint\":" + Q(request.MachineFingerprint)
        + ",\"hostName\":" + Q(request.HostName) + ",\"nonce\":" + Q(B(request.Nonce)) + ",\"possession\":" + Q(B(request.Possession)) + ",\"proof\":" + Q(B(request.Proof)) + "}");

    public static string Write(PairingRegistrationReply reply) => "{\"v\":1,\"ok\":true,\"fingerprint\":" + Q(reply.MachineFingerprint) + ",\"status\":" + Q(reply.Status) + "}";

    private static string Q(string text)
    {
        StringBuilder builder = new();
        ToolSettings.QuoteJson(builder, text);

        return builder.ToString();
    }

    /// <summary>The step a request body names ("bootstrap" or "register"), or null when the body is not a pairing request at all.</summary>
    public static string? StepOf(byte[] body)
    {
        if (!Open(body, out System.Text.Json.JsonDocument? doc))
        {
            return null;
        }

        using (doc)
        {
            return doc!.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object && doc.RootElement.TryGetProperty("step", out System.Text.Json.JsonElement step) && step.ValueKind == System.Text.Json.JsonValueKind.String ? step.GetString() : null;
        }
    }

    private static bool Open(byte[] body, out System.Text.Json.JsonDocument? doc)
    {
        doc = null;
        if (body.Length is 0 or > PairingProtocol.MaxBodyBytes)
        {
            return false;
        }

        string text;
        try
        {
            text = new UTF8Encoding(false, true).GetString(body);
        }
        catch (DecoderFallbackException)
        {
            return false;
        }

        return CanonicalJson.Open(text, out doc, out _);
    }

    private static bool Bytes(ContractReader reader, string name, int length, out byte[] value)
    {
        value = [];
        if (!reader.Text(name, out string? text) || text is null || text.Length > 8192)
        {
            return false;
        }

        byte[] buffer = new byte[6144];
        if (!Convert.TryFromBase64String(text, buffer, out int written) || (length > 0 && written != length) || written == 0)
        {
            return false;
        }

        value = buffer[..written];

        return true;
    }

    public static bool TryReadBootstrap(byte[] body, out PairingBootstrapRequest? request)
    {
        request = null;
        if (!Open(body, out System.Text.Json.JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "v", "step", "invitation", "nonce");
            if (reader.Problem is not null || !reader.Int("v", out int version) || version != 1 || !reader.Text("step", out string? step) || step != "bootstrap" || !reader.Text("invitation", out string? id) || id is null
                || !PairingProtocol.IsToken(id, PairingProtocol.IdBytes) || !Bytes(reader, "nonce", PairingProtocol.NonceBytes, out byte[] nonce))
            {
                return false;
            }

            request = new PairingBootstrapRequest(id, nonce);

            return true;
        }
    }

    public static bool TryReadRegistration(byte[] body, out PairingRegistrationRequest? request)
    {
        request = null;
        if (!Open(body, out System.Text.Json.JsonDocument? doc))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "v", "step", "invitation", "machineCertificate", "fingerprint", "hostName", "nonce", "possession", "proof");
            if (reader.Problem is not null || !reader.Int("v", out int version) || version != 1 || !reader.Text("step", out string? step) || step != "register" || !reader.Text("invitation", out string? id) || id is null
                || !PairingProtocol.IsToken(id, PairingProtocol.IdBytes) || !Bytes(reader, "machineCertificate", 0, out byte[] certificate) || !reader.Text("fingerprint", out string? fingerprint) || fingerprint is null
                || !reader.Text("hostName", out string? host) || host is null || !Bytes(reader, "nonce", PairingProtocol.NonceBytes, out byte[] nonce) || !Bytes(reader, "possession", 0, out byte[] possession) || !Bytes(reader, "proof", 32, out byte[] proof))
            {
                return false;
            }

            request = new PairingRegistrationRequest(id, certificate, fingerprint, host, nonce, possession, proof);

            return true;
        }
    }

    public static bool TryReadBootstrapReply(string json, out PairingBootstrapReply? reply)
    {
        reply = null;
        if (!CanonicalJson.Open(json, out System.Text.Json.JsonDocument? doc, out _))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "v", "ok", "authorityCertificate", "serverNonce", "proof");
            if (reader.Problem is not null || !reader.Int("v", out int version) || version != 1 || !Bytes(reader, "authorityCertificate", 0, out byte[] certificate) || !Bytes(reader, "serverNonce", PairingProtocol.NonceBytes, out byte[] nonce) || !Bytes(reader, "proof", 32, out byte[] proof))
            {
                return false;
            }

            reply = new PairingBootstrapReply(certificate, nonce, proof);

            return true;
        }
    }

    public static bool TryReadRegistrationReply(string json, out PairingRegistrationReply? reply)
    {
        reply = null;
        if (!CanonicalJson.Open(json, out System.Text.Json.JsonDocument? doc, out _))
        {
            return false;
        }

        using (doc)
        {
            ContractReader reader = new(doc!.RootElement, "v", "ok", "fingerprint", "status");
            if (reader.Problem is not null || !reader.Int("v", out int version) || version != 1 || !reader.Text("fingerprint", out string? fingerprint) || fingerprint is null || !reader.Text("status", out string? status) || status is null)
            {
                return false;
            }

            reply = new PairingRegistrationReply(fingerprint, status);

            return true;
        }
    }
}
