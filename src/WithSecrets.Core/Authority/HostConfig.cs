using System.Globalization;
using System.Text;
using System.Text.Json;

namespace WithSecrets;

/// <summary>The authority signing key a host service trusts: its fingerprint and public key. Public data only.</summary>
public sealed record PinnedAuthorityKey(string Fingerprint, byte[] PublicKey, DateTimeOffset Pinned);

/// <summary>
/// Where a host service finds a remote authority: the relay (a http, https, ws or wss URL; plain http and ws only for a loopback relay), the authority's registration id at that relay,
/// the fingerprint of the authority signing key to trust (given out of band by the administrator) and, optionally, the SHA-256 of the relay's TLS certificate as an extra pin (empty: none;
/// the normal certificate validation always applies). Public data only.
/// </summary>
public sealed record RemoteAuthorityConfig(string RelayUrl, string RegistrationId, string AuthorityFingerprint, string TlsPin = "");

/// <summary>What <c>host.json</c> holds: this machine's fingerprint (what the CLI checks the service against), the pinned authority key and, in remote-authority mode, where the authority is.</summary>
public sealed record HostConfig(string MachineFingerprint, PinnedAuthorityKey? Authority, RemoteAuthorityConfig? Remote = null);

/// <summary>The result of reading <c>host.json</c>: the config (null when the file is missing), or why it cannot be used.</summary>
public sealed record HostConfigLoad(HostConfig? Config, string? Problem);

/// <summary>
/// <c>host.json</c> in the store folder: configuration of the host service that is public data only. It is written when an
/// administrator approves the machine (the first trusted enrollment) and pins the authority's public signing key, and when a
/// signed key transition or an explicit recovery replaces that key. The host service rejects an authority response signed by any
/// other key. The file is replaced atomically; a file that cannot be read is an error, never "nothing pinned".
/// </summary>
public sealed class HostConfigFile(string path)
{
    public const string FileName = "host.json";

    public string FilePath { get; } = Path.GetFullPath(path);

    public static HostConfigFile InFolder(string folder) => new(Path.Combine(folder, FileName));

    public HostConfigLoad Load()
    {
        if (!File.Exists(FilePath))
        {
            return new HostConfigLoad(null, null);
        }

        try
        {
            string json = File.ReadAllText(FilePath, new UTF8Encoding(false, true));

            return Parse(json);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or DecoderFallbackException)
        {
            return new HostConfigLoad(null, Damaged("cannot be read"));
        }
    }

    private string Damaged(string why) => $"{FileName} {why}. Delete it and ask the administrator to run: with-secrets admin approve (or admin recover-authority)";

    private HostConfigLoad Parse(string json)
    {
        if (!CanonicalJson.Open(json, out JsonDocument? doc, out _))
        {
            return new HostConfigLoad(null, Damaged("is not valid"));
        }

        using (doc)
        {
            bool hasRemote = doc!.RootElement.TryGetProperty("remote", out JsonElement remoteElement);
            ContractReader reader = hasRemote ? new(doc!.RootElement, "version", "machineFingerprint", "authority", "remote") : new(doc!.RootElement, "version", "machineFingerprint", "authority");
            if (reader.Problem is not null || !reader.Int("version", out int version) || version != 1 || !reader.Text("machineFingerprint", out string? machine))
            {
                return new HostConfigLoad(null, Damaged("is not a version 1 file"));
            }

            if (KeyIdentity.ParseHex(machine!, true) != machine)
            {
                return new HostConfigLoad(null, Damaged("has a fingerprint that is not 64 hex digits"));
            }

            RemoteAuthorityConfig? remote = null;
            if (hasRemote && remoteElement.ValueKind != JsonValueKind.Null)
            {
                ContractReader remoteReader = new(remoteElement, "relayUrl", "registrationId", "authorityFingerprint", "tlsPin");
                if (remoteReader.Problem is not null || !remoteReader.Text("relayUrl", out string? relayUrl) || !remoteReader.Text("registrationId", out string? registration) || !remoteReader.Text("authorityFingerprint", out string? authorityFingerprint) || !remoteReader.Text("tlsPin", out string? tlsPin)
                    || RemoteTarget.Problem(new RemoteAuthorityConfig(relayUrl!, registration!, authorityFingerprint!, tlsPin!)) is not null)
                {
                    return new HostConfigLoad(null, Damaged("has a remote authority setting that is not valid"));
                }

                remote = new RemoteAuthorityConfig(relayUrl!, registration!, KeyIdentity.ParseHex(authorityFingerprint!, true)!, tlsPin!);
            }

            JsonElement authority = doc.RootElement.GetProperty("authority");
            if (authority.ValueKind == JsonValueKind.Null)
            {
                return new HostConfigLoad(new HostConfig(machine!, null, remote), null);
            }

            ContractReader key = new(authority, "keyFingerprint", "publicKey", "pinned");
            if (key.Problem is not null || !key.Text("keyFingerprint", out string? fingerprint) || !key.Text("publicKey", out string? publicText) || !key.Time("pinned", out DateTimeOffset pinned))
            {
                return new HostConfigLoad(null, Damaged("has an authority key that is not valid"));
            }

            byte[] publicKey;
            try
            {
                publicKey = Convert.FromBase64String(publicText!);
            }
            catch (FormatException)
            {
                return new HostConfigLoad(null, Damaged("has an authority key that is not base64"));
            }

            if (!KeyIdentity.IsCanonicalP256(publicKey) || KeyIdentity.Fingerprint(publicKey) != fingerprint)
            {
                return new HostConfigLoad(null, Damaged("has an authority key whose fingerprint is not its key's"));
            }

            return new HostConfigLoad(new HostConfig(machine!, new PinnedAuthorityKey(fingerprint!, publicKey, pinned), remote), null);
        }
    }

    /// <summary>
    /// Pins <paramref name="authority" /> and names the machine it is pinned for. Called by the administrator's approval of the machine
    /// and by explicit recovery. The file is replaced atomically.
    /// </summary>
    public void Pin(string machineFingerprint, PinnedAuthorityKey authority)
    {
        Write(new HostConfig(machineFingerprint, authority, Load().Config?.Remote));
    }

    /// <summary>
    /// Selects remote-authority mode (or, with null, local mode) for this machine. Public data only: the relay, the registration id and the authority key fingerprint to trust.
    /// The pinned key and the machine fingerprint are kept as they are. The file is replaced atomically.
    /// </summary>
    public void SetRemote(string machineFingerprint, RemoteAuthorityConfig? remote)
    {
        if (remote is not null && RemoteTarget.Problem(remote) is { } problem)
        {
            throw new ArgumentException(problem);
        }

        HostConfigLoad load = Load();
        Write(new HostConfig(machineFingerprint, load.Config?.MachineFingerprint == machineFingerprint ? load.Config.Authority : null, remote is null ? null : remote with { AuthorityFingerprint = KeyIdentity.ParseHex(remote.AuthorityFingerprint, true)! }));
    }

    /// <summary>
    /// Replaces the pinned key with the new one of a transition, only when the pinned key signed it. Null when it was applied (or the
    /// new key is already pinned), else why not; nothing changes on a refusal.
    /// </summary>
    public string? TryApplyTransition(KeyTransition transition)
    {
        HostConfigLoad load = Load();
        if (load.Problem is not null)
        {
            return load.Problem;
        }

        if (load.Config?.Authority is not { } pinned)
        {
            return "no authority key is pinned";
        }

        if (pinned.Fingerprint == transition.NewFingerprint)
        {
            return null;
        }

        if (!transition.Verify(pinned.PublicKey))
        {
            return "the key transition is not signed by the pinned authority key";
        }

        Write(new HostConfig(load.Config.MachineFingerprint, new PinnedAuthorityKey(transition.NewFingerprint, transition.NewPublicKey, transition.Created), load.Config.Remote));

        return null;
    }

    private void Write(HostConfig config)
    {
        StringBuilder text = new("{\"version\":1,\"machineFingerprint\":");
        ToolSettings.QuoteJson(text, config.MachineFingerprint);

        text.Append(",\"authority\":");
        if (config.Authority is { } key)
        {
            text.Append("{\"keyFingerprint\":");
            ToolSettings.QuoteJson(text, key.Fingerprint);
            text.Append(",\"publicKey\":");
            ToolSettings.QuoteJson(text, Convert.ToBase64String(key.PublicKey));
            text.Append(",\"pinned\":");
            ToolSettings.QuoteJson(text, key.Pinned.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            text.Append('}');
        }
        else
        {
            text.Append("null");
        }

        if (config.Remote is { } remote)
        {
            text.Append(",\"remote\":{\"relayUrl\":");
            ToolSettings.QuoteJson(text, remote.RelayUrl);
            text.Append(",\"registrationId\":");
            ToolSettings.QuoteJson(text, remote.RegistrationId);
            text.Append(",\"authorityFingerprint\":");
            ToolSettings.QuoteJson(text, remote.AuthorityFingerprint);
            text.Append(",\"tlsPin\":");
            ToolSettings.QuoteJson(text, remote.TlsPin);
            text.Append('}');
        }

        text.Append("}\n");
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        string temp = FilePath + "." + Guid.NewGuid().ToString("N") + ".new";
        try
        {
            File.WriteAllText(temp, text.ToString(), new UTF8Encoding(false));
            File.Move(temp, FilePath, true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }
}
