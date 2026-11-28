using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace ArcanaGuardian;

/// <summary>Independent browser TLS state. The journal records work before changing trust, and keeps old DER until cleanup succeeds.</summary>
public sealed class BrowserCertificates
{
    private readonly string _root;
    private readonly string _directory;
    private readonly IBrowserTrust _trust;

    public BrowserCertificates(string root) : this(root, new BrowserTrust())
    {
    }

    internal BrowserCertificates(string root, IBrowserTrust trust)
    {
        _root = Path.GetFullPath(root);
        _directory = Path.Combine(_root, "browser-https");
        _trust = trust;
    }

    public X509Certificate2 Open()
    {
        Journal state;
        X509Certificate2 leaf;
        try
        {
            if (!Directory.Exists(_directory))
            {
                throw new CryptographicException("no browser certificate is configured");
            }

            CheckDirectory(create: false);
            state = Read();
            leaf = OpenGeneration(state.Active ?? throw new CryptographicException("no browser certificate is active"),
                DateTimeOffset.UtcNow);
        }
        catch (Exception error) when (IsLifecycleError(error))
        {
            throw new BrowserCertificateException("Browser HTTPS cannot start: the recorded certificate or state failed integrity checks: " +
                Detail(error) + ". Run 'using-secrets certificate status', then 'using-secrets certificate setup' or 'using-secrets certificate replace'.",
                error);
        }

        try
        {
            VerifyRecordedTrust(state.Active!, leaf);
        }
        catch (Exception error) when (IsLifecycleError(error))
        {
            leaf.Dispose();
            throw new BrowserCertificateException("Browser HTTPS cannot start: the recorded certificate is intact, but no configured browser trust " +
                "target currently trusts that exact certificate. " + Detail(error) +
                ". Run 'using-secrets certificate status' and retry setup for the affected profile. Trust was not changed and no confirmation was requested.",
                error);
        }
        catch
        {
            leaf.Dispose();
            throw;
        }

        return leaf;
    }

    private void VerifyRecordedTrust(Generation active, X509Certificate2 leaf)
    {
        if (active.Targets.Length == 0)
        {
            throw new BrowserCertificateException("the active certificate has no recorded browser trust targets");
        }

        var unavailable = new List<string>();
        foreach (TrustTarget target in active.Targets)
        {
            try
            {
                if (_trust.Contains(target, leaf, CertificatePath(active))) return;
            }
            catch (Exception error) when (IsLifecycleError(error))
            {
                unavailable.Add(target + ": " + Detail(error));
            }
        }

        string detail = unavailable.Count == 0 ? "" : " Trust checks reported: " + string.Join("; ", unavailable) + ".";
        throw new BrowserCertificateException("no recorded browser trust target confirms this exact certificate." + detail);
    }

    internal BrowserCertificateLease OpenListener()
    {
        if (!Directory.Exists(_directory))
        {
            throw new BrowserCertificateException("No browser certificate is configured. Run using-secrets certificate setup.");
        }

        CheckDirectory(create: false);
        var lease = Lock(write: false);
        try
        {
            return new BrowserCertificateLease(Open(), lease);
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    internal X509Certificate2 OpenPreparedForTest()
    {
        var pending = Read().Pending ?? throw new InvalidOperationException("No pending test certificate.");
        return OpenGeneration(pending, DateTimeOffset.UtcNow);
    }

    private FileStream Lock(bool write)
    {
        string path = Path.Combine(_directory, "lock");
        RejectLink(path);
        try
        {
            return File.Open(path, write ? FileMode.OpenOrCreate : FileMode.Open,
                write ? FileAccess.ReadWrite : FileAccess.Read, write ? FileShare.None : FileShare.Read);
        }
        catch (IOException error)
        {
            throw new BrowserCertificateException("Could not lock the browser certificate state. Stop the authority and any certificate command, then retry.", error);
        }
    }

    public void Run(string action, bool permitPrompt, string? chromium, string? firefox, TextWriter output)
    {
        if (action is not ("status" or "prepare" or "setup" or "prepare-replacement" or "replace" or "remove"))
        {
            throw new ArgumentException("Unknown browser certificate operation.");
        }

        if (action is "status" or "remove" && !Directory.Exists(_directory))
        {
            output.WriteLine("No browser certificate is configured.");
            return;
        }

        CheckDirectory(create: true);
        if (action == "status")
        {
            var snapshot = Read();
            Describe(snapshot.Active, "Active", output);
            Describe(snapshot.Pending, "Pending", output);
            foreach (var retired in snapshot.Retired) Describe(retired, "Retired, cleanup pending", output);
            return;
        }

        using var exclusive = Lock(write: true);
        var state = Read();
        if (action == "remove")
        {
            var known = state.Retired.Select(generation => generation.Id).ToHashSet();
            var obsolete = new[] { state.Active, state.Pending }.OfType<Generation>().Where(generation => !known.Contains(generation.Id));
            state = state with
            {
                Active = null,
                Pending = null,
                Retired = [.. state.Retired, .. obsolete],
            };
            Save(state);
            CleanRetired(state, permitPrompt, output);
            return;
        }

        bool replacing = action is "prepare-replacement" or "replace";
        if (replacing && state.Pending is null && state.Retired.Length != 0)
        {
            CleanRetired(state, permitPrompt, output);
            output.WriteLine("Finished obsolete trust cleanup. The active certificate was kept.");
            return;
        }

        Generation candidate;
        if (!replacing && state.Active is { } current)
        {
            candidate = current;
        }
        else
        {
            if (replacing && state.Active is null)
            {
                throw new BrowserCertificateException("There is no active certificate to replace. Run 'using-secrets certificate setup'.");
            }

            candidate = state.Pending ?? new Generation(Guid.NewGuid(), null, null, []);
            if (state.Pending is null)
            {
                state = state with { Pending = candidate };
                Save(state);
            }

            if (candidate.Digest is null)
            {
                candidate = FinishPreparing(candidate);
                state = state with { Pending = candidate };
                Save(state);
            }
        }

        if (!File.Exists(CertificatePath(candidate)))
        {
            using var recorded = ReadRecordedPublic(candidate);
            WriteAtomically(CertificatePath(candidate), recorded.RawData);
        }

        using var publicLeaf = ReadPublic(candidate, DateTimeOffset.UtcNow);
        using var checkedKey = OpenGeneration(candidate, DateTimeOffset.UtcNow);
        output.WriteLine("Browser HTTPS public certificate: " + CertificatePath(candidate));
        output.WriteLine("SHA-256: " + candidate.Digest);
        output.WriteLine("SHA-1 for OS confirmation: " + publicLeaf.Thumbprint);

        if (action is "prepare" or "prepare-replacement")
        {
            return;
        }

        TrustTarget[] targets = [.. candidate.Targets, .. Targets(chromium, firefox),
            .. (replacing ? state.Active!.Targets : [])];
        candidate = candidate with { Targets = [.. targets.Distinct()] };
        if (candidate.Targets.Where(target => target.Path.Length != 0).GroupBy(target => target.Path).Any(group => group.Count() > 1))
        {
            throw new BrowserCertificateException("Select separate NSS databases for Chromium and Firefox.");
        }

        if (candidate.Targets.Length == 0)
        {
            throw new BrowserCertificateException("Select a Chromium NSS database or a Firefox profile using --chromium-nss or --firefox-nss.");
        }

        bool pending = state.Pending?.Id == candidate.Id;
        void Persist(Generation value)
        {
            candidate = value;
            state = pending ? state with { Pending = value } : state with { Active = value };
            Save(state); // A retry can identify the exact certificate and every store after any interruption.
        }

        Persist(candidate);
        var confirmed = new HashSet<TrustTarget>(ConfirmedTargets(candidate));
        foreach (TrustTarget target in candidate.Targets)
        {
            if (_trust.Contains(target, publicLeaf, CertificatePath(candidate)))
            {
                // Trust may have been installed by an earlier interrupted command or set manually.
                confirmed.Add(target);
                Persist(candidate with { Confirmed = [.. confirmed] });
                continue;
            }

            _trust.Install(target, publicLeaf, CertificatePath(candidate), permitPrompt, output);
            confirmed.Add(target);
            Persist(candidate with { Confirmed = [.. confirmed] });
        }

        if (pending)
        {
            state = state with
            {
                Active = candidate,
                Pending = null,
                Retired = state.Active is { } old ? [.. state.Retired, old] : state.Retired,
            };
            Save(state);
        }

        CleanRetired(state, permitPrompt, output);
        output.WriteLine("Browser HTTPS certificate is ready. Restart using-secrets after replacement and fully restart Firefox after trust changes.");
    }

    private static IEnumerable<TrustTarget> Targets(string? chromium, string? firefox)
    {
        if (OperatingSystem.IsWindows()) yield return new("windows", "");
        if (OperatingSystem.IsMacOS()) yield return new("macos", "");
        if (OperatingSystem.IsLinux() && chromium is not null) yield return new("chromium", NssPath(chromium));
        if (OperatingSystem.IsLinux() && firefox is not null) yield return new("firefox", NssPath(firefox));
    }

    private static string NssPath(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    private Generation FinishPreparing(Generation generation)
    {
        string path = CertificatePath(generation);
        RejectLink(path);
        using X509Certificate2 leaf = File.Exists(path)
            ? LoadDer(path)
            : WithKey(generation, create: true, key =>
            {
                using var created = BrowserCertificate.Create(key, DateTimeOffset.UtcNow, generation.Id);
                WriteAtomically(path, created.RawData);
                return X509CertificateLoader.LoadCertificate(created.RawData);
            });
        var complete = generation with { Digest = BrowserCertificate.Digest(leaf), Der = leaf.RawData };
        using var validated = OpenGeneration(complete, DateTimeOffset.UtcNow);
        return complete;
    }

    private void Describe(Generation? generation, string label, TextWriter output)
    {
        if (generation is null)
        {
            output.WriteLine(label + ": none");
            return;
        }

        if (generation.Digest is null)
        {
            output.WriteLine(label + ": preparation interrupted. Repeat the certificate command.");
            return;
        }

        output.WriteLine(label + " SHA-256: " + generation.Digest);
        try
        {
            using var leaf = ReadPublic(generation, DateTimeOffset.UtcNow, checkTime: false);
            output.WriteLine("Expires UTC: " + leaf.NotAfter.ToUniversalTime().ToString("O"));
            var confirmed = new HashSet<TrustTarget>(ConfirmedTargets(generation));
            bool complete = generation.Targets.Length != 0;
            foreach (TrustTarget target in generation.Targets)
            {
                try
                {
                    bool trusted = _trust.Contains(target, leaf, CertificatePath(generation));
                    complete &= trusted;
                    output.WriteLine(target + ": " + (trusted ? "trusted" : "not trusted") +
                        (confirmed.Contains(target) ? " (install confirmed)" : " (install not confirmed)"));
                }
                catch (Exception error) when (IsLifecycleError(error))
                {
                    complete = false;
                    output.WriteLine(target + ": trust check unavailable: " + Detail(error));
                }
            }

            if (!complete)
            {
                output.WriteLine("Setup incomplete: retry 'using-secrets certificate setup' for the affected target.");
            }
        }
        catch (Exception error) when (IsLifecycleError(error))
        {
            output.WriteLine("Certificate or trust unavailable: " + Detail(error));
        }
    }

    private void CleanRetired(Journal state, bool permitPrompt, TextWriter output)
    {
        foreach (Generation retired in state.Retired)
        {
            TrustTarget[] removeTargets = CleanupTargets(retired);
            if (removeTargets.Length != 0)
            {
                using var leaf = ReadRecordedPublic(retired);
                try
                {
                    if (removeTargets.Any(target => target.Kind == "windows") && _trust.IsMachineWideTrusted(leaf))
                    {
                        throw new BrowserCertificateException("This exact retired browser certificate is also trusted in LocalMachine Root. " +
                            "Remove it manually from Trusted Root Certification Authorities on the Local Computer store, then retry cleanup. " +
                            "using-secrets did not change machine-wide trust. SHA-256: " + retired.Digest);
                    }
                }
                catch (BrowserCertificateException)
                {
                    throw;
                }
                catch (Exception error) when (IsLifecycleError(error))
                {
                    throw new BrowserCertificateException("Could not check LocalMachine Root for the exact retired browser certificate. " +
                        "Verify the Local Computer Trusted Root store yourself, then retry cleanup. using-secrets did not change machine-wide trust. " +
                        "SHA-256: " + retired.Digest, error);
                }

                foreach (TrustTarget target in removeTargets)
                {
                    _trust.Remove(target, leaf, CertificatePath(retired), permitPrompt, output);
                }
            }

            // Persist successful trust removal before deleting the DER needed to verify it.
            var cleared = retired with { Targets = [], Confirmed = [] };
            state = state with { Retired = [.. state.Retired.Select(item => item.Id == retired.Id ? cleared : item)] };
            Save(state);
            DeleteKey(retired);
            DeleteFile(CertificatePath(retired));
            state = state with { Retired = [.. state.Retired.Where(item => item.Id != retired.Id)] };
            Save(state);
        }
    }

    private X509Certificate2 OpenGeneration(Generation generation, DateTimeOffset now)
    {
        using var leaf = ReadPublic(generation, now);
        return WithKey(generation, create: false, key =>
        {
            try
            {
                return leaf.CopyWithPrivateKey(key);
            }
            catch (ArgumentException)
            {
                throw new CryptographicException("the private key does not match the recorded browser certificate");
            }
        });
    }

    private X509Certificate2 ReadPublic(Generation generation, DateTimeOffset now, bool checkTime = true)
    {
        using var candidate = LoadDer(CertificatePath(generation));
        if (generation.Digest != BrowserCertificate.Digest(candidate))
        {
            throw new CryptographicException("the browser certificate does not match its recorded SHA-256 identity");
        }

        BrowserCertificate.Validate(candidate, now, checkTime);
        return X509CertificateLoader.LoadCertificate(candidate.RawData);
    }

    private static X509Certificate2 ReadRecordedPublic(Generation generation)
    {
        var certificate = X509CertificateLoader.LoadCertificate(generation.Der ??
            throw new CryptographicException("the exact browser certificate was not recorded"));
        try
        {
            if (!generation.Der.AsSpan().SequenceEqual(certificate.RawData) ||
                generation.Digest != BrowserCertificate.Digest(certificate))
            {
                throw new CryptographicException("the recorded browser certificate identity is inconsistent");
            }

            BrowserCertificate.Validate(certificate, DateTimeOffset.UtcNow, checkTime: false);
            return certificate;
        }
        catch
        {
            certificate.Dispose();
            throw;
        }
    }

    private static X509Certificate2 LoadDer(string path)
    {
        RejectLink(path);
        if (!File.Exists(path))
        {
            throw new CryptographicException("the recorded browser certificate is missing");
        }

        byte[] data = BoundedRead(path, 4096);
        var certificate = X509CertificateLoader.LoadCertificate(data);
        if (!data.AsSpan().SequenceEqual(certificate.RawData))
        {
            certificate.Dispose();
            throw new CryptographicException("the browser certificate file is not exact DER");
        }

        return certificate;
    }

    private T WithKey<T>(Generation generation, bool create, Func<ECDsa, T> use)
    {
        if (OperatingSystem.IsWindows())
        {
            string name = KeyName(generation);
            var provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
            using var key = CngKey.Exists(name, provider)
                ? CngKey.Open(name, provider)
                : create ? CngKey.Create(CngAlgorithm.ECDsaP256, name, new CngKeyCreationParameters
                {
                    Provider = provider,
                    ExportPolicy = CngExportPolicies.None,
                    KeyUsage = CngKeyUsages.Signing,
                }) : throw new CryptographicException("the browser TLS key is missing from the current user's CNG store");
            if (key.Algorithm != CngAlgorithm.ECDsaP256 || key.ExportPolicy != CngExportPolicies.None ||
                key.KeyUsage != CngKeyUsages.Signing)
            {
                throw new CryptographicException("the browser TLS key is not a non-exportable P-256 signing key");
            }

            using var signing = new ECDsaCng(key);
            return use(signing);
        }

        string path = KeyPath(generation);
        using FileSigningKey keyFile = (create ? FileSigningKey.OpenOrCreate(path, out _, _root) : FileSigningKey.TryOpen(path, _root))
            ?? throw new CryptographicException("the browser TLS key file is missing");
        return keyFile.UseBrowserKey(use);
    }

    private void DeleteKey(Generation generation)
    {
        if (OperatingSystem.IsWindows())
        {
            string name = KeyName(generation);
            var provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
            if (CngKey.Exists(name, provider))
            {
                using var key = CngKey.Open(name, provider);
                key.Delete();
            }
        }
        else
        {
            DeleteFile(KeyPath(generation));
        }
    }

    private void CheckDirectory(bool create)
    {
        RejectLink(_root);
        RejectLink(_directory);
        if (OperatingSystem.IsWindows())
        {
            if (create) Directory.CreateDirectory(_directory);
        }
        else
        {
            FileSigningKey.CheckDirectory(_directory, create, _root);
        }
    }

    private static void RejectLink(string path)
    {
        if (new FileInfo(path).LinkTarget is not null ||
            (File.Exists(path) || Directory.Exists(path)) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new BrowserCertificateException("The browser HTTPS state path is a link or reparse point.");
        }
    }

    private static void DeleteFile(string path)
    {
        RejectLink(path);
        File.Delete(path);
    }

    private string KeyName(Generation generation)
    {
        string scope = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(_root.ToUpperInvariant())))[..24];
        return "arcana-guardian-browser-" + scope + "-" + generation.Id.ToString("N");
    }
    private string KeyPath(Generation generation) => Path.Combine(_directory, generation.Id.ToString("N") + ".key");
    private string CertificatePath(Generation generation) => Path.Combine(_directory, generation.Id.ToString("N") + ".cer");
    private string JournalPath => Path.Combine(_directory, "state.json");

    private Journal Read()
    {
        RejectLink(JournalPath);
        if (!File.Exists(JournalPath)) return new(null, null, []);
        var state = JsonSerializer.Deserialize<Journal>(BoundedRead(JournalPath, 65536));
        if (state?.Retired is null) throw new BrowserCertificateException("The browser certificate journal is invalid.");
        state = state with
        {
            Active = state.Active is { } active ? Normalize(active) : null,
            Pending = state.Pending is { } pending ? Normalize(pending) : null,
            Retired = [.. state.Retired.Select(Normalize)],
        };
        var seen = new HashSet<Guid>();
        foreach (Generation item in new[] { state.Active, state.Pending }.OfType<Generation>().Concat(state.Retired))
        {
            if (item is null || item.Id == Guid.Empty || !seen.Add(item.Id) || item.Targets is null ||
                item.Confirmed is null ||
                (item.Digest is null && (item == state.Active || item.Targets.Length != 0 || item.Der is not null)) ||
                (item.Digest is not null && item.Der is not { Length: > 0 and <= 4096 }) ||
                (item.Digest is { } digest && (digest.Length != 64 || !digest.All(char.IsAsciiHexDigit))) ||
                item.Targets.Any(target => target is null || !target.IsValid()) ||
                item.Confirmed.Any(target => target is null || !target.IsValid() || !item.Targets.Contains(target)))
            {
                throw new BrowserCertificateException("The browser certificate journal is invalid.");
            }
        }

        return state;
    }

    private static Generation Normalize(Generation generation) => generation with
    {
        Confirmed = [.. (generation.Confirmed ?? []).Distinct()],
    };

    private static TrustTarget[] ConfirmedTargets(Generation generation) => generation.Confirmed ?? [];

    private static TrustTarget[] CleanupTargets(Generation generation) =>
        generation.Confirmed is { Length: > 0 } confirmed ? confirmed : generation.Targets;

    private void Save(Journal state) => WriteAtomically(JournalPath, JsonSerializer.SerializeToUtf8Bytes(state));

    private static byte[] BoundedRead(string path, int limit)
    {
        using var file = File.OpenRead(path);
        if (file.Length is 0 || file.Length > limit) throw new BrowserCertificateException("A browser certificate state file has an invalid length.");
        byte[] bytes = new byte[(int)file.Length];
        file.ReadExactly(bytes);
        return bytes;
    }

    private static void WriteAtomically(string path, byte[] bytes)
    {
        string temporary = path + ".new";
        DeleteFile(temporary);
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var file = new FileStream(temporary, options))
        {
            file.Write(bytes);
            file.Flush(flushToDisk: true);
        }

        File.Move(temporary, path, overwrite: true);
    }

    public static bool IsLifecycleError(Exception error) => error is IOException or UnauthorizedAccessException or
        CryptographicException or JsonException or System.Formats.Asn1.AsnContentException or ArgumentException or InvalidOperationException;

    public static string Detail(Exception error) => error is JsonException or System.Formats.Asn1.AsnContentException
        ? "the browser certificate state or encoding is malformed" : error.Message;

    private sealed record Generation(Guid Id, string? Digest, byte[]? Der, TrustTarget[] Targets, TrustTarget[]? Confirmed = null);
    private sealed record Journal(Generation? Active, Generation? Pending, Generation[] Retired);
}

internal sealed record BrowserCertificateLease(X509Certificate2 Certificate, FileStream Lock) : IDisposable
{
    public void Dispose()
    {
        Certificate.Dispose();
        Lock.Dispose();
    }
}

public sealed class BrowserCertificateException(string message, Exception? inner = null) : IOException(message, inner);
