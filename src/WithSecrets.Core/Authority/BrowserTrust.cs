using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace WithSecrets;

internal sealed record TrustTarget(string Kind, string Path)
{
    public bool IsValid() => Kind switch
    {
        "windows" or "macos" => Path == "",
        "chromium" or "firefox" => Path is not null && System.IO.Path.IsPathFullyQualified(Path),
        _ => false,
    };

    public override string ToString() => Path.Length == 0 ? Kind : Kind + " " + Path;
}

internal interface IBrowserTrust
{
    bool Contains(TrustTarget target, X509Certificate2 certificate, string path);
    void Install(TrustTarget target, X509Certificate2 certificate, string path, bool permitPrompt, TextWriter output);
    void Remove(TrustTarget target, X509Certificate2 certificate, string path, bool permitPrompt, TextWriter output);
}

internal sealed class BrowserTrust : IBrowserTrust
{
    public bool Contains(TrustTarget target, X509Certificate2 certificate, string path)
    {
        if (target.Kind == "windows" && OperatingSystem.IsWindows())
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            using var entry = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\SystemCertificates\Root\Certificates\" + certificate.Thumbprint);
            return entry is not null && WindowsEntries(store, certificate).Any();
        }

        if (target.Kind == "macos" && OperatingSystem.IsMacOS())
        {
            return MacLoginContains(certificate) &&
                Run("/usr/bin/security", "verify-cert", "-c", path, "-p", "ssl", "-s", BrowserAddress.Host).Code == 0;
        }

        (bool present, string flags) = NssEntry(target, certificate);
        return present && flags == Flags(target);
    }

    public void Install(TrustTarget target, X509Certificate2 certificate, string path, bool permitPrompt, TextWriter output)
    {
        if (Contains(target, certificate, path)) return;

        if (target.Kind == "windows" && OperatingSystem.IsWindows())
        {
            WindowsChange(certificate, install: true, permitPrompt, output);
        }
        else if (target.Kind == "macos" && OperatingSystem.IsMacOS())
        {
            throw new BrowserCertificateException("Import this exact public certificate into the login keychain and set its SSL trust in Keychain Access. Then retry the command. Check Safari or Chromium with its ordinary TLS validation.");
        }
        else
        {
            Nss(target, "-A", "-n", Nickname(certificate), "-t", Flags(target), "-i", path);
        }

        if (!Contains(target, certificate, path))
        {
            throw new BrowserCertificateException("The exact browser certificate is still untrusted in " + target + ". Retry setup after approving the OS confirmation or checking the browser profile.");
        }
    }

    public void Remove(TrustTarget target, X509Certificate2 certificate, string path, bool permitPrompt, TextWriter output)
    {
        if (target.Kind == "windows" && OperatingSystem.IsWindows())
        {
            if (Contains(target, certificate, path))
            {
                WindowsChange(certificate, install: false, permitPrompt, output);
                if (Contains(target, certificate, path))
                {
                    throw new BrowserCertificateException("The exact browser certificate is still in CurrentUser Root. Retry cleanup after confirming removal.");
                }
            }

            return;
        }

        if (target.Kind == "macos" && OperatingSystem.IsMacOS())
        {
            if (MacLoginContains(certificate))
            {
                throw new BrowserCertificateException("Remove the exact browser certificate from the login keychain in Keychain Access, then retry. SHA-256: " + BrowserCertificate.Digest(certificate));
            }

            return;
        }

        if (NssEntry(target, certificate).Present)
        {
            Nss(target, "-D", "-n", Nickname(certificate));
            if (NssEntry(target, certificate).Present) throw new BrowserCertificateException("NSS still contains the exact obsolete browser certificate.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static IEnumerable<bool> WindowsEntries(X509Store store, X509Certificate2 certificate)
    {
        foreach (var item in store.Certificates)
        {
            using (item)
            {
                if (item.RawData.AsSpan().SequenceEqual(certificate.RawData)) yield return true;
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static void WindowsChange(X509Certificate2 certificate, bool install, bool permitPrompt, TextWriter output)
    {
        if (!permitPrompt)
        {
            throw new BrowserCertificateException("Windows trust changes require a signed-in interactive terminal. The OS may ask to confirm the exact certificate. Prepare or check status without changing trust.");
        }

        using var machine = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        machine.Open(OpenFlags.ReadOnly);
        if (WindowsEntries(machine, certificate).Any())
        {
            throw new BrowserCertificateException("This exact certificate is in LocalMachine Root. Remove that entry separately before managing CurrentUser trust.");
        }

        output.WriteLine((install ? "Install" : "Remove") + " the exact CurrentUser Root leaf " + certificate.Thumbprint +
            ". Windows may call it a CA in its confirmation. This certificate has CA=false and is for browser HTTPS only.");
        output.Flush();
        using var current = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        current.Open(OpenFlags.ReadWrite);
        if (install) current.Add(certificate); else current.Remove(certificate);
    }

    private static string Flags(TrustTarget target) => target.Kind == "chromium" ? "P,," : "C,,";
    private static string Nickname(X509Certificate2 certificate) => "with-secrets-browser-" + BrowserCertificate.Digest(certificate)[..40];

    private static (bool Present, string Flags) NssEntry(TrustTarget target, X509Certificate2 certificate)
    {
        string nickname = Nickname(certificate);
        string listing = Nss(target, "-L");
        string? entry = listing.Split('\n').SingleOrDefault(line =>
            line.StartsWith(nickname, StringComparison.Ordinal) && line.Length > nickname.Length &&
            char.IsWhiteSpace(line[nickname.Length]));
        if (entry is null) return (false, "");

        string pem = Nss(target, "-L", "-n", nickname, "-a");
        using var loaded = X509Certificate2.CreateFromPem(pem);
        if (!loaded.RawData.AsSpan().SequenceEqual(certificate.RawData))
        {
            throw new BrowserCertificateException("An NSS entry has the expected nickname but different certificate bytes. It was left alone.");
        }

        return (true, entry[nickname.Length..].Trim());
    }

    private static string Nss(TrustTarget target, params string[] args)
    {
        if (!OperatingSystem.IsLinux() || target.Kind is not ("firefox" or "chromium"))
        {
            throw new BrowserCertificateException("This trust target cannot be accessed on the current OS.");
        }

        string database = Path.Combine(target.Path, "cert9.db");
        if (!File.Exists(database))
        {
            throw new BrowserCertificateException("No existing SQL NSS database in " + target.Path + ". Start and close the browser to initialize the intended profile.");
        }

        var result = Run("certutil", ["-d", "sql:" + target.Path, .. args]);
        if (result.Code != 0)
        {
            throw new BrowserCertificateException("NSS could not access " + target.Path + ". Close the browser, check the profile and ensure NSS certutil is installed. Password-protected profiles may require manual setup.");
        }

        return result.Output;
    }

    private static bool MacLoginContains(X509Certificate2 certificate)
    {
        string login = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library", "Keychains", "login.keychain-db");
        if (!File.Exists(login))
        {
            throw new BrowserCertificateException("The macOS login keychain could not be located.");
        }

        var result = Run("/usr/bin/security", "find-certificate", "-a", "-p", login);
        if (result.Code != 0)
        {
            throw new BrowserCertificateException("The macOS login keychain could not be queried.");
        }

        foreach (Match match in Regex.Matches(result.Output, "-----BEGIN CERTIFICATE-----[\\s\\S]*?-----END CERTIFICATE-----"))
        {
            using var found = X509Certificate2.CreateFromPem(match.Value);
            if (found.RawData.AsSpan().SequenceEqual(certificate.RawData)) return true;
        }

        return false;
    }

    private static (int Code, string Output) Run(string executable, params string[] args)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.Environment["LC_ALL"] = "C";
        foreach (string arg in args) start.ArgumentList.Add(arg);
        try
        {
            using var process = Process.Start(start) ?? throw new BrowserCertificateException("Could not start the browser trust utility.");
            process.StandardInput.Close();
            var read = process.StandardOutput.ReadToEndAsync();
            var errors = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(12000))
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
                throw new BrowserCertificateException("The browser trust utility timed out. Check the profile and try again.");
            }

            _ = errors.GetAwaiter().GetResult();
            return (process.ExitCode, read.GetAwaiter().GetResult());
        }
        catch (System.ComponentModel.Win32Exception)
        {
            throw new BrowserCertificateException("Could not start " + executable + ". Install the browser trust utility and retry.");
        }
    }
}
