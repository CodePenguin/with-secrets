using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using LocalHttpsLeaf;

string? mode = args.FirstOrDefault();
if (mode is "--windows-client" or "--linux-client")
{
    bool windows = mode == "--windows-client";
    if (args.Length < 2 || (windows && !OperatingSystem.IsWindows()) || (!windows && !OperatingSystem.IsLinux()))
    {
        throw new ArgumentException("Use the client mode for the browser host OS and pass the server's public certificate path.");
    }

    using var remoteLeaf = X509CertificateLoader.LoadCertificateFromFile(args[1]);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    using var presented = await SpikeCertificates.ReadPresentedAsync(
        SpikeCertificates.LeafPort, SpikeCertificates.Host, remoteLeaf, timeout.Token);
    SpikeCertificates.VerifyLeafProfile(presented);
    Console.WriteLine($"Forwarded server presented exact certificate {presented.Thumbprint}.");
    using var stop = new CancellationTokenSource();
    Console.CancelKeyPress += (_, eventArgs) =>
    {
        eventArgs.Cancel = true;
        stop.Cancel();
    };
    if (OperatingSystem.IsWindows())
    {
        await BrowserTests.RunWindowsAsync(remoteLeaf, null, null, args[2..], stop.Token);
    }
    else
    {
        await BrowserTests.RunLinuxAsync(remoteLeaf, args[2..], stop.Token);
    }
    return;
}

bool automated = mode is "--browser-tests" or "--linux-browser-tests" or "--diagnostics-only";
using var certificates = new SpikeCertificates();
var builder = WebApplication.CreateBuilder(automated ? [] : args);
if (automated)
{
    builder.Logging.SetMinimumLevel(LogLevel.Warning);
}

await using var app = builder.BuildSpike(certificates);
if (automated)
{
    await app.StartAsync();
    try
    {
        await certificates.VerifyAsync(app.Lifetime.ApplicationStopping);
        using var leaf = X509CertificateLoader.LoadCertificate(certificates.Leaf.RawData);
        if (mode == "--browser-tests" && OperatingSystem.IsWindows())
        {
            await BrowserTests.RunWindowsAsync(leaf, certificates.Child, certificates.Reissued, args[1..], app.Lifetime.ApplicationStopping);
        }
        else if (mode == "--linux-browser-tests" && OperatingSystem.IsLinux())
        {
            await BrowserTests.RunLinuxAsync(leaf, args[1..], app.Lifetime.ApplicationStopping);
        }
        else if (mode != "--diagnostics-only")
        {
            throw new PlatformNotSupportedException("Use the browser test mode for the host OS.");
        }
    }
    finally
    {
        await app.StopAsync();
    }
}
else
{
    string path = Path.Combine(Path.GetTempPath(), $"with-secrets-leaf-{Guid.NewGuid():N}.cer");
    try
    {
        await app.StartAsync();
        await certificates.VerifyAsync(app.Lifetime.ApplicationStopping);
        File.WriteAllBytes(path, certificates.Leaf.Export(X509ContentType.Cert));
        Console.WriteLine($"Public certificate: {path}\nSHA256: {certificates.Leaf.GetCertHashString(HashAlgorithmName.SHA256)}\nSHA1 (cleanup): {certificates.Leaf.Thumbprint}");
        await app.WaitForShutdownAsync();
    }
    finally
    {
        File.Delete(path);
    }
}
