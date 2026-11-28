using System.Text;
using System.Diagnostics;

namespace ArcanaGuardian.Tests;

/// <summary>A subprocess seam. The fixture format is deliberately distinct from production encryption.</summary>
internal sealed class FakeDotenvx : IDisposable
{
    public const string Credential = "fake-resolver-credential-canary";
    public const string PublicKey = "03a435b2dc61a408876ba5f2afa0a6ab5c827e2167228c3b8c9d1a8253ccd62514";
    private readonly string? _previousExecutable = Environment.GetEnvironmentVariable(DotenvxRun.ExecutableVariable);
    private readonly string? _previousToken = Environment.GetEnvironmentVariable("DOTENVX_ARMOR_TOKEN");
    private readonly string? _previousCurrentToken = Environment.GetEnvironmentVariable("DOTENVX_TOKEN");

    public FakeDotenvx()
    {
        string executable = Path.Combine(AppContext.BaseDirectory,
            OperatingSystem.IsWindows() ? "ArcanaGuardian.Tests.exe" : "ArcanaGuardian.Tests");
        Environment.SetEnvironmentVariable(DotenvxRun.ExecutableVariable, executable);
        Environment.SetEnvironmentVariable("DOTENVX_ARMOR_TOKEN", Credential);
        Environment.SetEnvironmentVariable("DOTENVX_TOKEN", Credential);
    }

    public static string Cipher(string value) => "encrypted:" + Convert.ToBase64String(Encoding.UTF8.GetBytes("fixture:" + value));

    public static int Run(string[] args)
    {
        if (File.Exists(Path.Combine(Directory.GetCurrentDirectory(), "Envfile")))
        {
            Console.Error.Write("[ACCESS_APPROVAL_");
            Console.Error.Flush();
            Thread.Sleep(50);
            Console.Error.WriteLine("REQUIRED] simulated prompt with an approval link");
            Thread.Sleep(TimeSpan.FromSeconds(30));
            return 1;
        }

        int separator = Array.IndexOf(args, "--");
        if (Environment.GetEnvironmentVariable("DOTENVX_ARMOR_TOKEN") != Credential
            || Environment.GetEnvironmentVariable("DOTENVX_TOKEN") != Credential
            || Environment.GetEnvironmentVariable("TOKEN") is not null
            || separator < 2 || separator % 2 != 0 || separator == args.Length - 1)
        {
            return 1;
        }

        ProcessStartInfo start = new(args[separator + 1]) { UseShellExecute = false };
        foreach (string argument in args[(separator + 2)..])
        {
            start.ArgumentList.Add(argument);
        }

        for (int i = separator - 2; i >= 0; i -= 2)
        {
            string file = args[i + 1];
            (IReadOnlyList<EnvDeclarations.Entry>? entries, _) = EnvDeclarations.Parse(file, File.ReadAllText(file));
            if (args[i] != "-f" || entries is null)
            {
                return 1;
            }

            foreach (var entry in entries)
            {
                if (!entry.Value.StartsWith("encrypted:", StringComparison.Ordinal))
                {
                    start.Environment[entry.Name] = entry.Value switch
                    {
                        "visible" when entry.Name == "LOG_LEVEL" => "fake-unapproved-literal",
                        "$LOG_LEVEL" when entry.Name == "COMPUTED" => "fake-expanded-value",
                        _ => entry.Value,
                    };
                    continue;
                }

                try
                {
                    string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(entry.Value["encrypted:".Length..]));
                    if (!decoded.StartsWith("fixture:", StringComparison.Ordinal))
                    {
                        return 1;
                    }

                    start.Environment[entry.Name] = decoded["fixture:".Length..];
                }
                catch (FormatException)
                {
                    return 1;
                }
            }
        }

        using Process child = Process.Start(start)!;
        child.WaitForExit();
        return child.ExitCode;
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(DotenvxRun.ExecutableVariable, _previousExecutable);
        Environment.SetEnvironmentVariable("DOTENVX_ARMOR_TOKEN", _previousToken);
        Environment.SetEnvironmentVariable("DOTENVX_TOKEN", _previousCurrentToken);
    }
}
