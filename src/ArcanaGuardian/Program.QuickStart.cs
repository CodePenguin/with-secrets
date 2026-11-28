using System.Diagnostics;
using System.Globalization;

namespace ArcanaGuardian;

internal static partial class Program
{
    private const string QuickStartCode = "quick-start:read-code";
    private const string QuickStartResult = "quick-start:result:";

    private static string? ReadQuickStartCode()
    {
        Console.Out.WriteLine(QuickStartCode);
        return Console.ReadLine();
    }

    private static async Task<int> WatchDesktop(TextWriter output)
    {
        string folder = StorePath();
        HostConfigFile configFile = HostConfigFile.InFolder(folder);
        ServiceTrust trust = ServiceTrust.From(configFile);
        if (trust is { PinnedFingerprint: null, Problem: null } && configFile.Load() is { Problem: null } local &&
            local.Config?.Remote is null && StateDatabase.InFolder(folder).TryManifest(out Manifest? manifest, out _))
        {
            if (manifest is null && local.Config is null)
            {
                await output.WriteLineAsync("{\"setupRequired\":true}");
                return 0;
            }

            if (manifest is not null)
            {
                // A committed setup can be missing its authority pin. The existing private
                // machine key still authenticates a status-only connection to its service.
                LinuxHardening.HardenProcess();
                if (LocalDeployment.ExistingMachineFingerprint(folder) is { } existingFingerprint &&
                    (local.Config is null || local.Config.MachineFingerprint == existingFingerprint))
                {
                    trust = new ServiceTrust(existingFingerprint);
                }
            }
        }

        return await CompanionWatch.RunAsync(trust, output, Console.Error);
    }

    /// <summary>The person owns this terminal. The child owns the local service and the browser flow, and remains running after setup.</summary>
    private static async Task<int> StartQuickStart(CliCommand.AdminApp command)
    {
        if (Environment.ProcessPath is not { } executable)
        {
            TerminalPrompt.Final("using-secrets: could not locate the program to start the local service.");
            return RunCommand.StoreError;
        }

        ProcessStartInfo start = new(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            start.ArgumentList.Add(Path.GetFullPath(Environment.GetCommandLineArgs()[0]));
        }

        start.ArgumentList.Add("--quick-start-worker");
        if (command.AdminPort is { } port)
        {
            start.ArgumentList.Add("--port");
            start.ArgumentList.Add(port.ToString(CultureInfo.InvariantCulture));
        }

        try
        {
            using Process child = Process.Start(start) ?? throw new InvalidOperationException("the service could not be started");
            Task<string> errors = child.StandardError.ReadToEndAsync();
            int asked = 0;
            bool finished = false;
            ConsoleCancelEventHandler cancel = (_, _) => StopQuickStart(child);
            Console.CancelKeyPress += cancel;
            try
            {
                Task<string?> next = child.StandardOutput.ReadLineAsync();
                while (await next is { } line)
                {
                    if (line.StartsWith(QuickStartResult, StringComparison.Ordinal)
                        && int.TryParse(line.AsSpan(QuickStartResult.Length), CultureInfo.InvariantCulture, out int result))
                    {
                        finished = true;
                        return result;
                    }

                    next = child.StandardOutput.ReadLineAsync();
                    if (line == QuickStartCode)
                    {
                        bool again = asked++ > 0;
                        Task<string?> entered = Task.Run(() => TerminalPrompt.ReadCode(again));
                        if (await Task.WhenAny(entered, next) == entered)
                        {
                            if (await entered is { } code)
                            {
                                await child.StandardInput.WriteLineAsync(code);
                                await child.StandardInput.FlushAsync();
                            }
                            else child.StandardInput.Close();
                        }
                        continue;
                    }

                    TerminalPrompt.Line(line);
                    if (line.StartsWith(FirstRunPage.AnnouncePrefix, StringComparison.Ordinal))
                    {
                        OpenInBrowser(command)?.Invoke(line[FirstRunPage.AnnouncePrefix.Length..]);
                    }
                }

                await child.WaitForExitAsync();
                string diagnostic = (await errors).Trim();
                if (diagnostic.Length > 0) TerminalPrompt.Final(diagnostic);
                return child.ExitCode == 0 ? RunCommand.StoreError : child.ExitCode;
            }
            finally
            {
                Console.CancelKeyPress -= cancel;
                if (!finished) StopQuickStart(child);
            }
        }
        catch (Exception error) when (error is InvalidOperationException or IOException or System.ComponentModel.Win32Exception)
        {
            TerminalPrompt.Final("using-secrets: the local service could not start or finish Quick Start.");
            return RunCommand.StoreError;
        }
    }

    private static void StopQuickStart(Process child)
    {
        try
        {
            if (!child.HasExited) child.Kill();
        }
        catch (Exception error) when (error is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // The worker may already have exited.
        }
    }
}
