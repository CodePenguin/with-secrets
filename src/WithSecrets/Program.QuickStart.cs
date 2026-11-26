using System.Diagnostics;
using System.Globalization;

namespace WithSecrets;

internal static partial class Program
{
    private const string QuickStartCode = "quick-start:read-code";
    private const string QuickStartResult = "quick-start:result:";

    private static string? ReadQuickStartCode()
    {
        Console.Out.WriteLine(QuickStartCode);
        return Console.ReadLine();
    }

    /// <summary>The person owns this terminal. The child owns the local service and the browser flow, and remains running after setup.</summary>
    private static async Task<int> StartQuickStart(CliCommand.AdminApp command)
    {
        if (Environment.ProcessPath is not { } executable)
        {
            TerminalPrompt.Final("with-secrets: could not locate the program to start the local service.");
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
            TerminalPrompt.Final("with-secrets: the local service could not start or finish Quick Start.");
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
