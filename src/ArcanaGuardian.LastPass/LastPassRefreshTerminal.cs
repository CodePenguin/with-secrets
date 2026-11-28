using System.Security.Cryptography;
using System.Text;

namespace ArcanaGuardian.LastPass;

/// <summary>The interactive terminal workflow used by the installed helper on all platforms.</summary>
public static class LastPassRefreshTerminal
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly TimeSpan HandoffTimeout = TimeSpan.FromSeconds(15);

    public static async Task<int> RunAsync(Stream privateChannel, string pinnedAuthorityFingerprint, CancellationToken cancel)
    {
        if (Console.IsInputRedirected || Console.IsOutputRedirected)
        {
            Console.Error.WriteLine("The Arcana Guardian LastPass helper requires an interactive terminal.");
            return 1;
        }

        try
        {
            using CancellationTokenSource handoffDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            handoffDeadline.CancelAfter(HandoffTimeout);
            using LastPassRefreshHandoff handoff = await LastPassRefreshHandoff.AcceptAsync(privateChannel, privateChannel,
                pinnedAuthorityFingerprint, handoffDeadline.Token).ConfigureAwait(false);
            LastPassRefreshRequest request = handoff.Request;
            using CancellationTokenSource refreshDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            TimeSpan remaining = request.Expires - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero) throw new OperationCanceledException();
            refreshDeadline.CancelAfter(remaining);
            CancellationToken refresh = refreshDeadline.Token;
            Task connection = CancelOnDisconnectAsync(privateChannel, refreshDeadline);
            try
            {
                await RefreshAsync(privateChannel, handoff, request, refresh).ConfigureAwait(false);
            }
            finally
            {
                await refreshDeadline.CancelAsync().ConfigureAwait(false);
                await connection.ConfigureAwait(false);
            }
            return 0;

        }
        catch (ProviderAdapterException error)
        {
            Console.Error.WriteLine(error.Message);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("The Arcana Guardian LastPass refresh was cancelled or expired.");
        }
        catch (EncoderFallbackException)
        {
            Console.Error.WriteLine("The terminal could not read the LastPass password as Unicode.");
        }
        catch (Exception error) when (error is IOException or InvalidOperationException or CryptographicException or ArgumentException)
        {
            Console.Error.WriteLine("The Arcana Guardian LastPass refresh could not be completed.");
        }
        return 1;
    }

    private static async Task RefreshAsync(Stream privateChannel, LastPassRefreshHandoff handoff,
        LastPassRefreshRequest request, CancellationToken cancel)
    {
        ShowRequest(Console.Out, request, handoff.MatchingCode);
        Console.WriteLine("Compare the code and request details with the Arcana Guardian browser page.");
        Console.WriteLine("Press Enter if they match, or Esc to cancel.");
        if ((await ReadKeyAsync(cancel).ConfigureAwait(false)).Key != ConsoleKey.Enter) throw new OperationCanceledException();

        LastPassRefreshHandoff.CheckExpiry(request);
        byte[] password = await ReadPasswordAsync(cancel).ConfigureAwait(false);
        try
        {
            using SecretValues values = await LastPassRefreshReader.ReadAsync(request.Username, request.European,
                password, LastPassRefreshHandoff.Paths(request), cancel).ConfigureAwait(false);
            await handoff.SendStageAsync(privateChannel, values, cancel).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(password); }
        Console.WriteLine("Selected values encrypted. Return to Arcana Guardian to review and approve the refresh.");
    }

    private static async Task CancelOnDisconnectAsync(Stream channel, CancellationTokenSource deadline)
    {
        try { await channel.ReadAsync(new byte[1], deadline.Token).ConfigureAwait(false); }
        catch (Exception error) when (error is IOException or OperationCanceledException or ObjectDisposedException) { }
        await deadline.CancelAsync().ConfigureAwait(false);
    }

    internal static void ShowRequest(TextWriter output, LastPassRefreshRequest request, string matchingCode)
    {
        output.WriteLine("Arcana Guardian | LastPass refresh");
        output.WriteLine($"Requested by  {request.RequestedBy}");
        output.WriteLine($"Provider      {request.ProviderName} ({(request.European ? "lastpass.eu" : "lastpass.com")})");
        output.WriteLine($"Account       {request.Username}");
        foreach (LastPassRefreshMapping mapping in request.Mappings)
        {
            int separator = mapping.Path.IndexOf('/');
            string? field = LastPassRefreshSelection.FieldName(mapping.Path[(separator + 1)..]);
            output.WriteLine($"  Item {mapping.Path[..separator]} / {field} → {mapping.LocalName}");
        }
        output.WriteLine($"Matching code  {matchingCode}");
    }

    private static async Task<ConsoleKeyInfo> ReadKeyAsync(CancellationToken cancel)
    {
        while (!Console.KeyAvailable)
            await Task.Delay(50, cancel).ConfigureAwait(false);
        cancel.ThrowIfCancellationRequested();
        return Console.ReadKey(intercept: true);
    }

    private static async Task<byte[]> ReadPasswordAsync(CancellationToken cancel)
    {
        char[] password = new char[4096];
        int count = 0;
        Console.Write("LastPass master password (hidden, Esc cancels) ");
        try
        {
            while (true)
            {
                ConsoleKeyInfo key = await ReadKeyAsync(cancel).ConfigureAwait(false);
                switch (key.Key)
                {
                    case ConsoleKey.Escape:
                        throw new OperationCanceledException();
                    case ConsoleKey.Enter:
                        if (count == 0) throw new OperationCanceledException();
                        byte[] utf8 = new byte[Utf8.GetByteCount(password.AsSpan(0, count))];
                        Utf8.GetBytes(password.AsSpan(0, count), utf8);
                        return utf8;
                    case ConsoleKey.Backspace when count > 0:
                        password[--count] = '\0';
                        break;
                    default:
                        if (char.IsControl(key.KeyChar)) break;
                        if (count == password.Length)
                            throw new ProviderAdapterException(ProviderErrorKind.InvalidConfiguration, "The LastPass master password exceeds the supported length.");
                        password[count++] = key.KeyChar;
                        break;
                }
            }
        }
        finally
        {
            Array.Clear(password);
            Console.WriteLine();
        }
    }
}
