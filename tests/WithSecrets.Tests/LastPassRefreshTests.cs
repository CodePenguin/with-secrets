using System.Buffers.Binary;
using System.IO.Pipes;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using WithSecrets.LastPass;

namespace WithSecrets.Tests;

internal static class LastPassRefreshTests
{
    private const string PasswordPath = "100/F_70617373776F7264";
    private const string UsernamePath = "100/F_757365726E616D65";
    private const string UrlPath = "100/F_75726C";
    private const string Username = "vault@example.test";
    private const string SelectedValue = "refresh fixture ☃";

    public static async Task Run(Action<bool, string> check)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(15));
        await ReadAndClose(check, timeout.Token);
        await SignedHandoff(check, timeout.Token);
    }

    private static async Task ReadAndClose(Action<bool, string> check, CancellationToken cancel)
    {
        byte[] password = "only used by the fixture"u8.ToArray();
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, Encoding.UTF8.GetBytes(Username), 100, HashAlgorithmName.SHA256, 32);
        string proof = Convert.ToHexStringLower(Rfc2898DeriveBytes.Pbkdf2(key, password, 1, HashAlgorithmName.SHA256, 32));
        byte[] vault = Vault(key, protectedItem: false);

        using FixtureHandler success = new(vault, proof);
        using (HttpClient client = new(success))
        using (SecretValues values = await LastPassRefreshReader.ReadAsync(
            client, Username.ToUpperInvariant(), true, password, [PasswordPath, UsernamePath, UrlPath], cancel))
        {
            check(values.Names.Count == 3 && values.Text(PasswordPath) == SelectedValue
                && values.Bytes(UsernamePath).Length == 0 && values.Text(UrlPath) == "https://example.test",
                "LastPass refresh streams only the selected fields and preserves an empty value");
            check(success.Requests.SequenceEqual(["/iterations.php", "/login.php", "/getaccts.php", "/logout.php", "/login_check.php"])
                && success.ExpectedRequest && password.All(value => value == 0),
                "LastPass refresh uses the expected region, login proof and session and verifies logout after a redirect");
        }

        foreach ((FixtureHandler handler, ProviderErrorKind error, bool loginOnly, string name) in new[]
        {
            (new FixtureHandler(vault, proof) { SessionClosed = false }, ProviderErrorKind.Unavailable, false,
                "withholds values when logout is unconfirmed"),
            (new FixtureHandler(vault[..^1], proof), ProviderErrorKind.InvalidResponse, false,
                "closes the session after a truncated vault response"),
            (new FixtureHandler(Vault(key, protectedItem: true), proof), ProviderErrorKind.InteractionRequired, false,
                "requires a separate protected-item interaction"),
            (new FixtureHandler(vault, proof) { RequireMfa = true }, ProviderErrorKind.InteractionRequired, true,
                "does not fetch the vault when additional verification is required"),
        })
        {
            byte[] input = "only used by the fixture"u8.ToArray();
            using HttpClient client = new(handler);
            bool refused = await RefusedAsync(async () =>
            {
                using SecretValues values = await LastPassRefreshReader.ReadAsync(client, Username, true, input, [PasswordPath], cancel);
            }, error);
            check(refused && input.All(value => value == 0)
                && handler.Requests.Last() == (loginOnly ? "/login.php" : "/login_check.php"), $"LastPass refresh {name}");
        }
    }

    private static async Task SignedHandoff(Action<bool, string> check, CancellationToken cancel)
    {
        using SoftwareSigningKey authority = new();
        string pin = KeyIdentity.Fingerprint(authority.PublicKey);
        (string storePublic, string storePrivate) = JweCipher.Instance.NewKeyPair();
        string account = "Vault@example.test";
        LastPassRefreshRequest request = new(Guid.NewGuid(), Guid.NewGuid(), "Test admin", "LastPass test", account,
            false, DateTimeOffset.UtcNow.AddMinutes(2), storePublic, [new(PasswordPath, "APP_PASSWORD"), new(UsernamePath, "APP_USER")]);

        using (NamedPipeServerStream server = NewPipe(out string name))
        using (NamedPipeClientStream helper = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly))
        {
            await Task.WhenAll(server.WaitForConnectionAsync(cancel), helper.ConnectAsync(cancel));
            Task<LastPassRefreshHandoff> accepting = LastPassRefreshHandoff.AcceptAsync(helper, helper, pin, cancel);
            using LastPassRefreshHandoff sender = await LastPassRefreshHandoff.SendAsync(server, server, request, authority, cancel);
            using LastPassRefreshHandoff accepted = await accepting;
            using StringWriter prompt = new();
            LastPassRefreshTerminal.ShowRequest(prompt, accepted.Request, accepted.MatchingCode);
            string display = prompt.ToString();
            check(sender.MatchingCode == accepted.MatchingCode && sender.MatchingCode.Length == 4
                && display.Contains("Test admin") && display.Contains(account, StringComparison.Ordinal)
                && display.Contains("100 / password") && display.Contains("APP_PASSWORD"),
                "LastPass helper displays the authenticated requester, full account, exact mapping and same matching code");

            string ciphertextLikeValue = JweCipher.Instance.Encrypt("a literal value", storePublic);
            using SecretValues selected = new(new Dictionary<string, byte[]>
            {
                [PasswordPath] = Encoding.UTF8.GetBytes(SelectedValue),
                [UsernamePath] = Encoding.UTF8.GetBytes(ciphertextLikeValue),
            });
            Task<IReadOnlyDictionary<string, string>> receiving = sender.ReceiveStageAsync(server, cancel);
            await accepted.SendStageAsync(helper, selected, cancel);
            IReadOnlyDictionary<string, string> sealedValues = await receiving;
            check(sealedValues.Count == 2 && JweCipher.Instance.Decrypt(storePrivate, sealedValues[PasswordPath]) == SelectedValue
                && sealedValues[UsernamePath] != ciphertextLikeValue
                && JweCipher.Instance.Decrypt(storePrivate, sealedValues[UsernamePath]) == ciphertextLikeValue
                && await RefusedAsync(() => sender.ReceiveStageAsync(server, cancel), ProviderErrorKind.AccessDenied),
                "LastPass helper seals the exact selection to the signed store key and the handoff accepts one stage");
        }

        using (NamedPipeServerStream server = NewPipe(out string name))
        using (NamedPipeClientStream helper = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly))
        using (SoftwareSigningKey other = new())
        {
            await Task.WhenAll(server.WaitForConnectionAsync(cancel), helper.ConnectAsync(cancel));
            Task<LastPassRefreshHandoff> accepting = LastPassRefreshHandoff.AcceptAsync(helper, helper, pin, cancel);
            using LastPassRefreshHandoff sender = await LastPassRefreshHandoff.SendAsync(server, server, request, other, cancel);
            check(await RefusedAsync(async () => { using LastPassRefreshHandoff wrong = await accepting; }, ProviderErrorKind.AccessDenied),
                "LastPass helper refuses a refresh signed by an unpinned authority before showing the password prompt");
        }

        using (NamedPipeServerStream server = NewPipe(out string name))
        using (NamedPipeClientStream helper = new(".", name, PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly))
        using (MemoryStream intercepted = new())
        {
            await Task.WhenAll(server.WaitForConnectionAsync(cancel), helper.ConnectAsync(cancel));
            Task<LastPassRefreshHandoff> accepting = LastPassRefreshHandoff.AcceptAsync(helper, helper, pin, cancel);
            using LastPassRefreshHandoff sender = await LastPassRefreshHandoff.SendAsync(server, intercepted, request, authority, cancel);
            byte[] modified = intercepted.ToArray();
            check(modified.AsSpan().IndexOf(Encoding.UTF8.GetBytes(request.RequestedBy)) < 0,
                "LastPass requester details are encrypted on the private wire");
            modified[^1] ^= 1;
            await server.WriteAsync(modified, cancel);
            check(await RefusedAsync(async () => { using LastPassRefreshHandoff wrong = await accepting; }, ProviderErrorKind.AccessDenied),
                "LastPass helper refuses an altered encrypted request");
        }
    }

    private static NamedPipeServerStream NewPipe(out string name)
    {
        name = "with-secrets-lp-" + Guid.NewGuid().ToString("N");
        return new(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
    }

    private static async Task<bool> RefusedAsync(Func<Task> action, ProviderErrorKind kind)
    {
        try { await action(); return false; }
        catch (ProviderAdapterException error) { return error.Kind == kind; }
    }

    private static byte[] Vault(byte[] key, bool protectedItem)
    {
        using MemoryStream output = new();
        WriteChunk(output, "LPAV"u8, "1"u8);
        using MemoryStream skipped = new();
        WriteItem(skipped, "999"u8);
        skipped.Write(new byte[128 * 1024]); // Malformed contents of an unselected item.
        WriteChunk(output, "ACCT"u8, skipped.ToArray());

        using Aes aes = Aes.Create();
        aes.SetKey(key);
        byte[] iv = new byte[16];
        byte[] field = [(byte)'!', .. iv, .. aes.EncryptCbc(Encoding.UTF8.GetBytes(SelectedValue), iv, PaddingMode.PKCS7)];
        using MemoryStream selected = new();
        WriteItem(selected, "100"u8);
        WriteItem(selected, "unused name"u8);
        WriteItem(selected, "unused group"u8);
        WriteItem(selected, Encoding.ASCII.GetBytes(Convert.ToHexString("https://example.test"u8)));
        WriteItem(selected, "unused note"u8);
        WriteItem(selected, "0"u8);
        WriteItem(selected, []);
        WriteItem(selected, []);
        WriteItem(selected, field);
        WriteItem(selected, protectedItem ? "1"u8 : "0"u8);
        WriteChunk(output, "ACCT"u8, selected.ToArray());
        return output.ToArray();
    }

    private static void WriteChunk(Stream output, ReadOnlySpan<byte> type, ReadOnlySpan<byte> body)
    {
        output.Write(type);
        WriteItem(output, body);
    }

    private static void WriteItem(Stream output, ReadOnlySpan<byte> body)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, body.Length);
        output.Write(length);
        output.Write(body);
    }

    private sealed class FixtureHandler(byte[] vault, string proof) : HttpMessageHandler
    {
        public List<string> Requests { get; } = [];
        public bool ExpectedRequest { get; private set; } = true;
        public bool SessionClosed { get; init; } = true;
        public bool RequireMfa { get; init; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancel)
        {
            string path = request.RequestUri!.AbsolutePath;
            Requests.Add(path);
            string form = await request.Content!.ReadAsStringAsync(cancel);
            ExpectedRequest &= request.Method == HttpMethod.Post && request.RequestUri.Scheme == "https"
                && request.RequestUri.Host == "lastpass.eu" && !form.Contains("fixture")
                && (path switch
                {
                    "/iterations.php" => form == "email=vault%40example.test" && !request.Headers.Contains("Cookie"),
                    "/login.php" => form.Contains("hash=" + proof) && form.Contains("iterations=100") && !request.Headers.Contains("Cookie"),
                    _ => request.Headers.TryGetValues("Cookie", out IEnumerable<string>? cookie)
                        && cookie.Single() == "PHPSESSID=session-fixture",
                });
            return path switch
            {
                "/iterations.php" => Reply("100"),
                "/login.php" => Reply(RequireMfa ? "<response><error cause='outofbandrequired'/></response>"
                    : "<response><ok uid='100' sessionid='session-fixture' token='logout-token'/></response>"),
                "/getaccts.php" => new(HttpStatusCode.OK) { Content = new ByteArrayContent(vault) },
                "/logout.php" => new(HttpStatusCode.MovedPermanently) { Headers = { Location = new("https://example.test/") } },
                "/login_check.php" => Reply(SessionClosed ? "<response><error from='session is not live'/></response>" : "<response><ok/></response>"),
                _ => throw new InvalidOperationException("Unexpected LastPass fixture request."),
            };
        }

        private static HttpResponseMessage Reply(string text) => new(HttpStatusCode.OK) { Content = new StringContent(text) };
    }
}
