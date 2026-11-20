using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// Flows over real HTTP with PRF key slots (the Dotenvx private key never rests on the machine): the first <c>--set</c> after the first setup, a run
/// approved by the first key and by an enrolled second key, every wrong PRF payload, an enrollment of a key without PRF, and
/// a scan of everything the tool writes or says for the private key, the master key and the PRF output.
/// </summary>
internal static class PrfFlowTests
{
    public static Task Run(Action<bool, string> check) => WebApprovalTests.PrfFlows(check);
}


internal static partial class WebApprovalTests
{
    private const string PrfA = "Prf-Alpha-Secret-1";
    private const string PrfB = "Prf-Bravo-Secret-2";

    /// <summary>True when any file under <paramref name="folder" /> (the database, its WAL and its shared memory) holds <paramref name="needle" />.</summary>
    internal static bool FolderHolds(string folder, byte[] needle)
    {
        foreach (string file in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
        {
            using FileStream stream = new(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using MemoryStream copy = new();
            stream.CopyTo(copy);
            if (copy.ToArray().AsSpan().IndexOf(needle) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>The forms in which a secret byte string could show up in text: lower and upper hex, base64 and base64url.</summary>
    internal static string[] Forms(byte[] secret) =>
        [Convert.ToHexStringLower(secret), Convert.ToHexString(secret), Convert.ToBase64String(secret), Base64Url.EncodeToString(secret)];

    private static bool Shows(IEnumerable<string> texts, params byte[][] secrets)
    {
        string[] forms = [.. secrets.SelectMany(Forms)];

        return texts.Any(text => forms.Any(form => text.Contains(form, StringComparison.Ordinal)));
    }

    internal static async Task PrfFlows(Action<bool, string> check)
    {
        string folder = Path.Combine(Path.GetTempPath(), "ws-prf-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.Timeout = TimeSpan.FromSeconds(20);
            ApprovalSettings local = new(null, 0, TimeSpan.FromSeconds(20));
            using TestAuthenticator laptop = TestAuthenticator.ES256();
            using TestAuthenticator phone = TestAuthenticator.RS256();
            using TestAuthenticator noPrf = TestAuthenticator.ES256(prf: false);
            int states = 0;

            // The program the runs start: it writes its environment to env.txt (to check what it was given) and prints one secret.
            string scripts = Path.Combine(folder, "scripts");
            Directory.CreateDirectory(scripts);
            string program = OperatingSystem.IsWindows() ? "show.cmd" : "show.sh";
            string envFile = Path.Combine(scripts, "env.txt");
            string programPath = Path.Combine(scripts, program);
            if (OperatingSystem.IsWindows())
            {
                File.WriteAllText(programPath, "@echo off\r\nset > \"%~dp0env.txt\"\r\necho a=%A_NAME%\r\n");
            }
            else
            {
                File.WriteAllText(programPath, "#!/bin/sh\nenv > \"" + envFile + "\"\necho \"a=$A_NAME\"\n");
                File.SetUnixFileMode(programPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }

            RunArgs args = CliArgs.ParseRun(["--secrets", "A_NAME", "--reason", "prf test", "--", "./" + program], out _)!;

            // A state with the laptop as admin and two stored secrets (the vault is under the state's master key).
            (StateDatabase Db, PasskeyStore Passkeys, SecretStore Store, CountingCipher Cipher) NewState(params TestAuthenticator[] more)
            {
                StateDatabase db = StateDatabase.InFolder(Path.Combine(folder, "state-" + Interlocked.Increment(ref states)));
                PasskeyStore passkeys = new(db);
                passkeys.Add(laptop.Record("localhost", "laptop"));
                foreach (TestAuthenticator extra in more)
                {
                    passkeys.Add(extra.Record("localhost", "extra"));
                }

                CountingCipher cipher = new();
                SecretStore store = new(db, cipher);
                if (SecretStoreTests.Put(store, new Dictionary<string, string> { ["A_NAME"] = PrfA, ["B_NAME"] = PrfB }) is { } problem)
                {
                    throw new InvalidOperationException(problem);
                }

                return (db, passkeys, store, cipher);
            }

            // Runs the command; the approval page is answered by the callback (base URL, origin, rpId) and its reply is kept.
            async Task<(int Code, string Out, string Err, List<string> Seen, bool Ran, int Links)> RunWith(StateDatabase db, PasskeyStore passkeys, SecretStore store, Func<string, string, string, (int Status, string Body)> approve)
            {
                File.Delete(envFile);
                TaskCompletionSource<string> link = new(TaskCreationOptions.RunContinuationsAsynchronously);
                StringWriter stdout = new();
                StringWriter stderr = new();
                TextWriter errors = TextWriter.Synchronized(stderr);
                int links = 0;
                PasskeyMethod method = new(passkeys, local);
                WebApprover approver = new(method, local, line =>
                {
                    links++;
                    errors.WriteLine(line);
                    link.TrySetResult(line);
                }, TimeSpan.Zero);
                RunCommand command = new(store, approver, TextWriter.Synchronized(stdout), errors);
                Task<int> running = Task.Run(() => command.ExecuteAsync(args, scripts));
                List<string> seen = [];
                Task first = await Task.WhenAny(link.Task, running, Task.Delay(TimeSpan.FromSeconds(20)));
                if (first == link.Task)
                {
                    Uri uri = new(link.Task.Result[AnnouncePrefix.Length..]);
                    string baseUrl = "http://127.0.0.1:" + uri.Port + uri.AbsolutePath;
                    seen.Add(Text(Send(client, HttpMethod.Get, baseUrl)));
                    (int status, string body) = approve(baseUrl, uri.GetLeftPart(UriPartial.Authority), uri.IdnHost);
                    seen.Add(status + " " + body);
                }

                Task done = await Task.WhenAny(running, Task.Delay(TimeSpan.FromSeconds(30)));
                int code = done == running ? running.Result : -1;

                return (code, stdout.ToString(), stderr.ToString(), seen, File.Exists(envFile), links);
            }

            // The master key and the store key of a state, opened with a key's PRF output (the way a run does it).
            (byte[] Master, string PrivateHex) Open(StateDatabase db, TestAuthenticator who)
            {
                Manifest manifest = TestState.Current(db)!;
                using Unlock unlock = TestVault.Unlock(db, who)!;
                byte[] master = KeyVault.OpenMaster(manifest, unlock);
                byte[] privateKey = KeyVault.UnwrapVault(manifest.Vault, master, manifest.Store);
                string hex = Encoding.UTF8.GetString(privateKey);
                SecretValues.Clear(privateKey);

                return (master, hex);
            }

            // (1) The first --set after --config: the store key and vault were made by the first setup, so the set is one page and one
            // admin assertion (no approval page, no PRF). The private key (and the master key) are in no file, row, reply, message or
            // audit entry before or after.
            {
                StateDatabase db = StateDatabase.InFolder(Path.Combine(folder, "first-set"));
                PasskeyStore passkeys = new(db);
                TestState.Add(db, laptop.Record("localhost", "laptop"), withStore: true);
                SecretStore store = new(db);
                Manifest before = TestState.Current(db)!;
                check(before.Store.Length == 66 && KeyVault.IsVault(before.Vault), "prf first set: the state from the first setup already has the store key and the vault");
                (byte[] master, string privateHex) = Open(db, laptop);
                EntryRun run = SetRun(passkeys, store, ["A_NAME"], laptop, Values(("A_NAME", PrfA)));
                Manifest? after = TestState.Current(db);
                check(run.Result is { Code: 0 } && run.Entry is not null && after is { Version: 2 } && after.Store == before.Store && after.Vault == before.Vault && after.Secrets.ContainsKey("A_NAME"), "prf first set: one page, no PRF, no approval page; the manifest keeps the store key and vault and adds the hash of the first secret (" + run.Result?.Detail + ")");
                check(privateHex.Length == 64 && DotenvxCipher.Instance.Derive(privateHex) == after!.Store, "prf first set: the vault holds the private key of the stored public key, and the passkey's PRF output opens it");
                byte[] privateAscii = Encoding.ASCII.GetBytes(privateHex);
                SqliteConnection.ClearAllPools();
                check(!FolderHolds(Path.GetDirectoryName(db.FilePath)!, privateAscii) && !FolderHolds(Path.GetDirectoryName(db.FilePath)!, Encoding.UTF8.GetBytes(privateHex.ToUpperInvariant())), "prf first set: the private key (hex) is in no file of the store folder: not in state.db, its WAL or anything else");
                check(!FolderHolds(Path.GetDirectoryName(db.FilePath)!, master) && !FolderHolds(Path.GetDirectoryName(db.FilePath)!, Encoding.ASCII.GetBytes(Base64Url.EncodeToString(master))), "prf first set: the master key is in no file either");
                check(!Shows([.. run.Seen, StateDatabaseTests.AuditText(db.FilePath), run.Result?.Detail ?? ""], privateAscii, master), "prf first set: the private key and the master key are in no page, reply, message or audit entry");
                check(!Shows(run.Seen, privateAscii) && !run.Seen.Any(text => text.Contains(privateHex, StringComparison.OrdinalIgnoreCase)), "prf first set: no HTTP body has the private key");
                check(!File.Exists(Path.Combine(Path.GetDirectoryName(db.FilePath)!, ".env.keys")), "prf first set: no .env.keys file");
                SecretValues.Clear(master);
            }

            // (2) A first --set that is cancelled or fails changes nothing: the manifest stays as the first setup left it.
            {
                foreach ((string label, Func<StateDatabase, PasskeyStore, EntryRun> act) in new (string, Func<StateDatabase, PasskeyStore, EntryRun>)[]
                {
                    ("the write fails", (db, passkeys) =>
                    {
                        SecretStore store = new(db) { BeforeCommit = () => throw new IOException("the test write failed") };

                        return SetRun(passkeys, store, ["A_NAME"], laptop, Values(("A_NAME", PrfA)));
                    }),
                    ("the entry is cancelled", (db, passkeys) => SetRun(passkeys, new SecretStore(db), ["A_NAME"], laptop, Values(("A_NAME", PrfA)), Twist.Cancel)),
                })
                {
                    StateDatabase db = StateDatabase.InFolder(Path.Combine(folder, "first-fail-" + Interlocked.Increment(ref states)));
                    PasskeyStore passkeys = new(db);
                    TestState.Add(db, laptop.Record("localhost", "laptop"), withStore: true);
                    Manifest before = TestState.Current(db)!;
                    EntryRun run = act(db, passkeys);
                    check(run.Result is { Code: not 0 } && TestState.Current(db) == before && new SecretStore(db).ListNames().Count == 0, "prf first set: " + label + ": nothing is stored and the manifest is unchanged (" + run.Result?.Detail + ")");
                }
            }

            // (3) A run approved by the first key: only the requested row is decrypted, the child has only that value, the key is in no
            // environment variable, and the PRF output and the private key are in no body, message or audit entry.
            {
                (StateDatabase db, PasskeyStore passkeys, SecretStore store, CountingCipher cipher) = NewState(phone);
                (byte[] master, string privateHex) = Open(db, laptop);
                string saltOfLaptop = TestState.Current(db)!.Keys.First(key => key.Id == TestAuthenticator.Encode(laptop.CredentialId)).Slot!.Salt;
                byte[] prfOut = laptop.Prf(Base64Url.DecodeFromChars(saltOfLaptop))!;
                var result = await RunWith(db, passkeys, store, (url, origin, rp) => TestState.Approve(client, url, origin, rp, laptop));
                string env = File.Exists(envFile) ? File.ReadAllText(envFile) : "";
                check(result.Code == 0 && result.Out.Contains("a=[REDACTED]", StringComparison.Ordinal) && !result.Out.Contains(PrfA, StringComparison.Ordinal), "prf run: approved by the first key, the child ran and its output is redacted (" + result.Code + " " + result.Err + ")");
                check(cipher.Decrypts == 1, "prf run: only the requested row was decrypted (" + cipher.Decrypts + " decrypts)");
                check(env.Contains("A_NAME=" + PrfA, StringComparison.Ordinal) && !env.Contains(PrfB, StringComparison.Ordinal) && !env.Contains("DOTENV_PRIVATE_KEY", StringComparison.OrdinalIgnoreCase) && !env.Contains(privateHex, StringComparison.OrdinalIgnoreCase), "prf run: the child has the requested value and no other secret, no DOTENV_PRIVATE_KEY and not the private key");
                string audit = StateDatabaseTests.AuditText(db.FilePath);
                check(!Shows([.. result.Seen, result.Out, result.Err, audit], prfOut, master) && !new List<string>([.. result.Seen, result.Out, result.Err, audit]).Any(text => text.Contains(privateHex, StringComparison.OrdinalIgnoreCase)), "prf run: the PRF output, the master key and the private key are in no page, reply, stdout, stderr or audit entry");
                check(!new List<string>([.. result.Seen, result.Out, result.Err, audit]).Any(text => text.Contains(PrfA, StringComparison.Ordinal) || text.Contains(PrfB, StringComparison.Ordinal)), "prf run: no value is in any page, reply, stdout, stderr or audit entry");
                check(result.Links == 1, "prf run: one approval link, one prompt");

                // The enrolled second key opens the same master key and runs too.
                (byte[] master2, string privateHex2) = Open(db, phone);
                check(master.AsSpan().SequenceEqual(master2) && privateHex == privateHex2, "prf run: the second key's slot opens the same master key and the same private key");
                result = await RunWith(db, passkeys, store, (url, origin, rp) => TestState.Approve(client, url, origin, rp, phone));
                check(result.Code == 0 && result.Out.Contains("a=[REDACTED]", StringComparison.Ordinal) && cipher.Decrypts == 2, "prf run: approved by the second key, it decrypts too (" + result.Code + " " + result.Err + ")");
                SecretValues.Clear(master);
                SecretValues.Clear(master2);
            }

            // (3b) The sign-in names no credential, so the authenticator picks one of the passkeys: a credential that is not in the manifest is
            // denied; and with two keys enrolled, whichever one is chosen opens its own slot (the same master key).
            {
                (StateDatabase db, PasskeyStore passkeys, SecretStore store, CountingCipher cipher) = NewState(phone);
                using TestAuthenticator stranger = TestAuthenticator.ES256();
                var denied = await RunWith(db, passkeys, store, (url, origin, rp) => TestState.Approve(client, url, origin, rp, stranger));
                check(denied.Code == RunCommand.Denied && !denied.Ran && cipher.Decrypts == 0 && !denied.Out.Contains(PrfA, StringComparison.Ordinal), "prf run: an assertion from a credential that is not in the manifest is denied (" + denied.Code + " " + denied.Err + ")");
                foreach ((TestAuthenticator chosen, string label) in new[] { (phone, "phone"), (laptop, "laptop") })
                {
                    int before = cipher.Decrypts;
                    var result = await RunWith(db, passkeys, store, (url, origin, rp) => TestState.Approve(client, url, origin, rp, chosen));
                    check(result.Code == 0 && result.Ran && cipher.Decrypts == before + 1, "prf run: the passkey chosen from several (" + label + ") opens its own slot and the run decrypts (" + result.Code + " " + result.Err + ")");
                }
            }

            // (4) A wrong PRF payload denies (exit 3), decrypts nothing and never starts the child; there is no fallback.
            foreach ((PrfMode mode, string label) in new[]
            {
                (PrfMode.Missing, "no PRF payload"), (PrfMode.Garbled, "a garbled PRF payload"), (PrfMode.WrongBind, "a PRF payload sealed for another page"),
                (PrfMode.OtherCredential, "the PRF output of another credential"), (PrfMode.ShortOutput, "a PRF output of the wrong size"),
            })
            {
                (StateDatabase db, PasskeyStore passkeys, SecretStore store, CountingCipher cipher) = NewState(phone);
                int before = cipher.Decrypts;
                var result = await RunWith(db, passkeys, store, (url, origin, rp) => TestState.Approve(client, url, origin, rp, laptop, mode, phone));
                string audit = StateDatabaseTests.AuditText(db.FilePath);
                check(result.Code is RunCommand.Denied or RunCommand.StoreError && (mode == PrfMode.OtherCredential || result.Code == RunCommand.Denied) && !result.Ran && cipher.Decrypts == before, "prf run: " + label + " is refused (exit 3; exit 4 when only the slot cannot open), the child never ran and nothing was decrypted (" + result.Code + " " + result.Err + ")");
                check(!result.Out.Contains(PrfA, StringComparison.Ordinal) && !result.Err.Contains(PrfA, StringComparison.Ordinal) && !audit.Contains(PrfA, StringComparison.Ordinal), "prf run: " + label + ": no value in the output, the messages or the audit");
            }

            // (4a) Key A signs, the page sends key B's valid PRF output for B's own salt: the slot is chosen by the signing key, so
            // nothing opens. (A store that tried every slot would accept this.)
            {
                (StateDatabase db, PasskeyStore passkeys, SecretStore store, CountingCipher cipher) = NewState(phone);
                var result = await RunWith(db, passkeys, store, (url, origin, rp) => TestState.Approve(client, url, origin, rp, laptop, PrfMode.OtherOwnSalt, phone));
                check(result.Code is RunCommand.Denied or RunCommand.StoreError && !result.Ran && cipher.Decrypts == 0 && !result.Out.Contains(PrfA, StringComparison.Ordinal), "prf run: key A's assertion with key B's valid PRF output for B's own salt opens nothing (" + result.Code + " " + result.Err + ")");
            }

            // (4b) The state a PRF payload was made against: a payload for a salt the key does not have in its slot decrypts nothing.
            {
                (StateDatabase db, PasskeyStore passkeys, SecretStore store, CountingCipher cipher) = NewState();
                int before = cipher.Decrypts;
                var result = await RunWith(db, passkeys, store, (url, origin, rp) =>
                {
                    // The same page, but the key answers with the PRF output for a salt of its own choosing.
                    (_, string page) = TestState.Get(client, url);
                    using JsonDocument start = JsonDocument.Parse(Between(page, "<script type=\"application/json\" id=\"start\">", "</script>"));
                    byte[] bind = Base64Url.DecodeFromChars(start.RootElement.GetProperty("bind").GetString()!);
                    (string epk, string iv, string ct) = PrfBrowser.Seal(start.RootElement.GetProperty("prfKey").GetString()!, bind, laptop.Prf(RandomNumberGenerator.GetBytes(32))!);
                    string assertion = laptop.Assert(ReuseBinding.Challenge(bind, 0), origin, rp, TestState.NextCount());

                    return TestState.Post(client, url + "/proof", "{\"reuse\":0,\"proof\":" + assertion + ",\"prf\":{\"epk\":\"" + epk + "\",\"iv\":\"" + iv + "\",\"ct\":\"" + ct + "\"}}");
                });
                check(result.Code is RunCommand.Denied or RunCommand.StoreError && !result.Ran && cipher.Decrypts == before, "prf run: the PRF output for another salt opens nothing (" + result.Code + " " + result.Err + ")");
            }

            // (5) Enrolling a key: one without PRF is refused before anything is stored (nothing changes); one with PRF gets a slot that
            // opens the same master key, and then runs.
            {
                (StateDatabase db, PasskeyStore passkeys, SecretStore store, CountingCipher cipher) = NewState();
                long version = TestState.Current(db)!.Version;
                (ApprovalDecision? decision, List<string> lines) = await PasskeyTargetRun(client, passkeys, local, local, false, item => item.Enroll(), laptop, noPrf, newName: "nokey");
                check(decision is { Approved: false } && decision.Detail.Contains(PrfClient.CannotPrf, StringComparison.Ordinal) && passkeys.All().Count == 1 && TestState.Current(db)!.Version == version, "prf enroll: a passkey without PRF is refused with the PRF message and nothing is stored (" + decision?.Detail + ")");

                (decision, lines) = await PasskeyTargetRun(client, passkeys, local, local, false, item => item.Enroll(), laptop, phone, newName: "phone");
                check(decision is { Approved: true } && passkeys.All().Count == 2 && TestState.Current(db)!.Version == version + 1, "prf enroll: a passkey with PRF is enrolled (" + decision?.Detail + "; " + string.Join(" | ", lines) + ")");
                (byte[] masterLaptop, _) = Open(db, laptop);
                (byte[] masterPhone, string hexPhone) = Open(db, phone);
                check(masterLaptop.AsSpan().SequenceEqual(masterPhone) && DotenvxCipher.Instance.Derive(hexPhone) == TestState.Current(db)!.Store, "prf enroll: the new key's slot opens the same master key and the vault");
                check(TestState.Current(db)!.Keys.Select(key => key.Slot!.Salt).Distinct().Count() == 1, "prf enroll: every key's slot has the same salt (the store's)");
                var result = await RunWith(db, passkeys, store, (url, origin, rp) => TestState.Approve(client, url, origin, rp, phone));
                check(result.Code == 0 && cipher.Decrypts == 1, "prf enroll: the new key approves a run and it decrypts (" + result.Code + " " + result.Err + ")");
                var firstResult = await RunWith(db, passkeys, store, (url, origin, rp) => TestState.Approve(client, url, origin, rp, laptop));
                check(firstResult.Code == 0 && cipher.Decrypts == 2, "prf enroll: both keys open the vault through the one eval salt (" + firstResult.Code + " " + firstResult.Err + ")");
                string everything = string.Join("\n", lines) + (decision?.Detail ?? "") + StateDatabaseTests.AuditText(db.FilePath);
                check(!Shows([everything], masterLaptop, laptop.Prf(Base64Url.DecodeFromChars(TestState.Current(db)!.Keys[0].Slot!.Salt))!, phone.Prf(Base64Url.DecodeFromChars(TestState.Current(db)!.Keys[1].Slot!.Salt))!), "prf enroll: the master key and the PRF outputs are in no message or audit entry");
                SecretValues.Clear(masterLaptop);
                SecretValues.Clear(masterPhone);

                // Enrolling when the approving admin releases nothing: no slot can be made, so nothing is added.
                (decision, _) = await PasskeyTargetRun(client, passkeys, local, local, false, item => item.Enroll(), laptop, phone, newName: "again", approval: PrfMode.Missing);
                check(decision is { Approved: false } && passkeys.All().Count == 2, "prf enroll: an approval that does not release the key adds nothing (" + decision?.Detail + ")");
            }

            // (6) The vault and the slots are signed: an edit is a failed verification (exit 4), nobody is asked and nothing is decrypted.
            static string Flip(string text) => text[..^2] + (text[^2] == 'A' ? "B" : "A") + text[^1];
            foreach ((string label, Func<Manifest, string> field) in new (string, Func<Manifest, string>)[]
            {
                ("a vault byte flipped", manifest => manifest.Vault),
                ("a slot wrap byte flipped", manifest => manifest.Keys[0].Slot!.Wrap),
                ("a slot salt byte flipped", manifest => manifest.Keys[0].Slot!.Salt),
            })
            {
                (StateDatabase db, PasskeyStore passkeys, SecretStore store, CountingCipher cipher) = NewState();
                string original = field(TestState.Current(db)!);
                ManifestTests.Execute(db.FilePath, "UPDATE manifest SET text = replace(text, '" + original + "', '" + Flip(original) + "')");
                FakeApprover asked = new(true, unlock: () => TestVault.Unlock(db, laptop));
                StringWriter errors = new();
                int code = await new RunCommand(new SecretStore(new StateDatabase(db.FilePath), cipher), asked, new StringWriter(), errors).ExecuteAsync(args, scripts);
                check(!new StateDatabase(db.FilePath).TryCheck(out _) && code == RunCommand.StoreError && asked.Requests.Count == 0 && cipher.Decrypts == 0, "prf tamper: " + label + " fails verification: exit 4, nobody is asked, nothing is decrypted (" + code + " " + errors + ")");
            }
            // (7) A run asks for the key release and offers nothing else.
            {
                (StateDatabase db, _, SecretStore store, _) = NewState();
                FakeApprover asked = new(false);
                await new RunCommand(store, asked, new StringWriter(), new StringWriter()).ExecuteAsync(args, scripts);
                check(asked.Requests.Count == 1 && asked.Requests[0].Reuse is null && asked.Requests[0].Unlock, "prf run: the request asks for the key release and offers no reuse");
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(folder, true);
        }
    }
}
