using System.Buffers.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace WithSecrets.Tests;

/// <summary>
/// The signed manifest: keys (with the one admin) and settings in one canonical JSON text, signed by the admin key. Every
/// read verifies it; any edit made to state.db outside the tool fails verification, and then nothing can be used.
/// </summary>
internal static class ManifestTests
{
    public static async Task Run(Action<bool, string> check)
    {
        string root = Path.Combine(Path.GetTempPath(), "ws-manifest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            Canonical(check);
            Parsing(check);
            Stored(check, root);
            Tampers(check, root);
            await NoRun(check, root);
            Stale(check, root);
            SignCounts(check, root);
            Parallel(check, root);
            await Revoke(check, root);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(root, true);
        }
    }

    private static readonly DateTimeOffset Created = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);

    private static PasskeyRecord Record(TestAuthenticator key, string name, string rp = "localhost") => key.Record(rp, name) with { Created = Created };

    private static void Canonical(Action<bool, string> check)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.RS256();
        Manifest first = Manifest.First(Record(laptop, "laptop"), ToolSettings.Defaults);
        string id = TestAuthenticator.Encode(laptop.CredentialId);
        string expected = "{\"v\":1,\"keys\":[{\"id\":\"" + id + "\",\"name\":\"laptop\",\"pub\":\"" + TestAuthenticator.Encode(laptop.CoseKey())
            + "\",\"alg\":-7,\"rp\":\"localhost\",\"created\":\"2026-11-01T10:00:00.0000000+00:00\",\"admin\":true}],\"settings\":" + ToolSettings.Defaults.Canonical() + "}";
        check(first.Canonical() == expected, "manifest: the canonical text has a fixed key order (" + first.Canonical() + ")");
        check(first.Version == 1 && first.Admin?.Id == id && first.Keys.Count == 1, "manifest: the first manifest is version 1 with the first key as admin");

        Manifest second = first.WithKey(Record(phone, "phone", "ws.example.com"));
        check(second.Version == 2 && second.Keys.Count == 2 && second.Keys.Count(key => key.Admin) == 1 && second.Admin?.Id == id, "manifest: adding a key is version + 1 and the new key is not admin");
        check(second.Keys.Select(key => key.Id).SequenceEqual(second.Keys.Select(key => key.Id).Order(StringComparer.Ordinal)), "manifest: keys are sorted by id");
        Manifest parsed = Manifest.Parse(second.Canonical(), out string? error)!;
        check(parsed is not null && error is null && parsed.Canonical() == second.Canonical() && parsed.Keys.SequenceEqual(second.Keys) && parsed.Settings == second.Settings, "manifest: round trip (" + error + ")");
        Manifest settings = second.WithSettings(ToolSettings.Defaults with { Port = 8765 });
        check(settings.Version == 3 && settings.Settings.Port == 8765 && settings.Keys.SequenceEqual(second.Keys), "manifest: a settings change is version + 1 with the same keys");
        Manifest removed = settings.WithoutKey(TestAuthenticator.Encode(phone.CredentialId));
        check(removed.Version == 4 && removed.Keys.Count == 1 && removed.Admin?.Id == id, "manifest: removing a key is version + 1");
        check(settings.SettingsPrefix() + settings.Settings.Canonical() + "}" == settings.Canonical(), "manifest: the text is the prefix, the settings and a closing brace");

        byte[] bind = [1, 2, 3];
        byte[] inner = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(expected));
        check(Manifest.Challenge(bind, expected).SequenceEqual(System.Security.Cryptography.SHA256.HashData([.. bind, .. inner])), "manifest: the challenge is SHA-256(bind || SHA-256(text))");
    }

    private static void Parsing(Action<bool, string> check)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        Manifest good = Manifest.First(Record(laptop, "laptop"), ToolSettings.Defaults).WithKey(Record(phone, "phone"));
        string text = good.Canonical();
        string phoneId = TestAuthenticator.Encode(phone.CredentialId);
        (string Name, string Text)[] bad =
        [
            ("white space", text.Replace(",\"keys\"", ", \"keys\"", StringComparison.Ordinal)),
            ("zero admins", text.Replace("\"admin\":true", "\"admin\":false", StringComparison.Ordinal)),
            ("two admins", text.Replace("\"admin\":false", "\"admin\":true", StringComparison.Ordinal)),
            ("version 0", text.Replace("{\"v\":2,", "{\"v\":0,", StringComparison.Ordinal)),
            ("a settings value out of range", text.Replace("\"timeoutMinutes\":5", "\"timeoutMinutes\":99", StringComparison.Ordinal)),
            ("an unknown algorithm", text.Replace("\"alg\":-7", "\"alg\":-8", StringComparison.Ordinal)),
            ("an extra member", text.Replace("{\"v\":2,", "{\"v\":2,\"x\":1,", StringComparison.Ordinal)),
            ("keys out of order", "{\"v\":2,\"keys\":[" + string.Join(",", Keys(text).Reverse()) + "]" + text[text.IndexOf(",\"settings\"", StringComparison.Ordinal)..]),
            ("a duplicate id", text.Replace(phoneId, TestAuthenticator.Encode(laptop.CredentialId), StringComparison.Ordinal)),
            ("a duplicate name", text.Replace("\"name\":\"phone\"", "\"name\":\"LAPTOP\"", StringComparison.Ordinal)),
            ("not JSON", "not json"),
        ];
        foreach ((string name, string value) in bad)
        {
            check(Manifest.Parse(value, out string? error) is null && error is not null, "manifest parse: " + name + " is refused (" + error + ")");
        }
    }

    /// <summary>The key objects of a manifest text, in order, as raw JSON.</summary>
    private static string[] Keys(string text)
    {
        using JsonDocument document = JsonDocument.Parse(text);

        return [.. document.RootElement.GetProperty("keys").EnumerateArray().Select(item => item.GetRawText())];
    }

    private static void Stored(Action<bool, string> check, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "stored"));
        check(db.TryManifest(out Manifest? none, out string? error) && none is null && error is null && !File.Exists(db.FilePath), "manifest store: a missing database has no manifest and creates nothing");
        check(TestState.Add(db, Record(laptop, "laptop"), ToolSettings.Defaults with { Port = 8765 }), "manifest store: the first key and the settings are stored, signed by that key");
        check(TestState.Add(db, Record(phone, "phone")), "manifest store: a second key, signed by the admin");
        StateDatabase again = new(db.FilePath);
        check(again.TryCheck(out error) && error is null, "manifest store: the state verifies (" + error + ")");
        IReadOnlyList<PasskeyRecord> keys = new PasskeyStore(again).All();
        check(keys.Count == 2 && keys.Single(key => key.Admin).Name == "laptop" && !keys.Single(key => key.Name == "phone").Admin, "manifest store: keys come from the manifest, the first is the admin");
        check(ToolSettings.Load(again, out error).Port == 8765 && error is null, "manifest store: settings come from the manifest");
        check(TestState.Current(again)!.Version == 2, "manifest store: the version is 2 after two changes");
        check(Tables(db.FilePath).SequenceEqual(["audit", "grants", "manifest", "schema_version", "sign_counts"]), "manifest store: no passkeys or settings table (" + string.Join(",", Tables(db.FilePath)) + ")");
        check(StateDatabase.SchemaVersion == 5, "manifest store: the schema version is 5");
        check(new GrantStore(again).Add("K", 10, "laptop") && new GrantStore(again).TryGet("K", out _, out _), "manifest store: grants work with a valid manifest");
        check(StateDatabase.InFolder(Path.Combine(root, "stored-empty")) is { } empty && !new GrantStore(empty).Add("K", 10) && !File.Exists(empty.FilePath), "manifest store: no grant is saved without a manifest");
    }

    private static string[] Tables(string path)
    {
        using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name";
        using SqliteDataReader reader = command.ExecuteReader();
        List<string> names = [];
        while (reader.Read())
        {
            names.Add(reader.GetString(0));
        }

        return [.. names];
    }

    internal static void Execute(string path, string sql, params (string Name, object Value)[] parameters)
    {
        using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;
        foreach ((string name, object value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }

        command.ExecuteNonQuery();
    }

    private static string Scalar(string path, string sql)
    {
        using SqliteConnection connection = new(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = sql;

        return command.ExecuteScalar()?.ToString() ?? "";
    }

    /// <summary>A state with an admin key (laptop), a second key (phone), a grant and a sign count. Returns the database.</summary>
    private static StateDatabase Seeded(string root, TestAuthenticator laptop, TestAuthenticator phone)
    {
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "seed-" + Guid.NewGuid().ToString("N")));
        TestState.Add(db, Record(laptop, "laptop"));
        TestState.Add(db, Record(phone, "phone"));
        new GrantStore(db).Add("K", 60, "laptop");
        new PasskeyStore(db).UpdateSignCount(TestAuthenticator.Encode(laptop.CredentialId), 5);

        return db;
    }

    private static void Tampers(Action<bool, string> check, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        using TestAuthenticator stranger = TestAuthenticator.ES256();
        string laptopId = TestAuthenticator.Encode(laptop.CredentialId);

        (string Name, Action<StateDatabase> Tamper)[] tampers =
        [
            ("edited manifest text", db => Execute(db.FilePath, "UPDATE manifest SET text = replace(text, '\"name\":\"phone\"', '\"name\":\"phone2\"')")),
            ("edited settings", db => Execute(db.FilePath, "UPDATE manifest SET text = replace(text, '\"port\":0', '\"port\":1')")),
            ("edited signature", db =>
            {
                string signature = Scalar(db.FilePath, "SELECT signature FROM manifest");
                byte[] bytes = Base64Url.DecodeFromChars(signature);
                bytes[^1] ^= 1;
                Execute(db.FilePath, "UPDATE manifest SET signature = $s", ("$s", Base64Url.EncodeToString(bytes)));
            }),
            ("a key flipped to admin", db => Execute(db.FilePath, "UPDATE manifest SET text = replace(replace(replace(text, '\"admin\":true', '\"admin\":X'), '\"admin\":false', '\"admin\":true'), '\"admin\":X', '\"admin\":false')")),
            ("a valid manifest signed by a different key swapped in", db =>
            {
                // The admin's manifest text with a signature made by another key over the same text.
                string text = Scalar(db.FilePath, "SELECT text FROM manifest");
                SignedManifest forged = TestState.Sign(stranger, text);
                ReplaceRow(db.FilePath, forged);
            }),
            ("a manifest with zero admins, signed", db =>
            {
                string text = Scalar(db.FilePath, "SELECT text FROM manifest").Replace("\"admin\":true", "\"admin\":false", StringComparison.Ordinal);
                ReplaceRow(db.FilePath, TestState.Sign(laptop, text));
            }),
            ("a manifest with two admins, signed", db =>
            {
                string text = Scalar(db.FilePath, "SELECT text FROM manifest").Replace("\"admin\":false", "\"admin\":true", StringComparison.Ordinal);
                ReplaceRow(db.FilePath, TestState.Sign(laptop, text));
            }),
            ("a passkey table inserted directly", db => Execute(db.FilePath, "CREATE TABLE passkeys (id TEXT); INSERT INTO passkeys VALUES ('planted')")),
            ("a sign count row for a key that is not in the manifest", db => Execute(db.FilePath, "INSERT INTO sign_counts (id, count) VALUES ('planted', 1)")),
            ("the manifest row deleted while grants exist", db => Execute(db.FilePath, "DELETE FROM manifest; DELETE FROM sign_counts")),
            ("the manifest row deleted while sign counts exist", db => Execute(db.FilePath, "DELETE FROM manifest; DELETE FROM grants")),
            ("a second manifest row", db => Execute(db.FilePath, "INSERT INTO manifest SELECT 2, version, text, bind, credential_id, authenticator_data, client_data, signature FROM manifest")),
            ("an edited bind", db => Execute(db.FilePath, "UPDATE manifest SET bind = 'AAAA'")),
            ("only the version column changed", db => Execute(db.FilePath, "UPDATE manifest SET version = version + 1")),
            ("an assertion the admin signed without user verification", db => ReplaceRow(db.FilePath, SignWith(laptop, Scalar(db.FilePath, "SELECT text FROM manifest"), userVerified: false))),
            ("an assertion the admin signed without user presence", db => ReplaceRow(db.FilePath, SignWith(laptop, Scalar(db.FilePath, "SELECT text FROM manifest"), userPresent: false))),
            ("an assertion the admin signed with clientData type webauthn.create", db => ReplaceRow(db.FilePath, SignWith(laptop, Scalar(db.FilePath, "SELECT text FROM manifest"), type: "webauthn.create"))),
            ("a view named grants in place of the table", db => Execute(db.FilePath, "DROP TABLE grants; CREATE VIEW grants AS SELECT 'K' AS key, 0 AS approved, 0 AS expires, 0 AS minutes, '' AS key_name")),
            ("a trigger added", db => Execute(db.FilePath, "CREATE TRIGGER sneaky AFTER INSERT ON audit BEGIN SELECT 1; END")),
            ("an index added", db => Execute(db.FilePath, "CREATE INDEX extra ON grants (expires)")),
            ("a table missing", db => Execute(db.FilePath, "DROP TABLE sign_counts")),
        ];

        foreach ((string name, Action<StateDatabase> tamper) in tampers)
        {
            StateDatabase seeded = Seeded(root, laptop, phone);
            check(seeded.TryCheck(out _), "manifest tamper: " + name + ": the state verifies before the edit");
            tamper(seeded);
            StateDatabase db = new(seeded.FilePath);
            check(!db.TryCheck(out string? error) && error is not null && error.Contains("state failed verification: delete state.db to start over (only if you did not edit it)", StringComparison.Ordinal), "manifest tamper: " + name + ": verification fails (" + error + ")");
            StringWriter stderr = new();
            check(db.Gate(stderr) == RunCommand.StoreError && stderr.ToString().Contains("state failed verification", StringComparison.Ordinal) && !stderr.ToString().Contains("not enrolled", StringComparison.OrdinalIgnoreCase), "manifest tamper: " + name + ": every command exits 4 with the verification message");
            check(new PasskeyStore(db).All().Count == 0 && !new PasskeyStore(db).TryAll(out _), "manifest tamper: " + name + ": no key can approve, and keys are an error, not empty");
            check(!new GrantStore(db).TryGet("K", out _, out _), "manifest tamper: " + name + ": the saved approval is not used");
            ToolSettings.Load(db, out string? settingsError);
            check(settingsError is not null, "manifest tamper: " + name + ": the settings are an error");
            check(!new PasskeyStore(db).UpdateSignCount(laptopId, 99), "manifest tamper: " + name + ": nothing is written");
        }

        // An empty state: no manifest and no rows. That is the first run, not a failure.
        {
            StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "empty-" + Guid.NewGuid().ToString("N")));
            new AuditLog(db).TryWrite("denied", new ApprovalRequest("p", "/p", [], "/", "r", ["A"]), "test");
            bool ok = db.TryCheck(out string? error);
            check(File.Exists(db.FilePath) && ok && error is null && db.Gate(new StringWriter()) is null, "manifest: a database with only audit rows is an empty state (" + error + ")");
        }
    }

    /// <summary>A real assertion by <paramref name="signer" /> over the manifest challenge, with flags or type of the caller's choice.</summary>
    private static SignedManifest SignWith(TestAuthenticator signer, string text, bool userVerified = true, bool userPresent = true, string type = "webauthn.get")
    {
        byte[] bind = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

        return new SignedManifest(text, bind, signer.Assert(Manifest.Challenge(bind, text), TestState.Origin, "localhost", 0, userVerified, type, userPresent));
    }

    /// <summary>Replaces the one manifest row with <paramref name="signed" />, as an agent with SQLite could.</summary>
    private static void ReplaceRow(string path, SignedManifest signed)
    {
        using JsonDocument proof = JsonDocument.Parse(signed.Proof);
        JsonElement root = proof.RootElement;
        Execute(path, "UPDATE manifest SET text = $text, bind = $bind, credential_id = $id, authenticator_data = $ad, client_data = $cd, signature = $sig",
            ("$text", signed.Text), ("$bind", Base64Url.EncodeToString(signed.Bind)), ("$id", root.GetProperty("id").GetString()!),
            ("$ad", root.GetProperty("authenticatorData").GetString()!), ("$cd", root.GetProperty("clientDataJSON").GetString()!), ("$sig", root.GetProperty("signature").GetString()!));
    }

    /// <summary>A tampered state runs nothing: no saved approval is reused and no key can approve.</summary>
    private static async Task NoRun(Action<bool, string> check, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        string folder = Path.Combine(root, "norun");
        Directory.CreateDirectory(folder);
        string program = OperatingSystem.IsWindows() ? "show.cmd" : "show.sh";
        string path = Path.Combine(folder, program);
        if (OperatingSystem.IsWindows())
        {
            File.WriteAllText(path, "@echo off\r\necho ran %MY_SECRET%\r\n");
        }
        else
        {
            File.WriteAllText(path, "#!/bin/sh\necho ran \"$MY_SECRET\"\n");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        StateDatabase db = Seeded(root, laptop, phone);
        RunArgs args = CliArgs.ParseRun(["--secrets", "MY_SECRET", "--reason", "tamper", "--", "./" + program], out _)!;
        ApprovalRequest request = new(program, path, [], folder, "tamper", ["MY_SECRET"]);
        string key = RequestFingerprint.Compute(request).Key;
        check(new GrantStore(db).Add(key, 60, "laptop"), "manifest no run: a grant for the run");

        async Task<(int Code, string Out)> Run()
        {
            StringWriter stdout = new();
            FakeApprover never = new(false);
            int code = await new RunCommand(new MemoryStore(new Dictionary<string, string> { ["MY_SECRET"] = "s3cret-value" }), never, new AuditLog(db), stdout, new StringWriter(), new GrantStore(db), new ReuseOffer(480, 10))
                .ExecuteAsync(args, folder);

            return (code, stdout.ToString());
        }

        (int code, string output) = await Run();
        check(code == 0 && output.Contains("ran", StringComparison.Ordinal), "manifest no run: with a valid state the grant runs the program (" + code + ")");
        Execute(db.FilePath, "UPDATE manifest SET text = replace(text, '\"port\":0', '\"port\":1')");
        (code, output) = await Run();
        check(code == RunCommand.Denied && !output.Contains("ran", StringComparison.Ordinal), "manifest no run: after an edit the grant is not used and nothing runs (" + code + ")");
    }

    private static void Stale(Action<bool, string> check, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        using TestAuthenticator tablet = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "stale"));
        TestState.Add(db, Record(laptop, "laptop"));
        Manifest v1 = TestState.Current(db)!;
        check(TestState.Write(db, v1.WithKey(Record(phone, "phone"))), "manifest stale: version 2 is written");
        Manifest stale = v1.WithKey(Record(tablet, "tablet"));
        SignedManifest signed = TestState.Sign(laptop, stale.Canonical());
        string? problem = db.Write((connection, transaction) => db.TryReplace(connection, transaction, 1, signed));
        check(problem is not null && TestState.Current(db)!.Keys.Select(key => key.Name).Order().SequenceEqual(["laptop", "phone"]), "manifest stale: a write based on version 1 is refused after version 2 (" + problem + ")");
        Manifest skip = TestState.Current(db)!.WithSettings(ToolSettings.Defaults with { Port = 1 }) with { Version = 9 };
        problem = db.Write((connection, transaction) => db.TryReplace(connection, transaction, 2, TestState.Sign(laptop, skip.Canonical())));
        check(problem is not null && TestState.Current(db)!.Version == 2, "manifest stale: a new version that is not the next one is refused");
        // A new manifest that swaps in another admin key, signed by that key: refused, whatever it signs.
        Manifest current = TestState.Current(db)!;
        PasskeyRecord tabletRecord = Record(tablet, "tablet") with { Admin = true };
        Manifest swapped = current with
        {
            Version = current.Version + 1,
            Keys = [.. current.Keys.Select(key => key with { Admin = false }).Append(ManifestKey.From(tabletRecord, true)).OrderBy(key => key.Id, StringComparer.Ordinal)],
        };
        problem = db.Write((connection, transaction) => db.TryReplace(connection, transaction, current.Version, TestState.Sign(tablet, swapped.Canonical())));
        check(swapped.Problem() is null && problem is not null && TestState.Current(db)!.Admin?.Id == TestAuthenticator.Encode(laptop.CredentialId), "manifest stale: a new manifest with another admin key, signed by it, is refused (" + problem + ")");
        Manifest otherPub = current with
        {
            Version = current.Version + 1,
            Keys = [.. current.Keys.Select(key => key.Admin ? key with { PublicKey = TestAuthenticator.Encode(tablet.CoseKey()) } : key)],
        };
        problem = db.Write((connection, transaction) => db.TryReplace(connection, transaction, current.Version, TestState.Sign(tablet, otherPub.Canonical())));
        check(problem is not null && TestState.Current(db)!.Version == current.Version, "manifest stale: the admin id with another public key is refused");

        Manifest unsigned = TestState.Current(db)!.WithSettings(ToolSettings.Defaults with { Port = 2 });
        problem = db.Write((connection, transaction) => db.TryReplace(connection, transaction, 2, TestState.Sign(phone, unsigned.Canonical())));
        check(problem is not null && TestState.Current(db)!.Version == 2, "manifest stale: a new manifest not signed by its admin is refused");
    }

    private static void SignCounts(Action<bool, string> check, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "counts"));
        TestState.Add(db, Record(laptop, "laptop"));
        string id = TestAuthenticator.Encode(laptop.CredentialId);
        PasskeyStore store = new(db);
        check(store.All().Single().SignCount == 0, "manifest sign count: starts at 0");
        check(store.UpdateSignCount(id, 4000000000u) && store.All().Single().SignCount == 4000000000u, "manifest sign count: a higher count is saved");
        check(!store.UpdateSignCount(id, 9) && !store.UpdateSignCount(id, 4000000000u) && store.All().Single().SignCount == 4000000000u, "manifest sign count: a lower or equal count changes nothing");
        check(!store.UpdateSignCount("nope", 1) && db.TryCheck(out _), "manifest sign count: an unknown key is not counted");
        check(TestState.Settings(db, ToolSettings.Defaults with { Port = 5 }) && store.All().Single().SignCount == 4000000000u, "manifest sign count: kept outside the manifest, so a manifest change keeps it");
    }

    /// <summary>Runs --revoke with the approval page answered by <paramref name="signer" /> (null: nothing is answered).</summary>
    private static async Task<((int Code, string Detail)? Result, int Status, int Announced)> RevokeRun(StateDatabase db, TestAuthenticator? signer)
    {
        using HttpClient client = new(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(20) };
        TaskCompletionSource<string> line = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int announced = 0;
        ApprovalSettings settings = new("passkey", null, 0, TimeSpan.FromSeconds(signer is null ? 1 : 20));
        PasskeyMethod method = new(new PasskeyStore(db), settings);
        EnrollmentTarget target = EnrollmentTarget.For(method, new WebApprover(method, settings, text =>
        {
            Interlocked.Increment(ref announced);
            line.TrySetResult(text);
        }, TimeSpan.Zero));
        Task<(int, string)> task = Task.Run(() => Revocation.Run(db, target, target, new GrantStore(db)));
        int status = 0;
        if (await Task.WhenAny(line.Task, task, Task.Delay(TimeSpan.FromSeconds(20))) == line.Task && signer is not null)
        {
            Uri link = new(line.Task.Result[line.Task.Result.IndexOf("http", StringComparison.Ordinal)..]);
            (status, _) = TestState.Approve(client, "http://127.0.0.1:" + link.Port + link.AbsolutePath, "http://localhost:" + link.Port, "localhost", signer);
        }

        Task done = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(20)));

        return (done == task ? task.Result : null, status, Volatile.Read(ref announced));
    }

    /// <summary>--revoke needs the admin key; it ends every saved approval and leaves the manifest alone.</summary>
    private static async Task Revoke(Action<bool, string> check, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        using TestAuthenticator phone = TestAuthenticator.ES256();
        StateDatabase db = Seeded(root, laptop, phone);
        long version = TestState.Current(db)!.Version;

        ((int Code, string Detail)? result, int status, int announced) = await RevokeRun(db, phone);
        check(result is { Code: RunCommand.Denied } && status == 403 && announced == 1 && new GrantStore(db).TryGet("K", out _, out _), "manifest revoke: a key that is not the admin cannot revoke; the approval stays (" + result?.Detail + ")");
        (result, _, _) = await RevokeRun(db, null);
        check(result is { Code: RunCommand.Denied } && new GrantStore(db).TryGet("K", out _, out _), "manifest revoke: no answer revokes nothing (" + result?.Detail + ")");
        (result, status, _) = await RevokeRun(db, laptop);
        check(result is { Code: 0, Detail: "Every saved approval has ended." } && status == 200 && !new GrantStore(db).TryGet("K", out _, out _) && TestState.Current(db)!.Version == version, "manifest revoke: the admin key revokes; the manifest is unchanged (" + result?.Detail + ")");

        StateDatabase empty = StateDatabase.InFolder(Path.Combine(root, "revoke-empty"));
        (result, _, announced) = await RevokeRun(empty, null);
        check(result is { Code: 0 } && announced == 0 && !File.Exists(empty.FilePath), "manifest revoke: with nothing enrolled there is nothing to revoke and nothing is asked");

        StateDatabase edited = Seeded(root, laptop, phone);
        Execute(edited.FilePath, "UPDATE manifest SET text = replace(text, '\"port\":0', '\"port\":1')");
        (result, _, announced) = await RevokeRun(edited, laptop);
        check(result is { Code: RunCommand.StoreError } && announced == 0, "manifest revoke: a state that fails verification is exit 4 (" + result?.Detail + ")");
    }

    /// <summary>Writers in parallel, each from a fresh connection like a separate process: no change is lost or forked.</summary>
    private static void Parallel(Action<bool, string> check, string root)
    {
        using TestAuthenticator laptop = TestAuthenticator.ES256();
        StateDatabase db = StateDatabase.InFolder(Path.Combine(root, "parallel"));
        TestState.Add(db, Record(laptop, "laptop"));
        string id = TestAuthenticator.Encode(laptop.CredentialId);
        const int Writers = 8;
        TestAuthenticator[] keys = [.. Enumerable.Range(0, Writers).Select(_ => TestAuthenticator.ES256())];
        try
        {
            // Every writer retries on a stale version until its key is in: all keys must end up there.
            Task[] tasks = [.. keys.Select((key, index) => Task.Run(() =>
            {
                for (int attempt = 0; attempt < 200; attempt++)
                {
                    StateDatabase mine = new(db.FilePath);
                    Manifest current = TestState.Current(mine)!;
                    if (TestState.Write(mine, current.WithKey(Record(key, "k" + index))))
                    {
                        return;
                    }
                }
            })), .. Enumerable.Range(0, Writers).Select(index => Task.Run(() => new PasskeyStore(new StateDatabase(db.FilePath)).UpdateSignCount(id, (uint)(100 + index))))];
            Task.WaitAll(tasks);
            Manifest final = TestState.Current(new StateDatabase(db.FilePath))!;
            check(final.Keys.Count == Writers + 1 && final.Version == Writers + 1, "manifest parallel: no lost update (" + final.Keys.Count + " keys, version " + final.Version + ")");
            check(new PasskeyStore(db).All().Single(key => key.Admin).SignCount == 100 + Writers - 1, "manifest parallel: the sign count ends at the highest value");
        }
        finally
        {
            foreach (TestAuthenticator key in keys)
            {
                key.Dispose();
            }
        }
    }
}
