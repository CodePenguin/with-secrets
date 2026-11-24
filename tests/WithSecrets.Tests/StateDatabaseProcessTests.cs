using System.Diagnostics;
using System.Security.Cryptography;

namespace WithSecrets.Tests;

/// <summary>
/// The creation of with-secrets.db when several independent operating-system processes reach an empty store folder together. Threads in one process do not show what a lock between processes must: so every writer here is a
/// process of its own (this test program started again in a child mode), they are released at the same moment by an explicit message on their standard input (nothing depends on timing), and what is checked is what the
/// operating system gave them: every passkey is stored, the manifest verifies and its versions run without a gap. The lock itself is checked the same way: a process that dies holding it releases it, and a lock that is held
/// or cannot be trusted refuses with a clear reason and changes nothing.
/// </summary>
internal static class StateDatabaseProcessTests
{
    private const int Writers = 5;
    private const int Rounds = 12;
    private const int MixedWrites = 8;

    // ---- the child side

    /// <summary>The entry of a child process (see Program.Main): <c>--state-writer FOLDER ADMIN-KEY ADMIN-ID</c> or <c>--state-hold-gate FOLDER</c>.</summary>
    public static int ChildMain(string[] args)
    {
        try
        {
            string folder = args[1];
            if (args[0] == "--state-hold-gate")
            {
                using IDisposable gate = StateDatabase.InFolder(folder).HoldCreationGateForTests();
                Console.Out.WriteLine("HELD");
                Console.Out.Flush();
                Thread.Sleep(Timeout.Infinite);

                return 0;
            }

            if (args[0] == "--state-authority-writer")
            {
                Console.Out.WriteLine("READY");
                Console.Out.Flush();
                Console.In.ReadLine();
                AuthorityStore authority = AuthorityStore.InFolder(folder);
                for (int index = 0; index < MixedWrites; index++)
                {
                    authority.RecordPairingEvent("cross-process-pairing", null, "test");
                }
                Console.Out.WriteLine("MIXED DONE");
                return 0;
            }

            // Every writer signs as the same admin (the parent made its key) and adds a passkey of its own.
            using TestAuthenticator admin = TestAuthenticator.ES256FromExport(Convert.FromBase64String(args[2]), Convert.FromBase64String(args[3]));
            using TestAuthenticator mine = TestAuthenticator.ES256();
            Console.Out.WriteLine("READY");
            Console.Out.Flush();
            Console.In.ReadLine();

            StateDatabase db = StateDatabase.InFolder(folder);
            PasskeyRecord adminRecord = admin.Record("localhost", "admin");
            string adminId = adminRecord.Id;
            for (int attempt = 0; attempt < 400; attempt++)
            {
                try
                {
                    if (TestState.Current(db)?.Keys.Any(key => key.Id == adminId) == true)
                    {
                        break;
                    }
                }
                catch (InvalidOperationException)
                {
                    // Retried.
                }

                TestState.Add(db, adminRecord);
            }

            PasskeyRecord record = mine.Record("localhost", "proc-" + Environment.ProcessId);
            for (int attempt = 0; attempt < 400; attempt++)
            {
                if (TestState.Add(StateDatabase.InFolder(folder), record))
                {
                    Console.Out.WriteLine("DONE " + record.Id);
                    Console.Out.Flush();

                    return 0;
                }
            }

            Console.Out.WriteLine("REFUSED");

            return 3;
        }
        catch (Exception error)
        {
            Console.Out.WriteLine("ERROR " + error.GetType().Name + ": " + error.Message.Replace('\n', ' '));

            return 4;
        }
    }

    // ---- the parent side

    private static Process Start(params string[] args)
    {
        string exe = Environment.ProcessPath ?? throw new InvalidOperationException("the path of this program is unknown");
        ProcessStartInfo info = new(exe) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        if (Path.GetFileNameWithoutExtension(exe).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            info.ArgumentList.Add(typeof(StateDatabaseProcessTests).Assembly.Location);
        }

        foreach (string argument in args)
        {
            info.ArgumentList.Add(argument);
        }

        return Process.Start(info) ?? throw new InvalidOperationException("the child process did not start");
    }

    private static async Task<string?> Line(Process process) => await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(120));

    public static async Task Run(Action<bool, string> check, string root)
    {
        await IndependentProcessesRace(check, root);
        await WritersWaitBehindAnotherProcess(check, root);
        await GateIsReleasedWhenItsHolderDies(check, root);
        await UntrustedGateFile(check, root);
        LockVerification(check, root);
    }

    /// <summary>Writer processes for one folder, all started and ready (each holds its own passkey), none released yet.</summary>
    private sealed class Group(string folder, TestAuthenticator admin, List<Process> children, int stateWriters) : IDisposable
    {
        public string Folder { get; } = folder;

        public List<Process> Children { get; } = children;
        public int StateWriters { get; } = stateWriters;

        public TestAuthenticator Admin { get; } = admin;

        public void Dispose()
        {
            foreach (Process child in Children)
            {
                if (!child.HasExited)
                {
                    child.Kill(true);
                }

                child.Dispose();
            }

            Admin.Dispose();
        }
    }

    private static async Task<(Group Group, List<string> Problems)> Launch(string folder, int count, int authorityWriters = 0)
    {
        Directory.CreateDirectory(folder);
        TestAuthenticator admin = TestAuthenticator.ES256();
        string key = Convert.ToBase64String(admin.ExportPrivate());
        string id = Convert.ToBase64String(admin.CredentialId);
        List<Process> children = [];
        List<string> problems = [];
        for (int writer = 0; writer < count; writer++)
        {
            children.Add(Start("--state-writer", folder, key, id));
        }
        for (int writer = 0; writer < authorityWriters; writer++)
        {
            children.Add(Start("--state-authority-writer", folder));
        }

        foreach (Process child in children)
        {
            string? ready = await Line(child);
            if (ready != "READY")
            {
                problems.Add("not ready: " + ready);
            }
        }

        return (new Group(folder, admin, children, count), problems);
    }

    /// <summary>The message every writer is waiting for: they are released together.</summary>
    private static async Task Release(Group group)
    {
        foreach (Process child in group.Children)
        {
            await child.StandardInput.WriteLineAsync("GO");
            await child.StandardInput.FlushAsync();
        }
    }

    /// <summary>Waits for every writer to finish and checks what is stored: every writer's passkey, a verified manifest, versions without a gap, an intact database.</summary>
    private static async Task<List<string>> FinishAndVerify(Group group, List<string> problems)
    {
        List<string> ids = [];
        int authorityFinished = 0;
        foreach (Process child in group.Children)
        {
            string? done = await Line(child);
            if (done is not null && done.StartsWith("DONE ", StringComparison.Ordinal))
            {
                ids.Add(done[5..]);
            }
            else if (done == "MIXED DONE")
            {
                authorityFinished++;
            }
            else
            {
                problems.Add("child said: " + done);
            }

            if (!child.WaitForExit(TimeSpan.FromSeconds(60)) || child.ExitCode != 0)
            {
                problems.Add("child exit " + (child.HasExited ? child.ExitCode : -1));
            }
        }

        int writers = group.StateWriters;
        StateDatabase db = StateDatabase.InFolder(group.Folder);
        Manifest? manifest = TestState.Current(db);
        string[] stored = manifest is null ? [] : [.. manifest.Keys.Select(item => item.Id)];
        bool allThere = ids.Count == writers && ids.All(item => stored.Contains(item, StringComparer.Ordinal));
        if (manifest is null || manifest.Version != writers + 1 || stored.Length != writers + 1 || !allThere || !db.TryCheck(out string? checkError) || checkError is not null)
        {
            problems.Add($"{stored.Length} keys of {writers + 1}, version {manifest?.Version}, children's keys present: {allThere}");
        }
        if (group.Children.Count > writers)
        {
            int expected = group.Children.Count - writers;
            if (authorityFinished != expected || AuthorityStore.InFolder(group.Folder).Audit().Count(item => item.Event == "cross-process-pairing") != expected * MixedWrites)
            {
                problems.Add("one or more authority writers lost changes during the state writes");
            }
        }

        return problems;
    }

    private static async Task IndependentProcessesRace(Action<bool, string> check, string root)
    {
        int bad = 0;
        string firstBad = "";
        for (int round = 0; round < Rounds; round++)
        {
            List<string> problems = [];
            try
            {
                (Group group, List<string> launched) = await Launch(Path.Combine(root, "proc-" + round), Writers, authorityWriters: round == 0 ? 3 : 0);
                using (group)
                {
                    problems.AddRange(launched);

                    // Every process has started and holds its own keys: only now are they all released, together, by a message each has been waiting for.
                    await Release(group);
                    await FinishAndVerify(group, problems);
                }
            }
            catch (Exception error)
            {
                problems.Add(error.GetType().Name + ": " + error.Message);
            }

            if (problems.Count > 0)
            {
                bad++;
                firstBad = firstBad.Length == 0 ? $"round {round}: {string.Join("; ", problems)}" : firstBad;
            }
        }

        check(bad == 0, "db processes: " + Rounds + " rounds of " + Writers + " independent processes reaching an empty store folder at the same moment: every process succeeded, every passkey is stored, the manifest verifies and its versions run without a gap (" + (bad == 0 ? "all kept" : bad + " rounds bad; " + firstBad) + ")");
    }

    /// <summary>
    /// Mutual exclusion between processes, without leaving it to chance: another process holds the creation lock, the writers are released and must not make the database while it is held (a creator that did not wait would
    /// have made it within moments); when the holder is gone they all finish and every passkey is stored.
    /// </summary>
    private static async Task WritersWaitBehindAnotherProcess(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "behind");
        Directory.CreateDirectory(folder);
        List<string> problems = [];
        using Process holder = Start("--state-hold-gate", folder);
        string? held = await Line(holder);
        (Group group, List<string> launched) = await Launch(folder, 3);
        using (group)
        {
            problems.AddRange(launched);
            await Release(group);
            DateTime until = DateTime.UtcNow.AddSeconds(1.5);
            bool madeEarly = false;
            while (DateTime.UtcNow < until && !madeEarly)
            {
                madeEarly = File.Exists(Path.Combine(folder, "with-secrets.db"));
                await Task.Delay(20);
            }

            holder.Kill(true);
            holder.WaitForExit();
            await FinishAndVerify(group, problems);
            check(held == "HELD" && !madeEarly && problems.Count == 0, "db processes: writers released while another process holds the creation lock make no database until it is gone, and then every one of them stores its passkey (" + (madeEarly ? "a database was made while the lock was held; " : "") + string.Join("; ", problems) + ")");
        }
    }
    private static async Task GateIsReleasedWhenItsHolderDies(Action<bool, string> check, string root)
    {
        string folder = Path.Combine(root, "gate");
        Directory.CreateDirectory(folder);
        string dbPath = Path.Combine(folder, "with-secrets.db");
        using Process holder = Start("--state-hold-gate", folder);
        string? held = await Line(holder);
        check(held == "HELD", "db gate: a process takes the creation lock (" + held + ")");

        // Held by another process: a creator waits for the busy timeout and then refuses with the reason, and changes nothing.
        StateDatabase waiting = new(dbPath, TimeSpan.FromMilliseconds(400));
        Exception? refused = null;
        try
        {
            waiting.Write((_, _) => 0);
        }
        catch (Exception error)
        {
            refused = error;
        }

        string[] leftovers = [.. Directory.GetFileSystemEntries(folder).Select(Path.GetFileName).Where(name => name != "with-secrets.db.lock")!];
        check(refused is StateDatabaseException && refused.Message.Contains("creation lock", StringComparison.Ordinal) && !File.Exists(dbPath) && leftovers.Length == 0, "db gate: while another process holds the creation lock, creating refuses with a clear reason and leaves no database and nothing else behind (" + refused?.Message + "; " + string.Join(",", leftovers) + ")");

        // The holder dies without releasing anything: the operating system releases the lock, and the next creator gets it.
        holder.Kill(true);
        holder.WaitForExit();
        StateDatabase next = new(dbPath, TimeSpan.FromSeconds(30));
        bool created = false;
        try
        {
            created = next.Write((_, _) => true);
        }
        catch (StateDatabaseException)
        {
            created = false;
        }

        check(created && File.Exists(dbPath) && File.Exists(Path.Combine(folder, "with-secrets.db.lock")) && next.TryCheck(out string? nextError) && nextError is null, "db gate: a process that dies while holding the creation lock releases it, and the next process creates the database (the lock file stays: it is never removed)");

        // An existing database never needs the gate: held by another process, reads and writes go on at once, and nothing is created again.
        using Process again = Start("--state-hold-gate", folder);
        string? heldAgain = await Line(again);
        bool wrote = false;
        try
        {
            wrote = new StateDatabase(dbPath, TimeSpan.FromMilliseconds(400)).Write((_, _) => true);
        }
        catch (StateDatabaseException)
        {
            wrote = false;
        }

        again.Kill(true);
        again.WaitForExit();
        check(heldAgain == "HELD" && wrote, "db gate: with a database already there, a writer does not use the creation lock (it wrote while another process held it, with a timeout that would have refused it)");
    }

    private static Task UntrustedGateFile(Action<bool, string> check, string root)
    {
        if (OperatingSystem.IsWindows())
        {
            Console.WriteLine("  SKIP lock file permissions and links: Windows controls access with the folder's access list and the file's share mode");

            return Task.CompletedTask;
        }

        UnixChecks(check, root);

        return Task.CompletedTask;
    }

    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    private static void UnixChecks(Action<bool, string> check, string root)
    {
        // The lock file is made with owner-only permissions.
        string made = Path.Combine(root, "gate-made");
        Directory.CreateDirectory(made);
        StateDatabase.InFolder(made).Write((_, _) => 0);
        string lockPath = Path.Combine(made, "with-secrets.db.lock");
        check(File.Exists(lockPath) && File.GetUnixFileMode(lockPath) == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "db gate: the lock file is made with owner-only permissions (" + (File.Exists(lockPath) ? Convert.ToString((int)File.GetUnixFileMode(lockPath), 8) : "missing") + ")");

        // A lock file that others can open is not trusted: refused, left as it is, no database made.
        string open = Path.Combine(root, "gate-open");
        Directory.CreateDirectory(open);
        string openLock = Path.Combine(open, "with-secrets.db.lock");
        File.WriteAllText(openLock, "");
        File.SetUnixFileMode(openLock, (UnixFileMode)Convert.ToInt32("666", 8));
        Exception? openRefused = null;
        try
        {
            StateDatabase.InFolder(open).Write((_, _) => 0);
        }
        catch (Exception error)
        {
            openRefused = error;
        }

        check(openRefused is StateDatabaseException && openRefused.Message.Contains("lock file", StringComparison.Ordinal) && !File.Exists(Path.Combine(open, "with-secrets.db")) && File.GetUnixFileMode(openLock) == (UnixFileMode)Convert.ToInt32("666", 8), "db gate: a lock file that others can open is refused with the reason, is not changed and no database is made (" + openRefused?.Message + ")");

        // A link in the place of the lock file is not followed.
        string linked = Path.Combine(root, "gate-link");
        Directory.CreateDirectory(linked);
        string victim = Path.Combine(root, "gate-victim.txt");
        File.WriteAllText(victim, "keep");
        File.CreateSymbolicLink(Path.Combine(linked, "with-secrets.db.lock"), victim);
        Exception? linkRefused = null;
        try
        {
            StateDatabase.InFolder(linked).Write((_, _) => 0);
        }
        catch (Exception error)
        {
            linkRefused = error;
        }

        check(linkRefused is StateDatabaseException && File.ReadAllText(victim) == "keep" && !File.Exists(Path.Combine(linked, "with-secrets.db")), "db gate: a lock file that is a link is refused and what it points to is untouched (" + linkRefused?.Message + ")");
    }

    /// <summary>
    /// The creation lock is trusted only when a second exclusive open of the held lock file is refused because the file is locked. The real refusal of this operating system is recognized; every other failure, and a second open that
    /// works, is not proof; and when locking cannot be verified nothing is created.
    /// </summary>
    private static void LockVerification(Action<bool, string> check, string root)
    {
        // The real thing, on whichever operating system this runs on: a second share-none open of a held file.
        string folder = Path.Combine(root, "verify");
        Directory.CreateDirectory(folder);
        StateDatabase db = StateDatabase.InFolder(folder);
        IOException? contention = null;
        using (db.HoldCreationGateForTests())
        {
            try
            {
                using FileStream second = new(Path.Combine(folder, "with-secrets.db.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1);
            }
            catch (IOException error)
            {
                contention = error;
            }
        }

        check(contention is not null && WithSecretsDatabase.ClassifyFailure(contention) == WithSecretsDatabase.GateProbe.Excluded, "db gate verification: the refusal of a second open of a held lock file is recognized as the lock working (" + (contention is null ? "it opened" : "HRESULT 0x" + contention.HResult.ToString("X8", System.Globalization.CultureInfo.InvariantCulture)) + ")");

        // Anything else is not proof. Failures that are not about the lock, made by hand: handle and memory exhaustion, a full disk, a plain I/O error, a lock violation (a byte range), no permission.
        Exception[] unrelated =
        [
            new IOException("too many open files (process)", OperatingSystem.IsWindows() ? unchecked((int)0x80070004) : 24),
            new IOException("too many open files (system)", OperatingSystem.IsWindows() ? unchecked((int)0x80070004) : 23),
            new IOException("no space left on device", OperatingSystem.IsWindows() ? unchecked((int)0x80070070) : 28),
            new IOException("an I/O error"),
            new IOException("a byte range is locked", unchecked((int)0x80070021)),
            new IOException("an input/output error", 5),
            new UnauthorizedAccessException("no permission"),
            new OutOfMemoryException(),
            new InvalidOperationException("anything else"),
        ];
        check(unrelated.All(error => WithSecretsDatabase.ClassifyFailure(error) == WithSecretsDatabase.GateProbe.Unverified), "db gate verification: handle exhaustion, a full disk, memory, permission, a byte-range lock and any other failure are not taken as proof that the lock works");

        // The other operating systems' answers are not this one's: each platform recognizes exactly its own.
        IOException otherPlatform = new("locked", OperatingSystem.IsWindows() ? 11 : OperatingSystem.IsMacOS() ? 11 : 35);
        check(WithSecretsDatabase.ClassifyFailure(otherPlatform) == WithSecretsDatabase.GateProbe.Unverified, "db gate verification: the contention answer of another platform is not accepted here");

        // When locking cannot be verified, the creation stops: no database, no change. A second open that fails for another reason, and one that wrongly works.
        string failing = Path.Combine(root, "verify-fail");
        Directory.CreateDirectory(failing);
        StateDatabase unverifiable = new(Path.Combine(failing, "with-secrets.db"), TimeSpan.FromSeconds(2)) { SecondGateOpen = () => throw new IOException("too many open files", OperatingSystem.IsWindows() ? unchecked((int)0x80070004) : 24) };
        Exception? refused = null;
        try
        {
            unverifiable.Write((_, _) => 0);
        }
        catch (Exception error)
        {
            refused = error;
        }

        string[] after = [.. Directory.GetFileSystemEntries(failing).Select(Path.GetFileName)!];
        check(refused is StateDatabaseException && refused.Message.Contains("could not be verified", StringComparison.Ordinal) && !File.Exists(Path.Combine(failing, "with-secrets.db")) && after.All(name => name == "with-secrets.db.lock"), "db gate verification: when the check fails for a reason other than the lock, creation stops with that diagnostic and no database or temporary file is made (" + refused?.Message + "; " + string.Join(",", after) + ")");

        string working = Path.Combine(root, "verify-open");
        Directory.CreateDirectory(working);
        string workingLock = Path.Combine(working, "with-secrets.db.lock");
        StateDatabase excludesNobody = new(Path.Combine(working, "with-secrets.db"), TimeSpan.FromSeconds(2)) { SecondGateOpen = () => new FileStream(Path.Combine(root, "verify-open-other.tmp"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite, 1, FileOptions.DeleteOnClose) };
        Exception? allowed = null;
        try
        {
            excludesNobody.Write((_, _) => 0);
        }
        catch (Exception error)
        {
            allowed = error;
        }

        check(allowed is StateDatabaseException && allowed.Message.Contains("does not exclude", StringComparison.Ordinal) && !File.Exists(Path.Combine(working, "with-secrets.db")) && File.Exists(workingLock), "db gate verification: a second open that works means the lock excludes nobody, and creation stops with that diagnostic (" + allowed?.Message + ")");
    }}
