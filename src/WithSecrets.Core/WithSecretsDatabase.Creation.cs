using Microsoft.Data.Sqlite;

namespace WithSecrets;

public sealed partial class WithSecretsDatabase
{
    internal static SqliteCommand Command(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach ((string name, object? value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        return command;
    }

    internal static int Execute(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        using SqliteCommand command = Command(connection, transaction, sql, parameters);

        return command.ExecuteNonQuery();
    }

    internal static object? Scalar(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        using SqliteCommand command = Command(connection, transaction, sql, parameters);

        return command.ExecuteScalar();
    }

    /// <summary>
    /// The creation gate: an exclusive lock, held by the operating system for as long as the returned stream is open, that serializes the first creation of the database between independent processes (and threads). The lock file is
    /// made once and never removed or replaced: a lock on a file that is unlinked while locked protects nothing, because the next process would make a new file at the same path and lock that one. The lock is a share-none open:
    /// on Linux and macOS .NET takes flock(LOCK_EX) on the one file; on Windows it is the file's share mode. Either way the operating system releases it when the process ends, however it ends, so a crashed creator never blocks
    /// the next. The gate is waited for as long as the busy timeout. What cannot be trusted is refused, not worked around: a lock file that is a link, is not a regular file, is not this user's, or is open to others (Unix),
    /// and a lock that does not exclude (a file system or setting without locking: a second exclusive open of the file must be refused).
    /// </summary>
    internal static FileStream AcquireCreationGate(string folder, string databaseName, string fileLabel, TimeSpan timeout, Func<FileStream>? secondOpen)
    {
        Directory.CreateDirectory(folder);
        string gatePath = Path.Combine(folder, databaseName + ".lock");
        DateTime deadline = DateTime.UtcNow + timeout;
        string lastBusy = "";
        while (true)
        {
            CheckGateFile(gatePath, fileLabel);
            FileStream? stream = null;
            try
            {
                stream = OpenGate(gatePath);

                // Prove that the lock excludes: a second exclusive open of the same file, made while this one is held, must be refused *because the file is locked*. Any other outcome is not proof: an open that succeeds means
                // the lock excludes nobody, and an open that fails for another reason (no more file handles, no memory, no permission) says nothing about locking. Neither is used as a lock.
                GateProbe probe = ClassifySecondOpen(secondOpen ?? (() => OpenGate(gatePath)));
                if (probe == GateProbe.Allowed)
                {
                    throw new WithSecretsDatabaseException($"{fileLabel} cannot be created safely: the lock file {gatePath} does not exclude other processes on this file system (file locking is off or not supported there)");
                }

                if (probe == GateProbe.Unverified)
                {
                    throw new WithSecretsDatabaseException($"{fileLabel} cannot be created safely: it could not be verified that the lock file {gatePath} excludes other processes (the check failed for a reason other than the file being locked). Nothing was changed.");
                }

                CheckGateFile(gatePath, fileLabel);

                return stream;
            }
            catch (IOException busy)
            {
                stream?.Dispose();
                lastBusy = busy.Message;
                if (DateTime.UtcNow >= deadline)
                {
                    throw new WithSecretsDatabaseException($"{fileLabel} cannot be created: another process holds the creation lock {gatePath} ({lastBusy}). Nothing was changed; run again once the other with-secrets command has finished.", busy);
                }

                Thread.Sleep(5);
            }
            catch
            {
                stream?.Dispose();
                throw;
            }
        }
    }

    private static FileStream OpenGate(string gatePath)
    {
        FileStreamOptions options = new()
        {
            Mode = FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            BufferSize = 1,
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        return new FileStream(gatePath, options);
    }
    /// <summary>What a second exclusive open of the held lock file showed.</summary>
    internal enum GateProbe
    {
        /// <summary>Refused because the file is locked: the lock excludes.</summary>
        Excluded,

        /// <summary>It opened: the lock excludes nobody.</summary>
        Allowed,

        /// <summary>It failed for some other reason: nothing is known about the lock.</summary>
        Unverified,
    }

    /// <summary>Makes the second open (the given one, or the lock file again) and says what it showed. Never throws.</summary>
    private static GateProbe ClassifySecondOpen(Func<FileStream> open)
    {
        try
        {
            using FileStream second = open();

            return GateProbe.Allowed;
        }
        catch (Exception failure)
        {
            return ClassifyFailure(failure);
        }
    }

    /// <summary>
    /// The refusal that proves the lock: the operating system's own "locked by another" answer and no other. Linux and macOS: <c>flock</c> would block (EWOULDBLOCK: 11 on Linux, 35 on macOS), which .NET reports as an I/O error carrying
    /// that errno. Windows: a sharing violation (ERROR_SHARING_VIOLATION, 32, HRESULT 0x80070020), which is what a share-none open of a file that is open says. Everything else (too many open files, disk full, no memory, no permission,
    /// any other I/O error) is <see cref="GateProbe.Unverified" />. A lock violation (33) is a byte-range lock and does not count either.
    /// </summary>
    internal static GateProbe ClassifyFailure(Exception failure)
    {
        if (failure is not IOException io)
        {
            return GateProbe.Unverified;
        }

        bool contended = OperatingSystem.IsWindows() ? (uint)io.HResult == 0x80070020 : io.HResult == (OperatingSystem.IsMacOS() ? 35 : 11);

        return contended ? GateProbe.Excluded : GateProbe.Unverified;
    }
    /// <summary>On Linux and macOS the lock file, when there is one, is a regular file of this user that nobody else can open. Throws otherwise (the file is not touched).</summary>
    private static void CheckGateFile(string gatePath, string fileLabel)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        if (!File.Exists(gatePath) && !Directory.Exists(gatePath) && new FileInfo(gatePath).LinkTarget is null)
        {
            return;
        }

        UnixFileInfo? info = UnixFileInfo.Of(gatePath);
        if (info is null || !info.IsRegularFile || info.Owner != UnixSocketEndpoint.EffectiveUserId() || (info.Permissions & 0x3F) != 0)
        {
            throw new WithSecretsDatabaseException($"{fileLabel} cannot be created safely: the lock file {gatePath} is not a regular file of this user that only this user can open, so it is not used (it is not changed either)");
        }
    }
}
