using System.Diagnostics;
using System.Text;

namespace WithSecrets.E2E;

/// <summary>One completed default recording per branch, shared with the primary checkout's demo server.</summary>
internal sealed class DemoOutput(string destination, string workingDirectory, FileStream? lease = null) : IDisposable
{
    public string Destination { get; } = destination;
    public string WorkingDirectory { get; } = workingDirectory;

    public static DemoOutput Open(string checkout, string? requested)
    {
        string branch = Git(checkout, "branch", "--show-current")?.Trim() ?? "";
        string? firstWorktree = Git(checkout, "worktree", "list", "--porcelain", "-z")?.Split('\0')[0];
        string primary = firstWorktree?.StartsWith("worktree ", StringComparison.Ordinal) == true ? firstWorktree["worktree ".Length..] : checkout;
        string root = Path.GetFullPath(Path.Combine(primary, "artifacts", "demo"));
        string localRoot = Path.GetFullPath(Path.Combine(checkout, "artifacts", "demo"));

        if (requested is not null)
        {
            string explicitPath = Path.GetFullPath(requested);
            if (!IsBelow(root, explicitPath) && !IsBelow(localRoot, explicitPath))
                throw new ArgumentException("An explicit output directory must be under " + root + " or " + localRoot + ".");
            if (Directory.Exists(explicitPath) && Directory.EnumerateFileSystemEntries(explicitPath).Any())
                throw new IOException("The explicit output directory is not empty: " + explicitPath);

            Directory.CreateDirectory(explicitPath);
            return new DemoOutput(explicitPath, explicitPath);
        }

        bool linked = !string.Equals(Path.GetFullPath(primary), Path.GetFullPath(checkout),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
        string name = branch == "main" ? "latest"
            : SlotName(linked || branch.Length == 0 ? Path.GetFileName(checkout) : branch);
        string destination = Path.Combine(root, name);
        string work = Path.Combine(root, ".recording");
        if (!IsBelow(root, destination) || !IsBelow(root, work))
            throw new ArgumentException("The default demo directory must be under " + root + ".");

        Directory.CreateDirectory(work);
        RefuseLink(work);
        RefuseLink(destination);
        FileStream gate = new(Path.Combine(work, name + ".lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            string staging = Path.Combine(work, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(staging);
            return new DemoOutput(destination, staging, gate);
        }
        catch
        {
            gate.Dispose();
            throw;
        }
    }

    public void Publish()
    {
        if (lease is null) return;

        RefuseLink(Destination);
        string previous = WorkingDirectory + "-previous";
        bool replacing = Directory.Exists(Destination);
        if (replacing) Directory.Move(Destination, previous);
        try
        {
            Directory.Move(WorkingDirectory, Destination);
        }
        catch
        {
            if (replacing) Directory.Move(previous, Destination);
            throw;
        }

        if (replacing)
        {
            try
            {
                Directory.Delete(previous, recursive: true);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine("The new demo was published. Could not remove the previous recording from " + previous + ".");
            }
        }
    }

    public void Dispose()
    {
        try
        {
            if (lease is not null && Directory.Exists(WorkingDirectory))
                Directory.Delete(WorkingDirectory, recursive: true);
        }
        finally
        {
            lease?.Dispose();
        }
    }

    private static bool IsBelow(string root, string path)
    {
        string relative = Path.GetRelativePath(root, path);
        return relative is not ("." or "..") && !Path.IsPathRooted(relative)
            && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }

    private static void RefuseLink(string path)
    {
        if (Directory.Exists(path) && File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            throw new IOException("The demo directory must not be a filesystem link: " + path);
    }

    private static string SlotName(string name)
    {
        string safe = new(name.Select(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' ? c : '-').ToArray());
        if (safe.Length == 0) return "branch";
        return safe.Equals("latest", StringComparison.OrdinalIgnoreCase) ? "branch-latest" : safe;
    }

    private static string? Git(string workingDirectory, params string[] args)
    {
        try
        {
            ProcessStartInfo start = new("git")
            {
                WorkingDirectory = workingDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            foreach (string arg in args) start.ArgumentList.Add(arg);
            using Process? git = Process.Start(start);
            if (git is null) return null;
            string value = git.StandardOutput.ReadToEnd();
            git.WaitForExit();
            return git.ExitCode == 0 ? value : null;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }
}
