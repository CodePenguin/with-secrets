namespace WithSecrets;

/// <summary>
/// The terminal side of a code that the person types after the last tap. Every line the program writes to the terminal while a
/// command runs goes through <see cref="Line" />. While the prompt waits for the code (<see cref="ReadCode" />), the prompt is the
/// last thing shown: other lines are held back and shown after the person pressed Enter; the network diagnostics
/// (<see cref="Noise" />) are dropped in that time. The prompt names no code and no key.
/// </summary>
public static class TerminalPrompt
{
    public const string Waiting = "Waiting for the code from the page. Paste it here and press Enter: ";

    public const string Wrong = "That code is wrong. Paste the code from the page and press Enter: ";

    private static readonly Lock Gate = new();
    private static readonly List<string> Held = [];
    private static bool _waiting;

    /// <summary>For tests: where lines go (the standard error stream when null).</summary>
    public static TextWriter? Output { get; set; }

    /// <summary>For tests: reads the typed line (the console when null).</summary>
    public static Func<string?>? Input { get; set; }

    private static TextWriter Out => Output ?? Console.Error;

    /// <summary>One line for the terminal; held until the code was typed when the prompt is waiting.</summary>
    public static void Line(string text)
    {
        lock (Gate)
        {
            if (_waiting)
            {
                Held.Add(text);

                return;
            }

            Out.WriteLine(text);
        }
    }

    /// <summary>A diagnostic line (network, proof): shown now, but dropped while the prompt waits.</summary>
    public static void Noise(string text)
    {
        lock (Gate)
        {
            if (!_waiting)
            {
                Out.WriteLine(text);
            }
        }
    }

    /// <summary>
    /// A line that ends the command (its result). When the wait ended while the read is still blocked (the time limit, Cancel on the
    /// page), the prompt line is ended first and the held lines are shown, so the result is not appended to the prompt.
    /// </summary>
    public static void Final(string text)
    {
        lock (Gate)
        {
            Release(false);
            Out.WriteLine(text);
        }
    }

    /// <summary>Ends the waiting state: a new line after the prompt (tests only; the console echoes Enter itself, so it is not added there) and the held lines. Call with the lock held.</summary>
    private static void Release(bool echoed)
    {
        if (!_waiting)
        {
            return;
        }

        _waiting = false;
        if (!echoed)
        {
            Out.WriteLine();
        }

        foreach (string text in Held)
        {
            Out.WriteLine(text);
        }

        Held.Clear();
    }

    /// <summary>Shows the prompt (no new line after it), reads the typed line, then shows the lines held meanwhile.</summary>
    public static string? ReadCode(bool again)
    {
        lock (Gate)
        {
            Out.Write(again ? Wrong : Waiting);
            Out.Flush();
            _waiting = true;
        }

        try
        {
            return Input is { } read ? read() : Console.ReadLine();
        }
        finally
        {
            lock (Gate)
            {
                Release(Output is null);
            }
        }
    }
}
