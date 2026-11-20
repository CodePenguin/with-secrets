namespace WithSecrets;

/// <summary>
/// The terminal side of a code that the person types after the last tap. Every line the program writes to the terminal while a
/// command runs goes through <see cref="Line" />, and is written at once: nothing is held back or dropped. The prompt is the last
/// thing shown at the wait because, in normal mode, the command writes nothing but its result while it waits (the diagnostics are
/// Debug events and off). With --debug they print as they arrive. The prompt names no code and no key.
/// </summary>
public static class TerminalPrompt
{
    public const string Waiting = "Type the code from the page: ";

    public const string Wrong = "That code is wrong. Paste the code from the page and press Enter: ";

    private static readonly Lock Gate = new();
    private static bool _promptOpen;

    /// <summary>For tests: where lines go (the standard error stream when null).</summary>
    public static TextWriter? Output { get; set; }

    /// <summary>For tests: reads the typed line (the console when null).</summary>
    public static Func<string?>? Input { get; set; }

    private static TextWriter Out => Output ?? Console.Error;

    /// <summary>One line for the terminal, written now. If the prompt line is still open (the read has not returned), it is ended first.</summary>
    public static void Line(string text)
    {
        lock (Gate)
        {
            EndPromptLine();
            Out.WriteLine(text);
        }
    }

    /// <summary>A diagnostic line (--debug): written now, like any line.</summary>
    public static void Noise(string text) => Line(text);

    /// <summary>A line that ends the command (its result).</summary>
    public static void Final(string text) => Line(text);

    /// <summary>Call with the lock held: a new line after a prompt that is still open.</summary>
    private static void EndPromptLine()
    {
        if (_promptOpen)
        {
            _promptOpen = false;
            Out.WriteLine();
        }
    }

    /// <summary>Shows the prompt (no new line after it) and reads the typed line.</summary>
    public static string? ReadCode(bool again)
    {
        lock (Gate)
        {
            EndPromptLine();
            Out.Write(again ? Wrong : Waiting);
            Out.Flush();
            _promptOpen = true;
        }

        try
        {
            return Input is { } read ? read() : Console.ReadLine();
        }
        finally
        {
            lock (Gate)
            {
                // The console echoes Enter itself; a test output does not.
                if (_promptOpen && Output is not null)
                {
                    Out.WriteLine();
                }

                _promptOpen = false;
            }
        }
    }
}
