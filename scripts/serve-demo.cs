#:sdk Microsoft.NET.Sdk.Web
#:property TargetFramework=net10.0
#:property Nullable=enable

using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;

var rootArgument = GetArgument(args, "--root")
    ?? throw new ArgumentException("Missing required --root <demo-root-directory> argument.");
var url = GetArgument(args, "--url") ?? "http://127.0.0.1:4173";
var root = Path.GetFullPath(rootArgument);

if (!Directory.Exists(root))
    throw new DirectoryNotFoundException($"Demo root does not exist: {root}");

var fileProvider = new PhysicalFileProvider(root);
var contentTypes = new FileExtensionContentTypeProvider();
contentTypes.Mappings[".webm"] = "video/webm";

var builder = WebApplication.CreateBuilder();
var app = builder.Build();

app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = fileProvider });
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = fileProvider,
    ContentTypeProvider = contentTypes
});

app.MapGet("/", () =>
{
    var runs = Directory.EnumerateDirectories(root)
        .Where(IsCompletedRun)
        .Select(path => new
        {
            Name = Path.GetFileName(path),
            Url = Uri.EscapeDataString(Path.GetFileName(path))
        })
        .OrderByDescending(run => run.Name, StringComparer.OrdinalIgnoreCase)
        .ToArray();

    var html = new StringBuilder("""
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>with-secrets UX demos</title>
          <style>
            body { font: 16px system-ui, sans-serif; max-width: 900px; margin: 3rem auto; padding: 0 1.25rem; }
            h1 { font-size: 1.7rem; }
            li { margin: .8rem 0; }
            a { overflow-wrap: anywhere; }
            .empty { color: #666; }
          </style>
        </head>
        <body>
          <h1>with-secrets UX demos</h1>
          <p>Select a recording run to review.</p>
        """);

    if (runs.Length == 0)
    {
        html.AppendLine("""<p class="empty">No completed demo runs found. Run scripts\demo.ps1 first.</p>""");
    }
    else
    {
        html.AppendLine("<ul>");
        foreach (var run in runs)
        {
            html.Append("<li><a href=\"/")
                .Append(run.Url)
                .Append("/index.html\">")
                .Append(HtmlEncoder.Default.Encode(run.Name))
                .AppendLine("</a></li>");
        }
        html.AppendLine("</ul>");
    }

    html.AppendLine("</body></html>");
    return Results.Content(html.ToString(), "text/html; charset=utf-8", Encoding.UTF8);
});

app.Urls.Add(url);
Console.WriteLine($"Demo library: {root}");
Console.WriteLine($"Open: {url}/");
Console.WriteLine("WebM files support HTTP byte-range requests for seeking. Press Ctrl+C to stop.");

await app.RunAsync();

static bool IsCompletedRun(string directory) =>
    File.Exists(Path.Combine(directory, "index.html")) &&
    Directory.Exists(Path.Combine(directory, "videos"));

static string? GetArgument(string[] arguments, string name)
{
    for (var i = 0; i < arguments.Length; i++)
    {
        if (arguments[i] == name)
            return i + 1 < arguments.Length ? arguments[i + 1] : null;
    }

    return null;
}
