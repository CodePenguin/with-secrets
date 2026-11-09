using System.Collections.Frozen;
using System.Reflection;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace WithSecrets;

/// <summary>
/// The administration web application's built files (Vite output) served by the host service from the one origin, under <c>/admin</c>. The files are not on disk: they are resources of this
/// assembly (the build embeds <c>src/WithSecrets.Admin.Web/dist</c> as <c>admin-web/...</c>), so the published program is one file with no loose frontend files and no Node at run time.
/// <para>
/// Routing (architecture 10.5): <c>/admin</c> and every extension-less path under it are application routes and answer the one <c>index.html</c> (the router of the page reads the address);
/// a path with a file extension is a file and is answered only if it exists (otherwise 404 with no body to guess from), so a missing script or style is never answered with the page;
/// <c>/api</c> never reaches this class. Only GET and HEAD. The page is served with a strict Content Security Policy: its own origin only, no inline script or style, no external asset.
/// </para>
/// </summary>
internal sealed class AdminWebAssets
{
    public const string Base = "/admin";
    private const string ResourcePrefix = "admin-web/";

    /// <summary>The content security policy of the page: same origin only; no inline script or style (Vite emits files); no frames, forms or plug-ins; no base tag.</summary>
    internal const string ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";

    private static readonly FrozenDictionary<string, string> ContentTypes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        [".html"] = "text/html; charset=utf-8",
        [".js"] = "text/javascript; charset=utf-8",
        [".mjs"] = "text/javascript; charset=utf-8",
        [".css"] = "text/css; charset=utf-8",
        [".json"] = "application/json; charset=utf-8",
        [".svg"] = "image/svg+xml",
        [".png"] = "image/png",
        [".ico"] = "image/x-icon",
        [".woff2"] = "font/woff2",
        [".txt"] = "text/plain; charset=utf-8",
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    private readonly FrozenDictionary<string, byte[]> _files;

    /// <summary>The files by their path below the application root, for example <c>index.html</c> and <c>assets/index-abc.js</c>.</summary>
    public AdminWebAssets(IEnumerable<KeyValuePair<string, byte[]>> files) => _files = files.ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>The files embedded in this assembly (none when it was built without the frontend).</summary>
    public static AdminWebAssets FromAssembly()
    {
        Assembly assembly = typeof(AdminWebAssets).Assembly;
        List<KeyValuePair<string, byte[]>> files = [];
        foreach (string name in assembly.GetManifestResourceNames().Where(name => name.StartsWith(ResourcePrefix, StringComparison.Ordinal)))
        {
            using Stream stream = assembly.GetManifestResourceStream(name)!;
            using MemoryStream copy = new();
            stream.CopyTo(copy);
            files.Add(new KeyValuePair<string, byte[]>(name[ResourcePrefix.Length..], copy.ToArray()));
        }

        return new AdminWebAssets(files);
    }

    /// <summary>True when the application is part of this build (it has at least its page).</summary>
    public bool Available => _files.ContainsKey("index.html");

    /// <summary>The paths of the files (for the publish check).</summary>
    public IReadOnlyCollection<string> Paths => _files.Keys;

    /// <summary>The version the frontend was built with (its <c>version.json</c>), or null.</summary>
    public string? FrontendVersion
    {
        get
        {
            if (!_files.TryGetValue("version.json", out byte[]? bytes))
            {
                return null;
            }

            try
            {
                using JsonDocument document = JsonDocument.Parse(bytes);

                return document.RootElement.TryGetProperty("version", out JsonElement version) ? version.GetString() : null;
            }
            catch (JsonException)
            {
                return null;
            }
        }
    }

    /// <summary>True for <c>/admin</c> and everything below it.</summary>
    public static bool IsApplicationPath(string path) => path == Base || path.StartsWith(Base + "/", StringComparison.Ordinal);

    /// <summary>The file this address names, or null: <c>index.html</c> for an application route, the file for a file address, null for a file that does not exist.</summary>
    internal (string Path, byte[] Content)? Resolve(string requestPath)
    {
        string relative = requestPath.Length <= Base.Length + 1 ? "" : requestPath[(Base.Length + 1)..];
        if (relative.Contains('\\', StringComparison.Ordinal) || relative.Contains("..", StringComparison.Ordinal) || relative.Contains("//", StringComparison.Ordinal))
        {
            return null;
        }

        string last = relative[(relative.LastIndexOf('/') + 1)..];
        bool isFile = last.Contains('.', StringComparison.Ordinal);
        if (!isFile)
        {
            // An application route (or the root): the page.
            return _files.TryGetValue("index.html", out byte[]? index) ? ("index.html", index) : null;
        }

        return _files.TryGetValue(relative, out byte[]? content) ? (relative, content) : null;
    }

    /// <summary>Answers a request under <c>/admin</c>. Without the application in this build the answer is the JSON 404 that says so.</summary>
    public async Task ServeAsync(HttpContext context, Func<HttpContext, Task> notBuilt)
    {
        HttpResponse response = context.Response;
        HttpRequest request = context.Request;
        if (!Available)
        {
            await notBuilt(context);

            return;
        }

        bool head = HttpMethods.IsHead(request.Method);
        if (!head && !HttpMethods.IsGet(request.Method))
        {
            response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            response.Headers.Allow = "GET, HEAD";

            return;
        }

        (string Path, byte[] Content)? file = Resolve(request.Path.Value ?? "");
        response.Headers.XContentTypeOptions = "nosniff";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers["X-Frame-Options"] = "DENY";
        if (file is null)
        {
            response.StatusCode = StatusCodes.Status404NotFound;

            return;
        }

        string extension = System.IO.Path.GetExtension(file.Value.Path);
        response.StatusCode = StatusCodes.Status200OK;
        response.ContentType = ContentTypes.TryGetValue(extension, out string? type) ? type : "application/octet-stream";
        response.ContentLength = file.Value.Content.Length;
        if (file.Value.Path == "index.html")
        {
            response.Headers.ContentSecurityPolicy = ContentSecurityPolicy;
            response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(), publickey-credentials-create=()";
        }

        if (!head)
        {
            await response.Body.WriteAsync(file.Value.Content, context.RequestAborted);
        }
    }
}
