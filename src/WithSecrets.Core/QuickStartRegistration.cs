using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Http;

namespace WithSecrets;

/// <summary>A one-use setup on the already running local service's browser origin.</summary>
internal sealed class QuickStartRegistration(HostService service)
{
    internal const string Prefix = "/admin/quick-start/";

    public string Code { get; } = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    public string Path { get; } = Prefix + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(24));
    public string Origin => $"http://localhost:{service.Port}";
    public string Url => Origin + Path;
    public string Fingerprint => service.QuickStartFingerprint;
    public string DeviceName => service.QuickStartDeviceName;
    public Func<Task>? WaitForCancellation { get; init; }

    public IDisposable Open(Func<string, string, string, OneShotResponse> handle) => service.OpenQuickStartRoute(this, handle);

    // A new challenge is made only after the terminal code was accepted. It binds the manifest assertion to this route, device and exact bootstrap purpose.
    public byte[] Bind() => SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
    {
        purpose = "with-secrets/v1 quick-start: enroll, trust local device, unlock, sign in",
        origin = Origin,
        route = Path,
        fingerprint = Fingerprint,
        nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32)),
    }));

    public static bool Opens(Manifest manifest, Unlock unlock)
    {
        using UnlockedKeys check = new();
        return check.TryOpen(manifest, unlock);
    }

    public AdminSession? Complete(PasskeyRecord signer, Unlock unlock) => service.CompleteQuickStart(signer, unlock);
}

public sealed partial class HostService
{
    private QuickStartRoute? _quickStart;
    internal string QuickStartFingerprint => KeyIdentity.Display(_options.Deployment.Fingerprint);
    internal string QuickStartDeviceName => _options.Deployment.HostName;

    private sealed class QuickStartRoute(HostService service, QuickStartRegistration registration, Func<string, string, string, OneShotResponse> handle) : IDisposable
    {
        public QuickStartRegistration Registration { get; } = registration;
        public Func<string, string, string, OneShotResponse> Handle { get; } = handle;
        public void Dispose() => Interlocked.CompareExchange(ref service._quickStart, null, this);
    }

    internal IDisposable OpenQuickStartRoute(QuickStartRegistration registration, Func<string, string, string, OneShotResponse> handle)
    {
        if (Authorization.IsRemote || !Lock.IsLocked)
        {
            throw new InvalidOperationException("Quick Start requires a locked local authority.");
        }

        QuickStartRoute route = new(this, registration, handle);
        return Interlocked.CompareExchange(ref _quickStart, route, null) is null
            ? route : throw new InvalidOperationException("Quick Start is already running.");
    }

    private async Task<bool> HandleQuickStartAsync(HttpContext context, string path)
    {
        if (!path.StartsWith(QuickStartRegistration.Prefix, StringComparison.Ordinal)) return false;

        HttpRequest request = context.Request;
        HttpResponse response = context.Response;
        QuickStartRoute? route = Volatile.Read(ref _quickStart);
        if (route is null || (path != route.Registration.Path && !path.StartsWith(route.Registration.Path + "/", StringComparison.Ordinal))
            || $"http://{request.Host.Value}" != route.Registration.Origin)
        {
            await Refuse(response, 404, "not found");
            return true;
        }

        string body = "";
        if (HttpMethods.IsPost(request.Method))
        {
            if (request.Headers.Origin.Count != 1 || request.Headers.Origin[0] != route.Registration.Origin)
            {
                await Refuse(response, 403, "the setup origin did not match");
                return true;
            }
            try
            {
                body = Encoding.UTF8.GetString(await ReadBody(request.Body, context.RequestAborted));
            }
            catch (Exception error) when (error is IOException or BodyTooLargeException)
            {
                await Refuse(response, 400, "the setup request could not be read");
                return true;
            }
        }
        else if (!HttpMethods.IsGet(request.Method))
        {
            await Refuse(response, 405, "use GET or POST");
            return true;
        }

        string suffix = path.Length == route.Registration.Path.Length ? "" : path[(route.Registration.Path.Length + 1)..];
        OneShotResponse result = route.Handle(request.Method, suffix, body);
        response.StatusCode = result.Status;
        response.ContentType = result.ContentType;
        response.Headers["Referrer-Policy"] = "no-referrer";
        if (result.ContentSecurityPolicy is { } policy) response.Headers["Content-Security-Policy"] = policy;
        if (result.Session is { } session) Admin.Api.SetQuickStartSession(response, session);
        await response.WriteAsync(result.Body, context.RequestAborted);
        return true;
    }

    internal AdminSession? CompleteQuickStart(PasskeyRecord signer, Unlock unlock)
    {
        if (Keys is not { } keys || !_options.State.TryManifest(out Manifest? manifest, out _) || manifest?.IsAdmin(signer.Id) != true
            || Lock.UnlockWith(UnlockMethod.Manual, () => keys.TryOpen(manifest, unlock)) != UnlockOutcome.Unlocked)
        {
            return null;
        }

        try
        {
            AdminSession? session = Lock.UseWhileUnlocked(() =>
            {
                LocalDeployment local = _options.Deployment;
                VerifiedCredential actor = new(signer.Id, signer.Name, true);
                string name = Enrollment.NameError(local.HostName) is null ? local.HostName : "This device";
                if (!AdminActions.ApproveMachine(local.Store, local.Keys, local.HostConfig, local.Fingerprint, local.Fingerprint, name, signer.Name, key: actor).Ok)
                {
                    throw new InvalidOperationException("the local device could not be trusted");
                }

                string browser = AdminSessions.NewBrowserId();
                if (Admin.Sessions.BeginLogin(browser) is not { } login) return null;
                Admin.Sessions.CompleteLogin(login.Code, signer.Name, null, SessionScope.Admin, actor);
                AdminSession? claimed = Admin.Sessions.Claim(login.Ticket, browser);
                if (claimed is not null) Admin.RecordSessionStart(claimed);
                return claimed;
            });
            AfterUnlock();
            return session;
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            Lock.Lock("Quick Start could not finish authorizing the local service");
            return null;
        }
    }
}
