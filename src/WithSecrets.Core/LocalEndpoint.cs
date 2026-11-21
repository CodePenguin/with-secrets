using System.Net;

using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace WithSecrets;

/// <summary>
/// How the command line reaches the host service of this machine, and where the service listens for it. Only the way requests and answers are carried differs between endpoints: the routes, the models, the request digest,
/// the identity challenge and the streamed answers are the application protocol and are the same over every endpoint. Every endpoint is a plain HTTP/1.1 carrier (<see cref="BaseUri" /> names no host that is looked up).
/// </summary>
public abstract class LocalEndpoint
{
    /// <summary>The address requests are made to (routes are appended). Its host is one the service accepts as its own.</summary>
    public abstract Uri BaseUri { get; }

    /// <summary>For messages: where the service is expected, without any request content.</summary>
    public abstract string Describe();

    /// <summary>A connection handler that reaches this endpoint (no proxy, no redirects).</summary>
    public abstract SocketsHttpHandler CreateHandler();

    /// <summary>Makes the service listen here.</summary>
    internal abstract void Listen(KestrelServerOptions kestrel);

    /// <summary>The loopback TCP endpoint on <paramref name="port" />: 127.0.0.1 and, where the host has IPv6, [::1].</summary>
    public static LocalEndpoint Loopback(int port, bool ipv6 = true) => new LoopbackEndpoint(port, ipv6);
}

/// <summary>Plain HTTP on the loopback addresses. Any process of any user on this machine can connect: it is the transport this work replaces for the command line, and the one the browser administration still uses.</summary>
internal sealed class LoopbackEndpoint(int port, bool ipv6) : LocalEndpoint
{
    public int Port { get; } = port;

    public override Uri BaseUri { get; } = new("http://127.0.0.1:" + port.ToString(System.Globalization.CultureInfo.InvariantCulture) + "/");

    public override string Describe() => "port " + Port.ToString(System.Globalization.CultureInfo.InvariantCulture);

    public override SocketsHttpHandler CreateHandler() => new() { UseProxy = false, AllowAutoRedirect = false };

    internal override void Listen(KestrelServerOptions kestrel)
    {
        kestrel.Listen(IPAddress.Loopback, Port);
        if (ipv6)
        {
            kestrel.Listen(IPAddress.IPv6Loopback, Port);
        }
    }
}
