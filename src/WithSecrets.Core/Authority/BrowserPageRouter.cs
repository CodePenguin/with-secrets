namespace WithSecrets;

/// <summary>Mounts timed passkey ceremony pages on the same HTTPS listener, under their existing random-token paths.</summary>
internal sealed class BrowserPageRouter(int port)
{
    private readonly Lock _gate = new();
    private readonly List<OneShotServer> _flows = [];

    public int Port { get; } = port;

    public void Add(OneShotServer flow)
    {
        lock (_gate) _flows.Add(flow);
    }

    public void Remove(OneShotServer flow)
    {
        lock (_gate) _flows.Remove(flow);
    }

    public OneShotServer? Find(string path)
    {
        lock (_gate) return _flows.FirstOrDefault(flow => flow.HasPage(path));
    }
}
