namespace ArcanaGuardian;

/// <summary>How a mounted value was obtained for one request (10.3.3): from the provider now, from the cache within normal freshness, stale under the outage allowance, or not at all.</summary>
public enum RetrievalOutcomeKind
{
    Fresh,
    Cached,
    Stale,
    Failed,
}

/// <summary>One mounted name's retrieval outcome: the logical path and the selected provider instance. Never a value, credential, ciphertext or external id.</summary>
public sealed record ProviderAudit(string Path, Guid InstanceId, string InstanceName, RetrievalOutcomeKind Outcome, ProviderErrorKind? ErrorKind)
{
    /// <summary>
    /// The signed audit event: type <see cref="AuditEventTypes.Admin" /> (the type of the service's events that are not a run's own), outcome <c>provider-fresh</c>,
    /// <c>provider-cached</c>, <c>provider-stale</c> or <c>provider-failed</c>, the path as the argument, and metadata <c>path</c>, <c>instance</c> (id),
    /// <c>instanceName</c>, <c>outcome</c> and, when there is one, <c>errorKind</c>. Names only.
    /// </summary>
    public AuditFacts ToFacts()
    {
        Dictionary<string, string> metadata = new(StringComparer.Ordinal) { ["path"] = Path, ["instance"] = InstanceId.ToString("D"), ["instanceName"] = InstanceName, ["outcome"] = Outcome.ToString() };
        if (ErrorKind is { } kind)
        {
            metadata["errorKind"] = kind.ToString();
        }

        string reason = Path + " from " + (InstanceName.Length > 0 ? InstanceName : InstanceId.ToString("D")) + (ErrorKind is { } why ? " (" + why + ")" : "");

        return new AuditFacts(AuditEventTypes.Admin, "provider-" + Outcome.ToString().ToLowerInvariant(), reason, "", "", "", [Path], Metadata: metadata);
    }
}

/// <summary>
/// The run's secret source: the native <see cref="SecretStore" /> plus every mounted secret (10.3). A name that a mount selects (ruling 2, mount over native) is
/// served by that mount's namespace entry and nothing else; any other name goes to the native store unchanged. For mounted names, per provider instance: cache rows
/// that verify and are younger than 75% of MaxStaleDuration are decrypted with the store key an administrator's unlock opened (<see cref="RetrievalOutcomeKind.Cached" />);
/// every other DISTINCT external id is requested in ONE retrieval batch for that instance; a success is cached (when caching is enabled, the store has a key, and the authority is
/// unlocked) and delivered (<see cref="RetrievalOutcomeKind.Fresh" />); a final Unavailable or RateLimited may be answered from the row read before the retrieval,
/// re-verified, while within MaxStaleDuration (<see cref="RetrievalOutcomeKind.Stale" />); anything else fails the whole call. When the instance generation moved
/// while its batch was in flight (an invalidation), the batch's results are discarded and the call fails closed. Every returned array belongs to the
/// returned <see cref="SecretValues" />; everything decrypted or retrieved on the way is zeroed, on success and on failure. Everything the call decrypts (native rows and
/// cache rows) is decrypted after the retrievals, in one use of the store key inside the authority's lock (<see cref="SecretStore.WithStoreKey" />). While the authority is
/// locked a call that names any mounted secret fails closed before anything is read or retrieved, and a lock that begins during the call fails it at that decryption
/// (it also stops the fresh values being cached). A cache write that fails for any other reason fails the call.
/// <para>
/// Audit: the records of one call are built in full and handed to <paramref name="audit" /> ONCE, after the outcome is known, so a sink that cannot commit leaves
/// no record of values that were then zeroed (the call fails). A failed call records every mounted name as Failed: those whose retrieval failed with their kind,
/// those that succeeded but are held back with none, and a name a mount selects that is not available.
/// </para>
/// </summary>
public sealed class ProviderSecretSource(
    SecretStore native,
    ProviderStore providers,
    ProviderRetriever retriever,
    ProviderCache cache,
    ProviderInvalidation invalidation,
    TimeProvider clock,
    Action<IReadOnlyList<ProviderAudit>> audit,
    Func<string, bool>? interactive = null) : ISecretSource
{
    private sealed record Selected(string Name, ProviderInstance Instance, NamespaceEntry Entry);

    /// <summary>
    /// What one external id of one instance came to: its value (owned by the caller's zeroing list), the verified cache row it is to be decrypted from (cached or stale; decrypted
    /// once, after every retrieval, in the one use of the store key), or why not.
    /// </summary>
    private sealed record Obtained(RetrievalOutcomeKind Outcome, byte[]? Value, ProviderErrorKind? ErrorKind, bool Invalidated = false, CachedSecret? Row = null);

    public string Label => native.Label;

    /// <summary>A mounted name's provider instance name (the instance id when the instance row is gone: the call then fails closed); any other name is native.</summary>
    public string LabelFor(string name)
    {
        if (!SecretNames.IsValid(name) || MountResolver.Resolve(providers.Mounts(), name) is not { } mount)
        {
            return native.Label;
        }

        return providers.Instance(mount.InstanceId)?.Name ?? mount.InstanceId.ToString("D");
    }

    /// <summary>For tests: receives every intermediate buffer after it was zeroed (and, on failure, the arrays that would have been returned).</summary>
    internal Action<IReadOnlyList<byte[]>>? Discarded { get; set; }

    /// <summary>For tests: runs after an instance group's resolution and cache reads, before its retrieval and its generation checks.</summary>
    internal Action? AfterReads { get; set; }

    public IReadOnlyList<string> ListNames()
    {
        return [.. native.ListNames().Concat(providers.Entries().Select(entry => entry.LogicalPath)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)];
    }

    public SecretValues GetValues(IReadOnlyCollection<string> names)
    {
        if (names.Any(name => !SecretNames.IsValid(name)) || names.Distinct(StringComparer.Ordinal).Count() != names.Count)
        {
            throw new SecretStoreException("the secret names are not valid");
        }

        // The generation baseline is taken BEFORE resolution: a reconcile, invalidation or mount removal after this point discards that instance's results.
        IReadOnlyDictionary<Guid, long> generations = providers.Generations();

        // Resolution happens once, before anything is decrypted or retrieved; a selected name never falls through.
        (List<string> nativeNames, List<Selected> mounted, List<ProviderAudit> unavailable) = Resolve(names);

        List<byte[]> owned = [];
        Dictionary<string, byte[]> result = new(StringComparer.Ordinal);
        Dictionary<(Guid, string), Obtained>? obtained = null;
        bool delivered = false;
        bool audited = false;
        VerifiedCredential? openedBy = null;
        try
        {
            if (unavailable.Count > 0)
            {
                // A name a mount selected has no entry or no instance: a hard error (no fall-through), before anything is decrypted or retrieved.
                throw new SecretStoreException(string.Join("; ", unavailable.Select(item => item.Path + " is not available")));
            }

            if (mounted.Count > 0 && cache.IsLocked)
            {
                // Locked: nothing is served from the cache, signed or retrieved for a mounted name (10.2), so the call fails closed before any read.
                throw new SecretStoreException("the authority is locked, so no mounted secret is delivered");
            }

            // The native rows are read now and decrypted only with the store key below; their manifest is the one the key is checked against.
            (Manifest? manifest, Dictionary<string, string> nativeRows) = nativeNames.Count > 0 ? native.ReadRows(nativeNames) : (native.Current().Manifest, new Dictionary<string, string>(StringComparer.Ordinal));
            string storeKey = manifest?.Store ?? "";
            if (mounted.Count > 0 && (storeKey.Length > 0 || nativeRows.Count > 0))
            {
                // Nothing is retrieved for a call the store key could not finish.
                native.EnsureStoreKey(manifest);
            }

            Dictionary<(Guid, string), Obtained> all = obtained = mounted.Count > 0 ? Task.Run(() => ObtainAsync(mounted, generations, storeKey, owned)).GetAwaiter().GetResult() : [];
            List<Selected> failed = [.. mounted.Where(item => all[Key(item)].Outcome == RetrievalOutcomeKind.Failed)];
            if (failed.Count > 0)
            {
                throw new SecretStoreException(string.Join("; ", failed.Select(item => Describe(item, all[Key(item)]))));
            }

            // The values are assembled inside the authority's lock, with one use of the store key for the native rows and every cached row (a store with a key needs it open and current); with no store key nothing is decrypted, but a lock that began during the retrievals still delivers nothing.
            bool Assemble(string? privateKey)
            {
                Dictionary<(Guid, string), byte[]> opened = [];
                if (privateKey is not null)
                {
                    foreach ((string name, byte[] value) in native.DecryptRows(privateKey, nativeRows))
                    {
                        result[name] = value;
                    }

                    foreach (((Guid, string) key, Obtained item) in all.Where(pair => pair.Value.Row is not null))
                    {
                        byte[] value = cache.Decrypt(item.Row!, privateKey);
                        owned.Add(value);
                        opened[key] = value;
                    }
                }

                foreach (Selected item in mounted)
                {
                    result[item.Name] = [.. all[Key(item)].Value ?? opened[Key(item)]];
                }

                return true;
            }

            if (nativeRows.Count > 0 || storeKey.Length > 0 || all.Values.Any(item => item.Row is not null))
            {
                native.WithStoreKey(manifest, privateKey =>
                {
                    openedBy = native.OpenedBy;
                    return Assemble(privateKey);
                });
            }
            else
            {
                native.WhileUnlocked(() =>
                {
                    openedBy = native.OpenedBy;
                    return Assemble(null);
                });
            }

            if (mounted.Count > 0)
            {
                // One step, after the outcome is known: a sink that throws fails the call, and every value is zeroed below.
                audited = true;
                audit([.. mounted.Select(item => Record(item, all[Key(item)].Outcome, all[Key(item)].ErrorKind))]);
            }

            delivered = true;

            return new SecretValues(result) { OpenedBy = openedBy };
        }
        catch when ((mounted.Count > 0 || unavailable.Count > 0) && !audited)
        {
            // Nothing is delivered: every mounted name is Failed (a held-back success, a name never retrieved or one not available, with no kind), in one step.
            audited = true;
            audit([.. mounted.Select(item => Record(item, RetrievalOutcomeKind.Failed, obtained?.GetValueOrDefault(Key(item)) is { Outcome: RetrievalOutcomeKind.Failed } failure ? failure.ErrorKind : null)), .. unavailable]);

            throw;
        }
        finally
        {
            List<byte[]> zeroed = [.. owned];
            if (!delivered)
            {
                zeroed.AddRange(result.Values);
            }

            foreach (byte[] buffer in zeroed)
            {
                SecretValues.Clear(buffer);
            }

            Discarded?.Invoke(zeroed);
        }
    }

    private static (Guid, string) Key(Selected item) => (item.Instance.Id, item.Entry.ExternalId);

    private static ProviderAudit Record(Selected item, RetrievalOutcomeKind outcome, ProviderErrorKind? kind) => new(item.Name, item.Instance.Id, item.Instance.Name, outcome, kind);

    private static string Describe(Selected item, Obtained outcome)
    {
        return outcome.Invalidated
            ? item.Name + " was invalidated while it was being retrieved" + (outcome.ErrorKind is { } why ? " (" + why + ")" : "")
            : item.Name + " could not be retrieved from its provider (" + (outcome.ErrorKind ?? ProviderErrorKind.Unknown) + ")";
    }

    /// <summary>Native names, mounted names with their entry and instance, and the Failed records of names a mount selects that are not available (no entry, or the instance row is gone).</summary>
    private (List<string> Native, List<Selected> Mounted, List<ProviderAudit> Unavailable) Resolve(IReadOnlyCollection<string> names)
    {
        IReadOnlyList<Mount> mounts = providers.Mounts();
        Dictionary<Guid, IReadOnlyList<NamespaceEntry>> entries = [];
        Dictionary<Guid, ProviderInstance?> instances = [];
        List<string> nativeNames = [];
        List<Selected> mounted = [];
        List<ProviderAudit> unavailable = [];
        foreach (string name in names)
        {
            if (MountResolver.Resolve(mounts, name) is not { } mount)
            {
                nativeNames.Add(name);
                continue;
            }

            if (!entries.TryGetValue(mount.Id, out IReadOnlyList<NamespaceEntry>? ofMount))
            {
                entries[mount.Id] = ofMount = providers.Entries(mount.Id);
            }

            if (!instances.TryGetValue(mount.InstanceId, out ProviderInstance? instance))
            {
                instances[mount.InstanceId] = instance = providers.Instance(mount.InstanceId);
            }

            NamespaceEntry? entry = ofMount.FirstOrDefault(item => string.Equals(item.LogicalPath, name, StringComparison.Ordinal));
            if (entry is null || instance is null)
            {
                // The mount selected the name: audited Failed against the selected instance; the call fails before anything is retrieved.
                unavailable.Add(new ProviderAudit(name, mount.InstanceId, instance?.Name ?? "", RetrievalOutcomeKind.Failed, null));

                continue;
            }

            mounted.Add(new Selected(name, instance, entry));
        }

        return (nativeNames, mounted, unavailable);
    }

    /// <summary>
    /// Every (instance, external id) of <paramref name="mounted" />, one instance at a time, each with at most one retrieval batch. Every buffer made is added to <paramref name="owned" />.
    /// A value served from the cache is its verified row, decrypted later by the caller (nothing is decrypted here).
    /// </summary>
    private async Task<Dictionary<(Guid, string), Obtained>> ObtainAsync(List<Selected> mounted, IReadOnlyDictionary<Guid, long> generations, string storeKey, List<byte[]> owned)
    {
        Dictionary<(Guid, string), Obtained> obtained = [];
        foreach (IGrouping<Guid, Selected> group in mounted.GroupBy(item => item.Instance.Id))
        {
            ProviderInstance instance = group.First().Instance;
            long generation = generations.GetValueOrDefault(instance.Id);
            if (invalidation.Generation(instance.Id) != generation)
            {
                // Something of this instance changed after resolution: nothing is read or retrieved for it.
                Discard(group, obtained);
                continue;
            }

            DateTimeOffset started = clock.GetUtcNow();
            bool cacheEnabled = instance.MaxStale > TimeSpan.Zero;
            bool interactiveOnly = interactive?.Invoke(instance.ProviderType) == true;

            Dictionary<string, Obtained> byExternal = new(StringComparer.Ordinal);
            Dictionary<string, CachedSecret?> before = new(StringComparer.Ordinal);
            List<(string ExternalId, ProviderSecretRequest Request)> requests = [];
            foreach (IGrouping<string, Selected> same in group.GroupBy(item => item.Entry.ExternalId, StringComparer.Ordinal))
            {
                CachedSecret? row = cacheEnabled ? cache.TryGet(instance.Id, same.Key, storeKey) : null;
                if (row is not null && Age(started, row) is { } age && (interactiveOnly
                    ? ProviderPolicy.WithinStaleWindow(age, instance.MaxStale) : ProviderPolicy.IsFreshEnough(age, instance.MaxStale)))
                {
                    byExternal[same.Key] = new Obtained(RetrievalOutcomeKind.Cached, null, null, Row: row);
                    continue;
                }

                if (interactiveOnly)
                {
                    byExternal[same.Key] = new Obtained(RetrievalOutcomeKind.Failed, null, ProviderErrorKind.InteractionRequired);
                    continue;
                }

                before[same.Key] = row;
                requests.Add((same.Key, new ProviderSecretRequest(Guid.NewGuid(), same.First().Entry.ProviderPath)));
            }

            AfterReads?.Invoke();

            if (requests.Count > 0)
            {
                IReadOnlyDictionary<Guid, RetrievalOutcome> outcomes = await retriever.RetrieveAsync(instance.Id, [.. requests.Select(item => item.Request)], CancellationToken.None).ConfigureAwait(false);
                List<(string ExternalId, byte[] Value)> fresh = [];
                foreach ((string externalId, ProviderSecretRequest request) in requests)
                {
                    if (outcomes.GetValueOrDefault(request.RequestId) is RetrievalSuccess success)
                    {
                        owned.Add(success.Value);
                        fresh.Add((externalId, success.Value));
                    }
                }

                bool current = invalidation.Generation(instance.Id) == generation;
                if (current && cacheEnabled && fresh.Count > 0 && storeKey.Length > 0)
                {
                    try
                    {
                        // Superseded (a newer retrieval already wrote a row) still delivers this retrieval's own value; only Invalidated discards.
                        current = cache.PutAll(instance.Id, fresh, started, storeKey, generation) != CacheWrite.Invalidated;
                    }
                    catch (AuthorityLockedException)
                    {
                        // Nothing is signed while locked: the fresh value is delivered, not persisted.
                    }
                }

                if (!current)
                {
                    // Raced an invalidation (possibly the adapter's own, for a secret it found removed): keep what each request failed with.
                    Dictionary<string, ProviderErrorKind> kinds = new(StringComparer.Ordinal);
                    foreach ((string externalId, ProviderSecretRequest request) in requests)
                    {
                        if (outcomes.GetValueOrDefault(request.RequestId) is RetrievalFailure failure)
                        {
                            kinds[externalId] = failure.Kind;
                        }
                    }

                    Discard(group, obtained, kinds);
                    continue;
                }

                foreach ((string externalId, byte[] value) in fresh)
                {
                    byExternal[externalId] = new Obtained(RetrievalOutcomeKind.Fresh, value, null);
                }

                DateTimeOffset now = clock.GetUtcNow();
                foreach ((string externalId, ProviderSecretRequest request) in requests)
                {
                    if (byExternal.ContainsKey(externalId))
                    {
                        continue;
                    }

                    ProviderErrorKind kind = outcomes.GetValueOrDefault(request.RequestId) is RetrievalFailure failure ? failure.Kind : ProviderErrorKind.Unknown;
                    byExternal[externalId] = Stale(instance, externalId, before[externalId], kind, now, storeKey) ?? new Obtained(RetrievalOutcomeKind.Failed, null, kind);
                }
            }

            // Invalidation takes precedence over work in progress, cache reads included.
            if (invalidation.Generation(instance.Id) != generation)
            {
                Discard(group, obtained);
                continue;
            }

            foreach (Selected item in group)
            {
                obtained[Key(item)] = byExternal[item.Entry.ExternalId];
            }
        }

        // A later provider batch can overlap an invalidation of an instance that already finished.
        IReadOnlyDictionary<Guid, long> currentGenerations = providers.Generations();
        foreach (Selected item in mounted)
        {
            (Guid instanceId, string externalId) = Key(item);
            if (currentGenerations.GetValueOrDefault(instanceId) != generations.GetValueOrDefault(instanceId)
                && obtained[(instanceId, externalId)].Outcome != RetrievalOutcomeKind.Failed)
            {
                obtained[(instanceId, externalId)] = new Obtained(RetrievalOutcomeKind.Failed, null, null, Invalidated: true);
            }
        }

        return obtained;
    }

    /// <summary>The row read before the retrieval, served stale only for a final Unavailable/RateLimited, within MaxStaleDuration, and when it still verifies unchanged now.</summary>
    private Obtained? Stale(ProviderInstance instance, string externalId, CachedSecret? before, ProviderErrorKind kind, DateTimeOffset now, string storeKey)
    {
        if (!ProviderPolicy.StaleEligible(kind) || before is null || Age(now, before) is not { } age || !ProviderPolicy.WithinStaleWindow(age, instance.MaxStale))
        {
            return null;
        }

        CachedSecret? again = cache.TryGet(instance.Id, externalId, storeKey);

        return again is not null && again == before ? new Obtained(RetrievalOutcomeKind.Stale, null, kind, Row: again) : null;
    }

    private static void Discard(IGrouping<Guid, Selected> group, Dictionary<(Guid, string), Obtained> obtained, IReadOnlyDictionary<string, ProviderErrorKind>? kinds = null)
    {
        foreach (Selected item in group)
        {
            ProviderErrorKind? kind = kinds is not null && kinds.TryGetValue(item.Entry.ExternalId, out ProviderErrorKind known) ? known : null;
            obtained[Key(item)] = new Obtained(RetrievalOutcomeKind.Failed, null, kind, Invalidated: true);
        }
    }

    /// <summary>The age of a row at <paramref name="now" />; null when its lastVerified lies in the future (a clock that went back): such a row is neither fresh nor stale-servable.</summary>
    private static TimeSpan? Age(DateTimeOffset now, CachedSecret row)
    {
        TimeSpan age = now - row.LastVerified;

        return age < TimeSpan.Zero ? null : age;
    }
}
