using System.Security.Cryptography;

namespace WithSecrets;

public abstract record RetrievalOutcome;

/// <summary>A value that passed the core's checks: well-formed UTF-8 and not empty.</summary>
public sealed record RetrievalSuccess(byte[] Value) : RetrievalOutcome;

public sealed record RetrievalFailure(ProviderErrorKind Kind, string? ProviderCode) : RetrievalOutcome;

/// <summary>
/// Retrieves one provider instance's batch with the core's bounded retry policy (10.3.4): the whole batch is one invocation, then only the requests that failed
/// with a retryable kind are asked again (at most <see cref="ProviderPolicy.MaxAttempts" /> invocations), under one overall deadline. Caller cancellation is
/// rethrown; a deadline or provider timeout is <see cref="ProviderErrorKind.Unavailable" />. No message or outcome carries a secret value.
/// </summary>
public sealed class ProviderRetriever(Func<Guid, IProviderAdapter> adapters, TimeProvider clock, Func<TimeSpan, CancellationToken, Task> delay)
{
    public async Task<IReadOnlyDictionary<Guid, RetrievalOutcome>> RetrieveAsync(Guid instanceId, IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancel)
    {
        Dictionary<Guid, RetrievalOutcome> outcomes = [];
        try
        {
            await FillAsync(outcomes, instanceId, requests, cancel).ConfigureAwait(false);
        }
        catch
        {
            // Nobody receives the outcomes of a call that throws, so the values already retrieved are wiped.
            foreach (RetrievalSuccess success in outcomes.Values.OfType<RetrievalSuccess>())
            {
                CryptographicOperations.ZeroMemory(success.Value);
            }

            throw;
        }

        return outcomes;
    }

    private async Task FillAsync(Dictionary<Guid, RetrievalOutcome> outcomes, Guid instanceId, IReadOnlyList<ProviderSecretRequest> requests, CancellationToken cancel)
    {
        if (requests.Count == 0)
        {
            return;
        }

        using CancellationTokenSource deadline = new(ProviderPolicy.Deadline, clock);
        using CancellationTokenSource linked = CancellationTokenSource.CreateLinkedTokenSource(cancel, deadline.Token);

        List<ProviderSecretRequest> outstanding = [.. requests];
        for (int attempt = 1; outstanding.Count > 0; attempt++)
        {
            cancel.ThrowIfCancellationRequested();
            TimeSpan? retryAfter = null;
            try
            {
                IProviderAdapter adapter = adapters(instanceId);

                // WaitAsync abandons an adapter that ignores its token, so the deadline holds.
                Task<IReadOnlyList<ProviderSecretResult>> call = adapter.RetrieveSecretsAsync(outstanding, linked.Token);
                IReadOnlyList<ProviderSecretResult> results;
                try
                {
                    results = await call.WaitAsync(linked.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    WipeWhenDone(call);
                    throw;
                }

                try
                {
                    results = ProviderBatch.Validate(outstanding, results);
                    outstanding = Apply(outstanding, results, outcomes, out retryAfter);
                }
                catch (Exception failure) when (failure is not OperationCanceledException)
                {
                    WipeAll(results);
                    WipeOutcomes(outstanding, outcomes);
                    throw;
                }
            }
            catch (OperationCanceledException)
            {
                cancel.ThrowIfCancellationRequested();
                if (deadline.IsCancellationRequested)
                {
                    FailAll(outstanding, outcomes, ProviderErrorKind.Unavailable, null);

                    return;
                }

                // A provider-side timeout: a retryable Unavailable.
                outstanding = Retryable(outstanding, outcomes, ProviderErrorKind.Unavailable, null);
            }
            catch (ProviderAdapterException exception)
            {
                cancel.ThrowIfCancellationRequested();
                outstanding = Retryable(outstanding, outcomes, exception.Kind, exception.ProviderCode);
                retryAfter = exception.RetryAfter;
            }
            catch (Exception)
            {
                cancel.ThrowIfCancellationRequested();
                FailAll(outstanding, outcomes, ProviderErrorKind.Unknown, null);

                return;
            }

            if (outstanding.Count == 0)
            {
                break;
            }

            if (attempt >= ProviderPolicy.MaxAttempts)
            {
                break;
            }

            TimeSpan wait = ProviderPolicy.Backoff[attempt - 1];
            if (retryAfter is { } hint)
            {
                TimeSpan honored = hint > ProviderPolicy.RetryAfterCap ? ProviderPolicy.RetryAfterCap : hint;
                if (honored > wait)
                {
                    wait = honored;
                }
            }

            try
            {
                await delay(wait, linked.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                cancel.ThrowIfCancellationRequested();
                FailAll(outstanding, outcomes, ProviderErrorKind.Unavailable, null);

                return;
            }
        }
    }

    // Records the item results; returns the requests that failed with a retryable kind (their failure stays recorded as the last outcome).
    private static List<ProviderSecretRequest> Apply(
        List<ProviderSecretRequest> outstanding,
        IReadOnlyList<ProviderSecretResult> results,
        Dictionary<Guid, RetrievalOutcome> outcomes,
        out TimeSpan? retryAfter)
    {
        List<ProviderSecretRequest> again = [];
        retryAfter = null;
        for (int index = 0; index < outstanding.Count; index++)
        {
            ProviderSecretRequest request = outstanding[index];
            ProviderSecretResult result = results[index];
            if (result.Secret is { } secret)
            {
                // The core keeps its own copy; the adapter's array is wiped as soon as it has been copied.
                byte[] owned = [.. secret.Value];
                CryptographicOperations.ZeroMemory(secret.Value);
                outcomes[request.RequestId] = Judge(owned);

                continue;
            }

            ProviderErrorKind kind = result.ErrorKind!.Value;
            outcomes[request.RequestId] = new RetrievalFailure(kind, result.ProviderCode);
            if (ProviderPolicy.IsRetryable(kind))
            {
                again.Add(request);
                if (result.RetryAfter is { } hint && (retryAfter is null || hint > retryAfter))
                {
                    retryAfter = hint;
                }
            }
        }

        return again;
    }

    private static void WipeWhenDone(Task<IReadOnlyList<ProviderSecretResult>> call)
    {
        if (call.IsCompletedSuccessfully)
        {
            WipeAll(call.Result);

            return;
        }

        _ = call.ContinueWith(done =>
        {
            if (done.IsCompletedSuccessfully)
            {
                WipeAll(done.Result);
            }
            else
            {
                _ = done.Exception;
            }
        }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private static void WipeOutcomes(List<ProviderSecretRequest> outstanding, Dictionary<Guid, RetrievalOutcome> outcomes)
    {
        foreach (ProviderSecretRequest request in outstanding)
        {
            if (outcomes.Remove(request.RequestId, out RetrievalOutcome? outcome) && outcome is RetrievalSuccess success)
            {
                CryptographicOperations.ZeroMemory(success.Value);
            }
        }
    }

    private static void WipeAll(IReadOnlyList<ProviderSecretResult>? results)
    {
        if (results is null)
        {
            return;
        }

        foreach (ProviderSecretResult result in results)
        {
            if (result?.Secret?.Value is { } value)
            {
                CryptographicOperations.ZeroMemory(value);
            }
        }
    }

    private static RetrievalOutcome Judge(byte[] value)
    {
        if (value.Length == 0)
        {
            return new RetrievalFailure(ProviderErrorKind.SecretNotFound, null);
        }

        if (ProviderBatch.IsStrictUtf8(value))
        {
            return new RetrievalSuccess(value);
        }

        CryptographicOperations.ZeroMemory(value);

        return new RetrievalFailure(ProviderErrorKind.InvalidResponse, null);
    }

    private static List<ProviderSecretRequest> Retryable(
        List<ProviderSecretRequest> outstanding,
        Dictionary<Guid, RetrievalOutcome> outcomes,
        ProviderErrorKind kind,
        string? providerCode)
    {
        FailAll(outstanding, outcomes, kind, providerCode);

        return ProviderPolicy.IsRetryable(kind) ? outstanding : [];
    }

    private static void FailAll(List<ProviderSecretRequest> outstanding, Dictionary<Guid, RetrievalOutcome> outcomes, ProviderErrorKind kind, string? providerCode)
    {
        foreach (ProviderSecretRequest request in outstanding)
        {
            outcomes[request.RequestId] = new RetrievalFailure(kind, providerCode);
        }
    }
}
