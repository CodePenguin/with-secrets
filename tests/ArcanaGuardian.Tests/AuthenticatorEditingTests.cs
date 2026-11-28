using System.Buffers.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;

namespace ArcanaGuardian.Tests;

internal static class AuthenticatorEditingTests
{
    internal static async Task Run(Action<bool, string> check)
    {
        check(AuthenticatorCode.ForStep("12345678901234567890"u8, 1) == "287082"
            && AuthenticatorCode.SetupKey("12345678901234567890"u8) == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "authenticator app: the six-digit RFC test vector and Base32 setup key match");

        string root = Directory.CreateTempSubdirectory("ws-authenticator-editing-").FullName;
        try
        {
            using AdminApp app = new(root);
            using Unlock release = TestVault.Unlock(app.State, app.Laptop)!;
            if (!app.State.TryManifest(out Manifest? manifest, out _) || !app.Service.Keys!.TryOpen(manifest!, release))
                throw new InvalidOperationException("could not open the test authority keys");

            AdminBrowser browser = await app.SignedIn();
            AdminBrowser other = await app.SignedIn();
            AdminBrowser anonymous = app.Browser();
            await anonymous.LoadAsync();

            const string start = "/api/v1/authorizations/inline";
            const string resume = "/api/v1/session/resume/authenticator";
            const string list = "/api/v1/access-credentials/authenticators";

            async Task<string> Authorize(string op, object parameters)
            {
                (int started, string initial) = await browser.PostAsync(start, JsonSerializer.Serialize(new { operation = op, parameters }));
                if (started != 201) throw new InvalidOperationException("the authenticator operation could not be prepared");
                using JsonDocument challenge = JsonDocument.Parse(initial);
                string id = challenge.RootElement.GetProperty("id").GetString()!;
                using JsonDocument proof = JsonDocument.Parse(challenge.RootElement.GetProperty("proof").GetProperty("payload").GetString()!);
                string assertion = app.Laptop.Assert(Base64Url.DecodeFromChars(proof.RootElement.GetProperty("bind").GetString()!), browser.Origin,
                    proof.RootElement.GetProperty("rpId").GetString()!, TestState.NextCount());
                (int accepted, _) = await browser.PostAsync("/api/v1/authorizations/" + id + "/proof", JsonSerializer.Serialize(new { proof = assertion }));
                if (accepted != 200) throw new InvalidOperationException("the authenticator operation proof was refused");
                return "/api/v1/authorizations/" + id + "?collect=authenticator-setup";
            }

            async Task<int> Lock(AdminBrowser owner) => (await owner.PostAsync(start, """{"operation":"session-lock-editing","applyFromSession":true}""")).Status;
            async Task<int> Code(AdminBrowser owner, string id, string code) => (await owner.PostAsync(resume, JsonSerializer.Serialize(new { id, code }))).Status;

            string setupPath = await Authorize("authenticator-add", new { name = "Phone app" });
            check((await other.GetAsync(setupPath)).Status == 404, "authenticator app: another browser cannot collect the setup key");
            (_, string initialSetup, _) = await browser.GetAsync(setupPath);
            using JsonDocument setup = JsonDocument.Parse(initialSetup);
            string setupKey = setup.RootElement.GetProperty("result").GetProperty("authenticatorSetup").GetProperty("setupKey").GetString()!;
            check(!(await browser.GetAsync(setupPath)).Html.Contains(setupKey, StringComparison.Ordinal),
                "authenticator app: the setup key can be collected only once");

            string otherPath = await Authorize("authenticator-add", new { name = "Backup app" });
            await browser.GetAsync(otherPath);
            (_, string rows, _) = await anonymous.GetAsync(list);
            using JsonDocument available = JsonDocument.Parse(rows);
            JsonElement.ArrayEnumerator items = available.RootElement.GetProperty("items").EnumerateArray();
            string id = items.Single(item => item.GetProperty("name").GetString() == "Phone app").GetProperty("id").GetString()!;
            check(items.Count() == 2 && !rows.Contains(setupKey, StringComparison.Ordinal)
                && app.Store.Authenticator(id) is { } record && !record.SealedSeed.Contains(setupKey, StringComparison.Ordinal)
                && !string.Join('\n', app.Store.Audit().Select(item => item.Detail)).Contains(setupKey, StringComparison.Ordinal),
                "authenticator app: multiple apps are supported and setup keys stay out of metadata, audit and plaintext storage");

            long step = app.Clock.GetUtcNow().ToUnixTimeSeconds() / 30;
            string current = AuthenticatorCode.ForStep(DecodeSetupKey(setupKey), step);
            check(await Code(anonymous, id, current) == 401 && await Code(browser, id, current) == 409,
                "authenticator app: codes neither start a session nor apply to active editing");
            check(await Lock(browser) == 201 && await Code(browser, id, current) == 200
                && (await browser.GetAsync("/api/v1/session")).Html.Contains("\"identity\":\"laptop\"", StringComparison.Ordinal),
                "authenticator app: a current code resumes editing under the existing admin identity");
            check(await Lock(other) == 201 && await Code(other, id, current) == 403 && app.Store.Authenticator(id)?.LastStep == step,
                "authenticator app: a used code is refused in a different locked session and its time step is persisted");

            string removed = await Authorize("authenticator-remove", new { id });
            check((await browser.GetAsync(removed)).Html.Contains("\"outcome\":\"applied\"", StringComparison.Ordinal) && app.Store.Authenticator(id) is null,
                "authenticator app: an admin passkey can remove an enrolled app");
            check(await Code(other, id, AuthenticatorCode.ForStep(DecodeSetupKey(setupKey), step + 1)) == 403,
                "authenticator app: a removed app cannot resume editing");
            await Code(other, id, "000000");
            await Code(other, id, "000000");
            check(await Code(other, id, "000000") == 429, "authenticator app: attempts are limited across all admin sessions");
            app.Service.Lock.Lock("test authority lock");
            await other.GetAsync("/api/v1/session");
            check(await Code(other, id, current) == 401 && app.Service.Lock.IsLocked, "authenticator app: an authority lock ends the session and cannot be undone with a code");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(root, true);
        }
    }

    private static byte[] DecodeSetupKey(string setupKey)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        byte[] seed = new byte[setupKey.Length * 5 / 8];
        int buffer = 0;
        int bits = 0;
        int offset = 0;
        foreach (char character in setupKey)
        {
            buffer = (buffer << 5) | alphabet.IndexOf(character, StringComparison.Ordinal);
            bits += 5;
            if (bits < 8) continue;
            bits -= 8;
            seed[offset++] = (byte)(buffer >> bits);
        }
        return seed;
    }
}
