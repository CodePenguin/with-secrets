# UX audit: admin web app (read-only)

Scope: worktree `with-secrets-impl`, branch `impl/mtls-pairing`. Sources read: `src/WithSecrets.Admin.Web/src` (App, Shell, Gate, SignInPage, Overview, Machines, Pairing, Grants, Settings, Passkeys, OperationDialog, operations.ts), `WebApprover.cs` (the service-served passkey / approval page), `ApprovalSummary.cs`, `Reuse.cs`, `SecretEntry.cs` and `SettingsPage.cs` (headers), `docs/architecture.md` 10.5, `tests/WithSecrets.E2E/ScenariosSpa.cs`, `ScenariosPairing.cs`, `SpaHarness.cs`, the Vitest files (titles). Nothing was built, run or modified.

Counting rules: "click" = a deliberate press on this page or the passkey page; "load" = a full page load (the SPA's own route changes are not loads); "tap" = a passkey user-verification gesture; "switch" = moving between the SPA tab and the passkey tab (manual on a phone). Counts are from the code and the E2E click paths, not from a stopwatch.

## 1. How an admin change works today (the common chain)

Every admin mutation, wherever it starts, runs the same chain (`OperationDialog.tsx`):

1. Click the row action (opens a modal dialog).
2. If the operation has fields: type, click **Review**. (Operations without fields start on the review step.)
3. Click **Ask for passkey authorization** (creates a pending authorization; changes nothing).
4. Click **Open the passkey page (new tab)** (loads the service page; the dialog now shows the same sentence again).
5. On the passkey page: wait for the 2 s click-through delay (`DefaultApproveDelay`), click **Approve once** (the label is the run-approval wording even for admin operations), then the tap.
6. Switch back to the SPA tab. It polls every 1 s, sees `verified`, performs the mutation with the authorization id, shows **Done**.
7. Click **Close**. Manually close the passkey tab (the E2E test closes it itself).

So the floor for the simplest change is 5 clicks + 1 tap + 1 extra page load + 2 tab switches, and the same facts are rendered 3 or 4 times (list row, review, waiting view with the signed sentence, passkey page).

Not a security rule but important to the phone: the tap result only reaches the SPA through that polling tab. The authorization id and the prepared operation live only in React state (`OperationProvider`). If the browser discards or reloads the SPA tab while the person is on the passkey tab (normal on iOS and on low-memory Android), the tap is spent, nothing is applied, and nothing tells the person. The session survives a reload (sessionStorage, see 6.4) but the dialog does not.

## 2. Flow 1: sign in and unlock

Cold start, authority unlocked, no session:

| Task | Current | Proposed | Security cost | Effort |
| --- | --- | --- | --- | --- |
| Sign in | Load `/admin` (1 load). Click **Sign in** (1). Click **Open the passkey page (new tab)** (2). Passkey page load (2nd load), wait 2 s, click **Approve once** (3), tap (1). Switch back (SPA polls and shows Overview). Totals: 3 clicks, 1 tap, 2 loads, 2 switches. The passkey tab is left open. | **Sign in** does the POST and then navigates the same tab to the passkey page (no separate "Open" link, no new tab). The service chooses the return address (`/admin`, fixed server-side, never taken from the query) and the passkey page shows the existing `follow`/Continue step to return. Totals: 2 clicks, 1 tap, same loads, 0 switches. | None to the rules: still one UV tap, the session is still read-only, the login code is still bound on the passkey page. The return URL must be server-fixed so it cannot be an open redirect. Needs the SPA to cope with a full navigation (it already restores the session from sessionStorage and the cookie). | M |
| Sign in, locked authority | Sign-in view shows state and an **Unlock the authority** button. Unlock: click (1), **Ask** (2), **Open** (3), page load, **Approve once** (4), tap, switch, **Close** (5). Then **Sign in** (6), **Open** (7), **Approve once** (8), tap. Totals: 8 clicks, 2 taps, 3 loads, 4 switches. The unlock does not sign you in (E2E `LockUnlock` clicks Sign in again). | One flow, "Unlock and sign in", one tap. The unlock authorization's tap also starts the read-only session. Totals: 2 clicks, 1 tap. | Needs an architecture amendment, see 2.1 wording. The session grants no mutation authority and a sign-in already requires a UV tap, so no authority is added. It does bind one assertion to two outcomes, which 10.5 does not currently describe. | M (needs the amendment first) |
| Lock, later come back | Lock is a danger button on Overview (click, Ask, Open, Approve, tap, Close = 5 clicks, 1 tap) and ends every session. Returning needs Unlock + Sign in (see above): in total 13 clicks and 3 taps for a lock-and-resume. | Same merged flow as above on the way back: Lock stays 1 tap, resume is 1 tap. | Same as above. | M |
| Idle session expiry (default 15 min idle, 8 h absolute, `AuthorityStore.Settings`) | After 15 min without use a read returns 401, `Gate` replaces the view with the sign-in (same address, good), then the whole sign-in chain again. Mid-dialog expiry also wastes the tap (the mutation is refused 401 and the authorization is consumed even when refused). | Raise the default idle to 60 min (maximum is already 120). The administrator can already set it; only the default changes. Better: in-page "keep alive" while a tab is visible. | Longer-lived read-only session. The browser session is read-only by 10.5, so the exposure is metadata reading by whoever holds the tab. A UI/config choice, no rule changes. | S |
| Sign-in error handling | `failed` shows an alert and **Start the sign-in again**. If the link is not loopback, `safeLink` returns null and the sign-in just shows the old button (no explanation). | Show "the service gave a passkey link that this page will not open" with the address it refused. | None. | S |

### 2.1 Proposed 10.5 amendment (for the maintainer to accept or reject)

Add under "Read-only browser session and per-operation administration authorization":

> A passkey authorization for `unlock`, when the administrator asks for it on the same passkey page, may also start the read-only browser session for that same assertion. The page names both outcomes before the tap. The session still cannot authorize any change, and no other operation's authorization may start a session.

Alternative with no amendment: leave unlock and sign-in as two taps but make the second follow the first automatically (same tab, no extra clicks): 2 + 2 clicks, 2 taps. Saves the clicks but not the tap.

## 3. Flow 2: approve a machine and pairing

Signed in, to bring one new machine from nothing to Trusted (E2E `PairMachine`):

| Task | Current | Proposed | Security cost | Effort |
| --- | --- | --- | --- | --- |
| Create invitation | **Pairing** nav (1), **Create an invitation** (2), **Ask** (3), **Open** (4), page load, **Approve once** (5), tap, switch, **Copy the invitation** (6), **Close** (7). 7 clicks, 1 tap, 1 load, 2 switches. Bundle exists only in dialog state: if the tab is discarded after the tap, the invitation is created (or not) and the bundle is lost. | Header action **Add a machine** on the Machines view (Pairing folded in, see 3.2). Click (1) opens the dialog already on the authorization step with the sentence and a **Continue to passkey** button (2), same-tab passkey page, **Approve** (3), tap, return. The bundle is shown on the passkey page's final step (the page already shows recovery codes once the same way) with Copy, and the SPA lists the invitation by status. 3 clicks + Copy, 1 tap, 0 switches. | The sentence the passkey signs and the tap stay. Showing the bundle on the service-served page instead of the SPA is arguably tighter (the SPA never holds it). Needs the service to apply on tap (see 6.1) or the SPA to keep the authorization across the navigation. | L |
| Machine pairs, admin notices | Nothing happens on the Pairing view. The admin must go to Machines (nav click) and find the Pending row. Overview "Needs your attention" does link to Machines. | The Pairing/Machines view polls invitations (already queried). When one becomes `consumed`, show a card at the top: "A machine paired: host name, full fingerprint. Check it against the screen of that machine." with **Approve** right there. | Fingerprint and host name stay visible before approval (rule). The comparison is still done by the person. | S |
| Approve pending machine | Machines nav (1), **Approve** (2), dialog: type a friendly name (the field is required, empty refused), **Review** (3), **Ask** (4), **Open** (5), **Approve once** (6), tap, switch, **Close** (7). 7 clicks, 1 typed input, 1 tap. | **Approve** (1) opens the dialog with the name pre-filled from the host name (editable) and the fingerprint and host name at the top. **Continue to passkey** (2) combines Review, Ask and Open. Same-tab passkey page, **Approve** (3), tap, return to the Machines view with the row Trusted. 3 clicks, 0 typed (name editable), 1 tap. | Must stay: the tap with the exact fingerprint, host name and friendly name in the signed sentence; the fingerprint and host name shown before the tap. Pre-filling the name is a UI default only (the service still refuses an empty name). | S for pre-fill and merged Review/Ask, M for same-tab |
| Accept new host name | Machines (1), **Accept host name** (2), **Ask** (3), **Open** (4), **Approve once** (5), tap, **Close** (6). | **Accept host name** (1), **Continue** (2), **Approve** (3), tap. Show old and new host name side by side on the dialog top. | Same as above. | S |
| Withdraw/disable/enable/rename | Same chain (5 to 6 clicks + 1 tap each). Trust again also needs the full fingerprint typed (an extra confirmation by design). | Same merge (-2 clicks each). Leave the typed fingerprint of "Trust again". | Typed fingerprint confirmation is a deliberate safeguard, keep. | S |
| End to end, from cold | Sign in 3 clicks + create 7 + approve 7 = 17 clicks, 3 taps, 3 passkey page loads, about 6 tab switches, plus copy and paste of the bundle on another device. | Sign in 2 + create 3 + approve 3 = 8 clicks, 3 taps, same page loads, 0 switches. | The three taps are required (sign-in is a session start; create and approve are two separate mutations). | |

### 3.1 What must stay

Per 10.5 the invitation creation and the machine approval each need their own fresh operation-bound tap; the signed text must name the full fingerprint, host name and the name given; the person must be shown the fingerprint and host name before approving. None of the proposals above removes those.

### 3.2 Merge Pairing into Machines

Pairing is only "step 1 of approving a machine". Seven top-level nav entries (Overview, Machines, Pairing, Grants, Audit, Settings, Passkeys) wrap onto several rows on a phone (the nav is a wrapping flex row above the content, 44 px targets) and every view change starts at the top. Fold Pairing into Machines and Passkeys into Settings: five entries. UI only.

## 4. Flow 3: approve a launch and grants

### 4.1 The run approval page (served by the service, `WebApprover.cs`)

This page is already close to the minimum. Current path for an agent run:

| Step | Detail |
| --- | --- |
| Link reaches the person | The terminal prints the link. A phone needs it typed, copied or forwarded: there is no QR code or push (nothing in the code). |
| Load | 1 page load. Shows Secrets (with source), Run, In (folder), Agent says, inline code or script contents and SHA-256, .env pairs, and the reuse hint. |
| Wait | 2 s before the buttons enable, and the challenges are made (one challenge per reuse time so each choice is signed). |
| Decide | **Approve once** (1 click) or **Approve for** [select, default `reuseMinutes`, 10 min unless changed] **Approve for selected time** (1 click, plus a select change if no default). Ctrl+Enter = Approve once. |
| Tap | 1 tap. The chosen reuse time is inside the signed challenge. |
| After | "Approved once. You can close this page." No return to context on a phone: the person has to switch to the terminal or chat by hand. |

So today: 1 load, 1 click (2 if the time must be chosen), 1 tap. Friction:

| Task | Current | Proposed | Security cost | Effort |
| --- | --- | --- | --- | --- |
| Getting the link to a phone | Copy a printed URL. | Print a QR code beside the link in the terminal. The link is already the secret that the terminal prints; a QR is only another rendering. | None beyond the terminal being a screen the person already trusts. | S |
| Two approve controls plus a select | **Approve once**, then a separate "Approve for" row with a select and a second button. | Keep "Approve once" first and most prominent (it is the safe default). Make the second button carry its time in the label ("Approve for 10 minutes") and show the select only as "other times". | None: the signed challenge per time is unchanged. The prominence of once vs. reuse is a policy choice, so keep once primary. | S |
| No default time when `reuseMinutes` is below 10 | `Preselected` is null so the list shows "Choose a time" and a click without a choice only says "Choose a time first". | Preselect the lowest offered step. | The longest time is still capped by `reuseMaxMinutes`; only the starting entry changes. | S |
| After the tap | Static text. | Show a clear "Done, return to the terminal" state; on the admin passkey pages, a **Back to administration** link (and `window.close()` where permitted). | None. | S |
| Wording | The admin operation pages reuse the run-approval template: title "Approve a request", button "Approve once". | Per-page heading and button text: "Approve this machine", "Sign in". | None; the signed sentence is unchanged. | S |
| No inbox of waiting approvals in the SPA | Overview "Needs your attention" counts machines and grants but not pending launch requests. | Show waiting approvals in Overview with the same one-use link (open in the same tab), so a phone user opens the admin app once instead of finding a terminal link. | The link is a bearer for a page that still needs the passkey tap, and that page still shows the exact secret names, program and folder. A read-only session already "permits inspection of authorized metadata"; a note in 10.5 that a pending-request link counts as metadata would remove doubt. | L |

Must stay: the page must show the exact secret names, resolved program, folder, reason and scripts before the tap; the tap must be fresh and bound to the request and the reuse time. A launch under an existing grant needs no tap (10.5), unchanged.

### 4.2 Grants view

| Task | Current | Proposed | Security cost | Effort |
| --- | --- | --- | --- | --- |
| Revoke a grant | Grants nav (1), **Revoke** (2), **Ask** (3), **Open** (4), **Approve once** (5), tap, **Close** (6). | **Revoke** (1), **Continue** (2), **Approve** (3), tap. | Tap stays. | S/M |
| Extend or renew | Click **Extend** (1), edit minutes (default 60, typed on a phone), **Review** (2), **Ask** (3), **Open** (4), **Approve once** (5), tap, **Close** (6). **No end (indefinite)** is a checkbox beside the minutes. | Quick-pick buttons in the dialog (+1 h, +4 h, +8 h, custom). Choosing one goes straight to the authorization step. Move "No end" behind an explicit "Make indefinite" step with its own warning. | Extending or changing a grant still needs its own tap (10.5). An indefinite grant is the highest-risk option; separating it is a UI safeguard. | S |
| Reading the list | Every grant is a card with 9 facts (id, status, secrets, program, folder, approved by, ends, created, revoked). Revoked and expired grants stay in the same list. Sorted as the service returns. | Active first, collapse ended grants, one-line summary per card (machine, program, secret names, ends), details on tap. | None. | S |
| Return to context | After **Close** the list is refreshed (`invalidateQueries`). | Auto-close the success state after a short delay with a status line, except the bundle case. | None. | S |

## 5. Flow 4: secrets, keys and settings

The SPA has no screens for secrets (10.5: "not applicable"), so secrets are changed only through the CLI, which opens a one-use page (`SecretEntry`, `SettingsPage`, `PasskeyRegistration`). Click counts are from the code comments and README.

| Task | Current | Proposed | Security cost | Effort |
| --- | --- | --- | --- | --- |
| Add or replace a secret | Terminal `with-secrets --set NAME` (typed command), copy the printed link to a browser (phone: type or forward), 1 load, type the value(s) (encrypted to the page key as typed), click **Save**, tap. About 2 clicks + 1 tap + 1 typed command + link transfer. A phone cannot start this on its own. | Keep the page and the typed value on the service page. Add a **Secrets** view in the SPA (names only, from `--list`) with **Add or replace** that opens the service's `--set` page in the same tab and returns. | The value is still typed only on the service-served page, still sealed to the page key, still one tap. Needs an amendment because 10.5 lists no secret screens and its credential-entry exception covers only provider credentials. Wording in 5.1. | L |
| Remove a secret | Terminal `--remove NAME`, link, load, **Approve**, tap. | **Remove** on the Secrets view, then **Continue**, **Approve**, tap. | Tap stays; the page lists exactly the names. | M (after the Secrets view) |
| Change several settings | SPA Settings has four separate cards (unlock mode, audit retention, session timeouts, key). Each change is its own dialog and its own tap: two settings = about 10 clicks and 2 taps. The unrelated `--config` page (reuse minutes and ceiling, etc.) is a different surface reached from the terminal. | One editable Settings form. A single **Save changes** creates one authorization for the whole set of changed values (operation `set-settings`, parameters = every changed setting), one tap. Show the diff (old to new) before the tap. | The batch is still one exact operation bound to its parameters; the passkey page must list every changed value. 10.5 says "completing one operation does not authorize a subsequent operation", which still holds. The E2E "each change is exactly one more signature" rule stays true per operation. Suggested wording in 5.2. Do not merge dangerous items (unattended unlock, key recovery) with ordinary ones. | M |
| One surface for settings | Two places: SPA Settings and terminal `--config`. | Move the `--config` fields (reuse settings) into the SPA Settings, so a phone user finds every setting in one place. | Same tap rule. Reuse settings are in the signed manifest today (`--config` signs the manifest); moving them means defining how the manifest is re-signed by the SPA flow, so it is a real design item. | L |
| Add or remove a passkey | `Add a passkey...`: authorization chain, then "the enrollment pages open one after another, each with its own tap" (so 2 or more taps). Remove: standard chain. | Merge Review/Ask/Open as elsewhere. Say up front how many taps the enrollment needs. | Each enrollment page tap is a separate registration or assertion by design. | S |
| Rotate and recover keys | Standard chain with a warning (danger), recover warns "every other host has to enroll again". | Merge Review/Ask/Open; keep the warning and add a typed confirmation word for **Recover**. | An extra confirmation, never fewer. | S |

### 5.1 Possible wording for a Secrets view (amendment to "Administration UI secret boundary")

> The administration application may list secret names and offer Add, Replace and Remove. Secret values are never typed into the application: Add and Replace open the service's own one-use passkey page in the same tab, where the value is typed, sealed to that page's key, and saved with one operation-bound passkey tap. The application never receives, stores or displays the value.

### 5.2 Possible wording for batched settings (clarification to "Administrative authorization")

> An administrative operation may change several related settings together. The authorization is bound to the complete set of changed values, the passkey page lists each of them, and it authorizes exactly that set once.

## 6. Cross-cutting findings

### 6.1 The SPA tab is on the critical path of every tap (phone and desktop)

The mutation is performed by the SPA after it sees `verified`, with the authorization id held only in memory. Consequences: a discarded or backgrounded tab on a phone loses the tap; an idle session expiring between tap and apply wastes the tap (the authorization is consumed even when the mutation is refused); the same-tab redirect idea needs the SPA to carry state across a navigation. Option A: the service applies the operation when the proof is verified (like the "delegated" operations that already return a passkey page link, 202), and the SPA only shows the outcome by reading state. Option B: persist `{authorizationId, operation}` in sessionStorage across the navigation and resume. Option A is safer (the authorization is verified and spent in one server step, no cookie/CSRF window) and shorter, but changes the "Current implementation" paragraph of 10.5, not the normative rules. Option B keeps the design but keeps the extra moving part. Effort L for A, M for B.

### 6.2 Same facts four times

For one machine approval the fingerprint and name appear in the list row, in the review, in the waiting view (twice: summary and signed parameters) and on the passkey page. Only the passkey page (what is signed) and the machine's own screen (what you compare against) matter for security. The in-dialog review exists to catch a wrong row before opening the passkey page. Merge it with the waiting view (show the service's signed sentence once, then one button). The dialog already refuses to continue if the service's operation name differs, which can stay.

### 6.3 Passkey tab left behind, no return path

`target=_blank rel=noopener` means no `window.close()` guarantee and no opener. After the tap the page ends with "You can close this page". On a phone that is an extra tab to dismiss and a tab switch back; on desktop tabs accumulate. Fix: same-tab navigation with a server-fixed return link, or at least a **Back to administration** link on the final state.

### 6.4 Documentation and UI differ

10.5 "Current implementation" says the anti-forgery value is "held in memory; nothing is kept in `localStorage` or `sessionStorage`". The code (`api/client.ts`) keeps the session secret and a browser secret in `sessionStorage` (per tab, so a reload stays signed in) and the E2E test checks exactly that. Not a UX defect but the docs should be corrected, and the reload behaviour is good for phones.

### 6.5 Reaching the admin app from a phone

`safeLink` in `OperationDialog.tsx` only accepts `http:` links whose host is `localhost`, `127.0.0.1` or `[::1]`. From a phone through an HTTPS name, a LAN address or a forward whose port differs from the one the service reports, the dialog shows "No usable passkey page link". This is consistent with the loopback-only scope of 10.5 ("no remote browser access"), but it contradicts the maintainer's phone use. This needs a decision, see open questions.

### 6.6 Smaller items

| Item | Detail | Proposal | Cost | Effort |
| --- | --- | --- | --- | --- |
| Error dead-ends | The failed state offers **Close** and **Start over**, which returns to the review step and needs a new authorization and a new tap. A 401 during apply makes `Gate` swap the view for sign-in while the dialog stays. | Distinguish "session ended" (offer sign-in, then resume at the same operation) from "operation refused". | None | M |
| Waiting copy | "Open the passkey page (new tab)" on the sign-in and the dialog, plus a paragraph telling the person to come back. | With same-tab flow most of this text disappears. | None | S |
| Overview | A status dashboard with six facts of versions and a "Needs your attention" list of counts. The primary buttons are Lock and Unlock. | Put actionable items first (waiting machines, waiting approvals, grants ending soon) with direct buttons; move versions to the footer (they are already there). | None | S |
| Audit | Needs the **Search** button after every filter change. | Apply filters on change. | None | S |
| Focus | Focus moves to the new view's `h1` after navigation and into the dialog (good for a11y, and costs no clicks). | Keep. | | |
| Passkey page delay | 2 s before Approve enables (anti click-through). | Keep for run approvals (the agent controls the content). For admin operations opened by the admin from the SPA it could be shortened to about 1 s, but it is a small gain. | Weakens accidental-tap protection slightly. | S |

## 7. Prioritized top 10

| # | Change | Saves | Security cost | Effort |
| --- | --- | --- | --- | --- |
| 1 | Merge **Review + Ask + Open** into one **Continue to passkey** step (show the service's signed sentence once). | 2 clicks on every admin operation; repeated facts | None (the passkey page still shows and signs the operation) | S |
| 2 | Same-tab passkey page with a server-fixed return to `/admin` (or at least a **Back to administration** link, and no extra tab). | 1 click, 2 tab switches, an orphan tab, phone tab-discard risk | None if the return is server-fixed | M |
| 3 | Pre-fill the friendly name from the host name when approving a machine; show a side-by-side old/new host name on host-change. | Typing on a phone, 1 click | None (UI default; service still validates) | S |
| 4 | One-tap **Unlock and sign in** (needs the 10.5 amendment in 2.1); fall back to automatic chaining if refused. | 6 clicks, 1 tap on every unlock | Amendment needed; no authority added | M |
| 5 | Surface the paired machine right away: "A machine paired: host, fingerprint, **Approve**"; fold Pairing into Machines. | 1 nav + the hunt for the Pending row; nav shrinks from 7 to 5 | Fingerprint and host name stay in front of the person | S/M |
| 6 | Service applies the mutation when the tap verifies (or persist and resume in the SPA). | Eliminates lost taps from discarded tabs, 401 during apply, the polling wait | Normative rules unchanged; "Current implementation" paragraph is rewritten | L |
| 7 | One batch **Save changes** for settings (one operation, one tap, diff shown). | N taps become 1 for N settings | Needs wording in 5.2; keep danger items separate | M |
| 8 | Raise the default session idle timeout from 15 to 60 minutes. | One whole sign-in chain per 15 idle minutes | Longer read-only session; the setting is already admin-controlled | S |
| 9 | QR code for the run-approval link in the terminal; "Done, return to the terminal" end state; time in the second approve button label. | Link transfer to a phone | None | S |
| 10 | Grants: quick-pick extend buttons, "No end" as a separate guarded step, active grants first. | 2 clicks and typing per extension; scannability | Indefinite is separated, not removed | S |

Next in line (not in the ten): an inbox of waiting launch approvals in the SPA (L, see 4.1), a Secrets view that hands off to the service's set page (L, amendment 5.1), bringing `--config` into the SPA (L).

## 8. Open questions for the maintainer

1. How do you reach the admin app from the phone today (ssh -L, an HTTPS name, a LAN address)? The loopback-only `safeLink` and the 10.5 scope ("no remote browser access") would break the passkey link in the dialog for anything but a forward with the same host and port. Is a phone-facing access path in scope, and if so which?
2. Are you willing to accept the 10.5 amendment that lets an unlock tap also start the read-only session (2.1)? If not, I would chain the two taps automatically instead.
3. Same-tab navigation versus a new tab for the passkey page: is the new tab a deliberate separation (so the SPA cannot navigate away while a tap is outstanding), or only a convenience? I assumed convenience; the signing page itself stays service-served in every proposal.
4. Should the service apply the mutation at tap time (6.1 option A), or do you want the SPA to keep performing it (option B)? A needs the "Current implementation" text rewritten.
5. May a pending launch-approval link be shown in the read-only session (an approval inbox in the SPA)? The tap and the exact-names page still gate it, but the link is a bearer.
6. Should the default session idle timeout rise from 15 to 60 minutes? And can the browser session remain valid across a lock (today a lock ends it and forces a new sign-in tap)?
7. May a batched settings change be one operation with one tap (5.2), or do you want one tap per setting as the E2E test asserts today ("each change is exactly one more passkey signature")?
8. Should secrets get an SPA screen at all (5.1), or stay terminal-only so the browser app never touches a value path? If terminal-only, would a QR/link from the SPA be acceptable?
9. The admin passkey page reuses the run-approval wording ("Approve once", "Approve a request"). Do you want operation-specific headings and button text? It does not change what is signed.
10. Can you sign in while the authority is locked, and what can a session read then? The Overview text says everything can be read while locked, but `Lock` ends every session, so a fresh sign-in is needed first. I could not tell from the sources what the service allows.
11. Is a 2 s click-through delay on admin operations (not run approvals) wanted? It is a UI choice, but it was written for the agent-controlled approval page.
12. I could not check actual layout on a phone. The code puts seven nav links in a wrapping row above the content, and dialog footers stack under 30 rem. Do you have a screenshot of the worst screen on your phone? That would change the order of items 5 and 10.
