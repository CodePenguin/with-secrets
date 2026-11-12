# Handoff: map the with-secrets pages and flows for storyboards

You are helping the maintainer storyboard the user experience of with-secrets, a C#/.NET 10 tool that lets an AI agent run programs needing credentials without seeing the values. A person approves each use on a one-use web page with a passkey tap. This task is READ-ONLY mapping and storyboard drafting. Do not change code, do not run servers or builds in the shared worktree, do not touch ~/.with-secrets, never print secret values, codes or keys. Do not edit docs/architecture.md (the maintainer owns it). Do not commit.

## Where things are
- Worktree (implementation, branch impl/mtls-pairing, tip 31e8fc6 or later): C:\Users\codep\Projects\with-secrets-impl
- Notes/reports (git-ignored): C:\Users\codep\Projects\with-secrets\.superpowers\sdd\2026-11-01-web-approval-passkey\
  - ux-audit.md : click paths, counts, friction points, proposals, open questions for every flow (READ FIRST)
  - task-m8-report.md : the UX fixes just built (before/after click counts, new flows)
  - task-m2-report.md : pairing; task-m7-report.md : Machines copied-key warning
  - task-m5-report.md / task-m6-report.md (when it exists) : encrypted .env values; code-loading variable warning on the approval page
- Accepted design: docs/architecture.md section 10.5 (admin web app) and 10.2 (machines, pairing, grants, lock) in the worktree. Never edit.
- Admin SPA source (React + TypeScript + Vite): src/WithSecrets.Admin.Web/src (App.tsx routes, features/, components/, views.test.tsx for rendered states). Playwright E2E click paths: tests/WithSecrets.E2E in the worktree.
- Server-rendered run approval page: src/WithSecrets.Core (WebApprover.cs and ApprovalSummary.cs).

## Pages and surfaces to map (confirm each against the source)
Admin app (served same-origin on loopback, default http://localhost:8765/admin; routes in src/App.tsx):
1. Sign in (passkey) and the locked/Unlock state
2. Overview (/)
3. Machines (/machines): list, Pending machine card ("paired: check fingerprint and host name, Approve"), create invitation (bundle shown once), copied-key warning, approve/disable/untrust
4. Grants (/grants)
5. Audit (/audit events, /audit/changes, /audit/gaps), with filters and signed-event metadata
6. Settings (/settings)
7. Passkeys (/passkeys)
8. The passkey authorization page (opens in a new tab for each admin mutation; "Continue to passkey" step; result states applied / refused / expired / already applied)
Outside the SPA:
9. Run approval page (one-use link, usually http://localhost:<approval port>/a/<id>): what is shown (program, folder, exact secret names, .env variables, code-loading variable warning, reuse choice) and the approve/deny tap
10. Terminal moments that hand a person to a page or a code: `with-secrets --config` (first setup, recovery code, passkey enrollment), `with-secrets admin` (prints the admin link and status), `with-secrets pair` (new machine, hidden code entry, prints fingerprint and host name), run exit codes (3 refused/timeout, 8 locked, 9 not ready, 5 audit failed)

## What to produce
For each flow below, a storyboard: numbered frames, each with the screen (or terminal) state, what the person sees, what they do, what the system does, and the security-relevant moment (fresh passkey tap, fingerprint/host name verification, exact-names review, one-time display). Mark which device each frame happens on (Windows PC, phone, a second machine such as WSL or a container) because the maintainer drives it from a phone.
1. First-time setup and first sign in
2. Locked authority: unlock and sign in
3. Pair a new machine (invitation created in the admin app, code entered on the new machine, machine appears Pending, approve it)
4. Approve an agent's run (one-use page, reuse/grant choice) including the new code-loading warning, an encrypted .env value, and a remote host's run
5. Add/edit/remove a secret, key or setting (today partly terminal-only; see ux-audit.md section 5)
6. Disable/untrust a machine, copied-key warning, revoke a grant
7. Read the audit trail
Also draw the cross-cutting states: refused, expired, locked, authority unreachable (remote host fails closed), tab lost between tap and result.

Use the actual labels and copy from the source. Show click and tap counts per flow (current, from M8) next to any improvement you propose. Rules you must keep in proposals: every mutation needs a fresh, single-use, operation-bound passkey tap with user verification; the browser session is read-only; machine approval must show fingerprint and host name; a run approval must show the exact names/program/folder; secrets and codes are never shown except the one-time invitation bundle. Anything that needs a change to accepted 10.5 text goes in a separate "needs maintainer decision" list with proposed wording.

Write the result to C:\Users\codep\Projects\with-secrets\.superpowers\sdd\2026-11-01-web-approval-passkey\storyboards.md (or a folder of files if you prefer) and reply with the page inventory (one line each) and the list of open design questions.
