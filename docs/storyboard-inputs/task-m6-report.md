# Task M6 report: prominent warning for code-loading variables on the approval page

Worktree C:\Users\codep\Projects\with-secrets-impl, branch impl/mtls-pairing (base 31e8fc6).

## 1. What was implemented

- One warning block, replacing the M5 line "Warning: the .env files set variables ...". It is built by `ApprovalSummary.AppendCodeChanges` from `ApprovalSummary.CodeChanges(request)`, which reuses `EnvDeclarations.IsProtectedVariable` (no second list). Format in the signed text: `Warning: This run changes how the program loads code or where it sends data.`, then per variable a `  | NAME=value` line and a `  Why: <reason>` line, then `Your approval covers exactly these values.` The block no longer depends on there being an `Env file:` line, so it also shows when the values come from anywhere else in the plan. Names are in ordinal order; the variables in the block are not repeated in "Other variables from .env".
- Reason classes: loads code (NODE_OPTIONS, LD_PRELOAD, LD_AUDIT, PYTHONSTARTUP, BASH_ENV, ENV, PERL5OPT, RUBYOPT, JAVA_TOOL_OPTIONS, _JAVA_OPTIONS, DOTNET_STARTUP_HOOKS, DYLD_INSERT_LIBRARIES, PATH and the other protected names); changes the library path (LD_LIBRARY_PATH, DYLD_*, PYTHONPATH, NODE_PATH, PYTHONHOME, PYTHONUSERBASE, PERL5LIB, PERLLIB, RUBYLIB); routes network traffic (*_PROXY); changes git behaviour (GIT_*).
- `ApprovalPage.SplitWarning` (WebApprover.cs) takes that block out of the text and renders it as its own `<section class="warn" aria-labelledby>` ABOVE the request text and above the Deny and Approve buttons: an h2 beginning "Warning:", a list with `<code>` name = `<code>` value and the reason, and the covers-exactly sentence in bold. Everything is HTML-encoded. Visual signal is a thick border, a tinted background and the word "Warning", not colour alone (#7a3e00 on #fff3e0, high contrast); long values wrap (overflow-wrap and word-break). The block is removed from the `<pre>` so there is one warning, not two. The text that the passkey signs is unchanged in structure (it still contains the block), so the bind and the page show the same content.
- The block cannot be forged by the agent: every line the agent writes starts with the code marker `  | `, and the split matches the exact `Warning: ...` and cover lines.
- Remote mode: the authority renders approvals through the same `WebApprover.Request` / `ApprovalSummary.BuildMessage` path, so the section appears there with no extra code; a parity test proves it on the authority's own page.
- Terminal echo (`showValues: false`) names the variables and gives the reasons, no values.
- `ChildRunner.CodeLoadingVariables/Prefixes` gained `LD_AUDIT` and the `DYLD_` prefix (the inherited-environment filter; ordinary visible values from the plan are still passed on, nothing stripped from them). Values the page cannot show (encrypted, secret references) are still refused for these names (M5 unchanged).
- Fingerprint/bind unchanged (`RequestFingerprint` untouched); a test proves a changed NODE_OPTIONS or HTTPS_PROXY value changes the request id.
- The admin app's launch-approval display does not list run variables (checked: `AdminViews`/Api carry grants, machines, audit only), so nothing to change there.

## 2. Files changed

- src/WithSecrets.Core/ApprovalSummary.cs, WebApprover.cs, ChildProcess.cs
- tests/WithSecrets.Tests/CodeChangesTests.cs (new), EnvDeclarationTests.cs (wiring, M5 flooding test updated to the new block), RemoteLaunchTests.cs (parity)
- tests/WithSecrets.E2E/Scenarios.cs, Program.cs (scenario c2)
- README.md, docs/operations.md, docs/architecture.md (current-implementation sentence in the 10.1 Status paragraph only), IMPLEMENTATION_PROGRESS.md

## 3. Tests

- Unit (`CodeChangesTests`, run in suite EnvDeclarations): 27 variable names across all four classes (name, value, reason, position), ordinary variable after the block, no warning when absent or for a Dotenvx private key, page order (section before pre, before Deny and Approve), single block, heading and aria label, name order, hostile values escaped (script, img, b, pre, quotes, newline), forged value cannot create a block, terminal echo has no values, names-only request, fingerprint follows values, filter knows DYLD_* and LD_AUDIT.
- Remote parity (`RemoteLaunch`, `CodeChangesParity`): the authority's real page, via a host launch, has the one section before the text and approve control, all names, values, reasons and the sentence, hostile value escaped, changed value is another digest.
- E2E `c2-run-code-changes` (real Chromium, .env with NODE_OPTIONS, HTTPS_PROXY, LD_LIBRARY_PATH, GIT_SSH_COMMAND with an HTML value): one section, texts, no markup injected, section before the approve control, no passkey call on load, axe-core WCAG 2.0/2.1/2.2 A/AA clean at 1280 and 375 px width, no horizontal scroll: 21 checks, passed.
- Mutation evidence (suite EnvDeclarations, each reverted): (1) value not HTML-encoded: 2 checks fail; (2) warning moved after the approve control: ordering check and 7 more fail (609 passed, 8 failed); (3) proxy class reason removed: 6 checks fail (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY, https_proxy, and the section check).
- Results: EnvDeclarations + RemoteLaunch + ApprovalSummary 984 passed, 0 failed; `dotnet build with-secrets.slnx --no-incremental` 0 warnings, 0 errors; verify-all result below.

## 4. Remaining gaps and limitations

- The block is recognised on the page by its fixed heading line; any other page that shows an `ApprovalPrompt` with the same text gets the same section (intended). A DOTENV_PRIVATE_KEY* variable in the plan is never passed on and is not listed.
- Encrypted values and secret references for these names are still refused, not warned (M5 decision, unchanged).
- The name list is the existing one plus LD_AUDIT and DYLD_*; any other behaviour-changing variable (for example CLASSPATH, PYTHONHASHSEED, SSL_CERT_FILE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS, curl/pip/npm config variables) is not classed and so is shown only in "Other variables" like any value. Extending is one entry in `ChildRunner.CodeLoadingVariables` or `EnvDeclarations`.
- Adding the `DYLD_` prefix also strips any inherited DYLD_* variable from the child's environment (a sensible tightening, macOS only).

## 5. Deviations from the architecture

- None to accepted design text; I did not edit 10.1 or 10.2. Architecture line 445 says "Continue stripping the existing child code-loading variables"; the code strips them from the inherited environment only, and passes the ordinary visible plan values on, as before (M5 decision).

### Proposed wording for architecture 10.1 (for the maintainer; replaces the sentence at "Preserve protected-variable rules" in Approval and trust)

> Preserve protected-variable rules for values the page cannot show: a secret reference or an encrypted value cannot target code-loading variables, process-selection variables such as `PATH`, `PATHEXT` or `COMSPEC`, library-path variables, proxy variables or git variables. Ordinary visible values (from `.env` files, flags or pairs) for such variables are not stripped and not refused: they are bound in the approval fingerprint and the approval page shows them first, in a distinct warning section above the request and the approve control, titled "This run changes how the program loads code or where it sends data", with each name, its value and a one-line reason per class (loads code, changes the library path, routes network traffic, changes git behaviour), and states that the approval covers exactly these values. The same section is shown by a remote authority for a remote host's launch. Continue removing these variables from the environment the child inherits. A denylist is not a complete security boundary; showing ordinary values is still required.

Nothing in 10.2 needs changing.

verify-all.ps1: build, dotnet-tests (623 s), frontend, publish, e2e (all scenarios incl. c2): ALL STAGES PASSED (5). Commit: 0f323eb.
