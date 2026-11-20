# Playwright end-to-end scenarios and UX recordings

The E2E runner is a standalone console application because it requires a locally installed Chromium browser. It uses the same isolated rigs and scenarios for verification and UX recordings.

## Run the scenarios normally

```powershell
dotnet run --project tests\WithSecrets.E2E
```

Run one scenario by prefix:

```powershell
dotnet run --project tests\WithSecrets.E2E -- k1
```

Normal runs do not create videos, screenshots or demo artifacts.

## Record a UX demo

From the repository root:

```powershell
.\scripts\demo.ps1
```

The script builds the E2E project, runs all scenarios with Playwright video recording enabled, and writes the result to `artifacts\demo\latest\`. Each run replaces the previous one: only the last demo is kept.

You can choose an explicit output directory:

```powershell
.\scripts\demo.ps1 -OutputDirectory artifacts\demo\review
```

An explicit directory must be under `artifacts\demo\` and must not already contain files. This never overwrites a recording and keeps demo output out of the rest of the repository; use a new directory name for each comparison run. The script exits nonzero if the build fails, a scenario fails, or the output directory cannot be used.

Alternatively, invoke the runner directly (it applies the same output-directory checks, but does not build first):

```powershell
dotnet run --project tests\WithSecrets.E2E -- --demo artifacts\demo\review
```

Without an explicit directory, the direct runner also writes to `artifacts\demo\latest\`, replacing the last demo. `scripts\demo.ps1` remains the recommended entry point because it builds before running.

## Output

Open `index.html` in the output directory. Each scenario's test name is also its recording link (additional browser contexts are suffixed `(2)`, `(3)`, etc.); the separate Browser 1/2 recording column is omitted. Rows also show pass/fail status, check counts, durations and failure evidence. Recordings use a split-screen composition: the full-height terminal occupies the left 38% and the real browser occupies the right 62%, with no terminal overlay covering the application. CLI stdout and stderr appear as one transcript in write order; the step caption sits at the top of the left pane, above the transcript. Complete separate-stream console logs remain downloadable beside the video.

Demo recordings include readable lower-third narration: a scenario introduction followed by short captions as the person advances through browser actions. Captions are injected only in demo mode, are not part of the application UI, and do not affect normal E2E runs. For convenient review and reliable video seeking, serve all runs through the local demo library:

```text
artifacts\demo\latest\
  index.html
  summary.json
  videos\<scenario>\browser-1.webm
  videos\<scenario>\browser-2.webm   (when a scenario uses more than one context)
  videos\<scenario>\console-browser-1.txt
  videos\<scenario>\console-browser-2.txt   (one per context that runs CLI commands)
  failures\<scenario>\context-1.png  (failed scenarios only)
  failures\<scenario>\diagnostics.txt
```

`summary.json` contains the same run summary in machine-readable form, with paths relative to the run directory. Every browser context opened by a scenario is closed and its recording finalized before the index and summary are written. Video files use stable `browser-N.webm` names so successive UI revisions can be compared directly; a scenario that opens two contexts produces `browser-1.webm` and `browser-2.webm`.

A failed scenario still produces its available recordings before the contexts are closed. In demo mode it also captures a screenshot of each open context and a sanitized diagnostics file containing the failed checks and page state. Normal E2E execution is unchanged.

## Serve and browse demo runs

```powershell
.\scripts\serve-demo.ps1
```

The helper starts a local server with a landing page listing every completed run under `artifacts\demo\`. Select a run to open its scenario index. The list is refreshed whenever you reload the landing page, so runs created while the server is running appear automatically.

The server is a single .NET 10 file-based app at `scripts\serve-demo.cs`; it does not introduce another project. It binds only to `127.0.0.1` on port `4173` by default. WebM responses support HTTP byte-range requests (`206 Partial Content`) for seeking. Use `-Port` to choose another local port. Keep the server running while reviewing and stop it with Ctrl+C.

## Recording behavior and safety

- Demo mode runs the same real Playwright scenarios as the ordinary E2E suite. It does not substitute screenshots or mock browser interactions.
- Each scenario gets a fresh browser context and its own video directory. All contexts opened by a scenario are closed and their recordings finalized before the index is written.
- The browser viewport is fixed at 1440×900 and interactions use demo-only slow motion and pauses, so a reviewer can follow each step; normal runs keep their timing and assertions unchanged.
- Every scenario that starts with the shared first-run setup has that identical setup trimmed from the front of its recording. `a-first-run-setup` is the setup itself and keeps it. Playwright's WebM keyframes are too sparse for a stream copy, so the trim re-encodes the recording to VP9 with the Playwright-bundled ffmpeg. If ffmpeg cannot be found, the recording is kept untrimmed and a warning is printed.
- Demo mode outlines the control that is about to be pressed, and the screenshot is taken before the press (the page may change at once after it). Demo mode has no slow motion and no waits between steps. The outline is injected by Playwright's init script (so it works under the one-shot pages' strict Content-Security-Policy) and stays above modal dialogs; it is `aria-hidden` and cannot receive pointer events.
- When a code, request or recovery box is revealed below the fold, demo mode scrolls it into view so the recording shows it; scrolling does not change what the scenario asserts.
- The recordings show the real interaction, including the one-time approval code, the recovery code and the pairing bundle, because they are review artifacts for the user experience. They are local, gitignored output and are not published.
- The scenarios continue to use temporary test state and fixed test secret values; they never access the user's real with-secrets state or provider credentials. Keep `artifacts\demo\` local and do not commit or share a run.
- Demo mode is separate from `scripts\verify-all.ps1`; normal verification remains unchanged.

## Terminal capture

In demo mode, the browser recording is composed as a split screen: the terminal fills the left 38% and the real application fills the right 62%. The terminal polls the same in-memory terminal writers used by the scenario, so stdout and stderr appear in one transcript as the command writes them. The step caption appears at the top of the terminal pane, separate from the scrolling transcript. The composition is injected only into the recorded browser context; it is not part of the application and does not affect normal E2E tests.

Each recorded browser context also writes its complete stdout and stderr to `videos/<scenario>/console-browser-N.txt`, linked from that scenario's row in `index.html`. Output is intentionally unredacted: all scenario values, secrets, approval codes and pairing material are disposable test data. Keep generated demo artifacts local and do not use this capture mechanism with real credentials.
