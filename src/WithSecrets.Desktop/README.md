# With Secrets desktop companion

The companion shows local service status and opens the admin app in the default browser. A new pending run request generates a generic OS notification. Clicking it opens that request while it is pending. Review and passkey approval take place in the browser. The companion uses the installed With Secrets executable to authenticate to the local named pipe or Unix socket.

Build from this directory with Go 1.27.4 or later. The output does not require Go or .NET to be installed. It runs beside a compatible, self-contained With Secrets executable. Complete the normal With Secrets setup so the local service identity is pinned. For development, pass `-service` with the path to that executable. Include `THIRD-PARTY-NOTICES.txt` with distributed builds.

| Platform | Build |
| --- | --- |
| Windows | `go build -trimpath -ldflags "-s -w -H windowsgui" -o with-secrets-desktop.exe .` |
| Linux | `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o with-secrets-desktop .` |
| macOS | Build on macOS with the command-line tools and the bundle commands below. |

On Windows, run the companion and the service as the same, non-elevated desktop user for toast delivery. On Linux, the desktop session must provide the freedesktop notification service and `xdg-open` to launch the browser. A compatible StatusNotifierItem host displays the icon and menu.

On macOS, keep the app bundle beside the `with-secrets` executable:

```sh
mkdir -p "With Secrets.app/Contents/MacOS"
cp Info.plist "With Secrets.app/Contents/Info.plist"
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o "With Secrets.app/Contents/MacOS/with-secrets-desktop" .
codesign --force --sign - "With Secrets.app"
open "With Secrets.app"
```

The ad hoc signature is for local testing. On any supported desktop, start the service, open the companion, close the browser, and submit a run that needs approval. Check that a generic notification appears and clicking it opens the pending request at `/admin/access/<requestId>`. Approve with your passkey in the browser. Choose **Quit** from the tray menu when finished.
