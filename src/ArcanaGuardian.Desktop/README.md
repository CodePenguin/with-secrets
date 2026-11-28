# Arcana Guardian desktop companion

The companion connects to the local service and starts it automatically on a configured installation if it is stopped. A lock badge means the authority is locked. An attention badge means setup is required or the service needs attention. Choose **Open Admin to unlock** to unlock with your passkey. If the tray says **Local device approval required**, unlock first, then open **Machines** from the tray and approve this device. The tray menu displays service startup errors. Quitting the companion leaves an established service running.

On a fresh installation, choose **Set up Arcana Guardian** in the tray menu. Compare the six-digit code on the setup page with the tray menu, then choose **Verify code** in the tray. Compare the device fingerprint there and finish setup in the browser. A pending run request produces a generic OS notification. Clicking it opens that request for review and passkey approval. The **Run request notifications** choice carries over when you reopen the tray.

Build from this directory with Go 1.27.4 or later. The output does not require Go or .NET to be installed. It runs beside a compatible, self-contained Arcana Guardian executable. For development, pass `-service` with the path to that executable. Include `THIRD-PARTY-NOTICES.txt` with distributed builds.

| Platform | Build |
| --- | --- |
| Windows | `go build -trimpath -ldflags "-s -w -H windowsgui" -o arcana-guardian-desktop.exe .` |
| Linux | `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o arcana-guardian-desktop .` |
| macOS | Build on macOS with the command-line tools and the bundle commands below. |

On Windows, run the companion and the service as the same, non-elevated desktop user for toast delivery. On Linux, the desktop session must provide the freedesktop notification service and `xdg-open` to launch the browser. A compatible StatusNotifierItem host displays the icon and menu.

On macOS, keep the app bundle beside the `using-secrets` executable:

```sh
mkdir -p "Arcana Guardian.app/Contents/MacOS"
cp Info.plist "Arcana Guardian.app/Contents/Info.plist"
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o "Arcana Guardian.app/Contents/MacOS/arcana-guardian-desktop" .
codesign --force --sign - "Arcana Guardian.app"
open "Arcana Guardian.app"
```

The ad hoc signature is for local testing. On any supported desktop, open the companion. Complete setup or unlock as indicated, close the browser, and submit a run that needs approval. Check that a generic notification appears and clicking it opens the pending request at `/admin/access/<requestId>`. Approve with your passkey in the browser. Choose **Quit** from the tray menu when finished.
