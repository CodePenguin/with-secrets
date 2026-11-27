package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"

	"fyne.io/systray"
	"github.com/worldiety/gift/notify"
)

//go:embed tray.png
var trayPNG []byte

func main() {
	serviceFlag := flag.String("service", "", "path to the existing with-secrets executable")
	flag.Parse()
	service, err := serviceExecutable(*serviceFlag)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	systray.Run(func() {
		systray.SetIcon(trayIcon(trayPNG))
		systray.SetTitle("With Secrets")
		status := systray.AddMenuItem("Connecting to service", "")
		status.Disable()
		open := systray.AddMenuItem("Open Admin", "Open With Secrets in your browser")
		open.Disable()
		alerts := systray.AddMenuItemCheckbox("Run request notifications", "Show local desktop notifications", true)
		systray.AddSeparator()
		quit := systray.AddMenuItem("Quit", "Close the desktop companion")

		snapshots := make(chan snapshot)
		go func() {
			defer close(finished)
			watchFinished := make(chan struct{})
			go func() {
				defer close(watchFinished)
				watchService(ctx, service, snapshots)
			}()
			runTray(ctx, snapshots, status, open, alerts, quit)
			cancel()
			<-watchFinished
		}()
	}, cancel)
	cancel()
	<-finished
}

func runTray(ctx context.Context, snapshots <-chan snapshot, status, open, alerts, quit *systray.MenuItem) {
	var current snapshot
	var lastLabel string
	enabled := true
	var permitted bool
	notices := make(map[string]int)
	clicked := make(chan review)
	permission := make(chan bool)
	notifier := notify.New(notify.Config{
		AppID: "com.github.codepenguin.withsecrets", AppName: "With Secrets",
		Post: func(f func()) { go f() },
	})
	authorize := func() {
		notifier.Authorize(func(granted bool) {
			select {
			case permission <- granted:
			case <-ctx.Done():
			}
		})
	}
	authorize()

	refreshNotices := func() {
		for id, port := range notices {
			if !enabled || (current.portAvailable() && (port != current.AdminPort || !current.contains(id))) {
				_ = notifier.Withdraw(id)
				delete(notices, id)
			}
		}
		if !enabled || !permitted || current.Locked || current.Remote || !current.portAvailable() {
			return
		}
		for _, id := range current.RequestIDs {
			if !validRequestID(id) || notices[id] == current.AdminPort {
				continue
			}
			target := review{port: current.AdminPort, id: id}
			err := notifier.Show(notify.Notification{
				ID: id, Title: "With Secrets", Body: "Run request waiting for review",
				OnClick: func() {
					select {
					case clicked <- target:
					case <-ctx.Done():
					}
				},
			})
			if err == nil {
				notices[id] = target.port
			} else {
				log.Printf("desktop notification: %v", err)
				alerts.SetTooltip("The desktop notification could not be shown")
			}
		}
	}
	defer func() {
		for id := range notices {
			_ = notifier.Withdraw(id)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-quit.ClickedCh:
			systray.Quit()
			return
		case next := <-snapshots:
			if label := next.label(); label != lastLabel {
				status.SetTitle(label)
				systray.SetTooltip("With Secrets: " + label)
				lastLabel = label
			}
			current = next
			if current.portAvailable() {
				open.Enable()
			} else {
				open.Disable()
			}
			refreshNotices()
		case <-open.ClickedCh:
			if current.portAvailable() {
				go openLink(adminURL(current.AdminPort))
			}
		case <-alerts.ClickedCh:
			enabled = !enabled
			if enabled {
				alerts.Check()
				authorize()
			} else {
				alerts.Uncheck()
			}
			refreshNotices()
		case permitted = <-permission:
			if !permitted {
				alerts.SetTooltip("Desktop notifications are unavailable or disabled in system settings")
			}
			refreshNotices()
		case target := <-clicked:
			if target.port == current.AdminPort && current.contains(target.id) {
				go openLink(target.url())
			}
		}
	}
}

func openLink(link string) {
	if err := openBrowser(link); err != nil {
		fmt.Fprintln(os.Stderr, "with-secrets desktop:", err)
	}
}
