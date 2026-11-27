package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"

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
		confirm := systray.AddMenuItem("Verify setup code", "Confirm that the browser shows the same code")
		fingerprint := systray.AddMenuItem("Device fingerprint", "")
		cancelSetup := systray.AddMenuItem("Cancel setup", "")
		fingerprint.Disable()
		confirm.Hide()
		fingerprint.Hide()
		cancelSetup.Hide()
		alerts := systray.AddMenuItemCheckbox("Run request notifications", "Show local desktop notifications", true)
		systray.AddSeparator()
		quit := systray.AddMenuItem("Quit", "Close the desktop companion")

		snapshots := make(chan snapshot)
		retry := make(chan struct{}, 1)
		go func() {
			defer close(finished)
			watchFinished := make(chan struct{})
			go func() {
				defer close(watchFinished)
				watchService(ctx, service, snapshots, retry)
			}()
			runTray(ctx, service, snapshots, retry, status, open, confirm, fingerprint, cancelSetup, alerts, quit)
			cancel()
			<-watchFinished
		}()
	}, cancel)
	cancel()
	<-finished
}

func runTray(ctx context.Context, service string, snapshots <-chan snapshot, retry chan<- struct{},
	status, open, confirm, fingerprint, cancelSetup, alerts, quit *systray.MenuItem) {
	ctx, closeTray := context.WithCancel(ctx)
	var current snapshot
	var lastLabel string
	var setup setupUpdate
	var stopSetup context.CancelFunc
	var setupWorkers sync.WaitGroup
	setupUpdates := make(chan setupUpdate)
	verifyCode := make(chan struct{}, 1)
	setupFailed := false
	setupCanceled := false
	defer func() {
		closeTray()
		setupWorkers.Wait()
	}()
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

	drawStatus := func() {
		label := current.label()
		if stopSetup != nil {
			label = "Setup in progress"
		} else if current.SetupRequired && setupFailed {
			label = "Setup ended. Try again."
		}
		if label != lastLabel {
			status.SetTitle(label)
			systray.SetTooltip("With Secrets: " + label)
			systray.SetIcon(trayIcon(statusIcon(trayPNG, current, stopSetup != nil)))
			lastLabel = label
		}
		switch {
		case stopSetup != nil:
			open.SetTitle("Open setup")
		case current.SetupRequired:
			open.SetTitle("Set up With Secrets")
		case current.Stopped:
			open.SetTitle("Start service")
		case current.Locked:
			open.SetTitle("Open Admin to unlock")
		default:
			open.SetTitle("Open Admin")
		}
		if (stopSetup != nil && setup.link != "") || (stopSetup == nil && (current.portAvailable() || current.SetupRequired || current.Stopped)) {
			open.Enable()
		} else {
			open.Disable()
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-quit.ClickedCh:
			systray.Quit()
			return
		case next := <-snapshots:
			current = next
			drawStatus()
			refreshNotices()
		case <-open.ClickedCh:
			switch {
			case stopSetup != nil:
				if setup.link != "" {
					go openLink(setup.link)
				}
			case current.SetupRequired:
				setupContext, cancelWorker := context.WithCancel(ctx)
				stopSetup = cancelWorker
				codeClicks := make(chan struct{}, 1)
				verifyCode = codeClicks
				setupFailed = false
				setupCanceled = false
				cancelSetup.Enable()
				cancelSetup.Show()
				drawStatus()
				setupWorkers.Go(func() {
					defer cancelWorker()
					runSetup(ctx, setupContext, service, setupUpdates, codeClicks)
				})
			case current.Stopped:
				select {
				case retry <- struct{}{}:
					current = snapshot{Starting: true}
					drawStatus()
				default:
				}
			case current.portAvailable():
				go openLink(adminURL(current.AdminPort))
			}
		case update := <-setupUpdates:
			if update.finished {
				stopSetup()
				stopSetup = nil
				setup = setupUpdate{}
				setupFailed = !update.success && !setupCanceled
				confirm.Hide()
				fingerprint.Hide()
				cancelSetup.Hide()
			} else if !setupCanceled {
				openFirst := setup.link == "" && update.link != ""
				setup = update
				if setup.fingerprint != "" {
					fingerprint.SetTitle("Device: " + setup.fingerprint)
					fingerprint.Show()
				}
				if setup.code != "" {
					confirm.SetTitle("Verify code " + setup.code)
					confirm.Show()
				} else {
					confirm.Hide()
				}
				if openFirst {
					go openLink(setup.link)
				}
			}
			drawStatus()
		case <-confirm.ClickedCh:
			if setup.code != "" {
				verifyCode <- struct{}{}
				setup.code = ""
				confirm.Hide()
			}
		case <-cancelSetup.ClickedCh:
			if stopSetup != nil {
				stopSetup()
				setupCanceled = true
				setup = setupUpdate{}
				confirm.Hide()
				fingerprint.Hide()
				cancelSetup.Disable()
				drawStatus()
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
