package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const fixtureSetupURL = "http://localhost:8765/admin/quick-start/0123456789abcdefghijklmnopqrstuv"

func TestMain(m *testing.M) {
	if marker := os.Getenv("WITH_SECRETS_DESKTOP_TEST_MARKER"); marker != "" && len(os.Args) == 2 {
		switch os.Args[1] {
		case "--watch-companion":
			if _, err := os.Stat(marker); err != nil {
				os.Exit(serviceNotRunning)
			}
			fmt.Println(`{"adminPort":8765,"locked":true,"remote":false,"requestIds":[]}`)
			os.Exit(0)
		case "service":
			if os.WriteFile(marker, []byte("started"), 0600) != nil {
				os.Exit(1)
			}
			os.Exit(0)
		case "--desktop-quick-start-worker":
			fmt.Println("Device fingerprint: disposable-device")
			fmt.Println("quick-start:desktop-code:012345")
			fmt.Println("To set up with-secrets, open this link: " + fixtureSetupURL)
			fmt.Println("quick-start:read-code")
			input := bufio.NewScanner(os.Stdin)
			if !input.Scan() || input.Text() != "012345" {
				os.Exit(1)
			}
			fmt.Println("quick-start:result:0")
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

func TestWatchStartsStoppedService(t *testing.T) {
	t.Setenv("WITH_SECRETS_DESKTOP_TEST_MARKER", filepath.Join(t.TempDir(), "service"))
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	snapshots := make(chan snapshot)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		watchService(ctx, executable, snapshots, nil)
	}()
	defer func() { cancel(); <-finished }()
	for {
		select {
		case state := <-snapshots:
			if state.Locked && state.AdminPort == 8765 {
				return
			}
		case <-ctx.Done():
			t.Fatal("watcher did not start and detect the service")
		}
	}
}

func TestSetupWaitsForExplicitConfirmation(t *testing.T) {
	t.Setenv("WITH_SECRETS_DESKTOP_TEST_MARKER", filepath.Join(t.TempDir(), "service"))
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	updates := make(chan setupUpdate)
	confirm := make(chan struct{}, 1)
	go runSetup(ctx, ctx, executable, updates, confirm)

	next := func() setupUpdate {
		select {
		case state := <-updates:
			return state
		case <-ctx.Done():
			t.Fatal("did not receive a setup update")
			return setupUpdate{}
		}
	}
	if got := next(); got.link != fixtureSetupURL || got.code != "" {
		t.Fatalf("unexpected initial setup update: %+v", got)
	}
	if got := next(); got.code != "012345" || got.fingerprint != "disposable-device" {
		t.Fatalf("unexpected setup verification update: %+v", got)
	}
	select {
	case got := <-updates:
		t.Fatalf("setup advanced before confirmation: %+v", got)
	case <-time.After(100 * time.Millisecond):
	}
	confirm <- struct{}{}
	if got := next(); got.code != "" || got.finished {
		t.Fatalf("unexpected update after confirmation: %+v", got)
	}
	if got := next(); !got.finished || !got.success {
		t.Fatalf("setup did not finish successfully: %+v", got)
	}
}

func TestReviewLink(t *testing.T) {
	target := review{port: 8766, id: "run-Abc_1"}
	if !validRequestID(target.id) || target.url() != "http://localhost:8766/admin/access/run-Abc_1" {
		t.Fatalf("unexpected review link: %s", target.url())
	}
	for _, id := range []string{"", "..", "//another-host", "%2f", "run-1?next=1", "review#other"} {
		if validRequestID(id) {
			t.Errorf("accepted an invalid request ID: %q", id)
		}
	}
}

func TestSetupLinkStaysOnLocalQuickStart(t *testing.T) {
	if !setupLink(fixtureSetupURL) {
		t.Fatal("a valid Quick Start URL was rejected")
	}
	for _, link := range []string{
		"http://other-host:8765/admin/quick-start/0123456789abcdefghijklmnopqrstuv",
		fixtureSetupURL + "?extra=1",
		fixtureSetupURL + "/another-path",
		"http://localhost:8765/admin",
	} {
		if setupLink(link) {
			t.Errorf("accepted an invalid setup link: %s", link)
		}
	}
}
