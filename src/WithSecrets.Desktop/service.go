package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

type snapshot struct {
	AdminPort     int      `json:"adminPort"`
	Locked        bool     `json:"locked"`
	Remote        bool     `json:"remote"`
	RequestIDs    []string `json:"requestIds"`
	SetupRequired bool     `json:"setupRequired"`
	Starting      bool     `json:"-"`
	Stopped       bool     `json:"-"`
}

const retryDelay = 3 * time.Second
const serviceNotRunning = 6
const startupGrace = 12 * time.Second

func (s snapshot) portAvailable() bool {
	return s.AdminPort > 0 && s.AdminPort < 65536
}

func (s snapshot) label() string {
	switch {
	case s.SetupRequired:
		return "Setup required"
	case s.Starting:
		return "Starting service"
	case s.Stopped:
		return "Service stopped"
	case !s.portAvailable():
		return "Service needs attention"
	case s.Remote:
		return "Service running, remote authority"
	case s.Locked:
		return "Service running, authority locked"
	default:
		return "Service running, authority unlocked"
	}
}

func (s snapshot) contains(id string) bool {
	return slices.Contains(s.RequestIDs, id)
}

type review struct {
	port int
	id   string
}

func (r review) url() string {
	return adminURL(r.port) + "/access/" + r.id
}

func adminURL(port int) string {
	return "http://localhost:" + strconv.Itoa(port) + "/admin"
}

func validRequestID(id string) bool {
	return len(id) > 0 && len(id) <= 128 && strings.IndexFunc(id, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_')
	}) == -1
}

func serviceExecutable(flag string) (string, error) {
	if flag != "" {
		return filepath.Abs(flag)
	}
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	name := "with-secrets"
	dir := filepath.Dir(self)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if runtime.GOOS == "darwin" && filepath.Base(dir) == "MacOS" {
		// The service is distributed next to the .app bundle.
		dir = filepath.Join(dir, "..", "..", "..")
	}
	return filepath.Join(dir, name), nil
}

func watchService(ctx context.Context, service string, out chan<- snapshot, retry <-chan struct{}) {
	send := func(value snapshot) {
		select {
		case out <- value:
		case <-ctx.Done():
		}
	}
	automaticStart := true
	var startingUntil time.Time
	for ctx.Err() == nil {
		setupRequired := false
		code := readSnapshots(ctx, service, func(next snapshot) {
			setupRequired = next.SetupRequired
			if next.portAvailable() {
				automaticStart = false
				startingUntil = time.Time{}
			}
			send(next)
		})
		if ctx.Err() != nil {
			return
		}
		if code == serviceNotRunning && automaticStart {
			automaticStart = false
			if err := startService(service); err == nil {
				startingUntil = time.Now().Add(startupGrace)
				send(snapshot{Starting: true})
			} else {
				send(snapshot{Stopped: true})
			}
		} else if !setupRequired {
			starting := code == serviceNotRunning && time.Now().Before(startingUntil)
			send(snapshot{Starting: starting, Stopped: code == serviceNotRunning && !starting})
		}
		select {
		case <-ctx.Done():
			return
		case <-retry:
			automaticStart = true
		case <-time.After(retryDelay):
		}
	}
}

func startService(service string) error {
	cmd := exec.Command(service, "service")
	detachService(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func readSnapshots(ctx context.Context, service string, send func(snapshot)) int {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(child, service, "--watch-companion")
	hideConsole(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return -1
	}
	if err := cmd.Start(); err != nil {
		return -1
	}

	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		next, err := decodeSnapshot(lines.Bytes())
		if err != nil {
			cancel()
			break
		}
		send(next)
	}
	if lines.Err() != nil {
		cancel()
	}
	_ = cmd.Wait()
	return cmd.ProcessState.ExitCode()
}

func decodeSnapshot(line []byte) (snapshot, error) {
	var next snapshot
	if err := json.Unmarshal(line, &next); err != nil {
		return snapshot{}, err
	}
	if (!next.portAvailable() && !next.SetupRequired) || (next.portAvailable() && next.SetupRequired) || len(next.RequestIDs) > 64 {
		return snapshot{}, errors.New("invalid service snapshot")
	}
	return next, nil
}
