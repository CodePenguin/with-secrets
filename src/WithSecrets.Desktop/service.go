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
	AdminPort  int      `json:"adminPort"`
	Locked     bool     `json:"locked"`
	Remote     bool     `json:"remote"`
	RequestIDs []string `json:"requestIds"`
}

const retryDelay = 3 * time.Second

func (s snapshot) portAvailable() bool {
	return s.AdminPort > 0 && s.AdminPort < 65536
}

func (s snapshot) label() string {
	switch {
	case !s.portAvailable():
		return "Service unavailable"
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

func watchService(ctx context.Context, service string, out chan<- snapshot) {
	send := func(value snapshot) {
		select {
		case out <- value:
		case <-ctx.Done():
		}
	}
	for ctx.Err() == nil {
		_ = readSnapshots(ctx, service, send)
		if ctx.Err() != nil {
			return
		}
		send(snapshot{})
		select {
		case <-ctx.Done():
			return
		case <-time.After(retryDelay):
		}
	}
}

func readSnapshots(ctx context.Context, service string, send func(snapshot)) error {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(child, service, "--watch-companion")
	hideConsole(cmd)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()

	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		var next snapshot
		if err := json.Unmarshal(lines.Bytes(), &next); err != nil {
			return err
		}
		if !next.portAvailable() || len(next.RequestIDs) > 64 {
			return errors.New("invalid service snapshot")
		}
		send(next)
	}
	return lines.Err()
}
