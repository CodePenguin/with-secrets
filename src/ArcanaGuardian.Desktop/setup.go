package main

import (
	"bufio"
	"context"
	"io"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type setupUpdate struct {
	link, code, fingerprint string
	finished, success       bool
}

var setupPath = regexp.MustCompile(`^/admin/quick-start/[a-zA-Z0-9_-]{32}$`)
var setupCode = regexp.MustCompile(`^[0-9]{6}$`)

func setupLink(link string) bool {
	address, err := url.Parse(link)
	if err != nil || address.Scheme != "https" || address.Hostname() != browserHost ||
		address.User != nil || address.RawQuery != "" || address.Fragment != "" || address.ForceQuery ||
		!setupPath.MatchString(address.EscapedPath()) {
		return false
	}
	if address.Host == browserHost {
		return true
	}
	port, err := strconv.Atoi(address.Port())
	return err == nil && port > 0 && port < 65536
}

func runSetup(parent, ctx context.Context, service string, updates chan<- setupUpdate, confirm <-chan struct{}) {
	send := func(update setupUpdate) {
		select {
		case updates <- update:
		case <-ctx.Done():
		}
	}
	success := false
	reported := false
	defer func() {
		select {
		case updates <- setupUpdate{finished: true, success: success}:
		case <-parent.Done():
		}
	}()
	cmd := exec.Command(service, "--desktop-quick-start-worker")
	detachService(cmd)
	input, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	defer output.Close()
	if cmd.Start() != nil {
		return
	}
	done := make(chan struct{})
	defer func() {
		close(done)
		_ = input.Close()
		_ = output.Close()
		if reported && !success {
			_ = cmd.Wait()
		} else {
			go func() { _ = cmd.Wait() }()
		}
	}()
	lines := make(chan string)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-done:
				return
			}
		}
	}()

	var current setupUpdate
	awaitingCode := false
	cancel := ctx.Done()
	var cancelTimeout <-chan time.Time
	for {
		var line string
		select {
		case <-cancel:
			// EOF requests cancellation. Only the service can determine whether
			// the final assertion has already crossed the commit boundary.
			_ = input.Close()
			cancel = nil
			cancelTimeout = time.After(8 * time.Second)
		case <-cancelTimeout:
			return
		case <-confirm:
			if awaitingCode && cancel != nil {
				if _, err := io.WriteString(input, current.code+"\n"); err != nil {
					return
				}
				awaitingCode = false
				send(setupUpdate{link: current.link, fingerprint: current.fingerprint})
			}
			continue
		case next, ok := <-lines:
			if !ok {
				return
			}
			line = next
		}
		switch {
		case strings.HasPrefix(line, "Device fingerprint: "):
			current.fingerprint = strings.TrimPrefix(line, "Device fingerprint: ")
		case strings.HasPrefix(line, "quick-start:desktop-code:"):
			current.code = strings.TrimPrefix(line, "quick-start:desktop-code:")
		case strings.HasPrefix(line, "To set up Arcana Guardian, open this link: "):
			link := strings.TrimPrefix(line, "To set up Arcana Guardian, open this link: ")
			if !setupLink(link) {
				return
			}
			current.link = link
			send(setupUpdate{link: current.link, fingerprint: current.fingerprint})
		case line == "quick-start:read-code":
			if current.link == "" || !setupCode.MatchString(current.code) {
				return
			}
			awaitingCode = true
			send(current)
		case strings.HasPrefix(line, "quick-start:result:"):
			reported = true
			success = line == "quick-start:result:0"
			return
		}
	}
}
