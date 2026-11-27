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
)

type setupUpdate struct {
	link, code, fingerprint string
	finished, success       bool
}

var setupPath = regexp.MustCompile(`^/admin/quick-start/[a-zA-Z0-9_-]{32}$`)
var setupCode = regexp.MustCompile(`^[0-9]{6}$`)

func setupLink(link string) bool {
	address, err := url.Parse(link)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(address.Port())
	return err == nil && port > 0 && port < 65536 && address.Scheme == "http" &&
		address.Hostname() == "localhost" && address.User == nil && address.RawQuery == "" &&
		address.Fragment == "" && !address.ForceQuery && setupPath.MatchString(address.EscapedPath())
}

func runSetup(parent, ctx context.Context, service string, updates chan<- setupUpdate, confirm <-chan struct{}) {
	send := func(update setupUpdate) {
		select {
		case updates <- update:
		case <-ctx.Done():
		}
	}
	success := false
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
		if success {
			go func() { _ = cmd.Wait() }()
		} else {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
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
	for {
		var line string
		select {
		case <-ctx.Done():
			return
		case <-confirm:
			if awaitingCode {
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
		case strings.HasPrefix(line, "To set up with-secrets, open this link: "):
			link := strings.TrimPrefix(line, "To set up with-secrets, open this link: ")
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
			success = line == "quick-start:result:0"
			return
		}
	}
}
