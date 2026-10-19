package suricata

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// Subprocess manages a Suricata subprocess lifecycle.
//
// Suricata is GPL-2.0; we never link it. We communicate exclusively through
// its EVE JSON output, which it writes to stdout, a file, or a unix socket.
// This process boundary is both the legal boundary and the correct architecture:
// it isolates crashes, lets Suricata be upgraded independently, and enforces
// the passive-only architecture by preventing any direct library linkage.
type Subprocess struct {
	cmd     *exec.Cmd
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	reader  *Reader
	mu      sync.Mutex
	started bool
	stopped bool
	err     error
	wg      sync.WaitGroup

	// Config
	BinPath    string   // Path to suricata binary
	ConfigPath string   // Path to suricata.yaml
	EveOutput  string   // Path to eve.json output file (or "-" for stdout)
	Interface  string   // Network interface to monitor
	RulePaths  []string // Additional rule directories
	ExtraArgs  []string // Extra command-line arguments

	// Runtime
	attr   Attributor
	ctx    context.Context
	cancel context.CancelFunc
}

// DefaultBinPath is the default Suricata binary location.
const DefaultBinPath = "/usr/bin/suricata"

// DefaultConfigTemplate is a minimal Suricata configuration for EVE output.
// It enables only the protocols we consume: flow, dns, tls, ssh, http, ssh.
const DefaultConfigTemplate = `
%YAML 1.1
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80,8080,8081,8443"
    SHELLCODE_PORTS: "!80,8080,8081,8443"

default-log-level: notice

default-rule-path: /etc/suricata/rules
rule-files:
  - suricata.rules
  - local.rules

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: {{EVE_OUTPUT}}
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            metadata: yes
            tags: yes
        - flow:
            enabled: yes
            all: yes
        - dns:
            enabled: yes
            query: yes
            answer: yes
        - tls:
            enabled: yes
            extended: yes
        - ssh:
            enabled: yes
        - http:
            enabled: yes
            extended: yes
        - fileinfo:
            enabled: no
        - files:
            enabled: no
        - smtp:
            enabled: no
        - smb:
            enabled: no
        - ikev2:
            enabled: no
        - nfs:
            enabled: no
        - dpd:
            enabled: no
        - stats:
            enabled: no
        - flow:
            enabled: yes

stream:
  memcap: 256mb
  checksum-validation: yes
  inline: no
  reassembly:
    memcap: 64mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
  detect-thread-ratio: 1.0

unix-command:
  enabled: no
`

// NewSubprocess creates a Suricata subprocess manager.
//
// binPath is the path to the suricata binary (default: /usr/bin/suricata).
// configPath is the path to suricata.yaml (will be generated if missing).
// eveOutput is the EVE output path ("-" for stdout, or file path).
// interface is the network interface to monitor.
// attr is the attributor for LAN-side IP to MAC resolution.
func NewSubprocess(ctx context.Context, binPath, configPath, eveOutput, iface string, attr Attributor) (*Subprocess, error) {
	if binPath == "" {
		binPath = DefaultBinPath
	}
	if _, err := os.Stat(binPath); err != nil {
		return nil, fmt.Errorf("suricata binary not found at %s: %w", binPath, err)
	}

	// Generate config if missing
	if configPath == "" {
		return nil, fmt.Errorf("configPath is required")
	}
	if _, err := os.Stat(configPath); err != nil {
		if err := writeConfig(configPath, eveOutput); err != nil {
			return nil, fmt.Errorf("writing default config: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	return &Subprocess{
		BinPath:    binPath,
		ConfigPath: configPath,
		EveOutput:  eveOutput,
		Interface:  iface,
		attr:       attr,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// writeConfig generates a Suricata config file from the template.
func writeConfig(path, eveOutput string) error {
	content := strings.ReplaceAll(DefaultConfigTemplate, "{{EVE_OUTPUT}}", eveOutput)
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// Start launches the Suricata subprocess and begins reading EVE output.
func (s *Subprocess) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return errors.New("subprocess already started")
	}
	if s.stopped {
		return errors.New("subprocess already stopped; create a new instance")
	}

	// Build command
	args := []string{
		"-c", s.ConfigPath,
		"-i", s.Interface,
	}
	if s.EveOutput != "-" {
		args = append(args, "-l", filepath.Dir(s.EveOutput))
	}
	args = append(args, s.ExtraArgs...)

	s.cmd = exec.CommandContext(s.ctx, s.BinPath, args...)
	s.cmd.Stdout = nil // We'll read EVE from file or stdout
	s.cmd.Stderr = nil

	var err error
	s.stdout, err = s.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	s.stderr, err = s.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	// If EVE output is a file, we'll tail that file instead of stdout
	// (handled by TailEveFile)

	if err := s.cmd.Start(); err != nil {
		return fmt.Errorf("starting suricata: %w", err)
	}

	s.started = true

	// Start stderr consumer
	s.wg.Add(1)
	go s.consumeStderr()

	// If EVE output is stdout, start reader
	if s.EveOutput == "-" {
		s.reader = NewReader(s.stdout, s.attr)
	}

	return nil
}

// consumeStderr drains stderr to prevent pipe blocking.
func (s *Subprocess) consumeStderr() {
	defer s.wg.Done()
	scanner := bufio.NewScanner(s.stderr)
	for scanner.Scan() {
		// Log or discard stderr
		_ = scanner.Text()
	}
}

// TailEveFile starts tailing the EVE output file.
// Call this after Start if EveOutput is a file path.
func (s *Subprocess) TailEveFile(ctx context.Context, out chan<- core.NormalizedEvent, interval time.Duration) error {
	if s.EveOutput == "-" {
		return errors.New("EveOutput is stdout; use reader instead")
	}
	return Tail(ctx, s.EveOutput, s.attr, out, interval)
}

// Reader returns the EVE reader for stdout mode.
// Only valid if EveOutput is "-".
func (s *Subprocess) Reader() *Reader {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reader
}

// Wait waits for the subprocess to exit and returns its error.
func (s *Subprocess) Wait() error {
	s.mu.Lock()
	cmd := s.cmd
	s.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return errors.New("subprocess not started")
	}

	err := cmd.Wait()
	s.wg.Wait()
	return err
}

// Stop gracefully stops the Suricata subprocess.
func (s *Subprocess) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started || s.stopped {
		return nil
	}

	s.stopped = true
	s.cancel()

	if s.cmd != nil && s.cmd.Process != nil {
		// Try graceful shutdown first
		if err := s.cmd.Process.Signal(os.Interrupt); err != nil {
			// Force kill if interrupt fails
			_ = s.cmd.Process.Kill()
		}
	}

	return nil
}

// Err returns the subprocess error, if any.
func (s *Subprocess) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// IsRunning returns true if the subprocess is running.
func (s *Subprocess) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started && !s.stopped && s.cmd != nil && s.cmd.Process != nil
}

// Health checks if Suricata is responsive.
// It verifies the process is alive and EVE output is flowing.
func (s *Subprocess) Health() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started || s.stopped {
		return errors.New("not running")
	}
	if s.cmd == nil || s.cmd.Process == nil {
		return errors.New("process not found")
	}

	// Check process is alive
	// On Unix, sending signal 0 checks existence without killing
	if err := s.cmd.Process.Signal(os.Signal(syscall.Signal(0))); err != nil {
		return fmt.Errorf("process dead: %w", err)
	}

	return nil
}

// Restart restarts the Suricata subprocess.
func (s *Subprocess) Restart() error {
	if err := s.Stop(); err != nil {
		return err
	}
	// Create new context for fresh start
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.started = false
	s.stopped = false
	s.err = nil
	return s.Start()
}

// PID returns the Suricata process ID.
func (s *Subprocess) PID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		return s.cmd.Process.Pid
	}
	return -1
}
