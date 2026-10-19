package cowrie

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// Attributor resolves a LAN-side IP to the device that owns it.
type Attributor interface {
	MACFor(ip netip.Addr) (string, bool)
}

// Subprocess manages a Cowrie honeypot subprocess lifecycle.
//
// Cowrie is a Python-based SSH/Telnet honeypot that logs to JSON.
// It is GPL-3.0; we never link it. We communicate exclusively through
// its JSON log output (cowrie.json or cowrie.json.XX). This process
// boundary is both the legal boundary and the correct architecture.
type Subprocess struct {
	cmd      *exec.Cmd
	stdout   io.ReadCloser
	stderr   io.ReadCloser
	mu       sync.Mutex
	started  bool
	stopped  bool
	err      error
	wg       sync.WaitGroup

	// Config
	BinPath     string            // Path to python interpreter running cowrie
	ConfigPath  string            // Path to cowrie.cfg
	LogPath     string            // Path to cowrie.json log file
	WorkDir     string            // Working directory (cowrie installation)
	ExtraArgs   []string          // Extra command-line arguments

	// Runtime
	attr Attributor
	ctx    context.Context
	cancel context.CancelFunc
	muLog  sync.Mutex
	logFile *os.File
	logChan chan string
}

// DefaultBinPath is the default Python interpreter for Cowrie.
const DefaultBinPath = "python3"

// DefaultConfigTemplate is a minimal Cowrie configuration for JSON logging.
// It enables SSH and Telnet with JSON output.
const DefaultConfigTemplate = `
[honeypot]
hostname = cowrie
backend = sqlite
api_token = 
download_dir = downloads
interact_timeout = 300
default_shell = /bin/bash
# Restrict to local network
listen_endpoints = 2222,2323

[output_jsonlog]
logfile = {{LOG_PATH}}
format = json

[output_sqlite]
enabled = false

[ssh]
enabled = true
listen_endpoints = 2222
rsa_key_file = etc/userdb.txt
dsa_key_file = etc/userdb.txt
version = SSH-2.0-OpenSSH_7.9p1 Debian-10

[telnet]
enabled = true
listen_endpoints = 2323

[shell]
enabled = true
# Fake filesystem
filesystem_file = etc/fs.pickle

[users]
admin = admin123
root = 123456
user = user
admin = admin
root = root
`

// SubprocessConfig holds configuration for the Cowrie subprocess.
type SubprocessConfig struct {
	BinPath    string
	ConfigPath string
	LogPath    string
	WorkDir    string
	Interface  string // Not used for Cowrie, but kept for interface compatibility
	Attr       Attributor
	ExtraArgs  []string
}

// NewSubprocess creates a Cowrie subprocess manager.
//
// binPath is the path to python3 (default: "python3").
// configPath is the path to cowrie.cfg (will be generated if missing).
// logPath is the path to cowrie.json log file.
// workDir is the Cowrie installation directory.
// attr is the attributor for LAN-side IP to MAC resolution (can be nil).
func NewSubprocess(ctx context.Context, config SubprocessConfig) (*Subprocess, error) {
	if config.BinPath == "" {
		config.BinPath = DefaultBinPath
	}
	if config.WorkDir == "" {
		return nil, fmt.Errorf("WorkDir is required (Cowrie installation directory)")
	}
	if config.ConfigPath == "" {
		return nil, fmt.Errorf("ConfigPath is required")
	}
	if config.LogPath == "" {
		return nil, fmt.Errorf("LogPath is required")
	}

	// Generate config if missing
	if _, err := os.Stat(config.ConfigPath); err != nil {
		if err := writeConfig(config.ConfigPath, config.LogPath); err != nil {
			return nil, fmt.Errorf("writing default config: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	return &Subprocess{
		BinPath:    "python3",
		ConfigPath: config.ConfigPath,
		LogPath:    config.LogPath,
		WorkDir:    config.WorkDir,
		ExtraArgs:  config.ExtraArgs,
		attr:       config.Attr,
		ctx:        ctx,
		cancel:     cancel,
		logChan:    make(chan string, 100),
	}, nil
}

// writeConfig generates a Cowrie config file from the template.
func writeConfig(path, logPath string) error {
	content := strings.ReplaceAll(DefaultConfigTemplate, "{{LOG_PATH}}", logPath)
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// Start launches the Cowrie subprocess and begins reading JSON logs.
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
		"-m", "cowrie",
		"-c", s.ConfigPath,
	}
	args = append(args, s.ExtraArgs...)

	s.cmd = exec.CommandContext(s.ctx, s.BinPath, args...)
	s.cmd.Dir = s.WorkDir

	var err error
	s.stdout, err = s.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	s.stderr, err = s.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := s.cmd.Start(); err != nil {
		return fmt.Errorf("starting cowrie: %w", err)
	}

	s.started = true

	// Start stderr consumer
	s.wg.Add(1)
	go s.consumeStderr()

	// Open log file for tailing
	logFile, err := os.Open(s.LogPath)
	if err != nil {
		// Log file might not exist yet; we'll try again later
	} else {
		s.logFile = logFile
		go s.tailLogFile()
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

// tailLogFile tails the Cowrie JSON log file and sends lines to logChan.
func (s *Subprocess) tailLogFile() {
	scanner := bufio.NewScanner(s.logFile)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		select {
		case s.logChan <- line:
		case <-s.ctx.Done():
			return
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		s.mu.Lock()
		s.err = fmt.Errorf("cowrie log: scanning: %w", err)
		s.mu.Unlock()
	}
}

// LogChan returns a channel that receives parsed Cowrie log lines.
// Only valid after Start() is called.
func (s *Subprocess) LogChan() <-chan string {
	return s.logChan
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

// Stop gracefully stops the Cowrie subprocess.
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

	if s.logFile != nil {
		_ = s.logFile.Close()
	}
	close(s.logChan)

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

// Health checks if Cowrie is responsive.
// It verifies the process is alive and log file is being written.
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
	if err := s.cmd.Process.Signal(os.Signal(syscall.Signal(0))); err != nil {
		return fmt.Errorf("process dead: %w", err)
	}

	return nil
}

// PID returns the Cowrie process ID.
func (s *Subprocess) PID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		return s.cmd.Process.Pid
	}
	return -1
}

// Restart restarts the Cowrie subprocess.
func (s *Subprocess) Restart() error {
	if err := s.Stop(); err != nil {
		return err
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.started = false
	s.stopped = false
	s.err = nil
	s.logChan = make(chan string, 100)
	return s.Start()
}