package dionaea

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
)

// Subprocess manages a Dionaea honeypot subprocess lifecycle.
//
// Dionaea is a multi-protocol honeypot (TFTP, HTTP, SMB, FTP, etc.) that
// captures malware payloads. It is GPL-2.0; we never link it. We consume
// its JSON log output (dionaea.log.json or stdout). This process boundary
// is both the legal boundary and the correct architecture.
type Subprocess struct {
	cmd     *exec.Cmd
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	mu      sync.Mutex
	started bool
	stopped bool
	err     error
	wg      sync.WaitGroup

	// Config
	BinPath    string   // Path to dionaea binary
	ConfigPath string   // Path to dionaea.conf
	LogPath    string   // Path to JSON log file (or "-" for stdout)
	WorkDir    string   // Working directory
	ExtraArgs  []string // Extra command-line arguments

	// Runtime
	ctx     context.Context
	cancel  context.CancelFunc
	muLog   sync.Mutex
	logFile *os.File
	logChan chan string
}

// DefaultBinPath is the default Dionaea binary location.
const DefaultBinPath = "/usr/bin/dionaea"

// DefaultConfigTemplate is a minimal Dionaea configuration for JSON logging.
// It enables TFTP, HTTP, and SMB modules with JSON logging.
const DefaultConfigTemplate = `
[modules]
# Enable only the protocols we consume
modules = [ "python", "pcap", "nfq", "curl", "emu", "tftp", "ftp", "smb", "mqtt" ]

[logging]
default_loglevels = "info"
log_file = /var/log/dionaea.log
log_levels = "info,error"
log_domain = "dionaea"

[logging_json]
enabled = true
log_file = {{LOG_PATH}}
format = json

[listen]
mode = "auto"
mode = "getifaddrs"
addresses = { eth0 = [ "0.0.0.0" ] }
port = 21,22,23,25,53,80,135,443,445,1433,3306,5060,5061,5900,8080,9000,9001,9002

[modules_python]
script_dir = /opt/dionaea/lib/dionaea/python/
scripts = [ "dionaea.core", "dionaea.log_json" ]

[pcap]
enabled = no

[nfq]
enabled = no

[curl]
enabled = yes

[emu]
enabled = yes
profile = "x86"
limits = 1000000
max_instructions = 10000000

[tftp]
enabled = yes
root = /var/dionaea/tftpboot
upload = yes

[ftp]
enabled = yes
root = /var/dionaea/ftp/
user = ftp
pass = ftp

[smb]
enabled = yes
netbios_name = "DIONAEA"
workgroup = "WORKGROUP"
lanman = yes
netbios = yes
`

// SubprocessConfig holds configuration for the Dionaea subprocess.
type SubprocessConfig struct {
	BinPath    string
	ConfigPath string
	LogPath    string
	WorkDir    string
	Interface  string
	ExtraArgs  []string
}

// Attributor resolves a LAN-side IP to the device that owns it.
type Attributor interface {
	MACFor(ip string) (string, bool)
}

// NewSubprocess creates a Dionaea subprocess manager.
//
// binPath is the path to dionaea binary (default: /usr/bin/dionaea).
// configPath is the path to dionaea.conf (will be generated if missing).
// logPath is the path to JSON log file ("-" for stdout).
// workDir is the working directory.
// attr is the attributor for LAN-side IP to MAC resolution (can be nil).
func NewSubprocess(ctx context.Context, config SubprocessConfig) (*Subprocess, error) {
	if config.BinPath == "" {
		config.BinPath = "/usr/bin/dionaea"
	}
	if config.WorkDir == "" {
		return nil, fmt.Errorf("WorkDir is required (Dionaea installation directory)")
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
		BinPath:    config.BinPath,
		ConfigPath: config.ConfigPath,
		LogPath:    config.LogPath,
		WorkDir:    config.WorkDir,
		ctx:        ctx,
		cancel:     cancel,
		logChan:    make(chan string, 100),
	}, nil
}

// writeConfig generates a Dionaea config file from the template.
func writeConfig(path, logPath string) error {
	content := strings.ReplaceAll(DefaultConfigTemplate, "{{LOG_PATH}}", logPath)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// Start launches the Dionaea subprocess.
func (s *Subprocess) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return errors.New("subprocess already started")
	}
	if s.stopped {
		return errors.New("subprocess already stopped; create a new instance")
	}

	args := []string{
		"-c", s.ConfigPath,
		"-l", s.LogPath,
		"-D", // daemonize
	}

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
		return fmt.Errorf("starting dionaea: %w", err)
	}

	s.started = true

	s.wg.Add(1)
	go s.consumeStderr()

	return nil
}

func (s *Subprocess) consumeStderr() {
	defer s.wg.Done()
	scanner := bufio.NewScanner(s.stderr)
	for scanner.Scan() {
		_ = scanner.Text()
	}
}

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

func (s *Subprocess) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started || s.stopped {
		return nil
	}

	s.stopped = true
	s.cancel()

	if s.cmd != nil && s.cmd.Process != nil {
		if err := s.cmd.Process.Signal(os.Interrupt); err != nil {
			_ = s.cmd.Process.Kill()
		}
	}

	return nil
}

func (s *Subprocess) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Subprocess) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started && !s.stopped && s.cmd != nil && s.cmd.Process != nil
}

func (s *Subprocess) Health() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started || s.stopped {
		return errors.New("not running")
	}
	if s.cmd == nil || s.cmd.Process == nil {
		return errors.New("process not found")
	}

	if err := s.cmd.Process.Signal(os.Signal(syscall.Signal(0))); err != nil {
		return fmt.Errorf("process dead: %w", err)
	}

	return nil
}

func (s *Subprocess) PID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		return s.cmd.Process.Pid
	}
	return -1
}

func (s *Subprocess) Restart() error {
	if err := s.Stop(); err != nil {
		return err
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.started = false
	s.stopped = false
	s.err = nil
	return s.Start()
}
