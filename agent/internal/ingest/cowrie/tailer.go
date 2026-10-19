package cowrie

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Tailer tails a Cowrie JSON log file and provides a channel of log lines.
type Tailer struct {
	logPath      string
	attr         Attributor
	pollInterval time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
	logFile      *os.File
	logChan      chan string
	mu           sync.Mutex
	stopped      bool
	err          error
	wg           sync.WaitGroup
}

// NewTailer creates a new tailer for a Cowrie JSON log file.
//
// logPath is the path to the cowrie.json log file.
// attr is the attributor for LAN-side IP to MAC resolution (can be nil).
// pollInterval is the interval to check for file rotation (default: 5s).
func NewTailer(ctx context.Context, logPath string, attr Attributor, pollInterval time.Duration) (*Tailer, error) {
	if logPath == "" {
		return nil, errors.New("logPath is required")
	}
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}

	ctx, cancel := context.WithCancel(ctx)
	return &Tailer{
		logPath:      logPath,
		attr:         attr,
		pollInterval: pollInterval,
		ctx:          ctx,
		cancel:       cancel,
		logChan:      make(chan string, 100),
	}, nil
}

// LogChan returns a channel that receives parsed Cowrie log lines.
func (t *Tailer) LogChan() <-chan string {
	return t.logChan
}

// Start begins tailing the log file.
func (t *Tailer) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.stopped {
		return errors.New("tailer already stopped; create a new instance")
	}

	// Open log file
	logFile, err := os.Open(t.logPath)
	if err != nil {
		return fmt.Errorf("opening log file: %w", err)
	}
	t.logFile = logFile

	// Start tailing
	t.wg.Add(1)
	go t.tailLogFile()

	return nil
}

func (t *Tailer) tailLogFile() {
	defer t.wg.Done()

	scanner := bufio.NewScanner(t.logFile)
	for t.ctx.Err() == nil {
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			select {
			case t.logChan <- line:
			case <-t.ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
			t.mu.Lock()
			t.err = fmt.Errorf("cowrie log: scanning: %w", err)
			t.mu.Unlock()
			return
		}

		// Check for file rotation (truncation)
		if fi, err := os.Stat(t.logPath); err == nil {
			if fi.Size() < int64(t.logFileSize()) {
				// File was truncated (rotated), reopen
				_ = t.logFile.Close()
				nf, err := os.Open(t.logPath)
				if err != nil {
					t.mu.Lock()
					t.err = fmt.Errorf("reopening rotated log: %w", err)
					t.mu.Unlock()
					return
				}
				t.logFile = nf
			}
		}
	}
}

func (t *Tailer) logFileSize() int64 {
	if t.logFile == nil {
		return 0
	}
	fi, err := t.logFile.Stat()
	if err != nil {
		return 0
	}
	return fi.Size()
}

// Stop gracefully stops the tailer.
func (t *Tailer) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.stopped {
		return nil
	}

	t.stopped = true
	close(t.logChan)

	if t.logFile != nil {
		_ = t.logFile.Close()
	}

	return nil
}

// Err returns any error that occurred during tailing.
func (t *Tailer) Err() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.err
}

// IsRunning returns true if the tailer is running.
func (t *Tailer) IsRunning() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.stopped
}
