package honeypot

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/ingest/cowrie"
	"github.com/lanceh17/Ro-invader/agent/internal/ingest/dionaea"
	"github.com/lanceh17/Ro-invader/agent/internal/pipeline"
	"github.com/lanceh17/Ro-invader/agent/internal/risk"
)

// HoneypotIngestConfig holds configuration for the honeypot IoC ingestion pipeline.
type HoneypotIngestConfig struct {
	// Cowrie log file path (empty to disable)
	CowrieLogPath string
	// Dionaea log file path (empty to disable)
	DionaeaLogPath string
	// Risk engine to feed IoCs into
	Engine *risk.Engine
	// Device attributor for mapping IPs to MACs
	Attributor pipeline.Attributor
	// Poll interval for log file tailing
	PollInterval time.Duration
	// Cowrie log tailer (set after start)
	CowrieTailer *cowrie.Tailer
	// Dionaea log tailer (set after start)
	DionaeaTailer *dionaea.Tailer
}

// HoneypotIngest manages the honeypot IoC ingestion pipeline.
//
// It tails Cowrie and/or Dionaea JSON log files, parses IoCs, converts them to signals,
// and feeds them into the risk engine for device scoring and containment decisions.
type HoneypotIngest struct {
	cfg     HoneypotIngestConfig
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.Mutex
	started bool
	stopped bool
	err     error
}

// NewHoneypotIngest creates a new honeypot IoC ingestion pipeline.
//
// ctx is the parent context for cancellation.
// cfg contains the configuration for the ingestion pipeline.
func NewHoneypotIngest(ctx context.Context, cfg HoneypotIngestConfig) (*HoneypotIngest, error) {
	if cfg.Engine == nil {
		return nil, errors.New("risk engine is required")
	}
	if cfg.Attributor == nil {
		return nil, errors.New("attributor is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}

	ctx, cancel := context.WithCancel(ctx)
	return &HoneypotIngest{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start begins the honeypot IoC ingestion pipeline.
//
// It starts tailing the Cowrie and/or Dionaea log files and processes
// IoCs as they appear.
func (h *HoneypotIngest) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.started {
		return errors.New("already started")
	}
	if h.stopped {
		return errors.New("already stopped; create a new instance")
	}

	// Start Cowrie tailer if configured
	if h.cfg.CowrieLogPath != "" {
		cowrieTailer, err := cowrie.NewTailer(h.ctx, h.cfg.CowrieLogPath, h.cfg.Attributor, h.cfg.PollInterval)
		if err != nil {
			return fmt.Errorf("starting cowrie tailer: %w", err)
		}
		if err := cowrieTailer.Start(); err != nil {
			return fmt.Errorf("starting cowrie tailer: %w", err)
		}
		h.cfg.CowrieTailer = cowrieTailer
		h.wg.Add(1)
		go h.processCowrieLogs()
	}

	// Start Dionaea tailer if configured
	if h.cfg.DionaeaLogPath != "" {
		dionaeaTailer, err := dionaea.NewTailer(h.ctx, h.cfg.DionaeaLogPath, h.cfg.PollInterval)
		if err != nil {
			return fmt.Errorf("starting dionaea tailer: %w", err)
		}
		if err := dionaeaTailer.Start(); err != nil {
			return fmt.Errorf("starting dionaea tailer: %w", err)
		}
		h.cfg.DionaeaTailer = dionaeaTailer
		h.wg.Add(1)
		go h.processDionaeaLogs()
	}

	h.started = true
	return nil
}

// processCowrieLogs processes Cowrie log entries and feeds IoCs to the risk engine.
func (h *HoneypotIngest) processCowrieLogs() {
	defer h.wg.Done()

	if h.cfg.CowrieTailer == nil {
		return
	}

	for {
		select {
		case <-h.ctx.Done():
			return
		case line, ok := <-h.cfg.CowrieTailer.LogChan():
			if !ok {
				return
			}
			entry, ok := cowrie.ParseLogLine([]byte(line))
			if !ok {
				continue
			}
			ioc, ok := entry.ToIoC()
			if !ok {
				continue
			}
			h.ingestIoC(ioc)
		}
	}
}

// processDionaeaLogs processes Dionaea log entries and feeds IoCs to the risk engine.
func (h *HoneypotIngest) processDionaeaLogs() {
	defer h.wg.Done()

	if h.cfg.DionaeaTailer == nil {
		return
	}

	for {
		select {
		case <-h.ctx.Done():
			return
		case line, ok := <-h.cfg.DionaeaTailer.LogChan():
			if !ok {
				return
			}
			entry, ok := dionaea.ParseLogLine([]byte(line))
			if !ok {
				continue
			}
			ioc, ok := entry.ToIoC()
			if !ok {
				continue
			}
			h.ingestIoC(ioc)
		}
	}
}

// ingestIoC processes a single IoC and feeds it into the risk engine as a signal.
func (h *HoneypotIngest) ingestIoC(ioc core.IoC) {
	// Attribute to device
	if h.cfg.Attributor == nil {
		return
	}
	mac, ok := h.cfg.Attributor.MACFor(ioc.SrcIP)
	if !ok {
		return
	}

	// Convert IoC to a Signal and observe it
	signal := ioc.ToSignal()
	if signal == nil {
		return
	}

	// Set the device MAC on the signal
	signal.DeviceMAC = mac

	// Observe through the risk engine
	h.cfg.Engine.Observe(*signal, ioc.Timestamp)
}

// Stop gracefully stops the honeypot ingestion pipeline.
func (h *HoneypotIngest) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.started || h.stopped {
		return nil
	}

	h.stopped = true
	h.cancel()
	h.wg.Wait()
	return nil
}

// Err returns any error that occurred during ingestion.
func (h *HoneypotIngest) Err() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

// IsRunning returns true if the ingestion pipeline is running.
func (h *HoneypotIngest) IsRunning() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.started && !h.stopped
}
