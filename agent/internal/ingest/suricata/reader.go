package suricata

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// maxEVLineBytes bounds a single EVE record.
//
// This must be raised well above bufio.Scanner's 64 KB default. Suricata emits
// fileinfo and http records carrying full metadata, and a single line can
// exceed the default comfortably. When the default is hit, Scanner aborts with
// ErrTooLong and the ingest loop silently stops consuming telemetry from that
// point forward — a failure mode that looks exactly like "everything is fine,
// no threats" and is therefore the worst possible place to be wrong.
const maxEVLineBytes = 16 << 20 // 16 MiB

// Reader consumes EVE records from a stream and yields normalized events.
//
// It accepts any io.Reader, which means the same code path handles a static
// file for tests and a live unix socket or fifo in production. That is
// deliberate: the production path is then covered by the test path.
type Reader struct {
	scanner *bufio.Scanner
	attr    Attributor
	err     error
}

// NewReader returns a Reader over r, attributing LAN-side addresses through
// attr. A nil attributor is permitted and yields events with no DeviceMAC,
// which every detector treats as unattributable.
func NewReader(r io.Reader, attr Attributor) *Reader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxEVLineBytes)
	return &Reader{scanner: sc, attr: attr}
}

// Next returns the next normalized event. It returns false at end of input or
// on error; check Err to distinguish the two. Lines that do not decode are
// skipped rather than failing the stream, because a single malformed record
// must not stop telemetry ingest for the rest of the network's lifetime.
func (r *Reader) Next() (core.NormalizedEvent, bool) {
	for r.scanner.Scan() {
		line := r.scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		rec, ok := UnmarshalRecord(line)
		if !ok {
			continue
		}
		ev, ok := Normalize(rec, r.attr)
		if !ok {
			continue
		}
		return ev, true
	}
	if err := r.scanner.Err(); err != nil {
		r.err = fmt.Errorf("suricata eve: reading stream: %w", err)
	}
	return core.NormalizedEvent{}, false
}

// Err reports the terminal stream error, if any.
func (r *Reader) Err() error { return r.err }

// ReadAll drains a reader. Used by tests and by any batch import path.
func ReadAll(rd io.Reader, attr Attributor) ([]core.NormalizedEvent, error) {
	r := NewReader(rd, attr)
	var out []core.NormalizedEvent
	for {
		ev, ok := r.Next()
		if !ok {
			break
		}
		out = append(out, ev)
	}
	return out, r.Err()
}

// ErrTruncated indicates the observed file shrank, which means it was
// rotated or truncated underneath us and the read offset must be reset.
var ErrTruncated = errors.New("suricata eve: file truncated")

// Tail follows path, emitting normalized events to out until ctx is
// cancelled.
//
// Suricata rotates eve.json on a schedule. A tail that does not detect
// rotation will block forever at the old offset while new telemetry piles up
// in the new file, which is silent and permanent. This implementation
// detects truncation by observing the size drop below the recorded offset and
// reopens from the beginning, which covers both a truncate-in-place rotation
// and a rename-and-recreate rotation.
//
// The offset deliberately does not resume from the exact byte after the last
// record. On rotation it restarts from zero, which can duplicate a small
// window of already-processed records. Duplicated events inflate a risk
// score slightly; lost events mean a missed detection, and of the two failure
// modes only one is dangerous.
func Tail(ctx context.Context, path string, attr Attributor, out chan<- core.NormalizedEvent, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Second
	}

	var (
		f      *os.File
		offset int64
	)

	open := func() error {
		if f != nil {
			_ = f.Close()
			f = nil
		}
		nf, err := os.Open(path)
		if err != nil {
			return err
		}
		f = nf
		// On reopen after truncation, start from the beginning so that no
		// records written between the truncation and our observation of it
		// are skipped.
		offset = 0
		return nil
	}

	if err := open(); err != nil {
		return fmt.Errorf("suricata eve: opening %s: %w", path, err)
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		info, err := f.Stat()
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("suricata eve: stat: %w", err)
			}
			// Rotated away entirely; wait for the replacement to appear.
			continue
		}

		size := info.Size()
		if size < offset {
			// Truncated or replaced. Restart from the top.
			_ = f.Close()
			f = nil
			if err := open(); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return fmt.Errorf("suricata eve: reopening after truncation: %w", err)
			}
			continue
		}

		if size == offset {
			continue
		}

		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return fmt.Errorf("suricata eve: seek: %w", err)
		}

		// Read complete, newline-terminated records only.
		//
		// bufio.Scanner (via ScanLines) hands back a trailing unterminated
		// line at EOF as if it were complete. A record being written while we
		// tick would therefore be split: the first fragment is consumed and
		// discarded as malformed JSON, the offset advances past it, and the
		// remainder is read from the middle of the record on the next pass —
		// losing it silently. ReadBytes leaves any unterminated tail for the
		// next tick instead, so a record split across ticks survives.
		br := bufio.NewReader(f)
		consumed := int64(0)
		for {
			line, err := br.ReadBytes('\n')
			if len(line) == 0 {
				break
			}
			if err != nil {
				// Either io.EOF on an unterminated tail or a genuine read
				// error. In both cases the bytes are not a complete record,
				// so they are not consumed and the offset does not advance
				// past them.
				break
			}

			// A complete record. Account for its bytes before processing, so
			// that a record which fails to normalize is still consumed and
			// does not stall the stream by being re-read forever.
			consumed += int64(len(line))

			rec, ok := UnmarshalRecord(bytes.TrimRight(line, "\r\n"))
			if !ok {
				continue
			}
			ev, ok := Normalize(rec, attr)
			if !ok {
				continue
			}
			select {
			case out <- ev:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		offset += consumed
	}
}
