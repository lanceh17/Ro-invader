package cowrie

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// CowrieLogEntry represents a single Cowrie JSON log entry.
// See https://github.com/cowrie/cowrie/blob/master/docs/LOGGING.md
type CowrieLogEntry struct {
	EventID   string `json:"eventid"`
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DstIP     string `json:"dst_ip"`
	DstPort   int    `json:"dst_port"`
	Protocol  string `json:"protocol"`

	// SSH-specific
	Username string `json:"username"`
	Password string `json:"password"`

	// File download
	URL      string `json:"url"`
	Shasum   string `json:"shasum"`
	Filepath string `json:"filepath"`

	// Session
	Session  string  `json:"session"`
	Duration float64 `json:"duration"`

	// Input
	Input string `json:"input"`

	// Raw event data for extensibility
	Raw json.RawMessage `json:"-"`
}

// ParseLogLine parses a single line of Cowrie JSON log output.
func ParseLogLine(line []byte) (CowrieLogEntry, bool) {
	var entry CowrieLogEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return CowrieLogEntry{}, false
	}
	// Store raw for debugging
	entry.Raw = line
	return entry, true
}

// ToIoC converts a Cowrie log entry into an Indicator of Compromise (IoC)
// with provenance tag "cowrie".
func (e CowrieLogEntry) ToIoC() (core.IoC, bool) {
	ts, err := time.Parse(time.RFC3339, strings.TrimSuffix(e.Timestamp, "Z"))
	if err != nil {
		ts = time.Now()
	}

	srcIP, err := netip.ParseAddr(e.SrcIP)
	if err != nil {
		return core.IoC{}, false
	}

	ioc := core.IoC{
		Source:    "cowrie",
		Timestamp: ts,
		SrcIP:     srcIP,
		SrcPort:   uint16(e.SrcPort),
		Protocol:  strings.ToLower(e.Protocol),
		Tags:      []string{},
		Evidence:  map[string]any{},
	}

	switch e.EventID {
	case "cowrie.session.connect":
		ioc.Type = core.IoCTypeConnectionAttempt
		ioc.Tags = append(ioc.Tags, "connection", "ssh")
		ioc.Evidence["session"] = e.Session

	case "cowrie.login.success", "cowrie.login.failed":
		ioc.Type = core.IoCTypeAuthAttempt
		ioc.Tags = append(ioc.Tags, "auth", "ssh", "credential-reuse")
		ioc.Evidence["username"] = e.Username
		ioc.Evidence["password"] = e.Password
		ioc.Evidence["success"] = e.EventID == "cowrie.login.success"
		ioc.Evidence["session"] = e.Session

	case "cowrie.session.file_download":
		ioc.Type = core.IoCTypeMalwareDownload
		ioc.Tags = append(ioc.Tags, "malware", "download", "payload")
		ioc.URL = e.URL
		ioc.SHA256 = e.Shasum
		ioc.Evidence["filepath"] = e.Filepath
		ioc.Evidence["session"] = e.Session

	case "cowrie.session.input":
		ioc.Type = core.IoCTypeCommandExecution
		ioc.Tags = append(ioc.Tags, "command", "shell")
		ioc.Evidence["input"] = e.Input
		ioc.Evidence["session"] = e.Session

	case "cowrie.session.closed":
		ioc.Type = core.IoCTypeConnectionAttempt
		ioc.Tags = append(ioc.Tags, "connection", "ssh", "closed")
		ioc.Evidence["session"] = e.Session
		ioc.Evidence["duration"] = e.Duration

	default:
		return core.IoC{}, false
	}

	return ioc, true
}
