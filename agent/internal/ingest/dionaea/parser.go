package dionaea

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// DionaeaLogEntry represents a single Dionaea JSON log entry.
// See https://github.com/DinoTools/dionaea
type DionaeaLogEntry struct {
	Timestamp  string             `json:"timestamp"`
	Connection *DionaeaConnection `json:"connection,omitempty"`
	Module     string             `json:"module,omitempty"`

	// Download events
	Download *DionaeaDownload `json:"download,omitempty"`

	// Module-specific
	Offer   *DionaeaOffer   `json:"offer,omitempty"`
	Request *DionaeaRequest `json:"request,omitempty"`

	// Raw event data
	Raw json.RawMessage `json:"-"`
}

type DionaeaConnection struct {
	Protocol   string `json:"protocol"`
	Transport  string `json:"transport"`
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
}

type DionaeaDownload struct {
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	MD5      string `json:"md5"`
	FilePath string `json:"filepath"`
	Size     int64  `json:"size"`
}

type DionaeaOffer struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
}

type DionaeaRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// ParseLogLine parses a single line of Dionaea JSON log output.
func ParseLogLine(line []byte) (DionaeaLogEntry, bool) {
	var entry DionaeaLogEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return DionaeaLogEntry{}, false
	}
	entry.Raw = line
	return entry, true
}

// ToIoC converts a Dionaea log entry into an Indicator of Compromise (IoC)
// with provenance tag "dionaea".
func (e DionaeaLogEntry) ToIoC() (core.IoC, bool) {
	ts, err := time.Parse(time.RFC3339, strings.TrimSuffix(e.Timestamp, "Z"))
	if err != nil {
		ts = time.Now()
	}

	var srcIP netip.Addr
	if e.Connection != nil {
		srcIP, _ = netip.ParseAddr(e.Connection.RemoteIP)
	}
	if srcIP.IsUnspecified() {
		return core.IoC{}, false
	}

	ioc := core.IoC{
		Source:    "dionaea",
		Timestamp: ts,
		SrcIP:     srcIP,
		Protocol:  strings.ToLower(e.Connection.Transport),
		Tags:      []string{},
		Evidence:  map[string]any{},
	}

	if e.Connection != nil {
		ioc.SrcPort = uint16(e.Connection.RemotePort)
		ioc.DstPort = uint16(e.Connection.LocalPort)
		dstIP, _ := netip.ParseAddr(e.Connection.LocalIP)
		ioc.DstIP = dstIP
		ioc.Evidence["local_ip"] = e.Connection.LocalIP
		ioc.Evidence["local_port"] = e.Connection.LocalPort
	}

	if e.Download != nil {
		ioc.Type = core.IoCTypeMalwareDownload
		ioc.Tags = append(ioc.Tags, "malware", "download", "payload")
		ioc.URL = e.Download.URL
		ioc.SHA256 = e.Download.SHA256
		ioc.MD5 = e.Download.MD5
		ioc.Evidence["filepath"] = e.Download.FilePath
		ioc.Evidence["size"] = e.Download.Size
	}

	if e.Module != "" {
		ioc.Tags = append(ioc.Tags, "module:"+e.Module)
		ioc.Evidence["module"] = e.Module
	}

	if e.Offer != nil {
		ioc.Type = core.IoCTypeConnectionAttempt
		ioc.Tags = append(ioc.Tags, "offer", e.Offer.Protocol)
		ioc.Evidence["offer_port"] = e.Offer.Port
		ioc.Evidence["offer_service"] = e.Offer.Service
	}

	if e.Request != nil {
		ioc.Type = core.IoCTypeCommandExecution
		ioc.Tags = append(ioc.Tags, "http", "request")
		ioc.Evidence["method"] = e.Request.Method
		ioc.Evidence["path"] = e.Request.Path
		ioc.Evidence["headers"] = e.Request.Headers
	}

	return ioc, true
}
