package core

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

// DeviceClass categorizes a device by its likely role on the managed network.
// Classification drives suppression: an inference-engine signature on a
// workstation is expected, on a security camera it is not.
type DeviceClass string

const (
	ClassUnknown     DeviceClass = "unknown"
	ClassWorkstation DeviceClass = "workstation"
	ClassServer      DeviceClass = "server"
	ClassIoT         DeviceClass = "iot"
	ClassAppliance   DeviceClass = "appliance"
	ClassCamera      DeviceClass = "camera"
	ClassTV          DeviceClass = "tv"
	ClassMobile      DeviceClass = "mobile"
)

// ContainmentState is a device's current restriction level.
type ContainmentState string

const (
	// ContainmentMonitor logs and scores only. It is the default for a
	// fresh installation and it affects no traffic.
	ContainmentMonitor ContainmentState = "monitor"
	// ContainmentRestricted blocks peer-to-peer LAN traffic while leaving
	// internet access unrestricted. This is the tier that most directly
	// drives R0 below one.
	ContainmentRestricted ContainmentState = "restricted"
	// ContainmentQuarantined blocks peer traffic and restricts egress to a
	// walled garden. It corresponds to the ISP remediation model that
	// cleared 92% of Mirai infections in 14 days.
	ContainmentQuarantined ContainmentState = "quarantined"
)

// Policy describes what a given ContainmentState actually does to a device.
type Policy struct {
	Name             ContainmentState
	BlockPeers       bool
	RestrictEgress   bool
	RequirePortalAck bool
}

var (
	// PolicyMonitor affects no traffic.
	PolicyMonitor = Policy{
		Name: ContainmentMonitor,
	}
	// PolicyRestrict blocks lateral movement, which is what terminates
	// propagation. Internet access is left alone so that cloud-dependent
	// devices keep working.
	PolicyRestrict = Policy{
		Name:       ContainmentRestricted,
		BlockPeers: true,
	}
	// PolicyQuarantine additionally restricts egress to a walled garden of
	// vendor patch servers, so the device can be remediated but not used to
	// propagate.
	PolicyQuarantine = Policy{
		Name:             ContainmentQuarantined,
		BlockPeers:       true,
		RestrictEgress:   true,
		RequirePortalAck: true,
	}
)

// PolicyFor returns the Policy implementing a ContainmentState.
// An unrecognized state falls back to monitor, so a corrupt persisted value
// can never result in a device being locked out with no route to recovery.
func PolicyFor(s ContainmentState) Policy {
	switch s {
	case ContainmentRestricted:
		return PolicyRestrict
	case ContainmentQuarantined:
		return PolicyQuarantine
	default:
		return PolicyMonitor
	}
}

// Device is the persistent identity of a host on the managed network.
type Device struct {
	MAC         net.HardwareAddr
	IPs         []netip.Addr
	Vendor      string
	Class       DeviceClass
	FirstSeen   time.Time
	LastSeen    time.Time
	RiskScore   float64
	Containment ContainmentState
	Notes       []string
}

// EventKind identifies what a NormalizedEvent represents.
type EventKind string

const (
	EventFlow      EventKind = "flow"
	EventDNSQuery  EventKind = "dns_query"
	EventDNSAnswer EventKind = "dns_answer"
	EventTLS       EventKind = "tls"
	EventSSHAuth   EventKind = "ssh_auth"
	EventInventory EventKind = "inventory"
)

// Endpoint is one side of an observed interaction. Fields that do not apply
// to the event kind are left zero, so a DNS query has Dst.Host set and no
// meaningful port, and a flow has both IP and port.
type Endpoint struct {
	IP   netip.Addr
	Port uint16
	Host string
}

// NormalizedEvent is the single shape every ingest path produces.
//
// Detectors accept only this type. Decoupling here means a Suricata upgrade
// that reorganizes EVE fields costs one adapter change rather than nine, and
// a second telemetry source can be added without touching any detector.
type NormalizedEvent struct {
	Time     time.Time
	Kind     EventKind
	Src      Endpoint
	Dst      Endpoint
	Bytes    int64
	Duration time.Duration

	// SNI is the TLS server name, when observed.
	SNI string
	// QueryName is the DNS question name, when Kind is a DNS event.
	QueryName string
	// AuthUser is the authenticated principal, when Kind is EventSSHAuth.
	AuthUser string
	// DeviceMAC is the LAN-side device attributable to this event. It is
	// zero for events where the origin cannot be attributed, such as pure
	// inbound traffic.
	DeviceMAC net.HardwareAddr

	// Raw holds the original source fields for debugging. It is deliberately
	// untyped; detectors that reach into it give up compile-time safety and
	// must be reviewed accordingly.
	Raw map[string]any
}

// SignalClass separates signals that a replicator cannot avoid producing
// from signals that merely reflect how current research prototypes behave.
// The distinction is not cosmetic: proof-of-concept artifacts are exactly
// what an evasive adversary would stop producing.
type SignalClass string

const (
	// SignalReplicationRequired marks a behavior inherent to weight-based
	// replication itself. These should hold against an evasive adversary.
	SignalReplicationRequired SignalClass = "replication_required"
	// SignalPoCArtifact marks a behavior observed in research prototypes
	// that a motivated adversary could eliminate.
	SignalPoCArtifact SignalClass = "poc_artifact"
)

// SignalKind identifies which detector produced a Signal.
type SignalKind string

const (
	SignalWeightTransfer  SignalKind = "R1"
	SignalModelHostOnIoT  SignalKind = "R2"
	SignalInferenceEngine SignalKind = "R3"
	SignalEastWestVolume  SignalKind = "R4"
	SignalBurst           SignalKind = "R5"
	SignalAuthFanout      SignalKind = "R6"
	SignalDNSDrift        SignalKind = "R7"
	SignalNewDevice       SignalKind = "R8"
	SignalBeacon          SignalKind = "R9"
)

// Signal is a detector's finding about a device.
//
// Weight and Confidence are distinct on purpose. Weight contributes to the
// risk score; Confidence records how sure the detector is that the behavior
// is what it claims to be. A high-weight, low-confidence signal should
// accumulate score without ever crossing an action threshold on its own.
type Signal struct {
	Kind       SignalKind
	Class      SignalClass
	DeviceMAC  net.HardwareAddr
	Weight     float64
	Confidence float64
	Reason     string
	Evidence   map[string]any
}

// Detector is a pure function over normalized telemetry. Implementations
// must not perform I/O, read the clock, or touch global state. That
// constraint is what makes the test suite runnable with no hardware.
type Detector interface {
	Kind() SignalKind
	Evaluate(NormalizedEvent) []Signal
}

// IoCType categorizes the type of indicator of compromise.
type IoCType string

const (
	IoCTypeMalwareDownload   IoCType = "malware_download"
	IoCTypeConnectionAttempt IoCType = "connection_attempt"
	IoCTypeAuthAttempt       IoCType = "auth_attempt"
	IoCTypeCommandExecution  IoCType = "command_execution"
	IoCTypeC2Callback        IoCType = "c2_callback"
	IoCTypeDataExfil         IoCType = "data_exfiltration"
)

// IoC is an indicator of compromise with provenance tracking.
//
// Each IoC carries a provenance tag identifying its source (suricata, cowrie,
// dionaea, feeds, etc.) so that downstream consumers can apply different
// trust levels or suppression rules based on source reliability.
type IoC struct {
	Source    string    // Provenance: "suricata", "cowrie", "dionaea", "feeds", etc.
	Timestamp time.Time // When the IoC was observed
	Type      IoCType   // Classification of the indicator
	SrcIP     netip.Addr
	SrcPort   uint16
	DstIP     netip.Addr
	DstPort   uint16
	Protocol  string

	// For file-based IoCs
	URL    string
	SHA256 string
	MD5    string

	// Tags for categorization and suppression
	Tags     []string
	Evidence map[string]any
}

// ToSignal converts an IoC to a Signal for the risk engine.
//
// The Signal is constructed with the appropriate kind, class, weight, and confidence
// based on the IoC type and source. Returns nil if the IoC cannot be converted
// to a signal (e.g., missing required fields).
func (i IoC) ToSignal() *Signal {
	// Map IoCType to SignalKind and SignalClass
	var kind SignalKind
	var class SignalClass
	var weight float64
	var confidence float64
	var reason string

	switch i.Type {
	case IoCTypeMalwareDownload:
		kind = SignalWeightTransfer
		class = SignalReplicationRequired
		weight = 35
		confidence = 0.7
		reason = fmt.Sprintf("malware download from %s (SHA256: %s)", i.URL, i.SHA256)
	case IoCTypeConnectionAttempt:
		kind = SignalModelHostOnIoT
		class = SignalReplicationRequired
		weight = 20
		confidence = 0.6
		reason = fmt.Sprintf("connection to model-hosting endpoint %s", i.URL)
	case IoCTypeAuthAttempt:
		kind = SignalAuthFanout
		class = SignalReplicationRequired
		weight = 28
		confidence = 0.65
		reason = fmt.Sprintf("authentication fan-out attempt")
	case IoCTypeCommandExecution:
		kind = SignalInferenceEngine
		class = SignalPoCArtifact
		weight = 15
		confidence = 0.5
		reason = fmt.Sprintf("command execution detected")
	case IoCTypeC2Callback:
		kind = SignalBeacon
		class = SignalPoCArtifact
		weight = 8
		confidence = 0.35
		reason = fmt.Sprintf("periodic beaconing on port %d", i.DstPort)
	case IoCTypeDataExfil:
		kind = SignalEastWestVolume
		class = SignalReplicationRequired
		weight = 25
		confidence = 0.6
		reason = fmt.Sprintf("sustained east-west volume")
	default:
		return nil
	}

	return &Signal{
		Kind:       kind,
		Class:      class,
		DeviceMAC:  net.HardwareAddr{}, // Will be set by caller
		Weight:     weight,
		Confidence: confidence,
		Reason:     reason,
		Evidence:   i.Evidence,
	}
}

// IoCFeed is an interface for consuming IoCs from various sources.
type IoCFeed interface {
	// Next returns the next IoC. Returns false at end of input or on error.
	Next() (IoC, bool)
	// Err returns any error encountered during iteration.
	Err() error
}

// IoCProcessor processes IoCs from feeds into the risk engine.
type IoCProcessor interface {
	// Ingest adds an IoC to the risk engine, returning the affected device MAC
	// and whether the IoC was actionable.
	Ingest(IoC) (net.HardwareAddr, bool)
	// Flush commits any pending IoCs.
	Flush() error
}
