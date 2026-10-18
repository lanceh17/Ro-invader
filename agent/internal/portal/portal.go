// Package portal is the remediation UI: the page a contained device is shown
// when its lookups are sinkholed, and the release action that puts it back.
//
// Two promises from SAFETY.md shape everything here:
//
//   - "Reversible by a human, always." Quarantine is time-boxed; releasing is
//     a first-class, audited operation, not an edit of a file by hand.
//   - "Its worst action is 'this device cannot reach its peers until a person
//     clicks release.'" So a release button must exist — and because the
//     portal is reachable by the compromised device itself, releases require
//     an operator token that device never sees. A self-service release would
//     be a containment bypass with extra steps.
//
// The handler writes no state outside its own store: releases go through the
// exception store, containment decisions through the audit log, and nothing
// here ever reaches the network beyond the device browsing to it.
//
// What it reads is a DeviceSource, not a particular device table, so that the
// page a device is shown and the release that frees it are built from the same
// lookups the resolver makes. That is what keeps "reversible by a human,
// always" true of every device the daemon can act on rather than only of the
// ones some particular file happens to name.
package portal

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/risk"
)

// DefaultRemediation is the generic cleanup guidance shown when the device
// table publishes no vendor for a device, or the one it publishes has no entry.
// It is deliberately vendor-neutral: inventing device-specific instructions we
// have not verified would be worse than honest general advice.
var DefaultRemediation = []string{
	"Update the device's firmware to the newest version published by the vendor's own site.",
	"Change any default or reused passwords on the device.",
	"Review connected accessories, accounts, and integrations; remove anything you do not recognize.",
	"Restart the device once it is updated, then release it below if it still needs network access.",
}

// unknownVendorLabel and unknownClassLabel are what a device the table has
// nothing about renders as.
//
// A blank cell beside the word "Vendor" reads as a bug, and an operator who
// sees that has no way to tell a broken page from a device nobody has
// classified yet. Those are different states and both of them are normal, so
// both of them are stated.
const (
	unknownVendorLabel = "Unknown (none published)"
	unknownClassLabel  = "Unclassified"
)

// DeviceSource is the portal's view of the network's device table: which
// device owns an address, and what is known about a device.
//
// It is the smallest thing the portal needs, and it is declared here rather
// than imported so that the portal states its own dependency instead of
// binding to whichever concrete table happens to exist this month. Both tables
// the daemon has satisfy it as written — a file-backed *inventory.Inventory and
// the router-backed deviceTable the resolver already uses — so a device
// discovered only by a router gets the same page, the same release form, and
// the same guarantees as one named in a file. Neither source is asked to
// pretend to be the other.
//
// Implementations must be safe for concurrent use. A source is read from HTTP
// handler goroutines for the whole lifetime of the server, while the daemon's
// poll loop may still be rewriting what that source answers.
//
// A nil DeviceSource means "no device table": every address is unattributable,
// the status page renders its no-record state, and release refuses. Pass an
// untyped nil — an interface holding a typed nil pointer is not itself nil,
// and nothing inside an interface can tell the difference.
type DeviceSource interface {
	MACFor(ip netip.Addr) (net.HardwareAddr, bool)
	Get(mac net.HardwareAddr) (core.Device, bool)
}

// Config wires the portal to the rest of the daemon.
type Config struct {
	// Engine is required; every page renders an assessment.
	Engine *risk.Engine

	// DeviceSource is the network's device table. Nil is allowed and means
	// there is none: the portal then reports every address as unknown and
	// refuses to release, which is the honest nothing rather than a page that
	// guesses. It is the same table the resolver attributes through, so the
	// device a page names is the device a query was decided about.
	DeviceSource DeviceSource

	// Garden is the walled-garden name list, shown so an operator can see
	// exactly what a contained device is allowed to reach.
	Garden []string

	// Remediation maps vendor names to cleanup steps. The lookup is
	// case-insensitive; a vendor without an entry, and a device with no vendor
	// at all, both get DefaultRemediation.
	Remediation map[string][]string

	// Exceptions, Audit and Token together enable the release action. Any
	// missing piece leaves the portal read-only, which the page reflects.
	Exceptions *Exceptions
	Audit      *Audit
	Token      string

	// ReadOnly marks an observing run: the engine may say "quarantined", but
	// the daemon is not containing anything. The page must say so rather
	// than claim a containment that is not happening — an instrument that
	// lies in test mode teaches its operator to distrust every reading.
	ReadOnly bool

	// ReleaseTTL bounds how long one release lasts. Zero selects 24h — long
	// enough to update and verify a device, short enough that a forgotten
	// release re-contains on its own.
	ReleaseTTL time.Duration

	Now func() time.Time
}

// Server is the portal HTTP handler. Safe for concurrent use.
//
// cfg is captured by value at New and never mutated afterwards, so every
// request goroutine reads the same immutable wiring. Nothing here is swapped
// out from under a running handler: there is no table pointer to race on, and
// the only mutable state reachable from a handler is inside a DeviceSource,
// which carries its own locking.
type Server struct {
	cfg  Config
	tmpl *template.Template
}

// New validates cfg and parses the page template.
func New(cfg Config) (*Server, error) {
	if cfg.Engine == nil {
		return nil, fmt.Errorf("portal: engine is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ReleaseTTL == 0 {
		cfg.ReleaseTTL = 24 * time.Hour
	}
	if cfg.ReleaseTTL < 0 {
		return nil, fmt.Errorf("portal: release ttl must be positive")
	}
	tmpl, err := template.New("page").Parse(pageTemplate)
	if err != nil {
		return nil, fmt.Errorf("portal: parsing template: %w", err)
	}
	return &Server{cfg: cfg, tmpl: tmpl}, nil
}

// ReleaseEnabled reports whether the release action is wired up.
func (s *Server) ReleaseEnabled() bool {
	return s.cfg.Exceptions != nil && s.cfg.Audit != nil && s.cfg.Token != ""
}

// Handler returns the portal's HTTP handler with hardening headers applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// {$} pins the status page to the site root; any other path 404s instead
	// of quietly serving device status to a crawler or scanner.
	mux.HandleFunc("GET /{$}", s.handleStatus)
	mux.HandleFunc("POST /release", s.handleRelease)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		// The page runs no JavaScript and loads no remote anything; the CSP
		// makes that a guarantee rather than a review-time observation.
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		mux.ServeHTTP(w, r)
	})
}

// pageData is the template model.
type pageData struct {
	Title   string
	Now     string
	Message string // post-release confirmation
	Error   string

	IP string
	// Identified means the address resolved to a MAC. Known means a record for
	// that device was found as well. The two differ exactly when the table can
	// name the device but cannot describe it — the one case where the page must
	// not claim either way about containment.
	Identified bool
	Known      bool

	MAC          string
	Vendor       string
	Class        string
	Unclassified bool // no class published, so the score was weighted neutrally
	Score        float64
	Tier         string
	Corroborated bool
	// DistinctKinds is how many independent signal kinds back the score.
	DistinctKinds int
	Reasons       []string

	ReleaseOn     bool
	ReleasedUntil string
	ReleasedBy    string

	Observing bool
	Flagged   bool
	Contained bool

	Garden []string
	Steps  []string
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	data := pageData{
		Title:     "R0-Invader — device status",
		Now:       s.cfg.Now().Format("2006-01-02 15:04:05 MST"),
		ReleaseOn: s.ReleaseEnabled(),
		Observing: s.cfg.ReadOnly,
	}
	if r.URL.Query().Get("released") == "1" {
		data.Message = "Release recorded. This device may reach the network again until the release expires."
	}

	ip, err := clientIP(r)
	if err != nil {
		data.Error = "Could not determine this request's source address: " + err.Error()
		s.render(w, http.StatusBadRequest, data)
		return
	}
	data.IP = ip.String()
	s.identify(&data, ip)
	data.Garden = s.cfg.Garden
	s.render(w, http.StatusOK, data)
}

// identify fills in everything the device table knows about ip.
//
// The two lookups are separate on purpose and are not merged into one. MACFor
// answers "is this address being contained right now", because the
// containment predicate resolves through the same source the same way. Get
// answers "can a person be shown a page and handed a release button". When the
// first succeeds and the second does not, the device is very probably
// contained at this instant and this page has nothing honest to say about it,
// so it says that rather than reporting a device as free.
//
// A release is reported even when the record is gone. The release store is
// keyed on the MAC, which does not change when a device drops out of a
// refreshed table, so a release outlives the record that justified it — and
// reporting it is what tells an operator their earlier decision is still in
// force.
func (s *Server) identify(d *pageData, ip netip.Addr) {
	if s.cfg.DeviceSource == nil {
		return
	}
	mac, ok := s.cfg.DeviceSource.MACFor(ip)
	if !ok {
		return
	}
	d.Identified = true
	d.MAC = mac.String()
	if exc, ok := s.cfg.Exceptions.Active(mac); ok {
		d.ReleasedUntil = exc.ExpiresAt.Format("2006-01-02 15:04:05 MST")
		d.ReleasedBy = exc.By
	}

	dev, ok := s.cfg.DeviceSource.Get(mac)
	if !ok {
		return
	}
	assess := s.cfg.Engine.Evaluate(dev, s.cfg.Now())
	d.Known = true
	d.fillIdentity(dev)
	d.Score = assess.Score
	d.Tier = string(assess.Tier)
	d.Corroborated = assess.Corroborated
	d.DistinctKinds = assess.DistinctKinds
	d.Reasons = assess.Reasons
	d.Flagged = assess.Tier == core.ContainmentQuarantined
	d.Contained = d.Flagged && !s.cfg.ReadOnly
	d.Steps = s.stepsFor(dev.Vendor)
}

// fillIdentity copies what the table knows about a device onto the page model,
// substituting readable text for what it does not have.
//
// A device discovered by a router is real, attributable and containable long
// before anyone classifies it, so an empty vendor and an unknown class are
// ordinary states here rather than a half-built record. Unclassified drives
// the note that explains why the score was weighted neutrally and why the
// cleanup steps are the generic ones.
func (d *pageData) fillIdentity(dev core.Device) {
	d.Vendor = strings.TrimSpace(dev.Vendor)
	if d.Vendor == "" {
		d.Vendor = unknownVendorLabel
	}
	d.Unclassified = dev.Class == "" || dev.Class == core.ClassUnknown
	d.Class = string(dev.Class)
	if d.Unclassified {
		d.Class = unknownClassLabel
	}
}

// releaseTarget is the device a release request names, resolved once and then
// used for both the assessment check and the release itself.
type releaseTarget struct {
	mac net.HardwareAddr
	dev core.Device
}

// acceptReleaseRequest applies every gate a release passes before anything is
// done with it: the action must be configured, the run must not be observing,
// the form must parse, and the token must match. It writes the refusal itself
// and reports whether the request may proceed.
//
// Keeping all four here is what makes "the button is hidden" and "the rule
// refuses" the same rule: a hand-rolled POST is turned away for exactly the
// reasons the page does not offer it.
func (s *Server) acceptReleaseRequest(w http.ResponseWriter, r *http.Request) bool {
	if !s.ReleaseEnabled() {
		http.Error(w, "release is not configured on this server", http.StatusServiceUnavailable)
		return false
	}
	if s.cfg.ReadOnly {
		http.Error(w, "this run is observing only; nothing is contained, so there is nothing to release", http.StatusBadRequest)
		return false
	}
	// The portal is reachable by the device it contains; cap the body so a
	// hostile client cannot pin the process with an oversized form.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "could not parse form: "+err.Error(), http.StatusBadRequest)
		return false
	}
	// Constant-time compare: the token is printed once at startup, and a
	// timing channel over a network connection is a cheap thing to close.
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("token")), []byte(s.cfg.Token)) != 1 {
		http.Error(w, "wrong token", http.StatusForbidden)
		return false
	}
	return true
}

// releaseIP reads the address a release form names, defaulting to the address
// making the request — the browser the quarantine redirect brought here.
func releaseIP(r *http.Request) (netip.Addr, error) {
	raw := strings.TrimSpace(r.PostFormValue("ip"))
	if raw == "" {
		addr, err := clientIP(r)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("could not determine source address: %w", err)
		}
		return addr, nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid ip %s", raw)
	}
	return addr, nil
}

// releaseTargetFor resolves an address into the record a release acts on.
//
// The error carries the status the handler should answer with, so every way a
// release can be refused — no device table, no device at that address, no
// record for the device — is decided here rather than in three branches of the
// handler.
//
// The middle two are deliberately different statuses. An address nothing holds
// is a 404 and stays one. An address the table resolves to a MAC it then has
// no record for is a transient internal condition — a poll that has not landed,
// or a source caught mid-refresh — and reporting it as a 404 would tell an
// operator the device does not exist, while reporting it as a 500 would blame
// the server for something that is usually true again within one poll
// interval.
func (s *Server) releaseTargetFor(ip netip.Addr) (releaseTarget, int, error) {
	if s.cfg.DeviceSource == nil {
		return releaseTarget{}, http.StatusBadRequest,
			errors.New("no device table configured; nothing to release")
	}
	mac, ok := s.cfg.DeviceSource.MACFor(ip)
	if !ok {
		return releaseTarget{}, http.StatusNotFound,
			fmt.Errorf("no device in the device table has address %s", ip)
	}
	dev, ok := s.cfg.DeviceSource.Get(mac)
	if !ok {
		return releaseTarget{}, http.StatusServiceUnavailable,
			fmt.Errorf("the device table resolved %s to %s but has no record for it right now; try again", ip, mac)
	}
	return releaseTarget{mac: mac, dev: dev}, 0, nil
}

// recordRelease audits a release that has already been persisted.
//
// The entry carries the assessment exactly as it stood at the moment of the
// release, which is what a later incident review needs in order to answer
// "what did we know when we let this device back on?".
func (s *Server) recordRelease(t releaseTarget, ip netip.Addr, a risk.Assessment, expires time.Time) error {
	return s.cfg.Audit.Record(AuditEntry{
		Action:        "release",
		MAC:           t.mac.String(),
		IPs:           ipStrings(t.dev.IPs),
		Vendor:        t.dev.Vendor,
		Class:         string(t.dev.Class),
		Score:         a.Score,
		Tier:          string(a.Tier),
		Corroborated:  a.Corroborated,
		DistinctKinds: a.DistinctKinds,
		Reasons:       a.Reasons,
		By:            "portal",
		Expires:       &expires,
	})
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	if !s.acceptReleaseRequest(w, r) {
		return
	}
	ip, err := releaseIP(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target, status, err := s.releaseTargetFor(ip)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	assess := s.cfg.Engine.Evaluate(target.dev, s.cfg.Now())
	if assess.Tier != core.ContainmentQuarantined {
		http.Error(w, fmt.Sprintf("%s is not quarantined (tier %s); nothing to release", ip, assess.Tier), http.StatusBadRequest)
		return
	}

	exc, err := s.cfg.Exceptions.Release(target.mac, "portal", s.cfg.ReleaseTTL)
	if err != nil {
		http.Error(w, "could not record release: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Audit after persistence: if this fails the release is real but
	// unrecorded, and the operator must be told rather than left believing
	// the log is complete.
	if err := s.recordRelease(target, ip, assess, exc.ExpiresAt); err != nil {
		http.Error(w,
			"release was saved and expires "+exc.ExpiresAt.Format(time.RFC3339)+
				", but the audit log write failed: "+err.Error()+
				". Fix the audit path; the log is required, not optional.",
			http.StatusInternalServerError)
		return
	}

	// See Other: a reload of the confirmation then re-GETs status instead of
	// re-submitting the release form.
	http.Redirect(w, r, "/?released=1", http.StatusSeeOther)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

func (s *Server) render(w http.ResponseWriter, status int, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = s.tmpl.Execute(w, d)
}

// stepsFor returns vendor-specific remediation steps, falling back to the
// generic list. Matching is case-insensitive because inventory files are
// hand-written and vendor strings drift.
//
// A device with no published vendor goes straight to the generic list, without
// consulting the map. There is nothing to match on, and an empty-string key in
// a hand-written remediation file would otherwise match every unclassified
// device on the network — a surprise rather than a feature.
func (s *Server) stepsFor(vendor string) []string {
	if strings.TrimSpace(vendor) == "" {
		return DefaultRemediation
	}
	for k, v := range s.cfg.Remediation {
		if len(v) > 0 && strings.EqualFold(k, vendor) {
			return v
		}
	}
	return DefaultRemediation
}

func clientIP(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse remote addr %q: %w", r.RemoteAddr, err)
	}
	return ip, nil
}

func ipStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; margin: 0; padding: 2rem 1.25rem; line-height: 1.55; background: #101418; color: #dfe6ec; }
main { max-width: 44rem; margin: 0 auto; }
h1 { font-size: 1.3rem; margin: 0 0 .2rem; }
h2 { font-size: .8rem; margin: 1.75rem 0 .5rem; color: #8fa5b8; text-transform: uppercase; letter-spacing: .08em; }
.sub { color: #7e91a3; font-size: .85rem; margin: 0 0 1.4rem; }
.banner { padding: .7rem .95rem; border-radius: .5rem; margin-bottom: 1rem; font-size: .92rem; }
.ok { background: #10291a; border: 1px solid #2c7a44; }
.warn { background: #2f2410; border: 1px solid #94762a; }
.bad { background: #331313; border: 1px solid #9c3a3a; }
.card { background: #161c23; border: 1px solid #28313b; border-radius: .6rem; padding: 1rem 1.15rem; }
dl { display: grid; grid-template-columns: 9.5rem 1fr; gap: .3rem 1rem; margin: 0; font-size: .93rem; }
dt { color: #7e91a3; }
dd { margin: 0; word-break: break-all; }
ul.reasons { margin: .4rem 0 0; padding-left: 1.2rem; font-size: .93rem; }
ul.reasons li { margin: .15rem 0; }
ol.steps { margin: .4rem 0 0; padding-left: 1.3rem; font-size: .95rem; }
ol.steps li { margin: .25rem 0; }
.garden { margin: .5rem 0 0; font-size: .88rem; color: #9fb2c3; }
code { background: #0c1015; padding: .08rem .34rem; border-radius: .3rem; font-size: .9em; }
form { display: flex; flex-wrap: wrap; gap: .8rem; align-items: flex-end; margin-top: .4rem; }
label { display: flex; flex-direction: column; gap: .25rem; font-size: .78rem; color: #7e91a3; }
input { font: inherit; padding: .5rem .6rem; border-radius: .4rem; border: 1px solid #37424e; background: #0c1015; color: #dfe6ec; min-width: 14rem; }
button { font: inherit; padding: .55rem 1.2rem; border-radius: .4rem; border: 1px solid #a03c3c; background: #7d2727; color: #fff; cursor: pointer; }
button:hover { background: #963232; }
.note { font-size: .8rem; color: #7e91a3; margin: .55rem 0 0; }
footer { margin-top: 2.25rem; color: #5f7183; font-size: .78rem; }
</style>
</head>
<body>
<main>
<h1>R0-Invader</h1>
<p class="sub">Device status · {{.Now}}</p>
{{if .Error}}<div class="banner bad">{{.Error}}</div>{{end}}
{{if .Message}}<div class="banner ok">{{.Message}}</div>{{end}}
{{if .ReleasedUntil}}<div class="banner ok">Released by {{.ReleasedBy}} · valid until {{.ReleasedUntil}}</div>{{end}}
{{if not .Known}}
{{if .Identified}}<div class="banner warn">No record for <code>{{.MAC}}</code> at <code>{{.IP}}</code> right now: the device table named the device but could not describe it, so this page cannot say whether it is contained. A refresh in progress looks like this. Reload in a moment.</div>{{else}}<div class="banner warn">No record for address <code>{{.IP}}</code>. It is not in the device table, so nothing is being contained for it.</div>{{end}}
{{else}}
{{if .Observing}}{{if .Flagged}}<div class="banner warn">This device is flagged at tier <strong>{{.Tier}}</strong>, but this run is in observe mode: nothing is contained and no lookups are being redirected.</div>{{else}}<div class="banner ok">This device is not contained. Tier: <strong>{{.Tier}}</strong> · observe mode.</div>{{end}}{{else if .Contained}}{{if not .ReleasedUntil}}<div class="banner bad">This device is <strong>quarantined</strong>. Its lookups resolve to this page instead of the internet until it is released.</div>{{end}}{{else}}
<div class="banner ok">This device is not contained. Tier: <strong>{{.Tier}}</strong>.</div>{{end}}
<div class="card">
<dl>
<dt>Address</dt><dd>{{.IP}}</dd>
<dt>MAC</dt><dd>{{.MAC}}</dd>
<dt>Vendor</dt><dd>{{.Vendor}}</dd>
<dt>Class</dt><dd>{{.Class}}</dd>
<dt>Risk</dt><dd>{{printf "%.1f" .Score}} · {{.Tier}} · {{if .Corroborated}}corroborated across {{.DistinctKinds}} signal kinds{{else}}not yet corroborated{{end}}</dd>
</dl>
{{if .Reasons}}
<h2>Why this device is flagged</h2>
<ul class="reasons">{{range .Reasons}}<li>{{.}}</li>{{end}}</ul>
{{end}}
</div>
{{if .Unclassified}}
<p class="note">No vendor or class has been published for this device, so its score was weighted neutrally rather than up or down, and the cleanup steps below are the general ones. Adding it to the device inventory classifies it.</p>
{{end}}
{{if .Steps}}
<h2>What to do about it</h2>
<ol class="steps">{{range .Steps}}<li>{{.}}</li>{{end}}</ol>
{{end}}
{{if .Garden}}
<p class="garden">While quarantined, only these names resolve: {{range $i, $n := .Garden}}{{if $i}}, {{end}}<code>{{$n}}</code>{{end}}</p>
{{end}}
{{if and .ReleaseOn .Contained}}
<h2>Release this device</h2>
<form method="post" action="/release">
<label>Operator token<input type="text" name="token" autocomplete="off" spellcheck="false" required></label>
<label>Device IP<input type="text" name="ip" value="{{.IP}}" required></label>
<button type="submit">Release</button>
</form>
<p class="note">The token is printed when the server starts. Releases expire automatically; an expired release re-contains the device with no further action.</p>
{{end}}
{{end}}
<footer>R0-Invader runs entirely on your network. Nothing on this page leaves it.</footer>
</main>
</body>
</html>`
