package core

import (
	"net/netip"
)

// IsLAN reports whether an address is on a locally administered or link-local
// range, meaning it plausibly belongs to a device on the network we manage.
//
// Suricata's EVE records carry IPs, never MACs. Deciding which end of a flow
// is "ours" is therefore the first thing every ingest path has to do, and
// getting it wrong silently corrupts attribution: an event attributed to the
// wrong device produces a signal against an innocent host.
func IsLAN(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	// Unmap so that an IPv4 address expressed in IPv6 form still classifies
	// correctly. Suricata is not always consistent about this.
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLinkLocalUnicast()
}

// IsPublic reports the complement of IsLAN, meaning the address is off-link
// and therefore a destination rather than an attributable device.
func IsPublic(addr netip.Addr) bool {
	return addr.IsValid() && !IsLAN(addr)
}

// LANSide returns the LAN-facing endpoint of a flow, which is the side that
// belongs to a device we can name and therefore the side a signal can be
// attributed to.
//
// The bool is false when attribution is ambiguous: both ends on-link, or
// neither. An ambiguous flow is reported rather than guessed at, because a
// guessed attribution is worse than none.
func LANSide(src, dst Endpoint) (Endpoint, bool) {
	srcLAN := IsLAN(src.IP)
	dstLAN := IsLAN(dst.IP)

	switch {
	case srcLAN && !dstLAN:
		return src, true
	case dstLAN && !srcLAN:
		return dst, true
	default:
		return Endpoint{}, false
	}
}
