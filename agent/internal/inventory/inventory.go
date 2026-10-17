// Package inventory holds the device table: which MAC owns which address,
// and how each device is classified.
//
// Attribution is the load-bearing step between raw telemetry and any signal
// that can name a device. Suricata's EVE records carry IPs, never MACs, so
// without this table a detector can observe a model-host contact and be
// unable to say which device made it — which is the entire point of the
// signal. The inventory is what closes that gap, sourced in production from
// DHCP leases and ARP tables and here from a static file for offline use.
//
// Classification lives here too, because only the risk engine's view of a
// device carries it, and classification is what turns a raw signal into a
// weighted one.
package inventory

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

// Entry is one known device.
type Entry struct {
	// MAC is the device's hardware address, in any form net.ParseMAC
	// accepts. It is the primary key: a device is its MAC, and an IP is
	// merely where it was last seen.
	MAC string `json:"mac"`
	// IPs are the addresses the device has been observed at. Multiple are
	// common across DHCP renewals and dual-stack hosts.
	IPs []string `json:"ips,omitempty"`
	// Class drives risk weighting. Empty means core.ClassUnknown.
	Class string `json:"class,omitempty"`
	// Vendor is the OUI-derived manufacturer, rendered into the remediation
	// portal so a user sees "Hikvision camera" rather than a MAC.
	Vendor string `json:"vendor,omitempty"`
	// Notes are free-form operator annotations.
	Notes []string `json:"notes,omitempty"`
}

// Inventory is a loaded device table. It is safe for concurrent reads after
// construction; it is built once and then consulted by the ingest loop.
type Inventory struct {
	byMAC   map[string]core.Device
	macOf   map[netip.Addr]net.HardwareAddr
	devices []core.Device
}

// File is the on-disk shape: a bare list of entries, or an object with a
// "devices" key, so both a hand-written list and an exported dump parse.
type fileShape struct {
	Devices []Entry `json:"devices"`
}

// Load reads and parses a JSON inventory file.
func Load(path string) (*Inventory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("inventory: reading %s: %w", path, err)
	}
	return Parse(raw)
}

// Parse builds an Inventory from JSON bytes.
//
// A bare array is accepted alongside the {"devices":[...]} wrapper, because
// an operator writing this file by hand should not have to remember which of
// the two shapes the tool wants.
func Parse(raw []byte) (*Inventory, error) {
	inv := &Inventory{
		byMAC: map[string]core.Device{},
		macOf: map[netip.Addr]net.HardwareAddr{},
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return inv, nil
	}

	var entries []Entry
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, fmt.Errorf("inventory: parsing entries: %w", err)
		}
	} else {
		var wrap fileShape
		if err := json.Unmarshal(raw, &wrap); err != nil {
			return nil, fmt.Errorf("inventory: parsing: %w", err)
		}
		entries = wrap.Devices
	}

	for i, e := range entries {
		dev, err := e.device()
		if err != nil {
			return nil, fmt.Errorf("inventory: entry %d: %w", i, err)
		}
		inv.add(dev)
	}
	return inv, nil
}

func (e Entry) device() (core.Device, error) {
	mac, err := net.ParseMAC(strings.TrimSpace(e.MAC))
	if err != nil {
		return core.Device{}, fmt.Errorf("invalid MAC %q: %w", e.MAC, err)
	}

	dev := core.Device{
		MAC:    mac,
		Vendor: e.Vendor,
		Notes:  e.Notes,
	}
	if e.Class != "" {
		dev.Class = core.DeviceClass(strings.ToLower(strings.TrimSpace(e.Class)))
	} else {
		dev.Class = core.ClassUnknown
	}

	for _, s := range e.IPs {
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return core.Device{}, fmt.Errorf("invalid IP %q: %w", s, err)
		}
		dev.IPs = append(dev.IPs, addr.Unmap())
	}
	return dev, nil
}

func (inv *Inventory) add(dev core.Device) {
	key := dev.MAC.String()
	inv.byMAC[key] = dev
	inv.devices = append(inv.devices, dev)
	for _, ip := range dev.IPs {
		// The first entry wins. A duplicate address across two MACs is an
		// inventory error (usually a stale lease); keeping the first and
		// ignoring the rest is safer than letting the later one silently
		// reattribute a device mid-flight.
		if _, exists := inv.macOf[ip]; !exists {
			inv.macOf[ip] = dev.MAC
		}
	}
}

// MACFor implements the suricata.Attributor contract: resolve a LAN-side IP
// to the device that owns it.
func (inv *Inventory) MACFor(ip netip.Addr) (net.HardwareAddr, bool) {
	mac, ok := inv.macOf[ip.Unmap()]
	if !ok {
		return nil, false
	}
	// Return a copy so a caller cannot mutate the table through the result.
	out := make(net.HardwareAddr, len(mac))
	copy(out, mac)
	return out, true
}

// Devices returns every known device, for the risk engine to assess.
func (inv *Inventory) Devices() []core.Device {
	out := make([]core.Device, len(inv.devices))
	copy(out, inv.devices)
	return out
}

// Get returns a device by MAC, and whether it was known.
func (inv *Inventory) Get(mac net.HardwareAddr) (core.Device, bool) {
	dev, ok := inv.byMAC[mac.String()]
	return dev, ok
}

// Len reports how many devices are known.
func (inv *Inventory) Len() int { return len(inv.devices) }
