package detect

import (
	"net"
	"net/netip"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
)

func mac(s string) net.HardwareAddr {
	hw, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return hw
}

func baseFlowEvent() core.NormalizedEvent {
	return core.NormalizedEvent{
		Time:      time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
		Kind:      core.EventFlow,
		DeviceMAC: mac("aa:bb:cc:dd:ee:ff"),
		Src: core.Endpoint{
			IP:   netip.MustParseAddr("192.168.1.44"),
			Port: 49152,
		},
		Dst: core.Endpoint{
			IP:   netip.MustParseAddr("192.168.1.50"),
			Port: 443,
		},
		Bytes:    200 << 20, // 200 MiB
		Duration: 10 * time.Second,
	}
}

func baseTLSEvent() core.NormalizedEvent {
	return core.NormalizedEvent{
		Time:      time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
		Kind:      core.EventTLS,
		DeviceMAC: mac("aa:bb:cc:dd:ee:ff"),
		Src: core.Endpoint{
			IP:   netip.MustParseAddr("192.168.1.44"),
			Port: 49152,
		},
		Dst: core.Endpoint{
			IP:   netip.MustParseAddr("192.168.1.50"),
			Port: 11434,
		},
		SNI: "vllm.ai",
	}
}

func baseAuthEvent() core.NormalizedEvent {
	return core.NormalizedEvent{
		Time:      time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
		Kind:      core.EventSSHAuth,
		DeviceMAC: mac("aa:bb:cc:dd:ee:ff"),
		AuthUser:  "admin",
	}
}

func baseInventoryEvent() core.NormalizedEvent {
	return core.NormalizedEvent{
		Time:      time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
		Kind:      core.EventInventory,
		DeviceMAC: mac("aa:bb:cc:dd:ee:ff"),
	}
}
