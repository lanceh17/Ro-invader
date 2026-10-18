package lab

import (
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/lanceh17/Ro-invader/agent/internal/core"
	"github.com/lanceh17/Ro-invader/agent/internal/risk"
)

type Device struct {
	MAC       net.HardwareAddr
	IP        netip.Addr
	Class     core.DeviceClass
	Engine    *risk.Engine
	Score     float64
	Tier      core.ContainmentState
	Contained bool
	Infected  bool
	Spread    int
}

type Config struct {
	N                  int
	SpreadRate         float64
	ContainmentEnabled bool
	Seed               int64
}

type Result struct {
	TotalInfections  int
	ContainedDevices int
	R0               float64
	Steps            int
}

type Simulation struct {
	cfg     Config
	devices []*Device
	rng     *rand.Rand
}

func NewSimulation(cfg Config) *Simulation {
	rng := rand.New(rand.NewSource(cfg.Seed))
	devices := make([]*Device, cfg.N)
	for i := 0; i < cfg.N; i++ {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i + 1)}
		ip := netip.AddrFrom4([4]byte{192, 168, 1, byte(i + 1)})
		devices[i] = &Device{
			MAC:    mac,
			IP:     ip,
			Class:  core.ClassCamera,
			Engine: risk.New(),
		}
	}
	return &Simulation{cfg: cfg, devices: devices, rng: rng}
}

func (s *Simulation) Run(maxSteps int) Result {
	s.devices[0].Infected = true
	totalInfections := 1
	containedCount := 0

	for step := 0; step < maxSteps; step++ {
		for _, dev := range s.devices {
			if !dev.Infected || dev.Contained {
				continue
			}
			if s.rng.Float64() < s.cfg.SpreadRate {
				var targets []*Device
				for _, d := range s.devices {
					if !d.Infected {
						targets = append(targets, d)
					}
				}
				if len(targets) > 0 {
					target := targets[s.rng.Intn(len(targets))]
					target.Infected = true
					totalInfections++
					dev.Spread++
					dev.Engine.Observe(core.Signal{
						Kind:       core.SignalWeightTransfer,
						Class:      core.SignalReplicationRequired,
						DeviceMAC:  dev.MAC,
						Weight:     35,
						Confidence: 0.5,
						Reason:     "Weight transfer to new host",
					}, time.Now())
				}
			}
		}

		for _, dev := range s.devices {
			if dev.Infected && !dev.Contained {
				dev.Engine.Observe(core.Signal{
					Kind:       core.SignalDNSDrift,
					Class:      core.SignalReplicationRequired,
					DeviceMAC:  dev.MAC,
					Weight:     18,
					Confidence: 1.0,
					Reason:     "DNS drift: querying novel domains",
				}, time.Now())
			}
		}

		for _, dev := range s.devices {
			if !dev.Infected {
				continue
			}
			coreDev := core.Device{MAC: dev.MAC, Class: dev.Class}
			a := dev.Engine.Evaluate(coreDev, time.Now())
			dev.Score = a.Score
			dev.Tier = a.Tier
			if s.cfg.ContainmentEnabled && a.Tier == core.ContainmentQuarantined && !dev.Contained {
				dev.Contained = true
				containedCount++
			}
		}

		hasActive := false
		for _, dev := range s.devices {
			if dev.Infected && !dev.Contained {
				hasActive = true
				break
			}
		}
		if !hasActive {
			return s.buildResult(totalInfections, containedCount, step+1)
		}
	}

	return s.buildResult(totalInfections, containedCount, maxSteps)
}

func (s *Simulation) buildResult(totalInfections, containedCount, steps int) Result {
	totalInfected := 0
	totalSpread := 0
	for _, dev := range s.devices {
		if dev.Infected {
			totalInfected++
			totalSpread += dev.Spread
		}
	}
	r0 := 0.0
	if totalInfected > 1 {
		r0 = float64(totalSpread) / float64(totalInfected)
	}
	return Result{
		TotalInfections:  totalInfections,
		ContainedDevices: containedCount,
		R0:               r0,
		Steps:            steps,
	}
}
