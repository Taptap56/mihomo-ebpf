package inbound

import (
	"net"
	"strconv"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/ebpf"
	"github.com/metacubex/mihomo/log"
)

// EbpfOption configures the "ebpf" listener: the CHIZI-style eBPF
// datapath (library github.com/CHIZI-0618/sing-ebpf) registered as
// a first-class mihomo listener, mirroring sing-box's "ebpf"
// inbound. Local (cgroup) captures this device's own traffic,
// Shared (TC packet rewrite) captures hotspot clients; both share
// the listener port.
//
// Example:
//
//	listeners:
//	  - name: ebpf-in
//	    type: ebpf
//	    port: 15361
//	    dns-listen: 127.0.0.1:1053
//	    local: { enabled: true, dns-mode: hijack, bypass-private-address: true }
//	    shared: { enabled: true, dns-mode: hijack, interface: ["wlan1"], bypass-private-address: true }
type EbpfOption struct {
	BaseOption
	DNSListen string           `inbound:"dns-listen,omitempty"`
	Local     EbpfLocalOption  `inbound:"local,omitempty"`
	Shared    EbpfSharedOption `inbound:"shared,omitempty"`
}

// EbpfLocalOption configures the cgroup (this-device) plane.
type EbpfLocalOption struct {
	Enabled              *bool  `inbound:"enabled,omitempty"`
	DNSMode              string `inbound:"dns-mode,omitempty"`
	BypassPrivateAddress *bool  `inbound:"bypass-private-address,omitempty"`
	CgroupPath           string `inbound:"cgroup-path,omitempty"`
}

// EbpfSharedOption configures the TC packet-rewrite (hotspot) plane.
type EbpfSharedOption struct {
	Enabled              *bool    `inbound:"enabled,omitempty"`
	DNSMode              string   `inbound:"dns-mode,omitempty"`
	BypassPrivateAddress *bool    `inbound:"bypass-private-address,omitempty"`
	Interface            []string `inbound:"interface,omitempty"`
}

func (o EbpfOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

// toConfig converts the listener option to the datapath config.
func (o *EbpfOption) toConfig(port uint16) LC.Ebpf {
	return LC.Ebpf{
		Enable:    true,
		Port:      port,
		DNSListen: o.DNSListen,
		Local: LC.EbpfLocal{
			Enabled:              o.Local.Enabled,
			DNSMode:              o.Local.DNSMode,
			BypassPrivateAddress: o.Local.BypassPrivateAddress,
			CgroupPath:           o.Local.CgroupPath,
		},
		Shared: LC.EbpfShared{
			Enabled:              o.Shared.Enabled,
			DNSMode:              o.Shared.DNSMode,
			BypassPrivateAddress: o.Shared.BypassPrivateAddress,
			Interface:            o.Shared.Interface,
		},
	}
}

type Ebpf struct {
	*Base
	config *EbpfOption
	mgr    *ebpf.Manager
}

func NewEbpf(options *EbpfOption) (*Ebpf, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Ebpf{
		Base:   base,
		config: options,
	}, nil
}

// Config implements constant.InboundListener
func (e *Ebpf) Config() C.InboundConfig {
	return e.config
}

// Listen implements constant.InboundListener: it starts the eBPF
// datapath (cgroup + TC attach). The listener port comes from the
// standard listener "port" field; 0 selects the datapath default.
func (e *Ebpf) Listen(tunnel C.Tunnel) error {
	var port uint16
	if _, portStr, err := net.SplitHostPort(e.RawAddress()); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			port = uint16(p)
		}
	}
	if e.mgr != nil {
		_ = e.mgr.Close()
		e.mgr = nil
	}
	e.mgr = ebpf.NewManager(e.config.toConfig(port), tunnel, e.Name())
	if err := e.mgr.Start(); err != nil {
		e.mgr = nil
		return err
	}
	log.Infoln("EBPF[%s] listening at %s", e.Name(), e.Address())
	return nil
}

// Close implements constant.InboundListener
func (e *Ebpf) Close() error {
	if e.mgr != nil {
		err := e.mgr.Close()
		e.mgr = nil
		return err
	}
	return nil
}
