package config

import "slices"

// Ebpf is the configuration of the CHIZI-style eBPF datapath
// (library github.com/CHIZI-0618/sing-ebpf, consumer implemented in
// listener/ebpf). Two planes share one listener port:
//
//   - Local: cgroup hooks capture this device's own TCP+UDP traffic.
//   - Shared: TC packet-rewrite on the listed interfaces captures
//     hotspot/tethering clients' TCP+UDP traffic.
//
// Both hand traffic to the tunnel with the original destination
// recovered from the library's maps.
type Ebpf struct {
	Enable    bool       `yaml:"enable" json:"enable"`
	Port      uint16     `yaml:"port" json:"port"`
	DNSListen string     `yaml:"dns-listen" json:"dns-listen"`
	Local     EbpfLocal  `yaml:"local" json:"local"`
	Shared    EbpfShared `yaml:"shared" json:"shared"`
}

// EbpfLocal configures the cgroup (this-device) plane.
type EbpfLocal struct {
	Enabled              *bool  `yaml:"enabled" json:"enabled"`
	DNSMode              string `yaml:"dns-mode" json:"dns-mode"`
	BypassPrivateAddress *bool  `yaml:"bypass-private-address" json:"bypass-private-address"`
	CgroupPath           string `yaml:"cgroup-path" json:"cgroup-path"`
}

// EbpfShared configures the TC packet-rewrite (hotspot) plane.
type EbpfShared struct {
	Enabled              *bool    `yaml:"enabled" json:"enabled"`
	DNSMode              string   `yaml:"dns-mode" json:"dns-mode"`
	BypassPrivateAddress *bool    `yaml:"bypass-private-address" json:"bypass-private-address"`
	Interface            []string `yaml:"interface" json:"interface"`
}

func boolPtrEqual(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// Equal compares two Ebpf configs for hot-reload decisions.
func (e *Ebpf) Equal(other Ebpf) bool {
	return e.Enable == other.Enable &&
		e.Port == other.Port &&
		e.DNSListen == other.DNSListen &&
		e.Local.Equal(other.Local) &&
		e.Shared.Equal(other.Shared)
}

// Equal compares two EbpfLocal configs.
func (l *EbpfLocal) Equal(other EbpfLocal) bool {
	return boolPtrEqual(l.Enabled, other.Enabled) &&
		l.DNSMode == other.DNSMode &&
		boolPtrEqual(l.BypassPrivateAddress, other.BypassPrivateAddress) &&
		l.CgroupPath == other.CgroupPath
}

// Equal compares two EbpfShared configs.
func (s *EbpfShared) Equal(other EbpfShared) bool {
	return boolPtrEqual(s.Enabled, other.Enabled) &&
		s.DNSMode == other.DNSMode &&
		boolPtrEqual(s.BypassPrivateAddress, other.BypassPrivateAddress) &&
		slices.Equal(s.Interface, other.Interface)
}
