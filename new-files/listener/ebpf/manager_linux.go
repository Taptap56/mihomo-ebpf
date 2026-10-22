//go:build with_ebpf && (linux || android)

// Package ebpf is mihomo's consumer of the sing-ebpf library
// (github.com/CHIZI-0618/sing-ebpf, by CHIZI-0618): the same eBPF
// datapath CHIZI's sing-box fork uses, re-implemented here as a
// mihomo listener. The library owns the BPF programs, maps and
// attachments; this package owns the listeners, the UDP session
// state and the hand-off to mihomo's tunnel.
//
//   - Local plane (cgroup hooks): this device's own TCP+UDP.
//     Original destinations are recovered with LookupOriginal.
//   - Shared plane (TC packet rewrite on the configured
//     interfaces): hotspot/tethering clients' TCP+UDP.
//     Original destinations are recovered with LookupFlow.
//
// Both planes share one listener port and the library's redirect
// prefixes, exactly like sing-box's ebpf inbound.
package ebpf

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	kernelRuntime "github.com/CHIZI-0618/sing-ebpf/runtime"
	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	"golang.org/x/sys/unix"
)

const (
	defaultPort       = 15361
	defaultDNSListen  = "127.0.0.1:1053"
	defaultCgroupPath = "/sys/fs/cgroup"
	udpTimeout        = 5 * time.Minute
	reconcileInterval = 5 * time.Second
)

var (
	redirectIPv4Candidates = []netip.Prefix{
		netip.MustParsePrefix("127.128.0.0/9"),
		netip.MustParsePrefix("127.64.0.0/10"),
	}
	redirectIPv6Candidates = []netip.Prefix{
		netip.MustParsePrefix("fd53:696e:672d:626f::/64"), // "sing-bo"
		netip.MustParsePrefix("fd53:696e:672d:6270::/64"), // "sing-bp"
	}
	privatePrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
	}
)

type planeKind uint8

const (
	planeCgroup planeKind = iota + 1
	planeShared
)

// Manager owns the whole eBPF datapath for one config generation.
type Manager struct {
	cfg    LC.Ebpf
	tunnel C.Tunnel
	name   string

	port       uint16
	dnsTarget  netip.AddrPort
	cgroupPath string

	localEnabled   bool
	sharedEnabled  bool
	localDNSHijack bool
	sharedDNSHijack bool
	bypassPrivate  bool

	policy       commonEBPF.CompiledPolicy
	redirectIPv4 netip.Prefix
	redirectIPv6 netip.Prefix

	selfBypass *commonEBPF.SelfBypass
	cgroup     *commonEBPF.CgroupBackend

	sharedRuntime kernelRuntime.SharedPacketRewriteRuntime

	tcp4 net.Listener
	tcp6 net.Listener
	udp4 *net.UDPConn
	udp6 *net.UDPConn

	sessionsMu sync.Mutex
	sessions   map[udpKey]*udpSession

	ctx    chan struct{}
	closed sync.Once
	wg     sync.WaitGroup
}

// NewManager creates a Manager for cfg; call Start to activate.
// name is the listener name from the config ("ebpf-in" by
// convention); it becomes the inbound name of every connection.
func NewManager(cfg LC.Ebpf, tunnel C.Tunnel, name string) *Manager {
	if name == "" {
		name = "EBPF"
	}
	return &Manager{
		cfg:      cfg,
		tunnel:   tunnel,
		name:     name,
		sessions: make(map[udpKey]*udpSession),
		ctx:      make(chan struct{}),
	}
}

// additions returns the inbound additions stamped on connections
// handed to the tunnel: the listener's configured name.
func (m *Manager) additions() []inbound.Addition {
	return []inbound.Addition{
		inbound.WithInName(m.name),
		inbound.WithSpecialRules(""),
	}
}

func boolDefault(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func (m *Manager) resolveConfig() error {
	m.port = m.cfg.Port
	if m.port == 0 {
		m.port = defaultPort
	}
	dnsListen := m.cfg.DNSListen
	if dnsListen == "" {
		dnsListen = defaultDNSListen
	}
	target, err := netip.ParseAddrPort(dnsListen)
	if err != nil {
		return fmt.Errorf("ebpf: invalid dns-listen %q: %w", dnsListen, err)
	}
	m.dnsTarget = target
	m.cgroupPath = m.cfg.Local.CgroupPath
	if m.cgroupPath == "" {
		if root, err := commonEBPF.DetectCgroup2Root(); err == nil && root != "" {
			m.cgroupPath = root
		} else {
			m.cgroupPath = defaultCgroupPath
		}
	}
	m.localEnabled = boolDefault(m.cfg.Local.Enabled, true)
	m.sharedEnabled = boolDefault(m.cfg.Shared.Enabled, len(m.cfg.Shared.Interface) > 0)
	m.localDNSHijack = m.cfg.Local.DNSMode != "off"
	m.sharedDNSHijack = m.cfg.Shared.DNSMode != "off"
	m.bypassPrivate = boolDefault(m.cfg.Local.BypassPrivateAddress, true) ||
		boolDefault(m.cfg.Shared.BypassPrivateAddress, true)
	if !m.localEnabled && !m.sharedEnabled {
		return errors.New("ebpf: both local and shared planes are disabled")
	}
	if m.sharedEnabled && len(m.cfg.Shared.Interface) == 0 {
		return errors.New("ebpf: shared plane enabled but no interface configured")
	}
	return nil
}

func (m *Manager) compilePolicy() error {
	policy, err := commonEBPF.CompileActionPolicy(commonEBPF.ActionPolicy{
		Local: commonEBPF.ActionScope{
			Default: commonEBPF.DecisionIntercept,
			UID: []commonEBPF.UIDDecision{
				// mihomo itself runs as root; never capture UID 0 or the
				// datapath loops on the core's own outbound sockets.
				{Start: 0, End: 0, Action: commonEBPF.DecisionPass},
			},
		},
		Shared: commonEBPF.ActionScope{
			Default: commonEBPF.DecisionIntercept,
		},
	})
	if err != nil {
		return fmt.Errorf("ebpf: compile policy: %w", err)
	}
	m.policy = policy
	return nil
}

func (m *Manager) bypassDecisions() []commonEBPF.CIDRDecision {
	if !m.bypassPrivate {
		return nil
	}
	decisions := make([]commonEBPF.CIDRDecision, 0, len(privatePrefixes))
	for _, prefix := range privatePrefixes {
		decisions = append(decisions, commonEBPF.CIDRDecision{
			Prefix: prefix, Action: commonEBPF.DecisionPass,
		})
	}
	return decisions
}

func hostAddresses() []netip.Addr {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var addresses []netip.Addr
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ip, ok := netipxFromIP(ipNet.IP); ok {
					addresses = append(addresses, ip)
				}
			}
		}
	}
	return addresses
}

func netipxFromIP(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func (m *Manager) selectRedirectPrefixes() error {
	// No consumer-side exclusions: the library itself checks the
	// candidates against interface addresses and existing routes.
	// (Passing this device's interface prefixes here — as an earlier
	// version did — rejects every candidate, because the loopback
	// prefix 127.0.0.0/8 contains both IPv4 candidates. sing-box's
	// consumer only excludes its FakeIP ranges, which mihomo's
	// consumer does not need: the default fake-ip range never
	// overlaps the redirect candidates.)
	prefix, err := commonEBPF.SelectRedirectPrefix(unix.AF_INET, redirectIPv4Candidates, nil)
	if err != nil {
		return fmt.Errorf("ebpf: select IPv4 redirect prefix: %w", err)
	}
	m.redirectIPv4 = prefix
	prefix, err = commonEBPF.SelectRedirectPrefix(unix.AF_INET6, redirectIPv6Candidates, nil)
	if err != nil {
		// IPv6 is optional; the datapath continues IPv4-only.
		log.Warnln("ebpf: no IPv6 redirect prefix available: %v", err)
		m.redirectIPv6 = netip.Prefix{}
		return nil
	}
	m.redirectIPv6 = prefix
	return nil
}


// Start binds the listeners and attaches the enabled eBPF planes.
func (m *Manager) Start() error {
	if err := m.resolveConfig(); err != nil {
		return err
	}
	if err := m.compilePolicy(); err != nil {
		return err
	}
	if err := m.selectRedirectPrefixes(); err != nil {
		return err
	}
	if err := m.listen(); err != nil {
		return err
	}
	started := false
	defer func() {
		if !started {
			m.Close()
		}
	}()

	if selfBypass, err := commonEBPF.NewSelfBypass(); err == nil {
		m.selfBypass = selfBypass
	} else {
		log.Warnln("ebpf: self-bypass unavailable: %v", err)
	}

	if m.localEnabled {
		if err := m.startCgroup(); err != nil {
			return fmt.Errorf("ebpf: local plane: %w", err)
		}
	}
	if m.sharedEnabled {
		if err := m.startShared(); err != nil {
			return fmt.Errorf("ebpf: shared plane: %w", err)
		}
	}
	m.wg.Add(1)
	go m.janitor()
	started = true
	log.Infoln("ebpf: datapath started (port %d, local=%v, shared=%v, redirect4=%v, redirect6=%v)",
		m.port, m.localEnabled, m.sharedEnabled, m.redirectIPv4, m.redirectIPv6)
	return nil
}

func (m *Manager) startCgroup() error {
	mapCapacity := commonEBPF.DefaultCgroupMapCapacity()
	if runtime.GOOS == "android" {
		mapCapacity = commonEBPF.CompactCgroupMapCapacity()
	}
	backend, err := commonEBPF.PrepareCgroup(commonEBPF.CgroupConfig{
		Path:         m.cgroupPath,
		EnableTCP:    true,
		EnableUDP:    true,
		EnableIPv6:   m.redirectIPv6.IsValid(),
		RedirectIPv4: m.redirectIPv4,
		RedirectIPv6: m.redirectIPv6,
		MapCapacity:  mapCapacity,
		UDPTimeout:   udpTimeout,
		Policy:       m.policy,
		SelfBypass:   m.selfBypass,
	})
	if err != nil {
		return err
	}
	m.cgroup = backend
	if err := backend.LoadPrograms(m.port); err != nil {
		return err
	}
	if err := backend.Attach(); err != nil {
		return err
	}
	if decisions := m.bypassDecisions(); len(decisions) > 0 {
		if _, err := backend.UpdateDestinationDecisions(decisions); err != nil {
			log.Warnln("ebpf: local bypass decisions: %v", err)
		}
	}
	if err := backend.UpdateHostAddresses(hostAddresses()); err != nil {
		log.Warnln("ebpf: local host addresses: %v", err)
	}
	return nil
}

func (m *Manager) prepareSharedBackend() (*commonEBPF.SharedPacketRewriteBackend, error) {
	mapCapacity := commonEBPF.DefaultSharedPacketRewriteMapCapacity()
	if runtime.GOOS == "android" {
		mapCapacity = commonEBPF.CompactSharedPacketRewriteMapCapacity()
	}
	backend, err := commonEBPF.PrepareSharedPacketRewrite(commonEBPF.SharedPacketRewriteConfig{
		ListenerPort:  m.port,
		EnableTCP:     true,
		EnableUDP:     true,
		RedirectIPv4:  m.redirectIPv4,
		RedirectIPv6:  m.redirectIPv6,
		Policy:        m.policy,
		MapCapacity:   mapCapacity,
		UDPTimeout:    udpTimeout,
		ICMPEchoReply: false,
	})
	if err != nil {
		return nil, err
	}
	if decisions := m.bypassDecisions(); len(decisions) > 0 {
		if _, err := backend.UpdateDestinationDecisions(decisions); err != nil {
			backend.Close()
			return nil, err
		}
	}
	if err := backend.Enable(); err != nil {
		backend.Close()
		return nil, err
	}
	return backend, nil
}

func (m *Manager) startShared() error {
	m.sharedRuntime = kernelRuntime.NewSharedPacketRewriteRuntime(kernelRuntime.SharedPacketRewriteRuntimeConfig{
		Hooks: kernelRuntime.SharedPacketRewriteHooks{
			PrepareBackend: m.prepareSharedBackend,
			PurgeUserspaceFlow: func() {
				m.sessionsMu.Lock()
				for key, session := range m.sessions {
					if session.plane == planeShared {
						m.closeSessionLocked(session)
						delete(m.sessions, key)
					}
				}
				m.sessionsMu.Unlock()
			},
		},
	})
	if err := m.sharedRuntime.Reconcile(m.cfg.Shared.Interface, hostAddresses()); err != nil {
		log.Warnln("ebpf: shared reconcile: %v (will retry in background)", err)
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(reconcileInterval)
		defer ticker.Stop()
		for {
			select {
			case <-m.ctx:
				return
			case <-ticker.C:
				_ = m.sharedRuntime.Reconcile(m.cfg.Shared.Interface, hostAddresses())
			}
		}
	}()
	return nil
}

func (m *Manager) sharedBackend() *commonEBPF.SharedPacketRewriteBackend {
	if m.sharedRuntime == nil {
		return nil
	}
	return m.sharedRuntime.Backend()
}

func (m *Manager) janitor() {
	defer m.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx:
			return
		case now := <-ticker.C:
			m.sessionsMu.Lock()
			for key, session := range m.sessions {
				if now.Sub(session.lastSeenTime()) > udpTimeout {
					m.closeSessionLocked(session)
					delete(m.sessions, key)
				}
			}
			m.sessionsMu.Unlock()
			if backend := m.sharedBackend(); backend != nil {
				_, _ = backend.SweepOrphanedFlows(udpTimeout, 256)
			}
		}
	}
}

// Close detaches the planes and closes the listeners.
func (m *Manager) Close() error {
	m.closed.Do(func() {
		close(m.ctx)
	})
	if m.tcp4 != nil {
		m.tcp4.Close()
	}
	if m.tcp6 != nil {
		m.tcp6.Close()
	}
	if m.udp4 != nil {
		m.udp4.Close()
	}
	if m.udp6 != nil {
		m.udp6.Close()
	}
	m.sessionsMu.Lock()
	for key, session := range m.sessions {
		m.closeSessionLocked(session)
		delete(m.sessions, key)
	}
	m.sessionsMu.Unlock()
	if m.sharedRuntime != nil {
		m.sharedRuntime.Close()
	}
	if m.cgroup != nil {
		m.cgroup.Close()
	}
	if m.selfBypass != nil {
		m.selfBypass.Close()
	}
	m.wg.Wait()
	return nil
}
