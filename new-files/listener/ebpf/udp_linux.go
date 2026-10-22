//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

// udpKey identifies a session by the client endpoint and the
// token destination its packets arrive at. The token is unique
// per flow in the library's maps, so (client, token) pins a flow.
type udpKey struct {
	client netip.AddrPort
	token  netip.AddrPort
}

type replyBinding struct {
	packetInfo []byte
	redirect   netip.Addr // cgroup plane: reserved reply token
	flow       *commonEBPF.SharedPacketRewriteFlowHandle
}

type udpSession struct {
	key       udpKey
	plane     planeKind
	origDst   netip.AddrPort
	flow      *commonEBPF.SharedPacketRewriteFlowHandle // shared plane base flow
	clientMAC net.HardwareAddr
	bindings  map[netip.AddrPort]*replyBinding
	dnsConn   *net.UDPConn
	lastSeen  atomic.Int64 // unix nano
	closed    bool
}

func (s *udpSession) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

func (s *udpSession) lastSeenTime() time.Time {
	return time.Unix(0, s.lastSeen.Load())
}

// closeLocked releases library resources of the session. The
// caller must hold Manager.sessionsMu.
func (m *Manager) closeSessionLocked(session *udpSession) {
	if session.closed {
		return
	}
	session.closed = true
	if session.dnsConn != nil {
		session.dnsConn.Close()
	}
	for _, binding := range session.bindings {
		if binding.flow != nil {
			if backend := m.sharedBackend(); backend != nil {
				_ = backend.ReleaseFlow(binding.flow)
			}
		}
		if binding.redirect.IsValid() && m.cgroup != nil {
			_ = m.cgroup.DeleteRedirect(commonEBPF.ProtocolUDP,
				netip.AddrPortFrom(binding.redirect, m.port))
		}
	}
	if session.flow != nil {
		if backend := m.sharedBackend(); backend != nil {
			_ = backend.ReleaseFlow(session.flow)
		}
	}
}


// handleUDPPacket processes one datagram that arrived at the
// shared listener with the given token destination.
func (m *Manager) handleUDPPacket(payload []byte, client, tokenDst netip.AddrPort) {
	key := udpKey{client: client, token: tokenDst}
	m.sessionsMu.Lock()
	session, ok := m.sessions[key]
	if !ok {
		var err error
		session, err = m.newSessionLocked(key)
		if err != nil {
			m.sessionsMu.Unlock()
			return
		}
		m.sessions[key] = session
	}
	session.touch()
	dnsConn := session.dnsConn
	m.sessionsMu.Unlock()

	if dnsConn != nil {
		_, _ = dnsConn.Write(payload)
		return
	}
	packet := &udpPacket{
		manager:  m,
		session:  session,
		data:     payload,
		tokenDst: tokenDst,
	}
	target := socks5.AddrFromStdAddrPort(session.origDst)
	m.tunnel.HandleUDPPacket(inbound.NewPacket(target, packet, C.EBPF, m.additions()...))
}

// newSessionLocked resolves a fresh (client, token) pair to its
// original destination through the cgroup plane first, then the
// shared plane, and prepares DNS hijacking when applicable. The
// caller must hold sessionsMu.
func (m *Manager) newSessionLocked(key udpKey) (*udpSession, error) {
	session := &udpSession{
		key:      key,
		bindings: make(map[netip.AddrPort]*replyBinding),
	}
	resolved := false
	if m.cgroup != nil {
		if original, err := m.cgroup.LookupOriginal(commonEBPF.ProtocolUDP, key.token); err == nil {
			session.plane = planeCgroup
			session.origDst = original.Destination
			resolved = true
		}
	}
	if !resolved {
		backend := m.sharedBackend()
		if backend == nil {
			return nil, net.ErrClosed
		}
		original, flow, err := backend.LookupFlow(commonEBPF.ProtocolUDP, key.client, key.token)
		if err != nil {
			return nil, err
		}
		session.plane = planeShared
		session.origDst = original.Destination
		session.flow = flow
		session.clientMAC = original.SourceMAC
		resolved = true
	}
	session.touch()

	hijack := (session.plane == planeCgroup && m.localDNSHijack) ||
		(session.plane == planeShared && m.sharedDNSHijack)
	if hijack && session.origDst.Port() == 53 {
		conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(m.dnsTarget))
		if err != nil {
			return nil, err
		}
		session.dnsConn = conn
		go m.dnsRelayLoop(session)
	}
	return session, nil
}

// dnsRelayLoop forwards DNS answers back to the client with the
// reply binding of the original DNS server address.
func (m *Manager) dnsRelayLoop(session *udpSession) {
	buffer := make([]byte, 65535)
	for {
		n, err := session.dnsConn.Read(buffer)
		if err != nil {
			return
		}
		payload := make([]byte, n)
		copy(payload, buffer[:n])
		session.touch()
		binding, err := m.sessionBinding(session, session.origDst)
		if err != nil {
			continue
		}
		_ = m.writeUDPReply(session.key.client, binding.packetInfo, payload)
	}
}

// sessionBinding returns (creating on first use) the reply
// binding that makes replies appear to come from source.
func (m *Manager) sessionBinding(session *udpSession, source netip.AddrPort) (*replyBinding, error) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	if binding, ok := session.bindings[source]; ok {
		return binding, nil
	}
	if session.closed {
		return nil, net.ErrClosed
	}
	binding := &replyBinding{}
	switch session.plane {
	case planeCgroup:
		redirect, err := m.cgroup.ReserveUDPReplyRedirect(source, m.port)
		if err != nil {
			return nil, err
		}
		binding.redirect = redirect
		binding.packetInfo = sourcePacketInfo(redirect)
	case planeShared:
		backend := m.sharedBackend()
		if backend == nil {
			return nil, net.ErrClosed
		}
		tokenSource, flow, err := backend.ReserveUDPReplyFlow(session.flow, source, session.clientMAC)
		if err != nil {
			return nil, err
		}
		binding.flow = flow
		binding.packetInfo = sourcePacketInfo(tokenSource)
	}
	session.bindings[source] = binding
	return binding, nil
}

// udpPacket adapts one datagram to mihomo's UDPPacket. Replies
// (WriteBack) are written through the session's reply binding so
// the client sees the original destination as the source.
type udpPacket struct {
	manager  *Manager
	session  *udpSession
	data     []byte
	tokenDst netip.AddrPort
}

func (p *udpPacket) Data() []byte { return p.data }

func (p *udpPacket) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(p.tokenDst)
}

func (p *udpPacket) Drop() {}

func (p *udpPacket) WriteBack(payload []byte, addr net.Addr) (int, error) {
	source := p.session.origDst
	if addr != nil {
		if addrPort, ok := addrPortOf(addr); ok {
			source = addrPort
		}
	}
	binding, err := p.manager.sessionBinding(p.session, source)
	if err != nil {
		return 0, err
	}
	p.session.touch()
	if err := p.manager.writeUDPReply(p.session.key.client, binding.packetInfo, payload); err != nil {
		return 0, err
	}
	return len(payload), nil
}

var _ C.UDPPacket = (*udpPacket)(nil)

