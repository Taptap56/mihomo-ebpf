//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"sync"
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

// idleTimeout is how long the session may stay silent before the
// janitor releases it; hijacked-DNS sessions are short-lived.
func (s *udpSession) idleTimeout() time.Duration {
	if s.dnsConn != nil {
		return dnsTimeout
	}
	return udpTimeout
}

// sessionRelease holds what must be freed when a session ends, so
// the (syscall-heavy) release can run outside sessionsMu.
type sessionRelease struct {
	dnsConn  *net.UDPConn
	bindings []*replyBinding
	flow     *commonEBPF.SharedPacketRewriteFlowHandle
}

// dnsBufferPool recycles the 64 KiB read buffers of the DNS relay
// loops instead of allocating one per hijacked-DNS session.
var dnsBufferPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, 65535)
		return &buffer
	},
}

// detachSessionLocked marks the session closed and returns what
// must be released. The caller must hold sessionsMu (write). It
// returns nil when the session was already closed.
func (m *Manager) detachSessionLocked(session *udpSession) *sessionRelease {
	if session.closed {
		return nil
	}
	session.closed = true
	release := &sessionRelease{dnsConn: session.dnsConn, flow: session.flow}
	for _, binding := range session.bindings {
		release.bindings = append(release.bindings, binding)
	}
	return release
}

// releaseSession frees library resources of a detached session.
// It does not need sessionsMu.
func (m *Manager) releaseSession(release *sessionRelease) {
	if release == nil {
		return
	}
	if release.dnsConn != nil {
		release.dnsConn.Close()
	}
	for _, binding := range release.bindings {
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
	if release.flow != nil {
		if backend := m.sharedBackend(); backend != nil {
			_ = backend.ReleaseFlow(release.flow)
		}
	}
}

// closeSessionLocked detaches and releases a session while the
// caller holds sessionsMu. The janitor uses expireSessions instead,
// which releases outside the lock.
func (m *Manager) closeSessionLocked(session *udpSession) {
	m.releaseSession(m.detachSessionLocked(session))
}

// expireSessions drops sessions idle past their timeout. Detaching
// happens under the lock; the BPF map/syscall cleanup runs after it
// is released so packets are not stalled behind it.
func (m *Manager) expireSessions(now time.Time) {
	var expired []*sessionRelease
	m.sessionsMu.Lock()
	for key, session := range m.sessions {
		if now.Sub(session.lastSeenTime()) > session.idleTimeout() {
			expired = append(expired, m.detachSessionLocked(session))
			delete(m.sessions, key)
		}
	}
	m.sessionsMu.Unlock()
	for _, release := range expired {
		m.releaseSession(release)
	}
}

// handleUDPPacket processes one datagram that arrived at the
// shared listener with the given token destination.
func (m *Manager) handleUDPPacket(payload []byte, client, tokenDst netip.AddrPort) {
	key := udpKey{client: client, token: tokenDst}
	m.sessionsMu.RLock()
	session, ok := m.sessions[key]
	m.sessionsMu.RUnlock()
	if !ok {
		m.sessionsMu.Lock()
		session, ok = m.sessions[key]
		if !ok {
			var err error
			session, err = m.newSessionLocked(key)
			if err != nil {
				m.sessionsMu.Unlock()
				return
			}
			m.sessions[key] = session
		}
		m.sessionsMu.Unlock()
	}
	session.touch()
	dnsConn := session.dnsConn

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
	bufferPtr := dnsBufferPool.Get().(*[]byte)
	defer dnsBufferPool.Put(bufferPtr)
	buffer := *bufferPtr
	var binding *replyBinding
	for {
		n, err := session.dnsConn.Read(buffer)
		if err != nil {
			return
		}
		session.touch()
		if binding == nil {
			b, err := m.sessionBinding(session, session.origDst)
			if err != nil {
				continue
			}
			binding = b
		}
		// The write is synchronous (the kernel copies the data), so
		// the pooled buffer can be sent directly without a copy.
		_ = m.writeUDPReply(session.key.client, binding.packetInfo, buffer[:n])
	}
}

// sessionBinding returns (creating on first use) the reply
// binding that makes replies appear to come from source.
func (m *Manager) sessionBinding(session *udpSession, source netip.AddrPort) (*replyBinding, error) {
	m.sessionsMu.RLock()
	existing, found := session.bindings[source]
	m.sessionsMu.RUnlock()
	if found {
		return existing, nil
	}
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

