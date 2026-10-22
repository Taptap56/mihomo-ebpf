//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/keepalive"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"
)

// resolveTCP maps an accepted connection (identified by its token
// local address) to its original destination, trying the cgroup
// plane first, then the shared packet-rewrite plane.
func (m *Manager) resolveTCP(client, tokenDst netip.AddrPort) (commonEBPF.OriginalDestination, *commonEBPF.SharedPacketRewriteFlowHandle, bool) {
	if m.cgroup != nil {
		if original, err := m.cgroup.LookupOriginal(commonEBPF.ProtocolTCP, tokenDst); err == nil {
			return original, nil, true
		}
	}
	if backend := m.sharedBackend(); backend != nil {
		if original, flow, err := backend.LookupFlow(commonEBPF.ProtocolTCP, client, tokenDst); err == nil {
			return original, flow, true
		}
	}
	return commonEBPF.OriginalDestination{}, nil, false
}

func (m *Manager) handleTCP(conn net.Conn) {
	client, ok1 := addrPortOf(conn.RemoteAddr())
	tokenDst, ok2 := addrPortOf(conn.LocalAddr())
	if !ok1 || !ok2 {
		conn.Close()
		return
	}
	original, flow, ok := m.resolveTCP(client, tokenDst)
	if !ok {
		// Not one of ours (stale token or direct local connection
		// to the listener port): nothing sensible to route to.
		conn.Close()
		return
	}
	keepalive.TCPKeepAlive(conn)
	wrapped := &flowConn{Conn: conn, manager: m, flow: flow}
	target := socks5.AddrFromStdAddrPort(original.Destination)
	log.Debugln("ebpf: tcp %v -> %v", client, original.Destination)
	m.tunnel.HandleTCPConn(inbound.NewSocket(target, wrapped, C.EBPF, m.additions()...))
}

// flowConn releases the shared-plane flow when the connection ends.
type flowConn struct {
	net.Conn
	manager *Manager
	flow    *commonEBPF.SharedPacketRewriteFlowHandle
}

func (c *flowConn) Close() error {
	err := c.Conn.Close()
	if c.flow != nil {
		if backend := c.manager.sharedBackend(); backend != nil {
			_ = backend.ReleaseFlow(c.flow)
		}
		c.flow = nil
	}
	return err
}
