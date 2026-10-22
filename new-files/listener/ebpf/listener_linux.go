//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/log"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// listen binds the shared TCP/UDP listeners (both planes, both
// families) on the configured port. The library's redirect routes
// deliver the rewritten traffic to these wildcard sockets; each
// connection/datagram arrives with a token local address inside
// the redirect prefixes, which is the lookup key for the maps.
func (m *Manager) listen() error {
	port := int(m.port)
	tcp4, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", fmt.Sprint(port)))
	if err != nil {
		return fmt.Errorf("ebpf: listen tcp4: %w", err)
	}
	m.tcp4 = tcp4
	udp4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		m.Close()
		return fmt.Errorf("ebpf: listen udp4: %w", err)
	}
	m.udp4 = udp4
	if m.redirectIPv6.IsValid() {
		tcp6, err := net.Listen("tcp6", net.JoinHostPort("::", fmt.Sprint(port)))
		if err != nil {
			log.Warnln("ebpf: listen tcp6: %v (IPv6 disabled)", err)
		} else {
			m.tcp6 = tcp6
		}
		udp6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: port})
		if err != nil {
			log.Warnln("ebpf: listen udp6: %v (IPv6 disabled)", err)
		} else {
			m.udp6 = udp6
		}
	}
	go m.acceptLoop(m.tcp4)
	if m.tcp6 != nil {
		go m.acceptLoop(m.tcp6)
	}
	go m.readLoop4()
	if m.udp6 != nil {
		go m.readLoop6()
	}
	return nil
}

func (m *Manager) acceptLoop(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-m.ctx:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				// e.g. EMFILE: back off briefly instead of spinning.
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return
		}
		go m.handleTCP(conn)
	}
}

func addrPortOf(addr net.Addr) (netip.AddrPort, bool) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return netip.AddrPortFrom(ipOf(a.IP), uint16(a.Port)), true
	case *net.UDPAddr:
		return netip.AddrPortFrom(ipOf(a.IP), uint16(a.Port)), true
	}
	return netip.AddrPort{}, false
}

func ipOf(ip net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// readLoop4 reads IPv4 datagrams with their token destination
// (via IP_PKTINFO) and dispatches them to the UDP session path.
func (m *Manager) readLoop4() {
	pc := ipv4.NewPacketConn(m.udp4)
	_ = pc.SetControlMessage(ipv4.FlagDst, true)
	buffer := make([]byte, 65535)
	for {
		n, cm, src, err := pc.ReadFrom(buffer)
		if err != nil {
			if m.readStopped(err) {
				return
			}
			continue
		}
		if cm == nil || cm.Dst == nil {
			continue
		}
		client, ok := addrPortOf(src)
		if !ok {
			continue
		}
		tokenDst := netip.AddrPortFrom(ipOf(cm.Dst), m.port)
		payload := make([]byte, n)
		copy(payload, buffer[:n])
		m.handleUDPPacket(payload, client, tokenDst)
	}
}

// readLoop6 is readLoop4 for IPv6 datagrams.
func (m *Manager) readLoop6() {
	pc := ipv6.NewPacketConn(m.udp6)
	_ = pc.SetControlMessage(ipv6.FlagDst, true)
	buffer := make([]byte, 65535)
	for {
		n, cm, src, err := pc.ReadFrom(buffer)
		if err != nil {
			if m.readStopped(err) {
				return
			}
			continue
		}
		if cm == nil || cm.Dst == nil {
			continue
		}
		client, ok := addrPortOf(src)
		if !ok {
			continue
		}
		tokenDst := netip.AddrPortFrom(ipOf(cm.Dst), m.port)
		payload := make([]byte, n)
		copy(payload, buffer[:n])
		m.handleUDPPacket(payload, client, tokenDst)
	}
}

// readStopped reports whether a UDP read loop must exit: the
// listener is shutting down or the socket is closed. Any other
// error backs off briefly so a persistent failure cannot spin a CPU
// core at 100%.
func (m *Manager) readStopped(err error) bool {
	select {
	case <-m.ctx:
		return true
	default:
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	time.Sleep(10 * time.Millisecond)
	return false
}

// writeUDPReply sends payload to client through the socket of the
// client's family, with the packet info that makes the reply carry
// the binding's redirect (token) source address.
func (m *Manager) writeUDPReply(client netip.AddrPort, packetInfo []byte, payload []byte) error {
	if client.Addr().Is4() {
		_, _, err := m.udp4.WriteMsgUDPAddrPort(payload, packetInfo, client)
		return err
	}
	if m.udp6 == nil {
		return net.ErrClosed
	}
	_, _, err := m.udp6.WriteMsgUDPAddrPort(payload, packetInfo, client)
	return err
}

// sourcePacketInfo marshals the send-side packet info that sets
// the reply's source address (the redirect token), mirroring
// sing-box's sourcePacketInfo.
func sourcePacketInfo(address netip.Addr) []byte {
	if address.Is4() {
		return (&ipv4.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
	}
	return (&ipv6.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
}
