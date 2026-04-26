package main

import (
	"net"
	"net/netip"
)

func addHost(ip netip.Addr, mac net.HardwareAddr, hosts map[string]Host) {
	key := ip.String()
	if _, ok := hosts[key]; ok {
		return
	}

	h := Host{
		IP:     ip,
		MAC:    mac,
		MACStr: mac.String(),
	}

	hosts[key] = h
}

func mapToSlice(m map[string]Host) []Host {
	out := make([]Host, 0, len(m))
	for _, h := range m {
		out = append(out, h)
	}
	return out
}

func targetIPv4s(pfx netip.Prefix, self netip.Addr) []netip.Addr {
	if !pfx.Addr().Is4() {
		return nil
	}

	network, broadcast, ok := ipv4NetworkAndBroadcast(pfx)
	if !ok {
		return nil
	}

	var out []netip.Addr
	for ip := pfx.Masked().Addr(); pfx.Contains(ip); ip = ip.Next() {
		if !ip.Is4() {
			continue
		}
		if ip == self || ip == network || ip == broadcast {
			continue
		}
		out = append(out, ip)
	}
	return out
}

func ipv4NetworkAndBroadcast(pfx netip.Prefix) (netip.Addr, netip.Addr, bool) {
	if !pfx.Addr().Is4() {
		return netip.Addr{}, netip.Addr{}, false
	}

	network := pfx.Masked().Addr()
	netU32, ok := ipv4ToUint32(network)
	if !ok {
		return netip.Addr{}, netip.Addr{}, false
	}

	bits := pfx.Bits()
	if bits < 0 || bits > 32 {
		return netip.Addr{}, netip.Addr{}, false
	}

	var hostMask uint32
	if bits == 32 {
		hostMask = 0
	} else {
		hostMask = (1 << (32 - bits)) - 1
	}

	broadcast := uint32ToIPv4(netU32 | hostMask)
	return network, broadcast, true
}

func ipv4ToUint32(ip netip.Addr) (uint32, bool) {
	if !ip.Is4() {
		return 0, false
	}
	b := ip.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), true
}

func uint32ToIPv4(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	})
}
