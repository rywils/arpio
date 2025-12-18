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

