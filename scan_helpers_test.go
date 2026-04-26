package main

import (
	"net"
	"net/netip"
	"testing"
)

func TestAddHostDedupByIP(t *testing.T) {
	hosts := map[string]Host{}
	ip := netip.MustParseAddr("192.168.1.10")

	addHost(ip, net.HardwareAddr{0, 1, 2, 3, 4, 5}, hosts)
	addHost(ip, net.HardwareAddr{6, 7, 8, 9, 10, 11}, hosts)

	if got := len(hosts); got != 1 {
		t.Fatalf("expected 1 host, got %d", got)
	}
}

func TestTargetIPv4sSkipsNetworkBroadcastAndSelf(t *testing.T) {
	pfx := netip.MustParsePrefix("192.168.1.10/24")
	self := netip.MustParseAddr("192.168.1.10")

	targets := targetIPv4s(pfx, self)
	if len(targets) != 253 {
		t.Fatalf("expected 253 targets, got %d", len(targets))
	}

	for _, ip := range []string{"192.168.1.0", "192.168.1.255", "192.168.1.10"} {
		wantMissing := netip.MustParseAddr(ip)
		for _, got := range targets {
			if got == wantMissing {
				t.Fatalf("unexpected target present: %s", wantMissing)
			}
		}
	}
}

func TestIPv4NetworkAndBroadcast(t *testing.T) {
	pfx := netip.MustParsePrefix("10.0.3.7/20")
	network, broadcast, ok := ipv4NetworkAndBroadcast(pfx)
	if !ok {
		t.Fatal("expected IPv4 network/broadcast calculation to succeed")
	}
	if network.String() != "10.0.0.0" {
		t.Fatalf("unexpected network: %s", network)
	}
	if broadcast.String() != "10.0.15.255" {
		t.Fatalf("unexpected broadcast: %s", broadcast)
	}
}
