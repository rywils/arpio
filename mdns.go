package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func mergeMDNS(hosts []Host, iface *net.Interface, timeout time.Duration) {
	var need []netip.Addr
	for _, h := range hosts {
		if h.Hostname == "" && h.IP.Is4() {
			need = append(need, h.IP)
		}
	}
	if len(need) == 0 {
		return
	}

	nameByIP := mdnsReverseLookup(iface, need, timeout)
	if len(nameByIP) == 0 {
		return
	}

	for i := range hosts {
		if hosts[i].Hostname != "" {
			continue
		}
		if n, ok := nameByIP[hosts[i].IP.String()]; ok {
			hosts[i].Hostname = n
		}
	}
}

// mdnsReverseLookup resolves hostnames via mDNS reverse PTR queries
// (RFC 6762 §12), the mechanism dns-sd/avahi-resolve-address use to turn
// an IP back into a name. Querying the DNS-SD service-enumeration name
// only returns pointers to service types, never host A/AAAA records, so
// it can't be used for this.
func mdnsReverseLookup(iface *net.Interface, targets []netip.Addr, timeout time.Duration) map[string]string {
	out := map[string]string{}

	addr := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	conn, err := net.ListenMulticastUDP("udp4", iface, addr)
	if err != nil {
		return out
	}
	defer conn.Close()

	_ = conn.SetReadBuffer(1 << 20)

	arpaToIP := sendReversePTRQueries(conn, addr, targets)
	if len(arpaToIP) == 0 {
		return out
	}

	return collectPTRResponses(conn, arpaToIP, timeout)
}

// sendReversePTRQueries fires one PTR query per target IP and returns a map
// from the queried "<ip>.in-addr.arpa." name back to the original IP string,
// so replies can be matched to the host that prompted them.
func sendReversePTRQueries(conn *net.UDPConn, addr *net.UDPAddr, targets []netip.Addr) map[string]string {
	arpaToIP := map[string]string{}
	for _, ip := range targets {
		name := reverseArpaName(ip)
		if name == "" {
			continue
		}
		arpaToIP[name] = ip.String()

		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypePTR)
		if b, err := q.Pack(); err == nil {
			_, _ = conn.WriteToUDP(b, addr)
		}
	}
	return arpaToIP
}

// collectPTRResponses reads replies until timeout, resolving arpaToIP
// entries to the hostnames carried in matching PTR answers.
func collectPTRResponses(conn *net.UDPConn, arpaToIP map[string]string, timeout time.Duration) map[string]string {
	out := map[string]string{}
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65536)

	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		m := new(dns.Msg)
		if err := m.Unpack(buf[:n]); err != nil {
			continue
		}

		addPTRAnswers(m, arpaToIP, out)
	}

	return out
}

// addPTRAnswers copies any PTR answer in m whose queried name is in
// arpaToIP into out, keyed by the original IP.
func addPTRAnswers(m *dns.Msg, arpaToIP, out map[string]string) {
	for _, rr := range append(m.Answer, m.Extra...) {
		ptr, ok := rr.(*dns.PTR)
		if !ok {
			continue
		}
		if ip, ok := arpaToIP[ptr.Hdr.Name]; ok {
			out[ip] = strings.TrimSuffix(ptr.Ptr, ".")
		}
	}
}

func reverseArpaName(ip netip.Addr) string {
	if !ip.Is4() {
		return ""
	}
	b := ip.As4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
}
