package main

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func mergeMDNS(hosts []Host, iface *net.Interface, timeout time.Duration) {
	nameByIP := mdnsNameByIP(iface, timeout)
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

func mdnsNameByIP(iface *net.Interface, timeout time.Duration) map[string]string {
	out := map[string]string{}

	addr := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}

	conn, err := net.ListenMulticastUDP("udp4", iface, addr)
	if err != nil {
		return out
	}
	defer conn.Close()

	_ = conn.SetReadBuffer(1 << 20)

	// Query for "any" records. 
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn("_services._dns-sd._udp.local"), dns.TypePTR)

	b, err := q.Pack()
	if err != nil {
		return out
	}

	_, _ = conn.WriteToUDP(b, addr)
	time.Sleep(50 * time.Millisecond)
	_, _ = conn.WriteToUDP(b, addr)

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


		for _, rr := range append(m.Answer, m.Extra...) {
			switch t := rr.(type) {
			case *dns.A:
				ip := t.A.String()
				name := strings.TrimSuffix(t.Hdr.Name, ".")
				out[ip] = name
			case *dns.AAAA:
				ip := t.AAAA.String()
				name := strings.TrimSuffix(t.Hdr.Name, ".")
				out[ip] = name
			}
		}
	}

	return out
}

