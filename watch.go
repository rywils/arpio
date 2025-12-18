package main

import (
	"fmt"
	"net/netip"
	"sort"
	"time"
)

// scannerCtx is populated by NewScanner() (linux + darwin)
type scannerCtx struct {
	ifaceName string
	iface     anyIface
	subnet    netip.Prefix
	selfIP    netip.Addr
	selfMAC   string
}

func (a anyIface) unwrap() *net.Interface {
	return a.iface
}

func watchLoop(scanner Scanner, ctx *scannerCtx, opts Options, passive bool) error {
	seen := map[string]Host{}

	for {
		var hosts []Host
		var err error

		if passive {
			hosts, err = scanner.Passive()
		} else {
			hosts, err = scanner.Scan()
		}
		if err != nil {
			return err
		}

		enrichVendors(hosts)

		if opts.MDNS {
			mergeMDNS(hosts, ctx.iface.unwrap(), opts.Timeout)
		}

		for _, h := range hosts {
			if old, ok := seen[h.IP.String()]; ok {
				if h.Hostname == "" {
					h.Hostname = old.Hostname
				}
				if h.Vendor == "" {
					h.Vendor = old.Vendor
				}
			}
			seen[h.IP.String()] = h
		}

		clearScreen()
		fmt.Printf(
			"arpio watch — iface=%s subnet=%s refresh=%s\n\n",
			ctx.ifaceName,
			ctx.subnet.String(),
			opts.Interval,
		)

		printHosts(sortedHosts(seen))

		time.Sleep(opts.Interval)
	}
}

func sortedHosts(m map[string]Host) []Host {
	out := make([]Host, 0, len(m))
	for _, h := range m {
		out = append(out, h)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].IP.Less(out[j].IP)
	})

	return out
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

