package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func runCLI() error {
	if len(os.Args) < 2 {
		usage()
		return nil
	}

	switch os.Args[1] {
	case "scan":
		return runScan(os.Args[2:])
	case "watch":
		return runWatch(os.Args[2:])
	default:
		usage()
		return nil
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output JSON")
	passive := fs.Bool("passive", false, "passive only (no ARP injection)")
	iface := fs.String("iface", "", "interface name (e.g. en0)")
	timeout := fs.Duration("timeout", 3*time.Second, "scan timeout (e.g. 3s)")
	mdns := fs.Bool("mdns", true, "mDNS discovery (hostnames)")
	fs.Parse(args)

	checkPrivileges()

	opts := Options{
		IfaceName: *iface,
		Timeout:   *timeout,
		MDNS:      *mdns,
	}

	scanner, ctx, err := NewScanner(opts)
	if err != nil {
		return err
	}

	var hosts []Host
	if *passive {
		hosts, err = scanner.Passive()
	} else {
		hosts, err = scanner.Scan()
	}
	if err != nil {
		return err
	}

	// Enrich vendors + (optionally) mDNS hostnames
	enrichVendors(hosts)

	if opts.MDNS {
		mergeMDNS(hosts, ctx.iface, opts.Timeout)
	}

	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(hosts)
	}

	printHosts(hosts)
	return nil
}

func runWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	passive := fs.Bool("passive", false, "passive only (no ARP injection)")
	iface := fs.String("iface", "", "interface name (e.g. en0)")
	timeout := fs.Duration("timeout", 3*time.Second, "per-iteration timeout (e.g. 3s)")
	interval := fs.Duration("interval", 2*time.Second, "refresh interval (e.g. 2s)")
	mdns := fs.Bool("mdns", true, "mDNS discovery (hostnames)")
	fs.Parse(args)

	checkPrivileges()

	opts := Options{
		IfaceName: *iface,
		Timeout:   *timeout,
		Interval:  *interval,
		MDNS:      *mdns,
	}

	scanner, ctx, err := NewScanner(opts)
	if err != nil {
		return err
	}

	return watchLoop(scanner, ctx, opts, *passive)
}

func usage() {
	fmt.Println(`arpio — fast LAN discovery

Usage:
  arpio scan  [--json] [--passive] [--iface en0] [--timeout 3s] [--mdns=true|false]
  arpio watch [--passive]          [--iface en0] [--timeout 3s] [--interval 2s] [--mdns=true|false]
`)
}

