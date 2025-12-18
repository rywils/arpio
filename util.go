package main

import (
	"errors"
	"fmt"
	"net"
	"os"
)

func checkPrivileges() {
	// NOTE: macOS pcap capture may still work without root depending on perms,
	// but ARP injection/capture is typically best with sudo
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "⚠️  warning: not running as root, results may be incomplete")
	}
}

func printHosts(hosts []Host) {
	fmt.Printf("%-15s %-18s %-18s %s\n", "IP", "MAC", "VENDOR", "HOSTNAME")
	fmt.Println("----------------------------------------------------------------")
	for _, h := range hosts {
		fmt.Printf("%-15s %-18s %-18s %s\n", h.IP, h.MACStr, h.Vendor, h.Hostname)
	}
}

func getInterfaceByName(name string) (*net.Interface, *net.IPNet, error) {
	if name == "" {
		return nil, nil, errors.New("empty interface name")
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, err
	}

	ipnet, err := firstIPv4Net(iface)
	if err != nil {
		return nil, nil, err
	}

	return iface, ipnet, nil
}

func getDefaultInterface() (*net.Interface, *net.IPNet, error) {
	ifaces, _ := net.Interfaces()

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ipnet, err := firstIPv4Net(&iface)
		if err == nil {
			return &iface, ipnet, nil
		}
	}
	return nil, nil, errors.New("no usable interface found")
}

func firstIPv4Net(iface *net.Interface) (*net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet, nil
		}
	}
	return nil, errors.New("no IPv4 address found on interface")
}

