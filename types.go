package main

import (
	"net"
	"net/netip"
	"time"
)

type Host struct {
	IP       netip.Addr        `json:"ip"`
	MAC      net.HardwareAddr  `json:"-"`
	MACStr   string            `json:"mac"`
	Vendor   string            `json:"vendor,omitempty"`
	Hostname string            `json:"hostname,omitempty"`
}

type Options struct {
	IfaceName string
	Timeout   time.Duration
	Interval  time.Duration
	MDNS      bool
}

type Scanner interface {
	Scan() ([]Host, error)    // active (if supported)
	Passive() ([]Host, error) // listen-only
}

