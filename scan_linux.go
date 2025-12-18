package main

import (
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/arp"
)

type anyIface struct{ iface *net.Interface }

type LinuxScanner struct {
	iface *net.Interface
	pfx   netip.Prefix
	opts  Options
}

func NewScanner(opts Options) (Scanner, *scannerCtx, error) {
	var iface *net.Interface
	var ipnet *net.IPNet
	var err error

	if opts.IfaceName != "" {
		iface, ipnet, err = getInterfaceByName(opts.IfaceName)
	} else {
		iface, ipnet, err = getDefaultInterface()
	}
	if err != nil {
		return nil, nil, err
	}

	pfx, _ := netip.ParsePrefix(ipnet.String())

	self, _ := netip.AddrFromSlice(ipnet.IP.To4())

	ctx := &scannerCtx{
		ifaceName: iface.Name,
		iface:     anyIface{iface},
		subnet:    pfx,
		selfIP:    self,
		selfMAC:   iface.HardwareAddr.String(),
	}

	return &LinuxScanner{iface: iface, pfx: pfx, opts: opts}, ctx, nil
}

func (s *LinuxScanner) Scan() ([]Host, error) {
	c, err := arp.Dial(s.iface)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	hosts := map[string]Host{}
	timeout := time.After(s.opts.Timeout)

	// fire requests
	for ip := s.pfx.Addr(); s.pfx.Contains(ip); ip = ip.Next() {
		go c.Request(ip)
	}

	for {
		select {
		case <-timeout:
			return mapToSlice(hosts), nil
		default:
			pkt, _, err := c.Read()
			if err != nil {
				continue
			}
			addHost(pkt.SenderIP, pkt.SenderHardwareAddr, hosts)
		}
	}
}

func (s *LinuxScanner) Passive() ([]Host, error) {
	c, err := arp.Dial(s.iface)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	hosts := map[string]Host{}
	timeout := time.After(s.opts.Timeout)

	for {
		select {
		case <-timeout:
			return mapToSlice(hosts), nil
		default:
			pkt, _, err := c.Read()
			if err == nil {
				addHost(pkt.SenderIP, pkt.SenderHardwareAddr, hosts)
			}
		}
	}
}

