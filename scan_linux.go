package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/arp"
)

type LinuxScanner struct {
	iface *net.Interface
	pfx   netip.Prefix
	self  netip.Addr
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

	return &LinuxScanner{iface: iface, pfx: pfx, self: self, opts: opts}, ctx, nil
}

func (s *LinuxScanner) Scan() ([]Host, error) {
	if subnetTooLarge(s.pfx) {
		return nil, fmt.Errorf("refusing to scan %s: too many hosts (narrow the interface's subnet or use -passive)", s.pfx)
	}

	c, err := arp.Dial(s.iface)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	// fire requests (skip self/network/broadcast)
	for _, ip := range targetIPv4s(s.pfx, s.self) {
		if err := c.Request(ip); err != nil {
			// continue scanning even if one request fails
			continue
		}
	}

	return collectLinuxARP(c, s.opts.Timeout)
}

func (s *LinuxScanner) Passive() ([]Host, error) {
	c, err := arp.Dial(s.iface)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	return collectLinuxARP(c, s.opts.Timeout)
}

func collectLinuxARP(c *arp.Client, timeout time.Duration) ([]Host, error) {
	hosts := map[string]Host{}
	type reply struct {
		ip  netip.Addr
		mac net.HardwareAddr
	}
	replyCh := make(chan reply, 64)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			pkt, _, err := c.Read()
			if err != nil {
				// Close() on timeout is expected to break Read().
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}

			select {
			case replyCh <- reply{ip: pkt.SenderIP, mac: pkt.SenderHardwareAddr}:
			case <-done:
				return
			}
		}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			_ = c.Close()
			<-done
			return mapToSlice(hosts), nil
		case r := <-replyCh:
			addHost(r.ip, r.mac, hosts)
		}
	}
}
