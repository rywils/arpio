package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type DarwinScanner struct {
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
	self, ok := netip.AddrFromSlice(ipnet.IP.To4())
	if !ok {
		return nil, nil, errors.New("failed to determine self IPv4")
	}

	ctx := &scannerCtx{
		ifaceName: iface.Name,
		iface:     anyIface{iface},
		subnet:    pfx,
		selfIP:    self,
		selfMAC:   iface.HardwareAddr.String(),
	}

	return &DarwinScanner{
		iface: iface,
		pfx:   pfx,
		self:  self,
		opts:  opts,
	}, ctx, nil
}

func (s *DarwinScanner) Scan() ([]Host, error) {
	if subnetTooLarge(s.pfx) {
		return nil, fmt.Errorf("refusing to scan %s: too many hosts (narrow the interface's subnet or use -passive)", s.pfx)
	}

	capture, err := openDarwinCapture(s.iface.Name)
	if err != nil {
		return nil, err
	}
	defer capture.close()

	for _, ip := range targetIPv4s(s.pfx, s.self) {
		_ = s.sendARPRequest(capture.handle, ip)
	}

	return collectDarwinARP(capture.parsed, s.opts.Timeout), nil
}

func (s *DarwinScanner) Passive() ([]Host, error) {
	capture, err := openDarwinCapture(s.iface.Name)
	if err != nil {
		return nil, err
	}
	defer capture.close()

	return collectDarwinARP(capture.parsed, s.opts.Timeout), nil
}

// darwinCapture is a live pcap handle plus the goroutine parsing ARP packets
// off it, shared by Scan and Passive.
type darwinCapture struct {
	handle *pcap.Handle
	parsed chan Host
	stop   chan struct{}
	wg     sync.WaitGroup
}

func openDarwinCapture(ifaceName string) (*darwinCapture, error) {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	_ = handle.SetBPFFilter("arp")

	c := &darwinCapture{
		handle: handle,
		parsed: make(chan Host, 128),
		stop:   make(chan struct{}),
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-c.stop:
				return
			case pkt := <-src.Packets():
				if pkt == nil {
					continue
				}
				if h, ok := hostFromARPPacket(pkt); ok {
					select {
					case c.parsed <- h:
					default:
					}
				}
			}
		}
	}()

	return c, nil
}

func (c *darwinCapture) close() {
	close(c.stop)
	c.handle.Close()
	c.wg.Wait()
}

func collectDarwinARP(parsed <-chan Host, timeout time.Duration) []Host {
	hosts := map[string]Host{}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case h := <-parsed:
			addHost(h.IP, h.MAC, hosts)
		case <-timer.C:
			return mapToSlice(hosts)
		}
	}
}

func hostFromARPPacket(pkt gopacket.Packet) (Host, bool) {
	arpLayer := pkt.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return Host{}, false
	}

	arpPkt := arpLayer.(*layers.ARP)
	ip, ok := netip.AddrFromSlice(arpPkt.SourceProtAddress)
	if !ok || !ip.Is4() {
		return Host{}, false
	}

	mac := net.HardwareAddr(arpPkt.SourceHwAddress)
	return Host{IP: ip, MAC: mac, MACStr: mac.String()}, true
}

func (s *DarwinScanner) sendARPRequest(handle *pcap.Handle, target netip.Addr) error {
	srcMAC := s.iface.HardwareAddr
	if len(srcMAC) != 6 {
		return errors.New("unexpected interface MAC length")
	}

	dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: s.self.AsSlice(), // 4 bytes
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    target.AsSlice(), // 4 bytes
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return err
	}

	return handle.WritePacketData(buf.Bytes())
}
