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

type anyIface struct{ iface *net.Interface }

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

	handle, err := pcap.OpenLive(s.iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	_ = handle.SetBPFFilter("arp")

	hosts := map[string]Host{}
	parsed := make(chan Host, 128)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-stop:
				return
			case pkt := <-src.Packets():
				if pkt == nil {
					continue
				}
				if h, ok := hostFromARPPacket(pkt); ok {
					select {
					case parsed <- h:
					default:
					}
				}
			}
		}
	}()

	// Inject ARP requests for each usable host IP in subnet.
	for _, ip := range targetIPv4s(s.pfx, s.self) {
		_ = s.sendARPRequest(handle, ip)
	}

	timer := time.NewTimer(s.opts.Timeout)
	defer timer.Stop()
loop:
	for {
		select {
		case h := <-parsed:
			addHost(h.IP, h.MAC, hosts)
		case <-timer.C:
			break loop
		}
	}

	close(stop)
	handle.Close()
	wg.Wait()

	return mapToSlice(hosts), nil
}

func (s *DarwinScanner) Passive() ([]Host, error) {
	handle, err := pcap.OpenLive(s.iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	_ = handle.SetBPFFilter("arp")

	hosts := map[string]Host{}
	parsed := make(chan Host, 128)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-stop:
				return
			case pkt := <-src.Packets():
				if pkt == nil {
					continue
				}
				if h, ok := hostFromARPPacket(pkt); ok {
					select {
					case parsed <- h:
					default:
					}
				}
			}
		}
	}()

	timer := time.NewTimer(s.opts.Timeout)
	defer timer.Stop()
loop:
	for {
		select {
		case h := <-parsed:
			addHost(h.IP, h.MAC, hosts)
		case <-timer.C:
			break loop
		}
	}

	close(stop)
	handle.Close()
	wg.Wait()

	return mapToSlice(hosts), nil
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
