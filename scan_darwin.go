package main

import (
	"errors"
	"net"
	"net/netip"
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
	handle, err := pcap.OpenLive(s.iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	_ = handle.SetBPFFilter("arp")

	hosts := map[string]Host{}

	stop := make(chan struct{})
	go func() {
		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-stop:
				return
			case pkt := <-src.Packets():
				if pkt == nil {
					continue
				}
				if arpLayer := pkt.Layer(layers.LayerTypeARP); arpLayer != nil {
					arp := arpLayer.(*layers.ARP)
					ip, ok := netip.AddrFromSlice(arp.SourceProtAddress)
					if ok && ip.Is4() {
						addHost(ip, net.HardwareAddr(arp.SourceHwAddress), hosts)
					}
				}
			}
		}
	}()

	// Inject ARP requests for each IP in subnet
	for ip := s.pfx.Addr(); s.pfx.Contains(ip); ip = ip.Next() {
		if !ip.Is4() {
			continue
		}
		_ = s.sendARPRequest(handle, ip)
	}

	time.Sleep(s.opts.Timeout)
	close(stop)

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
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	deadline := time.Now().Add(s.opts.Timeout)

	for time.Now().Before(deadline) {
		pkt := <-src.Packets()
		if pkt == nil {
			continue
		}
		if arpLayer := pkt.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			ip, ok := netip.AddrFromSlice(arp.SourceProtAddress)
			if ok && ip.Is4() {
				addHost(ip, net.HardwareAddr(arp.SourceHwAddress), hosts)
			}
		}
	}

	return mapToSlice(hosts), nil
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
		SourceProtAddress: s.self.AsSlice(),  // 4 bytes
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    target.AsSlice(),  // 4 bytes
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return err
	}

	return handle.WritePacketData(buf.Bytes())
}

