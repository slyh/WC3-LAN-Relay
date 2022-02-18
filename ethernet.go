package main

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var arpMap = make(map[string][]uint8)
var arpMapLock sync.Mutex

var port2IpMap = make(map[uint16]Addr)
var rewriteMap = make(map[string]Addr)
var rewriteAddr = []uint8{192, 168, 51, 57}
var rewritePortCounter = uint16(20000)
var rewriteMapLock sync.Mutex

type Addr struct {
	IP   []uint8
	Port uint16
}

func (addr Addr) IPString() string {
	return fmt.Sprintf("%d.%d.%d.%d", addr.IP[0], addr.IP[1], addr.IP[2], addr.IP[3])
}

func (addr Addr) String() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", addr.IP[0], addr.IP[1], addr.IP[2], addr.IP[3], addr.Port)
}

func ParsePacket(handle *pcap.Handle, ifName string) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		fmt.Println(err)
		return
	}

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		packet := <-in

		if packet.Layer(layers.LayerTypeEthernet) == nil {
			continue
		}

		ethernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

		if bytes.Equal(ethernet.SrcMAC, iface.HardwareAddr) {
			// Ignore packets from myself
			continue
		}

		if packet.Layer(layers.LayerTypeIPv4) != nil && (packet.Layer(layers.LayerTypeTCP) != nil || packet.Layer(layers.LayerTypeUDP) != nil) {
			go ReadIPv4(packet, iface)
		}

		if packet.Layer(layers.LayerTypeARP) != nil {
			go ReadARP(packet)
		}
	}
}

func ReadIPv4(packet gopacket.Packet, iface *net.Interface) {
	ethernet := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ipv4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

	UpdateARPMap(ipv4.SrcIP, ethernet.SrcMAC)

	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if packet.Layer(layers.LayerTypeTCP) != nil {
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		srcAddr := Addr{
			IP:   ipv4.SrcIP,
			Port: uint16(tcp.SrcPort),
		}
		newSrcAddr := GetRewroteSrcAddr(srcAddr)
		ipv4.SrcIP = newSrcAddr.IP
		tcp.SrcPort = layers.TCPPort(newSrcAddr.Port)
		tcp.SetNetworkLayerForChecksum(ipv4)
	}

	if packet.Layer(layers.LayerTypeUDP) != nil {
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		srcAddr := Addr{
			IP:   ipv4.SrcIP,
			Port: uint16(udp.SrcPort),
		}
		newSrcAddr := GetRewroteSrcAddr(srcAddr)
		ipv4.SrcIP = newSrcAddr.IP
		udp.SrcPort = layers.UDPPort(newSrcAddr.Port)
		udp.SetNetworkLayerForChecksum(ipv4)
	}

	if ipv4.DstIP.String() != "255.255.255.255" {
		// Rewrite dst ip to vlan subnet
		ipv4.DstIP[0] = 192
		ipv4.DstIP[1] = 168
		ipv4.DstIP[2] = 51
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializePacket(buffer, serializeOptions, packet)
	if err != nil {
		fmt.Println(err)
		return
	}
	payload := buffer.Bytes()
	outward <- payload
	// log.Printf("\n<-", string(payload))
}

func SendIPv4(handle *pcap.Handle, ifName string, raw []uint8) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		fmt.Println(err)
		return
	}

	decodeOptions := gopacket.DecodeOptions{}
	packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, decodeOptions)

	if packet.Layer(layers.LayerTypeIPv4) == nil || (packet.Layer(layers.LayerTypeTCP) == nil && packet.Layer(layers.LayerTypeUDP) == nil) {
		fmt.Println("Unknown layer")
		return
	}

	ipv4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

	dstPort := uint16(0)

	if packet.Layer(layers.LayerTypeTCP) != nil {
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		dstPort = uint16(tcp.DstPort)
	}

	if packet.Layer(layers.LayerTypeUDP) != nil {
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		dstPort = uint16(udp.DstPort)
	}

	rewriteMapLock.Lock()
	dstAddr, ok := port2IpMap[dstPort]
	rewriteMapLock.Unlock()
	if !ok {
		// fmt.Println("Dst Addr not found", dstPort)
		return
	}

	ipv4.SrcIP[0] = 10
	ipv4.SrcIP[1] = 200
	ipv4.SrcIP[2] = 1
	ipv4.DstIP = dstAddr.IP

	dstMAC, ok := ReadARPMap(dstAddr.IPString())
	if ipv4.DstIP.String() == "255.255.255.255" {
		dstMAC = []uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	} else if !ok {
		SendARP(handle, iface, dstAddr.IP)
		time.Sleep(1 * time.Second)
		dstMAC, ok = ReadARPMap(dstAddr.IPString())
		if !ok {
			fmt.Println("Dst MAC not found", ipv4.DstIP.String())
			return
		}
	}

	ethernet := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if packet.Layer(layers.LayerTypeTCP) != nil {
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		tcp.DstPort = layers.TCPPort(dstAddr.Port)
		tcp.SetNetworkLayerForChecksum(ipv4)
		gopacket.SerializeLayers(buf, opts, &ethernet, ipv4, tcp, gopacket.Payload(tcp.Payload))
	}

	if packet.Layer(layers.LayerTypeUDP) != nil {
		udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		udp.DstPort = layers.UDPPort(dstAddr.Port)
		udp.SetNetworkLayerForChecksum(ipv4)
		gopacket.SerializeLayers(buf, opts, &ethernet, ipv4, udp, gopacket.Payload(udp.Payload))
	}

	handle.WritePacketData(buf.Bytes())
}

func ReadARP(packet gopacket.Packet) {
	arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
	UpdateARPMap(net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
}

func SendARP(handle *pcap.Handle, iface *net.Interface, dstIp net.IP) {
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		fmt.Println(err)
		return
	}
	srcIp := addrs[0].(*net.IPNet).IP

	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: srcIp,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstIp,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buffer, opts, &eth, &arp)
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}
}

func ReadARPMap(ip string) (mac []uint8, ok bool) {
	arpMapLock.Lock()
	mac, ok = arpMap[ip]
	arpMapLock.Unlock()
	return
}

func UpdateARPMap(ip net.IP, mac []uint8) {
	arpMapLock.Lock()
	arpMap[ip.String()] = mac
	arpMapLock.Unlock()
}

func GetRewroteSrcAddr(addr Addr) (newAddr Addr) {
	rewriteMapLock.Lock()
	newAddr, ok := rewriteMap[addr.String()]
	if !ok {
		newAddr = Addr{
			IP:   rewriteAddr,
			Port: uint16(rewritePortCounter),
		}
		port2IpMap[rewritePortCounter] = addr
		rewriteMap[addr.String()] = newAddr
		rewritePortCounter++
	}
	rewriteMapLock.Unlock()
	return
}

func GetRewroteDstAddr(addr Addr) (newAddr Addr) {
	newAddr = Addr{
		IP:   addr.IP,
		Port: addr.Port,
	}
	newAddr.IP[0] = 192
	newAddr.IP[1] = 168
	newAddr.IP[2] = 51
	return
}
