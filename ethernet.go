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
var rewriteAddr = []uint8{192, 168, 51, 126}
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

func ParsePacket(handle *pcap.Handle, iface *net.Interface) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		packet := <-in
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)

		if ethernetLayer == nil {
			continue
		}

		ethernet := ethernetLayer.(*layers.Ethernet)

		if bytes.Equal(ethernet.SrcMAC, iface.HardwareAddr) {
			// Ignore packets from myself
			continue
		}

		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		udpLayer := packet.Layer(layers.LayerTypeUDP)

		if ipv4Layer != nil {
			ipv4 := ipv4Layer.(*layers.IPv4)
			UpdateARPMap(ipv4.SrcIP, ethernet.SrcMAC)
			if tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				go ReadIPv4(packet, ethernet, ipv4, tcp, nil, iface, true)
			}
			if udpLayer != nil {
				udp := udpLayer.(*layers.UDP)
				go ReadIPv4(packet, ethernet, ipv4, nil, udp, iface, true)
			}
			continue
		}

		arpLayer := packet.Layer(layers.LayerTypeARP)

		if arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			go ReadARP(arp)
			continue
		}
	}
}

func ReadIPv4(packet gopacket.Packet, ethernet *layers.Ethernet, ipv4 *layers.IPv4, tcp *layers.TCP, udp *layers.UDP, iface *net.Interface, nat bool) {
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if nat {
		if tcp != nil {
			srcAddr := Addr{
				IP:   ipv4.SrcIP,
				Port: uint16(tcp.SrcPort),
			}
			newSrcAddr := GetRewroteSrcAddr(srcAddr)
			ipv4.SrcIP = newSrcAddr.IP
			tcp.SrcPort = layers.TCPPort(newSrcAddr.Port)
		}

		if udp != nil {
			srcAddr := Addr{
				IP:   ipv4.SrcIP,
				Port: uint16(udp.SrcPort),
			}
			newSrcAddr := GetRewroteSrcAddr(srcAddr)
			ipv4.SrcIP = newSrcAddr.IP
			udp.SrcPort = layers.UDPPort(newSrcAddr.Port)
		}

		if ipv4.DstIP.String() != "255.255.255.255" {
			// Rewrite dst ip to vlan subnet
			ipv4.DstIP[0] = 192
			ipv4.DstIP[1] = 168
			ipv4.DstIP[2] = 51
		}
	}

	if tcp != nil {
		tcp.SetNetworkLayerForChecksum(ipv4)
	}

	if udp != nil {
		udp.SetNetworkLayerForChecksum(ipv4)
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

func SendIPv4(handle *pcap.Handle, iface *net.Interface, raw []uint8, nat bool) {
	decodeOptions := gopacket.DecodeOptions{}
	packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, decodeOptions)

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if ipv4Layer == nil || (tcpLayer == nil && udpLayer == nil) {
		fmt.Println("Unknown layer")
		return
	}

	ipv4 := ipv4Layer.(*layers.IPv4)
	var tcp *layers.TCP = nil
	var udp *layers.UDP = nil

	dstPort := uint16(0)

	if tcpLayer != nil {
		tcp = tcpLayer.(*layers.TCP)
		dstPort = uint16(tcp.DstPort)
	}

	if udpLayer != nil {
		udp = udpLayer.(*layers.UDP)
		dstPort = uint16(udp.DstPort)
	}

	rewriteMapLock.Lock()
	dstAddr, ok := port2IpMap[dstPort]
	rewriteMapLock.Unlock()

	if nat {
		if !ok {
			// fmt.Println("Dst Addr not found", dstPort)
			return
		}

		ipv4.SrcIP[0] = 10
		ipv4.SrcIP[1] = 200
		ipv4.SrcIP[2] = 1
		ipv4.DstIP = dstAddr.IP
	}

	dstMAC, ok := ReadARPMap(ipv4.DstIP.String())
	if ipv4.DstIP.String() == "255.255.255.255" {
		dstMAC = []uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	} else if !ok {
		SendARP(handle, iface, ipv4.DstIP)
		time.Sleep(1 * time.Second)
		dstMAC, ok = ReadARPMap(ipv4.DstIP.String())
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

	if tcp != nil {
		if nat {
			tcp.DstPort = layers.TCPPort(dstAddr.Port)
		}
		tcp.SetNetworkLayerForChecksum(ipv4)
		gopacket.SerializeLayers(buf, opts, &ethernet, ipv4, tcp, gopacket.Payload(tcp.Payload))
	}

	if udp != nil {
		if nat {
			udp.DstPort = layers.UDPPort(dstAddr.Port)
		}
		udp.SetNetworkLayerForChecksum(ipv4)
		gopacket.SerializeLayers(buf, opts, &ethernet, ipv4, udp, gopacket.Payload(udp.Payload))
	}

	handle.WritePacketData(buf.Bytes())
}

func ReadARP(arp *layers.ARP) {
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
