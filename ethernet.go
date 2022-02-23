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

var rewriteAddr = []uint8{192, 168, 51, 49}
var rewriteMask = []uint8{255, 255, 255, 0}
var rewritePortCounter = uint16(20000)
var rewriteMapLock sync.Mutex

type Addr struct {
	IP   net.IP
	Port uint16
}

func (addr Addr) String() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", addr.IP[0], addr.IP[1], addr.IP[2], addr.IP[3], addr.Port)
}

func ParsePacket(handle *pcap.Handle, iface *net.Interface) {
	if config.Role == config.ROLE_SERVER {
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Println(err)
			return
		}
		if len(addrs) > 0 {
			copy(rewriteAddr, addrs[config.WC3InterfaceIPIndex].(*net.IPNet).IP.To4())
			copy(rewriteMask, addrs[config.WC3InterfaceIPIndex].(*net.IPNet).Mask)
		}

		rewritePortCounter = uint16(config.NATSourcePortStart)

		fmt.Printf("NAT IP: %d.%d.%d.%d\n", rewriteAddr[0], rewriteAddr[1], rewriteAddr[2], rewriteAddr[3])
		fmt.Printf("NAT Ports: %d - %d\n", rewritePortCounter, config.NATSourcePortEnd)
	}

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		packet := <-in
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)

		if ethernetLayer == nil {
			fmt.Println("ParsePacket: No ethernet layer")
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
				ReadIPv4(packet, ethernet, ipv4, tcp, nil, iface)
			}
			if udpLayer != nil {
				udp := udpLayer.(*layers.UDP)
				go ReadIPv4(packet, ethernet, ipv4, nil, udp, iface)
			}
			continue
		}

		arpLayer := packet.Layer(layers.LayerTypeARP)

		if arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			go ReadARP(arp)
			continue
		}

		fmt.Println("ParsePacket: No wanted layer")
	}
}

func ReadIPv4(packet gopacket.Packet, ethernet *layers.Ethernet, ipv4 *layers.IPv4, tcp *layers.TCP, udp *layers.UDP, iface *net.Interface) {
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buffer := gopacket.NewSerializeBuffer()

	if config.Role == config.ROLE_SERVER {
		dstPort := uint16(0)

		if tcp != nil {
			dstPort = uint16(tcp.DstPort)
		}

		if udp != nil {
			dstPort = uint16(udp.DstPort)
		}

		rewriteMapLock.Lock()
		dstAddr, ok := port2IpMap[dstPort]
		rewriteMapLock.Unlock()

		if !ok {
			// fmt.Println("Dst Addr not found", dstPort)
			return
		}

		if ipv4.DstIP.String() != "255.255.255.255" {
			ipv4.DstIP = dstAddr.IP

			if tcp != nil {
				tcp.DstPort = layers.TCPPort(dstAddr.Port)
			}

			if udp != nil {
				udp.DstPort = layers.UDPPort(dstAddr.Port)
			}
		}
	}

	if tcp != nil {
		err := tcp.SetNetworkLayerForChecksum(ipv4)
		if err != nil {
			fmt.Println(err)
			return
		}

		err = gopacket.SerializeLayers(buffer, serializeOptions, ethernet, ipv4, tcp, gopacket.Payload(tcp.Payload))
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	if udp != nil {
		err := udp.SetNetworkLayerForChecksum(ipv4)
		if err != nil {
			fmt.Println(err)
			return
		}

		err = gopacket.SerializeLayers(buffer, serializeOptions, ethernet, ipv4, udp, gopacket.Payload(udp.Payload))
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	// err := gopacket.SerializePacket(buffer, serializeOptions, packet)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	payload := buffer.Bytes()

	if config.Role == config.ROLE_CLIENT {
		if ipv4.DstIP.String() == "255.255.255.255" {
			for i, _ := range queueList {
				queueList[i] <- payload
			}
		} else {
			var serverIndex = -1
			for index, server := range config.Servers {
				if server.LocalNetworkByte.Contains(ipv4.DstIP) {
					serverIndex = index
				}
			}

			if serverIndex == -1 {
				fmt.Println("No suitable remote:", ipv4.DstIP)
			} else {
				queueList[serverIndex] <- payload
			}
		}
	} else {
		outward <- payload
	}

	// log.Printf("\n<-", string(payload))
}

func SendIPv4(handle *pcap.Handle, iface *net.Interface, raw []uint8, serverIndex int) {
	decodeOptions := gopacket.DecodeOptions{}
	packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, decodeOptions)

	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if ethernetLayer == nil || ipv4Layer == nil || (tcpLayer == nil && udpLayer == nil) {
		fmt.Println("Unknown layer")
		return
	}

	ipv4 := ipv4Layer.(*layers.IPv4)
	var tcp *layers.TCP = nil
	var udp *layers.UDP = nil

	if tcpLayer != nil {
		tcp = tcpLayer.(*layers.TCP)
	}

	if udpLayer != nil {
		udp = udpLayer.(*layers.UDP)
	}

	if config.Role == config.ROLE_CLIENT {
		localNetwork := config.Servers[serverIndex].LocalNetworkByte
		for i, _ := range ipv4.SrcIP {
			ipv4.SrcIP[i] = (ipv4.SrcIP[i] &^ localNetwork.Mask[i]) | (localNetwork.IP[i] & localNetwork.Mask[i])
		}
	}

	if config.Role == config.ROLE_SERVER {
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
			// Rewrite game info from game hosts behind the client relay
			if IsGameInfoPacket(udp.Payload, srcAddr.Port) {
				RewriteGameInfoPacket(&udp.Payload, newSrcAddr.Port)
			}
		}

		if ipv4.DstIP.String() != "255.255.255.255" {
			for i, _ := range ipv4.DstIP {
				ipv4.DstIP[i] = (ipv4.DstIP[i] &^ rewriteMask[i]) | (rewriteAddr[i] & rewriteMask[i])
			}
		}
	}

	dstMAC, ok := ReadARPMap(ipv4.DstIP.String())
	if ipv4.DstIP.String() == "255.255.255.255" {
		dstMAC = []uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	} else if !ok {
		fmt.Println("Sending ARP request", ipv4.DstIP.String())
		SendARP(handle, iface, ipv4.DstIP)
		time.Sleep(1 * time.Second)
		dstMAC, ok = ReadARPMap(ipv4.DstIP.String())
		if !ok {
			fmt.Println("Dst MAC not found", ipv4.DstIP.String())
			return
		}
	}

	ethernet := ethernetLayer.(*layers.Ethernet)
	ethernet.SrcMAC = iface.HardwareAddr
	ethernet.DstMAC = dstMAC
	ethernet.EthernetType = layers.EthernetTypeIPv4

	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buffer := gopacket.NewSerializeBuffer()

	if tcp != nil {
		err := tcp.SetNetworkLayerForChecksum(ipv4)
		if err != nil {
			fmt.Println(err)
			return
		}

		err = gopacket.SerializeLayers(buffer, serializeOptions, ethernet, ipv4, tcp, gopacket.Payload(tcp.Payload))
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	if udp != nil {
		err := udp.SetNetworkLayerForChecksum(ipv4)
		if err != nil {
			fmt.Println(err)
			return
		}

		err = gopacket.SerializeLayers(buffer, serializeOptions, ethernet, ipv4, udp, gopacket.Payload(udp.Payload))
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	// err := gopacket.SerializePacket(buffer, serializeOptions, packet)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	err := handle.WritePacketData(buffer.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}
}

func ReadARP(arp *layers.ARP) {
	UpdateARPMap(net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
}

func SendARP(handle *pcap.Handle, iface *net.Interface, dstIp net.IP) {
	addrs, err := iface.Addrs()
	if err != nil {
		fmt.Println(err)
		return
	}
	if len(addrs) == 0 {
		fmt.Println("No IP assigned to the interface.")
		return
	}
	srcIp := addrs[config.WC3InterfaceIPIndex].(*net.IPNet).IP

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
		if rewritePortCounter > uint16(config.NATSourcePortEnd) {
			rewritePortCounter = uint16(config.NATSourcePortStart)
			fmt.Printf("Source ports exhausted, reusing ports from %d.", rewritePortCounter)
		}
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
