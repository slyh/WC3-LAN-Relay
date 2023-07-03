package main

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type MacMap struct {
	macs map[uint32][]uint8
	lock sync.RWMutex
}

func (m MacMap) Get(ip net.IP) (mac []uint8, ok bool) {
	m.lock.Lock()
	mac, ok = m.macs[IPv4ToInt(ip)]
	m.lock.Unlock()
	return
}

func (m MacMap) Set(ip net.IP, mac []uint8) {
	m.lock.Lock()
	m.macs[IPv4ToInt(ip)] = mac
	m.lock.Unlock()
}

type AddrMap struct {
	addrs map[uint64]Addr
	lock  sync.RWMutex
}

func (m AddrMap) Get(addr Addr) (result Addr, ok bool) {
	m.lock.Lock()
	result, ok = m.addrs[AddrToInt(addr)]
	m.lock.Unlock()
	return
}

func (m AddrMap) Set(addrKey Addr, valKey Addr) {
	m.lock.Lock()
	m.addrs[AddrToInt(addrKey)] = valKey
	m.lock.Unlock()
}

var macMap MacMap

var rewriteMap AddrMap
var rewriteMapLock sync.Mutex

var arpMap = make(map[string][]uint8)
var arpMapLock sync.Mutex

var port2IpMap = make(map[uint16]Addr)

// var rewriteMap = make(map[string]Addr)

var pcapAddr = []uint8{192, 0, 2, 1}
var pcapMask = []uint8{255, 255, 255, 0}

var rewriteAddr = []uint8{192, 0, 2, 1}
var rewriteMask = []uint8{255, 255, 255, 0}
var rewritePortCounter = uint16(20000)

type Addr struct {
	IP   net.IP
	Port uint16
}

func (addr Addr) String() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", addr.IP[0], addr.IP[1], addr.IP[2], addr.IP[3], addr.Port)
}

func SetPcapAddr(iface *net.Interface) {
	addrs, err := iface.Addrs()

	if err != nil {
		fmt.Println(err)
		return
	}

	if config.WC3InterfaceIPIndex < 0 {
		for i, addr := range addrs {
			ipv4 := addr.(*net.IPNet).IP.To4()
			// Reject IPv6 address and link local addresses
			if ipv4 != nil && !ipv4.IsLinkLocalUnicast() {
				config.WC3InterfaceIPIndex = i
			}
		}
	}

	if len(addrs) > 0 && config.WC3InterfaceIPIndex >= 0 {
		copy(pcapAddr, addrs[config.WC3InterfaceIPIndex].(*net.IPNet).IP.To4())
		copy(pcapMask, addrs[config.WC3InterfaceIPIndex].(*net.IPNet).Mask)
	}

	if reflect.DeepEqual(pcapAddr, []uint8{192, 0, 2, 1}) {
		fmt.Printf("Failed to find a suitable interface IP or it's specifically set to 192.0.2.1\n")
	}

	rewriteMap.addrs = make(map[uint64]Addr)
	macMap.macs = make(map[uint32][]uint8)
}

func ParsePacket(handle *pcap.Handle, iface *net.Interface) {
	if config.Role == config.ROLE_SERVER {
		copy(rewriteAddr, pcapAddr)
		copy(rewriteMask, pcapMask)

		rewritePortCounter = uint16(config.NATSourcePortStart)

		fmt.Printf("NAT IP: %d.%d.%d.%d\n", rewriteAddr[0], rewriteAddr[1], rewriteAddr[2], rewriteAddr[3])
		fmt.Printf("NAT Mask: %d.%d.%d.%d\n", rewriteMask[0], rewriteMask[1], rewriteMask[2], rewriteMask[3])
		fmt.Printf("NAT Ports: %d - %d\n", rewritePortCounter, config.NATSourcePortEnd)

		// Hardcode port 6112 for ghost
		var ghostAddr = Addr{
			IP:   []uint8{172, 16, 240, 10},
			Port: 6112,
		}
		port2IpMap[6112] = ghostAddr

		rewriteMap.Set(ghostAddr,
			Addr{
				IP:   rewriteAddr,
				Port: uint16(6112),
			})

		// rewriteMap["172.16.240.10:6112"] = Addr{
		// 	IP:   rewriteAddr,
		// 	Port: uint16(6112),
		// }
	}

	var eth layers.Ethernet
	var arp layers.ARP
	var ip4 layers.IPv4
	var tcp layers.TCP
	var udp layers.UDP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &arp, &ip4, &tcp, &udp)
	decoded := []gopacket.LayerType{}

	var hasEth bool
	var hasArp bool
	var hasIp4 bool
	var hasTcp bool
	var hasUdp bool

	for {
		hasEth = false
		hasArp = false
		hasIp4 = false
		hasTcp = false
		hasUdp = false

		packetData, _, err := handle.ReadPacketData()

		if err != nil {
			fmt.Printf("Could not read packet data: %v\n", err)
			continue
		}

		err = parser.DecodeLayers(packetData, &decoded)
		// Skip error check here, no need to stop for unsupported layers

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeEthernet:
				hasEth = true
			case layers.LayerTypeARP:
				hasArp = true
			case layers.LayerTypeIPv4:
				hasIp4 = true
			case layers.LayerTypeTCP:
				hasTcp = true
			case layers.LayerTypeUDP:
				hasUdp = true
			}
		}

		if !hasEth {
			fmt.Println("ParsePacket: No ethernet layer")
			continue
		}

		if bytes.Equal(eth.SrcMAC, iface.HardwareAddr) {
			// Ignore packets from myself
			continue
		}

		if hasIp4 {
			macMap.Set(ip4.SrcIP, eth.SrcMAC)
			if hasTcp {
				ReadIPv4(&eth, &ip4, &tcp, nil, iface)
				continue
			} else if hasUdp {
				ReadIPv4(&eth, &ip4, nil, &udp, iface)
				continue
			}
		} else if hasArp {
			ReadARP(&arp)
			continue
		}

		// fmt.Println("ParsePacket: No wanted layer")
	}
}

func ReadIPv4(ethernet *layers.Ethernet, ipv4 *layers.IPv4, tcp *layers.TCP, udp *layers.UDP, iface *net.Interface) {
	serializeOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buffer := gopacket.NewSerializeBuffer()

	if config.Role == config.ROLE_SERVER {
		if ipv4.DstIP.Equal(net.IPv4(255, 255, 255, 255)) == false {
			dstPort := uint16(0)

			if tcp != nil {
				dstPort = uint16(tcp.DstPort)
			} else if udp != nil {
				dstPort = uint16(udp.DstPort)
			}

			rewriteMapLock.Lock()
			dstAddr, ok := port2IpMap[dstPort]
			rewriteMapLock.Unlock()

			if !ok {
				// fmt.Println("Dst Addr not found", dstPort)
				return
			}

			ipv4.DstIP = dstAddr.IP

			if tcp != nil {
				tcp.DstPort = layers.TCPPort(dstAddr.Port)
			} else if udp != nil {
				udp.DstPort = layers.UDPPort(dstAddr.Port)
			}
		}
	}

	if config.Role == config.ROLE_CLIENT {
		// TODO: allow user to specify the broadcast address in config
		if ipv4.DstIP.Equal(net.IPv4(172, 16, 255, 255)) {
			ipv4.DstIP = net.IPv4(255, 255, 255, 255)
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
	} else if udp != nil {
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

	payload := buffer.Bytes()

	if config.Role == config.ROLE_CLIENT {
		if ipv4.DstIP.Equal(net.IPv4(255, 255, 255, 255)) {
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
	} else if udpLayer != nil {
		udp = udpLayer.(*layers.UDP)
	}

	if config.Role == config.ROLE_CLIENT {
		localNetwork := config.Servers[serverIndex].LocalNetworkByte
		for i, _ := range ipv4.SrcIP {
			ipv4.SrcIP[i] = (ipv4.SrcIP[i] &^ localNetwork.Mask[i]) | (localNetwork.IP[i] & localNetwork.Mask[i])
		}
		if udp != nil {
			if IsGameInfoPacket(udp.Payload, uint16(udp.SrcPort)) {
				AddGameNamePrefix(&udp.Payload, config.Servers[serverIndex].DisplayName)
			}
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

	dstMAC, ok := macMap.Get(ipv4.DstIP)
	// dstMAC, ok := ReadARPMap(ipv4.DstIP.String())
	if ipv4.DstIP.String() == "255.255.255.255" {
		dstMAC = []uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	} else if !ok {
		fmt.Println("Sending ARP request", ipv4.DstIP.String())
		SendARP(handle, iface, pcapAddr, ipv4.DstIP)
		time.Sleep(1 * time.Second)
		// dstMAC, ok = ReadARPMap(ipv4.DstIP.String())
		dstMAC, ok = macMap.Get(ipv4.DstIP)
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
	} else if udp != nil {
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

	err := handle.WritePacketData(buffer.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}
}

func ReadARP(arp *layers.ARP) {
	// UpdateARPMap(net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
	macMap.Set(net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
}

func SendARP(handle *pcap.Handle, iface *net.Interface, srcIp net.IP, dstIp net.IP) {
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
	err := handle.WritePacketData(buffer.Bytes())
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
	newAddr, ok := rewriteMap.Get(addr)
	// newAddr, ok := rewriteMap[addr.String()]
	if !ok {
		newAddr = Addr{
			IP:   rewriteAddr,
			Port: uint16(rewritePortCounter),
		}
		port2IpMap[rewritePortCounter] = addr
		// rewriteMap[addr.String()] = newAddr
		rewriteMap.Set(addr, newAddr)
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

func IPv4ToInt(ip net.IP) uint32 {
	ipv4 := ip.To4()
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3])
}

func AddrToInt(a Addr) uint64 {
	ipv4 := a.IP.To4()
	return uint64(a.Port)<<32 | uint64(ipv4[0])<<24 | uint64(ipv4[1])<<16 | uint64(ipv4[2])<<8 | uint64(ipv4[3])
}
