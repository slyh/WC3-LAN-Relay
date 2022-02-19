package main

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket/pcap"
)

var wg sync.WaitGroup

// var inward = make(chan []uint8, 10)
var outward = make(chan []uint8, 10)

func main() {
	addr, err := net.ResolveUDPAddr("udp", "192.168.99.2:16112")
	if err != nil {
		fmt.Println(err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Listening on", conn.LocalAddr())

	iface, err := net.InterfaceByName("ens37")
	if err != nil {
		fmt.Println(err)
		return
	}

	handle, err := pcap.OpenLive("ens37", 65535, false, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer handle.Close()

	go ParsePacket(handle, iface)

	go InwardHandler(conn, handle, iface)
	go OutwardHandler(conn)

	wg.Add(1)
	wg.Wait()
}

func InwardHandler(conn net.PacketConn, handle *pcap.Handle, iface *net.Interface) {
	buffer := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFrom(buffer)

		if err != nil {
			fmt.Println(err)
			continue
		}

		payload := buffer[:n]
		_ = src
		// inward <- payload
		// fmt.Print("\n-> ", src, string(payload))
		go SendIPv4(handle, iface, payload, true)
	}
}

func OutwardHandler(conn net.PacketConn) {
	dst, err := net.ResolveUDPAddr("udp", "192.168.99.1:16112")
	for {
		payload := <-outward
		if err != nil {
			fmt.Println(err)
			return
		}

		n, err := conn.WriteTo(payload, dst)
		if err != nil {
			fmt.Println(n, err)
			return
		}
	}
}
