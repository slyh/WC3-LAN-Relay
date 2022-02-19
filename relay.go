package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

var config ConfigType
var queueList []chan []uint8
var outward = make(chan []uint8, 100)

func main() {
	var err error
	config, err = ReadConfigFile("config.json")
	if err != nil {
		fmt.Println("Failed to read config file. ", err)
		return
	}

	queueList = make([]chan []uint8, len(config.Servers))
	for index, _ := range queueList {
		queueList[index] = make(chan []uint8, 100)
	}

	addr, err := net.ResolveUDPAddr("udp", config.Bind)
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

	iface, err := net.InterfaceByName(config.WC3Interface)
	if err != nil {
		fmt.Println(err)
		return
	}

	handle, err := pcap.OpenLive(config.PCAPInterface, 65535, false, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer handle.Close()

	go ParsePacket(handle, iface)

	go InwardHandler(conn, handle, iface)
	if config.Role == config.ROLE_CLIENT {
		for index, _ := range queueList {
			go OutwardHandler(conn, queueList[index], config.Servers[index].Remote)
		}
	} else {
		go OutwardHandler(conn, outward, config.Client)
	}

	wait := make(chan int)
	<-wait
}

func InwardHandler(conn net.PacketConn, handle *pcap.Handle, iface *net.Interface) {
	src2Index := make(map[string]int)
	for index, server := range config.Servers {
		src2Index[server.Remote] = index
	}

	buffer := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFrom(buffer)

		if err != nil {
			fmt.Println(err)
			continue
		}

		payload := buffer[:n]

		if config.Role == config.ROLE_SERVER {
			SendIPv4(handle, iface, payload, 0)
		} else {
			SendIPv4(handle, iface, payload, src2Index[src.String()])
		}
	}
}

func OutwardHandler(conn net.PacketConn, queue chan []uint8, remote string) {
	dst, err := net.ResolveUDPAddr("udp", remote)
	for {
		payload := <-queue
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
