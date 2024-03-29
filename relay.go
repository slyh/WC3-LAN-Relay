package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime/pprof"
	"time"

	"github.com/google/gopacket/pcap"
)

const MTU = 1500

var config ConfigType
var queueList []chan []uint8
var outward = make(chan []uint8, 100)

var packetCounter = 0

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to `file`")
var listIfs = flag.Bool("list-ifs", false, "list all pcap interfaces")

func main() {
	var err error

	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Println("could not create CPU profile: ", err)
			return
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Println("could not start CPU profile: ", err)
			return
		}
		defer pprof.StopCPUProfile()
	}

	if *listIfs {
		ifs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Println("Failed to list interfaces: ", err)
			return
		}
		fmt.Printf("PCAP interfaces:\n")
		for _, e := range ifs {
			fmt.Printf("%s %s %s\n", e.Name, e.Description, e.Addresses)
		}
		return
	}

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
	defer conn.Close()

	fmt.Println("Listening on", conn.LocalAddr())

	iface, err := net.InterfaceByName(config.WC3Interface)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Must invoke this function before handling packets
	SetPcapAddr(iface)

	iHandle, err := pcap.NewInactiveHandle(config.PCAPInterface)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer iHandle.CleanUp()

	iHandle.SetSnapLen(MTU + 22)
	iHandle.SetImmediateMode(false)
	iHandle.SetBufferSize(256 * (MTU + 22))
	iHandle.SetTimeout(time.Millisecond * 20 * -1) // Set it to negative so pcap won't complain timeout expired

	handle, err := iHandle.Activate()
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

	if config.Role == config.ROLE_SERVER {
		go StatusUpdate()
	}

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, os.Interrupt)

	<-sigterm
	fmt.Println("Exiting...")
	if *cpuprofile != "" {
		pprof.StopCPUProfile()
	}
	os.Exit(0)
}

func InwardHandler(conn net.PacketConn, handle *pcap.Handle, iface *net.Interface) {
	src2Index := make(map[string]int)
	for index, server := range config.Servers {
		src2Index[server.Remote] = index
	}

	buffer := make([]byte, MTU)
	for {
		n, src, err := conn.ReadFrom(buffer)

		if err != nil {
			fmt.Println(err)
			continue
		}

		payload := buffer[:n]

		if config.Role == config.ROLE_SERVER {
			SendIPv4(handle, iface, &payload, 0)
		} else {
			SendIPv4(handle, iface, &payload, src2Index[src.String()])
		}

		packetCounter++
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

		packetCounter++
	}
}

func StatusUpdate() {
	ticker := time.NewTicker(60 * time.Second)
	prevPacketCounter := 0
	for {
		<-ticker.C
		fmt.Printf("Ports used: %d / %d, Processed packets: %d (%d ppm)\n",
			rewritePortCounter-uint16(config.NATSourcePortStart),
			config.NATSourcePortEnd-config.NATSourcePortStart,
			packetCounter,
			packetCounter-prevPacketCounter,
		)
		prevPacketCounter = packetCounter
	}
}
