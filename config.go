package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

type ConfigType struct {
	Bind               string
	Client             string
	NATSourcePortStart int
	NATSourcePortEnd   int
	Role               int
	Servers            []Server
	WC3Interface       string
	PCAPInterface      string

	// constants
	ROLE_SERVER int
	ROLE_CLIENT int
}

type Server struct {
	Remote           string
	LocalNetwork     string
	LocalNetworkByte net.IPNet
}

func ReadConfigFile(path string) (config ConfigType, err error) {
	var data []uint8
	data, err = os.ReadFile(path)
	if err != nil {
		return
	}

	err = json.Unmarshal(data, &config)
	if err != nil {
		return
	}

	for index, server := range config.Servers {
		var ipNet *net.IPNet
		var ip []uint8
		var mask []uint8
		_, ipNet, err = net.ParseCIDR(server.LocalNetwork)
		if err != nil {
			return
		}
		ip = []uint8{ipNet.IP[0], ipNet.IP[1], ipNet.IP[2], ipNet.IP[3]}
		mask = []uint8{ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3]}
		config.Servers[index].LocalNetworkByte = net.IPNet{ip, mask}
		fmt.Printf("Forwarding %s to server %d.\n", config.Servers[index].LocalNetworkByte.String(), index)
	}

	return
}
