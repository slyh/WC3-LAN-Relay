package main

import (
	"encoding/json"
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
	LocalNetworkByte *net.IPNet
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

	for _, server := range config.Servers {
		_, server.LocalNetworkByte, err = net.ParseCIDR(server.LocalNetwork)
		if err != nil {
			return
		}
	}

	return
}
