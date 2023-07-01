WC3-LAN-Relay is a tool to relay Warcraft III traffics between networks.

## Config

#### Server

```json5
{
  "Bind": "1.2.3.4:7112", // Where should the server listen to forwarded traffics
  "Client": "5.6.7.8:7112", // Where should the server forward traffics to
  "NATSourcePortStart": 10000, // UDP ports for NAT
  "NATSourcePortEnd": 30000, // For example, UDP ports 10000-30000 will be used for NAT. Including port 30000.
  "Role": 0, // Server
  "Servers": [],
  "WC3Interface": "eth1", // Interface where Warcraft III traffics will be monitored
  "PCAPInterface": "eth1", // Should be same as WC3Interface on Linux. On Windows, you have to find the interface's identifier
  "WC3InterfaceIPIndex": 0 // Select which IP is used as the source IP on WC3Interface, or set to -1 for auto detection
}
```

#### Client

```json5
{
  "Bind": "5.6.7.8:7112", // Where should the client listen to forwarded traffics
  "Client": "", // For servers only, ignored
  "NATSourcePortStart": 10000, // For servers only, ignored
  "NATSourcePortEnd": 30000, // For servers only, ignored
  "Role": 1, // Client
  "Servers": [
    {
      "DisplayName": "NET01", // Game name will be prefixed with the display name
      "Remote": "1.2.3.4:7112", // Endpoint of the server
      "LocalNetwork": "172.16.251.0/24" // Source IPs of the remote network will be mapped to here
    },
    {
      "DisplayName": "NET02",
      "Remote": "1.2.3.5:7112",
      "LocalNetwork": "172.16.252.0/24"
    }
  ],
  "WC3Interface": "tap0", // Interface where Warcraft III traffics will be monitored
  "PCAPInterface": "tap0", // Should be same as WC3Interface on Linux. On Windows, you have to find the interface's identifier
  "WC3InterfaceIPIndex": 0 // Select which IP is used as the source IP on WC3Interface, or set to -1 for auto detection
}
```

## Setup

#### Server

```bash
# Drop TCP RST
iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP
iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP

go run ethernet.go relay.go config.go wc3.go
```

# Client

```bash
# Bind the network (AnyIP)
ip -4 route add local 172.16.251.0/24 dev lo
ip -4 route add local 172.16.252.0/24 dev lo

# Drop TCP RST
iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP
iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP

go run ethernet.go relay.go config.go wc3.go
```

## FAQ

#### TCP traffics are not going through

Ensure all the relay servers (including servers and clients) are not sending TCP RST packets.

On Windows, enable Windows Firewall.

On Linux, you might find these iptables rules useful.

```bash
iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP
iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP
```

#### Wrong IP is being used as the source address

Try changing the `WC3InterfaceIPIndex` option.