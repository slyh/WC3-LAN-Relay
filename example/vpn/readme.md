Server
```
Network Interface eth0
IP: 1.2.3.4
Reachable by the client

Network Interface eth1
IP: 192.168.51.1/24
```

Client
```
Network Interface eth0
IP: 5.6.7.8
Reachable by the server

Network Interface tap0
IP: 172.16.0.1/16

# Add TAP device tap0
openvpn --mktun --dev tap0

# Disable IPv6 if you want
sysctl -w net.ipv6.conf.tap0.disable_ipv6=1

# Bring up tap0
ip link set dev tap0 up
ip addr add 172.16.0.1/24 dev tap0

# Bind the network (AnyIP)
ip -4 route add local 172.16.251.0/24 dev lo

# Drop TCP RST
iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP
iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP
```

Players
```
Join the client's network via OpenVPN
IP: 172.16.0.100-200/16
```

Network **192.168.51.0/24** will be mapped to **172.16.251.0/24** by the client.
And players will share IP **192.168.51.1**.
