# FAQ

** TCP traffic not going through **

Ensure all the relay servers (including servers and clients) are not sending TCP RST packets.

On Windows, enable Windows Firewall.

On Linux, you might find these iptables rules useful.

```
iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP
iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP
```

** Wrong IP address is being used as source address **

The relay uses the first IP address it finds for NAT. You might want to disable IPv6 on that interface.

```
sysctl -w net.ipv6.conf.eth0.disable_ipv6=1
```