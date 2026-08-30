# Architecture

## Outer vs inner network

The **outer** network is ordinary Wi-Fi. Packets on `wlan0` have the Pis'
DHCP addresses (`10.7.51.1` and `10.7.50.242`) and UDP port 55555.

The **inner** network is a private `/30` on persistent `tun0` devices:

```text
192.168.250.1  Pi A
192.168.250.2  Pi B
```

Applications bind to or send toward the inner addresses. Linux routing, not
`svpn`, decides that those packets enter `tun0`.

## Why TUN, not TAP

`read()` on a TUN fd returns a Layer-3 IPv4 (or IPv6) packet. The project
needs arbitrary IP traffic (ICMP, TCP, UDP) between two hosts. TAP would add
Ethernet headers, MAC addresses, and ARP. None of that is required, and it
would enlarge packets and the explanation.

Flags: `IFF_TUN | IFF_NO_PI` so there is no extra `struct tun_pi` prefix.

## Packet path

```text
app on A
  -> Linux IP routing (dst 192.168.250.2 -> tun0)
  -> read(tun_fd)          inner IP packet
  -> DATA header + optional AEAD
  -> sendto() UDP          outer packet
  -> wlan0 / Wi-Fi
  -> recvfrom() on B
  -> parse / decrypt / replay check
  -> write(tun_fd)         inject inner IP into B's stack
  -> app on B
```

`write()` to TUN is the inverse of `read()`: the kernel treats the buffer as
an ingress IP packet on `tun0` and demultiplexes it to local sockets.

## Why UDP outside

Inner traffic may already be TCP. An outer TCP tunnel would nest two
reliability machines (TCP-over-TCP): extra head-of-line blocking when Wi-Fi
loses a datagram. UDP gives one inner packet ↔ one outer datagram. Lost
DATA packets are not retransmitted by `svpn`; inner TCP handles loss itself.
The handshake *does* retransmit, because it must complete before any DATA.

## Why MTU 1400

A 1400-byte inner IP packet plus a 28-byte tunnel header plus a 16-byte
Poly1305 tag plus UDP (8) plus outer IPv4 (20) is 1472 bytes, under a common
1500-byte Wi-Fi MTU. The process does not rely on outer IP fragmentation.

## Privilege split

`svpn` never calls `sudo`, never edits routes or firewalls, and never
configures the TUN address. Separate scripts create and address `tun0`.
That keeps device setup outside the tunnel process and avoids silent
privilege escalation.
