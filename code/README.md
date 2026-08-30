# Secure TUN/UDP VPN (svpn)

Point-to-point host-to-host tunnel between two Raspberry Pi 5s. Inner IPv4
packets are read from a TUN device, framed, optionally encrypted with
ChaCha20-Poly1305, and sent as UDP datagrams over Wi-Fi.

This is an educational tunnel, not a production VPN.

Encrypted mode authenticates and encrypts inner packets, including the tunnel
header as AEAD associated data. It does **not** hide outer endpoint IPs, UDP
port, packet sizes, timing, or traffic direction, and it cannot prevent Wi-Fi
jamming or packet dropping.

## 1. Overview

- **Outer network:** campus/home Wi-Fi (`wlan0`)
- **Inner network:** `192.168.250.1/30` ↔ `192.168.250.2/30` on `tun0`
- **Transport:** UDP port `55555`
- **Plaintext mode:** TUN ↔ userspace framing ↔ UDP (no crypto)
- **Encrypted mode:** authenticated ephemeral ECDH (`crypto_kx`) + Ed25519
  identity signatures + per-packet ChaCha20-Poly1305

## 2. Architecture

```text
                OUTER / PHYSICAL NETWORK
                        Wi-Fi

 Pi A (client)                                    Pi B (server)
 wlan0                                             wlan0
 10.7.51.1       <---- UDP port 55555 ---->        10.7.50.242
       |                                             |
    svpn process                                  svpn process
       |                                             |
     tun0                                          tun0
 192.168.250.1                                  192.168.250.2

                 INNER / VPN NETWORK
```

Linux routes `192.168.250.2` into `tun0` on A. `svpn` `read()`s the inner IP
packet, wraps it, and `sendto()`s it to B's Wi-Fi address. B authenticates or
copies the payload and `write()`s it back into its TUN. The reverse path is
symmetric after the handshake.

Further detail: [docs/architecture.md](docs/architecture.md),
[docs/protocol.md](docs/protocol.md).

## 3. Dependencies

On the Fedora laptop:

```bash
cd code
./scripts/install_deps_fedora.sh --yes
```

On both Pis (from the laptop, after `config.env` exists):

```bash
export SSHPASS='your-ssh-password'
./scripts/install_deps_pi.sh --remote
```

Or on a Pi itself:

```bash
./scripts/install_deps_pi.sh
```

## 4. Initial configuration

```bash
cd code
cp config.env.example config.env
```

Edit `config.env` if DHCP assigns different Wi-Fi addresses. The testbed used
for this submission:

```text
VPN_A_HOST / VPN_A_OUTER_IP = 10.7.51.1   (hostname vpn-a)
VPN_B_HOST / VPN_B_OUTER_IP = 10.7.50.242 (hostname vpn-b)
PI_USER = cn
```

Hosts are addressed by IPv4. Optional: `export SSHPASS=...` so scripts can SSH
with `sshpass` (do not commit the password).

Optional: `SVPN_SSH_CONFIG=/dev/null` forces scripts to ignore a custom system
SSH config and use standard defaults.

## 5. Deployment

From Fedora:

```bash
export SSHPASS='your-ssh-password'
./scripts/preflight.sh
./scripts/deploy.sh
```

`deploy.sh` rsyncs source to `~/code` on each Pi and runs
`make clean && make && make test` natively (no cross-compiler).

## 6. Key provisioning

```bash
./scripts/provision_keys.sh
```

Each Pi keeps `keys/identity.key` (mode `0600`). Only public keys are copied,
as `keys/peer_identity.pub`.

## 7. TUN setup

Does **not** change the default route. On each Pi (or via SSH):

```bash
# on vpn-a
cd ~/code
./scripts/setup_tun.sh a

# on vpn-b
cd ~/code
./scripts/setup_tun.sh b
```

Cleanup (deletes only this project's `tun0`):

```bash
./scripts/cleanup_tun.sh
```

## 8. Plaintext tunnel

Start **B then A**. Foreground (logs on stderr):

```bash
# vpn-b
./scripts/start_tunnel.sh b plaintext

# vpn-a
./scripts/start_tunnel.sh a plaintext
```

## 9. Encrypted tunnel

```bash
# vpn-b
./scripts/start_tunnel.sh b encrypted

# vpn-a
./scripts/start_tunnel.sh a encrypted
```

Wait for `session established` before sending traffic.

## 10. Ping test

From A:

```bash
ping -c 4 192.168.250.2
```

## 11. iperf / TCP / UDP tests

On B:

```bash
iperf3 -s -1 -B 192.168.250.2
```

On A:

```bash
iperf3 -c 192.168.250.2 -B 192.168.250.1 -t 10
iperf3 -c 192.168.250.2 -B 192.168.250.1 -u -b 20M -t 10
```

Or from Fedora:

```bash
./scripts/smoke_test.sh plaintext
./scripts/smoke_test.sh encrypted
./scripts/smoke_test.sh negative
```

See [docs/testing.md](docs/testing.md) for unit and integration coverage.

## 12. Stop / cleanup

```bash
./scripts/stop_tunnel.sh     # only the recorded background PID
./scripts/cleanup_tun.sh     # deletes tun0 only
```

`SIGINT`/`SIGTERM` also stop a foreground `svpn` and print counters.

## 13. Benchmarks

From Fedora, after preflight:

```bash
./scripts/benchmark.sh
```

Default: 5 TCP iperf3 runs × 20 s (3 s omit) × 3 modes × 2 directions.
Results land in `results/<timestamp>/summary.md`.

See [docs/benchmarking.md](docs/benchmarking.md) for how to interpret
direct vs plaintext vs encrypted throughput and CPU.

Packet-size, RTT, latency-under-load, and UDP-loss sweeps:

```bash
./scripts/packet_experiments.sh
```

Results land in `results/<timestamp>-packet/summary.md`. These complement the
bulk TCP tables; they do not replace them.

## 14. Capture demo

```bash
./scripts/capture_demo.sh
```

Writes:

- `captures/encrypted_tun0.pcap` — inner plaintext marker **visible**
- `captures/encrypted_wlan0.pcap` — marker **absent** (ciphertext + UDP)
- `captures/plaintext_wlan0.pcap` — control: marker **visible** on Wi-Fi

Open those files in Wireshark or inspect with `tshark`. On the encrypted
outer capture the application marker is absent; on the plaintext control
capture it is visible. Encryption hides the inner packet contents, not outer
addresses, port, size, timing, or direction.

## 15. Troubleshooting

| Symptom | What to check |
|---|---|
| SSH fails | `ssh cn@10.7.51.1` / `cn@10.7.50.242`; `export SSHPASS` |
| Preflight IP mismatch | DHCP moved `wlan0`; update `config.env` |
| Ping A↔B over Wi-Fi fails | Client isolation on the AP |
| TUN open denied | `./scripts/setup_tun.sh` as the `cn` user; `/dev/net/tun` |
| Handshake timeout | Start server first; UDP 55555; wrong peer IP |
| Signature invalid | Re-run `provision_keys.sh`; keys must match the peer |
| Ping tun works, TCP fails | MTU/firewall; confirm `tun0` MTU 1400 |
| Route not `wlan0` | Confirm traffic uses Wi-Fi, not Ethernet |
| Capture needs sudo | Script uses `sudo -S`; it will not edit sudoers |

Useful diagnostics:

```bash
ip -br addr
ip route get 10.7.50.242
ss -lunp
tcpdump -ni wlan0 udp port 55555
tcpdump -ni tun0
pidstat -u -p $(cat ~/code/run/svpn.pid) 1
```

## 16. Security limitations

- No CA/PKI: public keys are pinned out of band
- No session key rotation, roaming, or multi-peer routing
- No extra reliability or congestion control on the UDP layer
- No traffic-shape obfuscation: sizes, timing, outer IPs remain visible
- No daemon privilege separation or production hardening
- Inner IPv4 only; not an Internet gateway (no NAT / default-route takeover)

## 17. Build

```bash
make
make test
make test-sanitize
make debug
make clean
```

Binaries: `bin/svpn`, `bin/svpn-keygen`, `bin/tests`.
