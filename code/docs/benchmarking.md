# Benchmarking

Three modes, both directions, default **5 runs**, **20 s** iperf3 TCP,
**3 s** omit/warmup (`scripts/benchmark.sh`).

For each direction and trial, the script runs **direct → plaintext →
encrypted** before proceeding to the next trial. Interleaving prevents an
entire mode from being measured during a different period of Wi-Fi contention
than the others.

## Modes

| Mode | Path | Isolates |
|---|---|---|
| **direct** | A `wlan0` IP → B `wlan0` IP, no TUN, no `svpn` | Wi-Fi baseline |
| **plaintext** | inner TUN IPs, framing + UDP, no AEAD | userspace/tunnel cost |
| **encrypted** | same as plaintext + handshake + ChaCha20-Poly1305 + replay | extra crypto cost |

Reported overheads:

```text
tunnel overhead %              = (direct - plaintext) / direct * 100
incremental encryption %       = (plaintext - encrypted) / plaintext * 100
total VPN overhead %           = (direct - encrypted) / direct * 100
```

Direct-versus-encrypted is not labeled “encryption overhead”: that gap also
includes TUN copies, userspace, UDP encapsulation, framing, and a smaller
MTU. Incremental crypto cost is plaintext versus encrypted.

Direct mode has no `svpn` process. CPU comparison is plaintext `svpn` `%CPU`
vs encrypted `svpn` `%CPU` (`pidstat -u -p <pid> 1` on both Pis during iperf).
Report `encrypted CPU − plaintext CPU` in percentage points.

## Thermal

If `vcgencmd` exists, temperature and `get_throttled` are stored before/after
runs. Sticky bits such as `0x50000` mean under-voltage or throttling occurred
at some point in the boot history. Live throttling during a measurement run
invalidates that run; cool down and re-measure.

## Wi-Fi variability

Both Pis and the control host share the same managed network. Contention,
RSSI, and AP scheduling can move throughput more than crypto does. Results
are reported as mean ± sample standard deviation over multiple runs.

Outer destinations are always the Wi-Fi IPs for direct mode; tunnel modes
always use TUN IPs so a leftover `tun0` route cannot intercept the baseline.

## Packet experiments

`scripts/packet_experiments.sh` is complementary to the bulk TCP tables. It
interleaves the same three modes and writes `results/<timestamp>-packet/`.

| Test | What it measures |
|---|---|
| 1 | UDP datagram size sweep at a fixed 20 Mbps offer (`-l` 64…1372), plus max-effort at 64 and 1372 |
| 2 | `ping` RTT vs ICMP payload, and a DF oversize (`-M do -s 1400`) that should fail on TUN MTU 1400 |
| 3 | Idle RTT vs RTT during a short TCP iperf |
| 4 | UDP loss vs offered rate at payloads 64 and 1372 |

UDP size is varied with `iperf3 -u`, not TCP MSS (MSS coalescing hides
datagram size). Summarize with `scripts/summarize_packet_experiments.py`.
