# Testing

`make test` builds `bin/tests` and returns nonzero on failure.
`make test-sanitize` adds ASan + UBSan.

## Unit tests

| File | Property |
|---|---|
| `test_protocol.c` | Header encode/decode round trip; exact bytes for a known header; big-endian sequence; invalid magic/version/type; truncated buffers 0..27; zero-length DATA rejected; length mismatch / trailing data; oversized inner length; handshake payload size; random-ish buffers must not crash |
| `test_crypto.c` | `crypto_kx` directional keys (`tx==peer rx`, `tx!=rx`); nonce uniqueness and A2B≠B2A prefix; AEAD round trip empty/small/1400; tampered ciphertext, tag, AAD, wrong key, wrong nonce fail |
| `test_handshake.c` | Valid CHLO/SHLO signatures; tampered ephemeral key or random fails; wrong pinned identity fails; echoed client random; both sides same session id and matching directional keys; parse built packets |
| `test_replay.c` | First packet; monotonic; immediate duplicate; reorder inside 64-window once; repeat reorder; exactly outside window; jump ≥64; `UINT64_MAX` edges; sequence 0 rejected |

## Integration (two Pis)

`./scripts/preflight.sh` — SSH, hostnames, `wlan0` IPs vs `config.env`, peer
ping, route via `wlan0` not `eth0`, TUN node, toolchain, libsodium, iperf3,
tcpdump, pidstat, free UDP 55555, no stale `svpn`, thermal if available.

`./scripts/smoke_test.sh plaintext` — ping, TCP iperf3, UDP iperf3 through TUN.

`./scripts/smoke_test.sh encrypted` — same after `session established`.

`./scripts/smoke_test.sh negative` — A pins a throwaway public key; handshake
must fail and inner ping must not pass. Real identity files are not modified.

`./scripts/capture_demo.sh` — marker visible on encrypted `tun0` and plaintext
`wlan0`, absent from encrypted `wlan0`.

`./scripts/packet_experiments.sh` — UDP size sweep, ping RTT vs size, idle vs
loaded RTT, and UDP loss vs offered rate. Complementary to `benchmark.sh`.
