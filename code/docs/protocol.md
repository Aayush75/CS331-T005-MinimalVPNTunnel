# Protocol

All multi-byte integers are **big-endian**. Parsers take a pointer and a
length and never read past the buffer. C structs are not sent on the wire.

## Common header (28 bytes)

| Offset | Size | Field |
|-------:|-----:|---|
| 0 | 4 | magic `"SVPN"` (`53 56 50 4e`) |
| 4 | 1 | version `1` |
| 5 | 1 | type |
| 6 | 2 | flags (must be `0` in v1) |
| 8 | 8 | session_id |
| 16 | 8 | sequence |
| 24 | 2 | plaintext_len |
| 26 | 2 | reserved `0` |

Types: `1` CLIENT_HELLO, `2` SERVER_HELLO, `3` DATA, `4` CLOSE (parsed, unused).

Packets with nonzero flags or a nonzero reserved field are rejected. This
avoids silently accepting extensions that version 1 does not define.

### Example DATA header

Session id `01..08`, sequence `1`, plaintext_len `4`:

```text
53 56 50 4e  01  03  00 00
01 02 03 04 05 06 07 08
00 00 00 00 00 00 00 01
00 04  00 00
```

## DATA body

**Plaintext mode:** `plaintext_len` bytes of inner IP. `session_id` may be
zero. Sequence still starts at 1 and increments.

**Encrypted mode:** `plaintext_len + 16` bytes of ChaCha20-Poly1305-IETF
ciphertext (tag included). The 28-byte header is AEAD **AAD**. Inner IP is
the AEAD plaintext.

Zero-length DATA is rejected. `plaintext_len > 1400` is rejected. Extra
trailing bytes after the expected body are rejected.

## Handshake

Pi A is client/initiator; Pi B is server/responder. Fresh X25519-compatible
`crypto_kx` keypairs every process start. Long-term Ed25519 keys only sign.

### CLIENT_HELLO payload (112 bytes)

| Offset | Size | Field |
|-------:|-----:|---|
| 0 | 32 | client ephemeral public key |
| 32 | 16 | client random |
| 48 | 64 | Ed25519 signature |

Transcript (explicit concatenation, not a struct):

```text
"SVPN-CHLO-v1" || version || client_random || client_ephemeral_pk
```

### SERVER_HELLO payload (128 bytes)

| Offset | Size | Field |
|-------:|-----:|---|
| 0 | 32 | server ephemeral public key |
| 32 | 16 | echoed client random |
| 48 | 16 | server random |
| 64 | 64 | Ed25519 signature |

```text
"SVPN-SHLO-v1" || version || client_random || server_random
               || client_ephemeral_pk || server_ephemeral_pk
```

Client retransmits CLIENT_HELLO every 500 ms, overall timeout 10 s. Server
retransmits the same SERVER_HELLO if it sees an identical CLIENT_HELLO.

A signature that does not verify under the **pinned** peer identity public
key fails the handshake. Wrong echo of `client_random` is rejected.

## Session id

Not secret. First 8 bytes of `crypto_generichash` over:

```text
client_random || server_random || client_eph_pk || server_eph_pk
```

Encrypted DATA with a different session id is dropped (stale process).

## Key derivation

```text
crypto_kx_client_session_keys()  on A
crypto_kx_server_session_keys()  on B
```

This yields `client_tx == server_rx` and `client_rx == server_tx`.

## Nonce (12 bytes)

ChaCha20-Poly1305-IETF nonce:

```text
bytes 0..3  = first 4 bytes of BLAKE2b("A2B" || session_id)   // A→B
            or first 4 bytes of BLAKE2b("B2A" || session_id)   // B→A
bytes 4..11 = sequence as uint64 big-endian
```

Client TX uses A→B; server TX uses B→A.

Nonce reuse cannot occur in the intended lifecycle because:

1. each process start uses a new ephemeral `crypto_kx` pair (new session keys
   and a new session id / prefix)
2. each direction has its own key
3. sequence numbers start at 1 and never wrap; wrap terminates the session

`rand()` is never used for cryptographic values (`randombytes_buf` /
libsodium).

## Replay window

AEAD does not stop replay of a valid ciphertext. After successful decrypt,
each receive direction maintains `highest_sequence` and a 64-bit bitmap
(bit 0 = highest). Duplicate sequences and sequences older than
`highest - 63` are dropped. Unauthenticated packets never advance the window.

## Malformed packets

Drop, count, optionally log in `--verbose`. Do not crash. Repeated auth
failures do not tear down the process (except a failed *handshake* signature
on the client, which exits because there is no session).
