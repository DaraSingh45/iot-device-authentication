# IoT Device Authentication System

A challenge-response authentication layer for an IoT sensor node,
prototyped as a Raspberry Pi-style C client talking to a Python
gateway server over TCP. Built to replace the pattern a lot of cheap
IoT devices actually ship with - a hardcoded plaintext password or API
key sent on every connection - with something that doesn't expose the
credential even if the traffic is captured.

The device firmware is simulated on a normal machine over a TCP
socket rather than on real GPIO/sensor hardware, since the interesting
part here is the authentication protocol, not reading a temperature
sensor. The C client is written to be portable to an actual Raspberry
Pi with no changes - see [Running on real
hardware](#running-on-real-hardware) below.

## The problem this addresses

A device that authenticates by sending a fixed password or token has
two weaknesses: the credential is exposed to anyone who captures the
traffic, and there's nothing stopping a captured credential from being
replayed later. This project fixes both:

- The device never sends its secret key - only proof that it has it
- Each login uses a fresh, random, one-time challenge from the server,
  so a captured (challenge, response) pair from a past connection is
  useless on a new one - the server will never issue that exact
  challenge again
- Repeated failed attempts get locked out, so a stolen/guessed-at
  credential can't just be brute-forced against the server

## Protocol

```
device                              server
  |--------- HELLO <device_id> ------->|
  |<---- CHALLENGE <nonce> <ts> -------|
  |------- RESPONSE <hmac> ----------->|
  |<----- AUTH_OK <session_token> -----|   (or AUTH_FAIL <reason>)
  |---- DATA <session_token> <reading>->|
  |<----------- DATA_OK ---------------|
```

`<hmac>` is `HMAC-SHA256(secret, device_id|nonce|timestamp)`, hex
encoded. The secret is a key provisioned onto the device ahead of
time (see `DEVICE_SECRETS` in `server/gateway_server.py`) - it's never
transmitted, only proven.

## Project layout

| Path | Responsibility |
|---|---|
| `server/auth_manager.py` | Core verification logic - nonce issuing, HMAC checking, replay/lockout rules. No sockets, fully unit-testable. |
| `server/gateway_server.py` | Threaded TCP server that wraps `AuthManager` in the actual wire protocol |
| `device/device_client.c` | Simulated device firmware - connects, proves it holds the secret, sends one reading |
| `tools/attack_sim.py` | Spins up the server and throws bad-HMAC, replay, and brute-force attempts at it over real sockets |
| `tests/test_server_auth.py` | Unit tests for `AuthManager` |

## Requirements

**Server (Python):** Python 3.8+, standard library only - nothing to
`pip install`.

**Device (C):** `gcc`, `make`, and OpenSSL development headers (for
HMAC-SHA256):

```bash
sudo apt-get install build-essential libssl-dev
```

## Running it

Terminal 1 - start the gateway:

```bash
cd server
python3 gateway_server.py --port 5050
```

Terminal 2 - build and run the device:

```bash
cd device
make
./device_client 127.0.0.1 5050 pi-sensor-01 f3a1c9b2e7d4a05f6c8b1e2d3f4a5b6c
```

The secret above is `pi-sensor-01`'s key from `DEVICE_SECRETS` in
`gateway_server.py` - copy the hex string from there for whichever
device ID you use, or add your own entry.

Sample output from both sides: [`examples/sample_output.txt`](examples/sample_output.txt)

## Running on real hardware

`device_client.c` uses only POSIX sockets and OpenSSL, both of which
are standard on Raspberry Pi OS, so it compiles and runs there
unmodified with the same `make` / `./device_client` steps - just point
`server_ip` at the machine running `gateway_server.py` on your
network instead of `127.0.0.1`.

## Seeing the attacks fail

```bash
python3 tools/attack_sim.py
```

This starts its own server instance and runs through:

1. A legitimate device authenticating successfully
2. An attacker without the secret guessing and getting rejected
3. A captured (challenge, response) pair being replayed on a new
   connection - and failing, because the server issues a brand new
   challenge each time, so the old response no longer matches anything
4. Repeated wrong guesses triggering a lockout after 5 failures

## Testing

```bash
python3 tests/test_server_auth.py
# or
pytest tests/
```

Covers valid handshakes, wrong HMACs, unknown devices, stale
challenges, nonce replay (see the docstring on
`test_replayed_nonce_rejected` for how that one's set up), and lockout
behavior including expiry.

## Limitations

- Session tokens exist for the length of one TCP connection only -
  there's no persistent session store, so a device has to redo the
  full handshake on every reconnect
- Device secrets are hardcoded in `gateway_server.py` for this
  prototype; a real deployment would provision them per-device (e.g.
  at manufacture time) and keep them in a proper secrets store, not in
  source
- The lockout is per `device_id`, not per source IP, so a spoofed
  `device_id` in the `HELLO` line wouldn't get rate-limited correctly
  against the real device's history - fine for a single-network
  prototype, not for anything internet-facing
- No TLS - fine for a lab network, not for production without wrapping
  the TCP connection in something like mTLS

## Possible next steps

- Per-IP rate limiting in addition to per-device lockout
- Persist session tokens so a device can reconnect without a full
  re-handshake within some short window
- Move device secrets out of source and into a config file loaded at
  startup

## License

MIT - see [LICENSE](LICENSE).
