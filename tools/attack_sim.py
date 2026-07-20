#!/usr/bin/env python3

import hashlib
import hmac
import os
import socket
import socketserver
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

from auth_manager import AuthManager
from gateway_server import DEVICE_SECRETS, DeviceHandler

HOST, PORT = "127.0.0.1", 5099
DEVICE_ID = "pi-sensor-01"
REAL_SECRET = DEVICE_SECRETS[DEVICE_ID]


def start_server():
    DeviceHandler.auth_manager = AuthManager(DEVICE_SECRETS)
    server = socketserver.ThreadingTCPServer((HOST, PORT), DeviceHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def read_line(sock):
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf.decode().strip()


def do_handshake(device_id, compute_response, label):
    sock = socket.create_connection((HOST, PORT), timeout=5)
    sock.sendall(f"HELLO {device_id}\n".encode())

    challenge_line = read_line(sock)
    print(f"[{label}] <- {challenge_line}")
    _, nonce, timestamp = challenge_line.split()

    response_hex = compute_response(device_id, nonce, timestamp)
    sock.sendall(f"RESPONSE {response_hex}\n".encode())

    result_line = read_line(sock)
    print(f"[{label}] <- {result_line}")
    sock.close()
    return result_line


def legit_response(device_id, nonce, timestamp):
    message = f"{device_id}|{nonce}|{timestamp}".encode()
    return hmac.new(REAL_SECRET, message, hashlib.sha256).hexdigest()


def wrong_response(device_id, nonce, timestamp):
    return os.urandom(32).hex()  # a guess with no knowledge of the real secret


def main():
    print(f"Starting gateway server on {HOST}:{PORT}\n")
    start_server()
    time.sleep(0.3)

    print("=== Scenario 1: legitimate device, correct secret ===")
    result = do_handshake(DEVICE_ID, legit_response, "legit")
    assert result.startswith("AUTH_OK"), "legitimate device should be accepted"

    print("\n=== Scenario 2: attacker without the secret guesses ===")
    result = do_handshake(DEVICE_ID, wrong_response, "attacker")
    assert result.startswith("AUTH_FAIL bad_hmac"), "wrong HMAC should be rejected"

    print("\n=== Scenario 3: captured transcript replayed on a new connection ===")
    sock = socket.create_connection((HOST, PORT), timeout=5)
    sock.sendall(f"HELLO {DEVICE_ID}\n".encode())
    challenge_line = read_line(sock)
    _, old_nonce, old_ts = challenge_line.split()
    old_response = legit_response(DEVICE_ID, old_nonce, old_ts)
    sock.sendall(f"RESPONSE {old_response}\n".encode())
    read_line(sock)  # consume AUTH_OK for this legitimate exchange
    sock.close()

    def replay_old_response(device_id, nonce, timestamp):
        return old_response  # reuse the previously captured response verbatim

    result = do_handshake(DEVICE_ID, replay_old_response, "replay")
    assert result.startswith("AUTH_FAIL"), "a replayed old response should be rejected"
    print("    (rejected as bad_hmac - the captured response doesn't match the new nonce")
    print("     the server just issued, which is what defeats the replay)")

    print("\n=== Scenario 4: brute force - repeated wrong guesses trigger a lockout ===")
    for attempt in range(1, 8):
        result = do_handshake(DEVICE_ID, wrong_response, f"bruteforce#{attempt}")
        if "locked_out" in result:
            print(f"    locked out after {attempt} failed attempts")
            break
    else:
        raise AssertionError("expected a lockout after repeated failures")

    print("\nAll attack scenarios behaved as expected.")


if __name__ == "__main__":
    main()
