#!/usr/bin/env python3
"""
Gateway/hub server: accepts TCP connections from IoT devices, runs
each one through the challenge-response handshake (see
auth_manager.py), and accepts a sensor reading once a device is
authenticated.

Run:  python3 server/gateway_server.py --port 5050
"""

import argparse
import socketserver
import sys

from auth_manager import AuthManager

# In a real deployment these would be provisioned per-device (e.g. at
# manufacture time) and live in a secrets store, not in source. They're
# hardcoded here only because this is a two-device prototype/demo.
DEVICE_SECRETS = {
    "pi-sensor-01": bytes.fromhex("f3a1c9b2e7d4a05f6c8b1e2d3f4a5b6c"),
    "pi-sensor-02": bytes.fromhex("0b1c2d3e4f5061728394a5b6c7d8e9f0"),
}


class DeviceHandler(socketserver.StreamRequestHandler):
    auth_manager: AuthManager = None  # assigned on the class before the server starts

    def handle(self):
        try:
            line = self._read_line()
            if not line or not line.startswith("HELLO "):
                self._send("AUTH_FAIL bad_hello")
                return

            device_id = line.split(" ", 1)[1].strip()
            print(f"[server] HELLO from '{device_id}' ({self.client_address[0]})")

            issued = self.auth_manager.issue_challenge(device_id)
            if issued is None:
                self._send("AUTH_FAIL unknown_device")
                return
            nonce, timestamp = issued
            self._send(f"CHALLENGE {nonce} {timestamp}")

            line = self._read_line()
            if not line or not line.startswith("RESPONSE "):
                self._send("AUTH_FAIL bad_response")
                return
            response_hex = line.split(" ", 1)[1].strip()

            ok, reason = self.auth_manager.verify_response(device_id, response_hex)
            if not ok:
                print(f"[server] auth FAILED for '{device_id}': {reason}")
                self._send(f"AUTH_FAIL {reason}")
                return

            session_token = self.auth_manager.new_session()
            print(f"[server] auth OK for '{device_id}'")
            self._send(f"AUTH_OK {session_token}")

            line = self._read_line()
            if line and line.startswith("DATA "):
                self._handle_data(device_id, line, session_token)

        except (ConnectionError, ValueError) as exc:
            print(f"[server] connection error: {exc}")

    def _handle_data(self, device_id, line, session_token):
        parts = line.split(" ", 2)
        if len(parts) != 3 or parts[1] != session_token:
            self._send("DATA_REJECTED bad_session")
            return
        print(f"[server] reading from '{device_id}': {parts[2]}")
        self._send("DATA_OK")

    def _read_line(self):
        raw = self.rfile.readline()
        return raw.decode().strip() if raw else None

    def _send(self, text):
        self.wfile.write((text + "\n").encode())


def main():
    parser = argparse.ArgumentParser(description="IoT gateway authentication server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5050)
    args = parser.parse_args()

    DeviceHandler.auth_manager = AuthManager(DEVICE_SECRETS)

    with socketserver.ThreadingTCPServer((args.host, args.port), DeviceHandler) as server:
        print(f"[server] listening on {args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[server] shutting down")
            sys.exit(0)


if __name__ == "__main__":
    main()
