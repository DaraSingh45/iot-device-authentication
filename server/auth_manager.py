import hashlib
import hmac
import os
import time
from collections import defaultdict, deque

CHALLENGE_LIFETIME = 10   # seconds a device has to respond before the challenge goes stale
MAX_FAILURES = 5          # consecutive failures before a device is locked out
LOCKOUT_WINDOW = 60       # seconds a lockout lasts


class AuthManager:
    def __init__(self, device_secrets):
        """device_secrets: dict mapping device_id -> shared secret (bytes)."""
        self.device_secrets = device_secrets
        self._pending = {}                    # device_id -> (nonce, timestamp)
        self._consumed_nonces = set()         # nonces already used once, to block reuse
        self._failures = defaultdict(deque)   # device_id -> deque[timestamp] of recent failures
        self._locked_until = {}               # device_id -> unix time lockout ends

    def is_locked_out(self, device_id):
        until = self._locked_until.get(device_id)
        if until is None:
            return False
        if time.time() >= until:
            del self._locked_until[device_id]
            return False
        return True

    def issue_challenge(self, device_id):
        """Returns (nonce_hex, timestamp), or None if device_id isn't registered."""
        if device_id not in self.device_secrets:
            return None
        nonce = os.urandom(16).hex()
        timestamp = int(time.time())
        self._pending[device_id] = (nonce, timestamp)
        return nonce, timestamp

    def verify_response(self, device_id, response_hex):
        """Returns (accepted: bool, reason: str)."""
        if self.is_locked_out(device_id):
            return False, "locked_out"

        pending = self._pending.get(device_id)
        if pending is None:
            return False, "no_pending_challenge"

        nonce, timestamp = pending
        del self._pending[device_id]  # one-shot: a challenge can only be answered once

        if nonce in self._consumed_nonces:
            return False, "replayed_nonce"
        self._consumed_nonces.add(nonce)

        if time.time() - timestamp > CHALLENGE_LIFETIME:
            self._record_failure(device_id)
            return False, "stale_challenge"

        secret = self.device_secrets[device_id]
        expected = self._compute_hmac(secret, device_id, nonce, timestamp)

        if not hmac.compare_digest(expected, response_hex):
            self._record_failure(device_id)
            return False, "bad_hmac"

        self._failures[device_id].clear()
        return True, "ok"

    def new_session(self):
        return os.urandom(8).hex()

    def _record_failure(self, device_id):
        now = time.time()
        hist = self._failures[device_id]
        hist.append(now)
        while hist and now - hist[0] > LOCKOUT_WINDOW:
            hist.popleft()
        if len(hist) >= MAX_FAILURES:
            self._locked_until[device_id] = now + LOCKOUT_WINDOW

    @staticmethod
    def _compute_hmac(secret, device_id, nonce, timestamp):
        message = f"{device_id}|{nonce}|{timestamp}".encode()
        return hmac.new(secret, message, hashlib.sha256).hexdigest()
