import hashlib
import hmac
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

from auth_manager import AuthManager

SECRET = b"unit-test-secret-key"
DEVICE_ID = "test-device"


def make_manager():
    return AuthManager({DEVICE_ID: SECRET})


def compute_hmac(device_id, nonce, timestamp):
    message = f"{device_id}|{nonce}|{timestamp}".encode()
    return hmac.new(SECRET, message, hashlib.sha256).hexdigest()


def test_valid_handshake_succeeds():
    mgr = make_manager()
    nonce, ts = mgr.issue_challenge(DEVICE_ID)
    ok, reason = mgr.verify_response(DEVICE_ID, compute_hmac(DEVICE_ID, nonce, ts))
    assert ok and reason == "ok"


def test_wrong_hmac_rejected():
    mgr = make_manager()
    mgr.issue_challenge(DEVICE_ID)
    ok, reason = mgr.verify_response(DEVICE_ID, "0" * 64)
    assert not ok and reason == "bad_hmac"


def test_unknown_device_rejected():
    mgr = make_manager()
    assert mgr.issue_challenge("ghost-device") is None


def test_response_without_challenge_rejected():
    mgr = make_manager()
    ok, reason = mgr.verify_response(DEVICE_ID, "0" * 64)
    assert not ok and reason == "no_pending_challenge"


def test_stale_challenge_rejected():
    mgr = make_manager()
    nonce, ts = mgr.issue_challenge(DEVICE_ID)
    mgr._pending[DEVICE_ID] = (nonce, ts - 999)  # force the challenge to look old
    ok, reason = mgr.verify_response(DEVICE_ID, compute_hmac(DEVICE_ID, nonce, ts))
    assert not ok and reason == "stale_challenge"


def test_replayed_nonce_rejected():
    """Simulates an attacker who somehow gets a previously-used nonce
    treated as pending again, then replays a captured response against
    it. In normal operation a nonce is only ever pending once, so this
    manually re-arms it to exercise that specific defense in isolation."""
    mgr = make_manager()
    nonce, ts = mgr.issue_challenge(DEVICE_ID)
    response = compute_hmac(DEVICE_ID, nonce, ts)
    ok, _ = mgr.verify_response(DEVICE_ID, response)
    assert ok

    mgr._pending[DEVICE_ID] = (nonce, ts)
    ok2, reason2 = mgr.verify_response(DEVICE_ID, response)
    assert not ok2 and reason2 == "replayed_nonce"


def test_lockout_after_repeated_failures():
    mgr = make_manager()
    for _ in range(5):
        mgr.issue_challenge(DEVICE_ID)
        ok, _ = mgr.verify_response(DEVICE_ID, "0" * 64)
        assert not ok

    mgr.issue_challenge(DEVICE_ID)
    ok, reason = mgr.verify_response(DEVICE_ID, "0" * 64)
    assert not ok and reason == "locked_out"


def test_lockout_expires():
    mgr = make_manager()
    for _ in range(5):
        mgr.issue_challenge(DEVICE_ID)
        mgr.verify_response(DEVICE_ID, "0" * 64)
    assert mgr.is_locked_out(DEVICE_ID)

    mgr._locked_until[DEVICE_ID] = time.time() - 1  # force the lockout to have expired
    assert not mgr.is_locked_out(DEVICE_ID)


def test_successful_auth_clears_failure_history():
    mgr = make_manager()
    for _ in range(3):
        mgr.issue_challenge(DEVICE_ID)
        mgr.verify_response(DEVICE_ID, "0" * 64)

    nonce, ts = mgr.issue_challenge(DEVICE_ID)
    ok, _ = mgr.verify_response(DEVICE_ID, compute_hmac(DEVICE_ID, nonce, ts))
    assert ok
    assert len(mgr._failures[DEVICE_ID]) == 0


if __name__ == "__main__":
    test_valid_handshake_succeeds()
    test_wrong_hmac_rejected()
    test_unknown_device_rejected()
    test_response_without_challenge_rejected()
    test_stale_challenge_rejected()
    test_replayed_nonce_rejected()
    test_lockout_after_repeated_failures()
    test_lockout_expires()
    test_successful_auth_clears_failure_history()
    print("All tests passed.")
