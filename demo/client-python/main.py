#!/usr/bin/env python3
"""SM2 key exchange and SM4 crypto demo client (side A), using the Java demo server.

This demo talks plain HTTP to localhost, so nothing protects it on a real network, and
SM4-CBC with the zero IV of this protocol is for demonstration only. Do not copy either
choice into production. Private keys and negotiated keys are never printed.

The protocol takes the server's public key from the same unauthenticated response it
is checking, so by default anyone answering on the port can complete the exchange and
read the traffic. Set SM2_DEMO_SERVER_PUBKEY to the server's public key in hex to pin
it; a different key is then a hard failure.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))

from smx import (
    SM4,
    ECPoint,
    hex_to_bytes,
    sm2_decode_point,
    sm2_gen_key_pair,
    sm2_get_sa,
)
from smx.hexutil import hex_to_int

SERVER_URL = "http://localhost:8080"
ID_A = "python-client@demo.aicc"
KEY_LEN = 16
# Limits the whole request. A socket timeout alone restarts with each byte received.
REQUEST_DEADLINE_SECONDS = 15.0
MAX_RESPONSE_BYTES = 1024 * 1024
PIN_VARIABLE = "SM2_DEMO_SERVER_PUBKEY"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: a response must not send this request somewhere else."""

    def redirect_request(self, *args, **kwargs):
        return None


# Ignore proxy environment variables: the demo server only listens on localhost.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def printable(value: object) -> str:
    """Escape control characters, so server text cannot drive the terminal."""
    return "".join(
        char if char.isprintable() else f"\\x{ord(char):02x}" for char in str(value)
    )


def _fetch(request: urllib.request.Request) -> bytes:
    with _OPENER.open(request, timeout=REQUEST_DEADLINE_SECONDS) as response:
        return response.read(MAX_RESPONSE_BYTES + 1)


def _fetch_before_deadline(request: urllib.request.Request) -> bytes:
    """Run the whole request in a thread that the demo stops waiting for at the deadline."""
    outcome: list[object] = []

    def worker() -> None:
        try:
            outcome.append(_fetch(request))
        except BaseException as error:  # noqa: BLE001 - handed over to the waiting thread
            outcome.append(error)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(REQUEST_DEADLINE_SECONDS)
    if not outcome:
        raise TimeoutError("the server did not finish responding in time")
    if isinstance(outcome[0], BaseException):
        raise outcome[0]
    return outcome[0]


def post_json(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    print(f"Request: {body}")
    request = urllib.request.Request(
        SERVER_URL + path,
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    raw = _fetch_before_deadline(request)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("response too large")
    text = raw.decode("utf-8")
    print(f"Response: {printable(text)}")
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise TypeError("response is not a JSON object")
    return parsed


def pinned_server_key() -> ECPoint | None:
    """Return the pinned key; a value that is set but invalid raises ValueError."""
    value = os.environ.get(PIN_VARIABLE)
    return None if value is None else sm2_decode_point(value)


def run() -> int:
    print("=== SM2 Key Exchange Demo (Python Client) ===\n")

    pinned = pinned_server_key()
    if pinned is None:
        print(
            f"WARNING: the server is UNAUTHENTICATED. Set {PIN_VARIABLE} to pin its key;"
            " without it, anyone answering on this port can read this traffic.\n"
        )

    da_hex, pa_hex = sm2_gen_key_pair()
    print("Generated A certificate keypair:")
    print(f"  Public key (pA): {pa_hex}")

    ra_hex, ra_pub_hex = sm2_gen_key_pair()
    print("\nGenerated A random keypair:")
    print(f"  Public key (Ra): {ra_pub_hex}")

    print("\n--- Step 1: Key Exchange Init ---")
    init = post_json(
        "/api/keyswap/init",
        {"IDa": ID_A, "pA": pa_hex, "Ra": ra_pub_hex, "keyLen": KEY_LEN},
    )

    print("\n--- Step 2: Calculate Sa and Ka ---")
    server_key = sm2_decode_point(init["pB"])
    if pinned is not None and server_key != pinned:
        print("Server public key does not match the pinned key", file=sys.stderr)
        return 1
    result = sm2_get_sa(
        KEY_LEN,
        server_key,
        sm2_decode_point(init["Rb"]),
        sm2_decode_point(pa_hex),
        hex_to_int(da_hex),
        sm2_decode_point(ra_pub_hex),
        hex_to_int(ra_hex),
        ID_A,
        init["IDb"],
        hex_to_bytes(init["Sb"]),
    )
    if not result.success:
        print(f"getSa failed: {result.message}", file=sys.stderr)
        return 1
    print(f"Sa: {result.sa}")

    print("\n--- Step 3: Key Exchange Confirm ---")
    confirm = post_json(
        "/api/keyswap/confirm", {"sessionId": init["sessionId"], "Sa": result.sa}
    )
    if confirm.get("success") is not True:
        print("Key exchange confirmation failed", file=sys.stderr)
        return 1
    if pinned is None:
        print("\nKey exchange confirmed, with an UNAUTHENTICATED server.")
    else:
        print("\nKey exchange confirmed, with the pinned server key.")

    print("\n--- Step 4: Bidirectional Crypto Test ---")
    sm4 = SM4()
    sm4.set_key(hex_to_bytes(result.ka), bytes(16))  # zero IV, same as the server

    client_plaintext = "Hello from Python Client!"
    client_ciphertext = sm4.encrypt(client_plaintext)
    print(f"Client plaintext: {client_plaintext}")
    print(f"Client ciphertext: {client_ciphertext}\n")

    crypto = post_json(
        "/api/crypto/test",
        {
            "sessionId": init["sessionId"],
            "clientCiphertext": client_ciphertext,
            "clientPlaintext": client_plaintext,
        },
    )

    server_decrypt_ok = crypto["clientDecryptMatch"] is True
    print(
        f"\n[Server decrypted client message]: {'PASS' if server_decrypt_ok else 'FAIL'}"
    )

    server_decrypted = sm4.decrypt(crypto["serverCiphertext"])
    client_decrypt_ok = server_decrypted == crypto["serverPlaintext"]
    print(
        f"[Client decrypted server message]: {'PASS' if client_decrypt_ok else 'FAIL'}"
    )
    print(f"  Server plaintext: {printable(crypto['serverPlaintext'])}")
    print(f"  Client decrypted: {printable(server_decrypted)}")

    if not (server_decrypt_ok and client_decrypt_ok):
        print("\nBidirectional Crypto test FAILED!", file=sys.stderr)
        return 1
    print("\nBidirectional Crypto test PASSED!")
    print("\n=== Demo Complete ===")
    return 0


def main() -> int:
    try:
        return run()
    except (urllib.error.URLError, OSError, http.client.HTTPException) as error:
        print(f"Failed to connect to server: {printable(error)}", file=sys.stderr)
        print("Make sure the Java server is running on port 8080", file=sys.stderr)
    except (KeyError, TypeError, ValueError, RecursionError, MemoryError) as error:
        print(f"Invalid server response: {type(error).__name__}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
