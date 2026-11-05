#!/usr/bin/env python3
"""SM2 key exchange and SM4 crypto demo client (side A), using the Java demo server."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python"))

from smx import (
    SM4,
    hex_to_bytes,
    sm2_decode_point,
    sm2_gen_key_pair,
    sm2_get_sa,
)  # noqa: E402

SERVER_URL = "http://localhost:8080"
ID_A = "python-client@demo.aicc"
KEY_LEN = 16
HTTP_TIMEOUT_SECONDS = 10

# Ignore proxy environment variables: the demo server only listens on localhost.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def post_json(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    print(f"Request: {body}")
    request = urllib.request.Request(
        SERVER_URL + path,
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with _OPENER.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        text = response.read().decode("utf-8")
    print(f"Response: {text}")
    return json.loads(text)


def run() -> int:
    print("=== SM2 Key Exchange Demo (Python Client) ===\n")

    da_hex, pa_hex = sm2_gen_key_pair()
    print("Generated A certificate keypair:")
    print(f"  Private key (dA): {da_hex}")
    print(f"  Public key (pA): {pa_hex}")

    ra_hex, ra_pub_hex = sm2_gen_key_pair()
    print("\nGenerated A random keypair:")
    print(f"  Private key (ra): {ra_hex}")
    print(f"  Public key (Ra): {ra_pub_hex}")

    print("\n--- Step 1: Key Exchange Init ---")
    init = post_json(
        "/api/keyswap/init",
        {"IDa": ID_A, "pA": pa_hex, "Ra": ra_pub_hex, "keyLen": KEY_LEN},
    )

    print("\n--- Step 2: Calculate Sa and Ka ---")
    result = sm2_get_sa(
        KEY_LEN,
        sm2_decode_point(init["pB"]),
        sm2_decode_point(init["Rb"]),
        sm2_decode_point(pa_hex),
        int(da_hex, 16),
        sm2_decode_point(ra_pub_hex),
        int(ra_hex, 16),
        ID_A,
        init["IDb"],
        hex_to_bytes(init["Sb"]),
    )
    if not result.success:
        print(f"getSa failed: {result.message}", file=sys.stderr)
        return 1
    print(f"Sa: {result.sa}")
    print(f"Ka (negotiated key): {result.ka}")

    print("\n--- Step 3: Key Exchange Confirm ---")
    confirm = post_json(
        "/api/keyswap/confirm", {"sessionId": init["sessionId"], "Sa": result.sa}
    )
    if not confirm.get("success"):
        print("Key exchange confirmation failed", file=sys.stderr)
        return 1
    print("\nKey exchange completed successfully!")
    print(f"Negotiated key (Ka): {result.ka}")

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
    print(f"  Server plaintext: {crypto['serverPlaintext']}")
    print(f"  Client decrypted: {server_decrypted}")

    if not (server_decrypt_ok and client_decrypt_ok):
        print("\nBidirectional Crypto test FAILED!", file=sys.stderr)
        return 1
    print("\nBidirectional Crypto test PASSED!")
    print("\n=== Demo Complete ===")
    return 0


def main() -> int:
    try:
        return run()
    except (urllib.error.URLError, OSError) as error:
        print(f"Failed to connect to server: {error}", file=sys.stderr)
        print("Make sure the Java server is running on port 8080", file=sys.stderr)
    except (KeyError, ValueError) as error:
        print(f"Invalid server response: {error!r}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
