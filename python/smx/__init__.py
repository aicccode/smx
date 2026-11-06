"""SM2, SM3 and SM4 commercial cryptography algorithms with no third-party dependencies.

Per-key caches: by default the library remembers public keys, Z values and point tables
for recently used keys, which makes repeated signing, verifying and encrypting faster.
Private keys are never stored; the public-key cache is keyed by their SHA-256 digest.
The caches do reveal, through timing and to anyone who can read process memory, which
keys were used recently. To turn them off, call ``smx.set_key_cache_enabled(False)`` or
set the environment variable ``SMX_DISABLE_KEY_CACHE=1`` before import. Disabling also
drops everything already cached. ``smx.clear_key_caches()`` empties them at any time.

Timing: Python integers offer no constant-time guarantee; see :mod:`smx._ec`. SM4 here
uses table lookups and is not cache-timing resistant; the ``security`` branch of the
repository has the variant without them. For the limits of SM4-CBC, including the
absence of integrity, see :mod:`smx.sm4`.
"""

from .hexutil import bytes_to_hex, hex_to_bytes
from .point import SM2_A, SM2_B, SM2_GX, SM2_GY, SM2_N, SM2_P, ECPoint
from .sm2 import (
    SM2KeySwapParams,
    clear_key_caches,
    set_key_cache_enabled,
    sm2_check_sa,
    sm2_decode_point,
    sm2_decrypt,
    sm2_encrypt,
    sm2_gen_key_pair,
    sm2_get_public_key,
    sm2_get_sa,
    sm2_get_sb,
    sm2_sign,
    sm2_verify,
)
from .sm3 import SM3
from .sm4 import SM4

__all__ = [
    "SM2_A",
    "SM2_B",
    "SM2_GX",
    "SM2_GY",
    "SM2_N",
    "SM2_P",
    "SM3",
    "SM4",
    "ECPoint",
    "SM2KeySwapParams",
    "bytes_to_hex",
    "clear_key_caches",
    "hex_to_bytes",
    "set_key_cache_enabled",
    "sm2_check_sa",
    "sm2_decode_point",
    "sm2_decrypt",
    "sm2_encrypt",
    "sm2_gen_key_pair",
    "sm2_get_public_key",
    "sm2_get_sa",
    "sm2_get_sb",
    "sm2_sign",
    "sm2_verify",
]
