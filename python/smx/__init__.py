"""SM2, SM3, SM4 and SM9 commercial cryptography algorithms with no third-party dependencies.

Per-key caches: by default the library remembers public keys, Z values and point tables
for recently used keys, which makes repeated signing, verifying and encrypting faster.
SM9 keeps decoded master public keys and their pairing values the same way.
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
from .sm9 import (
    SM9_HID_ENCRYPT,
    SM9_HID_EXCHANGE,
    SM9_HID_SIGN,
    SM9_MODE_SM4,
    SM9_MODE_STREAM,
    SM9_N,
    SM9_Q,
    SM9ExchangeResult,
    sm9_decapsulate,
    sm9_decrypt,
    sm9_decrypt_text,
    sm9_enc_master_public_key,
    sm9_encapsulate,
    sm9_encrypt,
    sm9_exchange_check,
    sm9_exchange_confirm,
    sm9_exchange_init,
    sm9_exchange_respond,
    sm9_gen_enc_master_key,
    sm9_gen_enc_user_key,
    sm9_gen_sign_master_key,
    sm9_gen_sign_user_key,
    sm9_sign,
    sm9_sign_master_public_key,
    sm9_verify,
)

__all__ = [
    "SM2_A",
    "SM2_B",
    "SM2_GX",
    "SM2_GY",
    "SM2_N",
    "SM2_P",
    "SM3",
    "SM4",
    "SM9_HID_ENCRYPT",
    "SM9_HID_EXCHANGE",
    "SM9_HID_SIGN",
    "SM9_MODE_SM4",
    "SM9_MODE_STREAM",
    "SM9_N",
    "SM9_Q",
    "ECPoint",
    "SM2KeySwapParams",
    "SM9ExchangeResult",
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
    "sm9_decapsulate",
    "sm9_decrypt",
    "sm9_decrypt_text",
    "sm9_enc_master_public_key",
    "sm9_encapsulate",
    "sm9_encrypt",
    "sm9_exchange_check",
    "sm9_exchange_confirm",
    "sm9_exchange_init",
    "sm9_exchange_respond",
    "sm9_gen_enc_master_key",
    "sm9_gen_enc_user_key",
    "sm9_gen_sign_master_key",
    "sm9_gen_sign_user_key",
    "sm9_sign",
    "sm9_sign_master_public_key",
    "sm9_verify",
]
