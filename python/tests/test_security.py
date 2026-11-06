"""Security behaviour: the shared vectors, input rejection, caches and secret hygiene."""

from __future__ import annotations

import array
import json
import os
import pickle
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

import smx
from smx import (
    SM2_N,
    SM2_P,
    SM3,
    SM4,
    ECPoint,
    _ec,
    clear_key_caches,
    hexutil,
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
from smx import sm2 as sm2_module
from smx import sm3 as sm3_module
from smx.sm2 import user_sm3_z
from smx.sm4 import pkcs7_pad, pkcs7_unpad

from .slow import slow

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads(
    (ROOT.parent / "testvectors" / "security-vectors.json").read_text(encoding="utf-8")
)
V_SM2 = VECTORS["sm2"]
V_SM3 = VECTORS["sm3"]
V_SM4 = VECTORS["sm4"]
PRIVATE = V_SM2["private_key"]
PUBLIC = V_SM2["public_key"]
MIB = 1024 * 1024
DEFAULT_SB = object()


def make_sm4(key: bytes | None = None, iv: bytes | None = None) -> SM4:
    cipher = SM4()
    cipher.set_key(
        bytes.fromhex(V_SM4["key"]) if key is None else key,
        bytes.fromhex(V_SM4["iv"]) if iv is None else iv,
    )
    return cipher


class SharedVectorsSM2(unittest.TestCase):
    def test_valid_values(self):
        derived = sm2_get_public_key(int(PRIVATE, 16))
        self.assertEqual(derived.to_hex_encoded(), PUBLIC)
        signature = V_SM2["r"] + "h" + V_SM2["s"]
        self.assertTrue(
            sm2_verify(V_SM2["user_id"], signature, V_SM2["message"], PUBLIC)
        )
        k = int(V_SM2["nonce_k"], 16)
        with mock.patch("smx.sm2._random_scalar", return_value=k):
            self.assertEqual(
                sm2_sign(V_SM2["user_id"], V_SM2["message"], PRIVATE), signature
            )
            self.assertEqual(
                sm2_encrypt(V_SM2["plaintext"], PUBLIC), V_SM2["ciphertext"]
            )
        self.assertEqual(sm2_decrypt(V_SM2["ciphertext"], PRIVATE), V_SM2["plaintext"])

    def test_invalid_public_keys(self):
        signature = V_SM2["r"] + "h" + V_SM2["s"]
        for case in V_SM2["invalid_public_keys"]:
            with self.subTest(case["name"]):
                value = case["value"]
                with self.assertRaises(ValueError):
                    sm2_decode_point(value)
                with self.assertRaises(ValueError):
                    sm2_encrypt("x", value)
                self.assertIs(sm2_verify("id", signature, "m", value), False)

    def test_invalid_private_keys(self):
        ciphertext = V_SM2["ciphertext"]
        for case in V_SM2["invalid_private_keys"]:
            with self.subTest(case["name"]), self.assertRaises(ValueError):
                sm2_sign("id", "m", case["value"])
                with self.assertRaises(ValueError):
                    sm2_decrypt(ciphertext, case["value"])

    def test_largest_valid_private_key(self):
        d = V_SM2["n_minus_2_is_max_valid_private_key"]
        public = sm2_get_public_key(int(d, 16)).to_hex_encoded()
        signature = sm2_sign("id", "m", d)
        self.assertTrue(sm2_verify("id", signature, "m", public))
        self.assertEqual(sm2_decrypt(sm2_encrypt("hello", public), d), "hello")

    def test_invalid_signatures(self):
        for case in V_SM2["invalid_signatures"]:
            with self.subTest(case["name"]):
                signature = case["r"] + "h" + case["s"]
                result = sm2_verify(
                    V_SM2["user_id"], signature, V_SM2["message"], PUBLIC
                )
                self.assertIs(result, False)

    def test_invalid_ciphertexts(self):
        for case in V_SM2["invalid_ciphertexts"]:
            with self.subTest(case["name"]), self.assertRaises(ValueError):
                sm2_decrypt(case["value"], PRIVATE)

    def test_user_id_limit(self):
        public_point = sm2_decode_point(PUBLIC)
        longest = "a" * V_SM2["user_id_max_bytes"]
        too_long = "a" * V_SM2["user_id_first_invalid_bytes"]
        signature = sm2_sign(longest, "m", PRIVATE)
        self.assertTrue(sm2_verify(longest, signature, "m", PUBLIC))
        self.assertEqual(len(user_sm3_z(longest.encode(), public_point)), 32)
        with self.assertRaises(ValueError):
            sm2_sign(too_long, "m", PRIVATE)
        self.assertIs(sm2_verify(too_long, signature, "m", PUBLIC), False)
        with self.assertRaises(ValueError):
            user_sm3_z(too_long.encode(), public_point)
        # The limit counts bytes, not characters.
        self.assertIs(sm2_verify("密" * 2731, signature, "m", PUBLIC), False)


class SharedVectorsSM4(unittest.TestCase):
    def test_valid_ciphertexts(self):
        cipher = make_sm4()
        self.assertEqual(
            cipher.encrypt(V_SM4["valid_padded_plaintext"]),
            V_SM4["valid_padded_ciphertext"],
        )
        self.assertEqual(
            cipher.decrypt(V_SM4["valid_padded_ciphertext"]),
            V_SM4["valid_padded_plaintext"],
        )

    def test_full_padding_block(self):
        cipher = make_sm4()
        ciphertext = V_SM4["valid_full_padding_block_ciphertext"]
        self.assertEqual(cipher.decrypt(ciphertext), "")
        self.assertEqual(cipher.encrypt(""), ciphertext)

    def test_invalid_key_and_iv_lengths(self):
        for size in V_SM4["invalid_key_lengths_bytes"]:
            with self.assertRaises(ValueError):
                make_sm4(key=bytes(size))
        for size in V_SM4["invalid_iv_lengths_bytes"]:
            with self.assertRaises(ValueError):
                make_sm4(iv=bytes(size))

    def test_every_padding_and_length_failure_is_the_same_error(self):
        cipher = make_sm4()
        messages = set()
        bad = [case["value"] for case in V_SM4["invalid_paddings"]]
        bad += ["00" * size for size in V_SM4["invalid_ciphertext_lengths_bytes"]]
        bad += ["zz" * 16, "0"]
        for value in bad:
            with self.assertRaises(ValueError) as caught:
                cipher.decrypt(value)
            messages.add(str(caught.exception))
        self.assertEqual(messages, {"decryption failed"})

    def test_unpad_accepts_exactly_the_valid_paddings(self):
        for body in (b"", b"a" * 16):
            for pad in range(256):
                for last_differs in (False, True):
                    block = bytearray(b"z" * 16)
                    count = min(pad, 16)
                    block[16 - count :] = bytes([pad]) * count
                    block[-1] = pad
                    if last_differs and count > 1:
                        block[-2] ^= 1
                    data = body + bytes(block)
                    valid = 1 <= pad <= 16 and not (last_differs and count > 1)
                    if valid:
                        self.assertEqual(pkcs7_unpad(data), data[:-pad])
                    else:
                        with self.assertRaises(ValueError):
                            pkcs7_unpad(data)

    def test_failed_set_key_keeps_the_previous_key(self):
        cipher = make_sm4()
        expected = cipher.encrypt("x")
        with self.assertRaises(ValueError):
            cipher.set_key(bytes(15), bytes(16))
        self.assertEqual(cipher.encrypt("x"), expected)

    def test_multi_byte_buffers_count_bytes(self):
        cipher = make_sm4()
        words = array.array("I", [0] * 16)
        with self.assertRaises(ValueError):
            cipher.encrypt_block(words)
        good = array.array("I", [1, 2, 3, 4])
        self.assertEqual(
            cipher.encrypt_block(good), cipher.encrypt_block(good.tobytes())
        )

    def test_integer_is_not_a_key(self):
        with self.assertRaises(ValueError):
            make_sm4(key=16)


class SM3Lengths(unittest.TestCase):
    def test_length_limit_is_checked_before_any_change(self):
        hasher = SM3()
        hasher._length = sm3_module._MAX_MESSAGE_BYTES
        with self.assertRaises(ValueError):
            hasher.update(b"x")
        with self.assertRaises(ValueError):
            hasher.update_byte(1)
        self.assertEqual(hasher._length, sm3_module._MAX_MESSAGE_BYTES)
        self.assertEqual(hasher._buffer, bytearray())

    def test_non_byte_buffers_hash_their_bytes(self):
        words = array.array("I", range(40))
        raw = words.tobytes()
        expected = SM3().update(raw).finish().hash_bytes()
        self.assertEqual(SM3().update(words).finish().hash_bytes(), expected)
        view = memoryview(words)
        self.assertEqual(SM3().update(view).finish().hash_bytes(), expected)
        strided = memoryview(raw)[::2]
        self.assertEqual(
            SM3().update(strided).finish().hash_bytes(),
            SM3().update(raw[::2]).finish().hash_bytes(),
        )

    def test_buffer_is_empty_after_finish(self):
        hasher = SM3().update(array.array("I", range(5))).finish()
        self.assertEqual(hasher._buffer, bytearray())
        self.assertEqual(
            hasher.update(b"abc").finish().hash_bytes(),
            SM3().update(b"abc").finish().hash_bytes(),
        )

    @slow("about 30 minutes")
    def test_zeros_512_and_1024_mib(self):
        chunk = bytes(MIB)
        hasher = SM3()
        for _ in range(512):
            hasher.update(chunk)
        digest = sm3_module._finish_digest(hasher._state, b"", hasher._length)
        self.assertEqual(digest.hex(), V_SM3["zeros_512_mib"])
        for _ in range(512):
            hasher.update(chunk)
        self.assertEqual(hasher.finish().hash_bytes().hex(), V_SM3["zeros_1024_mib"])


class PointValidation(unittest.TestCase):
    def test_hex_helpers_are_canonical(self):
        for bad in ("0x00", "0X00", "00 ", " 00", "0_0", "+0", "٣٣"):
            with self.assertRaises(ValueError):
                hexutil.hex_to_bytes(bad)
            with self.assertRaises(ValueError):
                hexutil.hex_to_int(bad)

    def test_coordinates_must_be_integers(self):
        for bad in (("1", 1), (1, None), (1.0, 1), (True, 1)):
            with self.assertRaises(TypeError):
                ECPoint(*bad)

    def test_coordinates_must_be_in_the_field(self):
        for bad in ((SM2_P, 1), (1, SM2_P), (-1, 1), (2**256, 1)):
            with self.assertRaises(ValueError):
                ECPoint(*bad)

    def test_decoding_rejects_prefixed_hex(self):
        with self.assertRaises(ValueError):
            sm2_decode_point("0x" + PUBLIC[2:])

    def test_infinity_is_never_a_public_key(self):
        infinity = ECPoint.at_infinity()
        self.assertFalse(infinity._is_valid_public())
        with self.assertRaises(ValueError):
            user_sm3_z(b"id", infinity)

    def test_unpickled_point_cannot_bypass_validation(self):
        point = sm2_decode_point(PUBLIC)
        forged = pickle.loads(pickle.dumps(point))
        object.__setattr__(forged, "x", point.x + SM2_P)
        self.assertFalse(forged._is_valid_public())
        with self.assertRaises(ValueError):
            forged.multiply(5)
        result = sm2_get_sb(16, forged, point, point, 2, point, 3, "a", "b")
        self.assertFalse(result.success)


class KeyExchangeValidation(unittest.TestCase):
    def setUp(self):
        self.d_a, self.d_b, self.r_a, self.r_b = 11111, 22222, 33333, 44444
        self.p_a = sm2_get_public_key(self.d_a)
        self.p_b = sm2_get_public_key(self.d_b)
        self.big_ra = sm2_get_public_key(self.r_a)
        self.big_rb = sm2_get_public_key(self.r_b)

    def get_sb(self, **overrides):
        args = {
            "byte_len": 16,
            "p_a": self.p_a,
            "r_a": self.big_ra,
            "p_b": self.p_b,
            "d_b": self.d_b,
            "r_b": self.big_rb,
            "rb": self.r_b,
            "id_a": "A",
            "id_b": "B",
        }
        args.update(overrides)
        return sm2_get_sb(**args)

    def get_sa(self, sb=DEFAULT_SB, **overrides):
        args = {
            "byte_len": 16,
            "p_b": self.p_b,
            "r_b": self.big_rb,
            "p_a": self.p_a,
            "d_a": self.d_a,
            "r_a": self.big_ra,
            "ra": self.r_a,
            "id_a": "A",
            "id_b": "B",
            "sb": bytes.fromhex(self.get_sb().sb) if sb is DEFAULT_SB else sb,
        }
        args.update(overrides)
        return sm2_get_sa(**args)

    def test_valid_exchange(self):
        side_b = self.get_sb()
        side_a = self.get_sa()
        self.assertTrue(side_a.success and side_b.success)
        self.assertEqual(side_a.ka, side_b.kb)

    def test_every_bad_key_length_raises(self):
        for bad in (0, -1, 2**20 + 1, 2**64, 1.5, "16", None, True):
            with self.assertRaises(ValueError):
                self.get_sb(byte_len=bad)
            with self.assertRaises(ValueError):
                self.get_sa(sb=bytes(32), byte_len=bad)

    def test_largest_key_length(self):
        self.assertEqual(len(self.get_sb(byte_len=2**20).kb), 2**21)

    def test_every_bad_point_fails(self):
        bad_points = (ECPoint(1, 1), ECPoint.at_infinity(), None, "04", 5)
        for bad in bad_points:
            for name in ("p_a", "r_a", "p_b", "r_b"):
                self.assertFalse(self.get_sb(**{name: bad}).success, name)
                self.assertFalse(self.get_sa(sb=bytes(32), **{name: bad}).success, name)

    def test_every_bad_private_key_fails(self):
        for bad in (0, -1, SM2_N - 1, SM2_N, SM2_N + 1, True, None, 1.0, "5"):
            self.assertFalse(self.get_sb(d_b=bad).success)
            self.assertFalse(self.get_sb(rb=bad).success)
            self.assertFalse(self.get_sa(sb=bytes(32), d_a=bad).success)
            self.assertFalse(self.get_sa(sb=bytes(32), ra=bad).success)

    def test_bad_user_ids_fail(self):
        for bad in ("a" * 8192, "\ud800", None, b"A", 5):
            for name in ("id_a", "id_b"):
                self.assertFalse(self.get_sb(**{name: bad}).success)
                self.assertFalse(self.get_sa(sb=bytes(32), **{name: bad}).success)

    def test_short_or_wrongly_typed_confirmation_values_fail(self):
        good = bytes.fromhex(self.get_sb().sb)
        for bad in (b"", good[:31], good + b"\x00", "ab", None, 5, good.hex()):
            self.assertFalse(self.get_sa(sb=bad).success, repr(bad))
        side_b = self.get_sb()
        sa = bytes.fromhex(self.get_sa().sa)
        check = (side_b.v, side_b.za, side_b.zb, self.big_ra, self.big_rb)
        self.assertTrue(sm2_check_sa(*check, sa))
        for bad in (b"", sa[:31], sa + b"\x00", "ab", None, 5, sa.hex()):
            self.assertIs(sm2_check_sa(*check, bad), False, repr(bad))
        v, za, zb, big_ra, big_rb = check
        self.assertIs(sm2_check_sa(None, za, zb, big_ra, big_rb, sa), False)
        self.assertIs(sm2_check_sa(v, b"", zb, big_ra, big_rb, sa), False)
        self.assertIs(sm2_check_sa(v, za, None, big_ra, big_rb, sa), False)
        self.assertIs(
            sm2_check_sa(ECPoint.at_infinity(), za, zb, big_ra, big_rb, sa), False
        )

    def test_coordinates_with_leading_zeros_stay_32_bytes(self):
        # Find points with a small top byte in x or y, the padding bug of other ports.
        found = 0
        for scalar in range(2, 3000):
            point = sm2_get_public_key(scalar)
            if point.x >> 248 == 0 or point.y >> 248 == 0:
                found += 1
                self.assertEqual(len(point.to_encoded()), 65)
                self.assertEqual(len(point.x_bytes()), 32)
                self.assertEqual(len(point.y_bytes()), 32)
                side_b = self.get_sb(p_a=point)
                self.assertTrue(side_b.success)
                self.assertEqual(len(side_b.sb), 64)
        self.assertGreater(found, 0)

    def test_many_exchanges_agree(self):
        for scalar in range(1, 60):
            r_a = 100000 + scalar
            big_ra = sm2_get_public_key(r_a)
            side_b = self.get_sb(r_a=big_ra)
            side_a = self.get_sa(sb=bytes.fromhex(side_b.sb), r_a=big_ra, ra=r_a)
            self.assertTrue(side_a.success, scalar)
            self.assertEqual(side_a.ka, side_b.kb)


class BoundedRetries(unittest.TestCase):
    def test_key_generation(self):
        with (
            mock.patch("smx.sm2._random_scalar", return_value=SM2_N - 1),
            self.assertRaises(ValueError),
        ):
            sm2_gen_key_pair()

    def test_encrypt_with_all_zero_kdf(self):
        with (
            mock.patch("smx.sm2._kdf", return_value=bytes(1)) as kdf,
            self.assertRaises(ValueError),
        ):
            sm2_encrypt("x", PUBLIC)
        self.assertEqual(kdf.call_count, sm2_module._MAX_RETRIES)

    def test_sign_when_every_nonce_is_rejected(self):
        d = int(PRIVATE, 16)
        with (
            mock.patch.object(sm2_module._ec, "invert_blinded", return_value=0),
            self.assertRaises(ValueError),
        ):
            sm2_sign("id", "m", f"{d:064x}")

    def test_decrypt_with_all_zero_kdf(self):
        with (
            mock.patch("smx.sm2._kdf", return_value=bytes(19)),
            self.assertRaises(ValueError) as caught,
        ):
            sm2_decrypt(V_SM2["ciphertext"], PRIVATE)
        self.assertEqual(str(caught.exception), "decryption failed")

    def test_kdf_length_bound(self):
        with self.assertRaises(ValueError):
            sm2_module._kdf((2**32 - 1) * 32 + 1, (b"seed",))

    def test_rng_failure_is_a_clean_error(self):
        with (
            mock.patch("secrets.randbelow", side_effect=OSError("no entropy")),
            self.assertRaises(OSError),
        ):
            sm2_gen_key_pair()
            with self.assertRaises(OSError):
                sm2_encrypt("x", PUBLIC)
            with self.assertRaises(OSError):
                sm2_sign("id", "m", PRIVATE)


class KeyCaches(unittest.TestCase):
    def setUp(self):
        self.addCleanup(set_key_cache_enabled, True)
        clear_key_caches()

    def fill(self):
        signature = sm2_sign("id", "m", PRIVATE)
        self.assertTrue(sm2_verify("id", signature, "m", PUBLIC))
        sm2_encrypt("x", PUBLIC)

    def sizes(self):
        return (
            sm2_module._cached_z.cache_info().currsize,
            len(sm2_module._public_key_cache),
            _ec._remembered_key_tables.cache_info().currsize,
        )

    def test_on_by_default_and_filled_by_use(self):
        self.assertTrue(_ec.key_cache_enabled)
        self.fill()
        self.assertTrue(all(self.sizes()))

    def test_clear_empties_everything(self):
        self.fill()
        clear_key_caches()
        self.assertEqual(self.sizes(), (0, 0, 0))
        self.assertTrue(_ec.key_cache_enabled)

    def test_disabling_drops_cached_values_and_stays_empty(self):
        self.fill()
        set_key_cache_enabled(False)
        self.assertEqual(self.sizes(), (0, 0, 0))
        self.fill()
        self.assertEqual(self.sizes(), (0, 0, 0))
        set_key_cache_enabled(True)
        self.fill()
        self.assertTrue(all(self.sizes()))

    def test_results_are_the_same_either_way(self):
        k = int(V_SM2["nonce_k"], 16)
        outputs = []
        for enabled in (True, False):
            set_key_cache_enabled(enabled)
            with mock.patch("smx.sm2._random_scalar", return_value=k):
                outputs.append((sm2_sign("id", "m", PRIVATE), sm2_encrypt("x", PUBLIC)))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[0][0][64], "h")

    def test_private_key_is_not_in_the_cache(self):
        self.fill()
        d = int(PRIVATE, 16)
        raw = d.to_bytes(32, "big")
        for key, value in sm2_module._public_key_cache.items():
            self.assertNotEqual(key, raw)
            self.assertNotEqual(value.x, d)

    def test_only_a_bool_is_accepted(self):
        for bad in ("false", 0, 1, None):
            with self.assertRaises(TypeError):
                set_key_cache_enabled(bad)

    def test_exported(self):
        for name in ("set_key_cache_enabled", "clear_key_caches"):
            self.assertIn(name, smx.__all__)

    def run_python(self, value):
        code = (
            "import smx, smx._ec as e, smx.sm2 as s\n"
            "pub = smx.sm2_get_public_key(5).to_hex_encoded()\n"
            "sig = smx.sm2_sign('i', 'm', '%064x' % 5)\n"
            "assert smx.sm2_verify('i', sig, 'm', pub)\n"
            "print(e.key_cache_enabled, s._cached_z.cache_info().currsize,"
            " len(s._public_key_cache), e._remembered_key_tables.cache_info().currsize)"
        )
        env = {k: v for k, v in os.environ.items() if k != "SMX_DISABLE_KEY_CACHE"}
        if value is not None:
            env["SMX_DISABLE_KEY_CACHE"] = value
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.split()

    def test_environment_variable(self):
        self.assertEqual(self.run_python("1"), ["False", "0", "0", "0"])
        self.assertEqual(self.run_python("true"), ["False", "0", "0", "0"])
        self.assertEqual(self.run_python(None)[0], "True")
        self.assertEqual(self.run_python("0")[0], "True")

    def test_concurrent_use_while_toggling(self):
        errors = []
        signature = sm2_sign("id", "m", PRIVATE)
        stop = threading.Event()

        def worker():
            try:
                while not stop.is_set():
                    if not sm2_verify("id", signature, "m", PUBLIC):
                        errors.append("verify failed")
                    if sm2_sign("id", "m", PRIVATE)[64] != "h":
                        errors.append("sign failed")
            except Exception as error:  # noqa: BLE001 - reported by the assertion below
                errors.append(repr(error))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for _ in range(200):
            set_key_cache_enabled(False)
            set_key_cache_enabled(True)
        stop.set()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        set_key_cache_enabled(False)
        self.assertEqual(self.sizes(), (0, 0, 0))


class SecretHygiene(unittest.TestCase):
    def test_exchange_result_repr_hides_secrets(self):
        d, r = 12345, 67890
        p, big_r = sm2_get_public_key(d), sm2_get_public_key(r)
        result = sm2_get_sb(16, p, big_r, p, d, big_r, r, "a", "b")
        text = repr(result)
        self.assertNotIn(result.kb, text)
        self.assertNotIn(f"{result.v.x}", text)

    def test_errors_do_not_quote_input(self):
        for call in (
            lambda: sm2_sign("id", "m", "z" * 64),
            lambda: sm2_decrypt(V_SM2["ciphertext"], "z" * 64),
        ):
            with self.assertRaises(ValueError) as caught:
                call()
            self.assertNotIn("zz", str(caught.exception))

    def test_sm2_invalid_utf8_message_does_not_expose_plaintext(self):
        hidden = "\xff"
        with (
            mock.patch("smx.sm2._kdf", return_value=b"\x01"),
            mock.patch("smx.sm2._sm3", return_value=bytes(32)),
        ):
            c3 = bytes(32).hex()
            ciphertext = V_SM2["ciphertext"][:130] + c3 + "fe"
            with self.assertRaises(ValueError) as caught:
                sm2_decrypt(ciphertext, PRIVATE)
        self.assertEqual(str(caught.exception), "decryption failed")
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(hidden, str(caught.exception))

    def test_text_that_cannot_be_encoded_is_not_quoted(self):
        for call in (
            lambda: make_sm4().encrypt("secret\ud800"),
            lambda: sm2_encrypt("secret\ud800", PUBLIC),
        ):
            with self.assertRaises(ValueError) as caught:
                call()
            self.assertNotIsInstance(caught.exception, UnicodeError)
            self.assertIsNone(caught.exception.__context__)


class Pkcs7(unittest.TestCase):
    def test_pad_then_unpad(self):
        for size in range(40):
            data = bytes(range(size))
            self.assertEqual(pkcs7_unpad(pkcs7_pad(data)), data)
            self.assertEqual(len(pkcs7_pad(data)) % 16, 0)

    def test_bad_lengths(self):
        for size in (1, 15, 17, 31):
            with self.assertRaises(ValueError):
                pkcs7_unpad(bytes([1]) * size)


if __name__ == "__main__":
    unittest.main()
