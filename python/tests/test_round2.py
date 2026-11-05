"""Findings of the independent review: canonical hex, stateful traps, API contracts."""

from __future__ import annotations

import gc
import pickle
import random
import re
import sys
import unittest
from unittest import mock

from smx import (
    SM3,
    SM4,
    ECPoint,
    bytes_to_hex,
    hex_to_bytes,
    hexutil,
    sm2,
    sm2_check_sa,
    sm2_decode_point,
    sm2_decrypt,
    sm2_encrypt,
    sm2_get_public_key,
    sm2_get_sa,
    sm2_get_sb,
    sm2_sign,
    sm2_verify,
)
from smx import sm4 as sm4_module

RNG = random.Random(0x726432)
PRIVATE = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
PUBLIC = sm2_get_public_key(int(PRIVATE, 16)).to_hex_encoded()
HEX_RE = re.compile(r"[0-9a-fA-F]*")
LOWER_RE = re.compile(r"[0-9a-f]*")


def make_sm4() -> SM4:
    cipher = SM4()
    cipher.set_key(b"0123456789abcdef", bytes(16))
    return cipher


def cbc_encrypt_raw(cipher: SM4, data: bytes) -> str:
    """Encrypt without padding, to forge any decrypted content."""
    previous = bytes(16)
    output = b""
    for offset in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[offset : offset + 16], previous))
        previous = cipher.encrypt_block(block)
        output += previous
    return output.hex()


class CanonicalHex(unittest.TestCase):
    def test_signature_accepts_only_lowercase(self):
        signature = sm2_sign("id", "m", PRIVATE)
        self.assertTrue(sm2_verify("id", signature, "m", PUBLIC))
        r, s = signature.split("h")
        self.assertRegex(r + s, "[a-f]")
        for variant in (
            signature.upper(),
            r.upper() + "h" + s,
            r + "h" + s.upper(),
            r + "H" + s,
        ):
            self.assertIs(sm2_verify("id", variant, "m", PUBLIC), False, variant)

    def test_sm2_ciphertext_accepts_only_lowercase(self):
        ciphertext = sm2_encrypt("hello", PUBLIC)
        self.assertEqual(sm2_decrypt(ciphertext, PRIVATE), "hello")
        self.assertRegex(ciphertext, "^[0-9a-f]+$")
        for part in ((0, 130), (130, 194), (194, len(ciphertext))):
            start, end = part
            variant = (
                ciphertext[:start] + ciphertext[start:end].upper() + ciphertext[end:]
            )
            if variant != ciphertext:
                with self.assertRaises(ValueError):
                    sm2_decrypt(variant, PRIVATE)

    def test_sm4_ciphertext_accepts_only_lowercase(self):
        cipher = make_sm4()
        ciphertext = cipher.encrypt("hello there, some text")
        self.assertRegex(ciphertext, "[a-f]")
        with self.assertRaises(ValueError):
            cipher.decrypt(ciphertext.upper())
        with self.assertRaises(ValueError):
            cipher.decrypt_bytes(ciphertext.upper())

    def test_keys_stay_case_insensitive(self):
        signature = sm2_sign("id", "m", PRIVATE.lower())
        self.assertTrue(
            sm2_verify("id", signature, "m", PUBLIC.upper().replace("X", "x"))
        )
        ciphertext = sm2_encrypt("hello", PUBLIC.upper())
        self.assertEqual(sm2_decrypt(ciphertext, PRIVATE.lower()), "hello")
        self.assertEqual(sm2_decrypt(ciphertext, PRIVATE), "hello")


class HexConversions(unittest.TestCase):
    def test_encoding_matches_python(self):
        for size in list(range(40)) + [255, 4096]:
            data = bytes(RNG.getrandbits(8) for _ in range(size))
            self.assertEqual(bytes_to_hex(data), data.hex())
            self.assertEqual(hexutil.bytes_to_hex_upper(data), data.hex().upper())
        every = bytes(range(256))
        self.assertEqual(bytes_to_hex(every), every.hex())
        self.assertEqual(hexutil.bytes_to_hex_upper(every), every.hex().upper())

    def test_decoding_matches_python(self):
        for size in list(range(40)) + [255, 4096]:
            data = bytes(RNG.getrandbits(8) for _ in range(size))
            for text in (data.hex(), data.hex().upper()):
                self.assertEqual(hex_to_bytes(text), data)
            self.assertEqual(hexutil.lowercase_hex_to_bytes(data.hex()), data)
        every = bytes(range(256))
        self.assertEqual(hex_to_bytes(every.hex()), every)

    def test_every_character_is_classified_like_a_regex(self):
        # At the start, in the middle and at the end, so carries would show.
        for code in list(range(0x180)) + [0x660, 0xFF10, 0x10000]:
            char = chr(code)
            for text in (char + "a", "a" + char, "aaaa" + char + "a", "a" * 15 + char):
                accepts = bool(HEX_RE.fullmatch(text))
                accepts_lower = bool(LOWER_RE.fullmatch(text))
                for function, expected in (
                    (hex_to_bytes, accepts),
                    (hexutil.lowercase_hex_to_bytes, accepts_lower),
                ):
                    if expected:
                        self.assertEqual(function(text), bytes.fromhex(text))
                    else:
                        with self.assertRaises(ValueError, msg=repr(text)):
                            function(text)

    def test_integers(self):
        for text, value in (
            ("0", 0),
            ("f", 15),
            ("F", 15),
            ("100", 256),
            ("0" * 70, 0),
        ):
            self.assertEqual(hexutil.hex_to_int(text), value)
        self.assertEqual(hexutil.lowercase_hex_to_int("ff"), 255)
        for function in (hexutil.hex_to_int, hexutil.lowercase_hex_to_int):
            with self.assertRaises(ValueError):
                function("")
            with self.assertRaises(TypeError):
                function(None)
        with self.assertRaises(ValueError):
            hexutil.lowercase_hex_to_int("FF")

    def test_long_values_are_not_limited_by_int_conversion_rules(self):
        self.assertEqual(hexutil.hex_to_int("f" * 10000), 16**10000 - 1)

    def test_generated_private_key_format_is_uppercase_hex(self):
        private, _ = sm2.sm2_gen_key_pair()
        self.assertRegex(private, "^[0-9A-F]{64}$")


class PaddingOracle(unittest.TestCase):
    def forged(self, tail: bytes, blocks: int = 3) -> str:
        return cbc_encrypt_raw(make_sm4(), b"A" * (16 * (blocks - 1)) + tail)

    def test_utf8_validation_covers_the_same_bytes_with_any_padding(self):
        cipher = make_sm4()
        cases = {
            "good": b"B" * 15 + b"\x01",
            "zero": b"B" * 15 + b"\x00",
            "large": b"B" * 15 + b"\x11",
            "inconsistent": b"B" * 14 + b"\x03\x02",
        }
        for name, tail in cases.items():
            real = sm4_module._decode_utf8
            with mock.patch.object(sm4_module, "_decode_utf8", wraps=real) as check:
                try:
                    cipher.decrypt(self.forged(tail))
                except ValueError:
                    self.assertNotEqual(name, "good")
            self.assertEqual(check.call_count, 1, name)
            self.assertEqual(len(check.call_args[0][0]), 48, name)

    def test_padding_failure_and_utf8_failure_are_one_error(self):
        cipher = make_sm4()
        messages = set()
        for tail in (
            b"B" * 15 + b"\x00",
            b"\xff" * 15 + b"\x01",
            b"\xff" * 15 + b"\x00",
        ):
            with self.assertRaises(ValueError) as caught:
                cipher.decrypt(self.forged(tail))
            messages.add(str(caught.exception))
            self.assertIsNone(caught.exception.__context__)
        self.assertEqual(messages, {"decryption failed"})

    def test_padding_does_not_change_the_text_result(self):
        cipher = make_sm4()
        for text in ("", "a", "é", "密" * 5, "x" * 15, "x" * 16, "😀" * 8, "\x01\x02"):
            self.assertEqual(cipher.decrypt(cipher.encrypt(text)), text)

    def test_text_ending_inside_a_character_is_rejected(self):
        cipher = make_sm4()
        with self.assertRaises(ValueError):
            cipher.decrypt(self.forged(b"B" * 13 + b"\xe5\x01\x01"[:1] + b"\x02\x02"))

    def test_decrypt_bytes_returns_binary_plaintext(self):
        cipher = make_sm4()
        data = b"\xff\xfe\x00binary" + bytes(3)
        padded = sm4_module.pkcs7_pad(data)
        ciphertext = cbc_encrypt_raw(cipher, padded)
        self.assertEqual(cipher.decrypt_bytes(ciphertext), data)
        with self.assertRaises(ValueError):
            cipher.decrypt(ciphertext)
        for bad in ("", "00", "zz" * 16, cbc_encrypt_raw(cipher, bytes(16))):
            with self.assertRaises(ValueError) as caught:
                cipher.decrypt_bytes(bad)
            self.assertEqual(str(caught.exception), "decryption failed")

    def test_round_key_multiplication_is_unchanged(self):
        masks = sm4_module._lane_masks(5)
        repeat = masks[0]
        for key in (0, 1, 2**30 - 1, 2**30, 2**32 - 1, 0x12345678):
            uniform = (key + sm4_module._ROUND_KEY_OFFSET) * repeat - (repeat << 32)
            self.assertEqual(uniform, key * repeat)


class StatefulObjects(unittest.TestCase):
    def test_reading_before_finish_fails(self):
        for hasher in (SM3(), SM3().update(b"abc")):
            with self.assertRaises(ValueError):
                hasher.hash_bytes()
            with self.assertRaises(ValueError):
                hasher.hash_hex_upper()

    def test_update_after_finish_invalidates_the_old_digest(self):
        hasher = SM3().update(b"first").finish()
        self.assertEqual(len(hasher.hash_bytes()), 32)
        hasher.update(b"second")
        with self.assertRaises(ValueError):
            hasher.hash_bytes()
        hasher = SM3().update(b"first").finish().update_byte(1)
        with self.assertRaises(ValueError):
            hasher.hash_hex_upper()

    def test_finish_twice_fails_and_keeps_the_digest(self):
        hasher = SM3().update(b"abc").finish()
        digest = hasher.hash_bytes()
        with self.assertRaises(ValueError):
            hasher.finish()
        self.assertEqual(hasher.hash_bytes(), digest)

    def test_reuse_for_a_new_message_is_correct(self):
        hasher = SM3().update(b"first").finish()
        expected = SM3().update(b"abc").finish().hash_bytes()
        self.assertEqual(hasher.update(b"abc").finish().hash_bytes(), expected)
        empty = SM3().finish().hash_bytes()
        self.assertEqual(hasher.update(b"").finish().hash_bytes(), empty)

    def test_sm4_cannot_be_pickled_or_copied(self):
        import copy

        cipher = make_sm4()
        for action in (pickle.dumps, copy.copy, copy.deepcopy):
            with self.assertRaises(TypeError):
                action(cipher)


class ApiContracts(unittest.TestCase):
    def setUp(self):
        self.released = memoryview(bytes(32))
        self.released.release()
        self.blank = ECPoint.__new__(ECPoint)
        self.point = sm2_get_public_key(5)

    def test_blank_point_reports_cleanly(self):
        self.assertIs(self.blank.is_on_curve(), False)
        with self.assertRaises(ValueError):
            self.blank.to_encoded()
        with self.assertRaises(ValueError):
            self.blank.multiply(2)
        with self.assertRaises(ValueError):
            self.point.add(self.blank)

    def test_check_sa_always_returns_a_bool(self):
        p, good = self.point, bytes(32)
        for arguments in (
            (self.blank, good, good, p, p, good),
            (p, good, good, self.blank, p, good),
            (p, good, good, p, self.blank, good),
            (p, self.released, good, p, p, good),
            (p, good, self.released, p, p, good),
            (p, good, good, p, p, self.released),
        ):
            self.assertIs(sm2_check_sa(*arguments), False)

    def test_key_exchange_reports_blank_points_and_released_views(self):
        p = self.point
        self.assertFalse(sm2_get_sb(16, self.blank, p, p, 5, p, 5, "a", "b").success)
        self.assertFalse(
            sm2_get_sa(16, self.blank, p, p, 5, p, 5, "a", "b", bytes(32)).success
        )
        self.assertFalse(
            sm2_get_sa(16, p, p, p, 5, p, 5, "a", "b", self.released).success
        )

    def test_oversized_signature_is_refused_before_any_split(self):
        huge = "h" * (64 * 1024 * 1024)
        before = sys.getallocatedblocks()
        self.assertIs(sm2_verify("id", huge, "m", PUBLIC), False)
        self.assertLess(sys.getallocatedblocks() - before, 1000)

    def test_user_z_with_released_view(self):
        with self.assertRaises(ValueError):
            sm2.user_sm3_z(self.released, self.point)


def frames_of(error: BaseException):
    trace = error.__traceback__
    while trace is not None:
        yield trace.tb_frame
        trace = trace.tb_next


class TracebackRetention(unittest.TestCase):
    def assert_frames_are_clean(self, error, secrets):
        gc.collect()
        for frame in frames_of(error):
            for name, value in frame.f_locals.items():
                if frame.f_code.co_filename == __file__:
                    continue
                for secret in secrets:
                    self.assertFalse(
                        value is secret or value == secret,
                        f"{frame.f_code.co_name} keeps {name}",
                    )

    def test_sm2_decrypt_failure_keeps_no_secret_in_library_frames(self):
        d = int(PRIVATE, 16)
        ciphertext = sm2_encrypt("topsecret", PUBLIC)
        tampered = ciphertext[:-1] + ("0" if ciphertext[-1] != "0" else "1")
        with self.assertRaises(ValueError) as caught:
            sm2_decrypt(tampered, PRIVATE)
        self.assert_frames_are_clean(caught.exception, (d, PRIVATE))
        names = {
            name
            for frame in frames_of(caught.exception)
            if frame.f_code.co_filename != __file__
            for name in frame.f_locals
        }
        self.assertFalse(names & {"message", "key", "p2", "d", "private_key"}, names)

    def test_sm4_decrypt_failure_keeps_no_plaintext_in_library_frames(self):
        cipher = make_sm4()
        forged = cbc_encrypt_raw(cipher, b"TOPSECRETTOPSEC\x00")
        with self.assertRaises(ValueError) as caught:
            cipher.decrypt(forged)
        names = {
            name
            for frame in frames_of(caught.exception)
            if frame.f_code.co_filename != __file__
            for name in frame.f_locals
        }
        self.assertFalse(names & {"plain", "text", "decrypted", "keys"}, names)

    def test_sign_failure_keeps_no_key_in_library_frames(self):
        with self.assertRaises(ValueError) as caught:
            sm2_sign("a" * 8192, "m", PRIVATE)
        self.assert_frames_are_clean(caught.exception, (PRIVATE, int(PRIVATE, 16)))


class Interop(unittest.TestCase):
    def test_decode_point_upper_and_lower_are_the_same_point(self):
        self.assertEqual(sm2_decode_point(PUBLIC), sm2_decode_point(PUBLIC.upper()))


if __name__ == "__main__":
    unittest.main()
