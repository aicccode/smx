"""Known-answer tests: published vectors plus outputs pinned from the baseline."""

import hashlib
import unittest
from unittest import mock

import pytest

from smx import (
    SM3,
    SM4,
    ECPoint,
    sm2_decrypt,
    sm2_encrypt,
    sm2_get_public_key,
    sm2_get_sa,
    sm2_get_sb,
    sm2_sign,
    sm2_verify,
)

from .kat_vectors import (
    ENCRYPT_KAT,
    EXCHANGE_KAT,
    MULT_KAT,
    MULT_P_KAT,
    SIGN_KAT,
    SM3_KAT,
    SM4_CBC_KAT,
)

PRIVATE = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
PUBLIC_POINT = sm2_get_public_key(int(PRIVATE, 16))
PUBLIC = PUBLIC_POINT.to_hex_encoded()


def det(length: int, label: bytes = b"kat") -> bytes:
    """Deterministic test bytes, the same function that produced the vectors."""
    output = b""
    counter = 0
    while len(output) < length:
        output += hashlib.sha256(label + counter.to_bytes(4, "big")).digest()
        counter += 1
    return output[:length]


def sm3_hex(data: bytes) -> str:
    return SM3().update(data).finish().hash_bytes().hex()


class SM3KnownAnswers(unittest.TestCase):
    def test_gb_t_32905_vectors(self):
        self.assertEqual(
            sm3_hex(b"abc"),
            "66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0".replace(
                " ", ""
            ),
        )
        self.assertEqual(
            sm3_hex(b"abcd" * 16),
            "debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732".replace(
                " ", ""
            ),
        )

    def test_pinned_digests(self):
        for length, expected in SM3_KAT.items():
            self.assertEqual(sm3_hex(det(length)), expected, length)

    def test_any_chunking_gives_the_same_digest(self):
        data = det(1000)
        expected = SM3_KAT[1000]
        for chunk in (1, 3, 7, 13, 63, 64, 65, 127, 128, 129, 500):
            hasher = SM3()
            for offset in range(0, len(data), chunk):
                hasher.update(data[offset : offset + chunk])
            self.assertEqual(hasher.finish().hash_bytes().hex(), expected, chunk)

    def test_accepts_every_bytes_like_type(self):
        data = det(200)
        expected = sm3_hex(data)
        for value in (bytearray(data), memoryview(data)):
            self.assertEqual(sm3_hex(value), expected)

    def test_rejects_text(self):
        with self.assertRaises(TypeError):
            SM3().update("abc")

    def test_update_byte_matches_update(self):
        for length in (0, 1, 63, 64, 65, 130):
            hasher = SM3()
            data = det(length)
            for value in data[: length // 2]:
                hasher.update_byte(value)
            hasher.update(data[length // 2 :])
            self.assertEqual(hasher.finish().hash_bytes().hex(), sm3_hex(data), length)

    def test_rejected_byte_does_not_change_the_state(self):
        hasher = SM3().update(b"ab")
        with self.assertRaises(ValueError):
            hasher.update_byte(256)
        with self.assertRaises(ValueError):
            hasher.update_byte(-1)
        self.assertEqual(
            hasher.update(b"c").finish().hash_bytes().hex(), sm3_hex(b"abc")
        )

    def test_matches_openssl_when_available(self):
        if "sm3" not in hashlib.algorithms_available:
            self.skipTest("this OpenSSL build has no SM3")
        for length in (0, 1, 55, 56, 64, 1000, 10000):
            data = det(length, b"openssl")
            self.assertEqual(sm3_hex(data), hashlib.new("sm3", data).hexdigest())


class SM4KnownAnswers(unittest.TestCase):
    KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")

    def make(self, key: bytes = KEY, iv: bytes = bytes(16)) -> SM4:
        cipher = SM4()
        cipher.set_key(key, iv)
        return cipher

    def test_gb_t_32907_single_block(self):
        cipher = self.make()
        block = cipher.encrypt_block(self.KEY)
        self.assertEqual(block.hex(), "681edf34d206965e86b3e94f536e4246")
        self.assertEqual(cipher.decrypt_block(block), self.KEY)

    @pytest.mark.slow
    def test_gb_t_32907_one_million_iterations(self):
        cipher = self.make()
        block = self.KEY
        for _ in range(1_000_000):
            block = cipher.encrypt_block(block)
        self.assertEqual(block.hex(), "595298c7c6fd271f0402f804c33d3f66")
        for _ in range(1_000_000):
            block = cipher.decrypt_block(block)
        self.assertEqual(block, self.KEY)

    def test_pinned_cbc_ciphertexts(self):
        cipher = self.make(det(16, b"k"), det(16, b"iv"))
        for length, expected in SM4_CBC_KAT.items():
            plaintext = det(length, b"p").hex()[:length]
            ciphertext = cipher.encrypt(plaintext)
            self.assertEqual(
                hashlib.sha256(ciphertext.encode()).hexdigest(), expected, length
            )
            self.assertEqual(cipher.decrypt(ciphertext), plaintext)

    def test_block_operations_accept_bytes_like_input(self):
        cipher = self.make()
        expected = cipher.encrypt_block(self.KEY)
        for value in (bytearray(self.KEY), memoryview(self.KEY)):
            self.assertEqual(cipher.encrypt_block(value), expected)
            self.assertEqual(type(cipher.encrypt_block(value)), bytes)
            self.assertEqual(
                cipher.decrypt_block(cipher.encrypt_block(value)), self.KEY
            )


class SM2KnownAnswers(unittest.TestCase):
    def test_generator_multiples(self):
        generator = ECPoint.generator()
        for scalar, expected in MULT_KAT.items():
            self.assertEqual(generator.multiply(scalar).to_hex_encoded(), expected)

    def test_variable_base_multiples(self):
        for scalar, expected in MULT_P_KAT.items():
            self.assertEqual(PUBLIC_POINT.multiply(scalar).to_hex_encoded(), expected)

    def test_encrypt_with_fixed_k(self):
        for k, message, expected in ENCRYPT_KAT:
            with mock.patch("smx.sm2._random_scalar", return_value=k):
                ciphertext = sm2_encrypt(message, PUBLIC)
            if expected.startswith("sha256:"):
                digest = hashlib.sha256(ciphertext.encode()).hexdigest()
                self.assertEqual("sha256:" + digest, expected)
            else:
                self.assertEqual(ciphertext, expected)
            self.assertEqual(sm2_decrypt(ciphertext, PRIVATE), message)

    def test_sign_with_fixed_k(self):
        for k, user_id, message, expected in SIGN_KAT:
            with mock.patch("smx.sm2._random_scalar", return_value=k):
                self.assertEqual(sm2_sign(user_id, message, PRIVATE), expected)
            self.assertTrue(sm2_verify(user_id, expected, message, PUBLIC))

    def test_key_exchange(self):
        generator = ECPoint.generator()
        for length, d_a, r_a, d_b, r_b, ka, sa, sb, v in EXCHANGE_KAT:
            p_a, big_ra = generator.multiply(d_a), generator.multiply(r_a)
            p_b, big_rb = generator.multiply(d_b), generator.multiply(r_b)
            side_b = sm2_get_sb(length, p_a, big_ra, p_b, d_b, big_rb, r_b, "A", "B")
            side_a = sm2_get_sa(
                length, p_b, big_rb, p_a, d_a, big_ra, r_a, "A", "B", bytes.fromhex(sb)
            )
            self.assertTrue(side_b.success)
            self.assertTrue(side_a.success)
            self.assertEqual(side_a.ka, ka)
            self.assertEqual(side_b.kb, ka)
            self.assertEqual(side_a.sa, sa)
            self.assertEqual(side_b.sb, sb)
            self.assertEqual(side_b.v.to_hex_encoded(), v)


if __name__ == "__main__":
    unittest.main()
