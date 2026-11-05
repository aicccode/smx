import unittest

from smx import SM4
from smx.sm4 import pkcs7_pad, pkcs7_unpad


def make_cipher(key: bytes, iv: bytes) -> SM4:
    sm4 = SM4()
    sm4.set_key(key, iv)
    return sm4


class SM4Test(unittest.TestCase):
    def test_hashed_key_vector_shared_by_all_languages(self):
        # Keys and IVs that are not 16 bytes go through SM3 (uppercase hex prefix).
        sm4 = make_cipher(b"this is the key", b"this is the iv")
        plaintext = "国密SM4对称加密算法"
        ciphertext = sm4.encrypt(plaintext)
        self.assertEqual(
            ciphertext,
            "09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc",
        )
        self.assertEqual(sm4.decrypt(ciphertext), plaintext)

    def test_raw_16_byte_key_vector_generated_by_go(self):
        sm4 = make_cipher(b"0123456789abcdef", bytes(16))
        ciphertext = sm4.encrypt("Hello from Go Client!")
        self.assertEqual(
            ciphertext,
            "91ea70533805dcf27e8c42bbd0b27cda20be69aae26e297643247ba61f083719",
        )

    def test_standard_single_block_vector(self):
        # GB/T 32907-2016 Appendix A, example 1.
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        sm4 = make_cipher(key, bytes(16))
        block = sm4.encrypt_block(key)
        self.assertEqual(block.hex(), "681edf34d206965e86b3e94f536e4246")
        self.assertEqual(sm4.decrypt_block(block), key)

    def test_round_trip_at_block_boundaries(self):
        sm4 = make_cipher(b"0123456789abcdef", b"fedcba9876543210")
        for length in (0, 1, 15, 16, 17, 32, 100):
            message = "x" * length
            ciphertext = sm4.encrypt(message)
            self.assertEqual(len(ciphertext), (length // 16 + 1) * 32)
            self.assertEqual(sm4.decrypt(ciphertext), message)

    def test_encrypt_is_repeatable_because_iv_is_not_chained_between_calls(self):
        sm4 = make_cipher(b"0123456789abcdef", bytes(16))
        self.assertEqual(sm4.encrypt("same"), sm4.encrypt("same"))

    def test_empty_ciphertext_decrypts_to_empty_string(self):
        sm4 = make_cipher(b"0123456789abcdef", bytes(16))
        self.assertEqual(sm4.decrypt(""), "")

    def test_decrypt_rejects_malformed_ciphertext(self):
        sm4 = make_cipher(b"0123456789abcdef", bytes(16))
        for bad in ("abc", "zz" * 16, "00" * 15):
            with self.assertRaises(ValueError, msg=bad):
                sm4.decrypt(bad)

    def test_tampered_padding_is_rejected(self):
        sm4 = make_cipher(b"0123456789abcdef", bytes(16))
        forged = sm4.encrypt_block(bytes(16)).hex()  # decrypts to 16 zero bytes
        with self.assertRaises(ValueError):
            sm4.decrypt(forged)

    def test_raw_block_operations_reject_wrong_size(self):
        sm4 = make_cipher(b"0123456789abcdef", bytes(16))
        for bad in (b"", bytes(15), bytes(17)):
            with self.assertRaises(ValueError):
                sm4.encrypt_block(bad)
            with self.assertRaises(ValueError):
                sm4.decrypt_block(bad)

    def test_use_before_set_key_raises(self):
        with self.assertRaises(ValueError):
            SM4().encrypt("x")

    def test_pkcs7(self):
        self.assertEqual(pkcs7_pad(b""), bytes([16]) * 16)
        self.assertEqual(pkcs7_pad(b"a" * 15), b"a" * 15 + b"\x01")
        self.assertEqual(pkcs7_unpad(pkcs7_pad(b"abc")), b"abc")
        self.assertEqual(pkcs7_unpad(b""), b"")
        for bad in (b"a" * 15 + b"\x00", b"a" * 15 + b"\x11", b"a" * 14 + b"\x01\x02"):
            with self.assertRaises(ValueError):
                pkcs7_unpad(bad)


if __name__ == "__main__":
    unittest.main()
