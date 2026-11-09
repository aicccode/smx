"""SM9 tests: every vector of ../testvectors/sm9-vectors.json, round trips, tampering."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import smx
from smx import (
    SM9_HID_ENCRYPT,
    SM9_HID_EXCHANGE,
    SM9_HID_SIGN,
    SM9_MODE_SM4,
    SM9_MODE_STREAM,
    SM9_N,
    SM9ExchangeResult,
    _sm9_common,
    sm9,
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
from smx import _sm9_curve as curve
from smx import _sm9_field as field
from smx._sm9_pairing import pairing

VECTORS_PATH = Path(__file__).resolve().parents[2] / "testvectors" / "sm9-vectors.json"
VECTORS = json.loads(VECTORS_PATH.read_text("utf-8")) if VECTORS_PATH.exists() else None
needs_vectors = unittest.skipIf(VECTORS is None, f"{VECTORS_PATH} not found")
BOTH_MODES = (SM9_MODE_STREAM, SM9_MODE_SM4)


def flip_hex(text: str, position: int, bit: int = 1) -> str:
    """Flip one bit of the byte at ``position`` in a lowercase hex string."""
    data = bytearray.fromhex(text)
    data[position] ^= bit
    return data.hex()


def scalar(text: str) -> int:
    return int(text, 16)


@needs_vectors
class StandardVectorTest(unittest.TestCase):
    """GB/T 38635.5 appendices A to D."""

    def test_parameters(self):
        params = VECTORS["params"]
        self.assertEqual(int(params["q"], 16), smx.SM9_Q)
        self.assertEqual(int(params["n"], 16), SM9_N)
        self.assertEqual(int(params["t"], 16), field.T)
        self.assertEqual(params["P1"], curve.g1_to_bytes(curve.P1).hex())
        self.assertEqual(params["P2"], curve.g2_to_bytes(curve.P2).hex())
        self.assertEqual(
            (params["hid_sign"], params["hid_exchange"], params["hid_encrypt"]),
            (SM9_HID_SIGN, SM9_HID_EXCHANGE, SM9_HID_ENCRYPT),
        )

    def test_sign(self):
        v = VECTORS["standard"]["sign"]
        master = sm9_sign_master_public_key(v["master_private_key"])
        self.assertEqual(master, v["master_public_key"])
        user = sm9_gen_sign_user_key(v["master_private_key"], v["user_id"], v["hid"])
        self.assertEqual(user, v["user_private_key"])
        g = pairing(curve.P1, curve.g2_from_bytes(bytes.fromhex(master)))
        self.assertEqual(field.to_bytes(g).hex(), v["pairing_g"])
        signature = sm9._sign_known_r(v["message"], user, master, scalar(v["r"]))
        self.assertEqual(signature, v["signature"])
        self.assertTrue(sm9_verify(v["message"], signature, v["user_id"], master))
        self.assertTrue(
            sm9_verify(v["message"].encode(), signature, v["user_id"].encode(), master)
        )

    def test_exchange(self):
        v = VECTORS["standard"]["exchange"]
        check_exchange(self, v, v["master_private_key"], v["master_public_key"])

    def test_encapsulate(self):
        v = VECTORS["standard"]["encapsulate"]
        self.assertEqual(
            sm9_enc_master_public_key(v["master_private_key"]), v["master_public_key"]
        )
        check_kem(self, v, v["master_private_key"], v["master_public_key"], v["hid"])

    def test_encrypt(self):
        v = VECTORS["standard"]["encrypt"]
        self.assertEqual(
            sm9_enc_master_public_key(v["master_private_key"]), v["master_public_key"]
        )
        check_encrypt(
            self,
            v,
            v["plaintext"].encode(),
            v["master_private_key"],
            v["master_public_key"],
            v["hid"],
        )
        user = v["user_private_key"]
        self.assertEqual(
            sm9_decrypt_text(v["ciphertext_stream"], v["user_id"], user), v["plaintext"]
        )


def check_exchange(test, v, master_private, master_public):
    test.assertEqual(sm9_enc_master_public_key(master_private), master_public)
    id_a, id_b = v["id_a"], v["id_b"]
    hid = v.get("hid", SM9_HID_EXCHANGE)
    key_a = sm9_gen_enc_user_key(master_private, id_a, hid)
    key_b = sm9_gen_enc_user_key(master_private, id_b, hid)
    test.assertEqual(key_a, v["user_private_key_a"])
    test.assertEqual(key_b, v["user_private_key_b"])
    r_a, big_r_a = sm9._exchange_init(id_b, master_public, hid, scalar(v["r_a"]))
    r_b, big_r_b = sm9._exchange_init(id_a, master_public, hid, scalar(v["r_b"]))
    test.assertEqual((r_a, big_r_a), (v["r_a"], v["R_a"]))
    test.assertEqual((r_b, big_r_b), (v["r_b"], v["R_b"]))
    klen = v["key_len"]
    side_b = sm9_exchange_respond(
        klen, id_a, id_b, master_public, key_b, r_b, big_r_b, big_r_a
    )
    test.assertTrue(side_b.success, side_b.message)
    test.assertEqual(side_b.shared_key, v["shared_key"])
    test.assertEqual(side_b.s_b, v["s_b"])
    test.assertEqual(side_b.s_2, v["s_a"])
    side_a = sm9_exchange_confirm(
        klen, id_a, id_b, master_public, key_a, r_a, big_r_a, big_r_b, side_b.s_b
    )
    test.assertTrue(side_a.success, side_a.message)
    test.assertEqual(side_a.shared_key, v["shared_key"])
    test.assertEqual(side_a.s_a, v["s_a"])
    test.assertTrue(sm9_exchange_check(side_b.s_2, side_a.s_a))


def check_kem(test, v, master_private, master_public, hid):
    user = sm9_gen_enc_user_key(master_private, v["user_id"], hid)
    test.assertEqual(user, v["user_private_key"])
    key, ciphertext = sm9._encapsulate_known_r(
        v["user_id"], master_public, v["key_len"], hid, scalar(v["r"])
    )
    test.assertEqual((key, ciphertext), (v["key"], v["ciphertext"]))
    test.assertEqual(
        sm9_decapsulate(ciphertext, v["user_id"], user, v["key_len"]), v["key"]
    )


def check_encrypt(test, v, plaintext, master_private, master_public, hid):
    user = sm9_gen_enc_user_key(master_private, v["user_id"], hid)
    test.assertEqual(user, v["user_private_key"])
    for mode, name in (
        (SM9_MODE_STREAM, "ciphertext_stream"),
        (SM9_MODE_SM4, "ciphertext_sm4"),
    ):
        ciphertext = sm9._encrypt_known_r(
            plaintext, v["user_id"], master_public, hid, mode, scalar(v["r"])
        )
        test.assertEqual(ciphertext, v[name], mode)
        test.assertEqual(sm9_decrypt(ciphertext, v["user_id"], user, mode), plaintext)


@needs_vectors
class ExtraVectorTest(unittest.TestCase):
    def setUp(self):
        self.extra = VECTORS["extra"]

    def test_master_keys(self):
        e = self.extra
        self.assertEqual(
            sm9_sign_master_public_key(e["sign_master_private_key"]),
            e["sign_master_public_key"],
        )
        self.assertEqual(
            sm9_enc_master_public_key(e["enc_master_private_key"]),
            e["enc_master_public_key"],
        )

    def test_sign(self):
        e = self.extra
        for v in e["sign"]:
            with self.subTest(user_id=v["user_id"][:20]):
                user = sm9_gen_sign_user_key(e["sign_master_private_key"], v["user_id"])
                self.assertEqual(user, v["user_private_key"])
                message = bytes.fromhex(v["message_hex"])
                master = e["sign_master_public_key"]
                signature = sm9._sign_known_r(message, user, master, scalar(v["r"]))
                self.assertEqual(signature, v["signature"])
                self.assertTrue(sm9_verify(message, signature, v["user_id"], master))

    def test_encrypt(self):
        e = self.extra
        for v in e["encrypt"]:
            with self.subTest(user_id=v["user_id"][:20]):
                check_encrypt(
                    self,
                    v,
                    bytes.fromhex(v["plaintext_hex"]),
                    e["enc_master_private_key"],
                    e["enc_master_public_key"],
                    SM9_HID_ENCRYPT,
                )

    def test_encapsulate(self):
        e = self.extra
        for v in e["encapsulate"]:
            with self.subTest(user_id=v["user_id"], key_len=v["key_len"]):
                check_kem(
                    self,
                    v,
                    e["enc_master_private_key"],
                    e["enc_master_public_key"],
                    SM9_HID_ENCRYPT,
                )

    def test_exchange(self):
        e = self.extra
        for v in e["exchange"]:
            with self.subTest(id_a=v["id_a"], id_b=v["id_b"]):
                check_exchange(
                    self, v, e["enc_master_private_key"], e["enc_master_public_key"]
                )


@needs_vectors
class InvalidInputVectorTest(unittest.TestCase):
    """Every entry of invalid_points and invalid_scalars is rejected everywhere."""

    @classmethod
    def setUpClass(cls):
        e = VECTORS["extra"]
        cls.sign_master = e["sign_master_public_key"]
        cls.enc_master = e["enc_master_public_key"]
        cls.sign_user = e["sign"][1]["user_private_key"]
        cls.sign_id = e["sign"][1]["user_id"]
        cls.enc_user = e["encrypt"][0]["user_private_key"]
        cls.enc_id = e["encrypt"][0]["user_id"]
        cls.signature = sm9_sign(b"m", cls.sign_user, cls.sign_master)
        cls.ciphertext = sm9_encrypt(b"m", cls.enc_id, cls.enc_master)
        cls.kem = sm9_encapsulate(cls.enc_id, cls.enc_master, 16)[1]
        cls.exchange = e["exchange"][0]

    def test_invalid_g1_points(self):
        x = self.exchange
        for entry in VECTORS["invalid_points"]["g1"]:
            value = entry["value"]
            with self.subTest(name=entry["name"]):
                with self.assertRaises(ValueError):
                    sm9_encrypt(b"m", self.enc_id, value)
                with self.assertRaises(ValueError):
                    sm9_encapsulate(self.enc_id, value, 16)
                with self.assertRaises(ValueError):
                    sm9_exchange_init("Bob", value)
                with self.assertRaises(ValueError):
                    sm9_sign(b"m", value, self.sign_master)
                self.assertFalse(
                    sm9_verify(
                        b"m",
                        self.signature[:64] + value,
                        self.sign_id,
                        self.sign_master,
                    )
                )
                with self.assertRaises(ValueError):
                    sm9_decrypt(
                        value + self.ciphertext[130:], self.enc_id, self.enc_user
                    )
                with self.assertRaises(ValueError):
                    sm9_decapsulate(value, self.enc_id, self.enc_user, 16)
                respond = sm9_exchange_respond(
                    1, x["id_a"], x["id_b"], self.enc_master, x["user_private_key_b"],
                    x["r_b"], x["R_b"], value,
                )  # fmt: skip
                self.assertFalse(respond.success)
                confirm = sm9_exchange_confirm(
                    1, x["id_a"], x["id_b"], self.enc_master, x["user_private_key_a"],
                    x["r_a"], x["R_a"], value, x["s_b"],
                )  # fmt: skip
                self.assertFalse(confirm.success)
                bad_master = sm9_exchange_respond(
                    1, x["id_a"], x["id_b"], value, x["user_private_key_b"],
                    x["r_b"], x["R_b"], x["R_a"],
                )  # fmt: skip
                self.assertFalse(bad_master.success)

    def test_invalid_g2_points(self):
        x = self.exchange
        for entry in VECTORS["invalid_points"]["g2"]:
            value = entry["value"]
            with self.subTest(name=entry["name"]):
                self.assertFalse(sm9_verify(b"m", self.signature, self.sign_id, value))
                with self.assertRaises(ValueError):
                    sm9_sign(b"m", self.sign_user, value)
                with self.assertRaises(ValueError):
                    sm9_decrypt(self.ciphertext, self.enc_id, value)
                with self.assertRaises(ValueError):
                    sm9_decapsulate(self.kem, self.enc_id, value, 16)
                respond = sm9_exchange_respond(
                    1, x["id_a"], x["id_b"], self.enc_master, value,
                    x["r_b"], x["R_b"], x["R_a"],
                )  # fmt: skip
                self.assertFalse(respond.success)
                self.assertIsNone(
                    curve.g2_from_bytes(bytes.fromhex(value))
                    if _is_hex(value)
                    else None
                )

    def test_not_in_subgroup_is_on_curve(self):
        entry = next(
            e for e in VECTORS["invalid_points"]["g2"] if e["name"] == "not_in_subgroup"
        )
        data = bytes.fromhex(entry["value"])
        x1, x0, y1, y0 = (
            int.from_bytes(data[i : i + 32], "big") for i in (1, 33, 65, 97)
        )
        self.assertTrue(curve.g2_on_curve(x0, x1, y0, y1))
        self.assertFalse(curve.in_g2_subgroup((x0, x1, y0, y1)))

    def test_invalid_scalars(self):
        x = self.exchange
        for entry in VECTORS["invalid_scalars"]:
            value = entry["value"]
            with self.subTest(name=entry["name"]):
                for function in (sm9_sign_master_public_key, sm9_enc_master_public_key):
                    with self.assertRaises(ValueError):
                        function(value)
                for function in (sm9_gen_sign_user_key, sm9_gen_enc_user_key):
                    with self.assertRaises(ValueError):
                        function(value, "Alice")
                respond = sm9_exchange_respond(
                    1, x["id_a"], x["id_b"], self.enc_master, x["user_private_key_b"],
                    value, x["R_b"], x["R_a"],
                )  # fmt: skip
                self.assertFalse(respond.success)
                confirm = sm9_exchange_confirm(
                    1, x["id_a"], x["id_b"], self.enc_master, x["user_private_key_a"],
                    value, x["R_a"], x["R_b"], x["s_b"],
                )  # fmt: skip
                self.assertFalse(confirm.success)

    def test_max_valid_master_private_key(self):
        value = VECTORS["max_valid_master_private_key"]
        self.assertEqual(int(value, 16), SM9_N - 1)
        public = sm9_sign_master_public_key(value)
        user = sm9_gen_sign_user_key(value, "Alice")
        signature = sm9_sign(b"m", user, public)
        self.assertTrue(sm9_verify(b"m", signature, "Alice", public))
        public_e = sm9_enc_master_public_key(value.upper())
        user_e = sm9_gen_enc_user_key(value, "Bob")
        self.assertEqual(
            sm9_decrypt(sm9_encrypt(b"m", "Bob", public_e), "Bob", user_e), b"m"
        )


def _is_hex(text: str) -> bool:
    try:
        bytes.fromhex(text)
    except ValueError:
        return False
    return True


class SM9RoundTripTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sign_private, cls.sign_public = sm9_gen_sign_master_key()
        cls.enc_private, cls.enc_public = sm9_gen_enc_master_key()
        cls.alice_sign = sm9_gen_sign_user_key(cls.sign_private, "Alice")
        cls.bob_enc = sm9_gen_enc_user_key(cls.enc_private, "Bob")
        cls.alice_x = sm9_gen_enc_user_key(cls.enc_private, "Alice", SM9_HID_EXCHANGE)
        cls.bob_x = sm9_gen_enc_user_key(cls.enc_private, "Bob", SM9_HID_EXCHANGE)

    def test_key_formats(self):
        for value, length in (
            (self.sign_private, 64),
            (self.sign_public, 258),
            (self.enc_private, 64),
            (self.enc_public, 130),
            (self.alice_sign, 130),
            (self.bob_enc, 258),
        ):
            self.assertEqual(len(value), length)
            self.assertEqual(value, value.lower())
        self.assertEqual(
            sm9_sign_master_public_key(self.sign_private), self.sign_public
        )
        self.assertEqual(sm9_enc_master_public_key(self.enc_private), self.enc_public)

    def test_sign_verify(self):
        for message in (b"", b"x", "国密 SM9", bytes(range(256)) * 3, bytearray(b"ab")):
            signature = sm9_sign(message, self.alice_sign, self.sign_public)
            self.assertEqual(len(signature), 194)
            self.assertTrue(sm9_verify(message, signature, "Alice", self.sign_public))
        # Keys are accepted in upper case; the signature is not.
        upper = sm9_sign(b"m", self.alice_sign.upper(), self.sign_public.upper())
        self.assertTrue(sm9_verify(b"m", upper, "Alice", self.sign_public.upper()))
        self.assertFalse(sm9_verify(b"m", upper.upper(), "Alice", self.sign_public))

    def test_signatures_are_randomized(self):
        first = sm9_sign(b"m", self.alice_sign, self.sign_public)
        second = sm9_sign(b"m", self.alice_sign, self.sign_public)
        self.assertNotEqual(first, second)

    def test_signature_tampering(self):
        signature = sm9_sign(b"message", self.alice_sign, self.sign_public)
        for position in (0, 31, 32, 33, 64, 65, 96):
            for bit in (1, 0x80):
                with self.subTest(position=position, bit=bit):
                    tampered = flip_hex(signature, position, bit)
                    self.assertFalse(
                        sm9_verify(b"message", tampered, "Alice", self.sign_public)
                    )
        self.assertFalse(sm9_verify(b"messagf", signature, "Alice", self.sign_public))
        self.assertFalse(sm9_verify(b"message", signature, "Alicf", self.sign_public))
        self.assertFalse(
            sm9_verify(
                b"message", signature, "Alice", self.sign_public, SM9_HID_EXCHANGE
            )
        )
        other_private, other_public = sm9_gen_sign_master_key()
        self.assertFalse(sm9_verify(b"message", signature, "Alice", other_public))
        other_key = sm9_gen_sign_user_key(other_private, "Alice")
        forged = sm9_sign(b"message", other_key, self.sign_public)
        self.assertFalse(sm9_verify(b"message", forged, "Alice", self.sign_public))

    def test_verify_never_raises(self):
        signature = sm9_sign(b"m", self.alice_sign, self.sign_public)
        cases = [
            (None, signature, "Alice", self.sign_public, 1),
            (b"m", None, "Alice", self.sign_public, 1),
            (b"m", signature, None, self.sign_public, 1),
            (b"m", signature, "Alice", None, 1),
            (b"m", signature, "Alice", self.sign_public, 256),
            (b"m", signature, "Alice", self.sign_public, True),
            (b"m", signature[:-2], "Alice", self.sign_public, 1),
            (b"m", signature + "00", "Alice", self.sign_public, 1),
            (b"m", "00" * 32 + signature[64:], "Alice", self.sign_public, 1),
            (b"m", f"{SM9_N:064x}" + signature[64:], "Alice", self.sign_public, 1),
            (b"m", signature, "\ud800", self.sign_public, 1),
            (b"m", "zz" + signature[2:], "Alice", self.sign_public, 1),
        ]
        for case in cases:
            self.assertIs(sm9_verify(*case), False)

    def test_hid_is_any_byte(self):
        key = sm9_gen_sign_user_key(self.sign_private, "Alice", 0)
        signature = sm9_sign(b"m", key, self.sign_public)
        self.assertTrue(sm9_verify(b"m", signature, "Alice", self.sign_public, 0))
        self.assertFalse(sm9_verify(b"m", signature, "Alice", self.sign_public, 1))
        key = sm9_gen_enc_user_key(self.enc_private, "Bob", 255)
        ciphertext = sm9_encrypt(b"x", "Bob", self.enc_public, 255)
        self.assertEqual(sm9_decrypt(ciphertext, "Bob", key), b"x")
        for hid in (-1, 256, None, True, 1.0):
            with self.assertRaises(ValueError):
                sm9_gen_sign_user_key(self.sign_private, "Alice", hid)

    def test_encrypt_decrypt(self):
        for mode in BOTH_MODES:
            for message in (
                b"\x00",
                b"x" * 15,
                b"y" * 16,
                "国密".encode(),
                bytes(1000),
            ):
                with self.subTest(mode=mode, size=len(message)):
                    ciphertext = sm9_encrypt(message, "Bob", self.enc_public, mode=mode)
                    self.assertEqual(ciphertext, ciphertext.lower())
                    self.assertEqual(
                        sm9_decrypt(ciphertext, "Bob", self.bob_enc, mode), message
                    )
        ciphertext = sm9_encrypt("国密 SM9", "Bob", self.enc_public)
        self.assertEqual(sm9_decrypt_text(ciphertext, "Bob", self.bob_enc), "国密 SM9")
        self.assertEqual(len(ciphertext), 2 * (65 + 32 + len("国密 SM9".encode())))
        block = sm9_encrypt(b"x" * 16, "Bob", self.enc_public, mode=SM9_MODE_SM4)
        self.assertEqual(len(block), 2 * (65 + 32 + 32))

    def test_empty_plaintext_rejected(self):
        for mode in BOTH_MODES:
            with self.assertRaises(ValueError):
                sm9_encrypt(b"", "Bob", self.enc_public, mode=mode)
        with self.assertRaises(ValueError):
            sm9_encrypt(b"x", "Bob", self.enc_public, mode="cbc")
        with self.assertRaises(TypeError):
            sm9_encrypt(12, "Bob", self.enc_public)

    def assert_decrypt_fails(self, *args):
        with self.assertRaisesRegex(ValueError, "^decryption failed$"):
            sm9_decrypt(*args)

    def test_ciphertext_tampering(self):
        for mode in BOTH_MODES:
            ciphertext = sm9_encrypt(
                b"attack at dawn!!", "Bob", self.enc_public, mode=mode
            )
            size = len(ciphertext) // 2
            # C1 (x and y), C3 and C2 (first and last byte).
            for position in (1, 40, 64, 65, 80, 96, 97, size - 1):
                with self.subTest(mode=mode, position=position):
                    self.assert_decrypt_fails(
                        flip_hex(ciphertext, position), "Bob", self.bob_enc, mode
                    )
            failures = (
                (ciphertext.upper(), "Bob", self.bob_enc, mode),
                (ciphertext[:-2], "Bob", self.bob_enc, mode),
                (ciphertext + "00", "Bob", self.bob_enc, mode),
                (ciphertext[: 2 * 97], "Bob", self.bob_enc, mode),
                (ciphertext, "Bobb", self.bob_enc, mode),
                (
                    ciphertext,
                    "Bob",
                    sm9_gen_enc_user_key(self.enc_private, "Carol"),
                    mode,
                ),
                (ciphertext, "Bob", self.bob_x, mode),
            )
            for case in failures:
                with self.assertRaisesRegex(ValueError, "^decryption failed$"):
                    sm9_decrypt(*case)
        stream = sm9_encrypt(b"x" * 16, "Bob", self.enc_public)
        block = sm9_encrypt(b"x" * 16, "Bob", self.enc_public, mode=SM9_MODE_SM4)
        with self.assertRaisesRegex(ValueError, "^decryption failed$"):
            sm9_decrypt(stream, "Bob", self.bob_enc, SM9_MODE_SM4)
        with self.assertRaisesRegex(ValueError, "^decryption failed$"):
            sm9_decrypt(block, "Bob", self.bob_enc, SM9_MODE_STREAM)
        with self.assertRaises(ValueError):
            sm9_decrypt_text(
                sm9_encrypt(b"\xff", "Bob", self.enc_public), "Bob", self.bob_enc
            )

    def test_encryption_wrong_master(self):
        other_private, other_public = sm9_gen_enc_master_key()
        ciphertext = sm9_encrypt(b"m", "Bob", other_public)
        with self.assertRaises(ValueError):
            sm9_decrypt(ciphertext, "Bob", self.bob_enc)
        self.assertEqual(
            sm9_decrypt(ciphertext, "Bob", sm9_gen_enc_user_key(other_private, "Bob")),
            b"m",
        )

    def test_kem(self):
        for key_len in (1, 16, 32, 33, 100):
            key, ciphertext = sm9_encapsulate("Bob", self.enc_public, key_len)
            self.assertEqual(len(key), 2 * key_len)
            self.assertEqual(
                sm9_decapsulate(ciphertext, "Bob", self.bob_enc, key_len), key
            )
        key, ciphertext = sm9_encapsulate("Bob", self.enc_public, 32)
        self.assertNotEqual(sm9_decapsulate(ciphertext, "Carol", self.bob_enc, 32), key)
        for bad in (
            ciphertext.upper(),
            flip_hex(ciphertext, 10),
            ciphertext[:-2],
            "",
            None,
        ):
            with self.assertRaises((ValueError, TypeError)):
                sm9_decapsulate(bad, "Bob", self.bob_enc, 32)
        for key_len in (0, -1, (1 << 20) + 1, True, None):
            with self.assertRaises(ValueError):
                sm9_encapsulate("Bob", self.enc_public, key_len)
            with self.assertRaises(ValueError):
                sm9_decapsulate(ciphertext, "Bob", self.bob_enc, key_len)

    def run_exchange(self, key_len, id_a="Alice", id_b="Bob"):
        r_a, big_r_a = sm9_exchange_init(id_b, self.enc_public)
        r_b, big_r_b = sm9_exchange_init(id_a, self.enc_public)
        side_b = sm9_exchange_respond(
            key_len, id_a, id_b, self.enc_public, self.bob_x, r_b, big_r_b, big_r_a
        )
        side_a = sm9_exchange_confirm(
            key_len, id_a, id_b, self.enc_public, self.alice_x, r_a, big_r_a, big_r_b,
            side_b.s_b,
        )  # fmt: skip
        return (r_a, big_r_a, r_b, big_r_b), side_a, side_b

    def test_exchange(self):
        _, side_a, side_b = self.run_exchange(48)
        self.assertTrue(side_a.success and side_b.success)
        self.assertIsInstance(side_a, SM9ExchangeResult)
        self.assertEqual(side_a.shared_key, side_b.shared_key)
        self.assertEqual(len(side_a.shared_key), 96)
        self.assertTrue(sm9_exchange_check(side_b.s_2, side_a.s_a))
        self.assertNotIn(side_a.shared_key, repr(side_a))

    def test_exchange_mismatch(self):
        (r_a, big_r_a, r_b, big_r_b), side_a, side_b = self.run_exchange(16)
        self.assertFalse(sm9_exchange_check(side_b.s_2, flip_hex(side_a.s_a, 0)))
        self.assertFalse(sm9_exchange_check(side_b.s_2, side_b.s_b))
        self.assertFalse(sm9_exchange_check(None, side_a.s_a))
        self.assertFalse(sm9_exchange_check(side_b.s_2, side_a.s_a[:-2]))
        # A rejects a tampered S_B, a wrong peer identity and a wrong R_B.
        args = (16, "Alice", "Bob", self.enc_public, self.alice_x, r_a, big_r_a)
        bad = sm9_exchange_confirm(*args, big_r_b, flip_hex(side_b.s_b, 31))
        self.assertFalse(bad.success)
        self.assertEqual(bad.shared_key, "")
        _, other_r_b = sm9_exchange_init("Alice", self.enc_public)
        self.assertFalse(sm9_exchange_confirm(*args, other_r_b, side_b.s_b).success)
        wrong_id = sm9_exchange_confirm(
            16, "Alice", "Carol", self.enc_public, self.alice_x, r_a, big_r_a, big_r_b,
            side_b.s_b,
        )  # fmt: skip
        self.assertFalse(wrong_id.success)
        # B computes a different key with the wrong private key; A then rejects S_B.
        wrong_b = sm9_exchange_respond(
            16, "Alice", "Bob", self.enc_public, self.bob_enc, r_b, big_r_b, big_r_a
        )
        self.assertTrue(wrong_b.success)
        self.assertNotEqual(wrong_b.shared_key, side_b.shared_key)
        self.assertFalse(sm9_exchange_confirm(*args, big_r_b, wrong_b.s_b).success)

    def test_exchange_key_length(self):
        for key_len in (0, (1 << 20) + 1, None, True):
            with self.assertRaises(ValueError):
                sm9_exchange_respond(
                    key_len, "a", "b", self.enc_public, self.bob_x, "01" * 32, "", ""
                )
            with self.assertRaises(ValueError):
                sm9_exchange_confirm(
                    key_len,
                    "a",
                    "b",
                    self.enc_public,
                    self.alice_x,
                    "01" * 32,
                    "",
                    "",
                    "",
                )

    def test_exchange_bad_inputs_are_results(self):
        r_b, big_r_b = sm9_exchange_init("Alice", self.enc_public)
        _, big_r_a = sm9_exchange_init("Bob", self.enc_public)
        for args in (
            (None, "Bob", self.enc_public, self.bob_x, r_b, big_r_b, big_r_a),
            ("Alice", "Bob", None, self.bob_x, r_b, big_r_b, big_r_a),
            ("Alice", "Bob", self.enc_public, self.alice_sign, r_b, big_r_b, big_r_a),
            ("Alice", "Bob", self.enc_public, self.bob_x, "00" * 32, big_r_b, big_r_a),
            (
                "Alice",
                "Bob",
                self.enc_public,
                self.bob_x,
                r_b,
                big_r_b,
                "04" + "00" * 64,
            ),
            ("Alice", "Bob", self.enc_public, self.bob_x, r_b, None, big_r_a),
        ):
            result = sm9_exchange_respond(16, *args)
            self.assertFalse(result.success)
            self.assertTrue(result.message)

    def test_input_validation(self):
        with self.assertRaises(TypeError):
            sm9_gen_sign_user_key(self.sign_private, 5)
        with self.assertRaises(ValueError):
            sm9_gen_sign_user_key(self.sign_private, "\ud800")
        with self.assertRaises(ValueError):
            sm9_sign(b"m", self.alice_sign[:-2], self.sign_public)
        with self.assertRaises(ValueError):
            sm9_sign(b"m", self.alice_sign, self.sign_public[:-2])
        with self.assertRaises(TypeError):
            sm9_sign(b"m", None, self.sign_public)
        with self.assertRaises(ValueError):
            sm9_decrypt("00", "Bob", self.bob_enc[:-2])
        # A G2 key where a G1 key is expected and the other way round.
        with self.assertRaises(ValueError):
            sm9_sign(b"m", self.bob_enc, self.sign_public)
        with self.assertRaises(ValueError):
            sm9_encrypt(b"m", "Bob", self.sign_public)

    def test_identities_bytes_and_text(self):
        key = sm9_gen_sign_user_key(self.sign_private, "张三".encode())
        signature = sm9_sign(b"m", key, self.sign_public)
        self.assertTrue(sm9_verify(b"m", signature, "张三", self.sign_public))
        self.assertTrue(
            sm9_verify(b"m", signature, memoryview("张三".encode()), self.sign_public)
        )
        empty = sm9_gen_enc_user_key(self.enc_private, "")
        self.assertEqual(
            sm9_decrypt(sm9_encrypt(b"m", b"", self.enc_public), "", empty), b"m"
        )

    def test_cache_toggle(self):
        signature = sm9_sign(b"m", self.alice_sign, self.sign_public)
        try:
            smx.set_key_cache_enabled(False)
            self.assertFalse(_sm9_common._sign_masters or _sm9_common._enc_masters)
            self.assertTrue(sm9_verify(b"m", signature, "Alice", self.sign_public))
            self.assertFalse(_sm9_common._sign_masters)
        finally:
            smx.set_key_cache_enabled(True)
        self.assertTrue(sm9_verify(b"m", signature, "Alice", self.sign_public))
        self.assertTrue(_sm9_common._sign_masters)
        smx.clear_key_caches()
        self.assertFalse(_sm9_common._sign_masters)


class SM9InternalsTest(unittest.TestCase):
    def test_pairing_bilinear(self):
        a, b = 0x1234567890ABCDEF, 0xFEDCBA0987654321
        pa = curve.G1.to_affine(curve.mul_secret(curve.G1, curve.P1, a))
        qb = curve.G2.to_affine(curve.mul_secret(curve.G2, curve.P2, b))
        base = pairing(curve.P1, curve.P2)
        self.assertNotEqual(base, field.ONE)
        self.assertEqual(pairing(pa, qb), field.pow_public(base, a * b % SM9_N))
        self.assertEqual(pairing(None, curve.P2), field.ONE)
        self.assertEqual(field.pow_public(base, SM9_N), field.ONE)

    def test_secret_and_public_multiplication_agree(self):
        for k in (1, 2, 3, 30, 31, 32, 33, SM9_N - 1, SM9_N - 2, SM9_N - 6, 2**255):
            k %= SM9_N
            with self.subTest(k=k):
                for group, base in ((curve.G1, curve.P1), (curve.G2, curve.P2)):
                    secret = group.to_affine(curve.mul_secret(group, base, k))
                    public = group.to_affine(curve.mul_public(group, base, k), False)
                    self.assertEqual(secret, public)

    def test_gt_powers_agree(self):
        g = pairing(curve.P1, curve.P2)
        table = field.odd_powers_table(g)
        for k in (1, 2, 31, 32, 33, SM9_N - 1, SM9_N - 2, 0xABCDEF):
            self.assertEqual(field.pow_secret(table, k), field.pow_public(g, k))
        self.assertEqual(field.cyclotomic_sqr(g), field.sqr(g))
        self.assertEqual(field.mul(g, field.conj(g)), field.ONE)
        self.assertEqual(field.mul(g, field.inverse(g)), field.ONE)


if __name__ == "__main__":
    unittest.main()
