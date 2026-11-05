import unittest
from unittest import mock

from smx import (
    ECPoint,
    SM2_N,
    SM3,
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
from smx.sm2 import user_sm3_z

ID_A = "ALICE123@YAHOO.COM"
ID_B = "BILL456@YAHOO.COM"

D_A = int("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE", 16)
RA = int("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16)
D_B = int("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53", 16)
RB = int("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16)

# Key pair from GB/T 32918.5-2017, Appendix A.
STD_PRIVATE = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
STD_PUBLIC = (
    "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
    "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"
)
STD_K = int("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21", 16)

# Produced by the Go implementation in this repository (random k).
GO_CIPHERTEXTS = {
    "encryption standard": (
        "0444858f1f9e6a1fcc7c0256486d672ad2b8b0df45aba1ce422363df0daaa5fb07"
        "ff62ecd1ab9a3c722034588f16af133b080ef33f1c950a547eaba1ce54079b511f"
        "f91c1c0f710c859da92f5b26ae46f1df098531e4e8716c7ab69ba291f35f7920"
        "b0fbeddf0a85f0ddbf53d09096c47b11cb2a"
    ),
    "国密SM2": (
        "0403df678f154bd3e90d43750b61432bd30ecf0978e37fea7bbe4ecc058b157074"
        "8cc4fb73c4479af28ed86bfa4033e827c2cc64fa841988b644a65e058dcdb993"
        "efc5f5c74dbbec64278d2da6f43c13289e3d5aa70771090bc0664bd75346f130"
        "3561403bcd479879d7"
    ),
    "x": (
        "044023aca5c65ce7812371d8e180274c5a328e36b3cb408705d36778ac7c416448"
        "7b9d7cd1608a735119cfca28f5c9b08513f56b6d5f20c723e4fd39994151e437"
        "c956765cfd20ab6b5bc5d908d4bc2a535485cfc97591454c3ee51d176d955b9f05"
    ),
}
GO_SIGNATURES = {
    "encryption standard": (
        "4572a19e2ca29c80ad6797817e94cf36930a7189222866e6d73424ab1f969caf"
        "h81ff065c408c2ff4f49e35937b60e7206b50ed20569394a1aec9764514e725d7"
    ),
    "国密SM2": (
        "c55230ad6c1cae418ee4f78a6c9c0557d19202950fbb2a6ed4b45170e40d4e19"
        "h2b215b38ee1d5bfd99e9f7dffb60d73e252cc4261f2ab846bd7971b90dd03dd4"
    ),
    "x": (
        "08f6d7061db34dc854615228f1e6f98a96c0960c9d435347bf593a4dd67d6312"
        "h038fefa42772e436345927d2c80ab23f05e514a041786e661d52865e6606ffe2"
    ),
}


class KeyPairTest(unittest.TestCase):
    def test_generation_format(self):
        private_key, public_key = sm2_gen_key_pair()
        self.assertEqual(len(private_key), 64)
        self.assertEqual(private_key, private_key.upper())
        self.assertEqual(len(public_key), 130)
        self.assertTrue(public_key.startswith("04"))
        derived = sm2_get_public_key(int(private_key, 16))
        self.assertEqual(derived.to_hex_encoded(), public_key)

    def test_standard_public_key_derivation(self):
        derived = sm2_get_public_key(int(STD_PRIVATE, 16))
        self.assertEqual(derived.to_hex_encoded(), STD_PUBLIC)


class EncryptionTest(unittest.TestCase):
    def test_round_trip(self):
        private_key, public_key = sm2_gen_key_pair()
        for message in ("encryption standard", "国密", "x" * 100):
            ciphertext = sm2_encrypt(message, public_key)
            self.assertEqual(sm2_decrypt(ciphertext, private_key), message)

    def test_decrypts_go_ciphertext(self):
        for message, ciphertext in GO_CIPHERTEXTS.items():
            self.assertEqual(sm2_decrypt(ciphertext, STD_PRIVATE), message)

    def test_standard_vector_with_fixed_k(self):
        # GB/T 32918.5-2017, Appendix A: C1 || C3 || C2.
        with mock.patch("smx.sm2._random_scalar", return_value=STD_K):
            ciphertext = sm2_encrypt("encryption standard", STD_PUBLIC)
        self.assertEqual(
            ciphertext,
            "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73"
            "e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0"
            "59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766"
            "21886ca989ca9c7d58087307ca93092d651efa",
        )

    def test_rejects_empty_plaintext(self):
        with self.assertRaises(ValueError):
            sm2_encrypt("", STD_PUBLIC)

    def test_rejects_invalid_public_keys(self):
        off_curve = "04" + "00" * 31 + "01" + "00" * 31 + "01"
        for bad in (off_curve, "", "04" + "00" * 10):
            with self.assertRaises(ValueError, msg=bad):
                sm2_encrypt("x", bad)

    def test_decrypt_detects_tampering(self):
        private_key, public_key = sm2_gen_key_pair()
        ciphertext = sm2_encrypt("secret", public_key)
        last = "0" if ciphertext[-1] != "0" else "1"
        with self.assertRaises(ValueError):
            sm2_decrypt(ciphertext[:-1] + last, private_key)

    def test_decrypt_with_wrong_key_fails(self):
        _, public_key = sm2_gen_key_pair()
        other_private, _ = sm2_gen_key_pair()
        with self.assertRaises(ValueError):
            sm2_decrypt(sm2_encrypt("secret", public_key), other_private)

    def test_decrypt_rejects_malformed_input(self):
        valid = sm2_encrypt("secret", STD_PUBLIC)
        cases = (
            "04",
            "zz" + valid[2:],
            valid[:130] + "zz" + valid[132:],
            valid + "z",
            "04" + "00" * 64 + valid[130:],
        )
        for bad in cases:
            with self.assertRaises(ValueError, msg=bad):
                sm2_decrypt(bad, STD_PRIVATE)

    def test_rejects_out_of_range_private_keys(self):
        ciphertext = sm2_encrypt("secret", STD_PUBLIC)
        congruent = f"{int(STD_PRIVATE, 16) + SM2_N:x}"  # would decrypt if accepted
        for bad in ("00", f"{SM2_N - 1:064x}", f"{SM2_N:064x}", "not hex", congruent):
            with self.assertRaises(ValueError, msg=bad):
                sm2_decrypt(ciphertext, bad)


class SignatureTest(unittest.TestCase):
    def test_round_trip(self):
        private_key, public_key = sm2_gen_key_pair()
        signature = sm2_sign(ID_A, "encryption standard", private_key)
        self.assertRegex(signature, r"^[0-9a-f]{64}h[0-9a-f]{64}$")
        self.assertTrue(sm2_verify(ID_A, signature, "encryption standard", public_key))

    def test_verifies_go_signatures(self):
        for message, signature in GO_SIGNATURES.items():
            self.assertTrue(sm2_verify(ID_A, signature, message, STD_PUBLIC))

    def test_standard_vector_with_fixed_k(self):
        # GB/T 32918.5-2017, Appendix A.
        expected = (
            "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3"
            "h"
            "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa"
        )
        with mock.patch("smx.sm2._random_scalar", return_value=STD_K):
            signature = sm2_sign("1234567812345678", "message digest", STD_PRIVATE)
        self.assertEqual(signature, expected)
        self.assertTrue(
            sm2_verify("1234567812345678", expected, "message digest", STD_PUBLIC)
        )

    def test_rejects_wrong_message_user_or_key(self):
        private_key, public_key = sm2_gen_key_pair()
        _, other_public = sm2_gen_key_pair()
        signature = sm2_sign(ID_A, "encryption standard", private_key)
        self.assertFalse(sm2_verify(ID_A, signature, "wrong message", public_key))
        self.assertFalse(sm2_verify(ID_B, signature, "encryption standard", public_key))
        self.assertFalse(
            sm2_verify(ID_A, signature, "encryption standard", other_public)
        )

    def test_rejects_malformed_signatures(self):
        r, s = GO_SIGNATURES["x"].split("h")
        cases = (
            "",
            r,
            r + "h" + s + "h" + s,
            "h" + s,
            r + "h",
            "zz" + r[2:] + "h" + s,
            "0" * 64 + "h" + s,
            r + "h" + "0" * 64,
            f"{SM2_N:064x}h" + s,
            r + f"h{SM2_N:064x}",
            f"{SM2_N - int(s, 16):064x}h" + s,  # r + s == n
            f"{int(r, 16) + SM2_N:x}h" + s,  # congruent to a valid r
            r + f"h{int(s, 16) + SM2_N:x}",  # congruent to a valid s
        )
        for bad in cases:
            self.assertFalse(sm2_verify(ID_A, bad, "x", STD_PUBLIC), bad)

    def test_verify_rejects_invalid_public_key(self):
        signature = GO_SIGNATURES["x"]
        off_curve = "04" + "00" * 31 + "01" + "00" * 31 + "01"
        self.assertFalse(sm2_verify(ID_A, signature, "x", off_curve))
        # An empty key decodes to infinity; it must not be usable as a key.
        self.assertFalse(sm2_verify(ID_A, signature, "x", ""))
        with self.assertRaises(ValueError):
            sm2_verify(ID_A, signature, "x", "04abc")

    def test_sign_rejects_private_key_that_has_no_inverse(self):
        # d = n - 1 makes (1 + d) non-invertible.
        with self.assertRaises(ValueError):
            sm2_sign(ID_A, "x", f"{SM2_N - 1:064x}")


class KeyExchangeTest(unittest.TestCase):
    def setUp(self):
        self.p_a = sm2_get_public_key(D_A)
        self.r_a = sm2_get_public_key(RA)
        self.p_b = sm2_get_public_key(D_B)
        self.r_b = sm2_get_public_key(RB)

    def run_exchange(self, byte_len):
        result_b = sm2_get_sb(
            byte_len, self.p_a, self.r_a, self.p_b, D_B, self.r_b, RB, ID_A, ID_B
        )
        self.assertTrue(result_b.success, result_b.message)
        result_a = sm2_get_sa(
            byte_len,
            self.p_b,
            self.r_b,
            self.p_a,
            D_A,
            self.r_a,
            RA,
            ID_A,
            ID_B,
            bytes.fromhex(result_b.sb),
        )
        self.assertTrue(result_a.success, result_a.message)
        return result_a, result_b

    def test_matches_go_vector_16_bytes(self):
        result_a, result_b = self.run_exchange(16)
        self.assertEqual(result_a.ka, "f02f9068ad13e14f2b2602e0dfb2504f")
        self.assertEqual(result_b.kb, result_a.ka)
        self.assertEqual(
            result_b.sb,
            "b93374ade30a74e12ddb40e4c03d0c6fcf61badbf2c2c5cc39a91201d9228e2e",
        )
        self.assertEqual(
            result_a.sa,
            "daefca6c32f53c48444d4ef35f98471e5d1cd1e3b5b8e3322dede310306689f6",
        )
        self.assertEqual(
            result_b.v.to_hex_encoded(),
            "04588d82da2f0e75a042aab58a707c725e203d1bf1cb8eff56e37af32c24665267"
            "e85d7572801c598eeebc061347821a568895aef6fb8448fbef16845cfcc2e6f4",
        )
        self.assertEqual(
            result_b.za.hex(),
            "5d0b1182e1cee9093e96b6bdbf2e32f854d5c753e2ce9865d4984b8b70a8ae2b",
        )
        self.assertEqual(
            result_b.zb.hex(),
            "441bf12aca4164c866bf282787dfc63e0cc8268fa34d435491b0cbc7f6ddbd5e",
        )

    def test_matches_go_vector_multi_block_kdf(self):
        result_a, result_b = self.run_exchange(48)
        expected = (
            "f02f9068ad13e14f2b2602e0dfb2504ff5fabef8555364b7"
            "374436e8566d02aa5704021bc20a93dbefc42d1978da9b68"
        )
        self.assertEqual(result_a.ka, expected)
        self.assertEqual(result_b.kb, expected)

    def test_check_sa(self):
        result_a, result_b = self.run_exchange(16)
        sa = bytes.fromhex(result_a.sa)
        self.assertTrue(
            sm2_check_sa(result_b.v, result_b.za, result_b.zb, self.r_a, self.r_b, sa)
        )
        tampered = bytes([sa[0] ^ 1]) + sa[1:]
        self.assertFalse(
            sm2_check_sa(
                result_b.v, result_b.za, result_b.zb, self.r_a, self.r_b, tampered
            )
        )

    def test_get_sa_rejects_wrong_sb(self):
        result = sm2_get_sa(
            16, self.p_b, self.r_b, self.p_a, D_A, self.r_a, RA, ID_A, ID_B, bytes(32)
        )
        self.assertFalse(result.success)
        self.assertEqual(result.message, "B's verification value does not match")

    def test_rejects_invalid_static_public_keys(self):
        # An infinity static key would let a peer without a private key pass Sb.
        for bad in (ECPoint(1, 1), ECPoint.at_infinity()):
            result_b = sm2_get_sb(
                16, bad, self.r_a, self.p_b, D_B, self.r_b, RB, ID_A, ID_B
            )
            self.assertFalse(result_b.success)
            self.assertEqual(result_b.message, "PA point is not on curve")
            result_a = sm2_get_sa(
                16, bad, self.r_b, self.p_a, D_A, self.r_a, RA, ID_A, ID_B, bytes(32)
            )
            self.assertFalse(result_a.success)
            self.assertEqual(result_a.message, "PB point is not on curve")

    def test_rejects_off_curve_ephemeral_points(self):
        bad = ECPoint(1, 1)
        result_b = sm2_get_sb(
            16, self.p_a, bad, self.p_b, D_B, self.r_b, RB, ID_A, ID_B
        )
        self.assertFalse(result_b.success)
        self.assertEqual(result_b.message, "RA point is not on curve")
        result_a = sm2_get_sa(
            16, self.p_b, bad, self.p_a, D_A, self.r_a, RA, ID_A, ID_B, bytes(32)
        )
        self.assertFalse(result_a.success)
        self.assertEqual(result_a.message, "RB point is not on curve")

    def test_rejects_infinity_ephemeral_points(self):
        inf = ECPoint.at_infinity()
        self.assertFalse(
            sm2_get_sb(
                16, self.p_a, inf, self.p_b, D_B, self.r_b, RB, ID_A, ID_B
            ).success
        )
        self.assertFalse(
            sm2_get_sa(
                16, self.p_b, inf, self.p_a, D_A, self.r_a, RA, ID_A, ID_B, bytes(32)
            ).success
        )

    def test_rejects_non_positive_key_length(self):
        with self.assertRaises(ValueError):
            sm2_get_sb(0, self.p_a, self.r_a, self.p_b, D_B, self.r_b, RB, ID_A, ID_B)


class HelperTest(unittest.TestCase):
    def test_user_z_length_and_value(self):
        z = user_sm3_z(ID_A.encode(), sm2_get_public_key(D_A))
        self.assertEqual(
            z.hex(), "5d0b1182e1cee9093e96b6bdbf2e32f854d5c753e2ce9865d4984b8b70a8ae2b"
        )

    def test_decode_point(self):
        self.assertEqual(
            sm2_decode_point(STD_PUBLIC), sm2_get_public_key(int(STD_PRIVATE, 16))
        )

    def test_sm3_is_exported(self):
        self.assertEqual(len(SM3().finish().hash_bytes()), 32)


if __name__ == "__main__":
    unittest.main()
