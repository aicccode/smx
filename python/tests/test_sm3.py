import unittest

from smx import SM3


def digest(data: bytes) -> str:
    return SM3().update(data).finish().hash_hex_upper()


class SM3Test(unittest.TestCase):
    def test_abc(self):
        self.assertEqual(
            digest(b"abc"),
            "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0",
        )

    def test_empty(self):
        self.assertEqual(
            digest(b""),
            "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B",
        )

    def test_standard_64_byte_message(self):
        self.assertEqual(
            digest(b"abcd" * 16),
            "DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732",
        )

    def test_padding_boundaries_match_go(self):
        vectors = {
            54: "1BB1B592239447B5DE0395D94159996EA7CC4FCC7B9F66CCC5F0CFDC89586782",
            55: "A79CF9DCEE3404ABF7F769698201647FD9D3FF61D629D0F58BB4B5579A427DB8",
            56: "62F7363B15F4DE76DD925C493B9D6D00D4BA0EF2A1F334C1D0F13B293AEB40D1",
            57: "441F67CC31781DD2986FC612B92DFADE871D81357F2487F5C86D94A8C6778D82",
            63: "6165E4CBB15CDE01C6226E0015A47F710F8F8E1F2C296700033BB34D9212109C",
            65: "C886E6814BE748285A10B28AE62DDACD85DB830CD2CF3A2BFA2F729C15F63618",
            119: "8F3EA392A89A7119982D6634660DB1A95F35D68267A2235E3255998A857F4FBF",
            120: "6BABEE35E6A1515AF9D6255109C24F3C08897829422C6225D235FD4C8527E9EC",
        }
        for length, expected in vectors.items():
            self.assertEqual(digest(bytes(range(length))), expected, length)

    def test_padding_boundaries_match_incremental_feeding(self):
        # Lengths around the 55/56/64 byte padding boundaries.
        for length in (0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 128):
            data = bytes(i & 0xFF for i in range(length))
            incremental = SM3()
            for byte in data:
                incremental.update_byte(byte)
            incremental.finish()
            self.assertEqual(incremental.hash_hex_upper(), digest(data), length)

    def test_hash_bytes_matches_hex(self):
        sm3 = SM3().update(b"abc").finish()
        self.assertEqual(sm3.hash_bytes().hex().upper(), sm3.hash_hex_upper())
        self.assertEqual(len(sm3.hash_bytes()), 32)

    def test_instance_resets_after_finish(self):
        sm3 = SM3().update(b"first").finish()
        self.assertEqual(sm3.update(b"abc").finish().hash_hex_upper(), digest(b"abc"))

    def test_update_byte_rejects_out_of_range_value(self):
        with self.assertRaises(ValueError):
            SM3().update_byte(256)


if __name__ == "__main__":
    unittest.main()
