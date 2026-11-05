import unittest

from smx import SM2_N, SM2_P, ECPoint, hex_to_bytes

G = ECPoint.generator()

THREE_G_FROM_GO = (
    "04a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf"
    "530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6"
)


class ECPointTest(unittest.TestCase):
    def test_generator_on_curve(self):
        self.assertTrue(G.is_on_curve())

    def test_add_stays_on_curve(self):
        g2 = G.add(G)
        self.assertTrue(g2.is_on_curve())
        self.assertTrue(g2.add(G).is_on_curve())

    def test_twice_equals_add_self(self):
        self.assertEqual(G.twice(), G.add(G))

    def test_multiply_matches_go(self):
        p = G.multiply(3)
        self.assertEqual(p.to_hex_encoded(), THREE_G_FROM_GO)
        self.assertEqual(p, G.twice().add(G))

    def test_multiply_edge_scalars(self):
        self.assertTrue(G.multiply(0).infinity)
        self.assertEqual(G.multiply(1), G)
        self.assertTrue(G.multiply(SM2_N).infinity)
        self.assertEqual(G.multiply(SM2_N - 1), G.negate())
        self.assertTrue(ECPoint.at_infinity().multiply(5).infinity)
        with self.assertRaises(ValueError):
            G.multiply(-1)

    def test_encode_decode(self):
        self.assertEqual(ECPoint.from_encoded(G.to_encoded()), G)
        self.assertEqual(ECPoint.from_hex_encoded(G.to_hex_encoded()), G)
        with self.assertRaises(ValueError):
            ECPoint.from_encoded(b"")
        self.assertEqual(ECPoint.at_infinity().to_encoded(), b"\x00")

    def test_decode_rejects_malformed_input(self):
        valid = G.to_encoded()
        for bad in (valid[:-1], b"\x02" + valid[1:], valid + b"\x00"):
            with self.assertRaises(ValueError):
                ECPoint.from_encoded(bad)
        with self.assertRaises(ValueError):
            ECPoint.from_hex_encoded("zz" * 65)

    def test_decode_rejects_coordinates_outside_field(self):
        # Same rule as the Java FpElement constructor ("v is not in Fp").
        p_bytes = SM2_P.to_bytes(32, "big")
        for encoded in (b"\x04" + p_bytes + bytes(32), b"\x04" + bytes(32) + p_bytes):
            with self.assertRaises(ValueError):
                ECPoint.from_encoded(encoded)

    def test_hex_decoding_rejects_what_bytes_fromhex_tolerates(self):
        with self.assertRaises(ValueError):
            hex_to_bytes("ab  cd")

    def test_off_curve_point_detected(self):
        self.assertFalse(ECPoint(G.x, (G.y + 1) % SM2_P).is_on_curve())

    def test_infinity_arithmetic(self):
        inf = ECPoint.at_infinity()
        self.assertTrue(G.add(G.negate()).infinity)
        self.assertTrue(G.subtract(G).infinity)
        self.assertEqual(inf.add(G), G)
        self.assertEqual(G.add(inf), G)
        self.assertTrue(inf.twice().infinity)
        self.assertTrue(inf.negate().infinity)
        self.assertTrue(inf.is_on_curve())
        self.assertEqual(inf, ECPoint.at_infinity())
        self.assertNotEqual(inf, G)

    def test_points_are_immutable(self):
        with self.assertRaises(AttributeError):
            G.x = 1


if __name__ == "__main__":
    unittest.main()
