"""Randomized differential tests of the optimized code against slow references."""

import hashlib
import random
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from smx import (
    SM2_N,
    SM2_P,
    SM3,
    SM4,
    ECPoint,
    _ec,
    sm2_get_public_key,
    sm2_sign,
    sm2_verify,
)
from smx import sm2 as sm2_module
from smx import sm3 as sm3_module
from smx import sm4 as sm4_module
from smx._sm4_core import sub_bytes

from . import ec_reference as ref

RNG = random.Random(0x534D32)
P = SM2_P
N = SM2_N
C = 2**256 - N
EDGE_VALUES = (
    0,
    1,
    2,
    P - 1,
    P,
    P + 1,
    N - 1,
    N,
    2**256 - 1,
    2**255,
    2**224,
    2**64 - 1,
)
EDGE_SCALARS = (
    1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 31, 32, 33, 58, 62, 63, 64, 65, 255, 256,
    2**64, 2**128, 2**128 - 1, 2**192, 2**255, 2**255 + 1, 2**256 - 1 - C,
    N - 1, N - 2, N - 3, N - 6, N - 15, N - 16, N - 31, N - 32, N - 33, (N + 1) // 2,
    C, C + 2, 2 * C, 3 * C, C + 30 * 2**252,
)  # fmt: skip


def rand_scalar() -> int:
    return RNG.randrange(1, N)


def rand_point():
    return ref.multiply(ref.G, rand_scalar())


def rand_jacobian(point):
    z = RNG.randrange(1, P)
    return point[0] * z * z % P, point[1] * z * z * z % P, z


class FieldAndPointFormulas(unittest.TestCase):
    def test_double_random(self):
        for _ in range(200):
            point = rand_point()
            result = _ec.double(rand_jacobian(point))
            self.assertEqual(ref.from_jacobian(*result), ref.add(point, point))

    def test_double_special_cases(self):
        self.assertEqual(_ec.double(_ec.INFINITY)[2], 0)
        self.assertEqual(_ec.double((5, 0, 1))[2], 0)
        self.assertEqual(_ec.double((5, 7, 0))[2], 0)

    def test_add_affine_random(self):
        for _ in range(200):
            left, right = rand_point(), rand_point()
            result = _ec.add_affine(rand_jacobian(left), *right)
            self.assertEqual(ref.from_jacobian(*result), ref.add(left, right))

    def test_add_affine_special_cases(self):
        point = rand_point()
        jacobian = rand_jacobian(point)
        same = _ec.add_affine(jacobian, *point)
        self.assertEqual(ref.from_jacobian(*same), ref.add(point, point))
        self.assertEqual(_ec.add_affine(jacobian, *ref.negate(point))[2], 0)
        self.assertEqual(_ec.add_affine(_ec.INFINITY, *point), (*point, 1))

    def test_inversions(self):
        for modulus in (P, N):
            values = [v % modulus for v in EDGE_VALUES if v % modulus]
            values += [RNG.randrange(1, modulus) for _ in range(100)]
            for value in values:
                self.assertEqual(
                    _ec.invert_blinded(value, modulus),
                    pow(value, modulus - 2, modulus),
                )

    def test_blinded_inversion_uses_the_blinding_factor(self):
        seen = []
        real_pow = pow

        def spy(base, exponent, modulus):
            seen.append(base)
            return real_pow(base, exponent, modulus)

        with mock.patch.object(_ec, "pow", spy, create=True):
            _ec.invert_blinded(12345, P)
            _ec.invert_blinded(12345, P)
        self.assertEqual(len(seen), 2)
        self.assertNotIn(12345, seen)
        self.assertNotEqual(seen[0], seen[1])

    def test_affine_conversions(self):
        for _ in range(50):
            point = rand_point()
            jacobian = rand_jacobian(point)
            self.assertEqual(_ec.to_affine_public(jacobian), point)
            self.assertEqual(_ec.to_affine_blinded(jacobian), point)
        self.assertIsNone(_ec.to_affine_public(_ec.INFINITY))
        self.assertIsNone(_ec.to_affine_blinded(_ec.INFINITY))

    def test_batch_to_affine(self):
        for size in (1, 2, 3, 16, 33):
            points = [rand_point() for _ in range(size)]
            jacobians = [rand_jacobian(point) for point in points]
            self.assertEqual(_ec.batch_to_affine(jacobians), points)


class TableSelection(unittest.TestCase):
    def test_select_finds_every_lane(self):
        for _ in range(20):
            entries = [(RNG.randrange(P), RNG.randrange(P)) for _ in range(16)]
            table = _ec._pack_table(entries)
            for index, (x, y) in enumerate(entries):
                self.assertEqual(
                    _ec._select(table, index), _ec._LANE_SENTINEL | x << 256 | y
                )

    def test_select_with_extreme_lanes(self):
        values = [0, 1, P - 1, 2**256 - 1]
        entries = [(values[i % 4], values[(i >> 2) % 4]) for i in range(16)]
        table = _ec._pack_table(entries)
        for index, (x, y) in enumerate(entries):
            self.assertEqual(
                _ec._select(table, index), _ec._LANE_SENTINEL | x << 256 | y
            )


def digits_of(k):
    recoded = _ec._recode(k)
    return [
        2 * (recoded >> (_ec._WINDOW * i) & _ec._WINDOW_MASK) - _ec._WINDOW_MASK
        for i in range(_ec._WINDOW_COUNT)
    ]


class Recoding(unittest.TestCase):
    def check(self, k):
        digits = digits_of(k)
        total = sum(d << (_ec._WINDOW * i) for i, d in enumerate(digits))
        self.assertEqual(total, k if k & 1 else k + N)
        self.assertTrue(all(d & 1 for d in digits), "digits must be odd, so not zero")
        self.assertTrue(all(abs(d) <= _ec._WINDOW_MASK for d in digits))
        self.assertEqual(_ec._recode(k) >> (_ec._WINDOW * _ec._WINDOW_COUNT), 0)

    def test_edges(self):
        for k in EDGE_SCALARS:
            self.check(k)

    def test_random(self):
        for _ in range(2000):
            self.check(rand_scalar())

    def test_wnaf_reconstructs_and_is_sparse(self):
        for window in (6, 8):
            half = 1 << (window - 1)
            for k in list(EDGE_SCALARS) + [rand_scalar() for _ in range(500)]:
                digits = _ec._wnaf(k, window)
                self.assertEqual(sum(d << pos for pos, d in digits), k)
                for (first, _), (second, _) in zip(digits, digits[1:]):
                    self.assertGreaterEqual(second - first, window)
                for _, digit in digits:
                    self.assertTrue(digit & 1)
                    self.assertLess(abs(digit), half)


class ScalarMultiplication(unittest.TestCase):
    def test_generator_edge_scalars(self):
        for k in EDGE_SCALARS:
            result = ref.from_jacobian(*_ec.mul_generator(k))
            self.assertEqual(result, ref.multiply(ref.G, k), hex(k))

    def test_generator_random(self):
        for _ in range(200):
            k = rand_scalar()
            result = ref.from_jacobian(*_ec.mul_generator(k))
            self.assertEqual(result, ref.multiply(ref.G, k))

    def test_generator_exceptional_scalar_reaches_the_fallback(self):
        real = _ec.mul_double_and_add
        with mock.patch.object(_ec, "mul_double_and_add", wraps=real) as fallback:
            result = ref.from_jacobian(*_ec.mul_generator(C))
            self.assertEqual(fallback.call_count, 1)
            self.assertEqual(result, ref.multiply(ref.G, C))
            _ec.mul_generator(rand_scalar())
            self.assertEqual(fallback.call_count, 1)

    def test_variable_base_edge_scalars(self):
        point = rand_point()
        for k in EDGE_SCALARS:
            result = ref.from_jacobian(*_ec.mul_point(*point, k))
            self.assertEqual(result, ref.multiply(point, k), hex(k))

    def test_variable_base_random(self):
        for _ in range(100):
            point = rand_point()
            k = rand_scalar()
            result = ref.from_jacobian(*_ec.mul_point(*point, k))
            self.assertEqual(result, ref.multiply(point, k))

    def test_variable_base_exceptional_scalars_reach_the_fallback(self):
        point = rand_point()
        real = _ec.mul_double_and_add
        with mock.patch.object(_ec, "mul_double_and_add", wraps=real) as fallback:
            result = ref.from_jacobian(*_ec.mul_point(*point, N - 6))
            self.assertEqual(fallback.call_count, 1)
            self.assertEqual(result, ref.multiply(point, N - 6))

    def test_no_other_scalar_near_the_ends_is_exceptional(self):
        point = rand_point()
        with mock.patch.object(_ec, "mul_double_and_add", side_effect=AssertionError):
            for k in range(1, 200):
                _ec.mul_point(*point, k)
                _ec.mul_generator(k)
                _ec.mul_generator(N - k)
                _ec.mul_generator(C + 2 * k)
                if k != 6:
                    _ec.mul_point(*point, N - k)

    def test_public_method_matches_reference(self):
        for point in (ref.G, rand_point()):
            ec_point = ECPoint(*point)
            scalars = list(EDGE_SCALARS) + [N, N + 1, N + 2, 2 * N, 2 * N + 5, 2**300]
            for k in scalars:
                expected = ref.multiply(point, k % N)
                result = ec_point.multiply(k)
                if expected is None:
                    self.assertTrue(result.infinity, hex(k))
                else:
                    self.assertEqual((result.x, result.y), expected, hex(k))

    def test_public_method_scalar_zero_and_negative(self):
        self.assertTrue(ECPoint.generator().multiply(0).infinity)
        self.assertTrue(ECPoint(*rand_point()).multiply(N).infinity)
        with self.assertRaises(ValueError):
            ECPoint(*rand_point()).multiply(-1)

    def test_cached_multiply_matches_uncached(self):
        ec_point = ECPoint(*rand_point())
        for k in list(EDGE_SCALARS[:20]) + [rand_scalar() for _ in range(20)]:
            self.assertEqual(ec_point._multiply_cached(k), ec_point.multiply(k))

    def test_mul_public(self):
        for k in list(EDGE_SCALARS) + [rand_scalar() for _ in range(100)]:
            point = rand_point()
            result = ref.from_jacobian(*_ec.mul_public(*point, k))
            self.assertEqual(result, ref.multiply(point, k), hex(k))

    def test_shamir_cold_warm_and_hot(self):
        for _ in range(20):
            _ec.clear_caches()
            point = rand_point()
            for _ in range(4):
                s, t = rand_scalar(), rand_scalar()
                expected = ref.add(ref.multiply(ref.G, s), ref.multiply(point, t))
                self.assertEqual(
                    ref.from_jacobian(*_ec.mul_shamir(s, t, *point)), expected
                )

    def test_shamir_edges(self):
        point = rand_point()
        scalars = (1, 2, 3, 2**64 - 1, 2**64, 2**64 + 1, 2**128, 2**192, N - 1, N - 2)
        for s in scalars:
            for t in scalars:
                expected = ref.add(ref.multiply(ref.G, s), ref.multiply(point, t))
                self.assertEqual(
                    ref.from_jacobian(*_ec.mul_shamir(s, t, *point)), expected
                )

    def test_shamir_exceptional_sums(self):
        # P = [a]G, so choose s and t to make the sum infinity or a doubling.
        for path_use in range(3):
            a = rand_scalar()
            point = ref.multiply(ref.G, a)
            _ec.clear_caches()
            for _ in range(path_use):
                _ec.mul_shamir(1, 1, *point)
            t = rand_scalar()
            cancel = -a * t % N
            self.assertEqual(_ec.mul_shamir(cancel, t, *point)[2], 0)
            equal = a * t % N
            expected = ref.multiply(ref.G, 2 * equal % N)
            self.assertEqual(
                ref.from_jacobian(*_ec.mul_shamir(equal, t, *point)), expected
            )
            # The public key may be the generator itself.
            expected = ref.multiply(ref.G, (t + t) % N)
            self.assertEqual(ref.from_jacobian(*_ec.mul_shamir(t, t, *ref.G)), expected)

    def test_off_curve_and_unreduced_points_are_refused(self):
        for build in (
            lambda: ECPoint(1, 1).multiply(5),
            lambda: ECPoint(5, 7).twice(),
            lambda: ECPoint(5, 7).add(ECPoint.generator()),
            lambda: ECPoint.generator().add(ECPoint(5, 7)),
            lambda: ECPoint.generator().subtract(ECPoint(5, 7)),
            lambda: ECPoint(3, 0).twice(),
            lambda: ECPoint(ref.GX + P, ref.GY),
            lambda: ECPoint(-1, ref.GY),
            lambda: ECPoint(1, 2, True),
        ):
            with self.assertRaises(ValueError):
                build()


class SignaturesAcrossCacheTiers(unittest.TestCase):
    def test_verify_cold_warm_and_hot(self):
        sm2_module.clear_key_caches()
        d = rand_scalar() % (N - 2) + 1
        public = sm2_get_public_key(d).to_hex_encoded()
        private = f"{d:064x}"
        for round_number in range(5):
            message = f"message {round_number}"
            signature = sm2_sign("id", message, private)
            self.assertTrue(sm2_verify("id", signature, message, public), round_number)
            self.assertFalse(sm2_verify("id", signature, message + "!", public))
            self.assertFalse(sm2_verify("other", signature, message, public))
            r, s = signature.split("h")
            forged = f"{int(r, 16) ^ 1:064x}h{s}"
            self.assertFalse(sm2_verify("id", forged, message, public))

    def test_public_key_cache_is_keyed_by_private_key(self):
        sm2_module.clear_key_caches()
        keys = [rand_scalar() % (N - 2) + 1 for _ in range(3)]
        for _ in range(2):
            for d in keys:
                public = sm2_get_public_key(d).to_hex_encoded()
                signature = sm2_sign("id", "m", f"{d:064x}")
                self.assertTrue(sm2_verify("id", signature, "m", public))
        self.assertFalse(any(d in sm2_module._public_key_cache for d in keys))

    def test_public_key_cache_stays_bounded(self):
        sm2_module.clear_key_caches()
        for d in range(1, 2 * sm2_module._PUBLIC_KEY_CACHE_SIZE):
            sm2_module._public_key_of(d)
            self.assertLessEqual(
                len(sm2_module._public_key_cache), sm2_module._PUBLIC_KEY_CACHE_SIZE
            )

    def test_z_cache_returns_the_same_value_as_a_direct_computation(self):
        sm2_module.clear_key_caches()
        point = ECPoint(*rand_point())
        long_id = b"x" * (sm2_module._Z_CACHE_MAX_ID_LENGTH + 1)
        for identity in (b"", b"a", b"id" * 40, long_id):
            direct = sm2_module._compute_z(identity, point.x, point.y)
            for value in (
                identity,
                identity,
                bytearray(identity),
                memoryview(identity),
            ):
                self.assertEqual(sm2_module.user_sm3_z(value, point), direct)
        self.assertLessEqual(sm2_module._cached_z.cache_info().currsize, 3)

    def test_kdf_matches_definition(self):
        for seed_length in (0, 1, 32, 51, 52, 55, 56, 59, 60, 63, 64, 65, 96, 128, 200):
            seed = bytes(RNG.getrandbits(8) for _ in range(seed_length))
            for key_length in (0, 1, 31, 32, 33, 64, 100):
                expected = b"".join(
                    ref.sm3(seed + counter.to_bytes(4, "big"))
                    for counter in range(1, key_length // 32 + 2)
                )[:key_length]
                split = seed_length // 2
                result = sm2_module._kdf(key_length, (seed[:split], seed[split:]))
                self.assertEqual(result, expected, (seed_length, key_length))

    def test_xor(self):
        for length in (0, 1, 2, 31, 32, 33, 1000):
            left = bytes(RNG.getrandbits(8) for _ in range(length))
            right = bytes(RNG.getrandbits(8) for _ in range(length))
            expected = bytes(a ^ b for a, b in zip(left, right))
            self.assertEqual(sm2_module._xor(left, right), expected)
        self.assertEqual(sm2_module._xor(b"\x00\x01", b"\x00\x01"), b"\x00\x00")


class SM3Differential(unittest.TestCase):
    def test_against_the_textbook_version(self):
        lengths = list(range(130)) + [255, 256, 257, 1000, 4096]
        for length in lengths:
            data = bytes(RNG.getrandbits(8) for _ in range(length))
            self.assertEqual(sm3_module._digest(data), ref.sm3(data), length)
            self.assertEqual(SM3().update(data).finish().hash_bytes(), ref.sm3(data))

    def test_random_chunks_and_byte_updates(self):
        for _ in range(50):
            data = bytes(RNG.getrandbits(8) for _ in range(RNG.randrange(600)))
            hasher = SM3()
            offset = 0
            while offset < len(data):
                if RNG.random() < 0.3:
                    hasher.update_byte(data[offset])
                    offset += 1
                else:
                    step = RNG.choice((1, 2, 5, 63, 64, 65, 128, 200))
                    hasher.update(data[offset : offset + step])
                    offset += step
            self.assertEqual(hasher.finish().hash_bytes(), ref.sm3(data))

    def test_extreme_message_words(self):
        for fill in (b"\x00", b"\xff", b"\x80", b"\x7f"):
            data = fill * 64
            self.assertEqual(sm3_module._digest(data), ref.sm3(data))

    def test_input_buffer_is_not_retained(self):
        data = bytearray(b"a" * 70)
        hasher = SM3().update(data)
        data.extend(b"resizable again")
        data[:70] = b"z" * 70
        self.assertEqual(hasher.finish().hash_bytes(), ref.sm3(b"a" * 70))


class SM4Differential(unittest.TestCase):
    def make(self, key, iv):
        cipher = SM4()
        cipher.set_key(key, iv)
        return cipher

    def reference_cbc_encrypt(self, key, iv, data):
        keys = ref.sm4_round_keys(key)
        previous = iv
        output = b""
        for offset in range(0, len(data), 16):
            block = bytes(a ^ b for a, b in zip(data[offset : offset + 16], previous))
            previous = ref.sm4_block(block, keys)
            output += previous
        return output

    def test_key_schedule_and_blocks(self):
        for _ in range(100):
            key = bytes(RNG.getrandbits(8) for _ in range(16))
            block = bytes(RNG.getrandbits(8) for _ in range(16))
            cipher = self.make(key, bytes(16))
            keys = ref.sm4_round_keys(key)
            encrypted = ref.sm4_block(block, keys)
            self.assertEqual(cipher.encrypt_block(block), encrypted)
            self.assertEqual(cipher.decrypt_block(encrypted), block)

    def test_extreme_blocks_and_keys(self):
        for key in (bytes(16), b"\xff" * 16):
            for block in (bytes(16), b"\xff" * 16):
                cipher = self.make(key, bytes(16))
                keys = ref.sm4_round_keys(key)
                self.assertEqual(
                    cipher.encrypt_block(block), ref.sm4_block(block, keys)
                )

    def test_cbc_around_batch_sizes_matches_the_reference(self):
        key = b"0123456789abcdef"
        iv = b"fedcba9876543210"
        cipher = self.make(key, iv)
        batch = sm4_module._BATCH_BLOCKS * 16
        for size in (0, 1, 15, 16, 17, 2000, batch - 17, batch - 1, batch, batch + 16):
            text = "a" * size
            data = sm4_module.pkcs7_pad(text.encode())
            ciphertext = cipher.encrypt(text)
            self.assertEqual(
                ciphertext, self.reference_cbc_encrypt(key, iv, data).hex(), size
            )
            self.assertEqual(cipher.decrypt(ciphertext), text)

    def test_parallel_blocks_match_single_blocks(self):
        cipher = self.make(b"0123456789abcdef", bytes(16))
        keys = cipher._keys[1]
        for lanes in (1, 2, 3, 31, 32, 33, 64, 513):
            data = bytes(RNG.getrandbits(8) for _ in range(16 * lanes))
            if lanes == 3:
                data = bytes(16) + b"\xff" * 16 + data[32:]
            expected = b"".join(
                cipher.decrypt_block(data[i : i + 16]) for i in range(0, len(data), 16)
            )
            self.assertEqual(sm4_module._decrypt_blocks(data, keys), expected, lanes)
            self.assertEqual(
                sm4_module._crypt_lanes(data, lanes, keys), expected, lanes
            )

    def test_circuit_matches_the_standard_sbox_on_all_inputs(self):
        for value in range(256):
            self.assertEqual(sub_bytes(value, 1), ref.SBOX[value], value)
        # Every byte position of a word, and several words in one integer.
        for _ in range(500):
            data = bytes(RNG.getrandbits(8) for _ in range(12))
            expected = bytes(ref.SBOX[b] for b in data)
            ones = int.from_bytes(b"\x01" * 12, "big")
            result = sub_bytes(int.from_bytes(data, "big"), ones)
            self.assertEqual(result.to_bytes(12, "big"), expected)

    def test_invalid_utf8_gives_the_padding_error(self):
        cipher = self.make(b"0123456789abcdef", bytes(16))
        block = b"\xff" * 15 + b"\x01"
        ciphertext = cipher.encrypt_block(block).hex()
        with self.assertRaises(ValueError) as caught:
            cipher.decrypt(ciphertext)
        self.assertEqual(str(caught.exception), "decryption failed")
        self.assertIsNone(caught.exception.__context__)


class Laziness(unittest.TestCase):
    def test_import_builds_no_curve_tables(self):
        code = (
            "import smx, smx._ec as e\n"
            "assert e._generator_rows is None\n"
            "assert not e._generator_lookups and not e._generator_split_lookups\n"
        )
        root = Path(__file__).resolve().parents[1]
        subprocess.run([sys.executable, "-c", code], check=True, cwd=root)

    def test_hashlib_sm3_agrees_when_available(self):
        if "sm3" not in hashlib.algorithms_available:
            self.skipTest("this OpenSSL build has no SM3")
        data = b"x" * 100000
        self.assertEqual(sm3_module._digest(data), hashlib.new("sm3", data).digest())


OFF_CURVE_5 = (
    "043d8930bf8f513faac16606ed161c3cbc9a81771334bebc125ad6b5ad6b5ad6b6"
    "ec84eb6a69eb7656422f506c7b052e83d63caf66992eafd6706a8e407757a45d"
)
OFF_CURVE_BIG = (
    "0407074d62f83b1b5d6338149e16bd92b2934d1b7a9427a54a822d4d4f494e1d50"
    "05d1e8091f78546c0daccd47be2c560f8a7fb20a862ce46b7512813b7b6e4084"
)
OFF_CURVE_TWICE = (
    "0414e5e0a71a1f58d0fac687d6343eb1a1f58d0fac5397829cd0fac687d6343ec2"
    "948658115515a4f1d1b9d7b26106b79a7ee1663f9b3df2915f889545693c742c"
)
OFF_CURVE_ADD = (
    "043fffffffbfffffffffffffffffffffffffffffffc00000003ffffffffffffffc"
    "1fffffffdfffffffffffffffffffffffffffffffe00000002000000000000006"
)
THREE_G = (
    "04a97f7cd4b3c993b4be2daa8cdb41e24ca13f6bd945302244e26918f1d0509ebf"
    "530b5dd88c688ef5ccc5cec08a72150f7c400ee5cd045292aaacdd037458f6e6"
)
TWO_G = (
    "0456cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd52"
    "31b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3"
)

if __name__ == "__main__":
    unittest.main()
