"""Slow, simple reference implementations used only by the differential tests."""

from __future__ import annotations

from typing import Optional

from smx.sm4 import _CK, _FK

# GB/T 32907-2016.
SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c052b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6fd5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad80ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec68418f07dec3adc4d2079ee5f3ed7cb3948"
)

P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G = (GX, GY)

Point = Optional[tuple[int, int]]  # None is the point at infinity


def inverse(value: int, modulus: int = P) -> int:
    return pow(value % modulus, -1, modulus)


def add(left: Point, right: Point) -> Point:
    """Textbook affine addition."""
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if (x1 - x2) % P == 0:
        if (y1 + y2) % P == 0:
            return None
        slope = (3 * x1 * x1 + A) * inverse(2 * y1) % P
    else:
        slope = (y2 - y1) * inverse(x2 - x1) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def negate(point: Point) -> Point:
    return None if point is None else (point[0], -point[1] % P)


def multiply(point: Point, k: int) -> Point:
    """Right-to-left double-and-add, the most literal definition of [k]P."""
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def from_jacobian(x: int, y: int, z: int) -> Point:
    if z % P == 0:
        return None
    z_inv = inverse(z)
    return x * z_inv * z_inv % P, y * z_inv * z_inv * z_inv % P


def _rotl(x: int, n: int) -> int:
    n %= 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def sm3(data: bytes) -> bytes:
    """SM3 as written in GB/T 32905, with a separate step for every operation."""
    state = [
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
    ]  # fmt: skip
    padding = (
        b"\x80" + bytes((55 - len(data)) % 64) + (len(data) * 8).to_bytes(8, "big")
    )
    message = data + padding
    p0 = lambda x: x ^ _rotl(x, 9) ^ _rotl(x, 17)
    p1 = lambda x: x ^ _rotl(x, 15) ^ _rotl(x, 23)
    for offset in range(0, len(message), 64):
        w = [
            int.from_bytes(message[offset + i : offset + i + 4], "big")
            for i in range(0, 64, 4)
        ]
        for j in range(16, 68):
            w.append(
                p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
                ^ _rotl(w[j - 13], 7)
                ^ w[j - 6]
            )
        a, b, c, d, e, f, g, h = state
        for j in range(64):
            t = _rotl(0x79CC4519 if j < 16 else 0x7A879D8A, j)
            ss1 = _rotl((_rotl(a, 12) + e + t) & 0xFFFFFFFF, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            ff = a ^ b ^ c if j < 16 else (a & b) | (a & c) | (b & c)
            gg = e ^ f ^ g if j < 16 else (e & f) | (~e & g & 0xFFFFFFFF)
            tt1 = (ff + d + ss2 + (w[j] ^ w[j + 4])) & 0xFFFFFFFF
            tt2 = (gg + h + ss1 + w[j]) & 0xFFFFFFFF
            a, b, c, d = tt1, a, _rotl(b, 9), c
            e, f, g, h = p0(tt2), e, _rotl(f, 19), g
        state = [x ^ y for x, y in zip(state, (a, b, c, d, e, f, g, h))]
    return b"".join(word.to_bytes(4, "big") for word in state)


def _tau(a: int) -> int:
    return int.from_bytes(bytes(SBOX[b] for b in a.to_bytes(4, "big")), "big")


def sm4_round_keys(key: bytes) -> list:
    k = [int.from_bytes(key[i * 4 : i * 4 + 4], "big") ^ _FK[i] for i in range(4)]
    for i in range(32):
        b = _tau(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ _CK[i])
        k.append(k[i] ^ b ^ _rotl(b, 13) ^ _rotl(b, 23))
    return k[4:]


def sm4_block(block: bytes, round_keys: list) -> bytes:
    x = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 16, 4)]
    for i, rk in enumerate(round_keys):
        b = _tau(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk)
        x.append(x[i] ^ b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24))
    return b"".join(word.to_bytes(4, "big") for word in reversed(x[32:]))
