"""SM2 curve parameters and point arithmetic in Jacobian coordinates.

Python's native integers replace the BigInt256/FpElement types used by the
languages without arbitrary-precision arithmetic; the point formulas are the
same (a = -3 doubling and mixed Jacobian + affine addition).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from .hexutil import bytes_to_hex, hex_to_bytes

SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

_COORD_SIZE = 32
_ENCODED_SIZE = 1 + 2 * _COORD_SIZE

_Jacobian = Tuple[int, int, int]
_JACOBIAN_INFINITY: _Jacobian = (1, 1, 0)


def _double(point: _Jacobian) -> _Jacobian:
    x1, y1, z1 = point
    if z1 == 0 or y1 == 0:
        return _JACOBIAN_INFINITY

    delta = z1 * z1 % SM2_P
    gamma = y1 * y1 % SM2_P
    beta = x1 * gamma % SM2_P
    alpha = 3 * (x1 - delta) * (x1 + delta) % SM2_P

    x3 = (alpha * alpha - 8 * beta) % SM2_P
    z3 = ((y1 + z1) ** 2 - gamma - delta) % SM2_P
    y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % SM2_P
    return (x3, y3, z3)


def _add_affine(point: _Jacobian, x2: int, y2: int) -> _Jacobian:
    x1, y1, z1 = point
    if z1 == 0:
        return (x2, y2, 1)

    z1z1 = z1 * z1 % SM2_P
    h = (x2 * z1z1 - x1) % SM2_P
    r = (y2 * z1 * z1z1 - y1) % SM2_P
    if h == 0:
        return _double(point) if r == 0 else _JACOBIAN_INFINITY

    hh = h * h % SM2_P
    hhh = hh * h % SM2_P
    x1hh = x1 * hh % SM2_P
    x3 = (r * r - hhh - 2 * x1hh) % SM2_P
    y3 = (r * (x1hh - x3) - y1 * hhh) % SM2_P
    z3 = z1 * h % SM2_P
    return (x3, y3, z3)


@dataclass(frozen=True)
class ECPoint:
    """An immutable affine point on the SM2 curve."""

    x: int
    y: int
    infinity: bool = False

    @staticmethod
    def at_infinity() -> "ECPoint":
        return ECPoint(0, 0, True)

    @staticmethod
    def generator() -> "ECPoint":
        return ECPoint(SM2_GX, SM2_GY)

    @staticmethod
    def _from_jacobian(point: _Jacobian) -> "ECPoint":
        x, y, z = point
        if z == 0:
            return ECPoint.at_infinity()
        z_inv = pow(z, SM2_P - 2, SM2_P)
        z_inv2 = z_inv * z_inv % SM2_P
        return ECPoint(x * z_inv2 % SM2_P, y * z_inv2 * z_inv % SM2_P)

    @staticmethod
    def from_encoded(data: bytes) -> "ECPoint":
        """Decode ``04 || x || y``; empty input decodes to infinity."""
        if not data:
            return ECPoint.at_infinity()
        if data[0] != 0x04 or len(data) != _ENCODED_SIZE:
            raise ValueError("invalid point encoding")
        x = int.from_bytes(data[1 : 1 + _COORD_SIZE], "big")
        y = int.from_bytes(data[1 + _COORD_SIZE :], "big")
        if x >= SM2_P or y >= SM2_P:
            raise ValueError("point coordinate is not in Fp")
        return ECPoint(x, y)

    @staticmethod
    def from_hex_encoded(text: str) -> "ECPoint":
        """Decode a hex string of ``04 || x || y``."""
        return ECPoint.from_encoded(hex_to_bytes(text))

    def to_encoded(self) -> bytes:
        """Encode as ``04 || x || y`` (a single 0x00 byte for infinity)."""
        if self.infinity:
            return b"\x00"
        return (
            b"\x04"
            + self.x.to_bytes(_COORD_SIZE, "big")
            + self.y.to_bytes(_COORD_SIZE, "big")
        )

    def to_hex_encoded(self) -> str:
        """Encode as a lowercase hex string."""
        return bytes_to_hex(self.to_encoded())

    def x_bytes(self) -> bytes:
        return self.x.to_bytes(_COORD_SIZE, "big")

    def y_bytes(self) -> bytes:
        return self.y.to_bytes(_COORD_SIZE, "big")

    def is_on_curve(self) -> bool:
        """Check y^2 = x^3 + ax + b (infinity counts as on the curve)."""
        if self.infinity:
            return True
        return (
            self.y * self.y - ((self.x * self.x + SM2_A) * self.x + SM2_B)
        ) % SM2_P == 0

    def negate(self) -> "ECPoint":
        if self.infinity:
            return self
        return ECPoint(self.x, -self.y % SM2_P)

    def add(self, other: "ECPoint") -> "ECPoint":
        if self.infinity:
            return other
        if other.infinity:
            return self
        return ECPoint._from_jacobian(
            _add_affine((self.x, self.y, 1), other.x, other.y)
        )

    def subtract(self, other: "ECPoint") -> "ECPoint":
        return self.add(other.negate())

    def twice(self) -> "ECPoint":
        if self.infinity or self.y == 0:
            return ECPoint.at_infinity()
        return ECPoint._from_jacobian(_double((self.x, self.y, 1)))

    def multiply(self, k: int) -> "ECPoint":
        """Return [k]P using left-to-right double-and-add."""
        if k < 0:
            raise ValueError("scalar must be non-negative")
        if k == 0 or self.infinity:
            return ECPoint.at_infinity()
        if k == 1:
            return self

        result = _JACOBIAN_INFINITY
        for i in range(k.bit_length() - 1, -1, -1):
            result = _double(result)
            if (k >> i) & 1:
                result = _add_affine(result, self.x, self.y)
        return ECPoint._from_jacobian(result)
