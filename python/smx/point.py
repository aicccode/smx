"""SM2 curve parameters and the public affine point type.

Python's native integers replace the BigInt256/FpElement types used by the
languages without arbitrary-precision arithmetic. The arithmetic and the notes on
timing are in :mod:`smx._ec`.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import _ec
from .hexutil import bytes_to_hex, hex_to_bytes

SM2_P = _ec.P
SM2_A = _ec.A
SM2_B = _ec.B
SM2_N = _ec.N
SM2_GX = _ec.GX
SM2_GY = _ec.GY

_COORD_SIZE = 32
_ENCODED_SIZE = 1 + 2 * _COORD_SIZE


@dataclass(frozen=True)
class ECPoint:
    """An immutable affine point on the SM2 curve."""

    x: int
    y: int
    infinity: bool = False

    @staticmethod
    def at_infinity() -> ECPoint:
        return _INFINITY

    @staticmethod
    def generator() -> ECPoint:
        return _GENERATOR

    @staticmethod
    def _from_affine(affine) -> ECPoint:
        return _INFINITY if affine is None else ECPoint(*affine)

    @staticmethod
    def from_encoded(data: bytes) -> ECPoint:
        """Decode ``04 || x || y``; empty input decodes to infinity."""
        if not data:
            return _INFINITY
        if data[0] != 0x04 or len(data) != _ENCODED_SIZE:
            raise ValueError("invalid point encoding")
        x = int.from_bytes(data[1 : 1 + _COORD_SIZE], "big")
        y = int.from_bytes(data[1 + _COORD_SIZE :], "big")
        if x >= SM2_P or y >= SM2_P:
            raise ValueError("point coordinate is not in Fp")
        return ECPoint(x, y)

    @staticmethod
    def from_hex_encoded(text: str) -> ECPoint:
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

    def negate(self) -> ECPoint:
        if self.infinity:
            return self
        return ECPoint(self.x, -self.y % SM2_P)

    def add(self, other: ECPoint) -> ECPoint:
        if self.infinity:
            return other
        if other.infinity:
            return self
        return ECPoint._from_affine(
            _ec.to_affine_blinded(_ec.add_affine((self.x, self.y, 1), other.x, other.y))
        )

    def subtract(self, other: ECPoint) -> ECPoint:
        return self.add(other.negate())

    def twice(self) -> ECPoint:
        if self.infinity or self.y == 0:
            return _INFINITY
        return ECPoint._from_affine(
            _ec.to_affine_blinded(_ec.double((self.x, self.y, 1)))
        )

    def multiply(self, k: int) -> ECPoint:
        """Return [k]P, treating k as secret; see :mod:`smx._ec` for what that means.

        Every finite on-curve point has the prime order n, so k is reduced modulo n.
        An off-curve point has an unrelated order and takes a generic path instead.
        """
        if k < 0:
            raise ValueError("scalar must be non-negative")
        if k == 0 or self.infinity:
            return _INFINITY
        if k == 1:
            return self
        if not self.is_on_curve():
            jacobian = _ec.mul_double_and_add(self.x, self.y, k)
            return ECPoint._from_affine(_ec.to_affine_blinded(jacobian))
        reduced = k % SM2_N
        if reduced == 0:
            return _INFINITY
        x, y = self.x % SM2_P, self.y % SM2_P
        if x == SM2_GX and y == SM2_GY:
            jacobian = _ec.mul_generator(reduced)
        else:
            jacobian = _ec.mul_point(x, y, reduced)
        return ECPoint._from_affine(_ec.to_affine_blinded(jacobian))

    def _multiply_cached(self, k: int) -> ECPoint:
        """Like :meth:`multiply`, reusing tables for this long-lived public key.

        The point must be public and on the curve, and k must be in [1, n-1].
        """
        table = _ec.cached_key_tables(self.x, self.y).packed
        jacobian = _ec.mul_point_with_table(self.x, self.y, k, table)
        return ECPoint._from_affine(_ec.to_affine_blinded(jacobian))


_INFINITY = ECPoint(0, 0, True)
_GENERATOR = ECPoint(SM2_GX, SM2_GY)
