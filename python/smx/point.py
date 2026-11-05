"""SM2 curve parameters and the public affine point type.

Python's native integers replace the BigInt256/FpElement types used by the
languages without arbitrary-precision arithmetic. The arithmetic and the notes on
timing are in :mod:`smx._ec`.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import _ec
from .hexutil import as_bytes, bytes_to_hex, hex_to_bytes

SM2_P = _ec.P
SM2_A = _ec.A
SM2_B = _ec.B
SM2_N = _ec.N
SM2_GX = _ec.GX
SM2_GY = _ec.GY

_COORD_SIZE = 32
_ENCODED_SIZE = 1 + 2 * _COORD_SIZE
_ENCODED_HEX_SIZE = 2 * _ENCODED_SIZE


@dataclass(frozen=True)
class ECPoint:
    """An immutable affine point with coordinates in [0, p-1].

    Building a point does not check that it is on the curve, so that
    :meth:`is_on_curve` can answer the question, but every arithmetic method does.
    """

    x: int
    y: int
    infinity: bool = False

    def __post_init__(self) -> None:
        for value in (self.x, self.y):
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError("point coordinates must be integers")
            if not 0 <= value < SM2_P:
                raise ValueError("point coordinate is not in Fp")
        if self.infinity is not False and (
            self.infinity is not True or self.x != 0 or self.y != 0
        ):
            raise ValueError("invalid point at infinity")

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
        """Decode exactly ``04 || x || y``; anything else, or an off-curve point, fails."""
        data = as_bytes(data)
        if len(data) != _ENCODED_SIZE or data[0] != 0x04:
            raise ValueError("invalid point encoding")
        x = int.from_bytes(data[1 : 1 + _COORD_SIZE], "big")
        y = int.from_bytes(data[1 + _COORD_SIZE :], "big")
        point = ECPoint(x, y)
        if not point.is_on_curve():
            raise ValueError("point is not on the curve")
        return point

    @staticmethod
    def from_hex_encoded(text: str) -> ECPoint:
        """Decode the 130-digit hex string of ``04 || x || y``."""
        if not isinstance(text, str) or len(text) != _ENCODED_HEX_SIZE:
            raise ValueError("invalid point encoding")
        return ECPoint.from_encoded(hex_to_bytes(text))

    def _fields_are_valid(self) -> bool:
        """Check the fields again, as unpickling can bypass the constructor."""
        x, y, infinity = self.x, self.y, self.infinity
        if type(x) is not int or type(y) is not int or type(infinity) is not bool:
            return False
        if infinity:
            return x == 0 and y == 0
        return 0 <= x < SM2_P and 0 <= y < SM2_P

    def _require_valid_fields(self) -> None:
        if not self._fields_are_valid():
            raise ValueError("invalid point")

    def to_encoded(self) -> bytes:
        """Encode as ``04 || x || y`` (a single 0x00 byte for infinity)."""
        self._require_valid_fields()
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
        self._require_valid_fields()
        return self.x.to_bytes(_COORD_SIZE, "big")

    def y_bytes(self) -> bytes:
        self._require_valid_fields()
        return self.y.to_bytes(_COORD_SIZE, "big")

    def is_on_curve(self) -> bool:
        """Check y^2 = x^3 + ax + b (infinity counts as on the curve)."""
        if not self._fields_are_valid():
            return False
        if self.infinity:
            return True
        return (
            self.y * self.y - ((self.x * self.x + SM2_A) * self.x + SM2_B)
        ) % SM2_P == 0

    def negate(self) -> ECPoint:
        self._require_valid_fields()
        if self.infinity:
            return self
        return ECPoint(self.x, -self.y % SM2_P)

    def _is_valid_public(self) -> bool:
        return self.infinity is False and self.is_on_curve()

    def _require_group_element(self) -> None:
        if not self.is_on_curve():
            raise ValueError("point is not on the curve")

    def add(self, other: ECPoint) -> ECPoint:
        if not isinstance(other, ECPoint):
            raise TypeError("other must be an ECPoint")
        self._require_group_element()
        other._require_group_element()
        if self.infinity:
            return other
        if other.infinity:
            return self
        return ECPoint._from_affine(
            _ec.to_affine_blinded(_ec.add_affine((self.x, self.y, 1), other.x, other.y))
        )

    def subtract(self, other: ECPoint) -> ECPoint:
        if not isinstance(other, ECPoint):
            raise TypeError("other must be an ECPoint")
        return self.add(other.negate())

    def twice(self) -> ECPoint:
        self._require_group_element()
        if self.infinity:
            return _INFINITY
        return ECPoint._from_affine(
            _ec.to_affine_blinded(_ec.double((self.x, self.y, 1)))
        )

    def multiply(self, k: int) -> ECPoint:
        """Return [k]P, treating k as secret; see :mod:`smx._ec` for what that means.

        Every finite on-curve point has the prime order n, so k is reduced modulo n.
        A point that is not on the curve raises ValueError.
        """
        if not isinstance(k, int) or isinstance(k, bool):
            raise TypeError("scalar must be an integer")
        if k < 0:
            raise ValueError("scalar must be non-negative")
        self._require_group_element()
        if k == 0 or self.infinity:
            return _INFINITY
        if k == 1:
            return self
        reduced = k % SM2_N
        if reduced == 0:
            return _INFINITY
        if self.x == SM2_GX and self.y == SM2_GY:
            jacobian = _ec.mul_generator(reduced)
        else:
            jacobian = _ec.mul_point(self.x, self.y, reduced)
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
