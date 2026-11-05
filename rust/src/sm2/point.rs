// 椭圆曲线点实现（仿射坐标 + 内部使用Jacobian坐标加速标量乘法）

use super::bigint256::BigInt256;
use super::curve::{Affine, Jacobian};
use super::field::{P, sub_limbs};
use super::fp::FpElement;
use super::order;
use super::scalar_mul;

/// SM2曲线参数 a
pub const SM2_A: FpElement = FpElement {
    value: BigInt256 {
        limbs: [
            0xFFFFFFFFFFFFFFFC,
            0xFFFFFFFF00000000,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFEFFFFFFFF,
        ],
    },
};

/// SM2曲线参数 b
pub const SM2_B: FpElement = FpElement {
    value: BigInt256 {
        limbs: [
            0xDDBCBD414D940E93,
            0xF39789F515AB8F92,
            0x4D5A9E4BCF6509A7,
            0x28E9FA9E9D9F5E34,
        ],
    },
};

/// SM2基点 G 的 x 坐标
pub const SM2_GX: FpElement = FpElement {
    value: BigInt256 {
        limbs: [
            0x715A4589334C74C7,
            0x8FE30BBFF2660BE1,
            0x5F9904466A39C994,
            0x32C4AE2C1F198119,
        ],
    },
};

/// SM2基点 G 的 y 坐标
pub const SM2_GY: FpElement = FpElement {
    value: BigInt256 {
        limbs: [
            0x02DF32E52139F0A0,
            0xD0A9877CC62A4740,
            0x59BDCEE36B692153,
            0xBC3736A2F4F6779C,
        ],
    },
};

/// SM2曲线阶 n
pub const SM2_N: BigInt256 = BigInt256 { limbs: order::N };

/// 椭圆曲线点（仿射坐标）
///
/// The fields are public, so a value of this type need not be a valid point. Every operation
/// checks that it is (coordinates below p, on the curve) and treats anything else as invalid.
/// Without a way to report failure in their signatures, parsers and group operations return the
/// infinity point for invalid input, and all protocol entry points reject infinity. `is_on_curve`
/// is the complete validity check for a public key.
#[derive(Clone, Debug)]
pub struct ECPoint {
    pub x: FpElement,
    pub y: FpElement,
    pub infinity: bool,
}

impl ECPoint {
    /// 创建新的点
    #[inline]
    pub fn new(x: FpElement, y: FpElement) -> Self {
        ECPoint {
            x,
            y,
            infinity: false,
        }
    }

    /// 创建无穷远点
    #[inline]
    pub fn infinity() -> Self {
        ECPoint {
            x: FpElement::zero(),
            y: FpElement::zero(),
            infinity: true,
        }
    }

    /// 获取基点G
    #[inline]
    pub fn generator() -> Self {
        ECPoint::new(SM2_GX, SM2_GY)
    }

    /// 判断是否为无穷远点
    #[inline]
    pub fn is_infinity(&self) -> bool {
        self.infinity
    }

    /// 从十六进制坐标创建点
    ///
    /// Each coordinate must be exactly 64 hex digits, and the point valid; otherwise infinity.
    pub fn from_hex(x_hex: &str, y_hex: &str) -> Self {
        let parsed = BigInt256::from_fixed_hex(x_hex.as_bytes())
            .zip(BigInt256::from_fixed_hex(y_hex.as_bytes()))
            .map(|(x, y)| ECPoint {
                x: FpElement { value: x },
                y: FpElement { value: y },
                infinity: false,
            });
        match parsed {
            Some(point) if point.is_on_curve() => point,
            _ => ECPoint::infinity(),
        }
    }

    /// 从编码的字节解码点（04||x||y格式）; infinity for anything but a valid point.
    pub fn from_encoded(data: &[u8]) -> Self {
        Self::try_from_encoded(data).unwrap_or_else(ECPoint::infinity)
    }

    /// 从十六进制编码解码点; infinity for anything but a valid point.
    pub fn from_hex_encoded(hex: &str) -> Self {
        Self::try_from_hex_encoded(hex).unwrap_or_else(ECPoint::infinity)
    }

    /// Decodes exactly 65 bytes `04 || x || y` of a valid point: x, y below p and on the curve.
    pub fn try_from_encoded(data: &[u8]) -> Option<Self> {
        if data.len() != 65 || data[0] != 0x04 {
            return None;
        }
        let point = ECPoint {
            x: FpElement {
                value: BigInt256::from_be_bytes(&data[1..33]),
            },
            y: FpElement {
                value: BigInt256::from_be_bytes(&data[33..65]),
            },
            infinity: false,
        };
        point.is_on_curve().then_some(point)
    }

    /// Decodes exactly 130 hex digits (either case, no prefix) of a valid point.
    pub fn try_from_hex_encoded(hex: &str) -> Option<Self> {
        if hex.len() != 130 {
            return None;
        }
        let mut bytes = [0u8; 65];
        if !crate::hex::decode_into(hex.as_bytes(), &mut bytes) {
            return None;
        }
        Self::try_from_encoded(&bytes)
    }

    /// 编码点为字节数组（04||x||y格式）
    pub fn to_encoded(&self) -> Vec<u8> {
        if self.infinity {
            return vec![0x00];
        }
        let mut result = Vec::with_capacity(65);
        result.push(0x04);
        result.extend_from_slice(&self.x.to_be_bytes());
        result.extend_from_slice(&self.y.to_be_bytes());
        result
    }

    /// 编码为十六进制字符串
    pub fn to_hex_encoded(&self) -> String {
        if self.infinity {
            return "00".to_string();
        }
        let mut s = String::with_capacity(130);
        self.push_hex_encoded(&mut s);
        s
    }

    /// Appends the lower-case uncompressed encoding; the point must be finite.
    pub(crate) fn push_hex_encoded(&self, out: &mut String) {
        out.push_str("04");
        crate::hex::push_lower(out, &self.x.to_be_bytes());
        crate::hex::push_lower(out, &self.y.to_be_bytes());
    }

    /// 取反
    pub fn negate(&self) -> Self {
        if self.checked_affine().is_none() {
            return ECPoint::infinity();
        }
        ECPoint {
            x: self.x,
            y: self.y.negate(),
            infinity: false,
        }
    }

    /// Internal coordinates of a valid finite point.
    #[inline]
    pub(crate) fn checked_affine(&self) -> Option<Affine> {
        if self.infinity {
            return None;
        }
        let affine = Affine {
            x: self.x.value.limbs,
            y: self.y.value.limbs,
        };
        let below_p = sub_limbs(&affine.x, &P).1 & sub_limbs(&affine.y, &P).1;
        (below_p == 1 && scalar_mul::is_on_curve(&affine)).then_some(affine)
    }

    /// Internal coordinates of a point the caller already validated.
    #[inline]
    fn affine(&self) -> Affine {
        Affine {
            x: self.x.value.limbs,
            y: self.y.value.limbs,
        }
    }

    #[inline]
    fn from_jacobian(point: &Jacobian) -> ECPoint {
        match point.to_affine() {
            Some(affine) => ECPoint::new(
                FpElement {
                    value: BigInt256::new(affine.x),
                },
                FpElement {
                    value: BigInt256::new(affine.y),
                },
            ),
            None => ECPoint::infinity(),
        }
    }

    /// 点加法. An invalid operand gives infinity.
    #[allow(clippy::should_implement_trait)] // public name kept for API compatibility
    pub fn add(&self, other: &ECPoint) -> ECPoint {
        match (self.infinity, other.infinity) {
            (true, true) => ECPoint::infinity(),
            (true, false) => other.checked_copy(),
            (false, true) => self.checked_copy(),
            (false, false) => match (self.checked_affine(), other.checked_affine()) {
                // 使用Jacobian坐标计算后转回仿射
                (Some(a), Some(b)) => Self::from_jacobian(&a.to_jacobian().add_mixed_vartime(&b)),
                _ => ECPoint::infinity(),
            },
        }
    }

    /// The point itself when valid, otherwise infinity.
    fn checked_copy(&self) -> ECPoint {
        if self.checked_affine().is_some() {
            self.clone()
        } else {
            ECPoint::infinity()
        }
    }

    /// 点倍乘（P + P）
    pub fn twice(&self) -> ECPoint {
        match self.checked_affine() {
            Some(affine) => Self::from_jacobian(&affine.to_jacobian().double()),
            None => ECPoint::infinity(),
        }
    }

    /// 减法
    pub fn subtract(&self, other: &ECPoint) -> ECPoint {
        if other.infinity {
            return self.checked_copy();
        }
        let negated = other.negate();
        if negated.infinity {
            return ECPoint::infinity();
        }
        self.add(&negated)
    }

    /// 标量乘法：常数时间（对标量k），基点G使用预计算表
    ///
    /// An invalid point gives infinity: multiplying a secret scalar with a point off the curve
    /// would leak it (invalid-curve attack).
    pub fn multiply(&self, k: &BigInt256) -> ECPoint {
        if !self.infinity && self.x == SM2_GX && self.y == SM2_GY {
            return Self::from_jacobian(&scalar_mul::mul_base(&k.limbs));
        }
        match self.checked_affine() {
            Some(affine) => Self::from_jacobian(&scalar_mul::mul_ct(&affine, &k.limbs)),
            None => ECPoint::infinity(),
        }
    }

    /// [k]self for a public scalar, in variable time. The point must be valid and finite.
    pub(crate) fn multiply_public(&self, k: &BigInt256) -> ECPoint {
        Self::from_jacobian(&scalar_mul::mul_public(&self.affine(), &k.limbs))
    }

    /// [s]G + [t]self for public scalars, in variable time. The point must be valid and finite.
    pub(crate) fn base_mul_add_public(&self, s: &BigInt256, t: &BigInt256) -> ECPoint {
        let affine = self.affine();
        Self::from_jacobian(&scalar_mul::mul_base_and_public(
            &s.limbs,
            &t.limbs,
            Some(&affine),
        ))
    }

    /// 验证点在曲线上: a valid public key, meaning finite, with both coordinates below p and
    /// satisfying the curve equation. Infinity is not a valid key, so this returns false for it.
    pub fn is_on_curve(&self) -> bool {
        self.checked_affine().is_some()
    }
}

impl PartialEq for ECPoint {
    fn eq(&self, other: &Self) -> bool {
        if self.infinity && other.infinity {
            return true;
        }
        if self.infinity || other.infinity {
            return false;
        }
        self.x == other.x && self.y == other.y
    }
}

impl Eq for ECPoint {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_on_curve() {
        let g = ECPoint::generator();
        assert!(g.is_on_curve());
    }

    #[test]
    fn test_point_add() {
        let g = ECPoint::generator();
        let g2 = g.add(&g);
        assert!(g2.is_on_curve());
        let g3 = g2.add(&g);
        assert!(g3.is_on_curve());
    }

    #[test]
    fn test_point_twice() {
        let g = ECPoint::generator();
        let g2a = g.twice();
        let g2b = g.add(&g);
        assert_eq!(g2a, g2b);
    }

    #[test]
    fn test_point_multiply() {
        let g = ECPoint::generator();
        let k = BigInt256::from_hex("3");
        let p = g.multiply(&k);
        assert!(p.is_on_curve());

        let g2 = g.twice();
        let g3 = g2.add(&g);
        assert_eq!(p, g3);
    }

    #[test]
    fn test_point_encode_decode() {
        let g = ECPoint::generator();
        let encoded = g.to_encoded();
        let decoded = ECPoint::from_encoded(&encoded);
        assert_eq!(g, decoded);
    }

    #[test]
    fn test_infinity() {
        let g = ECPoint::generator();
        let neg_g = g.negate();
        let result = g.add(&neg_g);
        assert!(result.is_infinity());
    }
}
