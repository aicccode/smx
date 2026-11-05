// 椭圆曲线点实现（仿射坐标 + 内部使用Jacobian坐标加速标量乘法）

use super::bigint256::BigInt256;
use super::curve::{Affine, Jacobian};
use super::field::{P, reduce_once};
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
    pub fn from_hex(x_hex: &str, y_hex: &str) -> Self {
        ECPoint::new(FpElement::from_hex(x_hex), FpElement::from_hex(y_hex))
    }

    /// 从编码的字节解码点（04||x||y格式）
    pub fn from_encoded(data: &[u8]) -> Self {
        if data.is_empty() {
            return ECPoint::infinity();
        }
        if data[0] != 0x04 {
            panic!("Only uncompressed point format is supported");
        }
        if data.len() != 65 {
            panic!("Invalid point encoding length");
        }
        let x = FpElement::new(BigInt256::from_be_bytes(&data[1..33]));
        let y = FpElement::new(BigInt256::from_be_bytes(&data[33..65]));
        ECPoint::new(x, y)
    }

    /// 从十六进制编码解码点
    pub fn from_hex_encoded(hex: &str) -> Self {
        let digits = hex.trim_start_matches("0x").trim_start_matches("0X");
        // The usual encoding needs no heap at all.
        if digits.len() == 130 {
            let mut bytes = [0u8; 65];
            if crate::hex::decode_into(digits.as_bytes(), &mut bytes) {
                return Self::from_encoded(&bytes);
            }
        }
        // Everything else keeps the historic parse: invalid pairs read as 0, an odd trailing
        // digit is ignored.
        let mut bytes = Vec::with_capacity(digits.len() / 2);
        for i in 0..digits.len() / 2 {
            let byte = u8::from_str_radix(&digits[i * 2..i * 2 + 2], 16).unwrap_or(0);
            bytes.push(byte);
        }
        Self::from_encoded(&bytes)
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
        if self.infinity {
            return ECPoint::infinity();
        }
        ECPoint {
            x: self.x,
            y: self.y.negate(),
            infinity: false,
        }
    }

    /// Field limbs for the internal arithmetic. The public `value` field can hold a coordinate
    /// that was never reduced, which the internal formulas do not expect.
    #[inline]
    fn affine(&self) -> Affine {
        Affine {
            x: reduce_once(&self.x.value.limbs, &P),
            y: reduce_once(&self.y.value.limbs, &P),
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

    /// 点加法
    #[allow(clippy::should_implement_trait)] // public name kept for API compatibility
    pub fn add(&self, other: &ECPoint) -> ECPoint {
        if self.infinity {
            return other.clone();
        }
        if other.infinity {
            return self.clone();
        }

        // 使用Jacobian坐标计算后转回仿射
        Self::from_jacobian(
            &self
                .affine()
                .to_jacobian()
                .add_mixed_vartime(&other.affine()),
        )
    }

    /// 点倍乘（P + P）
    pub fn twice(&self) -> ECPoint {
        if self.infinity {
            return ECPoint::infinity();
        }
        Self::from_jacobian(&self.affine().to_jacobian().double())
    }

    /// 减法
    pub fn subtract(&self, other: &ECPoint) -> ECPoint {
        self.add(&other.negate())
    }

    /// 标量乘法：常数时间（对标量k），基点G使用预计算表
    pub fn multiply(&self, k: &BigInt256) -> ECPoint {
        if self.infinity {
            return ECPoint::infinity();
        }
        if self.x == SM2_GX && self.y == SM2_GY {
            return Self::from_jacobian(&scalar_mul::mul_base(&k.limbs));
        }
        Self::from_jacobian(&scalar_mul::mul_ct(&self.affine(), &k.limbs))
    }

    /// [k]self for a public scalar, in variable time. The point must be on the curve.
    pub(crate) fn multiply_public(&self, k: &BigInt256) -> ECPoint {
        if self.infinity {
            return ECPoint::infinity();
        }
        Self::from_jacobian(&scalar_mul::mul_public(&self.affine(), &k.limbs))
    }

    /// [s]G + [t]self for public scalars, in variable time. The point must be on the curve.
    pub(crate) fn base_mul_add_public(&self, s: &BigInt256, t: &BigInt256) -> ECPoint {
        let affine = self.affine();
        let point = (!self.infinity).then_some(&affine);
        Self::from_jacobian(&scalar_mul::mul_base_and_public(&s.limbs, &t.limbs, point))
    }

    /// 验证点在曲线上
    pub fn is_on_curve(&self) -> bool {
        self.infinity || scalar_mul::is_on_curve(&self.affine())
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
