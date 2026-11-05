// 素数域元素实现（模p运算）

use super::bigint256::BigInt256;
use super::field;
use super::modinv::{self, MOD_P};

/// SM2推荐曲线的素数p
pub const SM2_P: BigInt256 = BigInt256 { limbs: field::P };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpElement {
    pub value: BigInt256,
}

impl FpElement {
    #[inline]
    pub fn new(value: BigInt256) -> Self {
        // 确保值在有效范围内
        FpElement {
            value: BigInt256::new(field::reduce_once(&value.limbs, &SM2_P.limbs)),
        }
    }

    pub fn from_hex(hex: &str) -> Self {
        FpElement::new(BigInt256::from_hex(hex))
    }

    #[inline]
    pub fn zero() -> Self {
        FpElement {
            value: BigInt256::ZERO,
        }
    }

    #[inline]
    pub fn one() -> Self {
        FpElement {
            value: BigInt256::ONE,
        }
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.value.is_zero()
    }

    #[inline]
    pub fn is_one(&self) -> bool {
        self.value.is_one()
    }

    /// 加法
    #[inline]
    #[allow(clippy::should_implement_trait)] // public name kept for API compatibility
    pub fn add(&self, other: &FpElement) -> FpElement {
        FpElement {
            value: BigInt256::new(field::fe_add(&self.value.limbs, &other.value.limbs)),
        }
    }

    /// 减法
    #[inline]
    pub fn subtract(&self, other: &FpElement) -> FpElement {
        FpElement {
            value: BigInt256::new(field::fe_sub(&self.value.limbs, &other.value.limbs)),
        }
    }

    /// 乘法
    #[inline]
    pub fn multiply(&self, other: &FpElement) -> FpElement {
        FpElement {
            value: self.value.sm2_mod_mul_p(&other.value),
        }
    }

    /// 平方
    #[inline]
    pub fn square(&self) -> FpElement {
        FpElement {
            value: self.value.sm2_mod_square_p(),
        }
    }

    /// 取反
    #[inline]
    pub fn negate(&self) -> FpElement {
        let limbs = &self.value.limbs;
        let negated = field::fe_sub(&SM2_P.limbs, limbs);
        FpElement {
            value: BigInt256::new(field::select(field::is_zero_mask(limbs), limbs, &negated)),
        }
    }

    /// 求逆（常数时间的 safegcd 算法）
    pub fn invert(&self) -> FpElement {
        if self.is_zero() {
            panic!("Cannot invert zero");
        }
        let reduced = field::reduce_once(&self.value.limbs, &SM2_P.limbs);
        FpElement {
            value: BigInt256::new(modinv::invert(&reduced, &MOD_P)),
        }
    }

    /// 除法
    pub fn divide(&self, other: &FpElement) -> FpElement {
        self.multiply(&other.invert())
    }

    /// 2倍
    #[inline]
    pub fn double(&self) -> FpElement {
        self.add(self)
    }

    /// 3倍
    #[inline]
    pub fn triple(&self) -> FpElement {
        self.double().add(self)
    }

    /// 转换为BigInt256
    #[inline]
    pub fn to_bigint(&self) -> BigInt256 {
        self.value
    }

    /// 转换为大端字节数组
    #[inline]
    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.value.to_be_bytes()
    }

    /// 转换为十六进制字符串
    pub fn to_hex(&self) -> String {
        self.value.to_hex()
    }
}

impl Default for FpElement {
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp_add() {
        let a = FpElement::from_hex("1");
        let b = FpElement::from_hex("2");
        let c = a.add(&b);
        assert_eq!(c.value, BigInt256::from_hex("3"));
    }

    #[test]
    fn test_fp_sub() {
        let a = FpElement::from_hex("5");
        let b = FpElement::from_hex("3");
        let c = a.subtract(&b);
        assert_eq!(c.value, BigInt256::from_hex("2"));
    }

    #[test]
    fn test_fp_mul() {
        let a = FpElement::from_hex("3");
        let b = FpElement::from_hex("4");
        let c = a.multiply(&b);
        assert_eq!(c.value, BigInt256::from_hex("C"));
    }

    #[test]
    fn test_fp_invert() {
        let a = FpElement::from_hex("3");
        let inv = a.invert();
        let product = a.multiply(&inv);
        assert!(product.is_one());
    }

    #[test]
    fn test_fp_negate() {
        let a = FpElement::from_hex("1");
        let neg = a.negate();
        let sum = a.add(&neg);
        assert!(sum.is_zero());
    }
}
