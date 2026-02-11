// 素数域元素实现（模p运算）

use super::bigint256::BigInt256;

/// SM2推荐曲线的素数p
pub const SM2_P: BigInt256 = BigInt256 {
    limbs: [
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFEFFFFFFFF,
    ],
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FpElement {
    pub value: BigInt256,
}

impl FpElement {
    pub fn new(value: BigInt256) -> Self {
        // 确保值在有效范围内
        if value.compare(&SM2_P) != core::cmp::Ordering::Less {
            let reduced = value.mod_sub(&SM2_P, &SM2_P);
            FpElement { value: reduced }
        } else {
            FpElement { value }
        }
    }

    pub fn from_hex(hex: &str) -> Self {
        FpElement::new(BigInt256::from_hex(hex))
    }

    pub fn zero() -> Self {
        FpElement {
            value: BigInt256::ZERO,
        }
    }

    pub fn one() -> Self {
        FpElement {
            value: BigInt256::ONE,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.value.is_zero()
    }

    pub fn is_one(&self) -> bool {
        self.value.is_one()
    }

    /// 加法
    pub fn add(&self, other: &FpElement) -> FpElement {
        FpElement {
            value: self.value.mod_add(&other.value, &SM2_P),
        }
    }

    /// 减法
    pub fn subtract(&self, other: &FpElement) -> FpElement {
        FpElement {
            value: self.value.mod_sub(&other.value, &SM2_P),
        }
    }

    /// 乘法
    pub fn multiply(&self, other: &FpElement) -> FpElement {
        FpElement {
            value: self.value.sm2_mod_mul_p(&other.value),
        }
    }

    /// 平方
    pub fn square(&self) -> FpElement {
        FpElement {
            value: self.value.sm2_mod_square_p(),
        }
    }

    /// 取反
    pub fn negate(&self) -> FpElement {
        if self.is_zero() {
            *self
        } else {
            FpElement {
                value: SM2_P.mod_sub(&self.value, &SM2_P),
            }
        }
    }

    /// 求逆（使用SM2快速约减的费马小定理）
    pub fn invert(&self) -> FpElement {
        if self.is_zero() {
            panic!("Cannot invert zero");
        }
        // a^(-1) = a^(p-2) mod p
        let (p_minus_2, _) = SM2_P.sub(&BigInt256::new([2, 0, 0, 0]));
        let mut result = BigInt256::ONE;
        let mut base = self.value;
        let bit_len = p_minus_2.bit_length();
        for i in 0..bit_len {
            if p_minus_2.get_bit(i) {
                result = result.sm2_mod_mul_p(&base);
            }
            base = base.sm2_mod_square_p();
        }
        FpElement { value: result }
    }

    /// 除法
    pub fn divide(&self, other: &FpElement) -> FpElement {
        self.multiply(&other.invert())
    }

    /// 2倍
    pub fn double(&self) -> FpElement {
        self.add(self)
    }

    /// 3倍
    pub fn triple(&self) -> FpElement {
        self.double().add(self)
    }

    /// 转换为BigInt256
    pub fn to_bigint(&self) -> BigInt256 {
        self.value
    }

    /// 转换为大端字节数组
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
