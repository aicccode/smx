// 256位无符号整数实现（使用4个u64存储，小端序）

use super::field::{self, Limbs};
use super::modinv::{self, MOD_N, MOD_P};
use super::order::{self, N};
use crate::ct::{ct_barrier, wipe};
use crate::hex;
use core::cmp::Ordering;
use core::fmt;

/// Also used for private keys, hence the `Debug` that shows no value and the `==` that compares
/// all limbs without stopping early.
#[derive(Clone, Copy)]
pub struct BigInt256 {
    pub limbs: [u64; 4], // 小端序：limbs[0]是最低64位
}

impl BigInt256 {
    pub const ZERO: BigInt256 = BigInt256 {
        limbs: [0, 0, 0, 0],
    };
    pub const ONE: BigInt256 = BigInt256 {
        limbs: [1, 0, 0, 0],
    };

    #[inline]
    pub fn new(limbs: [u64; 4]) -> Self {
        BigInt256 { limbs }
    }

    /// 从十六进制字符串解析（大端表示）
    ///
    /// Up to 64 hex digits with an optional single "0x"/"0X" prefix. This signature cannot report
    /// failure, so anything else gives `BigInt256::ZERO`, which no key or scalar check accepts.
    /// Use `try_from_hex` to tell the two apart.
    pub fn from_hex(hex: &str) -> Self {
        Self::try_from_hex(hex).unwrap_or(Self::ZERO)
    }

    /// `from_hex` that reports invalid input. Examines every digit before deciding.
    pub fn try_from_hex(hex: &str) -> Option<Self> {
        let digits = hex
            .strip_prefix("0x")
            .or_else(|| hex.strip_prefix("0X"))
            .unwrap_or(hex)
            .as_bytes();
        if digits.is_empty() || digits.len() > 64 {
            return None;
        }
        let mut limbs = [0u64; 4];
        let mut invalid = 0i32;
        for (i, &c) in digits.iter().rev().enumerate() {
            let (nibble, bad) = hex::ascii_to_nibble(c);
            limbs[i / 16] |= u64::from(nibble) << (4 * (i % 16));
            invalid |= bad;
        }
        (invalid == 0).then_some(BigInt256 { limbs })
    }

    /// Exactly 64 hex digits of either case, with no prefix: the form of keys and signature parts.
    pub(crate) fn from_fixed_hex(hex: &[u8]) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        let valid = hex::decode_into(hex, &mut bytes);
        let value = Self::from_be_bytes(&bytes);
        wipe(&mut bytes, [0; 32]);
        valid.then_some(value)
    }

    /// 从大端字节数组解析
    ///
    /// Shorter input is left-padded with zeros. More than 32 bytes does not fit and gives
    /// `BigInt256::ZERO`.
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        if bytes.len() > 32 {
            return Self::ZERO;
        }
        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(bytes);
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().rev().zip(padded.chunks_exact(8)) {
            *limb = u64::from_be_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
        }
        wipe(&mut padded, [0; 32]);
        BigInt256 { limbs }
    }

    /// 转换为大端字节数组
    #[inline]
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (chunk, limb) in bytes.chunks_exact_mut(8).zip(self.limbs.iter().rev()) {
            chunk.copy_from_slice(&limb.to_be_bytes());
        }
        bytes
    }

    /// 转换为十六进制字符串（大写）
    pub fn to_hex(&self) -> String {
        hex::encode_upper(&self.to_be_bytes())
    }

    /// 转换为十六进制字符串（小写）
    pub fn to_hex_lower(&self) -> String {
        hex::encode_lower(&self.to_be_bytes())
    }

    /// 判断是否为零
    #[inline]
    pub fn is_zero(&self) -> bool {
        field::is_zero_mask(&self.limbs) != 0
    }

    /// 判断是否为1
    #[inline]
    pub fn is_one(&self) -> bool {
        let l = &self.limbs;
        ((l[0] ^ 1) | l[1] | l[2] | l[3]) == 0
    }

    /// 比较两个BigInt256
    #[inline]
    pub fn compare(&self, other: &BigInt256) -> Ordering {
        // Whichever subtraction borrows has the smaller first operand; independent of the data.
        let (_, less) = field::sub_limbs(&self.limbs, &other.limbs);
        let (_, greater) = field::sub_limbs(&other.limbs, &self.limbs);
        (greater as i32 - less as i32).cmp(&0)
    }

    /// 加法，返回(结果, 进位)
    #[inline]
    #[allow(clippy::should_implement_trait)] // public name kept for API compatibility
    pub fn add(&self, other: &BigInt256) -> (BigInt256, bool) {
        let (limbs, carry) = field::add_limbs(&self.limbs, &other.limbs);
        (BigInt256 { limbs }, carry != 0)
    }

    /// 减法，返回(结果, 借位)
    #[inline]
    #[allow(clippy::should_implement_trait)] // public name kept for API compatibility
    pub fn sub(&self, other: &BigInt256) -> (BigInt256, bool) {
        let (limbs, borrow) = field::sub_limbs(&self.limbs, &other.limbs);
        (BigInt256 { limbs }, borrow != 0)
    }

    /// 乘法，返回512位结果（使用8个u64）
    #[inline]
    #[allow(clippy::should_implement_trait)] // public name kept for API compatibility
    pub fn mul(&self, other: &BigInt256) -> [u64; 8] {
        field::mul_wide(&self.limbs, &other.limbs)
    }

    /// 模加法
    ///
    /// Subtracts the modulus at most once, so inputs at or above the modulus can give a result
    /// that still is.
    #[inline]
    pub fn mod_add(&self, other: &BigInt256, modulus: &BigInt256) -> BigInt256 {
        BigInt256 {
            limbs: field::add_mod(&self.limbs, &other.limbs, &modulus.limbs),
        }
    }

    /// 模减法
    #[inline]
    pub fn mod_sub(&self, other: &BigInt256, modulus: &BigInt256) -> BigInt256 {
        BigInt256 {
            limbs: field::sub_mod(&self.limbs, &other.limbs, &modulus.limbs),
        }
    }

    /// 模乘法
    ///
    /// Constant time for the SM2 moduli p and n, which have dedicated reductions. Other moduli
    /// use a general variable-time division, so they are not for secrets. A zero modulus gives
    /// zero.
    pub fn mod_mul(&self, other: &BigInt256, modulus: &BigInt256) -> BigInt256 {
        if modulus.is_zero() {
            return Self::ZERO;
        }
        let limbs = if modulus.limbs == N {
            order::mul_mod_n(&self.limbs, &other.limbs)
        } else if modulus.limbs == field::P {
            field::fe_mul(&self.limbs, &other.limbs)
        } else {
            reduce_wide_generic(&self.mul(other), &modulus.limbs)
        };
        BigInt256 { limbs }
    }

    /// 模平方
    pub fn mod_square(&self, modulus: &BigInt256) -> BigInt256 {
        if modulus.limbs == field::P {
            self.sm2_mod_square_p()
        } else {
            self.mod_mul(self, modulus)
        }
    }

    /// SM2专用：模乘法（使用快速约减）
    #[inline]
    pub fn sm2_mod_mul_p(&self, other: &BigInt256) -> BigInt256 {
        BigInt256 {
            limbs: field::fe_mul(&self.limbs, &other.limbs),
        }
    }

    /// SM2专用：模平方（使用快速约减）
    #[inline]
    pub fn sm2_mod_square_p(&self) -> BigInt256 {
        BigInt256 {
            limbs: field::fe_sqr(&self.limbs),
        }
    }

    /// 模逆
    ///
    /// Constant-time safegcd for the SM2 moduli. For other moduli, a^(m-2) by Fermat's little
    /// theorem, in variable time. Where no inverse exists (zero, a zero modulus, or a composite
    /// modulus that Fermat does not work for) the result is zero.
    pub fn mod_inverse(&self, modulus: &BigInt256) -> BigInt256 {
        if self.is_zero() || modulus.is_zero() {
            return Self::ZERO;
        }
        if modulus.limbs == N {
            let reduced = field::reduce_once(&self.limbs, &N);
            return BigInt256::new(modinv::invert(&reduced, &MOD_N));
        }
        if modulus.limbs == field::P {
            let reduced = field::reduce_once(&self.limbs, &field::P);
            return BigInt256::new(modinv::invert(&reduced, &MOD_P));
        }

        // 使用费马小定理: a^(-1) = a^(p-2) mod p
        let (p_minus_2, _) = modulus.sub(&BigInt256::new([2, 0, 0, 0]));
        let candidate = self.mod_pow(&p_minus_2, modulus);
        let one = Self::ONE.mod_mul(&Self::ONE, modulus);
        if self.mod_mul(&candidate, modulus) == one {
            candidate
        } else {
            Self::ZERO
        }
    }

    /// 模幂运算 (base^exp mod modulus); variable time in the exponent, so not for secret exponents.
    pub fn mod_pow(&self, exp: &BigInt256, modulus: &BigInt256) -> BigInt256 {
        if exp.is_zero() {
            return BigInt256::ONE.mod_mul(&BigInt256::ONE, modulus);
        }

        let mut result = BigInt256::ONE;
        let mut base = *self;
        let bit_len = exp.bit_length();

        for i in 0..bit_len {
            if exp.get_bit(i) {
                result = result.mod_mul(&base, modulus);
            }
            base = base.mod_square(modulus);
        }

        result
    }

    /// 右移1位
    #[inline]
    pub fn shift_right_1(&self) -> BigInt256 {
        let l = &self.limbs;
        BigInt256::new([
            (l[0] >> 1) | (l[1] << 63),
            (l[1] >> 1) | (l[2] << 63),
            (l[2] >> 1) | (l[3] << 63),
            l[3] >> 1,
        ])
    }

    /// 左移1位
    #[inline]
    pub fn shift_left_1(&self) -> BigInt256 {
        let l = &self.limbs;
        BigInt256::new([
            l[0] << 1,
            (l[1] << 1) | (l[0] >> 63),
            (l[2] << 1) | (l[1] >> 63),
            (l[3] << 1) | (l[2] >> 63),
        ])
    }

    /// 获取指定位置的位
    #[inline]
    pub fn get_bit(&self, bit: usize) -> bool {
        if bit >= 256 {
            return false;
        }
        (self.limbs[bit / 64] >> (bit % 64)) & 1 == 1
    }

    /// 获取最高有效位的位置（从0开始）
    pub fn bit_length(&self) -> usize {
        for i in (0..4).rev() {
            if self.limbs[i] != 0 {
                return (i + 1) * 64 - self.limbs[i].leading_zeros() as usize;
            }
        }
        0
    }

    /// 与操作
    #[inline]
    pub fn and(&self, other: &BigInt256) -> BigInt256 {
        let (a, b) = (&self.limbs, &other.limbs);
        BigInt256::new([a[0] & b[0], a[1] & b[1], a[2] & b[2], a[3] & b[3]])
    }
}

/// Remainder of a 512-bit value by an arbitrary non-zero modulus: Knuth's Algorithm D.
/// Variable time, only used for moduli other than the SM2 ones.
fn reduce_wide_generic(value: &[u64; 8], modulus: &Limbs) -> Limbs {
    let Some(n) = modulus.iter().rposition(|&l| l != 0).map(|top| top + 1) else {
        return [0; 4]; // unreachable from `mod_mul`, which handles a zero modulus
    };

    // Normalize so that the top limb of the divisor has its high bit set.
    let shift = modulus[n - 1].leading_zeros();
    let shl = |low: u64, high: u64| {
        if shift == 0 {
            high
        } else {
            (high << shift) | (low >> (64 - shift))
        }
    };
    let mut v = [0u64; 4];
    v[0] = modulus[0] << shift;
    for i in 1..n {
        v[i] = shl(modulus[i - 1], modulus[i]);
    }
    let mut u = [0u64; 9];
    u[0] = value[0] << shift;
    for i in 1..8 {
        u[i] = shl(value[i - 1], value[i]);
    }
    u[8] = if shift == 0 {
        0
    } else {
        value[7] >> (64 - shift)
    };

    let top = u128::from(v[n - 1]);
    for j in (0..=8 - n).rev() {
        // Estimate the quotient digit from the top limbs, then correct it.
        let numerator = (u128::from(u[j + n]) << 64) | u128::from(u[j + n - 1]);
        let mut q = numerator / top;
        let mut r = numerator % top;
        if n > 1 {
            while q >> 64 != 0 || q * u128::from(v[n - 2]) > ((r << 64) | u128::from(u[j + n - 2]))
            {
                q -= 1;
                r += top;
                if r >> 64 != 0 {
                    break;
                }
            }
        } else if q >> 64 != 0 {
            q = u128::from(u64::MAX);
        }
        let q = q as u64;

        // Multiply and subtract.
        let mut borrow = 0u64;
        let mut carry = 0u64;
        for i in 0..n {
            let (low, high) = field::mac(0, q, v[i], carry);
            carry = high;
            let (digit, b) = field::sbb(u[i + j], low, borrow);
            u[i + j] = digit;
            borrow = b;
        }
        let (digit, b) = field::sbb(u[j + n], carry, borrow);
        u[j + n] = digit;

        // The estimate was one too large in the rare case that this went negative.
        if b != 0 {
            let mut carry = 0u64;
            for i in 0..n {
                let (digit, c) = field::adc(u[i + j], v[i], carry);
                u[i + j] = digit;
                carry = c;
            }
            u[j + n] = u[j + n].wrapping_add(carry);
        }
    }

    // Denormalize the remainder.
    let mut out = [0u64; 4];
    for i in 0..n {
        out[i] = if shift == 0 {
            u[i]
        } else {
            (u[i] >> shift) | (u[i + 1] << (64 - shift))
        };
    }
    out
}

impl PartialEq for BigInt256 {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        let (a, b) = (&self.limbs, &other.limbs);
        ct_barrier((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])) == 0
    }
}

impl Eq for BigInt256 {}

impl fmt::Debug for BigInt256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BigInt256(..)")
    }
}

impl Default for BigInt256 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl PartialOrd for BigInt256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigInt256 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_hex() {
        let n =
            BigInt256::from_hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
        assert_eq!(
            n.to_hex(),
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
        );
    }

    #[test]
    fn test_add() {
        let a = BigInt256::from_hex("1");
        let b = BigInt256::from_hex("2");
        let (c, _) = a.add(&b);
        assert_eq!(
            c.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000003"
        );
    }

    #[test]
    fn test_sub() {
        let a = BigInt256::from_hex("5");
        let b = BigInt256::from_hex("3");
        let (c, _) = a.sub(&b);
        assert_eq!(
            c.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000002"
        );
    }

    #[test]
    fn test_mul() {
        let a = BigInt256::from_hex("3");
        let b = BigInt256::from_hex("4");
        let p =
            BigInt256::from_hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
        let c = a.mod_mul(&b, &p);
        assert_eq!(
            c.to_hex(),
            "000000000000000000000000000000000000000000000000000000000000000C"
        );
    }

    #[test]
    fn test_mod_inverse() {
        let a = BigInt256::from_hex("3");
        let p = BigInt256::from_hex("7");
        let inv = a.mod_inverse(&p);
        let product = a.mod_mul(&inv, &p);
        assert!(product.is_one());
    }
}
