// 256位无符号整数实现（使用4个u64存储，小端序）

use core::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BigInt256 {
    pub limbs: [u64; 4], // 小端序：limbs[0]是最低64位
}

impl BigInt256 {
    pub const ZERO: BigInt256 = BigInt256 { limbs: [0, 0, 0, 0] };
    pub const ONE: BigInt256 = BigInt256 { limbs: [1, 0, 0, 0] };

    pub fn new(limbs: [u64; 4]) -> Self {
        BigInt256 { limbs }
    }

    /// 从十六进制字符串解析（大端表示）
    pub fn from_hex(hex: &str) -> Self {
        let hex = hex.trim_start_matches("0x").trim_start_matches("0X");
        let hex = if hex.len() % 2 == 1 {
            format!("0{}", hex)
        } else {
            hex.to_string()
        };

        let mut bytes = vec![0u8; 32];
        let hex_bytes = hex.as_bytes();
        let start = 32usize.saturating_sub(hex.len() / 2);

        for i in 0..hex.len() / 2 {
            let high = Self::hex_char_to_u8(hex_bytes[i * 2]);
            let low = Self::hex_char_to_u8(hex_bytes[i * 2 + 1]);
            bytes[start + i] = (high << 4) | low;
        }

        Self::from_be_bytes(&bytes)
    }

    fn hex_char_to_u8(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }

    /// 从大端字节数组解析
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut padded = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        let copy_len = bytes.len().min(32);
        padded[start..start + copy_len].copy_from_slice(&bytes[bytes.len() - copy_len..]);

        let mut limbs = [0u64; 4];
        // 大端到小端转换
        for i in 0..4 {
            let offset = (3 - i) * 8;
            limbs[i] = u64::from_be_bytes([
                padded[offset],
                padded[offset + 1],
                padded[offset + 2],
                padded[offset + 3],
                padded[offset + 4],
                padded[offset + 5],
                padded[offset + 6],
                padded[offset + 7],
            ]);
        }
        BigInt256 { limbs }
    }

    /// 转换为大端字节数组
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let offset = (3 - i) * 8;
            let limb_bytes = self.limbs[i].to_be_bytes();
            bytes[offset..offset + 8].copy_from_slice(&limb_bytes);
        }
        bytes
    }

    /// 转换为十六进制字符串（大写）
    pub fn to_hex(&self) -> String {
        let bytes = self.to_be_bytes();
        let mut s = String::with_capacity(64);
        for b in &bytes {
            s.push_str(&format!("{:02X}", b));
        }
        s
    }

    /// 转换为十六进制字符串（小写）
    pub fn to_hex_lower(&self) -> String {
        self.to_hex().to_lowercase()
    }

    /// 判断是否为零
    pub fn is_zero(&self) -> bool {
        self.limbs[0] == 0 && self.limbs[1] == 0 && self.limbs[2] == 0 && self.limbs[3] == 0
    }

    /// 判断是否为1
    pub fn is_one(&self) -> bool {
        self.limbs[0] == 1 && self.limbs[1] == 0 && self.limbs[2] == 0 && self.limbs[3] == 0
    }

    /// 比较两个BigInt256
    pub fn compare(&self, other: &BigInt256) -> Ordering {
        for i in (0..4).rev() {
            if self.limbs[i] > other.limbs[i] {
                return Ordering::Greater;
            }
            if self.limbs[i] < other.limbs[i] {
                return Ordering::Less;
            }
        }
        Ordering::Equal
    }

    /// 加法，返回(结果, 进位)
    pub fn add(&self, other: &BigInt256) -> (BigInt256, bool) {
        let mut result = [0u64; 4];
        let mut carry = 0u64;

        for i in 0..4 {
            let (sum1, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (sum2, c2) = sum1.overflowing_add(carry);
            result[i] = sum2;
            carry = (c1 as u64) + (c2 as u64);
        }

        (BigInt256 { limbs: result }, carry != 0)
    }

    /// 减法，返回(结果, 借位)
    pub fn sub(&self, other: &BigInt256) -> (BigInt256, bool) {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;

        for i in 0..4 {
            let (diff1, b1) = self.limbs[i].overflowing_sub(other.limbs[i]);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }

        (BigInt256 { limbs: result }, borrow != 0)
    }

    /// 乘法，返回512位结果（使用8个u64）
    pub fn mul(&self, other: &BigInt256) -> [u64; 8] {
        let mut result = [0u64; 8];

        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let product = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                    + (result[i + j] as u128)
                    + carry;
                result[i + j] = product as u64;
                carry = product >> 64;
            }
            result[i + 4] = carry as u64;
        }

        result
    }

    /// 模加法
    pub fn mod_add(&self, other: &BigInt256, modulus: &BigInt256) -> BigInt256 {
        let (sum, carry) = self.add(other);
        if carry || sum.compare(modulus) != Ordering::Less {
            let (result, _) = sum.sub(modulus);
            result
        } else {
            sum
        }
    }

    /// 模减法
    pub fn mod_sub(&self, other: &BigInt256, modulus: &BigInt256) -> BigInt256 {
        let (diff, borrow) = self.sub(other);
        if borrow {
            let (result, _) = diff.add(modulus);
            result
        } else {
            diff
        }
    }

    /// 模乘法
    pub fn mod_mul(&self, other: &BigInt256, modulus: &BigInt256) -> BigInt256 {
        let product = self.mul(other);
        Self::mod_reduce_512(&product, modulus)
    }

    /// 模平方
    pub fn mod_square(&self, modulus: &BigInt256) -> BigInt256 {
        self.mod_mul(self, modulus)
    }

    /// SM2专用：模乘法（使用快速约减）
    pub fn sm2_mod_mul_p(&self, other: &BigInt256) -> BigInt256 {
        let product = self.mul(other);
        Self::sm2_mod_reduce_p(&product)
    }

    /// SM2专用：模平方（使用快速约减）
    pub fn sm2_mod_square_p(&self) -> BigInt256 {
        let product = self.mul(self);
        Self::sm2_mod_reduce_p(&product)
    }

    /// SM2专用快速模约减（使用32位字和预计算的约减系数）
    /// p = 2^256 - 2^224 - 2^96 + 2^64 - 1
    /// 对于每个高位字 w[i] (i=8..15), 2^(32i) mod p 的系数已预计算
    fn sm2_mod_reduce_p(c: &[u64; 8]) -> BigInt256 {
        // 拆分为32位字（小端序）
        let w = |i: usize| -> i64 {
            if i % 2 == 0 {
                (c[i / 2] & 0xFFFFFFFF) as i64
            } else {
                (c[i / 2] >> 32) as i64
            }
        };

        // 预计算的有符号约减系数 R_k[j] 表示 2^(32k) mod p 在位置j的系数
        // R_8:  [1, 0, -1, 1, 0, 0, 0, 1]
        // R_9:  [1, 1, -1, 0, 1, 0, 0, 1]
        // R_10: [1, 1,  0, 0, 0, 1, 0, 1]
        // R_11: [1, 1,  0, 1, 0, 0, 1, 1]
        // R_12: [1, 1,  0, 1, 1, 0, 0, 2]
        // R_13: [2, 1, -1, 2, 1, 1, 0, 2]
        // R_14: [2, 2, -1, 1, 2, 1, 1, 2]
        // R_15: [2, 2,  0, 1, 1, 2, 1, 3]
        static R: [[i64; 8]; 8] = [
            [ 1, 0, -1,  1, 0, 0, 0, 1],  // R_8
            [ 1, 1, -1,  0, 1, 0, 0, 1],  // R_9
            [ 1, 1,  0,  0, 0, 1, 0, 1],  // R_10
            [ 1, 1,  0,  1, 0, 0, 1, 1],  // R_11
            [ 1, 1,  0,  1, 1, 0, 0, 2],  // R_12
            [ 2, 1, -1,  2, 1, 1, 0, 2],  // R_13
            [ 2, 2, -1,  1, 2, 1, 1, 2],  // R_14
            [ 2, 2,  0,  1, 1, 2, 1, 3],  // R_15
        ];

        // 累加: result[j] = w[j] + Σ(w[i+8] * R[i][j], i=0..7)
        let mut acc = [0i64; 9]; // 8个输出位 + 1个溢出
        for j in 0..8 {
            acc[j] = w(j);
            for i in 0..8 {
                acc[j] += w(i + 8) * R[i][j];
            }
        }

        // 传播进位（32位字）
        for i in 0..8 {
            let carry = acc[i] >> 32;
            acc[i] &= 0xFFFFFFFF;
            if i < 8 {
                acc[i + 1] += carry;
            }
        }

        // 处理溢出：acc[8] 中的值需要再约减
        // acc[8] * 2^256 ≡ acc[8] * r (mod p)
        // r 在32位字中的系数: [1, 0, -1, 1, 0, 0, 0, 1]
        let overflow = acc[8];
        if overflow != 0 {
            acc[0] += overflow;
            acc[2] -= overflow;
            acc[3] += overflow;
            acc[7] += overflow;
            acc[8] = 0;

            // 传播进位
            for i in 0..8 {
                let carry = acc[i] >> 32;
                acc[i] &= 0xFFFFFFFF;
                if i < 8 {
                    acc[i + 1] += carry;
                }
            }

            // 第二次溢出（极少发生）
            let overflow2 = acc[8];
            if overflow2 != 0 {
                acc[0] += overflow2;
                acc[2] -= overflow2;
                acc[3] += overflow2;
                acc[7] += overflow2;
                acc[8] = 0;
                for i in 0..8 {
                    let carry = acc[i] >> 32;
                    acc[i] &= 0xFFFFFFFF;
                    if i < 8 {
                        acc[i + 1] += carry;
                    }
                }
            }
        }

        // 处理可能的负值（如果减法导致借位）
        for i in 0..8 {
            while acc[i] < 0 {
                acc[i] += 0x100000000;
                acc[i + 1] -= 1;
            }
        }

        // 组合32位字为64位limb
        let mut result = BigInt256 {
            limbs: [
                (acc[0] as u64) | ((acc[1] as u64) << 32),
                (acc[2] as u64) | ((acc[3] as u64) << 32),
                (acc[4] as u64) | ((acc[5] as u64) << 32),
                (acc[6] as u64) | ((acc[7] as u64) << 32),
            ],
        };

        // 最终约减
        let sm2_p = BigInt256 {
            limbs: [0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF],
        };
        loop {
            if result.compare(&sm2_p) != Ordering::Less {
                let (r, _) = result.sub(&sm2_p);
                result = r;
            } else {
                break;
            }
        }
        result
    }

    /// 512位数模约减到256位
    fn mod_reduce_512(value: &[u64; 8], modulus: &BigInt256) -> BigInt256 {
        // 使用简单的长除法进行模约减
        let mut remainder = [0u64; 8];
        remainder.copy_from_slice(value);

        // 找到被除数的最高有效位
        let mut dividend_bits = 512;
        for i in (0..8).rev() {
            if remainder[i] != 0 {
                dividend_bits = (i + 1) * 64 - remainder[i].leading_zeros() as usize;
                break;
            }
            if i == 0 {
                dividend_bits = 0;
            }
        }

        // 找到模数的最高有效位
        let mut modulus_bits = 256;
        for i in (0..4).rev() {
            if modulus.limbs[i] != 0 {
                modulus_bits = (i + 1) * 64 - modulus.limbs[i].leading_zeros() as usize;
                break;
            }
            if i == 0 {
                modulus_bits = 0;
            }
        }

        if modulus_bits == 0 {
            panic!("Division by zero");
        }

        if dividend_bits < modulus_bits {
            return BigInt256 {
                limbs: [remainder[0], remainder[1], remainder[2], remainder[3]],
            };
        }

        // 移位减法除法
        let shift_amount = dividend_bits - modulus_bits;

        for shift in (0..=shift_amount).rev() {
            // 将模数左移shift位
            let shifted_modulus = Self::shift_left_512(&modulus.limbs, shift);

            // 比较并减去
            if Self::compare_512(&remainder, &shifted_modulus) != Ordering::Less {
                remainder = Self::sub_512(&remainder, &shifted_modulus);
            }
        }

        BigInt256 {
            limbs: [remainder[0], remainder[1], remainder[2], remainder[3]],
        }
    }

    fn shift_left_512(value: &[u64; 4], shift: usize) -> [u64; 8] {
        let mut result = [0u64; 8];

        if shift == 0 {
            result[0] = value[0];
            result[1] = value[1];
            result[2] = value[2];
            result[3] = value[3];
            return result;
        }

        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        if bit_shift == 0 {
            for i in 0..4 {
                if i + word_shift < 8 {
                    result[i + word_shift] = value[i];
                }
            }
        } else {
            for i in 0..4 {
                if i + word_shift < 8 {
                    result[i + word_shift] |= value[i] << bit_shift;
                }
                if i + word_shift + 1 < 8 {
                    result[i + word_shift + 1] |= value[i] >> (64 - bit_shift);
                }
            }
        }

        result
    }

    fn compare_512(a: &[u64; 8], b: &[u64; 8]) -> Ordering {
        for i in (0..8).rev() {
            if a[i] > b[i] {
                return Ordering::Greater;
            }
            if a[i] < b[i] {
                return Ordering::Less;
            }
        }
        Ordering::Equal
    }

    fn sub_512(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        let mut result = [0u64; 8];
        let mut borrow = 0u64;

        for i in 0..8 {
            let (diff1, b1) = a[i].overflowing_sub(b[i]);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }

        result
    }

    /// 模逆（使用扩展欧几里得算法 - Fermat小定理版本）
    /// a^(-1) mod p = a^(p-2) mod p (当p为素数时)
    pub fn mod_inverse(&self, modulus: &BigInt256) -> BigInt256 {
        if self.is_zero() {
            panic!("Cannot invert zero");
        }

        // 使用费马小定理: a^(-1) = a^(p-2) mod p
        // 计算 p - 2
        let (p_minus_2, _) = modulus.sub(&BigInt256::new([2, 0, 0, 0]));

        // 使用平方-乘法快速幂
        self.mod_pow(&p_minus_2, modulus)
    }

    /// 模幂运算 (base^exp mod modulus)
    pub fn mod_pow(&self, exp: &BigInt256, modulus: &BigInt256) -> BigInt256 {
        if exp.is_zero() {
            return BigInt256::ONE;
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
    pub fn shift_right_1(&self) -> BigInt256 {
        let mut result = [0u64; 4];
        for i in 0..4 {
            result[i] = self.limbs[i] >> 1;
            if i < 3 {
                result[i] |= self.limbs[i + 1] << 63;
            }
        }
        BigInt256 { limbs: result }
    }

    /// 左移1位
    pub fn shift_left_1(&self) -> BigInt256 {
        let mut result = [0u64; 4];
        for i in (0..4).rev() {
            result[i] = self.limbs[i] << 1;
            if i > 0 {
                result[i] |= self.limbs[i - 1] >> 63;
            }
        }
        BigInt256 { limbs: result }
    }

    /// 获取指定位置的位
    pub fn get_bit(&self, bit: usize) -> bool {
        if bit >= 256 {
            return false;
        }
        let word = bit / 64;
        let bit_in_word = bit % 64;
        (self.limbs[word] >> bit_in_word) & 1 == 1
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
    pub fn and(&self, other: &BigInt256) -> BigInt256 {
        BigInt256 {
            limbs: [
                self.limbs[0] & other.limbs[0],
                self.limbs[1] & other.limbs[1],
                self.limbs[2] & other.limbs[2],
                self.limbs[3] & other.limbs[3],
            ],
        }
    }
}

impl Default for BigInt256 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl PartialOrd for BigInt256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.compare(other))
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
        let n = BigInt256::from_hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
        assert_eq!(n.to_hex(), "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
    }

    #[test]
    fn test_add() {
        let a = BigInt256::from_hex("1");
        let b = BigInt256::from_hex("2");
        let (c, _) = a.add(&b);
        assert_eq!(c.to_hex(), "0000000000000000000000000000000000000000000000000000000000000003");
    }

    #[test]
    fn test_sub() {
        let a = BigInt256::from_hex("5");
        let b = BigInt256::from_hex("3");
        let (c, _) = a.sub(&b);
        assert_eq!(c.to_hex(), "0000000000000000000000000000000000000000000000000000000000000002");
    }

    #[test]
    fn test_mul() {
        let a = BigInt256::from_hex("3");
        let b = BigInt256::from_hex("4");
        let p = BigInt256::from_hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
        let c = a.mod_mul(&b, &p);
        assert_eq!(c.to_hex(), "000000000000000000000000000000000000000000000000000000000000000C");
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

