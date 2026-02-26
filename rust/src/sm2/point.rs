// 椭圆曲线点实现（仿射坐标 + 内部使用Jacobian坐标加速标量乘法）

use super::bigint256::BigInt256;
use super::fp::FpElement;

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
pub const SM2_N: BigInt256 = BigInt256 {
    limbs: [
        0x53BBF40939D54123,
        0x7203DF6B21C6052B,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFEFFFFFFFF,
    ],
};

// ============ Jacobian坐标内部点 ============
// (X, Y, Z) 对应仿射 (X/Z², Y/Z³)
// 无穷远点: Z = 0

struct JacobianPoint {
    x: FpElement,
    y: FpElement,
    z: FpElement,
}

impl JacobianPoint {
    fn infinity() -> Self {
        JacobianPoint {
            x: FpElement::one(),
            y: FpElement::one(),
            z: FpElement::zero(),
        }
    }

    fn from_affine(p: &ECPoint) -> Self {
        if p.infinity {
            return Self::infinity();
        }
        JacobianPoint {
            x: p.x,
            y: p.y,
            z: FpElement::one(),
        }
    }

    fn to_affine(&self) -> ECPoint {
        if self.z.is_zero() {
            return ECPoint::infinity();
        }
        // x_affine = X / Z²
        // y_affine = Y / Z³
        let z_inv = self.z.invert();
        let z_inv2 = z_inv.square();
        let z_inv3 = z_inv2.multiply(&z_inv);
        let x = self.x.multiply(&z_inv2);
        let y = self.y.multiply(&z_inv3);
        ECPoint::new(x, y)
    }

    /// Jacobian点倍乘（a = p - 3 优化）
    /// 参考: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
    fn double(&self) -> JacobianPoint {
        if self.z.is_zero() || self.y.is_zero() {
            return Self::infinity();
        }

        // SM2曲线 a = p - 3, 使用 a=-3 优化
        // delta = Z1²
        let delta = self.z.square();
        // gamma = Y1²
        let gamma = self.y.square();
        // beta = X1 * gamma
        let beta = self.x.multiply(&gamma);
        // alpha = 3*(X1-delta)*(X1+delta)  (利用 a=-3: 3*X1²+a*Z1⁴ = 3*(X1²-Z1⁴) = 3*(X1-Z1²)*(X1+Z1²))
        let alpha = self.x.subtract(&delta).multiply(&self.x.add(&delta)).triple();
        // X3 = alpha² - 8*beta
        let beta8 = beta.double().double().double();
        let x3 = alpha.square().subtract(&beta8);
        // Z3 = (Y1+Z1)² - gamma - delta
        let z3 = self.y.add(&self.z).square().subtract(&gamma).subtract(&delta);
        // Y3 = alpha*(4*beta - X3) - 8*gamma²
        let gamma_sq = gamma.square();
        let y3 = alpha.multiply(&beta.double().double().subtract(&x3))
            .subtract(&gamma_sq.double().double().double());

        JacobianPoint { x: x3, y: y3, z: z3 }
    }

    /// Jacobian点加法 (mixed addition: other.Z = 1)
    /// 参考: https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2007-bl
    fn add_affine(&self, other: &ECPoint) -> JacobianPoint {
        if other.infinity {
            return JacobianPoint { x: self.x, y: self.y, z: self.z };
        }
        if self.z.is_zero() {
            return JacobianPoint::from_affine(other);
        }

        // Z1Z1 = Z1²
        let z1z1 = self.z.square();
        // U2 = X2*Z1Z1
        let u2 = other.x.multiply(&z1z1);
        // S2 = Y2*Z1*Z1Z1
        let s2 = other.y.multiply(&self.z).multiply(&z1z1);
        // H = U2 - X1
        let h = u2.subtract(&self.x);
        // r = S2 - Y1
        let r = s2.subtract(&self.y);

        if h.is_zero() {
            if r.is_zero() {
                return self.double();
            }
            return Self::infinity();
        }

        let hh = h.square();
        let hhh = hh.multiply(&h);
        // X3 = r² - H³ - 2*X1*H²
        let x3 = r.square().subtract(&hhh).subtract(&self.x.multiply(&hh).double());
        // Y3 = r*(X1*H² - X3) - Y1*H³
        let y3 = r.multiply(&self.x.multiply(&hh).subtract(&x3)).subtract(&self.y.multiply(&hhh));
        // Z3 = Z1*H
        let z3 = self.z.multiply(&h);

        JacobianPoint { x: x3, y: y3, z: z3 }
    }

}

/// 椭圆曲线点（仿射坐标）
#[derive(Clone, Debug)]
pub struct ECPoint {
    pub x: FpElement,
    pub y: FpElement,
    pub infinity: bool,
}

impl ECPoint {
    /// 创建新的点
    pub fn new(x: FpElement, y: FpElement) -> Self {
        ECPoint {
            x,
            y,
            infinity: false,
        }
    }

    /// 创建无穷远点
    pub fn infinity() -> Self {
        ECPoint {
            x: FpElement::zero(),
            y: FpElement::zero(),
            infinity: true,
        }
    }

    /// 获取基点G
    pub fn generator() -> Self {
        ECPoint::new(SM2_GX, SM2_GY)
    }

    /// 判断是否为无穷远点
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
        let hex = hex.trim_start_matches("0x").trim_start_matches("0X");
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for i in 0..hex.len() / 2 {
            let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
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
        let bytes = self.to_encoded();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in &bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
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

    /// 点加法
    pub fn add(&self, other: &ECPoint) -> ECPoint {
        if self.infinity {
            return other.clone();
        }
        if other.infinity {
            return self.clone();
        }

        // 使用Jacobian坐标计算后转回仿射
        let jp = JacobianPoint::from_affine(self);
        let result = jp.add_affine(other);
        result.to_affine()
    }

    /// 点倍乘（P + P）
    pub fn twice(&self) -> ECPoint {
        if self.infinity {
            return ECPoint::infinity();
        }
        if self.y.is_zero() {
            return ECPoint::infinity();
        }
        let jp = JacobianPoint::from_affine(self);
        jp.double().to_affine()
    }

    /// 减法
    pub fn subtract(&self, other: &ECPoint) -> ECPoint {
        self.add(&other.negate())
    }

    /// 标量乘法（使用Jacobian坐标的Double-and-Add算法，仅在最后转回仿射）
    pub fn multiply(&self, k: &BigInt256) -> ECPoint {
        if k.is_zero() || self.infinity {
            return ECPoint::infinity();
        }

        if k.is_one() {
            return self.clone();
        }

        let mut result = JacobianPoint::infinity();
        let bit_len = k.bit_length();

        // 从高位到低位扫描（更适合Jacobian坐标）
        for i in (0..bit_len).rev() {
            result = result.double();
            if k.get_bit(i) {
                result = result.add_affine(self);
            }
        }

        result.to_affine()
    }

    /// 验证点在曲线上
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }

        // y^2 = x^3 + a*x + b
        let lhs = self.y.square();
        let rhs = self.x.square().add(&SM2_A).multiply(&self.x).add(&SM2_B);
        lhs == rhs
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
