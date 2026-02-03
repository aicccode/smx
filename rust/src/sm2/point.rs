// 椭圆曲线点实现

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

        let x1 = &self.x;
        let y1 = &self.y;
        let x2 = &other.x;
        let y2 = &other.y;

        let dx = x2.subtract(x1);
        let dy = y2.subtract(y1);

        if dx.is_zero() {
            if dy.is_zero() {
                return self.twice();
            }
            return ECPoint::infinity();
        }

        // lambda = (y2 - y1) / (x2 - x1)
        let lambda = dy.divide(&dx);

        // x3 = lambda^2 - x1 - x2
        let x3 = lambda.square().subtract(x1).subtract(x2);

        // y3 = lambda * (x1 - x3) - y1
        let y3 = lambda.multiply(&x1.subtract(&x3)).subtract(y1);

        ECPoint::new(x3, y3)
    }

    /// 点倍乘（P + P）
    pub fn twice(&self) -> ECPoint {
        if self.infinity {
            return ECPoint::infinity();
        }

        let y1 = &self.y;
        if y1.is_zero() {
            return ECPoint::infinity();
        }

        let x1 = &self.x;
        let x1_sq = x1.square();

        // lambda = (3 * x1^2 + a) / (2 * y1)
        let numerator = x1_sq.triple().add(&SM2_A);
        let denominator = y1.double();
        let lambda = numerator.divide(&denominator);

        // x3 = lambda^2 - 2*x1
        let x3 = lambda.square().subtract(&x1.double());

        // y3 = lambda * (x1 - x3) - y1
        let y3 = lambda.multiply(&x1.subtract(&x3)).subtract(y1);

        ECPoint::new(x3, y3)
    }

    /// 减法
    pub fn subtract(&self, other: &ECPoint) -> ECPoint {
        self.add(&other.negate())
    }

    /// 标量乘法（Double-and-Add算法）
    pub fn multiply(&self, k: &BigInt256) -> ECPoint {
        if k.is_zero() || self.infinity {
            return ECPoint::infinity();
        }

        if k.is_one() {
            return self.clone();
        }

        let mut result = ECPoint::infinity();
        let mut addend = self.clone();
        let bit_len = k.bit_length();

        for i in 0..bit_len {
            if k.get_bit(i) {
                result = result.add(&addend);
            }
            addend = addend.twice();
        }

        result
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
