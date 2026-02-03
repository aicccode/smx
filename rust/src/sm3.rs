// SM3 实现（无第三方依赖），接口尽量贴近 Java/Swift/JS 版本

pub struct Sm3 {
    v: [u32; 8],
    buff: [u8; 64],
    buff_len: usize, // 已写入字节数
    data_bits_len: u64,
    hash_bytes: [u8; 32],
    hash_value_hex: String,
}

impl Sm3 {
    const IV: [u32; 8] = [
        0x7380_166F,
        0x4914_B2B9,
        0x1724_42D7,
        0xDA8A_0600,
        0xA96F_30BC,
        0x1631_38AA,
        0xE38D_EE4D,
        0xB0FB_0E4E,
    ];

    pub fn new() -> Self {
        Sm3 {
            v: Self::IV,
            buff: [0u8; 64],
            buff_len: 0,
            data_bits_len: 0,
            hash_bytes: [0u8; 32],
            hash_value_hex: String::new(),
        }
    }

    #[inline]
    fn reset(&mut self) {
        self.v = Self::IV;
        self.buff_len = 0;
        self.data_bits_len = 0;
    }

    /// 更新单字节
    pub fn update_byte(&mut self, b: u8) -> &mut Self {
        self.buff[self.buff_len] = b;
        self.buff_len += 1;
        self.data_bits_len += 8;
        if self.buff_len == 64 {
            let block = self.buff;
            self.process_block(&block);
            self.buff_len = 0;
        }
        self
    }

    /// 更新字节数组
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        for &b in data {
            self.update_byte(b);
        }
        self
    }

    /// 更新 UTF-8 字符串
    pub fn update_str(&mut self, s: &str) -> &mut Self {
        self.update(s.as_bytes())
    }

    pub fn finish(&mut self) -> &mut Self {
        // 完全按 Java 版本的填充逻辑
        let end = &self.buff[..self.buff_len];
        let block_len_bits = (self.buff_len as i32) * 8;
        let data_len_bits = (self.data_bits_len & 0xFFFF_FFFF) as i32;

        // 1
        let one: u8 = 0x80;
        // 需填0长度（bit）
        let fill_zero_len_bits = (512 - (block_len_bits + 65) % 512) - 7;
        // 总长度 bit
        let all_len_bits = fill_zero_len_bits + block_len_bits + 65 + 7;
        // 总长度 byte
        let all_byte_len = all_len_bits / 8;

        let mut buff = vec![0u8; all_byte_len as usize];
        for i in 0..all_byte_len {
            let idx = i as usize;
            if idx < end.len() {
                buff[idx] = end[idx];
            } else if idx == end.len() {
                buff[idx] = one;
            } else if i > all_byte_len - 5 {
                // 最后四字节填充全部数据的总长度（只保留32bit）
                let shift = (all_byte_len - i - 1) * 8;
                let val = (data_len_bits >> shift) & 0xFF;
                buff[idx] = val as u8;
            } else {
                buff[idx] = 0;
            }
        }

        // 处理填充后的块
        for i in 0..(all_len_bits / 512) {
            let start = (i * 512 / 8) as usize;
            let end = ((i + 1) * 512 / 8) as usize;
            let block = &buff[start..end];
            self.process_block(block);
        }

        self.generate_hash_string();
        self.reset();
        self
    }

    pub fn hash_bytes(&self) -> &[u8; 32] {
        &self.hash_bytes
    }

    pub fn hash_hex_upper(&self) -> &str {
        &self.hash_value_hex
    }

    fn generate_hash_string(&mut self) {
        let mut out = [0u8; 32];
        let mut off = 0;
        for &v in &self.v {
            out[off] = (v >> 24) as u8;
            out[off + 1] = (v >> 16) as u8;
            out[off + 2] = (v >> 8) as u8;
            out[off + 3] = v as u8;
            off += 4;
        }
        self.hash_bytes = out;
        let mut s = String::with_capacity(64);
        for b in &out {
            s.push_str(&format!("{:02X}", b));
        }
        self.hash_value_hex = s;
    }

    fn process_block(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len(), 64);
        // 消息扩展
        let mut w = [0u32; 68];
        let mut offset = 0;
        for j in 0..16 {
            w[j] = ((block[offset] as u32) << 24) |
                   ((block[offset + 1] as u32) << 16) |
                   ((block[offset + 2] as u32) << 8) |
                   (block[offset + 3] as u32);
            offset += 4;
        }
        for j in 16..68 {
            let wj3 = w[j - 3];
            let r15 = wj3.rotate_left(15);
            let wj13 = w[j - 13];
            let r7 = wj13.rotate_left(7);
            w[j] = Self::p1(w[j - 16] ^ w[j - 9] ^ r15) ^ r7 ^ w[j - 6];
        }
        let mut w2 = [0u32; 64];
        for j in 0..64 {
            w2[j] = w[j] ^ w[j + 4];
        }

        // 压缩函数
        let mut a = self.v[0];
        let mut b = self.v[1];
        let mut c = self.v[2];
        let mut d = self.v[3];
        let mut e = self.v[4];
        let mut f = self.v[5];
        let mut g = self.v[6];
        let mut h = self.v[7];

        for j in 0..64 {
            let a12 = a.rotate_left(12);
            let t_j = if j < 16 {
                0x79CC_4519u32.rotate_left(j as u32)
            } else {
                0x7A87_9D8Au32.rotate_left((j % 32) as u32)
            };
            let s_s = a12.wrapping_add(e).wrapping_add(t_j);
            let ss1 = s_s.rotate_left(7);
            let ss2 = ss1 ^ a12;
            let tt1 = if j < 16 {
                (a ^ b ^ c).wrapping_add(d).wrapping_add(ss2).wrapping_add(w2[j])
            } else {
                Self::ff1(a, b, c).wrapping_add(d).wrapping_add(ss2).wrapping_add(w2[j])
            };
            let tt2 = if j < 16 {
                (e ^ f ^ g).wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j])
            } else {
                Self::gg1(e, f, g).wrapping_add(h).wrapping_add(ss1).wrapping_add(w[j])
            };
            d = c;
            c = b.rotate_left(9);
            b = a;
            a = tt1;
            h = g;
            g = f.rotate_left(19);
            f = e;
            e = Self::p0(tt2);
        }

        self.v[0] ^= a;
        self.v[1] ^= b;
        self.v[2] ^= c;
        self.v[3] ^= d;
        self.v[4] ^= e;
        self.v[5] ^= f;
        self.v[6] ^= g;
        self.v[7] ^= h;
    }

    #[inline]
    fn ff1(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    #[inline]
    fn gg1(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | ((!x) & z)
    }

    #[inline]
    fn p0(x: u32) -> u32 {
        x ^ x.rotate_left(9) ^ x.rotate_left(17)
    }

    #[inline]
    fn p1(x: u32) -> u32 {
        x ^ x.rotate_left(15) ^ x.rotate_left(23)
    }
}

#[cfg(test)]
mod tests {
    use super::Sm3;

    fn sm3_hex(input: &str) -> String {
        let mut sm3 = Sm3::new();
        sm3.update_str(input).finish();
        sm3.hash_hex_upper().to_string()
    }

    #[test]
    fn test_sm3_abc() {
        let h = sm3_hex("abc");
        assert_eq!(
            h,
            "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0"
        );
    }

    #[test]
    fn test_sm3_empty() {
        let h = sm3_hex("");
        assert_eq!(
            h,
            "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B"
        );
    }
}
