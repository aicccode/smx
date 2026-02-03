//! SM4 国密算法实现 (CBC模式，PKCS#7填充)
//! 参考Java版本实现: java/src/site/aicc/sm4/SM4.java

use std::error::Error;
use std::fmt;

/// SM4 算法实现
pub struct SM4 {
    rk: [u32; 32],  // 轮密钥
    iv: [u8; 16],   // CBC初始向量
}

/// 自定义错误类型
#[derive(Debug)]
pub enum SM4Error {
    InvalidKeyLength,
    InvalidIVLength,
    InvalidHexString,
    InvalidPadding,
}

impl fmt::Display for SM4Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SM4Error::InvalidKeyLength => write!(f, "Invalid key length, expected 16 bytes"),
            SM4Error::InvalidIVLength => write!(f, "Invalid IV length, expected 16 bytes"),
            SM4Error::InvalidHexString => write!(f, "Invalid hex string"),
            SM4Error::InvalidPadding => write!(f, "Invalid padding"),
        }
    }
}

impl Error for SM4Error {}

impl SM4 {
    /// 创建新的SM4实例
    pub fn new() -> Self {
        SM4 {
            rk: [0; 32],
            iv: [0; 16],
        }
    }

    /// 设置密钥和IV
    pub fn set_key(&mut self, key: &[u8], iv: &[u8]) -> Result<(), SM4Error> {
        // 处理密钥
        let key_bytes = if key.len() != 16 {
            // 使用SM3哈希的十六进制字符串的ASCII字节（匹配Java行为）
            let mut sm3 = crate::sm3::Sm3::new();
            sm3.update(key);
            sm3.finish();
            let hash_hex = sm3.hash_hex_upper();
            let hash_hex_bytes = hash_hex.as_bytes();
            let mut new_key = [0; 16];
            new_key.copy_from_slice(&hash_hex_bytes[..16]);
            new_key
        } else {
            let mut new_key = [0; 16];
            new_key.copy_from_slice(key);
            new_key
        };

        // 处理IV
        let iv_bytes = if iv.len() != 16 {
            // 使用SM3哈希的十六进制字符串的ASCII字节（匹配Java行为）
            let mut sm3 = crate::sm3::Sm3::new();
            sm3.update(iv);
            sm3.finish();
            let hash_hex = sm3.hash_hex_upper();
            let hash_hex_bytes = hash_hex.as_bytes();
            let mut new_iv = [0; 16];
            new_iv.copy_from_slice(&hash_hex_bytes[..16]);
            new_iv
        } else {
            let mut new_iv = [0; 16];
            new_iv.copy_from_slice(iv);
            new_iv
        };

        self.init_key(&key_bytes, &iv_bytes);
        Ok(())
    }

    /// 加密字符串
    pub fn encrypt(&self, plaintext: &str) -> Result<String, Box<dyn Error>> {
        let input = plaintext.as_bytes();
        let padded = self.pkcs7_pad(input);
        let mut iv = self.iv;
        let mut output = Vec::new();

        for chunk in padded.chunks(16) {
            let block = self.cbc_encrypt_block(chunk, &iv)?;
            output.extend_from_slice(&block);
            iv.copy_from_slice(&block);
        }

        Ok(bytes_to_hex(&output))
    }

    /// 解密字符串
    pub fn decrypt(&self, ciphertext: &str) -> Result<String, Box<dyn Error>> {
        let input = hex_to_bytes(ciphertext)?;
        let mut iv = self.iv;
        let mut output = Vec::new();
        let mut prev_block = [0; 16];

        for chunk in input.chunks(16) {
            let block = self.cbc_decrypt_block(chunk, &iv)?;
            output.extend_from_slice(&block);
            prev_block.copy_from_slice(chunk);
            iv.copy_from_slice(&prev_block);
        }

        let unpadded = self.pkcs7_unpad(&output)?;
        Ok(String::from_utf8(unpadded)?)
    }

    // 初始化密钥
    fn init_key(&mut self, key: &[u8], iv: &[u8]) {
        // FK值应与Java版本一致
        const FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

        // CK值应与Java版本一致
        const CK: [u32; 32] = [
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
        ];

        // 加密密钥 MK (大端序)
        let mut mk = [0; 4];
        for i in 0..4 {
            mk[i] = ((key[i*4] as u32) << 24) |
                    ((key[i*4+1] as u32) << 16) |
                    ((key[i*4+2] as u32) << 8) |
                    (key[i*4+3] as u32);
        }

        // 轮密钥生成
        let mut k = [0; 36];
        k[0] = mk[0] ^ FK[0];
        k[1] = mk[1] ^ FK[1];
        k[2] = mk[2] ^ FK[2];
        k[3] = mk[3] ^ FK[3];

        for i in 0..32 {
            let input = k[i+1] ^ k[i+2] ^ k[i+3] ^ CK[i];
            k[i+4] = k[i] ^ self.t_prime(input);
            self.rk[i] = k[i+4];
        }

        // 设置IV
        self.iv.copy_from_slice(iv);
    }

    // S盒
    fn sbox(&self, input: u8) -> u8 {
        const S_TABLE: [u8; 256] = [
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
            0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
            0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
            0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
            0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
            0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
            0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
            0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
            0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
            0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
        ];
        S_TABLE[input as usize]
    }

    // 非线性变换 τ
    fn tau(&self, a: u32) -> u32 {
        let bytes = a.to_be_bytes();
        let b0 = self.sbox(bytes[0]);
        let b1 = self.sbox(bytes[1]);
        let b2 = self.sbox(bytes[2]);
        let b3 = self.sbox(bytes[3]);
        u32::from_be_bytes([b0, b1, b2, b3])
    }

    // 线性变换 L
    fn l(&self, b: u32) -> u32 {
        b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
    }

    // 合成置换 T
    fn t(&self, a: u32) -> u32 {
        let b = self.tau(a);
        self.l(b)
    }

    // T' 变换
    fn t_prime(&self, a: u32) -> u32 {
        let bytes = a.to_be_bytes();
        let b0 = self.sbox(bytes[0]);
        let b1 = self.sbox(bytes[1]);
        let b2 = self.sbox(bytes[2]);
        let b3 = self.sbox(bytes[3]);
        let b = u32::from_be_bytes([b0, b1, b2, b3]);
        b ^ b.rotate_left(13) ^ b.rotate_left(23)
    }

    // 轮函数 F
    fn f(&self, x0: u32, x1: u32, x2: u32, x3: u32, rk: u32) -> u32 {
        x0 ^ self.t(x1 ^ x2 ^ x3 ^ rk)
    }

    // 反序变换 R
    fn r(&self, a: &mut [u32; 4]) {
        // 交换X0和X3
        let temp = a[0];
        a[0] = a[3];
        a[3] = temp;

        // 交换X1和X2
        let temp = a[1];
        a[1] = a[2];
        a[2] = temp;
    }

    // CBC模式加密一个块
    fn cbc_encrypt_block(&self, block: &[u8], iv: &[u8]) -> Result<[u8; 16], SM4Error> {
        if block.len() != 16 {
            return Err(SM4Error::InvalidKeyLength);
        }

        // 转换为u32数组（与Java版本一致）
        let mut x = [0; 4];
        for i in 0..4 {
            x[i] = ((block[i*4] as u32) << 24) |
                   ((block[i*4+1] as u32) << 16) |
                   ((block[i*4+2] as u32) << 8) |
                   (block[i*4+3] as u32);
        }

        // 先异或IV再转换（与Java版本一致）
        for i in 0..4 {
            let iv_word = ((iv[i*4] as u32) << 24) |
                          ((iv[i*4+1] as u32) << 16) |
                          ((iv[i*4+2] as u32) << 8) |
                          (iv[i*4+3] as u32);
            x[i] ^= iv_word;
        }

        // 32轮加密 (与Java版本一致)
        let mut x_next = [0; 36];
        x_next[..4].copy_from_slice(&x);

        for i in 0..32 {
            x_next[i+4] = self.f(x_next[i], x_next[i+1], x_next[i+2], x_next[i+3], self.rk[i]);
        }

        // 反序变换 (与Java版本一致)
        let mut xo = [x_next[32], x_next[33], x_next[34], x_next[35]];
        self.r(&mut xo);

        // 转换为字节数组（大端序）
        let mut output = [0; 16];
        for i in 0..4 {
            let bytes = xo[i].to_be_bytes();
            output[i*4] = bytes[0];
            output[i*4+1] = bytes[1];
            output[i*4+2] = bytes[2];
            output[i*4+3] = bytes[3];
        }

        Ok(output)
    }

    // CBC模式解密一个块
    fn cbc_decrypt_block(&self, block: &[u8], iv: &[u8]) -> Result<[u8; 16], SM4Error> {
        if block.len() != 16 {
            return Err(SM4Error::InvalidKeyLength);
        }

        // 转换为u32数组
        let mut x = [0; 4];
        for i in 0..4 {
            x[i] = (block[i*4] as u32) << 24 | 
                   (block[i*4+1] as u32) << 16 | 
                   (block[i*4+2] as u32) << 8 | 
                   (block[i*4+3] as u32);
        }

        // 32轮解密
        let mut x_next = [0; 36];
        x_next[..4].copy_from_slice(&x);
        
        for i in 0..32 {
            x_next[i+4] = self.f(x_next[i], x_next[i+1], x_next[i+2], x_next[i+3], self.rk[31-i]);
        }

        // 反序变换
        let mut xo = [x_next[32], x_next[33], x_next[34], x_next[35]];
        self.r(&mut xo);

        // 转换为字节数组并与IV异或
        let mut output = [0; 16];
        for i in 0..4 {
            let bytes = xo[i].to_be_bytes();
            output[i*4] = bytes[0] ^ iv[i*4];
            output[i*4+1] = bytes[1] ^ iv[i*4+1];
            output[i*4+2] = bytes[2] ^ iv[i*4+2];
            output[i*4+3] = bytes[3] ^ iv[i*4+3];
        }

        Ok(output)
    }

    // PKCS#7填充
    fn pkcs7_pad(&self, input: &[u8]) -> Vec<u8> {
        let block_size = 16;
        let pad_len = if input.len() % block_size == 0 {
            block_size  // 如果已经是块大小的整数倍，填充一个完整块
        } else {
            block_size - (input.len() % block_size)
        };
        let mut output = input.to_vec();
        output.extend(std::iter::repeat(pad_len as u8).take(pad_len));
        output
    }

    // PKCS#7去除填充
    fn pkcs7_unpad(&self, input: &[u8]) -> Result<Vec<u8>, SM4Error> {
        if input.is_empty() {
            return Ok(Vec::new());
        }
        
        let pad_len = input[input.len() - 1] as usize;
        if pad_len == 0 || pad_len > 16 {
            return Err(SM4Error::InvalidPadding);
        }
        
        if input.len() < pad_len {
            return Err(SM4Error::InvalidPadding);
        }
        
        for i in (input.len() - pad_len)..input.len() {
            if input[i] as usize != pad_len {
                return Err(SM4Error::InvalidPadding);
            }
        }
        
        Ok(input[..input.len() - pad_len].to_vec())
    }
}

// 字节数组转16进制字符串
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

// 16进制字符串转字节数组
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, SM4Error> {
    if hex.len() % 2 != 0 {
        return Err(SM4Error::InvalidHexString);
    }
    
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2], 16)
            .map_err(|_| SM4Error::InvalidHexString)?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        // 测试SM3哈希一致性
        let key = "this is the key";
        let iv = "this is the iv";

        // 测试SM4加密
        let mut sm4 = SM4::new();
        sm4.set_key(key.as_bytes(), iv.as_bytes()).unwrap();

        let plaintext = "国密SM4对称加密算法";

        let ciphertext = sm4.encrypt(plaintext).unwrap();

        // 从Java测试中获取的预期加密结果
        let expected_ciphertext = "09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc";
        assert_eq!(ciphertext, expected_ciphertext);

        let decrypted = sm4.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}
