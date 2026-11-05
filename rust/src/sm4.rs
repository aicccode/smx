//! SM4 国密算法实现 (CBC模式，PKCS#7填充)
//! 参考Java版本实现: java/src/site/aicc/sm4/SM4.java
//!
//! Block code sits behind one dispatch point, chosen at run time: GFNI + AVX2 and AES-NI (+ AVX2)
//! on x86-64, the AES instructions with NEON on AArch64, and a portable table implementation.
//!
//! Cache-timing caveat: the portable code indexes tables with secret data, and its 1 KiB T-table
//! is a larger target than the 256-byte S-box its key schedule uses. It only runs where no
//! hardware path exists; the hardware paths use no data-dependent memory access.

use crate::hex;
use std::error::Error;
use std::fmt;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86;

const BLOCK_LEN: usize = 16;

// The SM4 S-box is S(x) = B(inv(A(x))) over the AES field. AES hardware provides inv followed by
// the AES affine map, which the post transform below compensates for. These are the nibble tables
// of the two outer maps, shared by the x86-64 and AArch64 paths.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const PRE_LO: [u8; 16] = [
    0x3e, 0xb2, 0x0e, 0x82, 0xbb, 0x37, 0x8b, 0x07, 0xa1, 0x2d, 0x91, 0x1d, 0x24, 0xa8, 0x14, 0x98,
];
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const PRE_HI: [u8; 16] = [
    0x00, 0xdc, 0x2e, 0xf2, 0xc5, 0x19, 0xeb, 0x37, 0x08, 0xd4, 0x26, 0xfa, 0xcd, 0x11, 0xe3, 0x3f,
];
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const POST_LO: [u8; 16] = [
    0x6c, 0xd4, 0xa6, 0x1e, 0x52, 0xea, 0x98, 0x20, 0x0b, 0xb3, 0xc1, 0x79, 0x35, 0x8d, 0xff, 0x47,
];
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const POST_HI: [u8; 16] = [
    0x00, 0xe0, 0x50, 0xb0, 0x9d, 0x7d, 0xcd, 0x2d, 0xc0, 0x20, 0x90, 0x70, 0x5d, 0xbd, 0x0d, 0xed,
];
/// Undoes the ShiftRows step that the AES round instructions apply.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const INV_SHIFT_ROWS: [u8; 16] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];

/// SM4 算法实现
pub struct SM4 {
    rk: [u32; 32], // 轮密钥
    iv: [u8; 16],  // CBC初始向量
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

// S盒
pub(crate) const SBOX: [u8; 256] = [
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
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

const FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

pub(crate) const CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

// 线性变换 L
const fn l(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

// 线性变换 L'
#[inline(always)]
pub(crate) const fn l_prime(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

/// `L(S(x) << 24)`. The other three byte positions are rotations of this entry, because L
/// commutes with rotation. See the module note on cache timing.
const T_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = l((SBOX[i] as u32) << 24);
        i += 1;
    }
    t
};

#[inline(always)]
fn t_soft(x: u32) -> u32 {
    T_TABLE[(x >> 24) as usize]
        ^ T_TABLE[((x >> 16) & 0xff) as usize].rotate_right(8)
        ^ T_TABLE[((x >> 8) & 0xff) as usize].rotate_right(16)
        ^ T_TABLE[(x & 0xff) as usize].rotate_right(24)
}

#[inline(always)]
fn tau_soft(x: u32) -> u32 {
    let b = x.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

#[inline(always)]
pub(crate) fn load_be(block: &[u8]) -> [u32; 4] {
    let word = |i: usize| u32::from_be_bytes([block[i], block[i + 1], block[i + 2], block[i + 3]]);
    [word(0), word(4), word(8), word(12)]
}

#[inline(always)]
pub(crate) fn store_be(block: &mut [u8], words: [u32; 4]) {
    for (bytes, word) in block.chunks_exact_mut(4).zip(words) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
}

/// Key schedule shared by all backends, given the round's non-linear layer `tau`.
#[inline(always)]
pub(crate) fn expand_key(key: &[u8; 16], mut tau: impl FnMut(u32) -> u32) -> [u32; 32] {
    let mk = load_be(key);
    let mut k = [mk[0] ^ FK[0], mk[1] ^ FK[1], mk[2] ^ FK[2], mk[3] ^ FK[3]];
    let mut rk = [0u32; 32];
    for (i, out) in rk.iter_mut().enumerate() {
        let next = k[0] ^ l_prime(tau(k[1] ^ k[2] ^ k[3] ^ CK[i]));
        k = [k[1], k[2], k[3], next];
        *out = next;
    }
    rk
}

#[inline(always)]
fn crypt_block_soft(rk: &[u32; 32], block: &mut [u8]) {
    let [mut a, mut b, mut c, mut d] = load_be(block);
    for keys in rk.chunks_exact(4) {
        a ^= t_soft(b ^ c ^ d ^ keys[0]);
        b ^= t_soft(c ^ d ^ a ^ keys[1]);
        c ^= t_soft(d ^ a ^ b ^ keys[2]);
        d ^= t_soft(a ^ b ^ c ^ keys[3]);
    }
    store_be(block, [d, c, b, a]);
}

fn cbc_encrypt_soft(rk: &[u32; 32], iv: &[u8; 16], buf: &mut [u8]) {
    let mut chain = *iv;
    for block in buf.chunks_exact_mut(BLOCK_LEN) {
        for (byte, prev) in block.iter_mut().zip(chain) {
            *byte ^= prev;
        }
        crypt_block_soft(rk, block);
        chain.copy_from_slice(block);
    }
}

/// CBC decryption in place over the whole `BYTES`-sized chunks of `buf`, on a batch primitive that
/// transforms the blocks of a chunk independently. Returns the rest, which is shorter than a
/// chunk, and leaves `chain` at the last ciphertext block seen.
#[inline]
pub(crate) fn cbc_decrypt_chunks<'a, const BYTES: usize>(
    rk: &[u32; 32],
    chain: &mut [u8; 16],
    buf: &'a mut [u8],
    mut crypt: impl FnMut(&[u32; 32], &mut [u8; BYTES]),
) -> &'a mut [u8] {
    let mut chunks = buf.chunks_exact_mut(BYTES);
    for chunk in &mut chunks {
        let mut plain = [0u8; BYTES];
        plain.copy_from_slice(chunk);
        crypt(rk, &mut plain);
        for (byte, prev) in plain[..BLOCK_LEN].iter_mut().zip(*chain) {
            *byte ^= prev;
        }
        for (byte, prev) in plain[BLOCK_LEN..].iter_mut().zip(chunk.iter()) {
            *byte ^= *prev;
        }
        chain.copy_from_slice(&chunk[BYTES - BLOCK_LEN..]);
        chunk.copy_from_slice(&plain);
    }
    chunks.into_remainder()
}

/// Same for a final partial batch: `buf` holds fewer than `BYTES / 16` blocks.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline]
pub(crate) fn cbc_decrypt_tail<const BYTES: usize>(
    rk: &[u32; 32],
    chain: &[u8; 16],
    buf: &mut [u8],
    mut crypt: impl FnMut(&[u32; 32], &mut [u8; BYTES]),
) {
    if buf.is_empty() {
        return;
    }
    let mut plain = [0u8; BYTES];
    plain[..buf.len()].copy_from_slice(buf);
    crypt(rk, &mut plain);
    for (byte, prev) in plain[..BLOCK_LEN].iter_mut().zip(*chain) {
        *byte ^= prev;
    }
    for (byte, prev) in plain[BLOCK_LEN..buf.len()].iter_mut().zip(buf.iter()) {
        *byte ^= *prev;
    }
    buf.copy_from_slice(&plain[..buf.len()]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Soft,
    #[cfg(target_arch = "aarch64")]
    NeonAes,
    #[cfg(target_arch = "x86_64")]
    Aesni,
    #[cfg(target_arch = "x86_64")]
    AesniAvx2,
    #[cfg(target_arch = "x86_64")]
    GfniAvx2,
}

impl Backend {
    /// Fastest backend for this CPU; the feature macros cache their result.
    #[inline]
    fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                if std::is_x86_feature_detected!("gfni") {
                    return Backend::GfniAvx2;
                }
                if std::is_x86_feature_detected!("aes") {
                    return Backend::AesniAvx2;
                }
            }
            if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("ssse3") {
                return Backend::Aesni;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("aes") {
                return Backend::NeonAes;
            }
        }
        Backend::Soft
    }

    /// Every backend this CPU can run, so tests cover the fallbacks too.
    #[cfg(test)]
    #[allow(unused_mut)] // no other backends on some targets
    fn all_available() -> Vec<Self> {
        let mut all = vec![Backend::Soft];
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("aes") {
                all.push(Backend::NeonAes);
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("ssse3") {
                all.push(Backend::Aesni);
            }
            if std::is_x86_feature_detected!("avx2") {
                if std::is_x86_feature_detected!("aes") {
                    all.push(Backend::AesniAvx2);
                }
                if std::is_x86_feature_detected!("gfni") {
                    all.push(Backend::GfniAvx2);
                }
            }
        }
        all
    }

    fn key_schedule(self, key: &[u8; 16]) -> [u32; 32] {
        match self {
            Backend::Soft => expand_key(key, tau_soft),
            // SAFETY: each variant is only constructed after detecting the features it needs.
            #[cfg(target_arch = "aarch64")]
            Backend::NeonAes => unsafe { aarch64::key_schedule(key) },
            // SAFETY: each variant is only constructed after detecting the features it needs.
            #[cfg(target_arch = "x86_64")]
            Backend::Aesni | Backend::AesniAvx2 => unsafe { x86::aesni::key_schedule(key) },
            #[cfg(target_arch = "x86_64")]
            Backend::GfniAvx2 => unsafe { x86::gfni::key_schedule(key) },
        }
    }

    /// `buf` must be a whole number of blocks.
    fn cbc_encrypt(self, rk: &[u32; 32], iv: &[u8; 16], buf: &mut [u8]) {
        match self {
            Backend::Soft => cbc_encrypt_soft(rk, iv, buf),
            // SAFETY: see `key_schedule`.
            #[cfg(target_arch = "aarch64")]
            Backend::NeonAes => unsafe { aarch64::cbc_encrypt(rk, iv, buf) },
            // SAFETY: see `key_schedule`.
            #[cfg(target_arch = "x86_64")]
            Backend::Aesni | Backend::AesniAvx2 => unsafe { x86::aesni::cbc_encrypt(rk, iv, buf) },
            #[cfg(target_arch = "x86_64")]
            Backend::GfniAvx2 => unsafe { x86::gfni::cbc_encrypt(rk, iv, buf) },
        }
    }

    /// `rk` is the encryption schedule; `buf` must be a whole number of blocks.
    fn cbc_decrypt(self, rk: &[u32; 32], iv: &[u8; 16], buf: &mut [u8]) {
        let mut reversed = *rk;
        reversed.reverse();
        let mut chain = *iv;
        // SAFETY (all unsafe calls): each variant is only constructed after detecting the
        // features its functions need.
        match self {
            Backend::Soft => {
                let rest =
                    cbc_decrypt_chunks::<BLOCK_LEN>(&reversed, &mut chain, buf, |keys, block| {
                        crypt_block_soft(keys, block)
                    });
                debug_assert!(rest.is_empty());
            }
            #[cfg(target_arch = "aarch64")]
            Backend::NeonAes => {
                let rest = cbc_decrypt_chunks(&reversed, &mut chain, buf, |keys, batch| unsafe {
                    aarch64::crypt_wide(keys, batch)
                });
                let rest = cbc_decrypt_chunks(&reversed, &mut chain, rest, |keys, batch| unsafe {
                    aarch64::crypt4(keys, batch)
                });
                cbc_decrypt_tail(&reversed, &chain, rest, |keys, batch| unsafe {
                    aarch64::crypt4(keys, batch)
                });
            }
            #[cfg(target_arch = "x86_64")]
            Backend::Aesni => {
                let rest = cbc_decrypt_chunks(&reversed, &mut chain, buf, |keys, batch| unsafe {
                    x86::aesni::crypt4(keys, batch)
                });
                cbc_decrypt_tail(&reversed, &chain, rest, |keys, batch| unsafe {
                    x86::aesni::crypt4(keys, batch)
                });
            }
            #[cfg(target_arch = "x86_64")]
            Backend::AesniAvx2 => {
                let rest = cbc_decrypt_chunks(&reversed, &mut chain, buf, |keys, batch| unsafe {
                    x86::aesni_avx2::crypt_wide(keys, batch)
                });
                let rest = cbc_decrypt_chunks(&reversed, &mut chain, rest, |keys, batch| unsafe {
                    x86::aesni_avx2::crypt8(keys, batch)
                });
                cbc_decrypt_tail(&reversed, &chain, rest, |keys, batch| unsafe {
                    x86::aesni_avx2::crypt8(keys, batch)
                });
            }
            #[cfg(target_arch = "x86_64")]
            Backend::GfniAvx2 => {
                let rest = cbc_decrypt_chunks(&reversed, &mut chain, buf, |keys, batch| unsafe {
                    x86::gfni_avx2::crypt_wide(keys, batch)
                });
                let rest = cbc_decrypt_chunks(&reversed, &mut chain, rest, |keys, batch| unsafe {
                    x86::gfni_avx2::crypt8(keys, batch)
                });
                cbc_decrypt_tail(&reversed, &chain, rest, |keys, batch| unsafe {
                    x86::gfni_avx2::crypt8(keys, batch)
                });
            }
        }
    }
}

impl Default for SM4 {
    fn default() -> Self {
        Self::new()
    }
}

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
        let key_bytes = normalize_key_material(key);
        self.rk = Backend::detect().key_schedule(&key_bytes);
        self.iv = normalize_key_material(iv);
        Ok(())
    }

    /// 加密字符串
    pub fn encrypt(&self, plaintext: &str) -> Result<String, Box<dyn Error>> {
        let buf = self.encrypt_padded(plaintext.as_bytes(), Backend::detect());
        Ok(hex::encode_lower(&buf))
    }

    /// 解密字符串
    pub fn decrypt(&self, ciphertext: &str) -> Result<String, Box<dyn Error>> {
        let mut buf = hex_to_bytes(ciphertext)?;
        if buf.len() % BLOCK_LEN != 0 {
            return Err(Box::new(SM4Error::InvalidKeyLength));
        }
        Backend::detect().cbc_decrypt(&self.rk, &self.iv, &mut buf);
        let plain_len = pkcs7_unpadded_len(&buf)?;
        buf.truncate(plain_len);
        Ok(String::from_utf8(buf)?)
    }

    /// PKCS#7 pad and CBC encrypt into a fresh buffer.
    fn encrypt_padded(&self, input: &[u8], backend: Backend) -> Vec<u8> {
        let pad_len = BLOCK_LEN - input.len() % BLOCK_LEN;
        let mut buf = Vec::with_capacity(input.len() + pad_len);
        buf.extend_from_slice(input);
        buf.resize(input.len() + pad_len, pad_len as u8);
        backend.cbc_encrypt(&self.rk, &self.iv, &mut buf);
        buf
    }
}

/// Keys and IVs of any other length become the first 16 ASCII hex digits of their SM3 hash
/// (matches the Java behaviour).
fn normalize_key_material(material: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    if material.len() == 16 {
        out.copy_from_slice(material);
    } else {
        let digest = crate::sm3::digest_parts(&[material]);
        hex::encode_upper_into(&digest[..8], &mut out);
    }
    out
}

/// Length of the data before the PKCS#7 padding. All padding bytes are always examined.
fn pkcs7_unpadded_len(input: &[u8]) -> Result<usize, SM4Error> {
    let Some(&last) = input.last() else {
        return Ok(0);
    };
    let pad_len = last as usize;
    if pad_len == 0 || pad_len > BLOCK_LEN || input.len() < pad_len {
        return Err(SM4Error::InvalidPadding);
    }
    let start = input.len() - pad_len;
    let mismatch = input[start..].iter().fold(0u8, |acc, &b| acc | (b ^ last));
    if mismatch != 0 {
        return Err(SM4Error::InvalidPadding);
    }
    Ok(start)
}

// 16进制字符串转字节数组
fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, SM4Error> {
    if hex_str.len() % 2 != 0 {
        return Err(SM4Error::InvalidHexString);
    }
    if let Some(bytes) = hex::decode_plain(hex_str) {
        return Ok(bytes);
    }
    // Anything but plain digits keeps the historic parse, including its acceptance of "+f".
    let mut bytes = Vec::with_capacity(hex_str.len() / 2);
    for i in (0..hex_str.len()).step_by(2) {
        let byte =
            u8::from_str_radix(&hex_str[i..i + 2], 16).map_err(|_| SM4Error::InvalidHexString)?;
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
        let expected_ciphertext =
            "09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc";
        assert_eq!(ciphertext, expected_ciphertext);

        let decrypted = sm4.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    fn unhex16(h: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// Single raw block on one backend, through its CBC entry point with a zero IV.
    fn encrypt_raw(backend: Backend, rk: &[u32; 32], block: &mut [u8; 16]) {
        backend.cbc_encrypt(rk, &[0; 16], block);
    }

    /// GB/T 32907-2016 example 1 and the 1,000,000 iteration example 2, on every backend.
    #[test]
    fn standard_vectors_on_every_backend() {
        let key = unhex16("0123456789abcdeffedcba9876543210");
        let once = unhex16("681edf34d206965e86b3e94f536e4246");
        let million = unhex16("595298c7c6fd271f0402f804c33d3f66");
        for backend in Backend::all_available() {
            let rk = backend.key_schedule(&key);
            let mut block = key;
            encrypt_raw(backend, &rk, &mut block);
            assert_eq!(block, once, "{backend:?}");

            let mut single = once;
            backend.cbc_decrypt(&rk, &[0; 16], &mut single);
            assert_eq!(single, key, "{backend:?}");

            let mut block = key;
            for _ in 0..1_000_000 {
                encrypt_raw(backend, &rk, &mut block);
            }
            assert_eq!(block, million, "{backend:?}");
        }
    }

    fn pseudo_random(seed: u32, len: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(2_654_435_761) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 11) as u8
            })
            .collect()
    }

    /// All backends agree with the portable code for every block count around the batch sizes.
    #[test]
    fn backends_agree_on_all_lengths() {
        let key: [u8; 16] = pseudo_random(1, 16).try_into().unwrap();
        let iv: [u8; 16] = pseudo_random(2, 16).try_into().unwrap();
        let reference_rk = Backend::Soft.key_schedule(&key);
        for blocks in 0..70 {
            let plain = pseudo_random(blocks as u32 + 3, blocks * 16);
            let mut expected = plain.clone();
            Backend::Soft.cbc_encrypt(&reference_rk, &iv, &mut expected);
            for backend in Backend::all_available() {
                let rk = backend.key_schedule(&key);
                assert_eq!(rk, reference_rk, "{backend:?}");
                let mut buf = plain.clone();
                backend.cbc_encrypt(&rk, &iv, &mut buf);
                assert_eq!(buf, expected, "{backend:?} encrypt {blocks}");
                backend.cbc_decrypt(&rk, &iv, &mut buf);
                assert_eq!(buf, plain, "{backend:?} decrypt {blocks}");
            }
        }
    }

    /// The soft path against a straight reading of the standard's round function.
    #[test]
    fn soft_round_function_matches_definition() {
        for x in pseudo_random(9, 4096).chunks_exact(4) {
            let x = u32::from_be_bytes(x.try_into().unwrap());
            assert_eq!(t_soft(x), l(tau_soft(x)));
        }
    }
}
