//! SM4 国密算法实现 (CBC模式，PKCS#7填充)
//! 参考Java版本实现: java/src/site/aicc/sm4/SM4.java
//!
//! Block code sits behind one dispatch point, chosen at run time: GFNI + AVX2 and AES-NI (+ AVX2)
//! on x86-64, the AES instructions with NEON on AArch64, and a portable table implementation.
//!
//! No path, key schedule included, has a memory access or branch that depends on secret data. The
//! portable code computes the S-box with a Boolean circuit, slower than a table on purpose.
//!
//! # CBC gives no integrity
//!
//! This is unauthenticated CBC. A successful decryption says nothing about who produced the
//! ciphertext, and anyone able to observe decryption failures can use them to recover plaintext.
//! Authenticate the ciphertext (encrypt-then-MAC) before calling `decrypt`.
//!
//! The IV given to `set_key` is reused by every `encrypt` call until the next `set_key`, so equal
//! plaintexts encrypt equally and a shared prefix shows. Set a fresh random IV per message.

use crate::ct::{ct_barrier, wipe, wipe_bytes};
use crate::hex;
use std::error::Error;
use std::fmt;

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod sbox;
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
///
/// Holds only the key schedule and IV, so `&self` methods can run concurrently. See the module
/// documentation for what CBC does not protect against.
pub struct SM4 {
    rk: [u32; 32], // 轮密钥
    iv: [u8; 16],  // CBC初始向量
    keyed: bool,
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

const FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

pub(crate) const CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

// 线性变换 L
#[inline(always)]
const fn l(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

// 线性变换 L'
#[inline(always)]
pub(crate) const fn l_prime(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

#[inline(always)]
fn t_soft(x: u32) -> u32 {
    l(sbox::sbox_word(x))
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
    wipe(&mut k, [0; 4]);
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
            Backend::Soft => expand_key(key, sbox::sbox_word),
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

impl Drop for SM4 {
    fn drop(&mut self) {
        wipe(&mut self.rk, [0; 32]);
        wipe(&mut self.iv, [0; 16]);
    }
}

impl SM4 {
    /// 创建新的SM4实例
    ///
    /// The instance has no key yet: `encrypt` and `decrypt` fail until `set_key` succeeded.
    pub fn new() -> Self {
        SM4 {
            rk: [0; 32],
            iv: [0; 16],
            keyed: false,
        }
    }

    /// 设置密钥和IV
    ///
    /// Both must be exactly 16 bytes. On failure the instance keeps its previous state.
    pub fn set_key(&mut self, key: &[u8], iv: &[u8]) -> Result<(), SM4Error> {
        let key: &[u8; 16] = key.try_into().map_err(|_| SM4Error::InvalidKeyLength)?;
        let iv: &[u8; 16] = iv.try_into().map_err(|_| SM4Error::InvalidIVLength)?;
        self.rk = Backend::detect().key_schedule(key);
        self.iv = *iv;
        self.keyed = true;
        Ok(())
    }

    /// 加密字符串
    ///
    /// CBC with PKCS#7, as lower-case hex. Gives no integrity; see the module documentation.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, Box<dyn Error>> {
        if !self.keyed {
            return Err(Box::new(SM4Error::InvalidKeyLength));
        }
        let buf = self
            .encrypt_padded(plaintext.as_bytes(), Backend::detect())
            .ok_or("Out of memory")?;
        Ok(hex::try_encode_lower(&buf).ok_or("Out of memory")?)
    }

    /// 解密字符串
    ///
    /// Takes the lower-case hex that `encrypt` produces. Bad ciphertext length, bad padding and a
    /// result that is not UTF-8 all return the same `SM4Error::InvalidPadding`, because telling
    /// them apart is a decryption oracle. For the same reason the same UTF-8 validation runs over
    /// the same bytes whether the padding was good or not.
    ///
    /// Limit: that validation stops at the first invalid byte, so its time still depends on the
    /// decrypted content, and success itself is visible to a caller. Neither makes
    /// unauthenticated CBC safe; see the module documentation.
    pub fn decrypt(&self, ciphertext: &str) -> Result<String, Box<dyn Error>> {
        let buf = self.decrypt_blocks(ciphertext)?;
        Ok(text_result(buf)?)
    }

    /// `decrypt` returning the plaintext bytes, which need not be text. No UTF-8 step runs here.
    pub fn decrypt_bytes(&self, ciphertext: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buf = self.decrypt_blocks(ciphertext)?;
        let (padding_ok, plain_len) = pkcs7_check(&buf);
        if ct_barrier(padding_ok) == 0 {
            wipe_bytes(&mut buf);
            return Err(Box::new(SM4Error::InvalidPadding));
        }
        wipe_bytes(&mut buf[plain_len..]);
        buf.truncate(plain_len);
        Ok(buf)
    }

    /// CBC decrypts a non-empty whole number of blocks, padding still attached.
    fn decrypt_blocks(&self, ciphertext: &str) -> Result<Vec<u8>, SM4Error> {
        if !self.keyed {
            return Err(SM4Error::InvalidKeyLength);
        }
        if !hex::has_no_upper_case(ciphertext.as_bytes()) {
            return Err(SM4Error::InvalidHexString);
        }
        let mut buf = hex::decode_plain(ciphertext).ok_or(SM4Error::InvalidHexString)?;
        if buf.is_empty() || buf.len() % BLOCK_LEN != 0 {
            return Err(SM4Error::InvalidPadding);
        }
        Backend::detect().cbc_decrypt(&self.rk, &self.iv, &mut buf);
        Ok(buf)
    }

    /// PKCS#7 pad and CBC encrypt into a fresh buffer; `None` when out of memory.
    fn encrypt_padded(&self, input: &[u8], backend: Backend) -> Option<Vec<u8>> {
        let pad_len = BLOCK_LEN - input.len() % BLOCK_LEN;
        let total = input.len().checked_add(pad_len)?;
        let mut buf = Vec::new();
        buf.try_reserve_exact(total).ok()?;
        buf.extend_from_slice(input);
        buf.resize(total, pad_len as u8);
        backend.cbc_encrypt(&self.rk, &self.iv, &mut buf);
        Some(buf)
    }
}

/// SM4-ECB in place over whole blocks, for SM9's block-cipher encryption mode. Uses the portable
/// rounds with the Boolean-circuit S-box, so it is constant time on every target; SM9 messages are
/// short, so the hardware backends would gain little here.
pub(crate) fn ecb_crypt(key: &[u8; 16], buf: &mut [u8], decrypt: bool) {
    debug_assert_eq!(buf.len() % BLOCK_LEN, 0);
    let mut rk = expand_key(key, sbox::sbox_word);
    if decrypt {
        rk.reverse();
    }
    for block in buf.chunks_exact_mut(BLOCK_LEN) {
        crypt_block_soft(&rk, block);
    }
    wipe(&mut rk, [0; 32]);
}

/// PKCS#7 padding check for SM9: 1 or 0 for the verdict, and the unpadded length.
pub(crate) fn pkcs7_unpad_len(input: &[u8]) -> (u64, usize) {
    pkcs7_check(input)
}

/// Removes the padding from decrypted blocks and returns the text, or the one error.
///
/// The UTF-8 validation runs on the whole buffer, unconditionally and before anything depends on
/// the padding verdict, so a padding failure costs the same validation as a success. Padding bytes
/// are ASCII, which makes this the same answer as validating the text alone when the padding is
/// good. `black_box` keeps the optimizer from moving the work behind the verdict or removing it.
#[inline(never)]
fn text_result(mut buf: Vec<u8>) -> Result<String, SM4Error> {
    let (padding_ok, plain_len) = pkcs7_check(&buf);
    #[cfg(test)]
    tests::VALIDATED_BYTES.with(|count| count.set(buf.len()));
    let utf8_ok =
        core::hint::black_box(core::str::from_utf8(core::hint::black_box(&buf[..])).is_ok());
    if ct_barrier(padding_ok & u64::from(utf8_ok)) == 0 {
        wipe_bytes(&mut buf);
        return Err(SM4Error::InvalidPadding);
    }
    wipe_bytes(&mut buf[plain_len..]);
    buf.truncate(plain_len);
    // SAFETY: the whole buffer was just validated as UTF-8, and the removed bytes were padding
    // bytes below 0x80, each a complete character, so the rest is valid UTF-8 too.
    Ok(unsafe { String::from_utf8_unchecked(buf) })
}

/// Checks PKCS#7 padding of a non-empty whole number of blocks without branching on it. Returns 1
/// or 0 for the verdict, and the length before the padding, which only means anything with a 1.
#[inline(never)]
fn pkcs7_check(input: &[u8]) -> (u64, usize) {
    let block = &input[input.len() - BLOCK_LEN..];
    let pad = u64::from(block[BLOCK_LEN - 1]);
    // Non-zero unless 1 <= pad <= 16: the subtractions wrap into the top bit otherwise.
    let bad_range = (pad.wrapping_sub(1) | (BLOCK_LEN as u64).wrapping_sub(pad)) >> 63;
    let mut bad = ct_barrier(bad_range);
    for (distance, &byte) in block.iter().rev().enumerate() {
        // All ones when this byte is part of the padding.
        let in_padding = ct_barrier(((distance as u64).wrapping_sub(pad) >> 63).wrapping_neg());
        bad |= (u64::from(byte) ^ pad) & in_padding;
    }
    let bad = ct_barrier(bad);
    // 1 when `bad` is zero.
    let ok = ((bad | bad.wrapping_neg()) >> 63) ^ 1;
    (ok, input.len().wrapping_sub(pad as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        /// How many bytes the last `text_result` validated.
        pub(super) static VALIDATED_BYTES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        // Key and IV as the removed text-key path derived them from "this is the key" and
        // "this is the iv": the first 16 hex digits of their SM3 hashes. Other lengths now fail.
        let key = "157224F19FD4C080";
        let iv = "65B06A99625C008A";

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

    /// The UTF-8 oracle: bad padding must cost the same validation as good padding.
    #[test]
    fn validation_runs_over_the_whole_buffer_whatever_the_padding() {
        let mut good = b"hello world".to_vec();
        good.extend_from_slice(&[5; 5]);
        let mut bad_value = good.clone();
        bad_value[15] = 0x41;
        let mut bad_run = good.clone();
        bad_run[12] = 0;
        for (buf, expect_ok) in [(good, true), (bad_value, false), (bad_run, false)] {
            VALIDATED_BYTES.with(|count| count.set(0));
            let result = text_result(buf);
            assert_eq!(VALIDATED_BYTES.with(|count| count.get()), 16);
            assert_eq!(result.is_ok(), expect_ok);
        }
    }

    #[test]
    fn invalid_utf8_under_good_padding_is_the_padding_error() {
        let mut buf = vec![0xff; 11];
        buf.extend_from_slice(&[5; 5]);
        assert!(matches!(text_result(buf), Err(SM4Error::InvalidPadding)));
        // A truncated sequence right before the padding stays invalid with it attached.
        let mut buf = vec![b'a'; 10];
        buf.push(0xe4);
        buf.extend_from_slice(&[5; 5]);
        assert!(text_result(buf).is_err());
    }

    #[test]
    fn bytes_decrypt_takes_any_plaintext_and_upper_case_is_rejected() {
        let (key, iv) = ([3u8; 16], [5u8; 16]);
        let mut sm4 = SM4::new();
        sm4.set_key(&key, &iv).unwrap();
        // Not UTF-8, with its padding appended by hand.
        let mut block = vec![0xffu8; 12];
        block.extend_from_slice(&[4; 4]);
        Backend::detect().cbc_encrypt(&sm4.rk, &iv, &mut block);
        let text = hex::encode_lower(&block);
        assert_eq!(sm4.decrypt_bytes(&text).unwrap(), vec![0xffu8; 12]);
        assert_eq!(
            sm4.decrypt(&text).unwrap_err().to_string(),
            "Invalid padding"
        );

        let ciphertext = sm4.encrypt("hello").unwrap();
        assert_eq!(sm4.decrypt(&ciphertext).unwrap(), "hello");
        assert_eq!(sm4.decrypt_bytes(&ciphertext).unwrap(), b"hello");
        let upper = ciphertext.to_uppercase();
        assert_ne!(upper, ciphertext);
        assert_eq!(
            sm4.decrypt(&upper).unwrap_err().to_string(),
            "Invalid hex string"
        );
        assert!(sm4.decrypt_bytes(&upper).is_err());
    }

    /// Every kind of padding failure and length error gives one and the same error.
    #[test]
    fn padding_failures_are_indistinguishable() {
        let (key, iv) = ([3u8; 16], [5u8; 16]);
        let mut sm4 = SM4::new();
        sm4.set_key(&key, &iv).unwrap();
        let backend = Backend::detect();
        let encrypt_raw_block = |block: &[u8; 16]| {
            let mut buf = *block;
            backend.cbc_encrypt(&sm4.rk, &iv, &mut buf);
            hex::encode_lower(&buf)
        };

        // The padding byte itself: all values but 1..=16, with an otherwise clean block.
        let mut outcomes = Vec::new();
        for pad in 0..=255u8 {
            let mut block = [pad; 16];
            block[0] = b'a'; // keeps pad = 16 invalid and short paddings printable
            let text = encrypt_raw_block(&block);
            let outcome = sm4.decrypt(&text);
            let expected_ok = (1..=15).contains(&pad);
            assert_eq!(outcome.is_ok(), expected_ok, "pad {pad}");
            if let Err(error) = outcome {
                outcomes.push(error.to_string());
            }
        }
        // Inconsistent bytes at each position of a padding of 16.
        for position in 0..16 {
            let mut block = [16u8; 16];
            if position != 15 {
                block[position] ^= 1;
                outcomes.push(
                    sm4.decrypt(&encrypt_raw_block(&block))
                        .unwrap_err()
                        .to_string(),
                );
            }
        }
        // Not UTF-8 under valid padding, and lengths that are not whole blocks.
        let mut block = [1u8; 16];
        block[0] = 0xff;
        outcomes.push(
            sm4.decrypt(&encrypt_raw_block(&block))
                .unwrap_err()
                .to_string(),
        );
        for text in ["", "00", "000000000000000000000000000000", &"0".repeat(34)] {
            outcomes.push(sm4.decrypt(text).unwrap_err().to_string());
        }
        assert!(
            outcomes.iter().all(|m| m == "Invalid padding"),
            "{outcomes:?}"
        );
    }

    #[test]
    fn soft_round_function_matches_definition() {
        for x in pseudo_random(9, 4096).chunks_exact(4) {
            let x = u32::from_be_bytes(x.try_into().unwrap());
            let b = x.to_be_bytes().map(|byte| sbox::SBOX[byte as usize]);
            assert_eq!(t_soft(x), l(u32::from_be_bytes(b)));
        }
    }
}
