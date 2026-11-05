// SM2椭圆曲线公钥密码算法实现

pub mod bigint256;
mod curve;
mod field;
pub mod fp;
mod modinv;
mod order;
pub mod point;
mod precomp;
mod scalar_mul;

use crate::ct::{ct_barrier, eq_bytes, wipe, wipe_bytes};
use crate::hex;
use crate::rng;
use crate::sm3::{MAX_MESSAGE_BYTES, Sm3, digest_parts};
use bigint256::BigInt256;
use core::fmt;
use point::{ECPoint, SM2_N};

/// a, b, Gx, Gy as hashed into every user identity value Z.
const CURVE_PARAMS_BE: [u8; 128] = {
    let parts = [
        point::SM2_A.value.limbs,
        point::SM2_B.value.limbs,
        point::SM2_GX.value.limbs,
        point::SM2_GY.value.limbs,
    ];
    let mut out = [0u8; 128];
    let mut part = 0;
    while part < 4 {
        let mut limb = 0;
        while limb < 4 {
            let bytes = parts[part][3 - limb].to_be_bytes();
            let mut b = 0;
            while b < 8 {
                out[part * 32 + limb * 8 + b] = bytes[b];
                b += 1;
            }
            limb += 1;
        }
        part += 1;
    }
    out
};

/// 2^127 and 2^127 - 1 for the key agreement's truncated coordinate.
const TWO_POW_W: BigInt256 = BigInt256 {
    limbs: [0, 0x8000_0000_0000_0000, 0, 0],
};
const W_MASK: BigInt256 = BigInt256 {
    limbs: [u64::MAX, 0x7FFF_FFFF_FFFF_FFFF, 0, 0],
};

/// n - 1: private keys stay below this, because 1 + d must be invertible modulo n.
const N_MINUS_1: BigInt256 = BigInt256 {
    limbs: [order::N[0] - 1, order::N[1], order::N[2], order::N[3]],
};

/// ENTL is a 16-bit count of bits.
const MAX_USER_ID_BYTES: usize = 8191;
/// The KDF counter is 32 bits and each value yields 32 bytes.
const MAX_KDF_BYTES: u64 = u32::MAX as u64 * 32;
/// Requested session key sizes in key exchange.
const MAX_KEY_EXCHANGE_BYTES: usize = 1 << 20;
/// Rejected values are vanishingly rare with a working RNG, so running out of attempts means the
/// RNG is broken. (A message of one byte sees an all-zero keystream 1 time in 256.)
const MAX_RANDOM_ATTEMPTS: u32 = 64;

const RNG_ERROR: &str = "System random number generator failed";
const OOM_ERROR: &str = "Out of memory";
const DECRYPT_ERROR: &str = "Decryption verification failed";

/// A secret value that is wiped however its scope ends. Best effort, as for all wiping: it does
/// not reach copies the compiler made or the working state inside scalar multiplications.
struct Secret(BigInt256);

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0.limbs, [0; 4]);
    }
}

/// Fixed-size secret bytes with the same property.
struct SecretBytes([u8; 32]);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe(&mut self.0, [0; 32]);
    }
}

/// A shared-secret point with the same property.
struct SecretPoint(ECPoint);

impl Drop for SecretPoint {
    fn drop(&mut self) {
        wipe(&mut self.0.x.value.limbs, [0; 4]);
        wipe(&mut self.0.y.value.limbs, [0; 4]);
    }
}

/// True for values allowed as private keys: 1 <= d <= n - 2.
fn is_valid_private_key(d: &BigInt256) -> bool {
    !d.is_zero() && d.compare(&N_MINUS_1) == core::cmp::Ordering::Less
}

/// Exactly 64 hex digits of either case, in [1, n - 2].
fn parse_private_key(hex: &str) -> Option<Secret> {
    let d = Secret(BigInt256::from_fixed_hex(hex.as_bytes())?);
    is_valid_private_key(&d.0).then_some(d)
}

/// A uniform value in [1, limit - 1], by rejection sampling from the OS generator.
fn random_below(limit: &BigInt256) -> Result<Secret, &'static str> {
    for _ in 0..MAX_RANDOM_ATTEMPTS {
        let mut bytes = SecretBytes([0u8; 32]);
        rng::fill(&mut bytes.0).map_err(|_| RNG_ERROR)?;
        let candidate = Secret(BigInt256::from_be_bytes(&bytes.0));
        if !candidate.0.is_zero() && candidate.0.compare(limit) == core::cmp::Ordering::Less {
            return Ok(candidate);
        }
    }
    Err(RNG_ERROR)
}

/// The hash value fully reduced modulo n. A 256-bit value is below 2n.
fn hash_to_scalar(digest: &[u8; 32]) -> BigInt256 {
    BigInt256::new(order::reduce_scalar(
        &BigInt256::from_be_bytes(digest).limbs,
    ))
}

/// (e + x) mod n, with x a field element, which can also be above n.
fn add_coordinate(e: &BigInt256, x: &BigInt256) -> BigInt256 {
    e.mod_add(&BigInt256::new(order::reduce_scalar(&x.limbs)), &SM2_N)
}

/// SM2密钥交换协议参数
///
/// `ka`, `kb` and `v` are secrets: `Debug` leaves them out, and callers must not log them.
#[derive(Clone)]
pub struct SM2KeySwapParams {
    pub sa: Option<String>,
    pub sb: Option<String>,
    pub ka: Option<String>,
    pub kb: Option<String>,
    pub v: Option<ECPoint>,
    pub za: Option<Vec<u8>>,
    pub zb: Option<Vec<u8>>,
    pub success: bool,
    pub message: Option<String>,
}

impl fmt::Debug for SM2KeySwapParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SM2KeySwapParams")
            .field("sa", &self.sa)
            .field("sb", &self.sb)
            .field("ka", &self.ka.as_ref().map(|_| ".."))
            .field("kb", &self.kb.as_ref().map(|_| ".."))
            .field("v", &self.v.as_ref().map(|_| ".."))
            .field("za", &self.za)
            .field("zb", &self.zb)
            .field("success", &self.success)
            .field("message", &self.message)
            .finish()
    }
}

impl SM2KeySwapParams {
    fn failed(message: &str) -> Self {
        SM2KeySwapParams {
            message: Some(message.to_string()),
            ..Self::new()
        }
    }

    fn new() -> Self {
        SM2KeySwapParams {
            sa: None,
            sb: None,
            ka: None,
            kb: None,
            v: None,
            za: None,
            zb: None,
            success: false,
            message: None,
        }
    }
}

/// SM2算法主结构
pub struct SM2;

impl SM2 {
    /// 生成密钥对
    /// 返回 (私钥hex, 公钥hex)
    ///
    /// # Panics
    ///
    /// If the operating system's random number generator fails, which this signature has no other
    /// way to report. No key is ever made from anything else. `try_gen_key_pair` returns an error
    /// instead.
    pub fn gen_key_pair() -> (String, String) {
        Self::try_gen_key_pair().expect(RNG_ERROR)
    }

    /// `gen_key_pair` that returns an error when the system random number generator fails.
    pub fn try_gen_key_pair() -> Result<(String, String), String> {
        let private_key = random_below(&N_MINUS_1)?;
        let public_key = ECPoint::generator().multiply(&private_key.0);
        Ok((private_key.0.to_hex(), public_key.to_hex_encoded()))
    }

    /// 公钥加密
    pub fn encrypt(plaintext: &str, public_key: &str) -> Result<String, String> {
        Self::encrypt_with_nonces(plaintext, public_key, || random_below(&SM2_N))
    }

    fn encrypt_with_nonces(
        plaintext: &str,
        public_key: &str,
        mut next_nonce: impl FnMut() -> Result<Secret, &'static str>,
    ) -> Result<String, String> {
        let message = plaintext.as_bytes();
        if message.is_empty() {
            return Err("Plaintext cannot be empty".to_string());
        }
        if message.len() as u64 > MAX_KDF_BYTES {
            return Err("Plaintext too long".to_string());
        }
        let pub_point =
            ECPoint::try_from_hex_encoded(public_key).ok_or("Invalid public key".to_string())?;

        let mut c2 = Vec::new();
        c2.try_reserve_exact(message.len()).map_err(|_| OOM_ERROR)?;
        let output_len = message
            .len()
            .checked_mul(2)
            .and_then(|hex_len| hex_len.checked_add(130 + 64))
            .ok_or(OOM_ERROR)?;
        let mut result = String::new();
        result
            .try_reserve_exact(output_len)
            .map_err(|_| OOM_ERROR)?;

        for _ in 0..MAX_RANDOM_ATTEMPTS {
            // 生成随机数 k
            let k = next_nonce()?;

            // C1 = [k]G
            let c1 = ECPoint::generator().multiply(&k.0);

            // P2 = [k]PB; finite because PB is valid and k is in [1, n-1]
            let p2 = SecretPoint(pub_point.multiply(&k.0));
            if p2.0.is_infinity() {
                continue;
            }

            // C2 = M XOR t
            let x2 = SecretBytes(p2.0.x.to_be_bytes());
            let y2 = SecretBytes(p2.0.y.to_be_bytes());
            c2.clear();
            c2.extend_from_slice(message);
            if Self::kdf_xor(&mut c2, &x2.0, &y2.0) {
                // 检查密钥是否全零
                continue;
            }

            // C3 = SM3(x2 || M || y2)
            let c3 = digest_parts(&[&x2.0, message, &y2.0]);

            // 输出 C1 || C3 || C2
            c1.push_hex_encoded(&mut result); // k is in [1, n-1], so C1 is finite
            hex::push_lower(&mut result, &c3);
            hex::push_lower(&mut result, &c2);

            return Ok(result);
        }
        wipe_bytes(&mut c2);
        Err(RNG_ERROR.to_string())
    }

    /// 私钥解密
    ///
    /// The ciphertext is `C1 || C3 || C2` in hex of either case, with a non-empty C2.
    pub fn decrypt(ciphertext: &str, private_key: &str) -> Result<String, String> {
        // 解析 C1 || C3 || C2. Working on bytes: this text need not be ASCII.
        let text = ciphertext.as_bytes();
        if text.len() <= 130 + 64 {
            return Err("Ciphertext too short".to_string());
        }
        if text.len() % 2 != 0 {
            return Err("Invalid hex string length".to_string());
        }
        let (c1_hex, rest) = text.split_at(130);
        let (c3_hex, c2_hex) = rest.split_at(64);
        if (c2_hex.len() / 2) as u64 > MAX_KDF_BYTES {
            return Err("Ciphertext too long".to_string());
        }

        let mut c1_bytes = [0u8; 65];
        if !hex::decode_into(c1_hex, &mut c1_bytes) {
            return Err("Invalid hex character".to_string());
        }
        let c1 = ECPoint::try_from_encoded(&c1_bytes).ok_or("Invalid C1 point".to_string())?;

        let mut c3 = [0u8; 32];
        let mut c2 = Vec::new();
        c2.try_reserve_exact(c2_hex.len() / 2)
            .map_err(|_| OOM_ERROR)?;
        c2.resize(c2_hex.len() / 2, 0);
        if !hex::decode_into(c3_hex, &mut c3) || !hex::decode_into(c2_hex, &mut c2) {
            return Err("Invalid hex character".to_string());
        }

        let d = parse_private_key(private_key).ok_or("Invalid private key".to_string())?;

        // P2 = [d]C1; finite because C1 is valid and d is in [1, n-2]
        let p2 = SecretPoint(c1.multiply(&d.0));
        if p2.0.is_infinity() {
            return Err(DECRYPT_ERROR.to_string());
        }

        // M = C2 XOR t
        let x2 = SecretBytes(p2.0.x.to_be_bytes());
        let y2 = SecretBytes(p2.0.y.to_be_bytes());
        let keystream_was_zero = Self::kdf_xor(&mut c2, &x2.0, &y2.0);

        // 验证 C3; the two failure causes are reported alike
        let computed_c3 = digest_parts(&[&x2.0, &c2, &y2.0]);
        if !eq_bytes(&computed_c3, &c3) || keystream_was_zero {
            wipe_bytes(&mut c2);
            return Err(DECRYPT_ERROR.to_string());
        }

        String::from_utf8(c2).map_err(|invalid| {
            let mut bytes = invalid.into_bytes();
            wipe_bytes(&mut bytes);
            "UTF-8 decode error".to_string()
        })
    }

    /// 签名
    pub fn sign(user_id: &str, message: &str, private_key: &str) -> Result<String, String> {
        Self::sign_with_nonces(user_id, message, private_key, || random_below(&SM2_N))
    }

    fn sign_with_nonces(
        user_id: &str,
        message: &str,
        private_key: &str,
        mut next_nonce: impl FnMut() -> Result<Secret, &'static str>,
    ) -> Result<String, String> {
        if user_id.len() > MAX_USER_ID_BYTES {
            return Err("User ID too long".to_string());
        }
        if message.len() as u64 > MAX_MESSAGE_BYTES - 32 {
            return Err("Message too long".to_string());
        }
        let d = parse_private_key(private_key).ok_or("Invalid private key".to_string())?;
        let public_key = ECPoint::generator().multiply(&d.0);

        // 计算 Z
        let z = Self::user_sm3_z(user_id.as_bytes(), &public_key);

        // e = SM3(Z || M)
        let e = hash_to_scalar(&digest_parts(&[&z, message.as_bytes()]));

        // d is at most n - 2, so 1 + d is invertible
        let inv = Secret(d.0.add(&BigInt256::ONE).0.mod_inverse(&SM2_N));

        for _ in 0..MAX_RANDOM_ATTEMPTS {
            // 生成随机数 k
            let k = next_nonce()?;

            // (x1, y1) = [k]G
            let kp = SecretPoint(ECPoint::generator().multiply(&k.0));
            let x1 = kp.0.x.to_bigint();

            // r = (e + x1) mod n
            let r = add_coordinate(&e, &x1);
            if r.is_zero() {
                continue;
            }

            // 检查 r + k != n
            let (rk, _) = r.add(&k.0);
            if rk == SM2_N {
                continue;
            }

            // s = ((1 + d)^-1 * (k - r*d)) mod n
            let rd = Secret(r.mod_mul(&d.0, &SM2_N));
            let k_minus_rd = Secret(k.0.mod_sub(&rd.0, &SM2_N));
            let s = k_minus_rd.0.mod_mul(&inv.0, &SM2_N);

            if s.is_zero() {
                continue;
            }

            let mut out = String::with_capacity(129);
            hex::push_lower(&mut out, &r.to_be_bytes());
            out.push('h');
            hex::push_lower(&mut out, &s.to_be_bytes());
            return Ok(out);
        }
        Err(RNG_ERROR.to_string())
    }

    /// 验签
    ///
    /// The signature is `r h s` with r and s exactly 64 hex digits each, in [1, n-1].
    pub fn verify(user_id: &str, signature: &str, message: &str, public_key: &str) -> bool {
        if user_id.len() > MAX_USER_ID_BYTES || message.len() as u64 > MAX_MESSAGE_BYTES - 32 {
            return false;
        }
        let text = signature.as_bytes();
        if text.len() != 129 || text[64] != b'h' {
            return false;
        }
        let (Some(r), Some(s)) = (
            BigInt256::from_fixed_hex(&text[..64]),
            BigInt256::from_fixed_hex(&text[65..]),
        ) else {
            return false;
        };

        // 验证 r, s 在 [1, n-1] 范围内
        if r.is_zero() || r.compare(&SM2_N) != core::cmp::Ordering::Less {
            return false;
        }
        if s.is_zero() || s.compare(&SM2_N) != core::cmp::Ordering::Less {
            return false;
        }

        let Some(pub_point) = ECPoint::try_from_hex_encoded(public_key) else {
            return false;
        };

        // 计算 Z
        let z = Self::user_sm3_z(user_id.as_bytes(), &pub_point);

        // e = SM3(Z || M)
        let e = hash_to_scalar(&digest_parts(&[&z, message.as_bytes()]));

        // t = (r + s) mod n
        let t = r.mod_add(&s, &SM2_N);
        if t.is_zero() {
            return false;
        }

        // (x1, y1) = [s]G + [t]PA
        let point = pub_point.base_mul_add_public(&s, &t);

        if point.is_infinity() {
            return false;
        }

        // R = (e + x1) mod n
        r == add_coordinate(&e, &point.x.to_bigint())
    }

    /// Checks all key exchange inputs; the result is the reason for rejecting them.
    fn check_exchange_inputs(
        byte_len: usize,
        points: [&ECPoint; 4],
        scalars: [&BigInt256; 2],
        ids: [&str; 2],
    ) -> Option<&'static str> {
        if byte_len == 0 || byte_len > MAX_KEY_EXCHANGE_BYTES {
            return Some("协商失败，密钥长度无效");
        }
        if ids.iter().any(|id| id.len() > MAX_USER_ID_BYTES) {
            return Some("协商失败，用户标识过长");
        }
        if points.iter().any(|point| !point.is_on_curve()) {
            return Some("协商失败，公钥不是有效的椭圆曲线点");
        }
        if scalars.iter().any(|scalar| !is_valid_private_key(scalar)) {
            return Some("协商失败，私钥无效");
        }
        None
    }

    /// B用户密钥交换
    ///
    /// All points must be valid and finite, `d_b` and `rb` in [1, n-2], `byte_len` from 1 byte to
    /// 1 MiB, and IDs at most 8191 bytes; otherwise `success` is false and `message` says why.
    #[allow(clippy::too_many_arguments)] // public signature kept for API compatibility
    pub fn get_sb(
        byte_len: usize,
        p_a: &ECPoint,
        r_a: &ECPoint,
        p_b: &ECPoint,
        d_b: &BigInt256,
        r_b: &ECPoint,
        rb: &BigInt256,
        id_a: &str,
        id_b: &str,
    ) -> SM2KeySwapParams {
        if let Some(reason) =
            Self::check_exchange_inputs(byte_len, [p_a, r_a, p_b, r_b], [d_b, rb], [id_a, id_b])
        {
            return SM2KeySwapParams::failed(reason);
        }
        let mut result = SM2KeySwapParams::new();

        // x2_ = 2^w + (x2 & (2^w - 1))
        let x2_ = Self::calc_x(r_b.x.to_bigint());

        // tb = (dB + x2_ * rb) mod n
        let tb = Secret(Self::calc_t(&SM2_N, rb, d_b, &x2_));

        // x1_ = 2^w + (x1 & (2^w - 1))
        let x1_ = Self::calc_x(r_a.x.to_bigint());

        // V = [tb](PA + [x1_]RA)
        let v = Self::calc_point(&tb.0, &x1_, p_a, r_a);
        if v.is_infinity() {
            result.message = Some("协商失败，V点是无穷远点".to_string());
            return result;
        }

        let za = Self::user_sm3_z(id_a.as_bytes(), p_a);
        let zb = Self::user_sm3_z(id_b.as_bytes(), p_b);

        let mut kb = Self::kdf_key_swap(byte_len, &v, &za, &zb);
        let sb = Self::create_s(0x02, &v, &za, &zb, r_a, r_b);

        result.sb = Some(hex::encode_lower(&sb));
        result.kb = Some(hex::encode_lower(&kb));
        wipe_bytes(&mut kb);
        result.v = Some(v);
        result.za = Some(za.to_vec());
        result.zb = Some(zb.to_vec());
        result.success = true;

        result
    }

    /// A用户密钥交换
    ///
    /// Inputs as for `get_sb`; `sb` must be the 32 bytes that B computed.
    #[allow(clippy::too_many_arguments)] // public signature kept for API compatibility
    pub fn get_sa(
        byte_len: usize,
        p_b: &ECPoint,
        r_b: &ECPoint,
        p_a: &ECPoint,
        d_a: &BigInt256,
        r_a: &ECPoint,
        ra: &BigInt256,
        id_a: &str,
        id_b: &str,
        sb: &[u8],
    ) -> SM2KeySwapParams {
        if let Some(reason) =
            Self::check_exchange_inputs(byte_len, [p_b, r_b, p_a, r_a], [d_a, ra], [id_a, id_b])
        {
            return SM2KeySwapParams::failed(reason);
        }
        let mut result = SM2KeySwapParams::new();

        // x1_ = 2^w + (x1 & (2^w - 1))
        let x1_ = Self::calc_x(r_a.x.to_bigint());

        // ta = (dA + x1_ * ra) mod n
        let ta = Secret(Self::calc_t(&SM2_N, ra, d_a, &x1_));

        // x2_ = 2^w + (x2 & (2^w - 1))
        let x2_ = Self::calc_x(r_b.x.to_bigint());

        // U = [ta](PB + [x2_]RB)
        let u = SecretPoint(Self::calc_point(&ta.0, &x2_, p_b, r_b));
        if u.0.is_infinity() {
            result.message = Some("协商失败，U点是无穷远点".to_string());
            return result;
        }

        let za = Self::user_sm3_z(id_a.as_bytes(), p_a);
        let zb = Self::user_sm3_z(id_b.as_bytes(), p_b);

        let s1 = Self::create_s(0x02, &u.0, &za, &zb, r_a, r_b);

        if !eq_bytes(&s1, sb) {
            result.message = Some("协商失败，B用户验证值与A侧计算值不相等".to_string());
            return result;
        }

        let mut ka = Self::kdf_key_swap(byte_len, &u.0, &za, &zb);
        let sa = Self::create_s(0x03, &u.0, &za, &zb, r_a, r_b);

        result.sa = Some(hex::encode_lower(&sa));
        result.ka = Some(hex::encode_lower(&ka));
        wipe_bytes(&mut ka);
        result.success = true;

        result
    }

    /// B用户验证Sa
    pub fn check_sa(
        v: &ECPoint,
        za: &[u8],
        zb: &[u8],
        r_a: &ECPoint,
        r_b: &ECPoint,
        sa: &[u8],
    ) -> bool {
        if za.len() != 32 || zb.len() != 32 || sa.len() != 32 {
            return false;
        }
        if !v.is_on_curve() || !r_a.is_on_curve() || !r_b.is_on_curve() {
            return false;
        }
        let s2 = Self::create_s(0x03, v, za, zb, r_a, r_b);
        eq_bytes(&s2, sa)
    }

    /// 解码公钥点; infinity for anything but a valid point.
    pub fn decode_point(hex: &str) -> ECPoint {
        ECPoint::from_hex_encoded(hex)
    }

    /// 从私钥计算公钥; infinity unless the key is in [1, n-2].
    pub fn get_public_key(private_key: &BigInt256) -> ECPoint {
        if !is_valid_private_key(private_key) {
            return ECPoint::infinity();
        }
        ECPoint::generator().multiply(private_key)
    }

    // ============ 内部辅助方法 ============

    /// KDF keystream (`x2 || y2 || ct`) XORed onto `data`. Returns true if it was all zero.
    fn kdf_xor(data: &mut [u8], x2: &[u8; 32], y2: &[u8; 32]) -> bool {
        // x2 || y2 fills exactly one SM3 block, which all counters then share.
        let mut prefix = Sm3::new();
        prefix.update(x2);
        prefix.update(y2);
        let mut seen = 0u8;
        for (index, chunk) in data.chunks_mut(32).enumerate() {
            let mut h = prefix.clone();
            h.update(&(index as u32 + 1).to_be_bytes());
            let block = h.finalize_digest();
            let mut block = SecretBytes(block);
            for (byte, key) in chunk.iter_mut().zip(block.0.iter_mut()) {
                *byte ^= *key;
                seen |= *key;
            }
        }
        ct_barrier(u64::from(seen)) == 0
    }

    /// KDF密钥派生函数（用于密钥交换）
    fn kdf_key_swap(keylen: usize, vu: &ECPoint, za: &[u8], zb: &[u8]) -> Vec<u8> {
        let mut prefix = Sm3::new();
        prefix.update(&vu.x.to_be_bytes());
        prefix.update(&vu.y.to_be_bytes());
        prefix.update(za);
        prefix.update(zb);

        let mut result = vec![0u8; keylen];
        for (index, chunk) in result.chunks_mut(32).enumerate() {
            let mut h = prefix.clone();
            h.update(&(index as u32 + 1).to_be_bytes());
            let block = SecretBytes(h.finalize_digest());
            chunk.copy_from_slice(&block.0[..chunk.len()]);
        }
        result
    }

    /// 计算用户身份Z值. The ID must be at most 8191 bytes, checked by every caller.
    fn user_sm3_z(user_id: &[u8], public_key: &ECPoint) -> [u8; 32] {
        debug_assert!(user_id.len() <= MAX_USER_ID_BYTES);
        // ENTL (2字节)
        let entl = ((user_id.len() * 8) as u16).to_be_bytes();
        digest_parts(&[
            &entl,
            user_id,
            &CURVE_PARAMS_BE,
            &public_key.x.to_be_bytes(),
            &public_key.y.to_be_bytes(),
        ])
    }

    /// 密钥交换协议中的x_计算: 2^w + (x & (2^w - 1))
    fn calc_x(x: BigInt256) -> BigInt256 {
        TWO_POW_W.add(&x.and(&W_MASK)).0
    }

    /// 计算 t = (d + x_ * r) mod n
    fn calc_t(n: &BigInt256, r: &BigInt256, d: &BigInt256, x_: &BigInt256) -> BigInt256 {
        let xr = x_.mod_mul(r, n);
        d.mod_add(&xr, n)
    }

    /// 计算点 [t](P + [x_]R); x_ comes from the public point R, t is secret. P and R are valid.
    fn calc_point(t: &BigInt256, x_: &BigInt256, p: &ECPoint, r: &ECPoint) -> ECPoint {
        let xr = r.multiply_public(x_);
        let sum = p.add(&xr);
        sum.multiply(t)
    }

    /// 创建验证值S
    fn create_s(
        tag: u8,
        vu: &ECPoint,
        za: &[u8],
        zb: &[u8],
        ra: &ECPoint,
        rb: &ECPoint,
    ) -> [u8; 32] {
        let h1 = digest_parts(&[
            &vu.x.to_be_bytes(),
            za,
            zb,
            &ra.x.to_be_bytes(),
            &ra.y.to_be_bytes(),
            &rb.x.to_be_bytes(),
            &rb.y.to_be_bytes(),
        ]);
        digest_parts(&[&[tag], &vu.y.to_be_bytes(), &h1])
    }
}

// ============ 辅助函数 ============

#[cfg(test)]
fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    hex::decode_plain(hex_str).ok_or_else(|| "Invalid hex".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GB/T 32918.5 sample values with the published nonce.
    const GBT_D: &str = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    const GBT_K: &str = "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21";

    fn pinned(hex: &str) -> impl FnMut() -> Result<Secret, &'static str> + use<'_> {
        move || Ok(Secret(BigInt256::from_hex(hex)))
    }

    #[test]
    fn pinned_nonce_signature_matches_the_standard() {
        let sig = SM2::sign_with_nonces("1234567812345678", "message digest", GBT_D, pinned(GBT_K))
            .unwrap();
        assert_eq!(
            sig,
            "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3h\
             b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa"
        );
    }

    #[test]
    fn nonce_source_failure_and_exhaustion_end_cleanly() {
        let fail = || Err(RNG_ERROR);
        assert_eq!(
            SM2::sign_with_nonces("id", "m", GBT_D, fail).unwrap_err(),
            RNG_ERROR
        );
        let pubkey = ECPoint::generator()
            .multiply(&BigInt256::from_hex(GBT_D))
            .to_hex_encoded();
        assert_eq!(
            SM2::encrypt_with_nonces("m", &pubkey, fail).unwrap_err(),
            RNG_ERROR
        );
    }

    #[test]
    fn pinned_nonce_ciphertext_matches_the_shared_vector() {
        let pubkey = ECPoint::generator()
            .multiply(&BigInt256::from_hex(GBT_D))
            .to_hex_encoded();
        let ct = SM2::encrypt_with_nonces("encryption standard", &pubkey, pinned(GBT_K)).unwrap();
        assert_eq!(
            ct,
            "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df059983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd876621886ca989ca9c7d58087307ca93092d651efa"
        );
    }

    #[test]
    fn test_key_pair_generation() {
        let (pri, pub_key) = SM2::gen_key_pair();
        assert_eq!(pri.len(), 64);
        assert_eq!(pub_key.len(), 130);
        assert!(pub_key.starts_with("04"));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let (pri, pub_key) = SM2::gen_key_pair();
        let message = "encryption standard";

        let encrypted = SM2::encrypt(message, &pub_key).unwrap();
        let decrypted = SM2::decrypt(&encrypted, &pri).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_sign_verify() {
        let (pri, pub_key) = SM2::gen_key_pair();
        let user_id = "ALICE123@YAHOO.COM";
        let message = "encryption standard";

        let signature = SM2::sign(user_id, message, &pri).unwrap();
        let valid = SM2::verify(user_id, &signature, message, &pub_key);

        assert!(valid);
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let (pri, pub_key) = SM2::gen_key_pair();
        let user_id = "ALICE123@YAHOO.COM";
        let message = "encryption standard";

        let signature = SM2::sign(user_id, message, &pri).unwrap();
        let valid = SM2::verify(user_id, &signature, "wrong message", &pub_key);

        assert!(!valid);
    }

    #[test]
    fn test_key_exchange() {
        let id_a = "ALICE123@YAHOO.COM";
        let id_b = "BILL456@YAHOO.COM";

        // A的密钥对
        let d_a =
            BigInt256::from_hex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE");
        let p_a = SM2::get_public_key(&d_a);

        // A的随机密钥对
        let ra =
            BigInt256::from_hex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
        let r_a = SM2::get_public_key(&ra);

        // B的密钥对
        let d_b =
            BigInt256::from_hex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53");
        let p_b = SM2::get_public_key(&d_b);

        // B的随机密钥对
        let rb =
            BigInt256::from_hex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
        let r_b = SM2::get_public_key(&rb);

        // B计算Sb和Kb
        let result_b = SM2::get_sb(16, &p_a, &r_a, &p_b, &d_b, &r_b, &rb, id_a, id_b);
        assert!(result_b.success);

        // A计算Sa和Ka
        let sb_bytes = hex_to_bytes(&result_b.sb.unwrap()).unwrap();
        let result_a = SM2::get_sa(16, &p_b, &r_b, &p_a, &d_a, &r_a, &ra, id_a, id_b, &sb_bytes);
        assert!(result_a.success);

        // 验证Ka == Kb
        assert_eq!(result_a.ka, result_b.kb);

        // B验证Sa
        let sa_bytes = hex_to_bytes(&result_a.sa.unwrap()).unwrap();
        let check = SM2::check_sa(
            result_b.v.as_ref().unwrap(),
            result_b.za.as_ref().unwrap(),
            result_b.zb.as_ref().unwrap(),
            &r_a,
            &r_b,
            &sa_bytes,
        );
        assert!(check);
    }

    #[test]
    fn test_user_sm3_z() {
        let user_id = "ALICE123@YAHOO.COM";
        let (_, pub_key) = SM2::gen_key_pair();
        let point = SM2::decode_point(&pub_key);
        let z = SM2::user_sm3_z(user_id.as_bytes(), &point);
        assert_eq!(z.len(), 32);
    }
}
