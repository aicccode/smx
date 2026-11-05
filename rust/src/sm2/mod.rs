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

use crate::hex;
use crate::sm3::{Sm3, digest_parts};
use bigint256::BigInt256;
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

/// Equality of byte strings that does not stop at the first difference.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    core::hint::black_box(diff) == 0
}

/// SM2密钥交换协议参数
#[derive(Clone, Debug)]
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

impl SM2KeySwapParams {
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
    pub fn gen_key_pair() -> (String, String) {
        loop {
            let private_key = Self::random_bigint();

            // 确保私钥在有效范围 [1, n-1]
            if private_key.is_zero() || private_key.compare(&SM2_N) != core::cmp::Ordering::Less {
                continue;
            }

            let public_key = ECPoint::generator().multiply(&private_key);

            let pri_hex = private_key.to_hex();
            let pub_hex = public_key.to_hex_encoded();

            // 确保长度正确
            if pri_hex.len() == 64 && pub_hex.len() == 130 {
                return (pri_hex, pub_hex);
            }
        }
    }

    /// 公钥加密
    pub fn encrypt(plaintext: &str, public_key: &str) -> Result<String, String> {
        let message = plaintext.as_bytes();
        if message.is_empty() {
            return Err("Plaintext cannot be empty".to_string());
        }

        let pub_point = ECPoint::from_hex_encoded(public_key);
        if !pub_point.is_on_curve() {
            return Err("Invalid public key".to_string());
        }

        loop {
            // 生成随机数 k
            let k = Self::random_bigint();
            if k.is_zero() || k.compare(&SM2_N) != core::cmp::Ordering::Less {
                continue;
            }

            // C1 = [k]G
            let c1 = ECPoint::generator().multiply(&k);

            // P2 = [k]PB
            let p2 = pub_point.multiply(&k);
            if p2.is_infinity() {
                continue;
            }

            // C2 = M XOR t
            let (x2, y2) = (p2.x.to_be_bytes(), p2.y.to_be_bytes());
            let mut c2 = message.to_vec();
            if Self::kdf_xor(&mut c2, &x2, &y2) {
                // 检查密钥是否全零
                continue;
            }

            // C3 = SM3(x2 || M || y2)
            let c3 = digest_parts(&[&x2, message, &y2]);

            // 输出 C1 || C3 || C2
            let mut result = String::with_capacity(130 + 64 + 2 * c2.len());
            c1.push_hex_encoded(&mut result); // k is in [1, n-1], so C1 is finite
            hex::push_lower(&mut result, &c3);
            hex::push_lower(&mut result, &c2);

            return Ok(result);
        }
    }

    /// 私钥解密
    pub fn decrypt(ciphertext: &str, private_key: &str) -> Result<String, String> {
        if ciphertext.len() < 130 + 64 {
            return Err("Ciphertext too short".to_string());
        }

        // 解析 C1 || C3 || C2
        let c1_hex = &ciphertext[0..130];
        let c3_hex = &ciphertext[130..194];
        let c2_hex = &ciphertext[194..];

        let c1 = ECPoint::from_hex_encoded(c1_hex);
        if !c1.is_on_curve() {
            return Err("Invalid C1 point".to_string());
        }

        let c3 = hex_to_bytes(c3_hex)?;
        let mut c2 = hex_to_bytes(c2_hex)?;

        let d = BigInt256::from_hex(private_key);

        // P2 = [d]C1
        let p2 = c1.multiply(&d);
        if p2.is_infinity() {
            return Err("Invalid decryption".to_string());
        }

        // M = C2 XOR t
        let (x2, y2) = (p2.x.to_be_bytes(), p2.y.to_be_bytes());
        Self::kdf_xor(&mut c2, &x2, &y2);

        // 验证 C3
        let computed_c3 = digest_parts(&[&x2, &c2, &y2]);
        if !ct_eq(&computed_c3, &c3) {
            return Err("Decryption verification failed".to_string());
        }

        String::from_utf8(c2).map_err(|e| format!("UTF-8 decode error: {}", e))
    }

    /// 签名
    pub fn sign(user_id: &str, message: &str, private_key: &str) -> Result<String, String> {
        let d = BigInt256::from_hex(private_key);
        let public_key = ECPoint::generator().multiply(&d);

        // 计算 Z
        let z = Self::user_sm3_z(user_id.as_bytes(), &public_key);

        // e = SM3(Z || M)
        let e = BigInt256::from_be_bytes(&digest_parts(&[&z, message.as_bytes()]));

        // (1 + d)^-1 does not change between attempts, so it is computed at most once.
        let mut d_plus_1_inv = None;
        loop {
            // 生成随机数 k
            let k = Self::random_bigint();
            if k.is_zero() || k.compare(&SM2_N) != core::cmp::Ordering::Less {
                continue;
            }

            // (x1, y1) = [k]G
            let kp = ECPoint::generator().multiply(&k);
            let x1 = kp.x.to_bigint();

            // r = (e + x1) mod n
            let r = e.mod_add(&x1, &SM2_N);
            if r.is_zero() {
                continue;
            }

            // 检查 r + k != n
            let (rk, _) = r.add(&k);
            if rk == SM2_N {
                continue;
            }

            // s = ((1 + d)^-1 * (k - r*d)) mod n
            let inv =
                *d_plus_1_inv.get_or_insert_with(|| d.add(&BigInt256::ONE).0.mod_inverse(&SM2_N));
            let rd = r.mod_mul(&d, &SM2_N);
            let k_minus_rd = k.mod_sub(&rd, &SM2_N);
            let s = k_minus_rd.mod_mul(&inv, &SM2_N);

            if s.is_zero() {
                continue;
            }

            let mut out = String::with_capacity(129);
            hex::push_lower(&mut out, &r.to_be_bytes());
            out.push('h');
            hex::push_lower(&mut out, &s.to_be_bytes());
            return Ok(out);
        }
    }

    /// 验签
    pub fn verify(user_id: &str, signature: &str, message: &str, public_key: &str) -> bool {
        let mut parts = signature.split('h');
        let (Some(r_hex), Some(s_hex), None) = (parts.next(), parts.next(), parts.next()) else {
            return false;
        };

        let r = BigInt256::from_hex(r_hex);
        let s = BigInt256::from_hex(s_hex);

        // 验证 r, s 在 [1, n-1] 范围内
        if r.is_zero() || r.compare(&SM2_N) != core::cmp::Ordering::Less {
            return false;
        }
        if s.is_zero() || s.compare(&SM2_N) != core::cmp::Ordering::Less {
            return false;
        }

        let pub_point = ECPoint::from_hex_encoded(public_key);
        if !pub_point.is_on_curve() {
            return false;
        }

        // 计算 Z
        let z = Self::user_sm3_z(user_id.as_bytes(), &pub_point);

        // e = SM3(Z || M)
        let e = BigInt256::from_be_bytes(&digest_parts(&[&z, message.as_bytes()]));

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
        let computed_r = e.mod_add(&point.x.to_bigint(), &SM2_N);

        r == computed_r
    }

    /// B用户密钥交换
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
        let mut result = SM2KeySwapParams::new();

        // x2_ = 2^w + (x2 & (2^w - 1))
        let x2_ = Self::calc_x(r_b.x.to_bigint());

        // tb = (dB + x2_ * rb) mod n
        let tb = Self::calc_t(&SM2_N, rb, d_b, &x2_);

        // 验证 Ra 在曲线上
        if !r_a.is_on_curve() {
            result.message = Some("协商失败，A用户随机公钥不是椭圆曲线倍点".to_string());
            return result;
        }

        // x1_ = 2^w + (x1 & (2^w - 1))
        let x1_ = Self::calc_x(r_a.x.to_bigint());

        // V = [tb](PA + [x1_]RA)
        let v = Self::calc_point(&tb, &x1_, p_a, r_a);
        if v.is_infinity() {
            result.message = Some("协商失败，V点是无穷远点".to_string());
            return result;
        }

        let za = Self::user_sm3_z(id_a.as_bytes(), p_a);
        let zb = Self::user_sm3_z(id_b.as_bytes(), p_b);

        let kb = Self::kdf_key_swap(byte_len, &v, &za, &zb);
        let sb = Self::create_s(0x02, &v, &za, &zb, r_a, r_b);

        result.sb = Some(hex::encode_lower(&sb));
        result.kb = Some(hex::encode_lower(&kb));
        result.v = Some(v);
        result.za = Some(za.to_vec());
        result.zb = Some(zb.to_vec());
        result.success = true;

        result
    }

    /// A用户密钥交换
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
        let mut result = SM2KeySwapParams::new();

        // x1_ = 2^w + (x1 & (2^w - 1))
        let x1_ = Self::calc_x(r_a.x.to_bigint());

        // ta = (dA + x1_ * ra) mod n
        let ta = Self::calc_t(&SM2_N, ra, d_a, &x1_);

        // 验证 Rb 在曲线上
        if !r_b.is_on_curve() {
            result.message = Some("协商失败，B用户随机公钥不是椭圆曲线倍点".to_string());
            return result;
        }

        // x2_ = 2^w + (x2 & (2^w - 1))
        let x2_ = Self::calc_x(r_b.x.to_bigint());

        // U = [ta](PB + [x2_]RB)
        let u = Self::calc_point(&ta, &x2_, p_b, r_b);
        if u.is_infinity() {
            result.message = Some("协商失败，U点是无穷远点".to_string());
            return result;
        }

        let za = Self::user_sm3_z(id_a.as_bytes(), p_a);
        let zb = Self::user_sm3_z(id_b.as_bytes(), p_b);

        let ka = Self::kdf_key_swap(byte_len, &u, &za, &zb);
        let s1 = Self::create_s(0x02, &u, &za, &zb, r_a, r_b);

        if !ct_eq(&s1, sb) {
            result.message = Some("协商失败，B用户验证值与A侧计算值不相等".to_string());
            return result;
        }

        let sa = Self::create_s(0x03, &u, &za, &zb, r_a, r_b);

        result.sa = Some(hex::encode_lower(&sa));
        result.ka = Some(hex::encode_lower(&ka));
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
        let s2 = Self::create_s(0x03, v, za, zb, r_a, r_b);
        ct_eq(&s2, sa)
    }

    /// 解码公钥点
    pub fn decode_point(hex: &str) -> ECPoint {
        ECPoint::from_hex_encoded(hex)
    }

    /// 从私钥计算公钥
    pub fn get_public_key(private_key: &BigInt256) -> ECPoint {
        ECPoint::generator().multiply(private_key)
    }

    // ============ 内部辅助方法 ============

    /// 生成随机256位整数
    fn random_bigint() -> BigInt256 {
        let mut bytes = [0u8; 32];
        getrandom(&mut bytes);
        BigInt256::from_be_bytes(&bytes)
    }

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
            for (byte, key) in chunk.iter_mut().zip(block) {
                *byte ^= key;
                seen |= key;
            }
        }
        seen == 0
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
            let block = h.finalize_digest();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        result
    }

    /// 计算用户身份Z值
    fn user_sm3_z(user_id: &[u8], public_key: &ECPoint) -> [u8; 32] {
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

    /// 计算点 [t](P + [x_]R); x_ comes from the public point R, t is secret. R is on the curve.
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

fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str.len() % 2 != 0 {
        return Err("Invalid hex string length".to_string());
    }
    if let Some(bytes) = hex::decode_plain(hex_str) {
        return Ok(bytes);
    }
    // Anything but plain digits keeps the historic parse, including its acceptance of "+f".
    let mut bytes = Vec::with_capacity(hex_str.len() / 2);
    for i in 0..hex_str.len() / 2 {
        let byte = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|_| "Invalid hex character")?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// 使用系统随机数生成器填充字节数组
#[allow(clippy::needless_return)] // only needless on some targets
fn getrandom(dest: &mut [u8]) {
    #[cfg(target_family = "unix")]
    {
        use std::fs::File;
        use std::io::Read;

        if let Ok(mut f) = File::open("/dev/urandom") {
            let _ = f.read_exact(dest);
            return;
        }
    }

    #[cfg(target_family = "windows")]
    {
        extern "system" {
            fn BCryptGenRandom(
                hAlgorithm: *mut core::ffi::c_void,
                pbBuffer: *mut u8,
                cbBuffer: u32,
                dwFlags: u32,
            ) -> i32;
        }

        unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                dest.as_mut_ptr(),
                dest.len() as u32,
                2, // BCRYPT_USE_SYSTEM_PREFERRED_RNG
            );
        }
        return;
    }

    #[cfg(target_family = "wasm")]
    {
        // WASM环境下使用简单的伪随机数生成
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut state = seed;
        for b in dest.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (state >> 33) as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
