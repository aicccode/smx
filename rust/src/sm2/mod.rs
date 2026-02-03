// SM2椭圆曲线公钥密码算法实现

pub mod bigint256;
pub mod fp;
pub mod point;

use bigint256::BigInt256;
use point::{ECPoint, SM2_N};
use crate::sm3::Sm3;

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

            // KDF
            let key = Self::kdf(message.len(), &p2);

            // 检查密钥是否全零
            if key.iter().all(|&b| b == 0) {
                continue;
            }

            // C2 = M XOR t
            let mut c2 = message.to_vec();
            for i in 0..c2.len() {
                c2[i] ^= key[i];
            }

            // C3 = SM3(x2 || M || y2)
            let mut sm3 = Sm3::new();
            sm3.update(&p2.x.to_be_bytes());
            sm3.update(message);
            sm3.update(&p2.y.to_be_bytes());
            sm3.finish();
            let c3 = sm3.hash_bytes();

            // 输出 C1 || C3 || C2
            let mut result = String::new();
            result.push_str(&c1.to_hex_encoded());
            result.push_str(&bytes_to_hex(c3));
            result.push_str(&bytes_to_hex(&c2));

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

        // KDF
        let key = Self::kdf(c2.len(), &p2);

        // M = C2 XOR t
        for i in 0..c2.len() {
            c2[i] ^= key[i];
        }

        // 验证 C3
        let mut sm3 = Sm3::new();
        sm3.update(&p2.x.to_be_bytes());
        sm3.update(&c2);
        sm3.update(&p2.y.to_be_bytes());
        sm3.finish();
        let computed_c3 = sm3.hash_bytes();

        if computed_c3.as_slice() != c3.as_slice() {
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
        let mut sm3 = Sm3::new();
        sm3.update(&z);
        sm3.update(message.as_bytes());
        sm3.finish();
        let e = BigInt256::from_be_bytes(sm3.hash_bytes());

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
            let one = BigInt256::ONE;
            let (d_plus_1, _) = d.add(&one);
            let d_plus_1_inv = d_plus_1.mod_inverse(&SM2_N);
            let rd = r.mod_mul(&d, &SM2_N);
            let k_minus_rd = k.mod_sub(&rd, &SM2_N);
            let s = k_minus_rd.mod_mul(&d_plus_1_inv, &SM2_N);

            if s.is_zero() {
                continue;
            }

            // 确保 r 和 s 都是64个十六进制字符
            let r_hex = r.to_hex();
            let s_hex = s.to_hex();
            if r_hex.len() == 64 && s_hex.len() == 64 {
                return Ok(format!("{}h{}", r_hex.to_lowercase(), s_hex.to_lowercase()));
            }
        }
    }

    /// 验签
    pub fn verify(user_id: &str, signature: &str, message: &str, public_key: &str) -> bool {
        let parts: Vec<&str> = signature.split('h').collect();
        if parts.len() != 2 {
            return false;
        }

        let r = BigInt256::from_hex(parts[0]);
        let s = BigInt256::from_hex(parts[1]);

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
        let mut sm3 = Sm3::new();
        sm3.update(&z);
        sm3.update(message.as_bytes());
        sm3.finish();
        let e = BigInt256::from_be_bytes(sm3.hash_bytes());

        // t = (r + s) mod n
        let t = r.mod_add(&s, &SM2_N);
        if t.is_zero() {
            return false;
        }

        // (x1, y1) = [s]G + [t]PA
        let sg = ECPoint::generator().multiply(&s);
        let tpa = pub_point.multiply(&t);
        let point = sg.add(&tpa);

        if point.is_infinity() {
            return false;
        }

        // R = (e + x1) mod n
        let computed_r = e.mod_add(&point.x.to_bigint(), &SM2_N);

        r == computed_r
    }

    /// B用户密钥交换
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

        result.sb = Some(bytes_to_hex(&sb));
        result.kb = Some(bytes_to_hex(&kb));
        result.v = Some(v);
        result.za = Some(za);
        result.zb = Some(zb);
        result.success = true;

        result
    }

    /// A用户密钥交换
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

        if s1.as_slice() != sb {
            result.message = Some("协商失败，B用户验证值与A侧计算值不相等".to_string());
            return result;
        }

        let sa = Self::create_s(0x03, &u, &za, &zb, r_a, r_b);

        result.sa = Some(bytes_to_hex(&sa));
        result.ka = Some(bytes_to_hex(&ka));
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
        s2.as_slice() == sa
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

    /// KDF密钥派生函数（用于加密）
    fn kdf(keylen: usize, p2: &ECPoint) -> Vec<u8> {
        let mut result = vec![0u8; keylen];
        let mut ct = 1u32;
        let blocks = (keylen + 31) / 32;

        for i in 0..blocks {
            let mut sm3 = Sm3::new();
            sm3.update(&p2.x.to_be_bytes());
            sm3.update(&p2.y.to_be_bytes());
            sm3.update(&ct.to_be_bytes());
            sm3.finish();
            let hash = sm3.hash_bytes();

            let start = i * 32;
            let end = ((i + 1) * 32).min(keylen);
            let copy_len = end - start;
            result[start..start + copy_len].copy_from_slice(&hash[..copy_len]);

            ct += 1;
        }

        result
    }

    /// KDF密钥派生函数（用于密钥交换）
    fn kdf_key_swap(keylen: usize, vu: &ECPoint, za: &[u8], zb: &[u8]) -> Vec<u8> {
        let mut result = vec![0u8; keylen];
        let mut ct = 1u32;
        let blocks = (keylen + 31) / 32;

        for i in 0..blocks {
            let mut sm3 = Sm3::new();
            sm3.update(&vu.x.to_be_bytes());
            sm3.update(&vu.y.to_be_bytes());
            sm3.update(za);
            sm3.update(zb);
            sm3.update(&ct.to_be_bytes());
            sm3.finish();
            let hash = sm3.hash_bytes();

            let start = i * 32;
            let end = ((i + 1) * 32).min(keylen);
            let copy_len = end - start;
            result[start..start + copy_len].copy_from_slice(&hash[..copy_len]);

            ct += 1;
        }

        result
    }

    /// 计算用户身份Z值
    fn user_sm3_z(user_id: &[u8], public_key: &ECPoint) -> Vec<u8> {
        let mut sm3 = Sm3::new();

        // ENTL (2字节)
        let entl = (user_id.len() * 8) as u16;
        sm3.update_byte((entl >> 8) as u8);
        sm3.update_byte((entl & 0xFF) as u8);

        // ID
        sm3.update(user_id);

        // a
        sm3.update(&point::SM2_A.to_be_bytes());

        // b
        sm3.update(&point::SM2_B.to_be_bytes());

        // Gx
        sm3.update(&point::SM2_GX.to_be_bytes());

        // Gy
        sm3.update(&point::SM2_GY.to_be_bytes());

        // xA
        sm3.update(&public_key.x.to_be_bytes());

        // yA
        sm3.update(&public_key.y.to_be_bytes());

        sm3.finish();
        sm3.hash_bytes().to_vec()
    }

    /// 密钥交换协议中的x_计算
    fn calc_x(x: BigInt256) -> BigInt256 {
        // 2^w
        let two_pow_w = BigInt256::from_hex("80000000000000000000000000000000");
        // 2^w - 1
        let mask = BigInt256::from_hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        // x & (2^w - 1)
        let x_masked = x.and(&mask);
        // 2^w + masked
        let (result, _) = two_pow_w.add(&x_masked);
        result
    }

    /// 计算 t = (d + x_ * r) mod n
    fn calc_t(n: &BigInt256, r: &BigInt256, d: &BigInt256, x_: &BigInt256) -> BigInt256 {
        let xr = x_.mod_mul(r, n);
        d.mod_add(&xr, n)
    }

    /// 计算点 [t](P + [x_]R)
    fn calc_point(t: &BigInt256, x_: &BigInt256, p: &ECPoint, r: &ECPoint) -> ECPoint {
        let xr = r.multiply(x_);
        let sum = p.add(&xr);
        sum.multiply(t)
    }

    /// 创建验证值S
    fn create_s(tag: u8, vu: &ECPoint, za: &[u8], zb: &[u8], ra: &ECPoint, rb: &ECPoint) -> Vec<u8> {
        // 第一个哈希
        let mut sm3 = Sm3::new();
        sm3.update(&vu.x.to_be_bytes());
        sm3.update(za);
        sm3.update(zb);
        sm3.update(&ra.x.to_be_bytes());
        sm3.update(&ra.y.to_be_bytes());
        sm3.update(&rb.x.to_be_bytes());
        sm3.update(&rb.y.to_be_bytes());
        sm3.finish();
        let h1 = sm3.hash_bytes().to_vec();

        // 第二个哈希
        let mut hash = Sm3::new();
        hash.update_byte(tag);
        hash.update(&vu.y.to_be_bytes());
        hash.update(&h1);
        hash.finish();
        hash.hash_bytes().to_vec()
    }
}

// ============ 辅助函数 ============

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Invalid hex string length".to_string());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in 0..hex.len() / 2 {
        let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "Invalid hex character")?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// 使用系统随机数生成器填充字节数组
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
        let d_a = BigInt256::from_hex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE");
        let p_a = SM2::get_public_key(&d_a);

        // A的随机密钥对
        let ra = BigInt256::from_hex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
        let r_a = SM2::get_public_key(&ra);

        // B的密钥对
        let d_b = BigInt256::from_hex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53");
        let p_b = SM2::get_public_key(&d_b);

        // B的随机密钥对
        let rb = BigInt256::from_hex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
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
