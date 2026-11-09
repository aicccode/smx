//! SM9 key encapsulation and public-key encryption (GB/T 38635.4).

use super::curve::{G1, G1Affine, P1, P2, g1_decode, g1_encode};
use super::fp::Scalar;
use super::fp12::Fp12;
use super::hash::{all_zero, kdf_into};
use super::{
    INVALID_MASTER_PUBLIC, INVALID_USER_PRIVATE, MAX_KDF_BYTES, MAX_RANDOM_ATTEMPTS, Nonces,
    RNG_ERROR, SM9, SM9_HID_ENCRYPT, SM9EncryptMode, Secret, SecretVec, decode_fixed, gt_bytes, h1,
    pairing, parse_g1, parse_g2, pinned, random_scalar,
};
use crate::ct::{ct_barrier, eq_bytes, wipe_bytes};
use crate::hex;
use crate::sm3::{MAX_MESSAGE_BYTES, digest_parts};
use crate::sm4;

/// The one error for every ciphertext that does not decrypt.
const DECRYPT_ERROR: &str = "Decryption verification failed";
const OOM_ERROR: &str = "Out of memory";
const INVALID_KEY_LEN: &str = "Invalid key length";
const IDENTITY_ERROR: &str = "No user key can exist for this identity and master public key";
const MAC_KEY_LEN: usize = 32;
const SM4_KEY_LEN: usize = 16;
const C1_LEN: usize = 65;
const C3_LEN: usize = 32;
/// Key sizes for encapsulation, as for key exchange.
pub(crate) const MAX_SHARED_KEY_BYTES: usize = 1 << 20;

/// Q = [H1(ID || hid)]P1 + Ppub-e, from public data; `None` for the identity.
pub(crate) fn peer_point(user_id: &[u8], hid: u8, ppub: &G1Affine) -> Option<G1> {
    let q = P1
        .to_jacobian()
        .mul_vartime(&h1(user_id, hid).0)
        .add_vartime(&ppub.to_jacobian());
    (!q.is_infinity()).then_some(q)
}

/// e(Ppub-e, P2)^r, computed as e([r]Ppub-e, P2): same value by bilinearity, and a G1
/// multiplication costs far less than a GT exponentiation. `None` only for r = 0.
pub(crate) fn master_gt_pow(ppub: &G1Affine, r: &Scalar) -> Option<Fp12> {
    let rp = Secret(ppub.to_jacobian().mul_ct(&r.0).to_affine()?);
    Some(pairing(&rp.0, &P2))
}

/// C1.xy without the 04 prefix.
fn xy(point: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&g1_encode(point)[1..]);
    out
}

/// PKCS#7 padding into a fresh buffer.
fn pad(message: &[u8]) -> Option<SecretVec> {
    let pad_len = 16 - message.len() % 16;
    let mut buf = SecretVec::zeroed(message.len().checked_add(pad_len)?)?;
    buf.0[..message.len()].copy_from_slice(message);
    buf.0[message.len()..].fill(pad_len as u8);
    Some(buf)
}

fn check_key_len(key_len: usize) -> Result<(), String> {
    if key_len == 0 || key_len > MAX_SHARED_KEY_BYTES {
        return Err(INVALID_KEY_LEN.to_string());
    }
    Ok(())
}

impl SM9 {
    /// 加密 for the identity under the encryption master public key, hid 0x03. The result is
    /// `C1 || C3 || C2` in lower-case hex, C1 with its 04 prefix. Empty plaintext is rejected.
    pub fn encrypt(
        plaintext: impl AsRef<[u8]>,
        user_id: impl AsRef<[u8]>,
        master_public: &str,
        mode: SM9EncryptMode,
    ) -> Result<String, String> {
        Self::encrypt_with_hid(plaintext, user_id, master_public, SM9_HID_ENCRYPT, mode)
    }

    /// `encrypt` with an explicit hid.
    pub fn encrypt_with_hid(
        plaintext: impl AsRef<[u8]>,
        user_id: impl AsRef<[u8]>,
        master_public: &str,
        hid: u8,
        mode: SM9EncryptMode,
    ) -> Result<String, String> {
        let (m, id) = (plaintext.as_ref(), user_id.as_ref());
        Self::encrypt_inner(m, id, master_public, hid, mode, &mut || random_scalar())
    }

    /// `encrypt_with_hid` with a pinned r, for known-answer tests only.
    #[doc(hidden)]
    pub fn encrypt_with_rand(
        plaintext: impl AsRef<[u8]>,
        user_id: impl AsRef<[u8]>,
        master_public: &str,
        hid: u8,
        mode: SM9EncryptMode,
        r_hex: &str,
    ) -> Result<String, String> {
        let (m, id) = (plaintext.as_ref(), user_id.as_ref());
        Self::encrypt_inner(m, id, master_public, hid, mode, &mut pinned(r_hex))
    }

    fn encrypt_inner(
        message: &[u8],
        user_id: &[u8],
        master_public: &str,
        hid: u8,
        mode: SM9EncryptMode,
        next_r: Nonces,
    ) -> Result<String, String> {
        if message.is_empty() {
            return Err("Plaintext cannot be empty".to_string());
        }
        if message.len() as u64 > MAX_KDF_BYTES - MAC_KEY_LEN as u64
            || message.len() as u64 > MAX_MESSAGE_BYTES - 1024
        {
            return Err("Plaintext too long".to_string());
        }
        let ppub = parse_g1(master_public, true).ok_or(INVALID_MASTER_PUBLIC)?;
        let qb = peer_point(user_id, hid, &ppub).ok_or(IDENTITY_ERROR)?;
        let k1_len = match mode {
            SM9EncryptMode::Stream => message.len(),
            SM9EncryptMode::Sm4 => SM4_KEY_LEN,
        };
        let mut key = SecretVec::zeroed(k1_len + MAC_KEY_LEN).ok_or(OOM_ERROR)?;
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let r = next_r()?;
            let Some(c1) = qb.mul_ct(&r.0.0).to_affine() else {
                continue;
            };
            let Some(w) = master_gt_pow(&ppub, &r.0) else {
                continue;
            };
            let w = gt_bytes(&Secret(w).0);
            kdf_into(&[&xy(&c1), &w.0, user_id], &mut key.0);
            let (k1, k2) = key.0.split_at(k1_len);
            if all_zero(k1) {
                continue;
            }
            let c2 = match mode {
                SM9EncryptMode::Stream => {
                    let mut c2 = SecretVec::zeroed(message.len()).ok_or(OOM_ERROR)?;
                    for ((out, m), k) in c2.0.iter_mut().zip(message).zip(k1) {
                        *out = m ^ k;
                    }
                    c2
                }
                SM9EncryptMode::Sm4 => {
                    let mut buf = pad(message).ok_or(OOM_ERROR)?;
                    let mut sm4_key = [0u8; SM4_KEY_LEN];
                    sm4_key.copy_from_slice(k1);
                    sm4::ecb_crypt(&sm4_key, &mut buf.0, false);
                    wipe_bytes(&mut sm4_key);
                    buf
                }
            };
            let c3 = digest_parts(&[&c2.0, k2]);
            let mut out = String::new();
            out.try_reserve_exact(2 * (C1_LEN + C3_LEN + c2.0.len()))
                .map_err(|_| OOM_ERROR)?;
            hex::push_lower(&mut out, &g1_encode(&c1));
            hex::push_lower(&mut out, &c3);
            hex::push_lower(&mut out, &c2.0);
            return Ok(out);
        }
        Err(RNG_ERROR.to_string())
    }

    /// 解密 to text; plaintext that is not UTF-8 fails here, `decrypt_bytes` takes any.
    pub fn decrypt(
        ciphertext: &str,
        user_id: impl AsRef<[u8]>,
        user_private: &str,
        mode: SM9EncryptMode,
    ) -> Result<String, String> {
        let plain = Self::decrypt_bytes(ciphertext, user_id, user_private, mode)?;
        // C3 was verified by then, so this failure tells nothing an attacker could not compute.
        String::from_utf8(plain).map_err(|invalid| {
            let mut bytes = invalid.into_bytes();
            wipe_bytes(&mut bytes);
            "UTF-8 decode error".to_string()
        })
    }

    /// `decrypt` returning bytes. The ciphertext must be the lower-case hex `encrypt` writes and
    /// `mode` the mode it used. C3 is compared in constant time before anything is decrypted;
    /// every ciphertext failure gives the same error.
    pub fn decrypt_bytes(
        ciphertext: &str,
        user_id: impl AsRef<[u8]>,
        user_private: &str,
        mode: SM9EncryptMode,
    ) -> Result<Vec<u8>, String> {
        let user_id = user_id.as_ref();
        let de = Secret(parse_g2(user_private).ok_or(INVALID_USER_PRIVATE)?);

        let text = ciphertext.as_bytes();
        let header = 2 * (C1_LEN + C3_LEN);
        if text.len() <= header || text.len() % 2 != 0 || !hex::has_no_upper_case(text) {
            return Err(DECRYPT_ERROR.to_string());
        }
        let c2_len = text.len() / 2 - C1_LEN - C3_LEN;
        let k1_len = match mode {
            SM9EncryptMode::Stream => c2_len,
            SM9EncryptMode::Sm4 => SM4_KEY_LEN,
        };
        let bad_length = match mode {
            SM9EncryptMode::Stream => c2_len as u64 > MAX_KDF_BYTES - MAC_KEY_LEN as u64,
            SM9EncryptMode::Sm4 => c2_len % 16 != 0,
        };
        if bad_length || c2_len as u64 > MAX_MESSAGE_BYTES - 1024 {
            return Err(DECRYPT_ERROR.to_string());
        }
        let (c1_hex, rest) = text.split_at(2 * C1_LEN);
        let (c3_hex, c2_hex) = rest.split_at(2 * C3_LEN);
        let mut c1_bytes = [0u8; C1_LEN];
        let mut c3 = [0u8; C3_LEN];
        let mut c2 = SecretVec::zeroed(c2_len).ok_or(OOM_ERROR)?;
        if !hex::decode_into(c1_hex, &mut c1_bytes)
            || !hex::decode_into(c3_hex, &mut c3)
            || !hex::decode_into(c2_hex, &mut c2.0)
        {
            return Err(DECRYPT_ERROR.to_string());
        }
        let c1 = g1_decode(&c1_bytes).ok_or(DECRYPT_ERROR)?;

        let w = gt_bytes(&pairing(&c1, &de.0));
        let mut key = SecretVec::zeroed(k1_len + MAC_KEY_LEN).ok_or(OOM_ERROR)?;
        kdf_into(&[&xy(&c1), &w.0, user_id], &mut key.0);
        let (k1, k2) = key.0.split_at(k1_len);
        let k1_zero = all_zero(k1);
        let mac_ok = eq_bytes(&digest_parts(&[&c2.0, k2]), &c3);
        if !mac_ok || k1_zero {
            return Err(DECRYPT_ERROR.to_string());
        }

        match mode {
            SM9EncryptMode::Stream => {
                for (byte, k) in c2.0.iter_mut().zip(k1) {
                    *byte ^= k;
                }
            }
            SM9EncryptMode::Sm4 => {
                let mut sm4_key = [0u8; SM4_KEY_LEN];
                sm4_key.copy_from_slice(k1);
                sm4::ecb_crypt(&sm4_key, &mut c2.0, true);
                wipe_bytes(&mut sm4_key);
                let (padding_ok, plain_len) = sm4::pkcs7_unpad_len(&c2.0);
                if ct_barrier(padding_ok) == 0 {
                    return Err(DECRYPT_ERROR.to_string());
                }
                wipe_bytes(&mut c2.0[plain_len..]);
                c2.0.truncate(plain_len);
            }
        }
        Ok(core::mem::take(&mut c2.0))
    }

    /// 密钥封装 for the identity, hid 0x03: (key K hex, ciphertext C hex), `key_len` bytes from
    /// 1 to 1 MiB.
    pub fn encapsulate(
        user_id: impl AsRef<[u8]>,
        master_public: &str,
        key_len: usize,
    ) -> Result<(String, String), String> {
        Self::encapsulate_with_hid(user_id, master_public, key_len, SM9_HID_ENCRYPT)
    }

    /// `encapsulate` with an explicit hid.
    pub fn encapsulate_with_hid(
        user_id: impl AsRef<[u8]>,
        master_public: &str,
        key_len: usize,
        hid: u8,
    ) -> Result<(String, String), String> {
        let id = user_id.as_ref();
        Self::encapsulate_inner(id, master_public, key_len, hid, &mut || random_scalar())
    }

    /// `encapsulate_with_hid` with a pinned r, for known-answer tests only.
    #[doc(hidden)]
    pub fn encapsulate_with_rand(
        user_id: impl AsRef<[u8]>,
        master_public: &str,
        key_len: usize,
        hid: u8,
        r_hex: &str,
    ) -> Result<(String, String), String> {
        let id = user_id.as_ref();
        Self::encapsulate_inner(id, master_public, key_len, hid, &mut pinned(r_hex))
    }

    fn encapsulate_inner(
        user_id: &[u8],
        master_public: &str,
        key_len: usize,
        hid: u8,
        next_r: Nonces,
    ) -> Result<(String, String), String> {
        check_key_len(key_len)?;
        let ppub = parse_g1(master_public, true).ok_or(INVALID_MASTER_PUBLIC)?;
        let qb = peer_point(user_id, hid, &ppub).ok_or(IDENTITY_ERROR)?;
        let mut key = SecretVec::zeroed(key_len).ok_or(OOM_ERROR)?;
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let r = next_r()?;
            let Some(c) = qb.mul_ct(&r.0.0).to_affine() else {
                continue;
            };
            let Some(w) = master_gt_pow(&ppub, &r.0) else {
                continue;
            };
            let w = gt_bytes(&Secret(w).0);
            if kdf_into(&[&xy(&c), &w.0, user_id], &mut key.0) {
                continue;
            }
            let key_hex = hex::try_encode_lower(&key.0).ok_or(OOM_ERROR)?;
            return Ok((key_hex, hex::encode_lower(&g1_encode(&c))));
        }
        Err(RNG_ERROR.to_string())
    }

    /// 密钥解封装: the `key_len`-byte key for the lower-case hex ciphertext C.
    pub fn decapsulate(
        ciphertext: &str,
        user_id: impl AsRef<[u8]>,
        user_private: &str,
        key_len: usize,
    ) -> Result<String, String> {
        check_key_len(key_len)?;
        let de = Secret(parse_g2(user_private).ok_or(INVALID_USER_PRIVATE)?);
        let c = decode_fixed::<C1_LEN>(ciphertext, false)
            .and_then(|bytes| g1_decode(&bytes.0))
            .ok_or(DECRYPT_ERROR)?;
        let w = gt_bytes(&pairing(&c, &de.0));
        let mut key = SecretVec::zeroed(key_len).ok_or(OOM_ERROR)?;
        if kdf_into(&[&xy(&c), &w.0, user_id.as_ref()], &mut key.0) {
            return Err(DECRYPT_ERROR.to_string());
        }
        hex::try_encode_lower(&key.0).ok_or_else(|| OOM_ERROR.to_string())
    }
}
