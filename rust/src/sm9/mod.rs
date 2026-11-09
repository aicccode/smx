//! SM9 identity-based cryptography (GB/T 38635 / GM/T 0044): key generation, signatures, key
//! encapsulation, encryption and key exchange on the 256-bit BN curve of the standard.
//!
//! The interface follows the SM2 one of this crate: hex strings in and out, `String` errors.
//! Keys and public points are read in either case; signatures, ciphertexts and confirmation
//! values only in the lower case this module writes, so each value has a single spelling.
//! User identities and messages are bytes (`&str` works too).
//!
//! # Security notes
//!
//! - Secret scalars (master keys, r, l and the derived key scalars) drive G1/G2 scalar
//!   multiplications and GT exponentiations with signed fixed windows and masked scans of the
//!   whole table; the field arithmetic is Montgomery on fixed limbs without branches.
//! - Public data (verification, decoding, the subgroup check of G2 points) may take variable time.
//! - The SM4 block mode uses the portable SM4 rounds with the Boolean-circuit S-box, which have
//!   no secret-indexed table lookups.
//! - Copies of secrets this code makes are wiped where practical; that is best effort only.

mod curve;
mod encrypt;
mod exchange;
mod fp;
mod fp12;
mod hash;
mod pairing;
mod tower;

pub use exchange::SM9KeyExchangeResult;

use crate::ct::{wipe, wipe_bytes};
use crate::hex;
use crate::rng;
use crate::sm3::MAX_MESSAGE_BYTES;
use curve::{Affine, G1Affine, G2Affine, P1, P2, g1_decode, g1_encode, g2_decode, g2_encode};
use fp::{Fp, Scalar};
use fp12::{Fp12, GT_BYTES};
use hash::{H1_TAG, H2_TAG, hash_to_scalar};
use pairing::{pairing, pairing_product};
use tower::{Fp2, Fp4};

/// hid of signing keys.
pub const SM9_HID_SIGN: u8 = 0x01;
/// hid of key exchange keys.
pub const SM9_HID_EXCHANGE: u8 = 0x02;
/// hid of encryption (and key encapsulation) keys.
pub const SM9_HID_ENCRYPT: u8 = 0x03;

/// How `encrypt` turns the KDF output into C2. The ciphertext does not record it, so `decrypt`
/// must be given the same mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SM9EncryptMode {
    /// C2 = M xor K1 (the default).
    #[default]
    Stream,
    /// C2 = SM4-ECB(K1, PKCS#7(M)), the mode of the standard's example.
    Sm4,
}

const RNG_ERROR: &str = "System random number generator failed";
const INVALID_MASTER_PRIVATE: &str = "Invalid master private key";
const INVALID_MASTER_PUBLIC: &str = "Invalid master public key";
const INVALID_USER_PRIVATE: &str = "Invalid user private key";
const T1_ZERO_ERROR: &str = "t1 is zero for this identity; generate a new master key";
/// Rejected values are vanishingly rare with a working RNG, so running out of attempts means the
/// RNG is broken. (A one-byte message sees an all-zero K1 1 time in 256.)
const MAX_RANDOM_ATTEMPTS: u32 = 64;
/// The KDF counter is 32 bits and each value yields 32 bytes.
const MAX_KDF_BYTES: u64 = u32::MAX as u64 * 32;
/// Room in an SM3 input for what goes with a message (tag, GT element, counter).
const HASH_OVERHEAD: u64 = 1024;

/// Values whose copies are wiped on drop.
pub(crate) trait Blank: Copy {
    const BLANK: Self;
}

impl Blank for Scalar {
    const BLANK: Scalar = Scalar::ZERO;
}

impl Blank for Fp12 {
    const BLANK: Fp12 = Fp12::new(Fp4::ZERO, Fp4::ZERO, Fp4::ZERO);
}

impl<const L: usize> Blank for [u8; L] {
    const BLANK: [u8; L] = [0; L];
}

impl Blank for G1Affine {
    const BLANK: G1Affine = Affine {
        x: Fp::ZERO,
        y: Fp::ZERO,
    };
}

impl Blank for G2Affine {
    const BLANK: G2Affine = Affine {
        x: Fp2::new(Fp::ZERO, Fp::ZERO),
        y: Fp2::new(Fp::ZERO, Fp::ZERO),
    };
}

/// A secret value that is wiped however its scope ends (best effort).
pub(crate) struct Secret<T: Blank>(pub(crate) T);

impl<T: Blank> Drop for Secret<T> {
    fn drop(&mut self) {
        wipe(&mut self.0, T::BLANK);
    }
}

/// A secret buffer that is wiped however its scope ends (best effort).
pub(crate) struct SecretVec(pub(crate) Vec<u8>);

impl SecretVec {
    /// `len` zero bytes, or `None` when memory runs out.
    fn zeroed(len: usize) -> Option<SecretVec> {
        let mut buf = Vec::new();
        buf.try_reserve_exact(len).ok()?;
        buf.resize(len, 0);
        Some(SecretVec(buf))
    }
}

impl Drop for SecretVec {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

/// Exactly `2 L` hex digits; upper case only accepted when `any_case`.
fn decode_fixed<const L: usize>(text: &str, any_case: bool) -> Option<Secret<[u8; L]>> {
    let text = text.as_bytes();
    if text.len() != 2 * L || (!any_case && !hex::has_no_upper_case(text)) {
        return None;
    }
    let mut out = Secret([0u8; L]);
    hex::decode_into(text, &mut out.0).then_some(out)
}

/// A scalar in [1, N-1] from 64 hex digits of either case.
fn parse_scalar(text: &str) -> Option<Secret<Scalar>> {
    let bytes = decode_fixed::<32>(text, true)?;
    Scalar::from_be_bytes_nonzero(&bytes.0).map(Secret)
}

/// A valid G1 point from 130 hex digits.
fn parse_g1(text: &str, any_case: bool) -> Option<G1Affine> {
    g1_decode(&decode_fixed::<65>(text, any_case)?.0)
}

/// A valid G2 point (subgroup checked) from 258 hex digits of either case.
fn parse_g2(text: &str) -> Option<G2Affine> {
    g2_decode(&decode_fixed::<129>(text, true)?.0)
}

/// A uniform scalar in [1, N-1], by rejection sampling from the OS generator.
fn random_scalar() -> Result<Secret<Scalar>, &'static str> {
    for _ in 0..MAX_RANDOM_ATTEMPTS {
        let mut bytes = Secret([0u8; 32]);
        rng::fill(&mut bytes.0).map_err(|_| RNG_ERROR)?;
        if let Some(k) = Scalar::from_be_bytes_nonzero(&bytes.0) {
            return Ok(Secret(k));
        }
    }
    Err(RNG_ERROR)
}

/// The source of the random r: the OS generator, or a pinned value for known-answer tests.
type Nonces<'a> = &'a mut dyn FnMut() -> Result<Secret<Scalar>, &'static str>;

/// A pinned r from hex, for the `*_with_rand` test entry points.
fn pinned(r_hex: &str) -> impl FnMut() -> Result<Secret<Scalar>, &'static str> + '_ {
    move || parse_scalar(r_hex).ok_or("Invalid r")
}

/// H1(ID || hid)
fn h1(user_id: &[u8], hid: u8) -> Scalar {
    hash_to_scalar(H1_TAG, &[user_id, &[hid]])
}

/// [k]P1 for a secret k.
fn g1_mul_ct(k: &Scalar) -> Option<G1Affine> {
    P1.to_jacobian().mul_ct(&k.0).to_affine()
}

/// [k]P2 for a secret k.
fn g2_mul_ct(k: &Scalar) -> Option<G2Affine> {
    P2.to_jacobian().mul_ct(&k.0).to_affine()
}

/// ks * (H1(ID || hid) + ks)^-1 mod N, the scalar of a user key; `None` when t1 = 0.
fn user_key_scalar(master: &Scalar, user_id: &[u8], hid: u8) -> Option<Secret<Scalar>> {
    let t1 = Secret(h1(user_id, hid).add(master));
    if t1.0.is_zero() {
        return None;
    }
    let inv = Secret(t1.0.invert());
    Some(Secret(master.mul(&inv.0)))
}

fn gt_bytes(value: &Fp12) -> Secret<[u8; GT_BYTES]> {
    Secret(value.to_bytes())
}

/// SM9 algorithms. All functions are associated functions on this unit type, as for `SM2`.
pub struct SM9;

impl SM9 {
    /// 生成签名主密钥对: (master private key ks hex, master public key Ppub-s = [ks]P2 hex).
    ///
    /// # Panics
    ///
    /// If the operating system's random number generator fails; `try_gen_sign_master_key`
    /// returns an error instead.
    pub fn gen_sign_master_key() -> (String, String) {
        Self::try_gen_sign_master_key().expect(RNG_ERROR)
    }

    /// `gen_sign_master_key` that reports a failing random number generator.
    pub fn try_gen_sign_master_key() -> Result<(String, String), String> {
        let ks = random_scalar()?;
        let public = g2_mul_ct(&ks.0).ok_or(RNG_ERROR)?;
        Ok((
            hex::encode_lower(&ks.0.to_be_bytes()),
            hex::encode_lower(&g2_encode(&public)),
        ))
    }

    /// Ppub-s = [ks]P2 for a signing master private key (64 hex digits, in [1, N-1]).
    pub fn sign_master_public_key(master_private: &str) -> Result<String, String> {
        let ks = parse_scalar(master_private).ok_or(INVALID_MASTER_PRIVATE)?;
        let public = g2_mul_ct(&ks.0).ok_or(INVALID_MASTER_PRIVATE)?;
        Ok(hex::encode_lower(&g2_encode(&public)))
    }

    /// 生成用户签名私钥 ds = [ks / (H1(ID || 0x01) + ks)]P1, a G1 point in hex.
    pub fn gen_sign_user_key(
        master_private: &str,
        user_id: impl AsRef<[u8]>,
    ) -> Result<String, String> {
        Self::gen_sign_user_key_with_hid(master_private, user_id, SM9_HID_SIGN)
    }

    /// `gen_sign_user_key` with an explicit hid.
    pub fn gen_sign_user_key_with_hid(
        master_private: &str,
        user_id: impl AsRef<[u8]>,
        hid: u8,
    ) -> Result<String, String> {
        let ks = parse_scalar(master_private).ok_or(INVALID_MASTER_PRIVATE)?;
        let t2 = user_key_scalar(&ks.0, user_id.as_ref(), hid).ok_or(T1_ZERO_ERROR)?;
        let ds = Secret(g1_mul_ct(&t2.0).ok_or(T1_ZERO_ERROR)?);
        Ok(hex::encode_lower(&g1_encode(&ds.0)))
    }

    /// 生成加密主密钥对: (master private key ke hex, master public key Ppub-e = [ke]P1 hex).
    ///
    /// # Panics
    ///
    /// If the operating system's random number generator fails; `try_gen_enc_master_key`
    /// returns an error instead.
    pub fn gen_enc_master_key() -> (String, String) {
        Self::try_gen_enc_master_key().expect(RNG_ERROR)
    }

    /// `gen_enc_master_key` that reports a failing random number generator.
    pub fn try_gen_enc_master_key() -> Result<(String, String), String> {
        let ke = random_scalar()?;
        let public = g1_mul_ct(&ke.0).ok_or(RNG_ERROR)?;
        Ok((
            hex::encode_lower(&ke.0.to_be_bytes()),
            hex::encode_lower(&g1_encode(&public)),
        ))
    }

    /// Ppub-e = [ke]P1 for an encryption master private key.
    pub fn enc_master_public_key(master_private: &str) -> Result<String, String> {
        let ke = parse_scalar(master_private).ok_or(INVALID_MASTER_PRIVATE)?;
        let public = g1_mul_ct(&ke.0).ok_or(INVALID_MASTER_PRIVATE)?;
        Ok(hex::encode_lower(&g1_encode(&public)))
    }

    /// 生成用户加密私钥 de = [ke / (H1(ID || 0x03) + ke)]P2, a G2 point in hex. Key exchange
    /// keys are made the same way with `SM9_HID_EXCHANGE`.
    pub fn gen_enc_user_key(
        master_private: &str,
        user_id: impl AsRef<[u8]>,
    ) -> Result<String, String> {
        Self::gen_enc_user_key_with_hid(master_private, user_id, SM9_HID_ENCRYPT)
    }

    /// `gen_enc_user_key` with an explicit hid.
    pub fn gen_enc_user_key_with_hid(
        master_private: &str,
        user_id: impl AsRef<[u8]>,
        hid: u8,
    ) -> Result<String, String> {
        let ke = parse_scalar(master_private).ok_or(INVALID_MASTER_PRIVATE)?;
        let t2 = user_key_scalar(&ke.0, user_id.as_ref(), hid).ok_or(T1_ZERO_ERROR)?;
        let de = Secret(g2_mul_ct(&t2.0).ok_or(T1_ZERO_ERROR)?);
        Ok(hex::encode_lower(&g2_encode(&de.0)))
    }

    /// 签名: `h || S` (97 bytes) in lower-case hex.
    pub fn sign(
        message: impl AsRef<[u8]>,
        user_private: &str,
        master_public: &str,
    ) -> Result<String, String> {
        Self::sign_inner(message.as_ref(), user_private, master_public, &mut || {
            random_scalar()
        })
    }

    /// `sign` with a pinned r, for known-answer tests only. Never use a fixed r for real keys.
    #[doc(hidden)]
    pub fn sign_with_rand(
        message: impl AsRef<[u8]>,
        user_private: &str,
        master_public: &str,
        r_hex: &str,
    ) -> Result<String, String> {
        Self::sign_inner(
            message.as_ref(),
            user_private,
            master_public,
            &mut pinned(r_hex),
        )
    }

    fn sign_inner(
        message: &[u8],
        user_private: &str,
        master_public: &str,
        next_r: Nonces,
    ) -> Result<String, String> {
        if message.len() as u64 > MAX_MESSAGE_BYTES - HASH_OVERHEAD {
            return Err("Message too long".to_string());
        }
        let ds = Secret(parse_g1(user_private, true).ok_or(INVALID_USER_PRIVATE)?);
        let ppub = parse_g2(master_public).ok_or(INVALID_MASTER_PUBLIC)?;
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let r = next_r()?;
            // w = e(P1, Ppub-s)^r = e([r]P1, Ppub-s): a G1 multiplication is far cheaper than the
            // GT exponentiation, and bilinearity makes the value the same.
            let Some(rp) = g1_mul_ct(&r.0) else {
                continue;
            };
            let rp = Secret(rp);
            let w = Secret(pairing(&rp.0, &ppub));
            let h = hash_to_scalar(H2_TAG, &[message, &gt_bytes(&w.0).0]);
            let l = Secret(r.0.sub(&h));
            if l.0.is_zero() {
                continue;
            }
            let Some(s) = ds.0.to_jacobian().mul_ct(&l.0.0).to_affine() else {
                continue;
            };
            let mut out = String::with_capacity(194);
            hex::push_lower(&mut out, &h.to_be_bytes());
            hex::push_lower(&mut out, &g1_encode(&s));
            return Ok(out);
        }
        Err(RNG_ERROR.to_string())
    }

    /// 验签 with the signing hid 0x01. The signature must be the lower-case hex `sign` writes.
    /// Any malformed input gives false.
    pub fn verify(
        message: impl AsRef<[u8]>,
        signature: &str,
        user_id: impl AsRef<[u8]>,
        master_public: &str,
    ) -> bool {
        Self::verify_with_hid(message, signature, user_id, master_public, SM9_HID_SIGN)
    }

    /// `verify` with an explicit hid.
    pub fn verify_with_hid(
        message: impl AsRef<[u8]>,
        signature: &str,
        user_id: impl AsRef<[u8]>,
        master_public: &str,
        hid: u8,
    ) -> bool {
        let message = message.as_ref();
        if message.len() as u64 > MAX_MESSAGE_BYTES - HASH_OVERHEAD {
            return false;
        }
        let Some(sig) = decode_fixed::<97>(signature, false) else {
            return false;
        };
        let mut h_bytes = [0u8; 32];
        h_bytes.copy_from_slice(&sig.0[..32]);
        let Some(h) = Scalar::from_be_bytes_nonzero(&h_bytes) else {
            return false;
        };
        let Some(s) = g1_decode(&sig.0[32..]) else {
            return false;
        };
        let Some(ppub) = parse_g2(master_public) else {
            return false;
        };
        // w = e(S, P) * e(P1, Ppub-s)^h = e(S, P) * e([h]P1, Ppub-s), one final exponentiation.
        let Some(hp) = P1.to_jacobian().mul_vartime(&h.0).to_affine() else {
            return false;
        };
        let h1 = h1(user_id.as_ref(), hid);
        let p = P2.to_jacobian().mul_vartime(&h1.0);
        let w = match p.add_vartime(&ppub.to_jacobian()).to_affine() {
            Some(p) => pairing_product((&s, &p), (&hp, &ppub)),
            None => pairing(&hp, &ppub),
        };
        let h2 = hash_to_scalar(H2_TAG, &[message, &w.to_bytes()]);
        h2.0 == h.0
    }

    /// e(P, Q) as 384 bytes of hex, for tests of the pairing itself.
    #[doc(hidden)]
    pub fn pairing_hex(g1_point: &str, g2_point: &str) -> Option<String> {
        let p = parse_g1(g1_point, true)?;
        let q = parse_g2(g2_point)?;
        Some(hex::encode_lower(&pairing(&p, &q).to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_key_round_trips() {
        let (ks, ppub) = SM9::gen_sign_master_key();
        assert_eq!(SM9::sign_master_public_key(&ks).unwrap(), ppub);
        let ds = SM9::gen_sign_user_key(&ks, "Alice").unwrap();
        let sig = SM9::sign(b"msg", &ds, &ppub).unwrap();
        assert!(SM9::verify("msg", &sig, "Alice", &ppub));
        assert!(!SM9::verify("msh", &sig, "Alice", &ppub));
        assert!(!SM9::verify("msg", &sig, "Alicf", &ppub));
    }

    #[test]
    fn pinned_r_source_failure_ends_cleanly() {
        let (ks, ppub) = SM9::gen_sign_master_key();
        let ds = SM9::gen_sign_user_key(&ks, "Alice").unwrap();
        assert!(SM9::sign_with_rand("m", &ds, &ppub, "00").is_err());
        let mut fail = || Err(RNG_ERROR);
        assert_eq!(
            SM9::sign_inner(b"m", &ds, &ppub, &mut fail).unwrap_err(),
            RNG_ERROR
        );
    }
}
