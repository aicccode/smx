//! SM9 key exchange (GB/T 38635.3): initiator A, responder B, keys of the encryption kind made
//! with hid 0x02 under the encryption master public key Ppub-e.

use super::curve::{G1Affine, g1_encode};
use super::encrypt::{MAX_SHARED_KEY_BYTES, master_gt_pow, peer_point};
use super::fp::Scalar;
use super::fp12::Fp12;
use super::hash::kdf_into;
use super::{
    INVALID_MASTER_PUBLIC, MAX_RANDOM_ATTEMPTS, Nonces, RNG_ERROR, SM9, SM9_HID_EXCHANGE, Secret,
    SecretVec, decode_fixed, gt_bytes, pairing, parse_g1, parse_g2, parse_scalar, pinned,
    random_scalar,
};
use crate::ct::eq_bytes;
use crate::hex;
use crate::sm3::digest_parts;
use core::fmt;

const IDENTITY_ERROR: &str = "No user key can exist for this identity and master public key";

/// The outcome of `exchange_respond` (`shared_key`, `s_b`, `s_2`) or `exchange_confirm`
/// (`shared_key`, `s_a`). On failure `success` is false, `message` says why and nothing else is
/// set. `shared_key` is secret: `Debug` leaves it out.
#[derive(Clone)]
pub struct SM9KeyExchangeResult {
    pub success: bool,
    pub message: Option<String>,
    pub shared_key: Option<String>,
    /// B's confirmation value, sent to A.
    pub s_b: Option<String>,
    /// The value B expects back from A as `s_a`; kept by B for `exchange_check`.
    pub s_2: Option<String>,
    /// A's confirmation value, sent to B.
    pub s_a: Option<String>,
}

impl fmt::Debug for SM9KeyExchangeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SM9KeyExchangeResult")
            .field("success", &self.success)
            .field("message", &self.message)
            .field("shared_key", &self.shared_key.as_ref().map(|_| ".."))
            .field("s_b", &self.s_b)
            .field("s_2", &self.s_2)
            .field("s_a", &self.s_a)
            .finish()
    }
}

impl SM9KeyExchangeResult {
    fn failed(message: &str) -> Self {
        SM9KeyExchangeResult {
            success: false,
            message: Some(message.to_string()),
            shared_key: None,
            s_b: None,
            s_2: None,
            s_a: None,
        }
    }
}

/// Everything both sides hash, from validated inputs.
struct Transcript<'a> {
    key_len: usize,
    id_a: &'a [u8],
    id_b: &'a [u8],
    r_a: [u8; 64],
    r_b: [u8; 64],
}

/// The parsed inputs of one side: own key, own r and R, the peer's R.
struct Side {
    de: Secret<super::curve::G2Affine>,
    r: Secret<Scalar>,
    own: G1Affine,
    peer: G1Affine,
    ppub: G1Affine,
}

fn xy(point: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&g1_encode(point)[1..]);
    out
}

/// Validates the inputs; the error is the reason for rejecting them.
fn parse_side(
    key_len: usize,
    master_public: &str,
    user_private: &str,
    r: &str,
    own_point: &str,
    peer_point: &str,
) -> Result<Side, &'static str> {
    if key_len == 0 || key_len > MAX_SHARED_KEY_BYTES {
        return Err("Invalid key length");
    }
    let ppub = parse_g1(master_public, true).ok_or(INVALID_MASTER_PUBLIC)?;
    let de = Secret(parse_g2(user_private).ok_or("Invalid user private key")?);
    let r = parse_scalar(r).ok_or("Invalid r")?;
    let own = parse_g1(own_point, true).ok_or("Invalid own R point")?;
    let peer = parse_g1(peer_point, true).ok_or("Invalid peer R point")?;
    Ok(Side {
        de,
        r,
        own,
        peer,
        ppub,
    })
}

impl Transcript<'_> {
    /// (SK, inner hash) for g1 || g2 || g3 as named in the standard.
    fn derive(&self, g: [&Fp12; 3]) -> Option<(SecretVec, [u8; 32], Secret<[u8; 384]>)> {
        let g1 = gt_bytes(g[0]);
        let g2 = gt_bytes(g[1]);
        let g3 = gt_bytes(g[2]);
        let tail: [&[u8]; 4] = [self.id_a, self.id_b, &self.r_a, &self.r_b];
        let mut key = SecretVec::zeroed(self.key_len)?;
        kdf_into(
            &[tail[0], tail[1], tail[2], tail[3], &g1.0, &g2.0, &g3.0],
            &mut key.0,
        );
        let inner = digest_parts(&[&g2.0, &g3.0, tail[0], tail[1], tail[2], tail[3]]);
        Some((key, inner, g1))
    }
}

/// SM3(tag || g1 || inner)
fn confirmation(tag: u8, g1: &[u8; 384], inner: &[u8; 32]) -> [u8; 32] {
    digest_parts(&[&[tag], g1, inner])
}

impl SM9 {
    /// 密钥交换第一步 (either side): a random r and R = [r]Q_peer with
    /// Q_peer = [H1(peer_id || 0x02)]P1 + Ppub-e. Returns (r hex, R hex); r is secret and must be
    /// kept for `exchange_respond` / `exchange_confirm`, R goes to the peer.
    pub fn exchange_init(
        peer_id: impl AsRef<[u8]>,
        master_public: &str,
    ) -> Result<(String, String), String> {
        Self::exchange_init_with_hid(peer_id, master_public, SM9_HID_EXCHANGE)
    }

    /// `exchange_init` with an explicit hid.
    pub fn exchange_init_with_hid(
        peer_id: impl AsRef<[u8]>,
        master_public: &str,
        hid: u8,
    ) -> Result<(String, String), String> {
        let id = peer_id.as_ref();
        Self::exchange_init_inner(id, master_public, hid, &mut || random_scalar())
    }

    /// `exchange_init_with_hid` with a pinned r, for known-answer tests only.
    #[doc(hidden)]
    pub fn exchange_init_with_rand(
        peer_id: impl AsRef<[u8]>,
        master_public: &str,
        hid: u8,
        r_hex: &str,
    ) -> Result<(String, String), String> {
        let id = peer_id.as_ref();
        Self::exchange_init_inner(id, master_public, hid, &mut pinned(r_hex))
    }

    fn exchange_init_inner(
        peer_id: &[u8],
        master_public: &str,
        hid: u8,
        next_r: Nonces,
    ) -> Result<(String, String), String> {
        let ppub = parse_g1(master_public, true).ok_or(INVALID_MASTER_PUBLIC)?;
        let q = peer_point(peer_id, hid, &ppub).ok_or(IDENTITY_ERROR)?;
        for _ in 0..MAX_RANDOM_ATTEMPTS {
            let r = next_r()?;
            let Some(point) = q.mul_ct(&r.0.0).to_affine() else {
                continue;
            };
            return Ok((
                hex::encode_lower(&r.0.to_be_bytes()),
                hex::encode_lower(&g1_encode(&point)),
            ));
        }
        Err(RNG_ERROR.to_string())
    }

    /// 响应方 B: from A's R_a, computes SK_B, S_B (to send to A) and S_2 (to keep for
    /// `exchange_check`). `key_len` is in bytes, 1 to 1 MiB. All points and keys are validated;
    /// on failure `success` is false and `message` says why.
    #[allow(clippy::too_many_arguments)] // the protocol has this many inputs
    pub fn exchange_respond(
        key_len: usize,
        id_a: impl AsRef<[u8]>,
        id_b: impl AsRef<[u8]>,
        master_public: &str,
        user_private_b: &str,
        r_b: &str,
        r_b_point: &str,
        r_a_point: &str,
    ) -> SM9KeyExchangeResult {
        let side = match parse_side(
            key_len,
            master_public,
            user_private_b,
            r_b,
            r_b_point,
            r_a_point,
        ) {
            Ok(side) => side,
            Err(reason) => return SM9KeyExchangeResult::failed(reason),
        };
        let transcript = Transcript {
            key_len,
            id_a: id_a.as_ref(),
            id_b: id_b.as_ref(),
            r_a: xy(&side.peer),
            r_b: xy(&side.own),
        };
        let g1 = Secret(pairing(&side.peer, &side.de.0));
        let Some(g2) = master_gt_pow(&side.ppub, &side.r.0) else {
            return SM9KeyExchangeResult::failed("Invalid r");
        };
        let g2 = Secret(g2);
        let g3 = Secret(g1.0.pow_ct(&side.r.0.0));
        let Some((key, inner, g1_bytes)) = transcript.derive([&g1.0, &g2.0, &g3.0]) else {
            return SM9KeyExchangeResult::failed("Out of memory");
        };
        let Some(shared_key) = hex::try_encode_lower(&key.0) else {
            return SM9KeyExchangeResult::failed("Out of memory");
        };
        SM9KeyExchangeResult {
            success: true,
            message: None,
            shared_key: Some(shared_key),
            s_b: Some(hex::encode_lower(&confirmation(0x82, &g1_bytes.0, &inner))),
            s_2: Some(hex::encode_lower(&confirmation(0x83, &g1_bytes.0, &inner))),
            s_a: None,
        }
    }

    /// 发起方 A: from B's R_b and S_B, checks S_B in constant time and only then gives SK_A and
    /// S_A (to send to B). `s_b` must be the 64 lower-case hex digits B produced.
    #[allow(clippy::too_many_arguments)] // the protocol has this many inputs
    pub fn exchange_confirm(
        key_len: usize,
        id_a: impl AsRef<[u8]>,
        id_b: impl AsRef<[u8]>,
        master_public: &str,
        user_private_a: &str,
        r_a: &str,
        r_a_point: &str,
        r_b_point: &str,
        s_b: &str,
    ) -> SM9KeyExchangeResult {
        let side = match parse_side(
            key_len,
            master_public,
            user_private_a,
            r_a,
            r_a_point,
            r_b_point,
        ) {
            Ok(side) => side,
            Err(reason) => return SM9KeyExchangeResult::failed(reason),
        };
        let Some(s_b) = decode_fixed::<32>(s_b, false) else {
            return SM9KeyExchangeResult::failed("Invalid S_B");
        };
        let transcript = Transcript {
            key_len,
            id_a: id_a.as_ref(),
            id_b: id_b.as_ref(),
            r_a: xy(&side.own),
            r_b: xy(&side.peer),
        };
        let Some(g1) = master_gt_pow(&side.ppub, &side.r.0) else {
            return SM9KeyExchangeResult::failed("Invalid r");
        };
        let g1 = Secret(g1);
        let g2 = Secret(pairing(&side.peer, &side.de.0));
        let g3 = Secret(g2.0.pow_ct(&side.r.0.0));
        let Some((key, inner, g1_bytes)) = transcript.derive([&g1.0, &g2.0, &g3.0]) else {
            return SM9KeyExchangeResult::failed("Out of memory");
        };
        if !eq_bytes(&confirmation(0x82, &g1_bytes.0, &inner), &s_b.0) {
            return SM9KeyExchangeResult::failed("S_B does not match: key exchange failed");
        }
        let Some(shared_key) = hex::try_encode_lower(&key.0) else {
            return SM9KeyExchangeResult::failed("Out of memory");
        };
        SM9KeyExchangeResult {
            success: true,
            message: None,
            shared_key: Some(shared_key),
            s_b: None,
            s_2: None,
            s_a: Some(hex::encode_lower(&confirmation(0x83, &g1_bytes.0, &inner))),
        }
    }

    /// B's last step: true iff A's S_A equals the S_2 B kept, compared in constant time. Both are
    /// 64 lower-case hex digits; anything else is false.
    pub fn exchange_check(s_2: &str, s_a: &str) -> bool {
        match (
            decode_fixed::<32>(s_2, false),
            decode_fixed::<32>(s_a, false),
        ) {
            (Some(expected), Some(got)) => eq_bytes(&expected.0, &got.0),
            _ => false,
        }
    }
}
