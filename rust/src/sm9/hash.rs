//! H1, H2 and the KDF of GB/T 38635.2, on the crate's SM3.

use super::fp::{Scalar, hash_to_range};
use crate::ct::{ct_barrier, wipe};
use crate::sm3::Sm3;

pub(crate) const H1_TAG: u8 = 0x01;
pub(crate) const H2_TAG: u8 = 0x02;

/// H(tag, Z) = (SM3(tag || Z || 1) || SM3(tag || Z || 2)[..8]) mod (N - 1) + 1, with Z the
/// concatenation of `parts`.
pub(crate) fn hash_to_scalar(tag: u8, parts: &[&[u8]]) -> Scalar {
    let mut prefix = Sm3::new();
    prefix.update(&[tag]);
    for part in parts {
        prefix.update(part);
    }
    let mut first = prefix.clone();
    first.update(&1u32.to_be_bytes());
    prefix.update(&2u32.to_be_bytes());
    let mut ha = [0u8; 40];
    ha[..32].copy_from_slice(&first.finalize_digest());
    ha[32..].copy_from_slice(&prefix.finalize_digest()[..8]);
    let h = hash_to_range(&ha);
    wipe(&mut ha, [0; 40]);
    h
}

/// KDF(Z, out.len()) into `out`, with Z the concatenation of `parts`. Returns true when the
/// output is all zero (decided without branching on the bytes).
pub(crate) fn kdf_into(parts: &[&[u8]], out: &mut [u8]) -> bool {
    let mut prefix = Sm3::new();
    for part in parts {
        prefix.update(part);
    }
    let mut seen = 0u8;
    for (index, chunk) in out.chunks_mut(32).enumerate() {
        let mut h = prefix.clone();
        h.update(&(index as u32 + 1).to_be_bytes());
        let mut block = h.finalize_digest();
        chunk.copy_from_slice(&block[..chunk.len()]);
        seen |= chunk.iter().fold(0, |acc, &b| acc | b);
        wipe(&mut block, [0; 32]);
    }
    ct_barrier(u64::from(seen)) == 0
}

/// True when every byte is zero, without an early exit.
pub(crate) fn all_zero(bytes: &[u8]) -> bool {
    let seen = bytes.iter().fold(0u8, |acc, &b| acc | b);
    ct_barrier(u64::from(seen)) == 0
}
