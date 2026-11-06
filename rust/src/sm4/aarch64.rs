//! SM4 CBC decryption on AArch64, 32 blocks at a time: the S-box through the AES instructions,
//! words in NEON lanes. Narrower batches measured slower than the lookup tables of the parent
//! module, which handle everything else.
//!
//! `AESE` with a zero key is SubBytes and ShiftRows, the same as x86's `aesenclast`, so the
//! nibble tables of the affine maps in the parent module apply unchanged. No memory access
//! depends on data. Only runs after run-time detection of the `aes` feature. The dedicated SM4
//! instructions are left out: their intrinsics are not stable and the development hardware
//! (Apple M2) does not have them.
// Intrinsics became safe inside matching `target_feature` functions only in newer compilers;
// this keeps a single spelling that compiles on all of them.
#![allow(unsafe_op_in_unsafe_fn)]

use super::{BLOCK_LEN, INV_SHIFT_ROWS, POST_HI, POST_LO, PRE_HI, PRE_LO};
use core::arch::aarch64::*;

/// Sets of four blocks in the bulk primitive.
const WIDE_SETS: usize = 8;
pub(super) const WIDE_BYTES: usize = WIDE_SETS * 64;
/// What one call of `crypt_wide` costs, in tenths of one block through the tables (measured on
/// an Apple M2), to decide whether a short tail takes the tables or a padded batch.
pub(super) const COST_WIDE: usize = 45;

// In-lane byte shuffles for 32-bit rotations.
const ROL8: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];
const ROL24: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];

#[inline(always)]
unsafe fn table(bytes: &[u8; 16]) -> uint8x16_t {
    vld1q_u8(bytes.as_ptr())
}

/// `tables[x]` per byte, for tables given by their low and high nibble parts.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn affine(x: uint8x16_t, lo: &[u8; 16], hi: &[u8; 16]) -> uint8x16_t {
    let low = vandq_u8(x, vdupq_n_u8(0x0f));
    let high = vshrq_n_u8::<4>(x);
    veorq_u8(vqtbl1q_u8(table(lo), low), vqtbl1q_u8(table(hi), high))
}

/// S-box on 16 bytes.
#[inline]
#[target_feature(enable = "neon,aes")]
unsafe fn sbox(x: uint8x16_t) -> uint8x16_t {
    let y = affine(x, &PRE_LO, &PRE_HI);
    let y = vqtbl1q_u8(y, table(&INV_SHIFT_ROWS));
    let y = vaeseq_u8(y, vdupq_n_u8(0));
    affine(y, &POST_LO, &POST_HI)
}

/// S-box then SM4's linear layer: `s ^ s<<<24 ^ (s ^ s<<<8 ^ s<<<16)<<<2`.
#[inline]
#[target_feature(enable = "neon,aes")]
unsafe fn t(x: uint32x4_t) -> uint32x4_t {
    let s = sbox(vreinterpretq_u8_u32(x));
    let rol8 = vqtbl1q_u8(s, table(&ROL8));
    let rol16 = vreinterpretq_u8_u16(vrev32q_u16(vreinterpretq_u16_u8(s)));
    let rol24 = vqtbl1q_u8(s, table(&ROL24));
    let a = vreinterpretq_u32_u8(veorq_u8(veorq_u8(s, rol8), rol16));
    let rotated = vsliq_n_u32::<2>(vshrq_n_u32::<30>(a), a);
    veorq_u32(vreinterpretq_u32_u8(veorq_u8(s, rol24)), rotated)
}

/// Words of four blocks to lanes, and back.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn transpose(a: uint32x4_t, b: uint32x4_t, c: uint32x4_t, d: uint32x4_t) -> [uint32x4_t; 4] {
    let ab_lo = vreinterpretq_u64_u32(vzip1q_u32(a, b));
    let ab_hi = vreinterpretq_u64_u32(vzip2q_u32(a, b));
    let cd_lo = vreinterpretq_u64_u32(vzip1q_u32(c, d));
    let cd_hi = vreinterpretq_u64_u32(vzip2q_u32(c, d));
    [
        vreinterpretq_u32_u64(vzip1q_u64(ab_lo, cd_lo)),
        vreinterpretq_u32_u64(vzip2q_u64(ab_lo, cd_lo)),
        vreinterpretq_u32_u64(vzip1q_u64(ab_hi, cd_hi)),
        vreinterpretq_u32_u64(vzip2q_u64(ab_hi, cd_hi)),
    ]
}

/// Big-endian block `index` as native words in one register.
#[inline]
#[target_feature(enable = "neon")]
unsafe fn load(ptr: *const u8, index: usize) -> uint32x4_t {
    let bytes = vld1q_u8(ptr.add(index * BLOCK_LEN));
    vreinterpretq_u32_u8(vrev32q_u8(bytes))
}

#[inline]
#[target_feature(enable = "neon")]
unsafe fn store(ptr: *mut u8, index: usize, value: uint32x4_t) {
    let bytes = vrev32q_u8(vreinterpretq_u8_u32(value));
    vst1q_u8(ptr.add(index * BLOCK_LEN), bytes);
}

/// Transforms `4 * SETS` independent blocks in place. Running several sets side by side uses the
/// execution units that one set's dependency chain leaves idle.
#[inline]
#[target_feature(enable = "neon,aes")]
unsafe fn crypt<const SETS: usize>(rk: &[u32; 32], blocks: *mut u8) {
    let mut state = [[vdupq_n_u32(0); 4]; SETS];
    for (set, words) in state.iter_mut().enumerate() {
        let base = 4 * set;
        *words = transpose(
            load(blocks, base),
            load(blocks, base + 1),
            load(blocks, base + 2),
            load(blocks, base + 3),
        );
    }
    for (round, &key) in rk.iter().enumerate() {
        let key = vdupq_n_u32(key);
        let (i0, i1, i2, i3) = (round % 4, (round + 1) % 4, (round + 2) % 4, (round + 3) % 4);
        for words in state.iter_mut() {
            let input = veorq_u32(veorq_u32(words[i1], words[i2]), words[i3]);
            words[i0] = veorq_u32(words[i0], t(veorq_u32(input, key)));
        }
    }
    for (set, words) in state.iter().enumerate() {
        let base = 4 * set;
        let [r0, r1, r2, r3] = transpose(words[3], words[2], words[1], words[0]);
        store(blocks, base, r0);
        store(blocks, base + 1, r1);
        store(blocks, base + 2, r2);
        store(blocks, base + 3, r3);
    }
}

#[target_feature(enable = "neon,aes")]
pub(super) unsafe fn crypt_wide(rk: &[u32; 32], blocks: &mut [u8; WIDE_BYTES]) {
    crypt::<WIDE_SETS>(rk, blocks.as_mut_ptr());
}

#[cfg(test)]
mod tests {
    use super::super::tables::SBOX;
    use super::*;

    #[target_feature(enable = "neon,aes")]
    unsafe fn sbox_bytes(input: [u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), sbox(vld1q_u8(input.as_ptr())));
        out
    }

    #[test]
    fn sbox_is_exact_on_all_inputs() {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            return;
        }
        for start in (0..256usize).step_by(16) {
            let mut input = [0u8; 16];
            for (i, b) in input.iter_mut().enumerate() {
                *b = (start + i) as u8;
            }
            // SAFETY: the feature was just detected.
            let output = unsafe { sbox_bytes(input) };
            for (x, y) in input.iter().zip(output) {
                assert_eq!(SBOX[*x as usize], y, "input {x:#x}");
            }
        }
    }
}
