//! SM4 CBC decryption on x86-64, many blocks at once: the S-box through GFNI or AES-NI, words in
//! AVX2 lanes. Only used where it beats the lookup tables of the parent module; AES-NI with
//! 128-bit vectors alone measured slower than them, so it has no path here.
//!
//! SM4's S-box is affine-equivalent to inversion in GF(2^8), so with field isomorphism T it can
//! be written S(x) = B(inv(A(x))) over the AES polynomial. GFNI computes both steps directly.
//! AES-NI's last round provides the inversion, followed by the AES affine map that the post
//! transform below already compensates for. Neither path accesses memory based on data.
//! Exhaustive tests of all 256 inputs are at the bottom of this file.
//!
//! GFNI goes through `asm!`, because its intrinsics and target feature need a compiler newer
//! than this crate's edition 2024 minimum (1.85). The instructions only run after run-time
//! detection of the `gfni` and `avx2` features. The VAES and AVX-512 forms are left out: they
//! have the same minimum-version problem and could not be tested on the development machine.
// Intrinsics became safe inside matching `target_feature` functions only in newer compilers;
// this keeps a single spelling that compiles on all of them.
#![allow(unsafe_op_in_unsafe_fn)]

use super::{INV_SHIFT_ROWS, POST_HI, POST_LO, PRE_HI, PRE_LO};
use core::arch::asm;
use core::arch::x86_64::*;

// GF2P8AFFINEQB matrices and constants of the same maps, for the GFNI path.
const GFNI_PRE: i64 = 0x4c28_7db9_1a22_505d;
const GFNI_POST: i64 = 0xf3ab_34a9_74a6_b589_u64 as i64;

/// What one call of `crypt8` costs, in tenths of one block through the tables (measured on an
/// Intel i5-13500H), to decide whether a short tail takes the tables or a padded batch.
pub(super) const COST_GFNI8: usize = 18;
pub(super) const COST_AESNI8: usize = 32;

/// Sets of eight blocks in the widest bulk primitive.
pub(super) const WIDE_SETS: usize = 4;
pub(super) const WIDE_BYTES: usize = WIDE_SETS * 128;

// In-lane byte shuffles for 32-bit rotations and for big-endian words.
const ROL8: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];
const ROL16: [u8; 16] = [2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13];
const ROL24: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];
const BSWAP32: [u8; 16] = [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12];

#[inline(always)]
unsafe fn table128(table: &[u8; 16]) -> __m128i {
    _mm_loadu_si128(table.as_ptr().cast())
}

#[inline(always)]
unsafe fn table256(table: &[u8; 16]) -> __m256i {
    _mm256_broadcastsi128_si256(table128(table))
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn affine256(x: __m256i, lo: &[u8; 16], hi: &[u8; 16]) -> __m256i {
    let mask = _mm256_set1_epi8(0x0f);
    let low = _mm256_and_si256(x, mask);
    let high = _mm256_and_si256(_mm256_srli_epi32::<4>(x), mask);
    _mm256_xor_si256(
        _mm256_shuffle_epi8(table256(lo), low),
        _mm256_shuffle_epi8(table256(hi), high),
    )
}

/// S-box on 32 bytes via AES-NI, one 128-bit lane at a time.
#[inline]
#[target_feature(enable = "aes,avx2")]
unsafe fn sbox256_aesni(x: __m256i) -> __m256i {
    let y = affine256(x, &PRE_LO, &PRE_HI);
    let y = _mm256_shuffle_epi8(y, table256(&INV_SHIFT_ROWS));
    let zero = _mm_setzero_si128();
    let low = _mm_aesenclast_si128(_mm256_castsi256_si128(y), zero);
    let high = _mm_aesenclast_si128(_mm256_extracti128_si256::<1>(y), zero);
    let y = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(low), high);
    affine256(y, &POST_LO, &POST_HI)
}

/// S-box on 32 bytes via GFNI.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn sbox256_gfni(x: __m256i) -> __m256i {
    let pre = _mm256_set1_epi64x(GFNI_PRE);
    let post = _mm256_set1_epi64x(GFNI_POST);
    let mut y = x;
    // SAFETY: the callers' backend selection detected GFNI and AVX2.
    asm!(
        "vgf2p8affineqb {y}, {y}, {pre}, 0x3e",
        "vgf2p8affineinvqb {y}, {y}, {post}, 0xd3",
        y = inout(ymm_reg) y,
        pre = in(ymm_reg) pre,
        post = in(ymm_reg) post,
        options(pure, nomem, nostack, preserves_flags),
    );
    y
}

/// SM4's linear layer L over 32-bit lanes: `x ^ x<<<24 ^ (x ^ x<<<8 ^ x<<<16)<<<2`.
macro_rules! linear_layer {
    ($x:expr, $xor:ident, $or:ident, $shl:ident, $shr:ident, $shuffle:ident, $table:ident) => {{
        let x = $x;
        let a = $xor(
            $xor(x, $shuffle(x, $table(&ROL8))),
            $shuffle(x, $table(&ROL16)),
        );
        let rotated = $or($shl::<2>(a), $shr::<30>(a));
        $xor($xor(x, $shuffle(x, $table(&ROL24))), rotated)
    }};
}

#[inline]
#[target_feature(enable = "avx2")]
unsafe fn transpose256(a: __m256i, b: __m256i, c: __m256i, d: __m256i) -> [__m256i; 4] {
    let ab_lo = _mm256_unpacklo_epi32(a, b);
    let ab_hi = _mm256_unpackhi_epi32(a, b);
    let cd_lo = _mm256_unpacklo_epi32(c, d);
    let cd_hi = _mm256_unpackhi_epi32(c, d);
    [
        _mm256_unpacklo_epi64(ab_lo, cd_lo),
        _mm256_unpackhi_epi64(ab_lo, cd_lo),
        _mm256_unpacklo_epi64(ab_hi, cd_hi),
        _mm256_unpackhi_epi64(ab_hi, cd_hi),
    ]
}

/// Eight-way code in YMM registers for one way of computing the S-box.
macro_rules! ymm_backend {
    ($name:ident, $features:literal, $sbox:ident) => {
        pub(super) mod $name {
            use super::*;

            #[inline]
            #[target_feature(enable = $features)]
            unsafe fn t(x: __m256i) -> __m256i {
                linear_layer!(
                    $sbox(x),
                    _mm256_xor_si256,
                    _mm256_or_si256,
                    _mm256_slli_epi32,
                    _mm256_srli_epi32,
                    _mm256_shuffle_epi8,
                    table256
                )
            }

            #[inline]
            #[target_feature(enable = $features)]
            unsafe fn load(ptr: *const __m128i, index: usize, swap: __m256i) -> __m256i {
                // Block `index` in the low lane and block `index + 4` in the high lane.
                let low = _mm256_castsi128_si256(_mm_loadu_si128(ptr.add(index)));
                let both = _mm256_inserti128_si256::<1>(low, _mm_loadu_si128(ptr.add(index + 4)));
                _mm256_shuffle_epi8(both, swap)
            }

            #[inline]
            #[target_feature(enable = $features)]
            unsafe fn store(ptr: *mut __m128i, index: usize, value: __m256i, swap: __m256i) {
                let value = _mm256_shuffle_epi8(value, swap);
                _mm_storeu_si128(ptr.add(index), _mm256_castsi256_si128(value));
                _mm_storeu_si128(ptr.add(index + 4), _mm256_extracti128_si256::<1>(value));
            }

            /// Transforms `8 * SETS` independent blocks in place. Running several sets of eight
            /// side by side uses the execution ports that one set's dependency chain leaves idle.
            #[inline]
            #[target_feature(enable = $features)]
            unsafe fn crypt<const SETS: usize>(rk: &[u32; 32], blocks: *mut u8) {
                let swap = table256(&BSWAP32);
                let ptr: *mut __m128i = blocks.cast();
                let mut state = [[_mm256_setzero_si256(); 4]; SETS];
                for (set, words) in state.iter_mut().enumerate() {
                    let base = ptr.add(8 * set);
                    *words = transpose256(
                        load(base, 0, swap),
                        load(base, 1, swap),
                        load(base, 2, swap),
                        load(base, 3, swap),
                    );
                }
                for (round, &key) in rk.iter().enumerate() {
                    let key = _mm256_set1_epi32(key as i32);
                    let (i0, i1, i2, i3) =
                        (round % 4, (round + 1) % 4, (round + 2) % 4, (round + 3) % 4);
                    for words in state.iter_mut() {
                        let input =
                            _mm256_xor_si256(_mm256_xor_si256(words[i1], words[i2]), words[i3]);
                        words[i0] = _mm256_xor_si256(words[i0], t(_mm256_xor_si256(input, key)));
                    }
                }
                for (set, words) in state.iter().enumerate() {
                    let base = ptr.add(8 * set);
                    let [r0, r1, r2, r3] = transpose256(words[3], words[2], words[1], words[0]);
                    store(base, 0, r0, swap);
                    store(base, 1, r1, swap);
                    store(base, 2, r2, swap);
                    store(base, 3, r3, swap);
                }
            }

            /// Eight blocks: batches too short for the wider version.
            #[target_feature(enable = $features)]
            pub(in super::super) unsafe fn crypt8(rk: &[u32; 32], blocks: &mut [u8; 128]) {
                crypt::<1>(rk, blocks.as_mut_ptr());
            }

            #[target_feature(enable = $features)]
            pub(in super::super) unsafe fn crypt_wide(
                rk: &[u32; 32],
                blocks: &mut [u8; WIDE_BYTES],
            ) {
                crypt::<WIDE_SETS>(rk, blocks.as_mut_ptr());
            }

            #[cfg(test)]
            pub(in super::super) fn sbox_for_test(input: [u8; 32]) -> [u8; 32] {
                // SAFETY: only called by tests after feature detection.
                unsafe {
                    #[target_feature(enable = $features)]
                    unsafe fn inner(input: [u8; 32]) -> [u8; 32] {
                        let x = _mm256_loadu_si256(input.as_ptr().cast());
                        let mut out = [0u8; 32];
                        _mm256_storeu_si256(out.as_mut_ptr().cast(), $sbox(x));
                        out
                    }
                    inner(input)
                }
            }
        }
    };
}

ymm_backend!(aesni_avx2, "aes,avx2", sbox256_aesni);
ymm_backend!(gfni_avx2, "avx2", sbox256_gfni);

#[cfg(test)]
mod tests {
    use super::super::tables::SBOX;
    use super::*;

    fn cases<const N: usize>() -> impl Iterator<Item = [u8; N]> {
        (0..256usize).step_by(N).map(|start| {
            let mut input = [0u8; N];
            for (i, b) in input.iter_mut().enumerate() {
                *b = (start + i) as u8;
            }
            input
        })
    }

    fn check<const N: usize>(sbox: impl Fn([u8; N]) -> [u8; N]) {
        for input in cases::<N>() {
            let output = sbox(input);
            for (x, y) in input.iter().zip(output) {
                assert_eq!(SBOX[*x as usize], y, "input {x:#x}");
            }
        }
    }

    #[test]
    fn sbox_is_exact_on_all_inputs() {
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("avx2") {
            check(aesni_avx2::sbox_for_test);
        }
        if is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2") {
            check(gfni_avx2::sbox_for_test);
        }
    }
}
