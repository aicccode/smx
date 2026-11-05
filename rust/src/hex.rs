//! Crate-internal hex conversion.
//!
//! Private keys pass through these helpers, so encoding and decoding are arithmetic only: no
//! lookup table indexed by the data and no branch on the value of a valid digit. Only whether the
//! text is valid hex is branched on, possibly at the first invalid digit, which reveals no key.

/// ASCII digit for a nibble; `letter_offset` is 7 for upper case and 39 for lower case.
#[inline(always)]
const fn nibble_to_ascii(nibble: u8, letter_offset: u8) -> u8 {
    let n = nibble as i32;
    // All ones when the nibble is above 9.
    let is_letter = (9 - n) >> 31;
    (n + b'0' as i32 + (is_letter & letter_offset as i32)) as u8
}

/// Value of an ASCII hex digit in the low nibble, and all ones in the second result when the
/// byte is not a hex digit (the value is then 0).
#[inline(always)]
pub(crate) const fn ascii_to_nibble(c: u8) -> (u8, i32) {
    let c = c as i32;
    let digit = c - b'0' as i32;
    let alpha = (c | 0x20) - b'a' as i32;
    let not_digit = (digit | (9 - digit)) >> 31;
    let not_alpha = (alpha | (5 - alpha)) >> 31;
    let value = (digit & !not_digit) | ((alpha + 10) & !not_alpha);
    (value as u8, not_digit & not_alpha)
}

fn encode(bytes: &[u8], letter_offset: u8) -> String {
    let mut out = vec![0u8; bytes.len() * 2];
    encode_into(bytes, &mut out, letter_offset);
    String::from_utf8(out).unwrap_or_default()
}

#[inline]
fn encode_into(bytes: &[u8], out: &mut [u8], letter_offset: u8) {
    for (pair, &b) in out.chunks_exact_mut(2).zip(bytes) {
        pair[0] = nibble_to_ascii(b >> 4, letter_offset);
        pair[1] = nibble_to_ascii(b & 0x0f, letter_offset);
    }
}

pub(crate) fn encode_lower(bytes: &[u8]) -> String {
    encode(bytes, 39)
}

pub(crate) fn encode_upper(bytes: &[u8]) -> String {
    encode(bytes, 7)
}

/// Upper-case hex into a caller buffer of exactly twice the input length.
#[inline]
pub(crate) fn encode_upper_into(bytes: &[u8], out: &mut [u8]) {
    debug_assert_eq!(out.len(), bytes.len() * 2);
    encode_into(bytes, out, 7);
}

/// Lower-case hex appended to `out`.
#[inline]
pub(crate) fn push_lower(out: &mut String, bytes: &[u8]) {
    let mut chunk = [0u8; 128];
    for part in bytes.chunks(chunk.len() / 2) {
        let used = &mut chunk[..part.len() * 2];
        encode_into(part, used, 39);
        out.push_str(core::str::from_utf8(used).unwrap_or_default());
    }
}

/// Decodes pairs of hex digits into `out`, one byte per pair of `hex`. Returns false when any
/// byte of `hex` is not a hex digit; `out` is then unspecified.
#[inline]
pub(crate) fn decode_into(hex: &[u8], out: &mut [u8]) -> bool {
    debug_assert_eq!(hex.len(), out.len() * 2);
    #[cfg(target_arch = "x86_64")]
    let (done, mut valid) = decode_sse2(hex, out);
    #[cfg(target_arch = "aarch64")]
    let (done, mut valid) = decode_neon(hex, out);
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let (done, mut valid) = (0, true);
    valid &= decode_scalar(&hex[done * 2..], &mut out[done..]);
    valid
}

/// Portable decoder, also the tail of the SIMD one.
fn decode_scalar(hex: &[u8], out: &mut [u8]) -> bool {
    let mut invalid = 0i32;
    for (byte, pair) in out.iter_mut().zip(hex.chunks_exact(2)) {
        let (high, bad_high) = ascii_to_nibble(pair[0]);
        let (low, bad_low) = ascii_to_nibble(pair[1]);
        *byte = (high << 4) | low;
        invalid |= bad_high | bad_low;
    }
    invalid == 0
}

/// Decodes 16 digits at a time with SSE2, which every x86-64 CPU has; the same arithmetic as
/// `ascii_to_nibble`, per lane. Returns the output bytes done and whether all digits were valid.
#[cfg(target_arch = "x86_64")]
#[inline]
fn decode_sse2(hex: &[u8], out: &mut [u8]) -> (usize, bool) {
    use core::arch::x86_64::*;
    let mut done = 0;
    let mut valid = 0xffffu32;
    for (input, output) in hex.chunks_exact(16).zip(out.chunks_exact_mut(8)) {
        // SAFETY: SSE2 is part of the x86-64 baseline; loads and stores go through unaligned
        // intrinsics on slices of exactly 16 and 8 bytes.
        #[allow(unused_unsafe)]
        unsafe {
            let c = _mm_loadu_si128(input.as_ptr().cast());
            let digit = _mm_sub_epi8(c, _mm_set1_epi8(b'0' as i8));
            let alpha = _mm_sub_epi8(
                _mm_or_si128(c, _mm_set1_epi8(0x20)),
                _mm_set1_epi8(b'a' as i8),
            );
            let is_digit = _mm_cmpeq_epi8(_mm_min_epu8(digit, _mm_set1_epi8(9)), digit);
            let is_alpha = _mm_cmpeq_epi8(_mm_min_epu8(alpha, _mm_set1_epi8(5)), alpha);
            let nibbles = _mm_or_si128(
                _mm_and_si128(digit, is_digit),
                _mm_and_si128(_mm_add_epi8(alpha, _mm_set1_epi8(10)), is_alpha),
            );
            valid &= _mm_movemask_epi8(_mm_or_si128(is_digit, is_alpha)) as u32;
            // Each 16-bit lane holds (low digit << 8) | high digit; make it one byte.
            let high = _mm_slli_epi16::<4>(_mm_and_si128(nibbles, _mm_set1_epi16(0x00ff)));
            let low = _mm_srli_epi16::<8>(nibbles);
            let bytes = _mm_packus_epi16(_mm_or_si128(high, low), _mm_setzero_si128());
            _mm_storel_epi64(output.as_mut_ptr().cast(), bytes);
        }
        done += 8;
    }
    (done, valid == 0xffff)
}

/// The same on NEON, which every AArch64 CPU has.
#[cfg(target_arch = "aarch64")]
#[inline]
fn decode_neon(hex: &[u8], out: &mut [u8]) -> (usize, bool) {
    use core::arch::aarch64::*;
    let mut done = 0;
    let mut valid = 0xffu8;
    for (input, output) in hex.chunks_exact(16).zip(out.chunks_exact_mut(8)) {
        // SAFETY: NEON is part of the AArch64 baseline; the slices hold exactly 16 and 8 bytes.
        #[allow(unused_unsafe)]
        unsafe {
            let c = vld1q_u8(input.as_ptr());
            let digit = vsubq_u8(c, vdupq_n_u8(b'0'));
            let alpha = vsubq_u8(vorrq_u8(c, vdupq_n_u8(0x20)), vdupq_n_u8(b'a'));
            let is_digit = vcleq_u8(digit, vdupq_n_u8(9));
            let is_alpha = vcleq_u8(alpha, vdupq_n_u8(5));
            let nibbles = vorrq_u8(
                vandq_u8(digit, is_digit),
                vandq_u8(vaddq_u8(alpha, vdupq_n_u8(10)), is_alpha),
            );
            valid &= vminvq_u8(vorrq_u8(is_digit, is_alpha));
            // Each 16-bit lane holds (low digit << 8) | high digit; make it one byte.
            let words = vreinterpretq_u16_u8(nibbles);
            let high = vshlq_n_u16::<4>(vandq_u16(words, vdupq_n_u16(0x00ff)));
            let low = vshrq_n_u16::<8>(words);
            vst1_u8(output.as_mut_ptr(), vmovn_u16(vorrq_u16(high, low)));
        }
        done += 8;
    }
    (done, valid == 0xff)
}

/// Decodes an even-length string of plain hex digits. `None` covers every other input, as well as
/// running out of memory.
pub(crate) fn decode_plain(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::new();
    out.try_reserve_exact(hex.len() / 2).ok()?;
    out.resize(hex.len() / 2, 0);
    decode_into(hex.as_bytes(), &mut out).then_some(out)
}

/// Like `encode_lower`, returning `None` instead of aborting when memory runs out.
pub(crate) fn try_encode_lower(bytes: &[u8]) -> Option<String> {
    let len = bytes.len().checked_mul(2)?;
    let mut out = Vec::new();
    out.try_reserve_exact(len).ok()?;
    out.resize(len, 0);
    encode_into(bytes, &mut out, 39);
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nibble_tables_match_every_byte() {
        for c in 0..=255u8 {
            let expected = (c as char).to_digit(16);
            let (value, invalid) = ascii_to_nibble(c);
            match expected {
                Some(v) => {
                    assert_eq!(u32::from(value), v, "{c}");
                    assert_eq!(invalid, 0, "{c}");
                }
                None => {
                    assert_eq!(value, 0, "{c}");
                    assert_eq!(invalid, -1, "{c}");
                }
            }
        }
    }

    /// The SIMD decoder against the scalar one on every byte in every lane.
    #[test]
    fn decoders_agree() {
        let mut text = *b"0123456789abcdef";
        for pos in 0..16 {
            for c in 0..=255u8 {
                text[pos] = c;
                let mut scalar = [0u8; 8];
                let scalar_ok = decode_scalar(&text, &mut scalar);
                let mut full = [0u8; 8];
                let full_ok = decode_into(&text, &mut full);
                assert_eq!(full_ok, scalar_ok);
                if scalar_ok {
                    assert_eq!(full, scalar);
                }
            }
            text[pos] = b"0123456789abcdef"[pos];
        }
    }

    #[test]
    fn encode_matches_format() {
        let bytes: Vec<u8> = (0..=255).collect();
        let lower: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let upper: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(encode_lower(&bytes), lower);
        assert_eq!(encode_upper(&bytes), upper);
        let mut pushed = String::from("x");
        push_lower(&mut pushed, &bytes);
        assert_eq!(pushed, format!("x{lower}"));
        assert_eq!(decode_plain(&lower).unwrap(), bytes);
        assert_eq!(decode_plain(&upper).unwrap(), bytes);
        assert_eq!(try_encode_lower(&bytes).unwrap(), lower);
        assert!(decode_plain("0").is_none());
        assert!(decode_plain("0g").is_none());
        assert!(decode_plain("+f").is_none());
        assert!(decode_plain("é").is_none());
        assert_eq!(
            decode_plain("00FFaAbB12cdEf0900FFaAbB12cdEf09ff").unwrap(),
            [
                0, 255, 170, 187, 18, 205, 239, 9, 0, 255, 170, 187, 18, 205, 239, 9, 255
            ]
        );
        // An invalid byte is noticed at every position, in SIMD chunks and in the tail.
        for len in [2usize, 30, 32, 34, 64, 100] {
            for pos in 0..len {
                let mut text = vec![b'a'; len];
                assert!(decode_plain(core::str::from_utf8(&text).unwrap()).is_some());
                for bad in [b'g', b'/', b':', b'@', b'`', 0u8, b' ', 0x7f] {
                    text[pos] = bad;
                    assert!(decode_plain(core::str::from_utf8(&text).unwrap()).is_none());
                }
            }
        }
    }
}
