//! The SM4 S-box as a Boolean circuit, for CPUs without AES instructions: no memory access and no
//! branch depends on the data.
//!
//! S(x) = B(inv(A(x))) with inversion in a tower of fields, GF(((2^2)^2)^2):
//! - GF(4) has elements `a1 w + a0` with w^2 = w + 1;
//! - GF(16) has `A z + B` over GF(4) with z^2 = z + w;
//! - GF(256) has `E y + F` over GF(16) with y^2 = y + 9 (y^2 + y + lambda, lambda = 0b1001).
//!
//! The input and output linear layers below combine SM4's affine maps with the isomorphism into
//! this tower. All values are bit-slices of `u32`s holding one bit per byte of a 32-bit word, so
//! the four S-boxes of a round are computed together. A test checks all 256 inputs in every lane
//! against the table of the standard.

/// All lanes set, used as logical NOT.
const ONES: u32 = 0x0101_0101;

type Gf4 = (u32, u32);
type Gf16 = [u32; 4];

#[inline(always)]
fn xor4(a: Gf4, b: Gf4) -> Gf4 {
    (a.0 ^ b.0, a.1 ^ b.1)
}

/// (a1 w + a0)(b1 w + b0); the tuples are (high, low).
#[inline(always)]
fn mul4(a: Gf4, b: Gf4) -> Gf4 {
    let high = a.0 & b.0;
    let low = a.1 & b.1;
    let mid = (a.0 ^ a.1) & (b.0 ^ b.1);
    (mid ^ low, high ^ low)
}

/// Multiplication by w.
#[inline(always)]
fn scale4(a: Gf4) -> Gf4 {
    (a.0 ^ a.1, a.0)
}

#[inline(always)]
fn split(x: Gf16) -> (Gf4, Gf4) {
    ((x[3], x[2]), (x[1], x[0]))
}

#[inline(always)]
fn join(high: Gf4, low: Gf4) -> Gf16 {
    [low.1, low.0, high.1, high.0]
}

#[inline(always)]
fn xor16(a: Gf16, b: Gf16) -> Gf16 {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

#[inline(always)]
fn mul16(x: Gf16, y: Gf16) -> Gf16 {
    let (a, b) = split(x);
    let (c, d) = split(y);
    let ac = mul4(a, c);
    let bd = mul4(b, d);
    let mid = mul4(xor4(a, b), xor4(c, d));
    join(xor4(mid, bd), xor4(scale4(ac), bd))
}

/// Inverse in GF(16), with 0 mapping to 0: (A z + B)^-1 = (A z + A + B) / (w A^2 + A B + B^2).
#[inline(always)]
fn inv16(x: Gf16) -> Gf16 {
    let (a, b) = split(x);
    let product = mul4(a, b);
    // w A^2 has bits (a0, a1); B^2 has bits (b1, b0 ^ b1).
    let norm = (product.0 ^ a.1 ^ b.0, product.1 ^ a.0 ^ b.0 ^ b.1);
    // Inversion in GF(4) is squaring.
    let inverse = (norm.0, norm.0 ^ norm.1);
    join(mul4(a, inverse), mul4(xor4(a, b), inverse))
}

/// Inverse in GF(256), with 0 mapping to 0. Input and output are [low..., high...] bit order.
#[inline(always)]
fn inv256(t: [u32; 8]) -> [u32; 8] {
    let f = [t[0], t[1], t[2], t[3]];
    let e = [t[4], t[5], t[6], t[7]];
    let product = mul16(e, f);
    // lambda E^2 + F^2 is linear in the bits of E and F.
    let norm = [
        product[0] ^ e[0] ^ e[1] ^ e[2] ^ e[3] ^ f[0] ^ f[1] ^ f[3],
        product[1] ^ e[1] ^ e[3] ^ f[1] ^ f[2],
        product[2] ^ e[1] ^ f[2] ^ f[3],
        product[3] ^ e[0] ^ f[3],
    ];
    let inverse = inv16(norm);
    let out_e = mul16(e, inverse);
    let out_f = mul16(xor16(e, f), inverse);
    [
        out_f[0], out_f[1], out_f[2], out_f[3], out_e[0], out_e[1], out_e[2], out_e[3],
    ]
}

/// The S-box applied to each byte of a word.
#[inline]
pub(super) fn sbox_word(word: u32) -> u32 {
    let x0 = word & ONES;
    let x1 = (word >> 1) & ONES;
    let x2 = (word >> 2) & ONES;
    let x3 = (word >> 3) & ONES;
    let x4 = (word >> 4) & ONES;
    let x5 = (word >> 5) & ONES;
    let x6 = (word >> 6) & ONES;
    let x7 = (word >> 7) & ONES;

    let [t0, t1, t2, t3, t4, t5, t6, t7] = inv256([
        x1 ^ x2 ^ x5,
        x1 ^ x4 ^ x5 ^ x6 ^ ONES,
        x2 ^ x5 ^ x7,
        x3 ^ x4 ^ ONES,
        x0 ^ x1 ^ x2 ^ x4 ^ x6,
        x6 ^ ONES,
        x2 ^ x7 ^ ONES,
        x0 ^ x1 ^ x2 ^ x3 ^ x4 ^ x5 ^ x6 ^ ONES,
    ]);

    (t0 ^ t2 ^ t4 ^ t6 ^ ONES)
        | ((t0 ^ t6 ^ ONES) << 1)
        | ((t1 ^ t2 ^ t4 ^ t5 ^ t6) << 2)
        | ((t0 ^ t4 ^ t6 ^ t7) << 3)
        | ((t1 ^ t3 ^ t7 ^ ONES) << 4)
        | ((t1 ^ t3 ^ t5) << 5)
        | ((t0 ^ t1 ^ ONES) << 6)
        | ((t0 ^ t1 ^ t2 ^ t3 ^ t5 ^ ONES) << 7)
}

/// The table of GB/T 32907, only to check the circuit and the hardware paths.
#[cfg(test)]
pub(crate) const SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_matches_the_standard_on_all_inputs_in_every_lane() {
        for lane in 0..4 {
            for x in 0..=255u8 {
                let shift = 8 * lane;
                // The other lanes hold a value that must not disturb this one.
                let word = (u32::from(x) << shift) | (0xa5a5_a5a5 & !(0xff << shift));
                let out = sbox_word(word);
                assert_eq!((out >> shift) as u8, SBOX[x as usize], "{x:#x} lane {lane}");
                for other in (0..4).filter(|&o| o != lane) {
                    assert_eq!(
                        (out >> (8 * other)) as u8,
                        SBOX[0xa5],
                        "{x:#x} lane {other}"
                    );
                }
            }
        }
    }
}
