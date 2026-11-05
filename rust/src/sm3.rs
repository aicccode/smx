//! SM3 实现（无第三方依赖），接口尽量贴近 Java/Swift/JS 版本

use crate::hex;

const BLOCK_LEN: usize = 64;

const IV: [u32; 8] = [
    0x7380_166F,
    0x4914_B2B9,
    0x1724_42D7,
    0xDA8A_0600,
    0xA96F_30BC,
    0x1631_38AA,
    0xE38D_EE4D,
    0xB0FB_0E4E,
];

/// Round constants `T_j <<< j`, precomputed.
const T: [u32; 64] = {
    let mut t = [0u32; 64];
    let mut j = 0;
    while j < 64 {
        let base: u32 = if j < 16 { 0x79CC_4519 } else { 0x7A87_9D8A };
        t[j] = base.rotate_left((j % 32) as u32);
        j += 1;
    }
    t
};

#[inline(always)]
const fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

#[inline(always)]
const fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

/// One compression round without register moves: the caller rotates the variable names.
macro_rules! round {
    ($w:ident, $j:expr, $ff:expr, $gg:expr,
     $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident) => {
        let a12 = $a.rotate_left(12);
        let ss1 = a12.wrapping_add($e).wrapping_add(T[$j]).rotate_left(7);
        let ss2 = ss1 ^ a12;
        $d = $d
            .wrapping_add($ff)
            .wrapping_add(ss2)
            .wrapping_add($w[$j] ^ $w[$j + 4]);
        $h = $h.wrapping_add($gg).wrapping_add(ss1).wrapping_add($w[$j]);
        $b = $b.rotate_left(9);
        $f = $f.rotate_left(19);
        $h = p0($h);
    };
}

/// Rounds 0..16: FF and GG are plain XOR.
macro_rules! low {
    ($w:ident, $j:expr, $a:ident, $b:ident, $c:ident, $d:ident,
     $e:ident, $f:ident, $g:ident, $h:ident) => {
        round!(
            $w,
            $j,
            $a ^ $b ^ $c,
            $e ^ $f ^ $g,
            $a,
            $b,
            $c,
            $d,
            $e,
            $f,
            $g,
            $h
        );
    };
}

/// Rounds 16..64: majority and choice, in their cheapest bitwise forms.
macro_rules! high {
    ($w:ident, $j:expr, $a:ident, $b:ident, $c:ident, $d:ident,
     $e:ident, $f:ident, $g:ident, $h:ident) => {
        round!(
            $w,
            $j,
            ($a & $b) | ($c & ($a | $b)),
            (($f ^ $g) & $e) ^ $g,
            $a,
            $b,
            $c,
            $d,
            $e,
            $f,
            $g,
            $h
        );
    };
}

/// Four rounds starting at `$j`, ending with the variables back in their original roles.
macro_rules! four {
    ($kind:ident, $w:ident, $j:expr, $a:ident, $b:ident, $c:ident, $d:ident,
     $e:ident, $f:ident, $g:ident, $h:ident) => {
        $kind!($w, $j, $a, $b, $c, $d, $e, $f, $g, $h);
        $kind!($w, $j + 1, $d, $a, $b, $c, $h, $e, $f, $g);
        $kind!($w, $j + 2, $c, $d, $a, $b, $g, $h, $e, $f);
        $kind!($w, $j + 3, $b, $c, $d, $a, $f, $g, $h, $e);
    };
}

/// Absorbs whole 64-byte blocks; any trailing partial block is ignored by construction.
fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    let [
        mut s0,
        mut s1,
        mut s2,
        mut s3,
        mut s4,
        mut s5,
        mut s6,
        mut s7,
    ] = *state;
    for block in blocks.chunks_exact(BLOCK_LEN) {
        let mut w = [0u32; 68];
        for (word, bytes) in w.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for j in 16..68 {
            w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
                ^ w[j - 13].rotate_left(7)
                ^ w[j - 6];
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) =
            (s0, s1, s2, s3, s4, s5, s6, s7);
        four!(low, w, 0, a, b, c, d, e, f, g, h);
        four!(low, w, 4, a, b, c, d, e, f, g, h);
        four!(low, w, 8, a, b, c, d, e, f, g, h);
        four!(low, w, 12, a, b, c, d, e, f, g, h);
        four!(high, w, 16, a, b, c, d, e, f, g, h);
        four!(high, w, 20, a, b, c, d, e, f, g, h);
        four!(high, w, 24, a, b, c, d, e, f, g, h);
        four!(high, w, 28, a, b, c, d, e, f, g, h);
        four!(high, w, 32, a, b, c, d, e, f, g, h);
        four!(high, w, 36, a, b, c, d, e, f, g, h);
        four!(high, w, 40, a, b, c, d, e, f, g, h);
        four!(high, w, 44, a, b, c, d, e, f, g, h);
        four!(high, w, 48, a, b, c, d, e, f, g, h);
        four!(high, w, 52, a, b, c, d, e, f, g, h);
        four!(high, w, 56, a, b, c, d, e, f, g, h);
        four!(high, w, 60, a, b, c, d, e, f, g, h);

        s0 ^= a;
        s1 ^= b;
        s2 ^= c;
        s3 ^= d;
        s4 ^= e;
        s5 ^= f;
        s6 ^= g;
        s7 ^= h;
    }
    *state = [s0, s1, s2, s3, s4, s5, s6, s7];
}

#[derive(Clone)]
pub struct Sm3 {
    v: [u32; 8],
    buff: [u8; BLOCK_LEN],
    buff_len: usize, // 已写入字节数
    data_bits_len: u64,
    hash_bytes: [u8; 32],
    hash_value_hex: [u8; 64],
    finished: bool,
}

impl Default for Sm3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sm3 {
    pub fn new() -> Self {
        Sm3 {
            v: IV,
            buff: [0u8; BLOCK_LEN],
            buff_len: 0,
            data_bits_len: 0,
            hash_bytes: [0u8; 32],
            hash_value_hex: [0u8; 64],
            finished: false,
        }
    }

    /// 更新单字节
    #[inline]
    pub fn update_byte(&mut self, b: u8) -> &mut Self {
        self.buff[self.buff_len] = b;
        self.buff_len += 1;
        self.data_bits_len = self.data_bits_len.wrapping_add(8);
        if self.buff_len == BLOCK_LEN {
            compress_blocks(&mut self.v, &self.buff);
            self.buff_len = 0;
        }
        self
    }

    /// 更新字节数组
    #[inline]
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.data_bits_len = self
            .data_bits_len
            .wrapping_add((data.len() as u64).wrapping_mul(8));
        let mut rest = data;
        if self.buff_len > 0 {
            let take = rest.len().min(BLOCK_LEN - self.buff_len);
            let (head, tail) = rest.split_at(take);
            self.buff[self.buff_len..self.buff_len + take].copy_from_slice(head);
            self.buff_len += take;
            rest = tail;
            if self.buff_len < BLOCK_LEN {
                return self;
            }
            compress_blocks(&mut self.v, &self.buff);
            self.buff_len = 0;
        }
        let whole = rest.len() - rest.len() % BLOCK_LEN;
        let (blocks, tail) = rest.split_at(whole);
        if !blocks.is_empty() {
            compress_blocks(&mut self.v, blocks);
        }
        self.buff[..tail.len()].copy_from_slice(tail);
        self.buff_len = tail.len();
        self
    }

    /// 更新 UTF-8 字符串
    #[inline]
    pub fn update_str(&mut self, s: &str) -> &mut Self {
        self.update(s.as_bytes())
    }

    pub fn finish(&mut self) -> &mut Self {
        let digest = self.finalize_digest();
        self.hash_bytes = digest;
        hex::encode_upper_into(&digest, &mut self.hash_value_hex);
        self.finished = true;
        self
    }

    pub fn hash_bytes(&self) -> &[u8; 32] {
        &self.hash_bytes
    }

    pub fn hash_hex_upper(&self) -> &str {
        if self.finished {
            core::str::from_utf8(&self.hash_value_hex).expect("hex output is ASCII")
        } else {
            ""
        }
    }

    /// Pads, returns the digest and resets for reuse, without touching the stored results.
    ///
    /// Compatibility note: as in the Java implementation this code was ported from, the length
    /// field only carries the low 32 bits of the bit count, so messages of 2^29 bytes (512 MiB)
    /// or more hash differently from standard SM3.
    pub(crate) fn finalize_digest(&mut self) -> [u8; 32] {
        let len = self.buff_len;
        self.buff[len] = 0x80;
        self.buff[len + 1..].fill(0);
        if len >= BLOCK_LEN - 8 {
            compress_blocks(&mut self.v, &self.buff);
            self.buff.fill(0);
        }
        let low_bits = self.data_bits_len as u32;
        self.buff[BLOCK_LEN - 4..].copy_from_slice(&low_bits.to_be_bytes());
        compress_blocks(&mut self.v, &self.buff);

        let mut out = [0u8; 32];
        for (bytes, word) in out.chunks_exact_mut(4).zip(self.v) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        self.v = IV;
        self.buff_len = 0;
        self.data_bits_len = 0;
        out
    }
}

/// One-shot digest of a sequence of byte strings.
#[inline]
pub(crate) fn digest_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sm3::new();
    for part in parts {
        h.update(part);
    }
    h.finalize_digest()
}

#[cfg(test)]
mod tests {
    use super::Sm3;

    fn sm3_hex(input: &str) -> String {
        let mut sm3 = Sm3::new();
        sm3.update_str(input).finish();
        sm3.hash_hex_upper().to_string()
    }

    #[test]
    fn test_sm3_abc() {
        let h = sm3_hex("abc");
        assert_eq!(
            h,
            "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0"
        );
    }

    #[test]
    fn test_sm3_empty() {
        let h = sm3_hex("");
        assert_eq!(
            h,
            "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B"
        );
    }
}
