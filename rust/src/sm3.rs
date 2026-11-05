//! SM3 实现（无第三方依赖），接口尽量贴近 Java/Swift/JS 版本

use crate::ct::wipe;
use crate::hex;
use std::sync::OnceLock;

const BLOCK_LEN: usize = 64;

/// The 64-bit length field counts bits, so no message may reach 2^61 bytes.
pub(crate) const MAX_MESSAGE_BYTES: u64 = (1 << 61) - 1;

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

/// A completed result, kept until the next message starts.
#[derive(Clone)]
struct Digest {
    bytes: [u8; 32],
    hex: [u8; 64],
    valid: bool,
}

impl Drop for Digest {
    fn drop(&mut self) {
        wipe(&mut self.bytes, [0; 32]);
        wipe(&mut self.hex, [0; 64]);
    }
}

/// Incremental SM3.
///
/// Reading never returns a stale or empty value: `hash_bytes` and `hash_hex_upper` give the digest
/// of the current message, whether `finish` was called or not, and reading does not disturb it.
/// `finish` ends the message; calling it again keeps the same result, and the next update starts
/// a new message.
///
/// A message may have at most 2^61 - 1 bytes. Beyond that there is no digest: `hash_hex_upper`
/// returns "", `hash_bytes` all zeros and `checked_hash_bytes` `None`, until the next message.
#[derive(Clone)]
pub struct Sm3 {
    v: [u32; 8],
    buff: [u8; BLOCK_LEN],
    buff_len: usize, // 已写入字节数
    data_len: u64,
    too_long: bool,
    finished: bool,
    result: OnceLock<Digest>,
}

impl Default for Sm3 {
    fn default() -> Self {
        Self::new()
    }
}

/// The input and the digest can be secrets when SM3 is used as a KDF.
impl Drop for Sm3 {
    fn drop(&mut self) {
        wipe(&mut self.v, [0; 8]);
        wipe(&mut self.buff, [0; BLOCK_LEN]);
    }
}

impl Sm3 {
    pub fn new() -> Self {
        Sm3 {
            v: IV,
            buff: [0u8; BLOCK_LEN],
            buff_len: 0,
            data_len: 0,
            too_long: false,
            finished: false,
            result: OnceLock::new(),
        }
    }

    /// Whatever was read or finished before is out of date once more data comes.
    #[inline]
    fn begin_update(&mut self) {
        if self.finished {
            self.finished = false;
        }
        if self.result.get().is_some() {
            self.result = OnceLock::new();
        }
    }

    /// Counts `count` more message bytes; false once the message is over the limit.
    #[inline]
    fn account(&mut self, count: u64) -> bool {
        match self.data_len.checked_add(count) {
            Some(total) if total <= MAX_MESSAGE_BYTES && !self.too_long => {
                self.data_len = total;
                true
            }
            _ => {
                self.too_long = true;
                false
            }
        }
    }

    /// 更新单字节
    #[inline]
    pub fn update_byte(&mut self, b: u8) -> &mut Self {
        self.begin_update();
        if !self.account(1) {
            return self;
        }
        self.buff[self.buff_len] = b;
        self.buff_len += 1;
        if self.buff_len == BLOCK_LEN {
            compress_blocks(&mut self.v, &self.buff);
            self.buff_len = 0;
        }
        self
    }

    /// 更新字节数组
    #[inline]
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.begin_update();
        if !self.account(data.len() as u64) {
            return self;
        }
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

    /// Completes the message; the next update starts a new one. Calling this again keeps the
    /// result. See the type documentation for messages over the length limit.
    pub fn finish(&mut self) -> &mut Self {
        if self.finished {
            return self;
        }
        let digest = Self::seal(self.too_long, self.finalize_digest());
        self.result = OnceLock::from(digest);
        self.finished = true;
        self
    }

    fn seal(too_long: bool, bytes: [u8; 32]) -> Digest {
        let mut hex_digits = [0u8; 64];
        hex::encode_upper_into(&bytes, &mut hex_digits);
        Digest {
            bytes,
            hex: hex_digits,
            valid: !too_long,
        }
    }

    /// The digest of the current message, computed from a copy of the state if not yet finished.
    fn digest(&self) -> &Digest {
        self.result.get_or_init(|| {
            let mut copy = self.clone();
            let too_long = copy.too_long;
            Self::seal(too_long, copy.finalize_digest())
        })
    }

    /// The digest of the current message; all zeros if it went over the length limit.
    pub fn hash_bytes(&self) -> &[u8; 32] {
        &self.digest().bytes
    }

    /// `hash_bytes` that reports a message over the length limit.
    pub fn checked_hash_bytes(&self) -> Option<&[u8; 32]> {
        let digest = self.digest();
        digest.valid.then_some(&digest.bytes)
    }

    /// The digest of the current message in hex; "" if it went over the length limit.
    pub fn hash_hex_upper(&self) -> &str {
        let digest = self.digest();
        if digest.valid {
            core::str::from_utf8(&digest.hex).unwrap_or("")
        } else {
            ""
        }
    }

    /// Pads, returns the digest (all zeros for a message over the limit) and resets for reuse,
    /// without touching the stored results.
    pub(crate) fn finalize_digest(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        if !self.too_long {
            let len = self.buff_len;
            self.buff[len] = 0x80;
            self.buff[len + 1..].fill(0);
            if len >= BLOCK_LEN - 8 {
                compress_blocks(&mut self.v, &self.buff);
                self.buff.fill(0);
            }
            // Cannot overflow: the byte count is at most 2^61 - 1.
            let bits = self.data_len * 8;
            self.buff[BLOCK_LEN - 8..].copy_from_slice(&bits.to_be_bytes());
            compress_blocks(&mut self.v, &self.buff);

            for (bytes, word) in out.chunks_exact_mut(4).zip(self.v) {
                bytes.copy_from_slice(&word.to_be_bytes());
            }
        }
        self.v = IV;
        self.buff_len = 0;
        self.data_len = 0;
        self.too_long = false;
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

    const ABC: &str = "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0";
    const EMPTY: &str = "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B";

    #[test]
    fn reading_without_finish_gives_the_current_digest() {
        let mut sm3 = Sm3::new();
        assert_eq!(sm3.hash_hex_upper(), EMPTY);
        sm3.update_str("a");
        let partial = sm3.hash_hex_upper().to_string();
        assert_ne!(partial, EMPTY);
        // Reading did not disturb the message.
        sm3.update_str("bc");
        assert_eq!(sm3.hash_hex_upper(), ABC);
        assert_eq!(hex_of(sm3.hash_bytes()), ABC);
        sm3.finish();
        assert_eq!(sm3.hash_hex_upper(), ABC);
    }

    #[test]
    fn finish_twice_keeps_the_result_and_update_starts_a_new_message() {
        let mut sm3 = Sm3::new();
        sm3.update_str("abc").finish().finish();
        assert_eq!(sm3.hash_hex_upper(), ABC);
        assert_eq!(sm3.checked_hash_bytes().map(hex_of).as_deref(), Some(ABC));

        // Not stale: the old digest is gone as soon as new data arrives.
        sm3.update_str("x");
        assert_ne!(sm3.hash_hex_upper(), ABC);
        sm3.finish();
        let x = sm3.hash_hex_upper().to_string();
        let mut fresh = Sm3::new();
        fresh.update_str("x").finish();
        assert_eq!(x, fresh.hash_hex_upper());

        // A byte update also starts over, and an empty update begins an empty message.
        sm3.update_byte(b'x');
        assert_eq!(sm3.hash_hex_upper(), x);
        sm3.finish();
        sm3.update(b"");
        assert_eq!(sm3.hash_hex_upper(), EMPTY);
    }

    #[test]
    fn clones_are_independent() {
        let mut sm3 = Sm3::new();
        sm3.update_str("a");
        let _ = sm3.hash_bytes();
        let mut copy = sm3.clone();
        copy.update_str("bc");
        assert_eq!(copy.hash_hex_upper(), ABC);
        assert_ne!(sm3.hash_hex_upper(), ABC);
    }

    fn hex_of(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    /// The limit is checked without having to hash 2^61 bytes.
    #[test]
    fn length_limit_is_enforced_and_clears_on_finish() {
        let mut sm3 = Sm3::new();
        sm3.data_len = super::MAX_MESSAGE_BYTES;
        sm3.update(b""); // adding nothing stays valid
        assert!(!sm3.too_long);
        sm3.update_byte(1);
        assert!(sm3.too_long);
        sm3.update(b"more"); // stays failed, does not wrap
        assert_eq!(sm3.hash_hex_upper(), "");
        sm3.finish();
        assert_eq!(sm3.hash_hex_upper(), "");
        assert_eq!(sm3.hash_bytes(), &[0u8; 32]);
        assert!(sm3.checked_hash_bytes().is_none());

        sm3.data_len = u64::MAX - 1;
        sm3.update(&[0u8; 5]); // overflow of the counter itself
        assert!(sm3.too_long);
        sm3.finish();
        assert_eq!(sm3.hash_hex_upper(), "");

        // The instance works again afterwards.
        sm3.update_str("abc").finish();
        assert_eq!(
            sm3.hash_hex_upper(),
            "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0"
        );

        // The longest allowed message still finalizes without overflow.
        let mut sm3 = Sm3::new();
        sm3.data_len = super::MAX_MESSAGE_BYTES;
        sm3.finish();
        assert_eq!(sm3.hash_hex_upper().len(), 64);
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
