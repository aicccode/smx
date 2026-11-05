//! Seeded malformed-input runs over every public function, asserting only the failure convention:
//! no panic, no hang, failures reported the normal way, no acceptance of tampered values. Plus
//! round-trip properties.
//!
//! A quick pass runs with the normal tests. The full run is
//! `FUZZ_CASES=200000 cargo test --release --test fuzz_api -- --nocapture --test-threads=8`.

use gm_rust::sm2::SM2;
use gm_rust::sm2::bigint256::BigInt256;
use gm_rust::sm2::fp::{FpElement, SM2_P};
use gm_rust::sm2::point::{ECPoint, SM2_N};
use gm_rust::sm3::Sm3;
use gm_rust::sm4::SM4;
use std::time::Instant;

const DEFAULT_CASES: u64 = 1000;
const D: &str = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
const PUBLIC: &str = "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13";

fn cases() -> u64 {
    std::env::var("FUZZ_CASES")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(DEFAULT_CASES)
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }

    fn limbs(&mut self) -> [u64; 4] {
        let mut v = [self.next(), self.next(), self.next(), self.next()];
        match self.below(5) {
            0 => {
                for limb in v.iter_mut() {
                    *limb = [0, 1, u64::MAX, 1 << 63, 0xFFFF_FFFF][self.below(5) as usize];
                }
            }
            1 => {
                v = [
                    SM2_P.limbs,
                    SM2_N.limbs,
                    [u64::MAX; 4],
                    [0; 4],
                    [1, 0, 0, 0],
                ][self.below(5) as usize];
                let delta = self.below(5);
                v[0] = if self.below(2) == 0 {
                    v[0].wrapping_add(delta)
                } else {
                    v[0].wrapping_sub(delta)
                };
            }
            _ => {}
        }
        v
    }

    fn big(&mut self) -> BigInt256 {
        BigInt256::new(self.limbs())
    }

    /// Arbitrary text: lengths around the interesting ones, hex-like or not, ASCII or not.
    fn text(&mut self) -> String {
        const LENGTHS: [usize; 16] = [
            0, 1, 2, 3, 15, 16, 31, 32, 63, 64, 65, 129, 130, 131, 194, 196,
        ];
        let len = if self.below(200) == 0 {
            self.below(5000) as usize
        } else {
            LENGTHS[self.below(16) as usize]
        };
        match self.below(5) {
            0 => {
                let raw = self.bytes(len);
                String::from_utf8_lossy(&raw).into_owned()
            }
            1 => (0..len)
                .map(|_| ['é', '中', '\u{0}', '𝒳', '+', '-', ' ', 'h', 'x'][self.below(9) as usize])
                .collect(),
            _ => (0..len)
                .map(|_| b"0123456789abcdefABCDEF"[self.below(22) as usize] as char)
                .collect(),
        }
    }

    /// A valid value with a malformation applied. Returns the text; it may stay valid.
    fn mutated(&mut self, valid: &str) -> String {
        let mut text: Vec<char> = valid.chars().collect();
        match self.below(11) {
            0 if !text.is_empty() => {
                let at = self.below(text.len() as u64) as usize;
                text[at] = "0123456789abcdef"
                    .chars()
                    .nth(self.below(16) as usize)
                    .unwrap();
            }
            1 if !text.is_empty() => {
                let at = self.below(text.len() as u64) as usize;
                text[at] =
                    ['z', 'g', ' ', '+', '-', 'é', '中', 'x', '\u{0}'][self.below(9) as usize];
            }
            2 => text.truncate(self.below(text.len() as u64 + 1) as usize),
            3 => text.push('f'),
            4 => text.insert(0, '+'),
            5 => return format!("0x{valid}"),
            6 => return valid.to_uppercase(),
            7 => text.push('中'),
            8 if !text.is_empty() => {
                text.remove(0);
            }
            9 => text.extend("00".chars()),
            _ => {}
        }
        text.into_iter().collect()
    }
}

/// Runs `body` for the configured number of cases and reports the time.
fn run(name: &str, seed: u64, mut body: impl FnMut(&mut Rng)) {
    let count = cases();
    let mut rng = Rng(seed);
    let start = Instant::now();
    for _ in 0..count {
        body(&mut rng);
    }
    println!("{name:<28} {count} cases, {:.2?}", start.elapsed());
}

fn point_from(rng: &mut Rng) -> ECPoint {
    match rng.below(5) {
        // Raw limbs: unreduced, off the curve, anything a struct literal allows.
        0 => ECPoint {
            x: FpElement { value: rng.big() },
            y: FpElement { value: rng.big() },
            infinity: rng.below(8) == 0,
        },
        1 => ECPoint::infinity(),
        2 => ECPoint::new(FpElement::new(rng.big()), FpElement::new(rng.big())),
        3 => ECPoint::generator(),
        _ => SM2::decode_point(PUBLIC),
    }
}

#[test]
fn fuzz_bigint() {
    run("BigInt256 parsers", 1, |rng| {
        let text = rng.text();
        let value = BigInt256::from_hex(&text);
        assert_eq!(
            BigInt256::try_from_hex(&text).unwrap_or(BigInt256::ZERO),
            value
        );
        let bytes = rng.bytes((rng.0 % 70) as usize);
        BigInt256::from_be_bytes(&bytes);
    });
    run("BigInt256 arithmetic", 2, |rng| {
        let (a, b, m) = (rng.big(), rng.big(), rng.big());
        let modulus = match rng.below(4) {
            0 => SM2_P,
            1 => SM2_N,
            2 => BigInt256::new([rng.below(9), 0, 0, 0]),
            _ => m,
        };
        let _ = (
            a.add(&b),
            a.sub(&b),
            a.mul(&b),
            a.compare(&b),
            a.cmp(&b),
            a == b,
        );
        let _ = (a.mod_add(&b, &modulus), a.mod_sub(&b, &modulus));
        let product = a.mod_mul(&b, &modulus);
        assert!(modulus.is_zero() || product < modulus);
        let square = a.mod_square(&modulus);
        assert!(modulus.is_zero() || square < modulus);
        let _ = (
            a.shift_left_1(),
            a.shift_right_1(),
            a.and(&b),
            a.bit_length(),
        );
        let _ = (
            a.get_bit(rng.next() as usize),
            a.get_bit(rng.below(300) as usize),
        );
        let _ = (
            a.to_hex(),
            a.to_hex_lower(),
            a.to_be_bytes(),
            a.is_zero(),
            a.is_one(),
        );
        // Inverses are checked, so anything non-zero really is one.
        if modulus == SM2_P || modulus == SM2_N {
            let inverse = a.mod_inverse(&modulus);
            let reduced = a.mod_mul(&BigInt256::ONE, &modulus);
            assert_eq!(inverse.is_zero(), reduced.is_zero());
            if !inverse.is_zero() {
                assert!(a.mod_mul(&inverse, &modulus).is_one());
            }
        }
    });
    // Generic modular powers cost far more per case, so only their small-modulus edge runs often.
    run("BigInt256 generic pow/inv", 3, |rng| {
        let (a, e) = (rng.big(), BigInt256::new([rng.below(64), 0, 0, 0]));
        let modulus = BigInt256::new([rng.below(40), rng.below(2), 0, 0]);
        let _ = a.mod_pow(&e, &modulus);
        if rng.below(50) == 0 {
            let inverse = a.mod_inverse(&modulus);
            if !inverse.is_zero() {
                assert!(a.mod_mul(&inverse, &modulus).is_one() || modulus.is_one());
            }
        }
    });
}

#[test]
fn fuzz_field() {
    run("FpElement", 4, |rng| {
        let (x, y) = if rng.below(2) == 0 {
            (
                FpElement { value: rng.big() },
                FpElement { value: rng.big() },
            )
        } else {
            (FpElement::new(rng.big()), FpElement::new(rng.big()))
        };
        let _ = (
            x.add(&y),
            x.subtract(&y),
            x.multiply(&y),
            x.square(),
            x.negate(),
        );
        let _ = (
            x.double(),
            x.triple(),
            x.is_zero(),
            x.is_one(),
            x.to_hex(),
            x.to_be_bytes(),
        );
        let _ = (x.to_bigint(), FpElement::from_hex(&rng.text()));
    });
    run("FpElement invert/divide", 5, |rng| {
        let (x, y) = (
            FpElement { value: rng.big() },
            FpElement { value: rng.big() },
        );
        let _ = (x.invert(), x.divide(&y));
    });
}

#[test]
fn fuzz_points() {
    run("ECPoint parsers", 6, |rng| {
        let text = if rng.below(2) == 0 {
            rng.mutated(PUBLIC)
        } else {
            rng.text()
        };
        let point = ECPoint::from_hex_encoded(&text);
        // Whatever is accepted is valid, and re-encodes to what came in.
        if !point.is_infinity() {
            assert!(point.is_on_curve());
            assert_eq!(point.to_hex_encoded(), text.to_lowercase());
        }
        assert_eq!(SM2::decode_point(&text), point);
        let len = [0usize, 1, 64, 65, 66][rng.below(5) as usize];
        let mut raw = rng.bytes(len);
        if rng.below(2) == 0 && !raw.is_empty() {
            raw[0] = 4;
        }
        assert!(ECPoint::from_encoded(&raw).is_infinity() || len == 65);
        let (a, b) = (rng.text(), rng.text());
        assert!(ECPoint::from_hex(&a, &b).is_infinity() || a.len() == 64);
    });
    run("ECPoint group operations", 7, |rng| {
        let (p, q) = (point_from(rng), point_from(rng));
        let _ = (
            p.add(&q),
            p.subtract(&q),
            p.twice(),
            p.negate(),
            p.is_on_curve(),
        );
        let _ = (p.to_encoded(), p.to_hex_encoded(), p == q, p.is_infinity());
    });
    // Scalar multiplication costs about 70 us, so this is the slow one.
    run("ECPoint multiply, keys", 8, |rng| {
        let (p, k) = (point_from(rng), rng.big());
        let out = p.multiply(&k);
        assert!(out.is_infinity() || out.is_on_curve());
        let public = SM2::get_public_key(&k);
        assert!(public.is_infinity() || public.is_on_curve());
    });
}

#[test]
fn fuzz_sm2_verify() {
    let signature = SM2::sign("id", "message", D).unwrap();
    run("SM2::verify", 9, |rng| {
        let (sig, key) = (rng.mutated(&signature), rng.mutated(PUBLIC));
        let accepted = SM2::verify("id", &sig, "message", &key);
        let same = sig == signature && key.eq_ignore_ascii_case(PUBLIC);
        assert_eq!(accepted, same, "{sig} {key}");
        assert!(!SM2::verify(
            &rng.text(),
            &rng.text(),
            &rng.text(),
            &rng.text()
        ));
    });
}

#[test]
fn fuzz_sm2_sign_and_encrypt() {
    run("SM2::sign", 10, |rng| {
        let key = rng.mutated(D);
        // Most mutations are rejected before any curve work.
        if let Ok(sig) = SM2::sign("id", "m", &key) {
            assert_eq!(sig.len(), 129);
        }
        assert!(SM2::sign(&rng.text(), &rng.text(), &rng.text()).is_err() || rng.below(1) == 0);
    });
    run("SM2::encrypt", 11, |rng| {
        let key = rng.mutated(PUBLIC);
        let result = SM2::encrypt("m", &key);
        assert!(result.is_ok() == key.eq_ignore_ascii_case(PUBLIC), "{key}");
        assert!(SM2::encrypt(&rng.text(), &rng.text()).is_err() || rng.below(1) == 0);
    });
}

#[test]
fn fuzz_sm2_decrypt() {
    let ciphertext = SM2::encrypt("attack at dawn", PUBLIC).unwrap();
    run("SM2::decrypt", 12, |rng| {
        let (text, key) = (rng.mutated(&ciphertext), rng.mutated(D));
        let result = SM2::decrypt(&text, &key);
        let same = text == ciphertext && key.eq_ignore_ascii_case(D);
        assert_eq!(result.is_ok(), same, "{text}");
        assert_eq!(SM2::decrypt_bytes(&text, &key).is_ok(), same, "{text}");
        if let Ok(plain) = &result {
            assert_eq!(plain, "attack at dawn");
        }
        if let Err(message) = &result {
            assert!(!message.contains(D), "secret in error");
        }
        assert!(SM2::decrypt(&rng.text(), &rng.text()).is_err());
    });
}

#[test]
fn fuzz_key_exchange() {
    let (d_a, r_a_k) = (BigInt256::from_hex(D), BigInt256::new([5, 7, 9, 11]));
    let (d_b, r_b_k) = (
        BigInt256::new([13, 17, 19, 23]),
        BigInt256::new([29, 31, 37, 41]),
    );
    let p_a = SM2::get_public_key(&d_a);
    let r_a = SM2::get_public_key(&r_a_k);
    let p_b = SM2::get_public_key(&d_b);
    let r_b = SM2::get_public_key(&r_b_k);
    let b_ok = SM2::get_sb(16, &p_a, &r_a, &p_b, &d_b, &r_b, &r_b_k, "a", "b");
    let sb: Vec<u8> = b_ok.sb.as_ref().map(|s| hex_decode(s)).unwrap();
    let za = b_ok.za.clone().unwrap();
    let zb = b_ok.zb.clone().unwrap();
    let v = b_ok.v.clone().unwrap();

    run("SM2::get_sb, get_sa", 13, |rng| {
        let pick = |rng: &mut Rng, good: &ECPoint| {
            if rng.below(3) == 0 {
                point_from(rng)
            } else {
                good.clone()
            }
        };
        let (a1, a2, a3, a4) = (
            pick(rng, &p_a),
            pick(rng, &r_a),
            pick(rng, &p_b),
            pick(rng, &r_b),
        );
        let scalar = |rng: &mut Rng, good: &BigInt256| {
            if rng.below(3) == 0 { rng.big() } else { *good }
        };
        let (s1, s2) = (scalar(rng, &d_b), scalar(rng, &r_b_k));
        let len = [0usize, 1, 16, 33, 1 << 20, (1 << 20) + 1, usize::MAX][rng.below(7) as usize];
        // Skip the valid megabyte: it is slow and not malformed.
        let len = if len == 1 << 20 { 64 } else { len };
        let (ida, idb) = (rng.text(), rng.text());
        let b = SM2::get_sb(len, &a1, &a2, &a3, &s1, &a4, &s2, &ida, &idb);
        assert_eq!(b.success, b.kb.is_some());
        assert_eq!(b.success, b.message.is_none());
        let shape = [0usize, 1, 31, 32, 33][rng.below(5) as usize];
        let junk = rng.bytes(shape);
        let a = SM2::get_sa(len, &a3, &a4, &a1, &s1, &a2, &s2, &ida, &idb, &junk);
        assert!(!a.success, "random Sb accepted");
        assert!(a.ka.is_none());
        let _ = format!("{a:?} {b:?}");
    });
    run("SM2::check_sa", 14, |rng| {
        let shape = [0usize, 1, 31, 32, 33][rng.below(5) as usize];
        let (x, y, z) = (rng.bytes(shape), rng.bytes(shape), rng.bytes(shape));
        let (p, q, r) = (point_from(rng), point_from(rng), point_from(rng));
        assert!(!SM2::check_sa(&p, &x, &y, &q, &r, &z));
        // Valid shape and values with a wrong Sa.
        assert!(!SM2::check_sa(&v, &za, &zb, &r_a, &r_b, &rng.bytes(32)));
    });
    let _ = sb;
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn fuzz_sm3() {
    run("Sm3", 15, |rng| {
        let mut h = Sm3::new();
        let mut whole = Vec::new();
        for _ in 0..rng.below(4) {
            let len = rng.below(200) as usize;
            let part = rng.bytes(len);
            if rng.below(2) == 0 {
                h.update(&part);
            } else {
                for byte in &part {
                    h.update_byte(*byte);
                }
            }
            whole.extend_from_slice(&part);
        }
        h.finish();
        let mut other = Sm3::new();
        other.update(&whole).finish();
        assert_eq!(h.hash_bytes(), other.hash_bytes());
        assert_eq!(h.hash_hex_upper(), other.hash_hex_upper());
        other.update_str(&rng.text());
        let reread = other.clone();
        assert_eq!(reread.hash_bytes(), other.hash_bytes());
        other.finish().finish();
        assert_eq!(reread.hash_bytes(), other.hash_bytes());
    });
}

#[test]
fn fuzz_sm4() {
    let mut keyed = SM4::new();
    keyed.set_key(&[7; 16], &[9; 16]).unwrap();
    run("SM4::set_key", 16, |rng| {
        let mut sm4 = SM4::new();
        let (k, i) = (rng.below(40) as usize, rng.below(40) as usize);
        let (key, iv) = (rng.bytes(k), rng.bytes(i));
        assert_eq!(sm4.set_key(&key, &iv).is_ok(), k == 16 && i == 16);
        assert_eq!(sm4.encrypt("x").is_ok(), k == 16 && i == 16);
    });
    run("SM4::encrypt, round trip", 17, |rng| {
        let text = rng.text();
        let ciphertext = keyed.encrypt(&text).unwrap();
        assert_eq!(ciphertext.len() % 32, 0);
        assert_eq!(keyed.decrypt(&ciphertext).unwrap(), text);
        assert_eq!(keyed.decrypt_bytes(&ciphertext).unwrap(), text.as_bytes());
    });
    let sample = keyed
        .encrypt("attack at dawn, attack at dawn, attack")
        .unwrap();
    run("SM4::decrypt", 18, |rng| {
        let text = match rng.below(3) {
            0 => rng.mutated(&sample),
            1 => rng.text(),
            _ => {
                let blocks = rng.below(9) as usize;
                let raw = rng.bytes(blocks * 16);
                raw.iter().map(|b| format!("{b:02x}")).collect()
            }
        };
        // Only the plain-hex error and the single padding error may appear.
        if let Err(error) = keyed.decrypt(&text) {
            let message = error.to_string();
            assert!(
                message == "Invalid padding" || message == "Invalid hex string",
                "{message}"
            );
        }
        let _ = SM4::new().decrypt(&text).unwrap_err();
        if let Ok(bytes) = keyed.decrypt_bytes(&text) {
            assert!(bytes.len() < text.len());
        }
    });
}

#[test]
fn round_trip_properties() {
    run("SM2 key/sign/encrypt round trip", 19, |rng| {
        // One in a hundred: these are the slow, fully valid paths.
        if rng.below(100) != 0 {
            return;
        }
        let (private, public) = SM2::gen_key_pair();
        let id: String = rng.text().chars().take(100).collect();
        let message = rng.text();
        let signature = SM2::sign(&id, &message, &private).unwrap();
        assert!(SM2::verify(&id, &signature, &message, &public));
        assert!(!SM2::verify(
            &id,
            &signature,
            &format!("{message}."),
            &public
        ));
        let plain = if message.is_empty() {
            "x".to_string()
        } else {
            message
        };
        let ciphertext = SM2::encrypt(&plain, &public).unwrap();
        assert_eq!(SM2::decrypt(&ciphertext, &private).unwrap(), plain);
    });
}
