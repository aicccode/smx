//! Asserts every case of the shared, independently generated vectors in
//! `testvectors/security-vectors.json`, plus the rules that all language ports must share.

use gm_rust::sm2::SM2;
use gm_rust::sm2::bigint256::BigInt256;
use gm_rust::sm2::point::ECPoint;
use gm_rust::sm3::Sm3;
use gm_rust::sm4::SM4;
use std::collections::BTreeMap;

// -------------------------------------------------- a small JSON reader, for this test only

#[derive(Debug, Clone)]
enum Json {
    Null,
    Bool,
    Number(f64),
    Text(String),
    List(Vec<Json>),
    Map(BTreeMap<String, Json>),
}

impl Json {
    fn get(&self, key: &str) -> &Json {
        match self {
            Json::Map(map) => map.get(key).unwrap_or_else(|| panic!("missing {key}")),
            other => panic!("not an object: {other:?}"),
        }
    }

    fn text(&self, key: &str) -> &str {
        match self.get(key) {
            Json::Text(text) => text,
            other => panic!("{key} is not text: {other:?}"),
        }
    }

    fn list(&self, key: &str) -> &[Json] {
        match self.get(key) {
            Json::List(list) => list,
            other => panic!("{key} is not a list: {other:?}"),
        }
    }

    fn number(&self) -> usize {
        match self {
            Json::Number(n) => *n as usize,
            other => panic!("not a number: {other:?}"),
        }
    }
}

struct Parser<'a> {
    text: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn space(&mut self) {
        while self.text[self.at].is_ascii_whitespace() {
            self.at += 1;
        }
    }

    fn value(&mut self) -> Json {
        self.space();
        match self.text[self.at] {
            b'{' => self.map(),
            b'[' => self.list(),
            b'"' => Json::Text(self.string()),
            b't' | b'f' => {
                self.at += if self.text[self.at] == b't' { 4 } else { 5 };
                Json::Bool
            }
            b'n' => {
                self.at += 4;
                Json::Null
            }
            _ => {
                let start = self.at;
                while b"+-.eE0123456789".contains(&self.text[self.at]) {
                    self.at += 1;
                }
                let digits = core::str::from_utf8(&self.text[start..self.at]).unwrap();
                Json::Number(digits.parse().unwrap())
            }
        }
    }

    fn string(&mut self) -> String {
        self.at += 1;
        let mut out = Vec::new();
        loop {
            match self.text[self.at] {
                b'"' => {
                    self.at += 1;
                    return String::from_utf8(out).unwrap();
                }
                b'\\' => {
                    self.at += 1;
                    match self.text[self.at] {
                        b'u' => {
                            let hex = &self.text[self.at + 1..self.at + 5];
                            let code = u32::from_str_radix(core::str::from_utf8(hex).unwrap(), 16);
                            let c = char::from_u32(code.unwrap()).unwrap();
                            out.extend_from_slice(c.to_string().as_bytes());
                            self.at += 5;
                        }
                        other => {
                            out.push(match other {
                                b'n' => b'\n',
                                b't' => b'\t',
                                b'r' => b'\r',
                                literal => literal,
                            });
                            self.at += 1;
                        }
                    }
                }
                byte => {
                    out.push(byte);
                    self.at += 1;
                }
            }
        }
    }

    fn list(&mut self) -> Json {
        self.at += 1;
        let mut items = Vec::new();
        loop {
            self.space();
            match self.text[self.at] {
                b']' => {
                    self.at += 1;
                    return Json::List(items);
                }
                b',' => self.at += 1,
                _ => items.push(self.value()),
            }
        }
    }

    fn map(&mut self) -> Json {
        self.at += 1;
        let mut items = BTreeMap::new();
        loop {
            self.space();
            match self.text[self.at] {
                b'}' => {
                    self.at += 1;
                    return Json::Map(items);
                }
                b',' => self.at += 1,
                _ => {
                    let key = self.string();
                    self.space();
                    self.at += 1; // the colon
                    items.insert(key, self.value());
                }
            }
        }
    }
}

fn vectors() -> Json {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testvectors/security-vectors.json"
    );
    let text = std::fs::read(path).expect("shared vectors");
    Parser { text: &text, at: 0 }.value()
}

fn unhex(h: &str) -> Vec<u8> {
    assert!(h.len() % 2 == 0);
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

// -------------------------------------------------- SM2

#[test]
fn valid_sm2_values_are_accepted() {
    let all = vectors();
    let v = all.get("sm2");
    let (d, public) = (v.text("private_key"), v.text("public_key"));
    let derived = SM2::get_public_key(&BigInt256::from_hex(d));
    assert_eq!(derived.to_hex_encoded(), public);
    assert_eq!(ECPoint::from_hex_encoded(public), derived);

    let signature = format!("{}h{}", v.text("r"), v.text("s"));
    let (id, message) = (v.text("user_id"), v.text("message"));
    assert!(SM2::verify(id, &signature, message, public));
    let fresh = SM2::sign(id, message, d).unwrap();
    assert!(SM2::verify(id, &fresh, message, public));

    assert_eq!(
        SM2::decrypt(v.text("ciphertext"), d).unwrap(),
        v.text("plaintext")
    );

    // The largest valid private key works in every operation.
    let top = v.text("n_minus_2_is_max_valid_private_key");
    let top_public = SM2::get_public_key(&BigInt256::from_hex(top));
    assert!(top_public.is_on_curve());
    let top_public = top_public.to_hex_encoded();
    let top_signature = SM2::sign(id, message, top).unwrap();
    assert!(SM2::verify(id, &top_signature, message, &top_public));
    let top_ct = SM2::encrypt("x", &top_public).unwrap();
    assert_eq!(SM2::decrypt(&top_ct, top).unwrap(), "x");
}

#[test]
fn invalid_public_keys_are_rejected_everywhere() {
    let all = vectors();
    let v = all.get("sm2");
    let (id, message, d) = (v.text("user_id"), v.text("message"), v.text("private_key"));
    let signature = format!("{}h{}", v.text("r"), v.text("s"));
    let d_big = BigInt256::from_hex(d);
    let good = ECPoint::from_hex_encoded(v.text("public_key"));
    let sb = [0u8; 32];
    for case in v.list("invalid_public_keys") {
        let (name, value) = (case.text("name"), case.text("value"));
        assert!(ECPoint::from_hex_encoded(value).is_infinity(), "{name}");
        assert!(SM2::decode_point(value).is_infinity(), "{name}");
        assert!(ECPoint::try_from_hex_encoded(value).is_none(), "{name}");
        assert!(SM2::encrypt("hello", value).is_err(), "{name}");
        assert!(!SM2::verify(id, &signature, message, value), "{name}");

        // Key exchange, in each peer position, as parsed and as the raw coordinates would be.
        let bad = ECPoint::from_hex_encoded(value);
        for position in 0..4 {
            let mut p = [&good, &good, &good, &good];
            p[position] = &bad;
            let b = SM2::get_sb(16, p[0], p[1], p[2], &d_big, p[3], &d_big, "a", "b");
            assert!(
                !b.success && b.sb.is_none() && b.kb.is_none(),
                "{name} {position}"
            );
            let a = SM2::get_sa(16, p[0], p[1], p[2], &d_big, p[3], &d_big, "a", "b", &sb);
            assert!(
                !a.success && a.sa.is_none() && a.ka.is_none(),
                "{name} {position}"
            );
        }

        // The same point built by struct literal, without going through the parser.
        if value.len() == 130 && value.is_ascii() && value.bytes().all(|c| c.is_ascii_hexdigit()) {
            let raw = ECPoint {
                x: gm_rust::sm2::fp::FpElement {
                    value: BigInt256::try_from_hex(&value[2..66]).unwrap(),
                },
                y: gm_rust::sm2::fp::FpElement {
                    value: BigInt256::try_from_hex(&value[66..]).unwrap(),
                },
                infinity: false,
            };
            if value.starts_with("04") {
                assert!(!raw.is_on_curve(), "{name}");
                assert!(raw.multiply(&d_big).is_infinity(), "{name}");
                let b = SM2::get_sb(16, &raw, &good, &good, &d_big, &good, &d_big, "a", "b");
                assert!(!b.success, "{name}");
            }
        }
    }
}

#[test]
fn invalid_private_keys_are_rejected_everywhere() {
    let all = vectors();
    let v = all.get("sm2");
    let (id, message) = (v.text("user_id"), v.text("message"));
    let ciphertext = v.text("ciphertext");
    let good = ECPoint::from_hex_encoded(v.text("public_key"));
    let good_d = BigInt256::from_hex(v.text("private_key"));
    for case in v.list("invalid_private_keys") {
        let (name, value) = (case.text("name"), case.text("value"));
        assert!(SM2::sign(id, message, value).is_err(), "{name}");
        assert!(SM2::decrypt(ciphertext, value).is_err(), "{name}");
        let parsed = BigInt256::from_hex(value);
        assert!(SM2::get_public_key(&parsed).is_infinity(), "{name}");
        let b = SM2::get_sb(16, &good, &good, &good, &parsed, &good, &good_d, "a", "b");
        assert!(!b.success, "{name} dB");
        let b = SM2::get_sb(16, &good, &good, &good, &good_d, &good, &parsed, "a", "b");
        assert!(!b.success, "{name} rb");
        let a = SM2::get_sa(
            16, &good, &good, &good, &parsed, &good, &good_d, "a", "b", &[0; 32],
        );
        assert!(!a.success, "{name} dA");
        let a = SM2::get_sa(
            16, &good, &good, &good, &good_d, &good, &parsed, "a", "b", &[0; 32],
        );
        assert!(!a.success, "{name} ra");
    }
}

#[test]
fn invalid_signatures_are_rejected() {
    let all = vectors();
    let v = all.get("sm2");
    let (id, message, public) = (v.text("user_id"), v.text("message"), v.text("public_key"));
    for case in v.list("invalid_signatures") {
        let signature = format!("{}h{}", case.text("r"), case.text("s"));
        assert!(
            !SM2::verify(id, &signature, message, public),
            "{}",
            case.text("name")
        );
    }
    let r_s = format!("{}h{}", v.text("r"), v.text("s"));
    for malformed in [
        String::new(),
        "h".to_string(),
        r_s.replace('h', ""),
        r_s.replace('h', "hh"),
        format!("{r_s}h"),
        format!("h{r_s}"),
        format!("0x{r_s}"),
        format!("{r_s}00"),
    ] {
        assert!(!SM2::verify(id, &malformed, message, public), "{malformed}");
    }
}

#[test]
fn invalid_ciphertexts_are_rejected() {
    let all = vectors();
    let v = all.get("sm2");
    let d = v.text("private_key");
    for case in v.list("invalid_ciphertexts") {
        assert!(
            SM2::decrypt(case.text("value"), d).is_err(),
            "{}",
            case.text("name")
        );
    }
}

#[test]
fn user_id_length_limit() {
    let all = vectors();
    let v = all.get("sm2");
    let (d, public) = (v.text("private_key"), v.text("public_key"));
    let max = v.get("user_id_max_bytes").number();
    let first_invalid = v.get("user_id_first_invalid_bytes").number();
    let good = ECPoint::from_hex_encoded(public);
    let d_big = BigInt256::from_hex(d);

    let longest = "x".repeat(max);
    let signature = SM2::sign(&longest, "m", d).unwrap();
    assert!(SM2::verify(&longest, &signature, "m", public));
    assert!(
        SM2::get_sb(
            16, &good, &good, &good, &d_big, &good, &d_big, &longest, "b"
        )
        .success
    );

    // ENTL would have wrapped to 0 here, also making the ID collide with the empty one.
    for length in [first_invalid, first_invalid + 1, 16384, 65536, 70000] {
        let too_long = "x".repeat(length);
        assert!(SM2::sign(&too_long, "m", d).is_err(), "{length}");
        assert!(!SM2::verify(&too_long, &signature, "m", public), "{length}");
        let b = SM2::get_sb(
            16, &good, &good, &good, &d_big, &good, &d_big, &too_long, "b",
        );
        assert!(!b.success, "{length}");
        let b = SM2::get_sb(
            16, &good, &good, &good, &d_big, &good, &d_big, "a", &too_long,
        );
        assert!(!b.success, "{length}");
        let a = SM2::get_sa(
            16, &good, &good, &good, &d_big, &good, &d_big, &too_long, "b", &[0; 32],
        );
        assert!(!a.success, "{length}");
    }
}

#[test]
fn key_exchange_bounds() {
    let all = vectors();
    let v = all.get("sm2");
    let d_big = BigInt256::from_hex(v.text("private_key"));
    let good = ECPoint::from_hex_encoded(v.text("public_key"));
    let exchange = |len: usize, sb: &[u8]| {
        (
            SM2::get_sb(len, &good, &good, &good, &d_big, &good, &d_big, "a", "b"),
            SM2::get_sa(
                len, &good, &good, &good, &d_big, &good, &d_big, "a", "b", sb,
            ),
        )
    };
    for len in [0usize, (1 << 20) + 1, usize::MAX, usize::MAX / 2, 1 << 40] {
        let (b, a) = exchange(len, &[0; 32]);
        assert!(!b.success && b.kb.is_none(), "{len}");
        assert!(!a.success && a.ka.is_none(), "{len}");
    }
    let (b, _) = exchange(1 << 20, &[]);
    assert!(b.success);
    assert_eq!(b.kb.as_ref().unwrap().len(), 2 << 20);

    // Sb and Sa of the wrong size, including empty.
    let (b, _) = exchange(16, &[]);
    let sb = unhex(b.sb.as_ref().unwrap());
    let (za, zb) = (b.za.as_ref().unwrap(), b.zb.as_ref().unwrap());
    for short in [&[][..], &sb[..1], &sb[..31]] {
        assert!(!exchange(16, short).1.success);
        assert!(!SM2::check_sa(
            b.v.as_ref().unwrap(),
            za,
            zb,
            &good,
            &good,
            short
        ));
    }
    let (_, a) = exchange(16, &sb);
    assert!(a.success);
    let sa = unhex(a.sa.as_ref().unwrap());
    let v_point = b.v.as_ref().unwrap();
    assert!(SM2::check_sa(v_point, za, zb, &good, &good, &sa));
    assert!(!SM2::check_sa(v_point, &[], zb, &good, &good, &sa));
    assert!(!SM2::check_sa(v_point, za, &[], &good, &good, &sa));
    assert!(!SM2::check_sa(
        &ECPoint::infinity(),
        za,
        zb,
        &good,
        &good,
        &sa
    ));
    assert!(!SM2::check_sa(
        v_point,
        za,
        zb,
        &ECPoint::infinity(),
        &good,
        &sa
    ));
}

/// V and the coordinates are fixed-width: many exchanges have leading zero bytes in them.
#[test]
fn exchanges_with_leading_zero_coordinates_work() {
    let mut seen_leading_zero = 0;
    for seed in 1u64..400 {
        let scalar = |salt: u64| {
            BigInt256::new([
                seed.wrapping_mul(0x9E37_79B9).wrapping_add(salt),
                salt,
                seed,
                1,
            ])
        };
        let (d_a, ra, d_b, rb) = (scalar(1), scalar(2), scalar(3), scalar(4));
        let (p_a, r_a) = (SM2::get_public_key(&d_a), SM2::get_public_key(&ra));
        let (p_b, r_b) = (SM2::get_public_key(&d_b), SM2::get_public_key(&rb));
        let b = SM2::get_sb(32, &p_a, &r_a, &p_b, &d_b, &r_b, &rb, "a", "b");
        assert!(b.success);
        let v_point = b.v.as_ref().unwrap();
        if v_point.x.to_be_bytes()[0] == 0 || v_point.y.to_be_bytes()[0] == 0 {
            seen_leading_zero += 1;
        }
        let a = SM2::get_sa(
            32,
            &p_b,
            &r_b,
            &p_a,
            &d_a,
            &r_a,
            &ra,
            "a",
            "b",
            &unhex(b.sb.as_ref().unwrap()),
        );
        assert!(a.success, "seed {seed}");
        assert_eq!(a.ka, b.kb);
    }
    assert!(
        seen_leading_zero > 0,
        "the case this test is for did not occur"
    );
}

// -------------------------------------------------- SM3

/// The two long messages; run with `--release -- --ignored`.
#[test]
#[ignore = "hashes 1.5 GiB; run with --release -- --ignored"]
fn sm3_long_vectors() {
    let all = vectors();
    let v = all.get("sm3");
    let chunk = vec![0u8; 1 << 20];
    for (mib, name) in [(512, "zeros_512_mib"), (1024, "zeros_1024_mib")] {
        let mut h = Sm3::new();
        for _ in 0..mib {
            h.update(&chunk);
        }
        h.finish();
        assert_eq!(h.hash_hex_upper().to_lowercase(), v.text(name));
    }
}

// -------------------------------------------------- SM4

#[test]
fn sm4_vectors() {
    let all = vectors();
    let v = all.get("sm4");
    let (key, iv) = (unhex(v.text("key")), unhex(v.text("iv")));
    let mut sm4 = SM4::new();
    sm4.set_key(&key, &iv).unwrap();
    assert_eq!(
        sm4.encrypt(v.text("valid_padded_plaintext")).unwrap(),
        v.text("valid_padded_ciphertext")
    );
    assert_eq!(
        sm4.decrypt(v.text("valid_padded_ciphertext")).unwrap(),
        v.text("valid_padded_plaintext")
    );
    // A whole block of padding decrypts to the empty string.
    assert_eq!(
        sm4.decrypt(v.text("valid_full_padding_block_ciphertext"))
            .unwrap(),
        ""
    );
    assert_eq!(
        sm4.encrypt("").unwrap(),
        v.text("valid_full_padding_block_ciphertext")
    );

    for length in v.list("invalid_key_lengths_bytes") {
        let mut other = SM4::new();
        assert!(other.set_key(&vec![1u8; length.number()], &iv).is_err());
        assert!(other.encrypt("x").is_err());
    }
    for length in v.list("invalid_iv_lengths_bytes") {
        let mut other = SM4::new();
        assert!(other.set_key(&key, &vec![1u8; length.number()]).is_err());
        assert!(other.encrypt("x").is_err());
    }

    // One error for all of these.
    let mut messages = Vec::new();
    for case in v.list("invalid_paddings") {
        messages.push(sm4.decrypt(case.text("value")).unwrap_err().to_string());
    }
    for length in v.list("invalid_ciphertext_lengths_bytes") {
        let text = "00".repeat(length.number());
        messages.push(sm4.decrypt(&text).unwrap_err().to_string());
    }
    assert!(messages.len() >= 10);
    assert!(messages.iter().all(|m| *m == messages[0]), "{messages:?}");
}

// -------------------------------------------------- secrets in output

#[test]
fn debug_output_shows_no_secrets() {
    let d = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
    let big = BigInt256::from_hex(d);
    let debug = format!("{big:?}");
    assert!(
        !debug.contains("3945") && !debug.contains(&big.limbs[0].to_string()),
        "{debug}"
    );

    let (p, r) = (
        SM2::get_public_key(&big),
        SM2::get_public_key(&BigInt256::new([5, 0, 0, 0])),
    );
    let result = SM2::get_sb(
        16,
        &p,
        &r,
        &p,
        &big,
        &r,
        &BigInt256::new([5, 0, 0, 0]),
        "a",
        "b",
    );
    assert!(result.success);
    let debug = format!("{result:?}");
    assert!(!debug.contains(result.kb.as_ref().unwrap()), "{debug}");
    let v_hex = result.v.as_ref().unwrap().to_hex_encoded();
    assert!(!debug.contains(&v_hex[2..66]), "{debug}");

    for error in [
        SM2::sign("x".repeat(9000).as_str(), "m", d).unwrap_err(),
        SM2::decrypt("zz", d).unwrap_err(),
        SM2::decrypt(&"0".repeat(232), d).unwrap_err(),
    ] {
        assert!(!error.contains(d), "{error}");
    }
}
