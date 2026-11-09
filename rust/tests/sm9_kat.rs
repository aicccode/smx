//! SM9 known-answer tests: every vector of `testvectors/sm9-vectors.json` (GB/T 38635.5 worked
//! examples plus extra vectors from the independent reference `testvectors/sm9_ref.py`), and
//! every invalid point and scalar listed there.

use gm_rust::sm9::{SM9, SM9_HID_ENCRYPT, SM9_HID_EXCHANGE, SM9_HID_SIGN, SM9EncryptMode};

const VECTORS: &str = include_str!("../../testvectors/sm9-vectors.json");

/// Just enough JSON for the vector file.
#[derive(Debug)]
enum Json {
    Obj(Vec<(String, Json)>),
    Arr(Vec<Json>),
    Str(String),
    Num(i64),
    Other,
}

impl Json {
    fn get(&self, key: &str) -> &Json {
        match self {
            Json::Obj(fields) => fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("missing key {key}")),
            _ => panic!("not an object"),
        }
    }

    fn s(&self, key: &str) -> &str {
        match self.get(key) {
            Json::Str(s) => s,
            other => panic!("{key} is not a string: {other:?}"),
        }
    }

    fn n(&self, key: &str) -> i64 {
        match self.get(key) {
            Json::Num(n) => *n,
            other => panic!("{key} is not a number: {other:?}"),
        }
    }

    fn arr(&self, key: &str) -> &[Json] {
        match self.get(key) {
            Json::Arr(items) => items,
            other => panic!("{key} is not an array: {other:?}"),
        }
    }
}

struct Parser<'a> {
    text: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn skip_ws(&mut self) {
        while self.pos < self.text.len() && self.text[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn expect(&mut self, c: u8) {
        self.skip_ws();
        assert_eq!(self.text[self.pos], c, "at {}", self.pos);
        self.pos += 1;
    }

    fn string(&mut self) -> String {
        self.expect(b'"');
        let mut out = Vec::new();
        loop {
            let c = self.text[self.pos];
            self.pos += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.text[self.pos];
                    self.pos += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hex = std::str::from_utf8(&self.text[self.pos..self.pos + 4]);
                            let code = u32::from_str_radix(hex.unwrap(), 16).unwrap();
                            self.pos += 4;
                            let ch = char::from_u32(code).expect("no surrogates in the file");
                            out.extend_from_slice(ch.to_string().as_bytes());
                        }
                        other => out.push(other),
                    }
                }
                other => out.push(other),
            }
        }
        String::from_utf8(out).unwrap()
    }

    fn value(&mut self) -> Json {
        self.skip_ws();
        match self.text[self.pos] {
            b'{' => {
                self.pos += 1;
                let mut fields = Vec::new();
                self.skip_ws();
                if self.text[self.pos] == b'}' {
                    self.pos += 1;
                    return Json::Obj(fields);
                }
                loop {
                    let key = self.string();
                    self.expect(b':');
                    fields.push((key, self.value()));
                    self.skip_ws();
                    let c = self.text[self.pos];
                    self.pos += 1;
                    if c == b'}' {
                        return Json::Obj(fields);
                    }
                    assert_eq!(c, b',');
                }
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.skip_ws();
                if self.text[self.pos] == b']' {
                    self.pos += 1;
                    return Json::Arr(items);
                }
                loop {
                    items.push(self.value());
                    self.skip_ws();
                    let c = self.text[self.pos];
                    self.pos += 1;
                    if c == b']' {
                        return Json::Arr(items);
                    }
                    assert_eq!(c, b',');
                }
            }
            b'"' => Json::Str(self.string()),
            b'-' | b'0'..=b'9' => {
                let start = self.pos;
                while self.pos < self.text.len()
                    && (self.text[self.pos] == b'-' || self.text[self.pos].is_ascii_digit())
                {
                    self.pos += 1;
                }
                let digits = std::str::from_utf8(&self.text[start..self.pos]).unwrap();
                Json::Num(digits.parse().unwrap())
            }
            _ => {
                for word in ["true", "false", "null"] {
                    if self.text[self.pos..].starts_with(word.as_bytes()) {
                        self.pos += word.len();
                        return Json::Other;
                    }
                }
                panic!("bad JSON at {}", self.pos)
            }
        }
    }
}

fn vectors() -> Json {
    let mut parser = Parser {
        text: VECTORS.as_bytes(),
        pos: 0,
    };
    parser.value()
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn hid(v: &Json) -> u8 {
    v.n("hid") as u8
}

#[test]
fn hids_match_the_file() {
    let params = vectors();
    let params = params.get("params");
    assert_eq!(params.n("hid_sign"), i64::from(SM9_HID_SIGN));
    assert_eq!(params.n("hid_exchange"), i64::from(SM9_HID_EXCHANGE));
    assert_eq!(params.n("hid_encrypt"), i64::from(SM9_HID_ENCRYPT));
}

#[test]
fn standard_signature() {
    let all = vectors();
    let v = all.get("standard").get("sign");
    let ks = v.s("master_private_key");
    assert_eq!(
        SM9::sign_master_public_key(ks).unwrap(),
        v.s("master_public_key")
    );
    let ds = SM9::gen_sign_user_key_with_hid(ks, v.s("user_id"), hid(v)).unwrap();
    assert_eq!(ds, v.s("user_private_key"));
    assert_eq!(
        SM9::pairing_hex(all.get("params").s("P1"), v.s("master_public_key")).unwrap(),
        v.s("pairing_g")
    );
    let sig = SM9::sign_with_rand(v.s("message"), &ds, v.s("master_public_key"), v.s("r"));
    assert_eq!(sig.unwrap(), v.s("signature"));
    assert!(SM9::verify_with_hid(
        v.s("message"),
        v.s("signature"),
        v.s("user_id"),
        v.s("master_public_key"),
        hid(v)
    ));
}

#[test]
fn extra_signatures() {
    let all = vectors();
    let extra = all.get("extra");
    let ks = extra.s("sign_master_private_key");
    let ppub = extra.s("sign_master_public_key");
    assert_eq!(SM9::sign_master_public_key(ks).unwrap(), ppub);
    for v in extra.arr("sign") {
        let id = v.s("user_id");
        let ds = SM9::gen_sign_user_key(ks, id).unwrap();
        assert_eq!(ds, v.s("user_private_key"), "{id}");
        let msg = unhex(v.s("message_hex"));
        let sig = SM9::sign_with_rand(&msg, &ds, ppub, v.s("r")).unwrap();
        assert_eq!(sig, v.s("signature"), "{id}");
        assert!(SM9::verify(&msg, &sig, id, ppub));
    }
}

#[test]
fn standard_key_exchange() {
    let all = vectors();
    check_exchange(all.get("standard").get("exchange"), None);
}

#[test]
fn extra_key_exchanges() {
    let all = vectors();
    let extra = all.get("extra");
    let ke = extra.s("enc_master_private_key");
    let ppub = extra.s("enc_master_public_key");
    for v in extra.arr("exchange") {
        check_exchange(v, Some((ke, ppub)));
    }
}

fn check_exchange(v: &Json, master: Option<(&str, &str)>) {
    let (ke, ppub) =
        master.unwrap_or_else(|| (v.s("master_private_key"), v.s("master_public_key")));
    let hid = if master.is_some() {
        SM9_HID_EXCHANGE
    } else {
        hid(v)
    };
    assert_eq!(SM9::enc_master_public_key(ke).unwrap(), ppub);
    let (id_a, id_b) = (v.s("id_a"), v.s("id_b"));
    let de_a = SM9::gen_enc_user_key_with_hid(ke, id_a, hid).unwrap();
    let de_b = SM9::gen_enc_user_key_with_hid(ke, id_b, hid).unwrap();
    assert_eq!(de_a, v.s("user_private_key_a"));
    assert_eq!(de_b, v.s("user_private_key_b"));
    let key_len = v.n("key_len") as usize;

    let (r_a, big_r_a) = SM9::exchange_init_with_rand(id_b, ppub, hid, v.s("r_a")).unwrap();
    let (r_b, big_r_b) = SM9::exchange_init_with_rand(id_a, ppub, hid, v.s("r_b")).unwrap();
    assert_eq!(r_a, v.s("r_a"));
    assert_eq!(r_b, v.s("r_b"));
    assert_eq!(big_r_a, v.s("R_a"));
    assert_eq!(big_r_b, v.s("R_b"));

    let b = SM9::exchange_respond(key_len, id_a, id_b, ppub, &de_b, &r_b, &big_r_b, &big_r_a);
    assert!(b.success, "{:?}", b.message);
    assert_eq!(b.shared_key.as_deref(), Some(v.s("shared_key")));
    assert_eq!(b.s_b.as_deref(), Some(v.s("s_b")));
    assert_eq!(b.s_2.as_deref(), Some(v.s("s_a")));

    let a = SM9::exchange_confirm(
        key_len,
        id_a,
        id_b,
        ppub,
        &de_a,
        &r_a,
        &big_r_a,
        &big_r_b,
        v.s("s_b"),
    );
    assert!(a.success, "{:?}", a.message);
    assert_eq!(a.shared_key.as_deref(), Some(v.s("shared_key")));
    assert_eq!(a.s_a.as_deref(), Some(v.s("s_a")));
    assert!(SM9::exchange_check(b.s_2.as_deref().unwrap(), v.s("s_a")));
}

fn check_encapsulation(v: &Json, ke: &str, ppub: &str, hid: u8) {
    let id = v.s("user_id");
    let de = SM9::gen_enc_user_key_with_hid(ke, id, hid).unwrap();
    assert_eq!(de, v.s("user_private_key"), "{id}");
    let key_len = v.n("key_len") as usize;
    let (key, c) = SM9::encapsulate_with_rand(id, ppub, key_len, hid, v.s("r")).unwrap();
    assert_eq!(key, v.s("key"), "{id}");
    assert_eq!(c, v.s("ciphertext"), "{id}");
    assert_eq!(SM9::decapsulate(&c, id, &de, key_len).unwrap(), key);
}

#[test]
fn standard_encapsulation() {
    let all = vectors();
    let v = all.get("standard").get("encapsulate");
    let ke = v.s("master_private_key");
    assert_eq!(
        SM9::enc_master_public_key(ke).unwrap(),
        v.s("master_public_key")
    );
    check_encapsulation(v, ke, v.s("master_public_key"), hid(v));
}

#[test]
fn extra_encapsulations() {
    let all = vectors();
    let extra = all.get("extra");
    for v in extra.arr("encapsulate") {
        check_encapsulation(
            v,
            extra.s("enc_master_private_key"),
            extra.s("enc_master_public_key"),
            SM9_HID_ENCRYPT,
        );
    }
}

fn check_encryption(v: &Json, plaintext: &[u8], ke: &str, ppub: &str, hid: u8) {
    let id = v.s("user_id");
    let de = SM9::gen_enc_user_key_with_hid(ke, id, hid).unwrap();
    assert_eq!(de, v.s("user_private_key"), "{id}");
    for (mode, key) in [
        (SM9EncryptMode::Stream, "ciphertext_stream"),
        (SM9EncryptMode::Sm4, "ciphertext_sm4"),
    ] {
        let c = SM9::encrypt_with_rand(plaintext, id, ppub, hid, mode, v.s("r")).unwrap();
        assert_eq!(c, v.s(key), "{id} {mode:?}");
        assert_eq!(SM9::decrypt_bytes(&c, id, &de, mode).unwrap(), plaintext);
    }
}

#[test]
fn standard_encryption() {
    let all = vectors();
    let v = all.get("standard").get("encrypt");
    let ke = v.s("master_private_key");
    let ppub = v.s("master_public_key");
    assert_eq!(SM9::enc_master_public_key(ke).unwrap(), ppub);
    check_encryption(v, v.s("plaintext").as_bytes(), ke, ppub, hid(v));
    let de = v.s("user_private_key");
    let text = SM9::decrypt(
        v.s("ciphertext_sm4"),
        v.s("user_id"),
        de,
        SM9EncryptMode::Sm4,
    );
    assert_eq!(text.unwrap(), v.s("plaintext"));
}

#[test]
fn extra_encryptions() {
    let all = vectors();
    let extra = all.get("extra");
    for v in extra.arr("encrypt") {
        check_encryption(
            v,
            &unhex(v.s("plaintext_hex")),
            extra.s("enc_master_private_key"),
            extra.s("enc_master_public_key"),
            SM9_HID_ENCRYPT,
        );
    }
}

#[test]
fn invalid_points_are_rejected() {
    let all = vectors();
    let std_sign = all.get("standard").get("sign");
    let std_enc = all.get("standard").get("encrypt");
    let sign_ppub = std_sign.s("master_public_key");
    let ds = std_sign.s("user_private_key");
    let sig = std_sign.s("signature");
    let msg = std_sign.s("message");
    let enc_ppub = std_enc.s("master_public_key");
    let de = std_enc.s("user_private_key");
    let ct = std_enc.s("ciphertext_stream");
    let invalid = all.get("invalid_points");

    for p in invalid.arr("g1") {
        let (name, value) = (p.s("name"), p.s("value"));
        // As an encryption master public key.
        assert!(
            SM9::encrypt("m", "Bob", value, SM9EncryptMode::Stream).is_err(),
            "{name}"
        );
        assert!(SM9::encapsulate("Bob", value, 32).is_err(), "{name}");
        assert!(SM9::exchange_init("Bob", value).is_err(), "{name}");
        // As a signing user key.
        assert!(SM9::sign(msg, value, sign_ppub).is_err(), "{name}");
        // As the S of a signature.
        let forged = format!("{}{}", &sig[..64], value);
        assert!(!SM9::verify(msg, &forged, "Alice", sign_ppub), "{name}");
        // As a KEM ciphertext and as C1.
        assert!(SM9::decapsulate(value, "Bob", de, 32).is_err(), "{name}");
        let forged = format!("{}{}", value, &ct[130..]);
        assert!(SM9::decrypt_bytes(&forged, "Bob", de, SM9EncryptMode::Stream).is_err());
        // As R_a and R_b in key exchange.
        let r = "00000000000000000000000000000000000000000000000000000000000000ab";
        let p_ok = SM9::exchange_init("Bob", enc_ppub).unwrap().1;
        let resp = SM9::exchange_respond(16, "A", "B", enc_ppub, de, r, &p_ok, value);
        assert!(!resp.success, "{name}");
        let resp = SM9::exchange_respond(16, "A", "B", enc_ppub, de, r, value, &p_ok);
        assert!(!resp.success, "{name}");
    }

    for p in invalid.arr("g2") {
        let (name, value) = (p.s("name"), p.s("value"));
        // As a signing master public key.
        assert!(!SM9::verify(msg, sig, "Alice", value), "{name}");
        assert!(SM9::sign(msg, ds, value).is_err(), "{name}");
        // As an encryption user key.
        assert!(SM9::decrypt_bytes(ct, "Bob", value, SM9EncryptMode::Stream).is_err());
        assert!(
            SM9::decapsulate(&ct[..130], "Bob", value, 32).is_err(),
            "{name}"
        );
        let r = "00000000000000000000000000000000000000000000000000000000000000ab";
        let p_ok = SM9::exchange_init("Bob", enc_ppub).unwrap().1;
        let resp = SM9::exchange_respond(16, "A", "B", enc_ppub, value, r, &p_ok, &p_ok);
        assert!(!resp.success, "{name}");
        assert!(SM9::pairing_hex(all.get("params").s("P1"), value).is_none());
    }
}

#[test]
fn invalid_scalars_are_rejected() {
    let all = vectors();
    let enc_ppub = all.get("standard").get("encrypt").s("master_public_key");
    for s in all.arr("invalid_scalars") {
        let (name, value) = (s.s("name"), s.s("value"));
        assert!(SM9::sign_master_public_key(value).is_err(), "{name}");
        assert!(SM9::enc_master_public_key(value).is_err(), "{name}");
        assert!(SM9::gen_sign_user_key(value, "Alice").is_err(), "{name}");
        assert!(SM9::gen_enc_user_key(value, "Bob").is_err(), "{name}");
        assert!(SM9::exchange_init_with_rand("Bob", enc_ppub, 2, value).is_err());
        assert!(SM9::encapsulate_with_rand("Bob", enc_ppub, 16, 3, value).is_err());
    }
    let max = all.s("max_valid_master_private_key");
    assert!(SM9::sign_master_public_key(max).is_ok());
    assert!(SM9::enc_master_public_key(max).is_ok());
    assert!(SM9::sign_master_public_key(&max.to_uppercase()).is_ok());
}
