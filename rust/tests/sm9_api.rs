//! SM9 behaviour beyond the vectors: random round trips, tampering, wrong identities, keys and
//! modes, input spelling rules and key exchange mismatches.

use gm_rust::sm9::{SM9, SM9_HID_ENCRYPT, SM9_HID_EXCHANGE, SM9EncryptMode};

const MODES: [SM9EncryptMode; 2] = [SM9EncryptMode::Stream, SM9EncryptMode::Sm4];

/// Flips one bit of the hex digit at `pos`, keeping it a lower-case hex digit.
fn flip(hex: &str, pos: usize) -> String {
    let mut bytes = hex.as_bytes().to_vec();
    let digit = (bytes[pos] as char).to_digit(16).unwrap() ^ 1;
    bytes[pos] = char::from_digit(digit, 16).unwrap() as u8;
    String::from_utf8(bytes).unwrap()
}

struct EncKeys {
    ke: String,
    ppub: String,
}

fn enc_keys() -> EncKeys {
    let (ke, ppub) = SM9::gen_enc_master_key();
    EncKeys { ke, ppub }
}

#[test]
fn key_generation_formats() {
    let (ks, ppub_s) = SM9::try_gen_sign_master_key().unwrap();
    assert_eq!(ks.len(), 64);
    assert_eq!(ppub_s.len(), 258);
    assert!(ppub_s.starts_with("04"));
    assert_eq!(
        SM9::sign_master_public_key(&ks.to_uppercase()).unwrap(),
        ppub_s
    );
    let ds = SM9::gen_sign_user_key(&ks, "Alice").unwrap();
    assert_eq!(ds.len(), 130);

    let (ke, ppub_e) = SM9::try_gen_enc_master_key().unwrap();
    assert_eq!(ppub_e.len(), 130);
    assert_eq!(SM9::enc_master_public_key(&ke).unwrap(), ppub_e);
    let de = SM9::gen_enc_user_key(&ke, "Bob").unwrap();
    assert_eq!(de.len(), 258);
    // hid matters, and the default is 0x03.
    assert_eq!(
        SM9::gen_enc_user_key_with_hid(&ke, "Bob", SM9_HID_ENCRYPT).unwrap(),
        de
    );
    assert_ne!(
        SM9::gen_enc_user_key_with_hid(&ke, "Bob", 0xff).unwrap(),
        de
    );
    // Fresh master keys differ.
    assert_ne!(SM9::gen_sign_master_key().0, ks);
}

#[test]
fn sign_verify_round_trips_and_rejections() {
    let (ks, ppub) = SM9::gen_sign_master_key();
    let (_, other_ppub) = SM9::gen_sign_master_key();
    for (id, msg) in [
        ("Alice", &b"hello"[..]),
        ("", &b""[..]),
        ("张三", &[0u8; 300][..]),
    ] {
        let ds = SM9::gen_sign_user_key(&ks, id).unwrap();
        let sig = SM9::sign(msg, &ds, &ppub).unwrap();
        assert_eq!(sig.len(), 194);
        assert!(SM9::verify(msg, &sig, id, &ppub));
        // Uppercase keys are accepted.
        assert!(SM9::verify(msg, &sig, id, &ppub.to_uppercase()));
        let sig2 = SM9::sign(msg, &ds.to_uppercase(), &ppub).unwrap();
        assert_ne!(sig, sig2, "r is random");
        assert!(SM9::verify(msg, &sig2, id, &ppub));
        // Wrong message, identity, hid and master key.
        assert!(!SM9::verify(b"other", &sig, id, &ppub));
        assert!(!SM9::verify(msg, &sig, "Mallory", &ppub));
        assert!(!SM9::verify_with_hid(msg, &sig, id, &ppub, 0x02));
        assert!(!SM9::verify(msg, &sig, id, &other_ppub));
        // An upper-case signature is another spelling, rejected.
        assert!(!SM9::verify(msg, &sig.to_uppercase(), id, &ppub));
        // Tampering anywhere (h, prefix, S).
        for pos in [0, 63, 65, 66, 100, 193] {
            assert!(!SM9::verify(msg, &flip(&sig, pos), id, &ppub), "{pos}");
        }
        assert!(!SM9::verify(msg, &sig[..192], id, &ppub));
        assert!(!SM9::verify(msg, &format!("{sig}00"), id, &ppub));
        assert!(!SM9::verify(msg, "", id, &ppub));
    }
    // h = 0 and h = N are out of range.
    let ds = SM9::gen_sign_user_key(&ks, "Alice").unwrap();
    let sig = SM9::sign("m", &ds, &ppub).unwrap();
    let zero_h = format!("{}{}", "0".repeat(64), &sig[64..]);
    assert!(!SM9::verify("m", &zero_h, "Alice", &ppub));
    let n = "b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25";
    assert!(!SM9::verify(
        "m",
        &format!("{n}{}", &sig[64..]),
        "Alice",
        &ppub
    ));
    // A key of the wrong kind is rejected.
    let keys = enc_keys();
    assert!(SM9::sign("m", &ds, &keys.ppub).is_err());
    assert!(!SM9::verify("m", &sig, "Alice", &keys.ppub));
}

#[test]
fn encrypt_decrypt_round_trips() {
    let keys = enc_keys();
    for id in ["Bob", "", "李四"] {
        let de = SM9::gen_enc_user_key(&keys.ke, id).unwrap();
        for len in [1usize, 15, 16, 17, 31, 32, 33, 64, 1000] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
            for mode in MODES {
                let c = SM9::encrypt(&msg, id, &keys.ppub, mode).unwrap();
                let c2_len = match mode {
                    SM9EncryptMode::Stream => len,
                    SM9EncryptMode::Sm4 => (len / 16 + 1) * 16,
                };
                assert_eq!(c.len(), 2 * (97 + c2_len));
                assert_eq!(SM9::decrypt_bytes(&c, id, &de, mode).unwrap(), msg);
                assert_eq!(
                    SM9::decrypt_bytes(&c, id, &de.to_uppercase(), mode).unwrap(),
                    msg
                );
            }
        }
    }
    let de = SM9::gen_enc_user_key(&keys.ke, "Bob").unwrap();
    let c = SM9::encrypt("你好, SM9", "Bob", &keys.ppub, SM9EncryptMode::default()).unwrap();
    assert_eq!(
        SM9::decrypt(&c, "Bob", &de, SM9EncryptMode::Stream).unwrap(),
        "你好, SM9"
    );
    let c = SM9::encrypt([0xffu8, 0xfe], "Bob", &keys.ppub, SM9EncryptMode::Stream).unwrap();
    assert!(SM9::decrypt(&c, "Bob", &de, SM9EncryptMode::Stream).is_err());
    assert!(SM9::decrypt_bytes(&c, "Bob", &de, SM9EncryptMode::Stream).is_ok());
}

#[test]
fn decrypt_rejections_are_uniform() {
    let keys = enc_keys();
    let de = SM9::gen_enc_user_key(&keys.ke, "Bob").unwrap();
    let wrong_de = SM9::gen_enc_user_key(&keys.ke, "Carol").unwrap();
    let other = enc_keys();
    let other_de = SM9::gen_enc_user_key(&other.ke, "Bob").unwrap();
    for mode in MODES {
        let c = SM9::encrypt(b"attack at dawn!!x", "Bob", &keys.ppub, mode).unwrap();
        let expected = SM9::decrypt_bytes(&c, "Bob", &de, mode).unwrap_err_or_none();
        assert!(expected.is_none());
        let err =
            |c: &str, id: &str, key: &str, mode| SM9::decrypt_bytes(c, id, key, mode).unwrap_err();
        let reference = err(&flip(&c, c.len() - 1), "Bob", &de, mode);
        // Tampered C1, C3 and C2, wrong identity, user key and master key, wrong mode.
        for pos in [3, 129, 130, 193, 194, c.len() - 1] {
            assert_eq!(err(&flip(&c, pos), "Bob", &de, mode), reference, "{pos}");
        }
        assert_eq!(err(&c, "Bobb", &de, mode), reference);
        assert_eq!(err(&c, "Bob", &wrong_de, mode), reference);
        assert_eq!(err(&c, "Bob", &other_de, mode), reference);
        let other_mode = if mode == SM9EncryptMode::Stream {
            SM9EncryptMode::Sm4
        } else {
            SM9EncryptMode::Stream
        };
        assert_eq!(err(&c, "Bob", &de, other_mode), reference);
        // Spelling and length.
        assert_eq!(err(&c.to_uppercase(), "Bob", &de, mode), reference);
        assert_eq!(err(&c[..194], "Bob", &de, mode), reference);
        assert_eq!(err(&c[..c.len() - 1], "Bob", &de, mode), reference);
        assert_eq!(err(&c[..c.len() - 2], "Bob", &de, mode), reference);
        assert_eq!(err("", "Bob", &de, mode), reference);
        assert_eq!(err(&format!("{c}zz"), "Bob", &de, mode), reference);
        // An invalid user key is a different, key-related error.
        assert_ne!(err(&c, "Bob", &de[..256], mode), reference);
    }
}

#[test]
fn encrypt_input_rules() {
    let keys = enc_keys();
    for mode in MODES {
        assert!(SM9::encrypt(b"", "Bob", &keys.ppub, mode).is_err());
        assert!(SM9::encrypt(b"x", "Bob", &keys.ppub.to_uppercase(), mode).is_ok());
        assert!(SM9::encrypt(b"x", "Bob", &keys.ppub[..128], mode).is_err());
        assert!(SM9::encrypt_with_rand(b"x", "Bob", &keys.ppub, 3, mode, "zz").is_err());
    }
    // A signing master public key (G2) is not an encryption one.
    let (_, ppub_s) = SM9::gen_sign_master_key();
    assert!(SM9::encrypt(b"x", "Bob", &ppub_s, SM9EncryptMode::Stream).is_err());
}

#[test]
fn encapsulation_round_trips_and_rejections() {
    let keys = enc_keys();
    let de = SM9::gen_enc_user_key(&keys.ke, "Bob").unwrap();
    for key_len in [1usize, 16, 32, 33, 100, 1 << 20] {
        let (k, c) = SM9::encapsulate("Bob", &keys.ppub, key_len).unwrap();
        assert_eq!(k.len(), 2 * key_len);
        assert_eq!(c.len(), 130);
        assert_eq!(SM9::decapsulate(&c, "Bob", &de, key_len).unwrap(), k);
        if key_len < 1000 {
            assert_ne!(SM9::decapsulate(&c, "Bobb", &de, key_len).unwrap(), k);
        }
    }
    for bad_len in [0usize, (1 << 20) + 1] {
        assert!(SM9::encapsulate("Bob", &keys.ppub, bad_len).is_err());
    }
    let (k, c) = SM9::encapsulate_with_hid("Bob", &keys.ppub, 32, 0x07).unwrap();
    let de7 = SM9::gen_enc_user_key_with_hid(&keys.ke, "Bob", 0x07).unwrap();
    assert_eq!(SM9::decapsulate(&c, "Bob", &de7, 32).unwrap(), k);
    assert_ne!(SM9::decapsulate(&c, "Bob", &de, 32).unwrap(), k);
    assert!(SM9::decapsulate(&c.to_uppercase(), "Bob", &de, 32).is_err());
    assert!(SM9::decapsulate(&flip(&c, 129), "Bob", &de, 32).is_err());
    assert!(SM9::decapsulate(&c, "Bob", &de, 0).is_err());
}

fn exchange_keys(keys: &EncKeys, id_a: &str, id_b: &str) -> (String, String) {
    (
        SM9::gen_enc_user_key_with_hid(&keys.ke, id_a, SM9_HID_EXCHANGE).unwrap(),
        SM9::gen_enc_user_key_with_hid(&keys.ke, id_b, SM9_HID_EXCHANGE).unwrap(),
    )
}

#[test]
fn key_exchange_round_trip() {
    let keys = enc_keys();
    let (id_a, id_b) = ("alice@example.com", "bob@example.com");
    let (de_a, de_b) = exchange_keys(&keys, id_a, id_b);
    for key_len in [1usize, 16, 48, 1 << 20] {
        let (r_a, ra) = SM9::exchange_init(id_b, &keys.ppub).unwrap();
        let (r_b, rb) = SM9::exchange_init(id_a, &keys.ppub).unwrap();
        let b = SM9::exchange_respond(key_len, id_a, id_b, &keys.ppub, &de_b, &r_b, &rb, &ra);
        assert!(b.success, "{:?}", b.message);
        let s_b = b.s_b.clone().unwrap();
        let a = SM9::exchange_confirm(key_len, id_a, id_b, &keys.ppub, &de_a, &r_a, &ra, &rb, &s_b);
        assert!(a.success, "{:?}", a.message);
        assert_eq!(a.shared_key, b.shared_key);
        assert_eq!(a.shared_key.as_ref().unwrap().len(), 2 * key_len);
        let s_a = a.s_a.unwrap();
        assert!(SM9::exchange_check(b.s_2.as_ref().unwrap(), &s_a));
        assert!(!SM9::exchange_check(
            b.s_2.as_ref().unwrap(),
            &flip(&s_a, 5)
        ));
        assert!(!SM9::exchange_check(
            b.s_2.as_ref().unwrap(),
            &s_a.to_uppercase()
        ));
        assert!(!SM9::exchange_check(&s_a, &s_a[..62]));
        // The secret key does not show in debug output.
        if key_len >= 16 {
            let shown = format!("{b:?}");
            assert!(!shown.contains(b.shared_key.as_ref().unwrap().as_str()));
        }
    }
}

#[test]
fn key_exchange_mismatches_fail() {
    let keys = enc_keys();
    let (id_a, id_b) = ("A", "B");
    let (de_a, de_b) = exchange_keys(&keys, id_a, id_b);
    let (r_a, ra) = SM9::exchange_init(id_b, &keys.ppub).unwrap();
    let (r_b, rb) = SM9::exchange_init(id_a, &keys.ppub).unwrap();
    let b = SM9::exchange_respond(16, id_a, id_b, &keys.ppub, &de_b, &r_b, &rb, &ra);
    assert!(b.success);
    let s_b = b.s_b.clone().unwrap();
    let confirm = |id_a: &str, id_b: &str, de: &str, r: &str, s_b: &str, len: usize| {
        SM9::exchange_confirm(len, id_a, id_b, &keys.ppub, de, r, &ra, &rb, s_b)
    };
    assert!(confirm(id_a, id_b, &de_a, &r_a, &s_b, 16).success);
    // Tampered S_B, other identities, a wrong key, a wrong r, other key length.
    assert!(!confirm(id_a, id_b, &de_a, &r_a, &flip(&s_b, 0), 16).success);
    assert!(!confirm(id_a, id_b, &de_a, &r_a, &s_b.to_uppercase(), 16).success);
    assert!(!confirm("A2", id_b, &de_a, &r_a, &s_b, 16).success);
    assert!(!confirm(id_a, "B2", &de_a, &r_a, &s_b, 16).success);
    assert!(!confirm(id_a, id_b, &de_b, &r_a, &s_b, 16).success);
    assert!(!confirm(id_a, id_b, &de_a, &r_b, &s_b, 16).success);
    let a = confirm(id_a, id_b, &de_a, &r_a, &s_b, 32);
    assert!(a.success, "S_B does not depend on the key length");
    assert_ne!(a.shared_key, b.shared_key);
    // A responder that used the wrong key gives a key and S_B that A rejects.
    let (_, de_c) = exchange_keys(&keys, id_a, "C");
    let wrong = SM9::exchange_respond(16, id_a, id_b, &keys.ppub, &de_c, &r_b, &rb, &ra);
    assert!(wrong.success);
    assert!(!confirm(id_a, id_b, &de_a, &r_a, wrong.s_b.as_ref().unwrap(), 16).success);
    // Invalid inputs.
    for key_len in [0usize, (1 << 20) + 1] {
        let bad = SM9::exchange_respond(key_len, id_a, id_b, &keys.ppub, &de_b, &r_b, &rb, &ra);
        assert!(!bad.success && bad.message.is_some() && bad.shared_key.is_none());
    }
    let zero = "0".repeat(64);
    let bad = SM9::exchange_respond(16, id_a, id_b, &keys.ppub, &de_b, &zero, &rb, &ra);
    assert!(!bad.success);
    let bad = SM9::exchange_respond(16, id_a, id_b, &rb[..128], &de_b, &r_b, &rb, &ra);
    assert!(!bad.success);
}

/// `Result::unwrap_err` that gives `None` on success, to keep the tests short.
trait ErrOrNone {
    fn unwrap_err_or_none(self) -> Option<String>;
}

impl<T> ErrOrNone for Result<T, String> {
    fn unwrap_err_or_none(self) -> Option<String> {
        self.err()
    }
}
