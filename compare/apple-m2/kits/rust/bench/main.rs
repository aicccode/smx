//! Mac benchmark for the Rust SM2/SM3/SM4 library. The same source builds against the original
//! code (base/) and the current code (new/); both expose the same public API.

use gm_rust::sm2::SM2;
use gm_rust::sm2::bigint256::BigInt256;
use gm_rust::sm2::point::ECPoint;
use gm_rust::sm3::Sm3;
use gm_rust::sm4::SM4;
use std::hint::black_box;
use std::time::{Duration, Instant};

const SAMPLES: usize = 7;
const SAMPLE_TIME: Duration = Duration::from_millis(200);
const WARMUP: Duration = Duration::from_millis(300);
const USER_ID: &str = "1234567812345678";
const PEER_ID: &str = "8765432112345678";

/// Median and minimum of 7 samples of at least 200 ms each, in microseconds per operation.
fn measure(name: &str, mut f: impl FnMut()) {
    // Warm up, and find a batch size for which one sample takes at least SAMPLE_TIME.
    let start = Instant::now();
    let mut calls = 0u64;
    while start.elapsed() < WARMUP {
        f();
        calls += 1;
    }
    let per_call = WARMUP.as_secs_f64() / calls as f64;
    // 25% headroom, so that a sample rarely falls short of SAMPLE_TIME.
    let mut batch = ((1.25 * SAMPLE_TIME.as_secs_f64() / per_call).ceil() as u64).max(1);
    let mut samples = Vec::with_capacity(SAMPLES);
    while samples.len() < SAMPLES {
        let t = Instant::now();
        for _ in 0..batch {
            f();
        }
        let elapsed = t.elapsed();
        if elapsed < SAMPLE_TIME {
            // Too short: discard it and use a larger batch from now on.
            batch = batch * 2;
            continue;
        }
        samples.push(elapsed.as_secs_f64() * 1e6 / batch as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!("{name}\t{:.3}\t{:.3}", samples[SAMPLES / 2], samples[0]);
}

/// ASCII text of the given length, which the string-based SM2 and SM4 APIs require.
fn text(len: usize) -> String {
    (0..len).map(|i| (b'a' + (i % 26) as u8) as char).collect()
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// One complete key exchange between fresh ephemeral keys: B computes Sb and its key, A checks Sb
/// and computes Sa and its key, B checks Sa. Long-term keys are given.
fn key_exchange(
    d_a: &BigInt256,
    p_a: &ECPoint,
    d_b: &BigInt256,
    p_b: &ECPoint,
) -> (String, String) {
    let (ra_hex, r_a_hex) = SM2::gen_key_pair();
    let (rb_hex, r_b_hex) = SM2::gen_key_pair();
    let (ra, r_a) = (BigInt256::from_hex(&ra_hex), ECPoint::from_hex_encoded(&r_a_hex));
    let (rb, r_b) = (BigInt256::from_hex(&rb_hex), ECPoint::from_hex_encoded(&r_b_hex));
    let b = SM2::get_sb(16, p_a, &r_a, p_b, d_b, &r_b, &rb, USER_ID, PEER_ID);
    assert!(b.success);
    let sb = unhex(b.sb.as_ref().unwrap());
    let a = SM2::get_sa(16, p_b, &r_b, p_a, d_a, &r_a, &ra, USER_ID, PEER_ID, &sb);
    assert!(a.success);
    let sa = unhex(a.sa.as_ref().unwrap());
    assert!(SM2::check_sa(
        b.v.as_ref().unwrap(),
        b.za.as_ref().unwrap(),
        b.zb.as_ref().unwrap(),
        &r_a,
        &r_b,
        &sa
    ));
    (a.ka.unwrap(), b.kb.unwrap())
}

fn main() {
    // SM3: one-shot hash, including the hex digest that `finish` produces on both sides.
    for (name, len) in [("sm3/64B", 64), ("sm3/1KB", 1024), ("sm3/1MB", 1 << 20)] {
        let data = vec![0x5au8; len];
        measure(name, || {
            let mut h = Sm3::new();
            h.update(black_box(&data));
            h.finish();
            black_box(h.hash_bytes());
        });
    }

    // SM4: 16-byte key and IV, CBC with PKCS#7 through the hex-string API.
    let key = *b"0123456789abcdef";
    let iv = *b"fedcba9876543210";
    measure("sm4/key_schedule", || {
        let mut s = SM4::new();
        s.set_key(black_box(&key), black_box(&iv)).unwrap();
        black_box(&s);
    });
    let mut sm4 = SM4::new();
    sm4.set_key(&key, &iv).unwrap();
    let sizes = [("16B", 16), ("1KB", 1024), ("1MB", 1 << 20)];
    let plains: Vec<String> = sizes.iter().map(|(_, len)| text(*len)).collect();
    let ciphers: Vec<String> = plains.iter().map(|p| sm4.encrypt(p).unwrap()).collect();
    for (p, c) in plains.iter().zip(&ciphers) {
        assert_eq!(sm4.decrypt(c).unwrap(), *p, "SM4 round trip");
    }
    for ((name, _), plain) in sizes.iter().zip(&plains) {
        measure(&format!("sm4/cbc_encrypt/{name}"), || {
            black_box(sm4.encrypt(black_box(plain)).unwrap());
        });
    }
    for ((name, _), cipher) in sizes.iter().zip(&ciphers) {
        measure(&format!("sm4/cbc_decrypt/{name}"), || {
            black_box(sm4.decrypt(black_box(cipher)).unwrap());
        });
    }

    // SM2: hex-string keys, as the public API takes them.
    let (d_hex, pub_hex) = SM2::gen_key_pair();
    let message = text(32);
    let signature = SM2::sign(USER_ID, &message, &d_hex).unwrap();
    assert!(SM2::verify(USER_ID, &signature, &message, &pub_hex), "SM2 verify");
    let ciphertext = SM2::encrypt(&message, &pub_hex).unwrap();
    assert_eq!(SM2::decrypt(&ciphertext, &d_hex).unwrap(), message, "SM2 round trip");
    let (d_b_hex, p_b_hex) = SM2::gen_key_pair();
    let (d_a, p_a) = (BigInt256::from_hex(&d_hex), ECPoint::from_hex_encoded(&pub_hex));
    let (d_b, p_b) = (BigInt256::from_hex(&d_b_hex), ECPoint::from_hex_encoded(&p_b_hex));
    let (ka, kb) = key_exchange(&d_a, &p_a, &d_b, &p_b);
    assert_eq!(ka, kb, "SM2 key exchange");
    assert_eq!(ka.len(), 32);

    measure("sm2/keygen", || {
        black_box(SM2::gen_key_pair());
    });
    measure("sm2/sign", || {
        black_box(SM2::sign(USER_ID, black_box(&message), &d_hex).unwrap());
    });
    measure("sm2/verify", || {
        assert!(SM2::verify(USER_ID, black_box(&signature), &message, &pub_hex));
    });
    measure("sm2/encrypt/32B", || {
        black_box(SM2::encrypt(black_box(&message), &pub_hex).unwrap());
    });
    measure("sm2/decrypt/32B", || {
        black_box(SM2::decrypt(black_box(&ciphertext), &d_hex).unwrap());
    });
    measure("sm2/key_exchange", || {
        black_box(key_exchange(&d_a, &p_a, &d_b, &p_b));
    });
}
