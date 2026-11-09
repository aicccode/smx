//! Throughput/latency benchmark for the public API, std-only.
//!
//! Run with `cargo bench --bench sm_bench`. Only public APIs of the baseline are
//! used, so the same file can be run against any older checkout of this crate
//! for a before/after comparison (drop `bench_sm9` for checkouts without SM9). Pass a
//! substring as first argument to filter.

use gm_rust::sm2::SM2;
use gm_rust::sm2::bigint256::BigInt256;
use gm_rust::sm2::fp::FpElement;
use gm_rust::sm2::point::{ECPoint, SM2_N};
use gm_rust::sm3::Sm3;
use gm_rust::sm4::SM4;
use gm_rust::sm9::{SM9, SM9_HID_EXCHANGE, SM9EncryptMode};
use std::hint::black_box;
use std::time::{Duration, Instant};

const ROUNDS: usize = 5;
const ROUND_TIME: Duration = Duration::from_millis(120);
const BATCH_TIME: Duration = Duration::from_millis(2);

struct Filter(Option<String>);

impl Filter {
    /// Best-of-`ROUNDS` nanoseconds per call of `f`; optional throughput for `bytes` per call.
    fn run<F: FnMut()>(&self, name: &str, bytes: usize, mut f: F) {
        if let Some(pattern) = &self.0 {
            if !name.contains(pattern.as_str()) {
                return;
            }
        }
        // Calibrate a batch size so that reading the clock does not distort short operations.
        let mut batch = 1u64;
        loop {
            let start = Instant::now();
            for _ in 0..batch {
                f();
            }
            if start.elapsed() >= BATCH_TIME {
                break;
            }
            batch *= 2;
        }
        let mut best = f64::MAX;
        for _ in 0..ROUNDS {
            let start = Instant::now();
            let mut calls = 0u64;
            while start.elapsed() < ROUND_TIME {
                for _ in 0..batch {
                    f();
                }
                calls += batch;
            }
            best = best.min(start.elapsed().as_nanos() as f64 / calls as f64);
        }
        if bytes > 0 {
            let mbps = bytes as f64 / best * 1000.0;
            println!("{name:<28} {best:>14.1} ns/op {mbps:>10.1} MB/s");
        } else {
            println!("{name:<28} {best:>14.1} ns/op");
        }
    }
}

/// ASCII payload so that the `&str` based SM4/SM2 APIs accept it.
fn payload(len: usize) -> String {
    (0..len).map(|i| (b'a' + (i % 26) as u8) as char).collect()
}

fn bench_sm3(b: &Filter) {
    for (name, len) in [("sm3/64B", 64), ("sm3/1KB", 1024), ("sm3/1MB", 1024 * 1024)] {
        let data = payload(len);
        b.run(name, len, || {
            let mut h = Sm3::new();
            h.update(black_box(data.as_bytes()));
            h.finish();
            black_box(h.hash_bytes());
        });
    }
}

fn bench_sm4(b: &Filter) {
    let key = *b"0123456789abcdef";
    let iv = *b"fedcba9876543210";
    let mut sm4 = SM4::new();
    sm4.set_key(&key, &iv).unwrap();

    b.run("sm4/key_schedule", 0, || {
        let mut s = SM4::new();
        s.set_key(black_box(&key), black_box(&iv)).unwrap();
        black_box(&s);
    });
    for (name, len) in [("16B", 16), ("1KB", 1024), ("1MB", 1024 * 1024)] {
        let plain = payload(len);
        let cipher = sm4.encrypt(&plain).unwrap();
        b.run(&format!("sm4/encrypt_{name}"), len, || {
            black_box(sm4.encrypt(black_box(&plain)).unwrap());
        });
        b.run(&format!("sm4/decrypt_{name}"), len, || {
            black_box(sm4.decrypt(black_box(&cipher)).unwrap());
        });
    }
}

fn bench_sm2(b: &Filter) {
    let id = "ALICE123@YAHOO.COM";
    let msg = "encryption standard";
    let plain = payload(32);
    let pri = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    let d = BigInt256::from_hex(pri);
    let public = SM2::get_public_key(&d).to_hex_encoded();
    let sig = SM2::sign(id, msg, pri).unwrap();
    let cipher = SM2::encrypt(&plain, &public).unwrap();

    b.run("sm2/keygen", 0, || {
        black_box(SM2::gen_key_pair());
    });
    b.run("sm2/sign", 0, || {
        black_box(SM2::sign(id, msg, pri).unwrap());
    });
    b.run("sm2/verify", 0, || {
        assert!(SM2::verify(id, black_box(&sig), msg, &public));
    });
    b.run("sm2/encrypt_32B", 0, || {
        black_box(SM2::encrypt(&plain, &public).unwrap());
    });
    b.run("sm2/decrypt_32B", 0, || {
        black_box(SM2::decrypt(&cipher, pri).unwrap());
    });

    let (id_a, id_b) = ("ALICE123@YAHOO.COM", "BILL456@YAHOO.COM");
    let d_a =
        BigInt256::from_hex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE");
    let r_a_k =
        BigInt256::from_hex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
    let d_b =
        BigInt256::from_hex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53");
    let r_b_k =
        BigInt256::from_hex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
    let (p_a, r_a) = (SM2::get_public_key(&d_a), SM2::get_public_key(&r_a_k));
    let (p_b, r_b) = (SM2::get_public_key(&d_b), SM2::get_public_key(&r_b_k));
    b.run("sm2/key_exchange_full", 0, || {
        let rb = SM2::get_sb(16, &p_a, &r_a, &p_b, &d_b, &r_b, &r_b_k, id_a, id_b);
        let sb = hex_decode(rb.sb.as_ref().unwrap());
        let ra = SM2::get_sa(16, &p_b, &r_b, &p_a, &d_a, &r_a, &r_a_k, id_a, id_b, &sb);
        assert!(ra.success);
        let sa = hex_decode(ra.sa.as_ref().unwrap());
        assert!(SM2::check_sa(
            rb.v.as_ref().unwrap(),
            rb.za.as_ref().unwrap(),
            rb.zb.as_ref().unwrap(),
            &r_a,
            &r_b,
            &sa
        ));
    });
}

fn bench_sm9(b: &Filter) {
    let (ks, ppub_s) = SM9::gen_sign_master_key();
    let (ke, ppub_e) = SM9::gen_enc_master_key();
    let ds = SM9::gen_sign_user_key(&ks, "Alice").unwrap();
    let de = SM9::gen_enc_user_key(&ke, "Bob").unwrap();
    let msg = "Chinese IBS standard";
    let plain = payload(32);
    let sig = SM9::sign(msg, &ds, &ppub_s).unwrap();
    let stream = SM9::encrypt(&plain, "Bob", &ppub_e, SM9EncryptMode::Stream).unwrap();
    let block = SM9::encrypt(&plain, "Bob", &ppub_e, SM9EncryptMode::Sm4).unwrap();
    let (_, kem) = SM9::encapsulate("Bob", &ppub_e, 32).unwrap();

    b.run("sm9/sign_master_keygen", 0, || {
        black_box(SM9::gen_sign_master_key());
    });
    b.run("sm9/sign_user_key", 0, || {
        black_box(SM9::gen_sign_user_key(&ks, black_box("Alice")).unwrap());
    });
    b.run("sm9/enc_user_key", 0, || {
        black_box(SM9::gen_enc_user_key(&ke, black_box("Bob")).unwrap());
    });
    b.run("sm9/sign", 0, || {
        black_box(SM9::sign(msg, &ds, &ppub_s).unwrap());
    });
    b.run("sm9/verify", 0, || {
        assert!(SM9::verify(msg, black_box(&sig), "Alice", &ppub_s));
    });
    b.run("sm9/encrypt_32B", 0, || {
        black_box(SM9::encrypt(&plain, "Bob", &ppub_e, SM9EncryptMode::Stream).unwrap());
    });
    b.run("sm9/decrypt_32B", 0, || {
        black_box(SM9::decrypt(&stream, "Bob", &de, SM9EncryptMode::Stream).unwrap());
    });
    b.run("sm9/encrypt_sm4_32B", 0, || {
        black_box(SM9::encrypt(&plain, "Bob", &ppub_e, SM9EncryptMode::Sm4).unwrap());
    });
    b.run("sm9/decrypt_sm4_32B", 0, || {
        black_box(SM9::decrypt(&block, "Bob", &de, SM9EncryptMode::Sm4).unwrap());
    });
    b.run("sm9/encapsulate", 0, || {
        black_box(SM9::encapsulate("Bob", &ppub_e, 32).unwrap());
    });
    b.run("sm9/decapsulate", 0, || {
        black_box(SM9::decapsulate(&kem, "Bob", &de, 32).unwrap());
    });

    let (id_a, id_b) = ("Alice", "Bob");
    let de_a = SM9::gen_enc_user_key_with_hid(&ke, id_a, SM9_HID_EXCHANGE).unwrap();
    let de_b = SM9::gen_enc_user_key_with_hid(&ke, id_b, SM9_HID_EXCHANGE).unwrap();
    b.run("sm9/key_exchange_full", 0, || {
        let (r_a, ra) = SM9::exchange_init(id_b, &ppub_e).unwrap();
        let (r_b, rb) = SM9::exchange_init(id_a, &ppub_e).unwrap();
        let resp = SM9::exchange_respond(16, id_a, id_b, &ppub_e, &de_b, &r_b, &rb, &ra);
        let s_b = resp.s_b.as_ref().unwrap();
        let conf = SM9::exchange_confirm(16, id_a, id_b, &ppub_e, &de_a, &r_a, &ra, &rb, s_b);
        assert!(SM9::exchange_check(
            resp.s_2.as_ref().unwrap(),
            conf.s_a.as_ref().unwrap()
        ));
    });
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn bench_primitives(b: &Filter) {
    let x = FpElement::from_hex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
    let y = FpElement::from_hex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
    let k = BigInt256::from_hex("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21");
    let k2 =
        BigInt256::from_hex("1234567890ABCDEF1234567890ABCDEFFEDCBA0987654321FEDCBA0987654321");
    let g = ECPoint::generator();
    let p = g.multiply(&k2);

    b.run("fp/mul", 0, || {
        black_box(black_box(&x).multiply(black_box(&y)));
    });
    b.run("fp/square", 0, || {
        black_box(black_box(&x).square());
    });
    b.run("fp/add", 0, || {
        black_box(black_box(&x).add(black_box(&y)));
    });
    b.run("fp/invert", 0, || {
        black_box(black_box(&x).invert());
    });
    b.run("fn/mod_mul", 0, || {
        black_box(black_box(&k).mod_mul(black_box(&k2), &SM2_N));
    });
    b.run("fn/mod_inverse", 0, || {
        black_box(black_box(&k).mod_inverse(&SM2_N));
    });
    b.run("ec/mul_generator", 0, || {
        black_box(black_box(&g).multiply(black_box(&k)));
    });
    b.run("ec/mul_variable", 0, || {
        black_box(black_box(&p).multiply(black_box(&k)));
    });
    b.run("ec/add", 0, || {
        black_box(black_box(&g).add(black_box(&p)));
    });
    b.run("ec/encode_hex", 0, || {
        black_box(black_box(&p).to_hex_encoded());
    });
    let encoded = p.to_hex_encoded();
    b.run("ec/decode_hex", 0, || {
        black_box(ECPoint::from_hex_encoded(black_box(&encoded)));
    });
}

fn main() {
    // `cargo bench` passes `--bench`; anything else is a name filter.
    let filter = std::env::args().skip(1).find(|a| !a.starts_with("--"));
    let b = Filter(filter);
    bench_sm3(&b);
    bench_sm4(&b);
    bench_sm2(&b);
    bench_sm9(&b);
    bench_primitives(&b);
}
