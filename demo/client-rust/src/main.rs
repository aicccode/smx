//! SM2 密钥交换Demo客户端 - Rust版
//! 作为A侧与Java服务端(B侧)进行密钥交换
//!
//! Demo limitations, not to be copied into a real system: traffic is plain HTTP, the server is
//! only authenticated if `SM2_DEMO_SERVER_PUBKEY` pins its public key (otherwise any impostor
//! passes key confirmation), and the protocol fixes the SM4 IV to zero, which reuses it for every
//! message under a session key. CBC itself gives no integrity either; see the `gm_rust::sm4`
//! documentation.

use gm_rust::sm2::{bigint256::BigInt256, point::ECPoint, SM2};
use gm_rust::sm4::SM4;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::time::Duration;

const SERVER_URL: &str = "http://localhost:8080";
const IDA: &str = "rust-client@demo.aicc";
/// No response of this protocol comes close to this size.
const MAX_RESPONSE_BYTES: u64 = 1 << 20;
/// Deadline for a whole request, reply body included, so a drip-feeding server cannot stall us.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
/// Hex of the expected server public key; when set, any other key is a hard failure.
const PIN_VARIABLE: &str = "SM2_DEMO_SERVER_PUBKEY";

#[derive(Serialize)]
struct InitRequest {
    #[serde(rename = "IDa")]
    id_a: String,
    #[serde(rename = "pA")]
    p_a: String,
    #[serde(rename = "Ra")]
    r_a: String,
    #[serde(rename = "keyLen")]
    key_len: usize,
}

#[derive(Deserialize, Debug)]
struct InitResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "IDb")]
    id_b: String,
    #[serde(rename = "pB")]
    p_b: String,
    #[serde(rename = "Rb")]
    r_b: String,
    #[serde(rename = "Sb")]
    sb: String,
}

#[derive(Serialize)]
struct ConfirmRequest {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "Sa")]
    sa: String,
}

#[derive(Deserialize, Debug)]
struct ConfirmResponse {
    success: bool,
}

#[derive(Serialize)]
struct CryptoTestRequest {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "clientCiphertext")]
    client_ciphertext: String,
    #[serde(rename = "clientPlaintext")]
    client_plaintext: String,
}

#[derive(Deserialize, Debug)]
struct CryptoTestResponse {
    #[serde(rename = "clientDecryptMatch")]
    client_decrypt_match: bool,
    #[serde(rename = "serverPlaintext")]
    server_plaintext: String,
    #[serde(rename = "serverCiphertext")]
    server_ciphertext: String,
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.is_ascii() || hex.len() & 1 != 0 {
        return Err("not a hex string".to_string());
    }
    (0..hex.len() / 2)
        .map(|i| {
            let pair = &hex[i * 2..i * 2 + 2];
            if !pair.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err("not a hex string".to_string());
            }
            u8::from_str_radix(pair, 16).map_err(|_| "not a hex string".to_string())
        })
        .collect()
}

/// Server text with control characters replaced, so it cannot drive the terminal.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// The pinned server key, if configured. A value that is not a valid key is an error, not "no pin".
fn pinned_server_key() -> Result<Option<ECPoint>, String> {
    match std::env::var(PIN_VARIABLE) {
        Ok(value) => ECPoint::try_from_hex_encoded(value.trim())
            .map(Some)
            .ok_or_else(|| format!("{PIN_VARIABLE} is not a valid SM2 public key")),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{PIN_VARIABLE} is not a valid SM2 public key"))
        }
    }
}

/// POSTs JSON and parses a JSON reply of bounded size.
fn post<Request: Serialize, Reply: DeserializeOwned>(
    path: &str,
    request: &Request,
) -> Result<Reply, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(REQUEST_DEADLINE)
        .redirects(0)
        .build();
    let response = agent
        .post(&format!("{SERVER_URL}{path}"))
        .set("Content-Type", "application/json")
        .send_json(request)
        .map_err(|e| clean(&format!("request to {path} failed: {e}")))?;
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|e| clean(&format!("reading reply from {path} failed: {e}")))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(format!("reply from {path} is too large"));
    }
    serde_json::from_slice(&body).map_err(|e| clean(&format!("malformed reply from {path}: {e}")))
}

fn to_json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| format!("cannot encode request: {e}"))
}

fn run() -> Result<(), String> {
    println!("=== SM2 Key Exchange Demo (Rust Client) ===\n");

    let pinned_key = pinned_server_key()?;
    if pinned_key.is_none() {
        println!(
            "WARNING: the server is UNAUTHENTICATED. An impostor would pass every step below."
        );
        println!("Set {PIN_VARIABLE} to the server's public key to detect that.\n");
    }

    // 生成A侧(客户端)证书密钥对
    let (da_hex, pa_hex) = SM2::try_gen_key_pair()?;
    println!("Generated A certificate keypair:");
    println!("  Public key (pA): {pa_hex}");

    // 生成A侧随机密钥对
    let (ra_hex, ra_pub_hex) = SM2::try_gen_key_pair()?;
    println!("\nGenerated A random keypair:");
    println!("  Public key (Ra): {ra_pub_hex}");

    let key_len: usize = 16;

    // Step 1: 发起密钥交换
    println!("\n--- Step 1: Key Exchange Init ---");
    let init_request = InitRequest {
        id_a: IDA.to_string(),
        p_a: pa_hex.clone(),
        r_a: ra_pub_hex.clone(),
        key_len,
    };
    println!("Request: {}", to_json(&init_request)?);

    let init_response: InitResponse = post("/api/keyswap/init", &init_request)
        .map_err(|e| format!("{e}\nMake sure the Java server is running on port 8080"))?;
    println!("Response: {}", clean(&format!("{init_response:?}")));

    // Step 2: 计算Sa和Ka
    println!("\n--- Step 2: Calculate Sa and Ka ---");

    // Invalid points decode to infinity, which get_sa rejects.
    let p_b = ECPoint::from_hex_encoded(&init_response.p_b);
    if let Some(pinned) = &pinned_key {
        if *pinned != p_b {
            return Err("server public key does not match the pinned key".to_string());
        }
        println!("Server public key matches the pinned key.");
    }
    let r_b = ECPoint::from_hex_encoded(&init_response.r_b);
    let p_a = ECPoint::from_hex_encoded(&pa_hex);
    let r_a = ECPoint::from_hex_encoded(&ra_pub_hex);
    let d_a = BigInt256::from_hex(&da_hex);
    let ra = BigInt256::from_hex(&ra_hex);
    let sb_bytes = hex_to_bytes(&init_response.sb).map_err(|e| format!("server Sb: {e}"))?;

    let result = SM2::get_sa(
        key_len,
        &p_b,
        &r_b,
        &p_a,
        &d_a,
        &r_a,
        &ra,
        IDA,
        &init_response.id_b,
        &sb_bytes,
    );

    if !result.success {
        return Err(clean(&format!("getSa failed: {:?}", result.message)));
    }

    let (Some(sa), Some(ka)) = (result.sa.as_ref(), result.ka.as_ref()) else {
        return Err("getSa returned no result".to_string());
    };
    println!("Sa: {sa}");
    println!("Ka (negotiated key): derived, not displayed");

    // Step 3: 确认密钥交换
    println!("\n--- Step 3: Key Exchange Confirm ---");
    let confirm_request = ConfirmRequest {
        session_id: init_response.session_id.clone(),
        sa: sa.clone(),
    };
    println!("Request: {}", to_json(&confirm_request)?);

    let confirm_response: ConfirmResponse = post("/api/keyswap/confirm", &confirm_request)?;
    println!("Response: {confirm_response:?}");

    if !confirm_response.success {
        return Err("Key exchange confirmation failed".to_string());
    }

    if pinned_key.is_some() {
        println!("\nKey exchange completed with the pinned server.");
    } else {
        println!("\nKey exchange completed, with an UNAUTHENTICATED server.");
    }

    // Step 4: 双向加密通信测试
    println!("\n--- Step 4: Bidirectional Crypto Test ---");

    // 初始化SM4. The all-zero IV is part of this demo's protocol; see the top of this file.
    let iv = [0u8; 16];
    let ka_bytes = hex_to_bytes(ka)?;
    let mut sm4 = SM4::new();
    sm4.set_key(&ka_bytes, &iv)
        .map_err(|e| format!("cannot set SM4 key: {e}"))?;

    // 客户端加密消息
    let client_plaintext = "Hello from Rust Client!";
    let client_ciphertext = sm4
        .encrypt(client_plaintext)
        .map_err(|e| format!("encryption failed: {e}"))?;
    println!("Client plaintext: {client_plaintext}");
    println!("Client ciphertext: {client_ciphertext}");

    // 发送给服务端
    let crypto_request = CryptoTestRequest {
        session_id: init_response.session_id.clone(),
        client_ciphertext: client_ciphertext.clone(),
        client_plaintext: client_plaintext.to_string(),
    };
    println!("\nRequest: {}", to_json(&crypto_request)?);

    let crypto_response: CryptoTestResponse = post("/api/crypto/test", &crypto_request)?;
    println!("Response: {}", clean(&format!("{crypto_response:?}")));

    // 验证服务端是否正确解密了客户端的消息
    let server_decrypt_ok = crypto_response.client_decrypt_match;
    println!(
        "\n[Server decrypted client message]: {}",
        if server_decrypt_ok { "PASS" } else { "FAIL" }
    );

    // 客户端解密服务端的消息
    let server_decrypted = sm4
        .decrypt(&crypto_response.server_ciphertext)
        .map_err(|e| clean(&format!("decryption failed: {e}")))?;
    let client_decrypt_ok = server_decrypted == crypto_response.server_plaintext;
    println!(
        "[Client decrypted server message]: {}",
        if client_decrypt_ok { "PASS" } else { "FAIL" }
    );
    println!(
        "  Server plaintext: {}",
        clean(&crypto_response.server_plaintext)
    );
    println!("  Client decrypted: {}", clean(&server_decrypted));

    if !(server_decrypt_ok && client_decrypt_ok) {
        return Err("Bidirectional Crypto test FAILED!".to_string());
    }
    println!("\nBidirectional Crypto test PASSED!");
    println!("\n=== Demo Complete ===");
    Ok(())
}

fn main() {
    if let Err(message) = run() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
