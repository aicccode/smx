//! SM2 密钥交换Demo客户端 - Rust版
//! 作为A侧与Java服务端(B侧)进行密钥交换

use gm_rust::sm2::{SM2, bigint256::BigInt256, point::ECPoint};
use gm_rust::sm4::SM4;
use serde::{Deserialize, Serialize};

const SERVER_URL: &str = "http://localhost:8080";
const IDA: &str = "rust-client@demo.aicc";

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
    #[serde(rename = "clientDecrypted")]
    client_decrypted: String,
    #[serde(rename = "clientDecryptMatch")]
    client_decrypt_match: bool,
    #[serde(rename = "serverPlaintext")]
    server_plaintext: String,
    #[serde(rename = "serverCiphertext")]
    server_ciphertext: String,
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    println!("=== SM2 Key Exchange Demo (Rust Client) ===\n");

    // 生成A侧(客户端)证书密钥对
    let (da_hex, pa_hex) = SM2::gen_key_pair();
    println!("Generated A certificate keypair:");
    println!("  Private key (dA): {}", da_hex);
    println!("  Public key (pA): {}", pa_hex);

    // 生成A侧随机密钥对
    let (ra_hex, ra_pub_hex) = SM2::gen_key_pair();
    println!("\nGenerated A random keypair:");
    println!("  Private key (ra): {}", ra_hex);
    println!("  Public key (Ra): {}", ra_pub_hex);

    let key_len: usize = 16;

    // Step 1: 发起密钥交换
    println!("\n--- Step 1: Key Exchange Init ---");
    let init_request = InitRequest {
        id_a: IDA.to_string(),
        p_a: pa_hex.clone(),
        r_a: ra_pub_hex.clone(),
        key_len,
    };
    println!("Request: {:?}", serde_json::to_string(&init_request).unwrap());

    let init_response: InitResponse = match ureq::post(&format!("{}/api/keyswap/init", SERVER_URL))
        .set("Content-Type", "application/json")
        .send_json(&init_request)
    {
        Ok(resp) => resp.into_json().expect("Failed to parse response"),
        Err(e) => {
            eprintln!("Failed to connect to server: {}", e);
            eprintln!("Make sure the Java server is running on port 8080");
            std::process::exit(1);
        }
    };
    println!("Response: {:?}", init_response);

    // Step 2: 计算Sa和Ka
    println!("\n--- Step 2: Calculate Sa and Ka ---");

    let p_b = ECPoint::from_hex_encoded(&init_response.p_b);
    let r_b = ECPoint::from_hex_encoded(&init_response.r_b);
    let p_a = ECPoint::from_hex_encoded(&pa_hex);
    let r_a = ECPoint::from_hex_encoded(&ra_pub_hex);
    let d_a = BigInt256::from_hex(&da_hex);
    let ra = BigInt256::from_hex(&ra_hex);
    let sb_bytes = hex_to_bytes(&init_response.sb);

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
        eprintln!("getSa failed: {:?}", result.message);
        std::process::exit(1);
    }

    let sa = result.sa.as_ref().unwrap();
    let ka = result.ka.as_ref().unwrap();
    println!("Sa: {}", sa);
    println!("Ka (negotiated key): {}", ka);

    // Step 3: 确认密钥交换
    println!("\n--- Step 3: Key Exchange Confirm ---");
    let confirm_request = ConfirmRequest {
        session_id: init_response.session_id.clone(),
        sa: sa.clone(),
    };
    println!("Request: {:?}", serde_json::to_string(&confirm_request).unwrap());

    let confirm_response: ConfirmResponse =
        ureq::post(&format!("{}/api/keyswap/confirm", SERVER_URL))
            .set("Content-Type", "application/json")
            .send_json(&confirm_request)
            .expect("Failed to send confirm request")
            .into_json()
            .expect("Failed to parse confirm response");
    println!("Response: {:?}", confirm_response);

    if !confirm_response.success {
        eprintln!("Key exchange confirmation failed");
        std::process::exit(1);
    }

    println!("\nKey exchange completed successfully!");
    println!("Negotiated key (Ka): {}", ka);

    // Step 4: 双向加密通信测试
    println!("\n--- Step 4: Bidirectional Crypto Test ---");

    // 初始化SM4
    let iv = hex_to_bytes("00000000000000000000000000000000");
    let ka_bytes = hex_to_bytes(ka);
    let mut sm4 = SM4::new();
    sm4.set_key(&ka_bytes, &iv).expect("Failed to set SM4 key");

    // 客户端加密消息
    let client_plaintext = "Hello from Rust Client!";
    let client_ciphertext = sm4.encrypt(client_plaintext).expect("Failed to encrypt");
    println!("Client plaintext: {}", client_plaintext);
    println!("Client ciphertext: {}", client_ciphertext);

    // 发送给服务端
    let crypto_request = CryptoTestRequest {
        session_id: init_response.session_id.clone(),
        client_ciphertext: client_ciphertext.clone(),
        client_plaintext: client_plaintext.to_string(),
    };
    println!("\nRequest: {:?}", serde_json::to_string(&crypto_request).unwrap());

    let crypto_response: CryptoTestResponse =
        ureq::post(&format!("{}/api/crypto/test", SERVER_URL))
            .set("Content-Type", "application/json")
            .send_json(&crypto_request)
            .expect("Failed to send crypto request")
            .into_json()
            .expect("Failed to parse crypto response");
    println!("Response: {:?}", crypto_response);

    // 验证服务端是否正确解密了客户端的消息
    let server_decrypt_ok = crypto_response.client_decrypt_match;
    println!("\n[Server decrypted client message]: {}", if server_decrypt_ok { "PASS" } else { "FAIL" });

    // 客户端解密服务端的消息
    let server_decrypted = sm4.decrypt(&crypto_response.server_ciphertext).expect("Failed to decrypt");
    let client_decrypt_ok = server_decrypted == crypto_response.server_plaintext;
    println!("[Client decrypted server message]: {}", if client_decrypt_ok { "PASS" } else { "FAIL" });
    println!("  Server plaintext: {}", crypto_response.server_plaintext);
    println!("  Client decrypted: {}", server_decrypted);

    if server_decrypt_ok && client_decrypt_ok {
        println!("\nBidirectional Crypto test PASSED!");
    } else {
        eprintln!("\nBidirectional Crypto test FAILED!");
    }

    println!("\n=== Demo Complete ===");
}
