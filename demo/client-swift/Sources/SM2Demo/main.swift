// SM2 密钥交换Demo客户端 - Swift版
// 作为A侧与Java服务端(B侧)进行密钥交换

import Foundation
import GMSwift

let SERVER_URL = "http://localhost:8080"
let IDA = "swift-client@demo.aicc"

// MARK: - JSON Models

struct InitRequest: Encodable {
    let IDa: String
    let pA: String
    let Ra: String
    let keyLen: Int
}

struct InitResponse: Decodable {
    let sessionId: String
    let IDb: String
    let pB: String
    let Rb: String
    let Sb: String
}

struct ConfirmRequest: Encodable {
    let sessionId: String
    let Sa: String
}

struct ConfirmResponse: Decodable {
    let success: Bool
}

struct CryptoTestRequest: Encodable {
    let sessionId: String
    let clientCiphertext: String
    let clientPlaintext: String
}

struct CryptoTestResponse: Decodable {
    let clientDecrypted: String
    let clientDecryptMatch: Bool
    let serverPlaintext: String
    let serverCiphertext: String
}

// MARK: - HTTP helpers using curl

func postJSON<T: Encodable, R: Decodable>(_ url: String, body: T) throws -> R {
    let jsonData = try JSONEncoder().encode(body)
    let jsonString = String(data: jsonData, encoding: .utf8)!

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
    process.arguments = [
        "-s", "-X", "POST",
        "-H", "Content-Type: application/json",
        "-d", jsonString,
        url
    ]

    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice

    try process.run()
    process.waitUntilExit()

    let data = pipe.fileHandleForReading.readDataToEndOfFile()

    if data.isEmpty {
        throw NSError(domain: "SM2Demo", code: 1, userInfo: [NSLocalizedDescriptionKey: "No response from server"])
    }

    return try JSONDecoder().decode(R.self, from: data)
}

func hexToBytes(_ hex: String) -> [UInt8] {
    var bytes = [UInt8]()
    var index = hex.startIndex
    while index < hex.endIndex {
        let nextIndex = hex.index(index, offsetBy: 2)
        let byteString = String(hex[index..<nextIndex])
        if let byte = UInt8(byteString, radix: 16) {
            bytes.append(byte)
        }
        index = nextIndex
    }
    return bytes
}

// MARK: - Main

func main() {
    print("=== SM2 Key Exchange Demo (Swift Client) ===\n")

    // 生成A侧(客户端)证书密钥对
    let (daHex, paHex) = SM2.genKeyPair()
    print("Generated A certificate keypair:")
    print("  Private key (dA): \(daHex)")
    print("  Public key (pA): \(paHex)")

    // 生成A侧随机密钥对
    let (raHex, raPubHex) = SM2.genKeyPair()
    print("\nGenerated A random keypair:")
    print("  Private key (ra): \(raHex)")
    print("  Public key (Ra): \(raPubHex)")

    let keyLen = 16 // 16字节 = 128位密钥

    // Step 1: 发起密钥交换
    print("\n--- Step 1: Key Exchange Init ---")
    let initRequest = InitRequest(
        IDa: IDA,
        pA: paHex,
        Ra: raPubHex,
        keyLen: keyLen
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = .prettyPrinted
    if let jsonData = try? encoder.encode(initRequest),
       let jsonString = String(data: jsonData, encoding: .utf8) {
        print("Request: \(jsonString)")
    }

    let initResponse: InitResponse
    do {
        initResponse = try postJSON("\(SERVER_URL)/api/keyswap/init", body: initRequest)
        print("Response: sessionId=\(initResponse.sessionId), IDb=\(initResponse.IDb)")
        print("  pB: \(initResponse.pB)")
        print("  Rb: \(initResponse.Rb)")
        print("  Sb: \(initResponse.Sb)")
    } catch {
        print("Failed to connect to server: \(error)")
        print("Make sure the Java server is running on port 8080")
        exit(1)
    }

    // Step 2: 计算Sa和Ka
    print("\n--- Step 2: Calculate Sa and Ka ---")

    let pB = ECPoint.fromHexEncoded(initResponse.pB)
    let Rb = ECPoint.fromHexEncoded(initResponse.Rb)
    let pA = ECPoint.fromHexEncoded(paHex)
    let Ra = ECPoint.fromHexEncoded(raPubHex)
    let dA = BigInt256.fromHex(daHex)
    let ra = BigInt256.fromHex(raHex)
    let sbBytes = hexToBytes(initResponse.Sb)

    let result = SM2.getSa(
        byteLen: keyLen,
        pB: pB, Rb: Rb,
        pA: pA, dA: dA, Ra: Ra, ra: ra,
        IDa: IDA, IDb: initResponse.IDb,
        Sb: sbBytes
    )

    guard result.success, let sa = result.sa, let ka = result.ka else {
        print("getSa failed: \(result.message ?? "unknown error")")
        exit(1)
    }

    print("Sa: \(sa)")
    print("Ka (negotiated key): \(ka)")

    // Step 3: 确认密钥交换
    print("\n--- Step 3: Key Exchange Confirm ---")
    let confirmRequest = ConfirmRequest(
        sessionId: initResponse.sessionId,
        Sa: sa
    )

    if let jsonData = try? encoder.encode(confirmRequest),
       let jsonString = String(data: jsonData, encoding: .utf8) {
        print("Request: \(jsonString)")
    }

    do {
        let confirmResponse: ConfirmResponse = try postJSON("\(SERVER_URL)/api/keyswap/confirm", body: confirmRequest)
        print("Response: success=\(confirmResponse.success)")

        if !confirmResponse.success {
            print("Key exchange confirmation failed")
            exit(1)
        }
    } catch {
        print("Confirm request failed: \(error)")
        exit(1)
    }

    print("\nKey exchange completed successfully!")
    print("Negotiated key (Ka): \(ka)")

    // Step 4: 双向加密通信测试
    print("\n--- Step 4: Bidirectional Crypto Test ---")

    // 初始化SM4
    let iv = "00000000000000000000000000000000"
    let sm4 = getSM4().setKey(key: ka, iv: iv, hex: true)

    // 客户端加密消息
    let clientPlaintext = "Hello from Swift Client!"
    let clientCiphertext = sm4.encrypt(text: clientPlaintext)
    print("Client plaintext: \(clientPlaintext)")
    print("Client ciphertext: \(clientCiphertext)")

    // 发送给服务端
    let cryptoRequest = CryptoTestRequest(
        sessionId: initResponse.sessionId,
        clientCiphertext: clientCiphertext,
        clientPlaintext: clientPlaintext
    )

    if let jsonData = try? encoder.encode(cryptoRequest),
       let jsonString = String(data: jsonData, encoding: .utf8) {
        print("\nRequest: \(jsonString)")
    }

    do {
        let cryptoResponse: CryptoTestResponse = try postJSON("\(SERVER_URL)/api/crypto/test", body: cryptoRequest)
        print("Response:")
        print("  clientDecrypted: \(cryptoResponse.clientDecrypted)")
        print("  clientDecryptMatch: \(cryptoResponse.clientDecryptMatch)")
        print("  serverPlaintext: \(cryptoResponse.serverPlaintext)")
        print("  serverCiphertext: \(cryptoResponse.serverCiphertext)")

        // 验证服务端是否正确解密了客户端的消息
        let serverDecryptOk = cryptoResponse.clientDecryptMatch
        print("\n[Server decrypted client message]: \(serverDecryptOk ? "PASS" : "FAIL")")

        // 客户端解密服务端的消息
        let serverDecrypted = sm4.decrypt(text: cryptoResponse.serverCiphertext)
        let clientDecryptOk = serverDecrypted == cryptoResponse.serverPlaintext
        print("[Client decrypted server message]: \(clientDecryptOk ? "PASS" : "FAIL")")
        print("  Server plaintext: \(cryptoResponse.serverPlaintext)")
        print("  Client decrypted: \(serverDecrypted)")

        if serverDecryptOk && clientDecryptOk {
            print("\nBidirectional Crypto test PASSED!")
        } else {
            print("\nBidirectional Crypto test FAILED!")
        }
    } catch {
        print("Crypto test failed: \(error)")
        exit(1)
    }

    print("\n=== Demo Complete ===")
}

main()
