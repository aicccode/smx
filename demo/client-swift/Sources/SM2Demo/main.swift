// SM2 密钥交换Demo客户端 - Swift版
// 作为A侧与Java服务端(B侧)进行密钥交换

import Foundation
import GMSwift

// 这是演示代码。它用明文 HTTP 通信，并且为了和 Java 服务端的协议保持一致使用全 0 的 SM4 IV，
// 真实系统必须使用 TLS，并且为每条消息使用新的随机 IV。CBC 本身不提供完整性。
//
// 服务端身份：pB 和 IDb 来自同一个未经认证的响应，冒充者可以用自己的密钥通过密钥确认并读取通信内容。
// 设置环境变量 SM2_DEMO_SERVER_PUBKEY（服务端公钥的十六进制）后，pB 不同就是硬失败。

let serverURL = "http://localhost:8080"
let clientId = "swift-client@demo.aicc"

// MARK: - JSON Models
// 字段名就是服务端 JSON 协议的键名，不能按命名规范修改

// swift-format-ignore: AlwaysUseLowerCamelCase
struct InitRequest: Encodable {
    let IDa: String
    let pA: String
    let Ra: String
    let keyLen: Int
}

// swift-format-ignore: AlwaysUseLowerCamelCase
struct InitResponse: Decodable {
    let sessionId: String
    let IDb: String
    let pB: String
    let Rb: String
    let Sb: String
}

// swift-format-ignore: AlwaysUseLowerCamelCase
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

/// 响应上限，防止服务端返回无限长的数据
let maximumResponseBytes = 1 << 20
/// 每个请求的总期限（秒），不是单次读取的超时：缓慢滴送数据的服务端同样会被中止
let requestDeadlineSeconds = 30

/// 服务端的任何文本都不可信：去掉控制字符（包括转义序列的起始字符和双向控制符），并限制长度，然后才能打印。
func sanitized(_ text: String) -> String {
    var scalars = String.UnicodeScalarView()
    var count = 0
    for scalar in text.unicodeScalars {
        if count >= 300 {
            scalars.append(contentsOf: "...".unicodeScalars)
            break
        }
        let value = scalar.value
        let control =
            value < 0x20 || (0x7F...0x9F).contains(value) || (0x200E...0x200F).contains(value)
            || (0x2028...0x202E).contains(value) || (0x2066...0x2069).contains(value)
        scalars.append(control ? "?" : scalar)
        count += 1
    }
    return String(scalars)
}

/// 打印服务端文本（或包含服务端文本的错误）的唯一入口
func printServer(_ label: String, _ text: String) {
    print("\(label)\(sanitized(text))")
}

/// 没有设置时返回 nil 并打印警告；设置了但不是合法公钥时直接失败。
func pinnedServerKey() -> ECPoint? {
    guard let pinned = ProcessInfo.processInfo.environment["SM2_DEMO_SERVER_PUBKEY"], !pinned.isEmpty else {
        print("WARNING: the server is UNAUTHENTICATED. Anyone on the network path can impersonate it and read this")
        print("         traffic. Set SM2_DEMO_SERVER_PUBKEY to the server public key to detect that.")
        return nil
    }
    let point = ECPoint.fromHexEncoded(pinned)
    if point.isInfinity {
        print("SM2_DEMO_SERVER_PUBKEY is not a valid public key")
        exit(1)
    }
    print("Server public key is pinned by SM2_DEMO_SERVER_PUBKEY")
    return point
}

func postJSON<T: Encodable, R: Decodable>(_ url: String, body: T) throws -> R {
    let jsonData = try JSONEncoder().encode(body)

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
    // 请求体走标准输入，不放在命令行上：其它用户可以通过进程列表看到命令行。
    process.arguments = [
        "-s", "-X", "POST",
        "--max-time", String(requestDeadlineSeconds),
        "--max-filesize", String(maximumResponseBytes),
        "-H", "Content-Type: application/json",
        "--data-binary", "@-",
        url,
    ]

    let input = Pipe()
    let output = Pipe()
    process.standardInput = input
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice

    // 写入时 curl 可能已经退出；SIGPIPE 不能杀死进程，下面按响应为空处理
    signal(SIGPIPE, SIG_IGN)
    try process.run()
    input.fileHandleForWriting.write(jsonData)
    input.fileHandleForWriting.closeFile()

    var data = Data()
    while data.count <= maximumResponseBytes {
        let chunk = output.fileHandleForReading.availableData
        if chunk.isEmpty {
            break
        }
        data.append(chunk)
    }
    if data.count > maximumResponseBytes {
        process.terminate()
    }
    process.waitUntilExit()

    if data.isEmpty || data.count > maximumResponseBytes {
        throw NSError(
            domain: "SM2Demo", code: 1, userInfo: [NSLocalizedDescriptionKey: "No valid response from server"])
    }

    return try JSONDecoder().decode(R.self, from: data)
}

/// 严格的十六进制解码，长度为奇数或含有其它字符时返回 nil。这个输入来自网络。
func hexToBytes(_ hex: String) -> [UInt8]? {
    let digits = Array(hex.utf8)
    guard digits.count % 2 == 0 else {
        return nil
    }
    var bytes = [UInt8]()
    bytes.reserveCapacity(digits.count / 2)
    for index in stride(from: 0, to: digits.count, by: 2) {
        guard let high = hexValue(digits[index]), let low = hexValue(digits[index + 1]) else {
            return nil
        }
        bytes.append(high << 4 | low)
    }
    return bytes
}

func hexValue(_ digit: UInt8) -> UInt8? {
    switch digit {
    case UInt8(ascii: "0")...UInt8(ascii: "9"): return digit - UInt8(ascii: "0")
    case UInt8(ascii: "a")...UInt8(ascii: "f"): return digit - UInt8(ascii: "a") + 10
    case UInt8(ascii: "A")...UInt8(ascii: "F"): return digit - UInt8(ascii: "A") + 10
    default: return nil
    }
}

// MARK: - Main

func main() {
    print("=== SM2 Key Exchange Demo (Swift Client) ===\n")
    let pinnedKey = pinnedServerKey()

    // 生成A侧(客户端)证书密钥对
    let (daHex, paHex) = SM2.genKeyPair()
    guard !daHex.isEmpty else {
        print("System random generator failed")
        exit(1)
    }
    print("Generated A certificate keypair:")
    print("  Public key (pA): \(paHex)")

    // 生成A侧随机密钥对
    let (raHex, raPubHex) = SM2.genKeyPair()
    guard !raHex.isEmpty else {
        print("System random generator failed")
        exit(1)
    }
    print("\nGenerated A random keypair:")
    print("  Public key (Ra): \(raPubHex)")

    let keyLen = 16  // 16字节 = 128位密钥

    // Step 1: 发起密钥交换
    print("\n--- Step 1: Key Exchange Init ---")
    let initRequest = InitRequest(
        IDa: clientId,
        pA: paHex,
        Ra: raPubHex,
        keyLen: keyLen
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = .prettyPrinted
    if let jsonData = try? encoder.encode(initRequest),
        let jsonString = String(data: jsonData, encoding: .utf8)
    {
        print("Request: \(jsonString)")
    }

    let initResponse: InitResponse
    do {
        initResponse = try postJSON("\(serverURL)/api/keyswap/init", body: initRequest)
        printServer("Response: sessionId=", initResponse.sessionId)
        printServer("  IDb: ", initResponse.IDb)
        printServer("  pB: ", initResponse.pB)
        printServer("  Rb: ", initResponse.Rb)
        printServer("  Sb: ", initResponse.Sb)
    } catch {
        printServer("Failed to connect to server: ", "\(error)")
        print("Make sure the Java server is running on port 8080")
        exit(1)
    }

    // Step 2: 计算Sa和Ka
    print("\n--- Step 2: Calculate Sa and Ka ---")

    let pB = ECPoint.fromHexEncoded(initResponse.pB)
    if let pinnedKey = pinnedKey, pB.isInfinity || pB != pinnedKey {
        print("Server public key does not match SM2_DEMO_SERVER_PUBKEY: refusing to continue")
        exit(1)
    }
    let pointRb = ECPoint.fromHexEncoded(initResponse.Rb)
    let pA = ECPoint.fromHexEncoded(paHex)
    let pointRa = ECPoint.fromHexEncoded(raPubHex)
    let dA = BigInt256.fromHex(daHex)
    let ra = BigInt256.fromHex(raHex)
    guard let sbBytes = hexToBytes(initResponse.Sb) else {
        print("Server returned a malformed Sb")
        exit(1)
    }

    let result = SM2.getSa(
        byteLen: keyLen,
        pB: pB, Rb: pointRb,
        pA: pA, dA: dA, Ra: pointRa, ra: ra,
        IDa: clientId, IDb: initResponse.IDb,
        Sb: sbBytes
    )

    guard result.success, let sa = result.sa, let ka = result.ka else {
        printServer("getSa failed: ", result.message ?? "unknown error")
        exit(1)
    }

    print("Sa: \(sa)")
    print("Negotiated a \(keyLen)-byte session key")

    // Step 3: 确认密钥交换
    print("\n--- Step 3: Key Exchange Confirm ---")
    let confirmRequest = ConfirmRequest(
        sessionId: initResponse.sessionId,
        Sa: sa
    )

    if let jsonData = try? encoder.encode(confirmRequest),
        let jsonString = String(data: jsonData, encoding: .utf8)
    {
        print("Request: \(jsonString)")
    }

    do {
        let confirmResponse: ConfirmResponse = try postJSON("\(serverURL)/api/keyswap/confirm", body: confirmRequest)
        print("Response: success=\(confirmResponse.success)")

        if !confirmResponse.success {
            print("Key exchange confirmation failed")
            exit(1)
        }
    } catch {
        printServer("Confirm request failed: ", "\(error)")
        exit(1)
    }

    print("\nKey exchange completed successfully!")

    // Step 4: 双向加密通信测试
    print("\n--- Step 4: Bidirectional Crypto Test ---")

    // 初始化SM4
    let iv = "00000000000000000000000000000000"
    let sm4: Sm4Impl
    let clientCiphertext: String
    let clientPlaintext = "Hello from Swift Client!"
    do {
        sm4 = try getSM4().setKeyChecked(key: ka, iv: iv, hex: true)
        clientCiphertext = try sm4.encryptChecked(text: clientPlaintext)
    } catch {
        print("SM4 setup failed: \(error)")
        exit(1)
    }

    // 客户端加密消息
    print("Client plaintext: \(clientPlaintext)")
    print("Client ciphertext: \(clientCiphertext)")

    // 发送给服务端
    let cryptoRequest = CryptoTestRequest(
        sessionId: initResponse.sessionId,
        clientCiphertext: clientCiphertext,
        clientPlaintext: clientPlaintext
    )

    if let jsonData = try? encoder.encode(cryptoRequest),
        let jsonString = String(data: jsonData, encoding: .utf8)
    {
        print("\nRequest: \(jsonString)")
    }

    do {
        let cryptoResponse: CryptoTestResponse = try postJSON("\(serverURL)/api/crypto/test", body: cryptoRequest)
        print("Response:")
        printServer("  clientDecrypted: ", cryptoResponse.clientDecrypted)
        print("  clientDecryptMatch: \(cryptoResponse.clientDecryptMatch)")
        printServer("  serverPlaintext: ", cryptoResponse.serverPlaintext)
        printServer("  serverCiphertext: ", cryptoResponse.serverCiphertext)

        // 验证服务端是否正确解密了客户端的消息
        let serverDecryptOk = cryptoResponse.clientDecryptMatch
        print("\n[Server decrypted client message]: \(serverDecryptOk ? "PASS" : "FAIL")")

        // 客户端解密服务端的消息
        let serverDecrypted = try sm4.decryptChecked(text: cryptoResponse.serverCiphertext)
        let clientDecryptOk = serverDecrypted == cryptoResponse.serverPlaintext
        print("[Client decrypted server message]: \(clientDecryptOk ? "PASS" : "FAIL")")
        printServer("  Server plaintext: ", cryptoResponse.serverPlaintext)
        printServer("  Client decrypted: ", serverDecrypted)

        if serverDecryptOk && clientDecryptOk {
            print("\nBidirectional Crypto test PASSED!")
        } else {
            print("\nBidirectional Crypto test FAILED!")
            exit(1)
        }
    } catch {
        printServer("Crypto test failed: ", "\(error)")
        exit(1)
    }

    print(pinnedKey == nil ? "\n=== Demo Complete (server identity NOT verified) ===" : "\n=== Demo Complete ===")
}

main()
