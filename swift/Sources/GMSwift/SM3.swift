class SM3 {
    // 初始IV常量
    private static let IV: [UInt32] = [
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    ]
    
    private var buffer: [UInt8] = Array(repeating: 0, count: 64)
    private var bufferOffset = 0
    private var byteCount = 0
    private var V: [UInt32] = IV
    
    private var hashValue: String = ""
    private var hashBytes: [UInt8] = []
    
    func update(_ data: [UInt8]) -> SM3 {
        for byte in data {
            buffer[bufferOffset] = byte
            bufferOffset += 1
            byteCount += 1
            
            if bufferOffset == 64 {
                processBlock()
                bufferOffset = 0
            }
        }
        return self
    }
    
    func update(_ string: String) -> SM3 {
        return update(Array(string.utf8))
    }
    
    func finalize() -> SM3 {
        // 填充消息
        let bitLength = byteCount * 8
        buffer[bufferOffset] = 0x80
        bufferOffset += 1
        
        if bufferOffset > 56 {
            // 填充0直到块结束
            while bufferOffset < 64 {
                buffer[bufferOffset] = 0
                bufferOffset += 1
            }
            processBlock()
            bufferOffset = 0
        }
        
        // 填充0直到56字节
        while bufferOffset < 56 {
            buffer[bufferOffset] = 0
            bufferOffset += 1
        }
        
        // 添加消息长度(64位)
        for i in 0..<8 {
            buffer[56 + i] = UInt8(truncatingIfNeeded: bitLength >> (56 - i * 8))
        }
        processBlock()
        
        // 生成哈希值
        var result = ""
        for i in 0..<8 {
            let word = V[i]
            let hex = String(word, radix: 16, uppercase: false)
            result += String(repeating: "0", count: 8 - hex.count) + hex
        }
        hashValue = result.uppercased()
        return self
    }
    
    func getHash() -> String {
        return hashValue
    }
    
    private func processBlock() {
        var W = [UInt32](repeating: 0, count: 68)
        var W1 = [UInt32](repeating: 0, count: 64)
        
        // 消息扩展
        for i in 0..<16 {
            W[i] = (UInt32(buffer[i * 4]) & 0xff) << 24 |
                   (UInt32(buffer[i * 4 + 1]) & 0xff) << 16 |
                   (UInt32(buffer[i * 4 + 2]) & 0xff) << 8 |
                   (UInt32(buffer[i * 4 + 3]) & 0xff)
        }
        
        for i in 16..<68 {
            let wj3 = W[i-3]
            let r15 = rotateLeft(wj3, 15)
            let wj13 = W[i-13]
            let r7 = rotateLeft(wj13, 7)
            W[i] = P1(W[i-16] ^ W[i-9] ^ r15) ^ r7 ^ W[i-6]
        }
        
        for i in 0..<64 {
            W1[i] = W[i] ^ W[i+4]
        }
        
        // 压缩函数
        var A = V[0]
        var B = V[1]
        var C = V[2]
        var D = V[3]
        var E = V[4]
        var F = V[5]
        var G = V[6]
        var H = V[7]
        
        for j in 0..<64 {
            let A12 = rotateLeft(A, 12)
            let T_j = j < 16 ? rotateLeft(0x79CC4519, j) : rotateLeft(0x7A879D8A, j % 32)
            let S_S = A12 &+ E &+ T_j
            let SS1 = rotateLeft(S_S, 7)
            let SS2 = SS1 ^ A12
            
            let TT1: UInt32
            let TT2: UInt32
            
            if j < 16 {
                TT1 = (A ^ B ^ C) &+ D &+ SS2 &+ W1[j]
                TT2 = (E ^ F ^ G) &+ H &+ SS1 &+ W[j]
            } else {
                TT1 = ((A & B) | (A & C) | (B & C)) &+ D &+ SS2 &+ W1[j]
                TT2 = ((E & F) | (~E & G)) &+ H &+ SS1 &+ W[j]
            }
            
            D = C
            C = rotateLeft(B, 9)
            B = A
            A = TT1
            H = G
            G = rotateLeft(F, 19)
            F = E
            E = P0(TT2)
        }
        
        V[0] ^= A
        V[1] ^= B
        V[2] ^= C
        V[3] ^= D
        V[4] ^= E
        V[5] ^= F
        V[6] ^= G
        V[7] ^= H
    }
    
    private func T(_ j: Int) -> UInt32 {
        return j < 16 ? 0x79CC4519 : 0x7A879D8A
    }
    
    private func rotateLeft(_ x: UInt32, _ n: Int) -> UInt32 {
        return (x << n) | (x >> (32 - n))
    }
    
    private func P0(_ x: UInt32) -> UInt32 {
        return x ^ rotateLeft(x, 9) ^ rotateLeft(x, 17)
    }
    
    private func P1(_ x: UInt32) -> UInt32 {
        return x ^ rotateLeft(x, 15) ^ rotateLeft(x, 23)
    }
    
    private func FF0(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        return x ^ y ^ z
    }
    
    private func FF1(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        return (x & y) | (x & z) | (y & z)
    }
    
    private func GG0(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        return x ^ y ^ z
    }
    
    private func GG1(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 {
        return (x & y) | (~x & z)
    }
}

func getSM3() -> SM3 {
    return SM3()
}
