class Sm4Impl {
    // S 盒
    let STable: [Int8] = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    ]
    
    let FK: [UInt32] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
    
    let CK: [UInt32] = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ]
    
    var rk: [UInt32] = Array(repeating: 0, count: 32)
    var iv: [UInt8] = Array(repeating: 0, count: 16)
    
    func Sbox(_ input: UInt8) -> UInt8 {
        let output = STable[Int(input) & 0xFF]
        return output
    }
    
    func setKey(key: String, iv: String, hex: Bool) -> Sm4Impl {
        if hex {
            setKeyBytes(keyBytes: hex2Bytes(hex: key), ivBytes: hex2Bytes(hex: iv))
        } else {
            setKeyString(keyString: key, ivString: iv)
        }
        return self
    }
    
    func setKeyBytes(keyBytes: [UInt8], ivBytes: [UInt8]) {
        self.initKey(key: keyBytes, iv: ivBytes)
    }
    
    func setKeyString(keyString: String, ivString: String) {
        var key = stringToBytes(text: keyString)
        let sm3 = getSM3()
        if key.count != 16 {
            key = Array(repeating: 0, count: 16)
            let hashKey = sm3.updateString(text: keyString).finish().getHashCode()
            let sm3Bytes = stringToBytes(text: hashKey)
            for i in 0..<sm3Bytes.count {
                key[i] = sm3Bytes[i]
            }
        }
        
        var iv = stringToBytes(text: ivString)
        if iv.count != 16 {
            iv = Array(repeating: 0, count: 16)
            let hashIv = sm3.updateString(text: ivString).finish().getHashCode()
            let sm3Bytes = stringToBytes(text: hashIv)
            for i in 0..<sm3Bytes.count {
                iv[i] = sm3Bytes[i]
            }
        }
        initKey(key: key, iv: iv)
    }
    
    func initKey(key: [UInt8], iv: [UInt8]) {
        var MK: [UInt32] = Array(repeating: 0, count: 4)
        var offset = 0
        for i in 0..<(key.count / 4) {
            MK[i] = (UInt32(key[offset]) & 0xff) << 24 | (UInt32(key[offset + 1]) & 0xff) << 16 | (UInt32(key[offset + 2]) & 0xff) << 8 | UInt32(key[offset + 3]) & 0xff
            offset += 4
        }
        
        var K: [UInt32] = Array(repeating: 0, count: 36)
        K[0] = MK[0] ^ FK[0]
        K[1] = MK[1] ^ FK[1]
        K[2] = MK[2] ^ FK[2]
        K[3] = MK[3] ^ FK[3]
        for i in 0..<32 {
            K[i + 4] = K[i] ^ T_(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i])
            rk[i] = K[i + 4]
        }
        self.iv = Array(iv[0..<16])
    }
    
    func encrypt(text: String) -> String {
        return doCrypt(input: stringToBytes(text: text), cbcIV: Array(iv), encrypt: true)
    }
    
    func decrypt(text: String) -> String {
        return doCrypt(input: hex2Bytes(hex: text), cbcIV: Array(iv), encrypt: false)
    }
    
    func doCrypt(input: [UInt8], cbcIV: [UInt8], encrypt: Bool) -> String {
        var input = input
        if encrypt {
            input = fixInput(input: input)
        }
        var out: [UInt8] = []
        var offset = 0
        for _ in 0..<(input.count / 16) {
            var X: [UInt32] = Array(repeating: 0, count: 36)
            let nextiv = Array(input[offset..<(offset + 16)])
            for i in 0..<4 {
                if encrypt {
                    X[i] = ((UInt32(input[offset]) ^ UInt32(cbcIV[offset % 16])) & 0xff) << 24 | ((UInt32(input[offset + 1]) ^ UInt32(cbcIV[offset % 16])) & 0xff) << 16 | ((UInt32(input[offset + 2]) ^ UInt32(cbcIV[offset % 16])) & 0xff) << 8 | (UInt32(input[offset + 3]) ^ UInt32(cbcIV[offset % 16])) & 0xff
                } else {
                    X[i] = (UInt32(input[offset]) & 0xff) << 24 | (UInt32(input[offset + 1]) & 0xff) << 16 | (UInt32(input[offset + 2]) & 0xff) << 8 | UInt32(input[offset + 3]) & 0xff
                }
                offset += 4
            }
            for i in 0..<32 {
                X[i + 4] = F(x0: X[i], x1: X[i + 1], x2: X[i + 2], x3: X[i + 3], rk: encrypt ? rk[i] : rk[31 - i])
            }
            let XO = Array(X[32..<36])
            let XRO = R(A: XO)
            var XBO: [UInt8] = []
            var index = 0
            for i in 0..<4 {
                XBO.append(limitToSignedByte(i: (XRO[i] >> 24) & 0xff))
                XBO.append(limitToSignedByte(i: (XRO[i] >> 16) & 0xff))
                XBO.append(limitToSignedByte(i: (XRO[i] >> 8) & 0xff))
                XBO.append(limitToSignedByte(i: XRO[i] & 0xff))
                index += 1
            }
            if encrypt {
                cbcIV = Array(XBO[0..<16])
            } else {
                for i in 0..<XBO.count {
                    XBO[i] ^= cbcIV[i]
                }
                cbcIV = Array(nextiv[0..<16])
            }
            out.append(contentsOf: XBO)
        }
        if encrypt {
            return bytes2Hex(bytes: out, upperCase: false)
        } else {
            let bs = out
            return bytesToUTF8String(bytes: Array(bs[0..<(bs.count - Int(bs[bs.count - 1]))]))
        }
    }
    
    func F(x0: UInt32, x1: UInt32, x2: UInt32, x3: UInt32, rk: UInt32) -> UInt32 {
        return x0 ^ T(a: x1 ^ x2 ^ x3 ^ rk)
    }
    
    func T(a: UInt32) -> UInt32 {
        var abs = self.int2Bytes(n: a)
        for i in 0..<abs.count {
            abs[i] = Sbox(abs[i])
        }
        let b = bytes2Int(bytes: abs)
        return b ^ ((b << 2) | (b >> (32 - 2))) ^ ((b << 10) | (b >> (32 - 10))) ^ ((b << 18) | (b >> (32 - 18))) ^ ((b << 24) | (b >> (32 - 24)))
    }
    
    func T_(a: UInt32) -> UInt32 {
        var abs = self.int2Bytes(n: a)
        for i in 0..<abs.count {
            abs[i] = Sbox(abs[i])
        }
        let b = bytes2Int(bytes: abs)
        return b ^ ((b << 13) | (b >> (32 - 13))) ^ ((b << 23) | (b >> (32 - 23)))
    }
    
    func R(A: [UInt32]) -> [UInt32] {
        var A = A
        A[0] = A[0] ^ A[3]
        A[3] = A[0] ^ A[3]
        A[0] = A[0] ^ A[3]
        A[1] = A[1] ^ A[2]
        A[2] = A[1] ^ A[2]
        A[1] = A[1] ^ A[2]
        return A
    }
    
    func fixInput(input: [UInt8]) -> [UInt8] {
        let t = 16 - input.count % 16
        var out = Array(repeating: UInt8(t), count: t)
        return input + out
    }
    
    func bytesToUTF8String(bytes: [UInt8]) -> String {
        let uint8Array = bytes
        let decoder = String(bytes: uint8Array, encoding: .utf8)
        return decoder ?? ""
    }

    func stringToBytes(text: String) -> [UInt8] {
        let code = text.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        var bytes: [UInt8] = []
        var i = code.startIndex
        while i < code.endIndex {
            let c = code[i]
            if c == "%" {
                let hex = code[code.index(after: i)...code.index(i, offsetBy: 2)]
                if let hexVal = UInt8(hex, radix: 16) {
                    bytes.append(hexVal)
                }
                i = code.index(i, offsetBy: 3)
            } else {
                bytes.append(UInt8(c.asciiValue ?? 0))
                i = code.index(after: i)
            }
        }
        return bytes
    }

    let HEX_ARRAY = [..."0123456789ABCDEF"]

    func bytes2Hex(bytes: [UInt8], upperCase: Bool) -> String {
        var hexChars: [String] = []
        for j in 0..<bytes.count {
            let v = bytes[j] & 0xFF
            hexChars.append(HEX_ARRAY[Int(v) >> 4])
            hexChars.append(HEX_ARRAY[Int(v) & 0x0F])
        }
        return hexChars.joined(separator: "").lowercased()
    }

    func hex2Bytes( hex: String) -> [Int8] {
        var bytes = [Int8]()
        let length = hex.count
        if length & 1 != 0 {
            return bytes
        }
        bytes.reserveCapacity(length/2)
        var index = hex.startIndex
        for _ in 0..<length/2 {
            let nextIndex = hex.index(index, offsetBy: 2)
            if let b = UInt8(hex[index..<nextIndex], radix: 16) {
                bytes.append(limitToSignedByte(i: Int(b)))
            } else {
                return bytes
            }
            index = nextIndex
        }
        return bytes
    }

    func bytes2Int(bytes: [UInt8]) -> UInt32 {
        let n = (UInt32(bytes[0]) & 0xff) << 24 | (UInt32(bytes[1]) & 0xff) << 16 | (UInt32(bytes[2]) & 0xff) << 8 | UInt32(bytes[3]) & 0xff
        return n
    }

    func limitToSignedByte(i: Int) -> UInt8 {
        let b = i & 0xFF
        var c = 0
        if b >= 128 {
            c = b % 128
            c = -1 * (128 - c)
        } else {
            c = b
        }
        return UInt8(c)
    }

    func int2Bytes(n: UInt32) -> [UInt8] {
        var b: [UInt8] = Array(repeating: 0, count: 4)
        b[0] = UInt8(0xFF & n >> 24)
        b[1] = UInt8(0xFF & n >> 16)
        b[2] = UInt8(0xFF & n >> 8)
        b[3] = UInt8(0xFF & n)
        return b
    }
}



