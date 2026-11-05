// 十六进制编解码。逐字节运算不含按数据分支或查表，因此也可以用于私钥等秘密数据。

enum Hex {
    /// 小写字母与 '9' 之间的偏移（'a' - '9' - 1）
    static let lowercaseGap: Int8 = 39
    /// 大写字母与 '9' 之间的偏移（'A' - '9' - 1）
    static let uppercaseGap: Int8 = 7

    @inline(__always)
    private static func digit(_ nibble: UInt8, gap: Int8) -> UInt8 {
        let value = Int8(truncatingIfNeeded: nibble)
        // value > 9 时 (9 - value) 为负，算术右移后得到全 1 掩码
        let letterMask = (9 &- value) &>> 7
        return UInt8(truncatingIfNeeded: value &+ 48 &+ (letterMask & gap))
    }

    /// 取值 0...15，非十六进制字符返回负数。
    @inline(__always)
    private static func value(_ char: UInt8) -> Int16 {
        let c = Int16(char)
        let decimal = c &- 48
        let letter = (c | 0x20) &- 87
        let decimalMask = ~((decimal | (9 &- decimal)) &>> 15)
        let letterMask = ~(((letter &- 10) | (15 &- letter)) &>> 15)
        return (decimal & decimalMask) | (letter & letterMask) | ~(decimalMask | letterMask)
    }

    static func encode(_ bytes: UnsafeBufferPointer<UInt8>, gap: Int8 = lowercaseGap) -> String {
        let output = [UInt8](unsafeUninitializedCapacity: bytes.count * 2) { buffer, initialized in
            guard let input = bytes.baseAddress, let target = buffer.baseAddress else {
                initialized = 0
                return
            }
            // 每次处理4字节（SWAR）：把32位展开成8个半字节，再统一转成 ASCII
            let letterGap = UInt64(truncatingIfNeeded: gap) & 0xFF
            var index = 0
            while index &+ 4 <= bytes.count {
                let word = UnsafeRawPointer(input + index).loadUnaligned(as: UInt32.self)
                var spread = UInt64(UInt32(bigEndian: word))
                spread = (spread | (spread &<< 16)) & 0x0000_FFFF_0000_FFFF
                spread = (spread | (spread &<< 8)) & 0x00FF_00FF_00FF_00FF
                spread = (spread | (spread &<< 4)) & 0x0F0F_0F0F_0F0F_0F0F
                // 半字节 >= 10 的字节加6后第4位为1
                let letters = ((spread &+ 0x0606_0606_0606_0606) &>> 4) & 0x0101_0101_0101_0101
                let ascii = spread &+ 0x3030_3030_3030_3030 &+ letters &* letterGap
                UnsafeMutableRawPointer(target + index &* 2).storeBytes(of: ascii.bigEndian, as: UInt64.self)
                index &+= 4
            }
            while index < bytes.count {
                let byte = input[index]
                target[index &* 2] = digit(byte &>> 4, gap: gap)
                target[index &* 2 &+ 1] = digit(byte & 0x0F, gap: gap)
                index &+= 1
            }
            initialized = bytes.count * 2
        }
        return String(decoding: output, as: UTF8.self)
    }

    static func encode(_ bytes: [UInt8], gap: Int8 = lowercaseGap) -> String {
        return bytes.withUnsafeBufferPointer { encode($0, gap: gap) }
    }

    /// 把 utf8 中的十六进制数字解码到 output，返回 false 表示存在非十六进制字符。
    @inline(__always)
    static func decode(
        _ utf8: UnsafeBufferPointer<UInt8>, into output: UnsafeMutablePointer<UInt8>
    ) -> Bool {
        var seen: Int16 = 0
        for index in 0..<(utf8.count / 2) {
            let high = value(utf8[index &* 2])
            let low = value(utf8[index &* 2 &+ 1])
            seen |= high | low
            output[index] = UInt8(truncatingIfNeeded: (high &<< 4) | low)
        }
        return seen >= 0
    }

    /// 严格解码：只有长度为偶数且全部是 ASCII 十六进制数字时才返回结果。
    /// 返回 nil 时由调用方走原有的按 Character 解析的路径，以保持对非常规输入的既有行为。
    static func decodeStrict(_ hex: String) -> [UInt8]? {
        var hex = hex
        return hex.withUTF8 { utf8 -> [UInt8]? in
            if utf8.count % 2 != 0 {
                return nil
            }
            var valid = false
            let bytes = [UInt8](unsafeUninitializedCapacity: utf8.count / 2) { buffer, initialized in
                if let base = buffer.baseAddress {
                    valid = decode(utf8, into: base)
                } else {
                    valid = true
                }
                initialized = utf8.count / 2
            }
            return valid ? bytes : nil
        }
    }
}
