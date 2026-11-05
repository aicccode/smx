// 十六进制编解码。逐字节运算不含按数据分支或查表，因此也可以用于私钥等秘密数据。

import Foundation

enum Hex {
    /// 小写字母与 '9' 之间的偏移（'a' - '9' - 1）
    static let lowercaseGap: Int8 = 39
    /// 大写字母与 '9' 之间的偏移（'A' - '9' - 1）
    static let uppercaseGap: Int8 = 7

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

    /// 把一个大端32位字展开成8个十六进制字符（结果按大端写出）。没有按半字节的比较：
    /// 优化器曾把逐字节的 `(9 - n) >> 7` 写法编译成比较加条件跳转，所以尾部也走这里。
    @inline(__always)
    private static func hexWord(_ word: UInt32, letterGap: UInt64) -> UInt64 {
        var spread = UInt64(word)
        spread = (spread | (spread &<< 16)) & 0x0000_FFFF_0000_FFFF
        spread = (spread | (spread &<< 8)) & 0x00FF_00FF_00FF_00FF
        spread = (spread | (spread &<< 4)) & 0x0F0F_0F0F_0F0F_0F0F
        // 半字节 >= 10 的字节加6后第4位为1
        let letters = ((spread &+ 0x0606_0606_0606_0606) &>> 4) & 0x0101_0101_0101_0101
        return (spread &+ 0x3030_3030_3030_3030 &+ letters &* letterGap).bigEndian
    }

    /// 输出长度必须是输入的两倍。不内联，以便 Tools/check_constant_time.py 检查编译结果。
    @inline(never)
    static func encodeDigits(
        _ input: UnsafePointer<UInt8>, count: Int, into target: UnsafeMutablePointer<UInt8>, gap: Int8
    ) {
        let letterGap = UInt64(truncatingIfNeeded: gap) & 0xFF
        var index = 0
        while index &+ 4 <= count {
            let word = UInt32(bigEndian: UnsafeRawPointer(input + index).loadUnaligned(as: UInt32.self))
            UnsafeMutableRawPointer(target + index &* 2).storeBytes(
                of: hexWord(word, letterGap: letterGap), as: UInt64.self)
            index &+= 4
        }
        // 尾部不足4字节：补0后走同一个转换，再写出需要的字符。循环次数只取决于长度。
        var word: UInt32 = 0
        var position = index
        while position < count {
            word |= UInt32(input[position]) &<< UInt32(truncatingIfNeeded: 24 &- (position &- index) &* 8)
            position &+= 1
        }
        var encoded = hexWord(word, letterGap: letterGap)
        withUnsafeBytes(of: &encoded) { raw in
            var offset = 0
            while offset < (count &- index) &* 2 {
                target[index &* 2 &+ offset] = raw[offset]
                offset &+= 1
            }
        }
    }

    static func encode(_ bytes: UnsafeBufferPointer<UInt8>, gap: Int8 = lowercaseGap) -> String {
        let output = [UInt8](unsafeUninitializedCapacity: bytes.count * 2) { buffer, initialized in
            guard let input = bytes.baseAddress, let target = buffer.baseAddress else {
                initialized = 0
                return
            }
            encodeDigits(input, count: bytes.count, into: target, gap: gap)
            initialized = bytes.count * 2
        }
        return String(decoding: output, as: UTF8.self)
    }

    static func encode(_ bytes: [UInt8], gap: Int8 = lowercaseGap) -> String {
        return bytes.withUnsafeBufferPointer { encode($0, gap: gap) }
    }

    /// 把 utf8 中的十六进制数字解码到 output，返回 false 表示存在非十六进制字符。
    /// 不提前退出。不内联，以便 Tools/check_constant_time.py 检查编译结果。
    @inline(never)
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

    /// 公开数据（签名、密文）的规范形式：本库只输出小写，大写形式不接受，否则同一个值有多种字符串，
    /// 以字符串为键的去重或防重放缓存可以被绕过。长度不合法或含大写时返回 nil。
    static func decodeCanonical(_ hex: String) -> [UInt8]? {
        return containsUppercaseHexLetter(hex) ? nil : decodeStrict(hex)
    }

    static func containsUppercaseHexLetter(_ hex: String) -> Bool {
        return hex.utf8.contains { $0 >= UInt8(ascii: "A") && $0 <= UInt8(ascii: "F") }
    }

    /// 严格解码：只有长度为偶数且全部是 ASCII 十六进制数字（大小写均可）时才返回结果，否则返回 nil。
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

// MARK: - 敏感数据清除与严格解码

/// 尽力清除敏感内存。这个函数不被内联也不被优化，memset 不会被当作死存储删掉。
/// Swift 无法保证没有其它副本（寄存器、栈上的临时值、写时复制留下的旧缓冲区）。
@_optimize(none)
@inline(never)
func secureWipe(_ buffer: UnsafeMutableRawBufferPointer) {
    if let base = buffer.baseAddress, buffer.count > 0 {
        memset(base, 0, buffer.count)
    }
}

func secureWipe<Element>(_ array: inout [Element]) {
    array.withUnsafeMutableBytes { secureWipe($0) }
}

/// 恒定流程的 UTF-8 校验：输入合法时返回 0，否则返回非 0。
///
/// 对每个字节都执行同样的运算，不查表、不提前退出、不按数据分支，耗时只取决于 count。优化器曾把这段掩码运算
/// 编译成按状态的条件跳转，所以这个函数不做优化，也不调用其它函数；速度约为优化版本的几分之一，但不依赖优化器的选择。
/// 规则与标准相同：拒绝过长编码、代理区和 U+10FFFF 以上的值。所有比较的取值都小于 2^31。
@_optimize(none)
@inline(never)
func utf8InvalidMask(_ bytes: UnsafePointer<UInt8>, count: Int) -> UInt32 {
    var need: UInt32 = 0  // 还需要的后续字节数
    var low: UInt32 = 0x80  // 下一个后续字节的范围
    var high: UInt32 = 0xBF
    var bad: UInt32 = 0
    var cursor = bytes
    var remaining = count
    while remaining > 0 {
        let c = UInt32(cursor.pointee)
        // need != 0 时全 1
        let continuing = 0 &- ((need | (0 &- need)) &>> 31)
        // a <= c <= b 时全 1：((c - a) | (b - c)) 的符号位，减 1 后变成掩码
        let inContinuation = (((c &- low) | (high &- c)) &>> 31) &- 1
        let ascii = (((0x7F as UInt32) &- c) &>> 31) &- 1
        let two = (((c &- 0xC2) | (0xDF &- c)) &>> 31) &- 1
        let three = (((c &- 0xE0) | (0xEF &- c)) &>> 31) &- 1
        let four = (((c &- 0xF0) | (0xF4 &- c)) &>> 31) &- 1
        let valid = (continuing & inContinuation) | (~continuing & (ascii | two | three | four))
        bad |= ~valid & 1

        let isE0 = (((c ^ 0xE0) | (0 &- (c ^ 0xE0))) &>> 31) &- 1
        let isF0 = (((c ^ 0xF0) | (0 &- (c ^ 0xF0))) &>> 31) &- 1
        let isED = (((c ^ 0xED) | (0 &- (c ^ 0xED))) &>> 31) &- 1
        let isF4 = (((c ^ 0xF4) | (0 &- (c ^ 0xF4))) &>> 31) &- 1
        let startLow = (isE0 & 0xA0) | (isF0 & 0x90) | (~(isE0 | isF0) & 0x80)
        let startHigh = (isED & 0x9F) | (isF4 & 0x8F) | (~(isED | isF4) & 0xBF)
        need = (continuing & (need &- 1)) | (~continuing & ((two & 1) | (three & 2) | (four & 3)))
        low = (continuing & 0x80) | (~continuing & startLow)
        high = (continuing & 0xBF) | (~continuing & startHigh)

        cursor = cursor.successor()
        remaining = remaining &- 1
    }
    return bad | need
}

/// 严格 UTF-8：输入不是合法 UTF-8 时返回 nil，不做替换修复
func strictUTF8String(_ bytes: [UInt8]) -> String? {
    let invalid = bytes.withUnsafeBufferPointer { buffer -> UInt32 in
        guard let base = buffer.baseAddress else {
            return 0
        }
        return utf8InvalidMask(base, count: buffer.count)
    }
    return invalid == 0 ? String(decoding: bytes, as: UTF8.self) : nil
}
