// 256位无符号整数实现（使用4个UInt64存储，小端序）

import Foundation

public struct BigInt256: Comparable {
    var limbs: (UInt64, UInt64, UInt64, UInt64) // 小端序：limbs.0是最低64位

    public static let zero = BigInt256(limbs: (0, 0, 0, 0))
    public static let one = BigInt256(limbs: (1, 0, 0, 0))

    // 手动实现Equatable，因为元组不自动conformEquatable
    public static func == (lhs: BigInt256, rhs: BigInt256) -> Bool {
        return lhs.limbs.0 == rhs.limbs.0 &&
               lhs.limbs.1 == rhs.limbs.1 &&
               lhs.limbs.2 == rhs.limbs.2 &&
               lhs.limbs.3 == rhs.limbs.3
    }

    init(limbs: (UInt64, UInt64, UInt64, UInt64)) {
        self.limbs = limbs
    }

    init(_ l0: UInt64, _ l1: UInt64, _ l2: UInt64, _ l3: UInt64) {
        self.limbs = (l0, l1, l2, l3)
    }

    /// 从十六进制字符串解析（大端表示）
    public static func fromHex(_ hex: String) -> BigInt256 {
        var hex = hex.hasPrefix("0x") || hex.hasPrefix("0X") ? String(hex.dropFirst(2)) : hex
        if hex.count % 2 == 1 {
            hex = "0" + hex
        }

        var bytes = [UInt8](repeating: 0, count: 32)
        let hexBytes = Array(hex.utf8)
        let start = max(0, 32 - hex.count / 2)

        for i in 0..<(hex.count / 2) {
            let high = hexCharToU8(hexBytes[i * 2])
            let low = hexCharToU8(hexBytes[i * 2 + 1])
            bytes[start + i] = (high << 4) | low
        }

        return fromBEBytes(bytes)
    }

    private static func hexCharToU8(_ c: UInt8) -> UInt8 {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"):
            return c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"):
            return c - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"):
            return c - UInt8(ascii: "A") + 10
        default:
            return 0
        }
    }

    /// 从大端字节数组解析
    static func fromBEBytes(_ bytes: [UInt8]) -> BigInt256 {
        var padded = [UInt8](repeating: 0, count: 32)
        let start = max(0, 32 - bytes.count)
        let copyLen = min(bytes.count, 32)
        for i in 0..<copyLen {
            padded[start + i] = bytes[bytes.count - copyLen + i]
        }

        var l = [UInt64](repeating: 0, count: 4)
        for i in 0..<4 {
            let offset = (3 - i) * 8
            var value: UInt64 = 0
            for j in 0..<8 {
                value = (value << 8) | UInt64(padded[offset + j])
            }
            l[i] = value
        }
        return BigInt256(l[0], l[1], l[2], l[3])
    }

    /// 转换为大端字节数组
    func toBEBytes() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 32)
        let arr = [limbs.0, limbs.1, limbs.2, limbs.3]
        for i in 0..<4 {
            let offset = (3 - i) * 8
            let limb = arr[i]
            for j in 0..<8 {
                bytes[offset + 7 - j] = UInt8(truncatingIfNeeded: limb >> (j * 8))
            }
        }
        return bytes
    }

    /// 转换为十六进制字符串（大写）
    func toHex() -> String {
        let bytes = toBEBytes()
        return bytes.map { String(format: "%02X", $0) }.joined()
    }

    /// 转换为十六进制字符串（小写）
    func toHexLower() -> String {
        return toHex().lowercased()
    }

    /// 判断是否为零
    var isZero: Bool {
        return limbs.0 == 0 && limbs.1 == 0 && limbs.2 == 0 && limbs.3 == 0
    }

    /// 判断是否为1
    var isOne: Bool {
        return limbs.0 == 1 && limbs.1 == 0 && limbs.2 == 0 && limbs.3 == 0
    }

    /// 比较
    public static func < (lhs: BigInt256, rhs: BigInt256) -> Bool {
        if lhs.limbs.3 != rhs.limbs.3 { return lhs.limbs.3 < rhs.limbs.3 }
        if lhs.limbs.2 != rhs.limbs.2 { return lhs.limbs.2 < rhs.limbs.2 }
        if lhs.limbs.1 != rhs.limbs.1 { return lhs.limbs.1 < rhs.limbs.1 }
        return lhs.limbs.0 < rhs.limbs.0
    }

    /// 加法
    func add(_ other: BigInt256) -> (BigInt256, Bool) {
        var result = (UInt64(0), UInt64(0), UInt64(0), UInt64(0))
        var carry: UInt64 = 0

        let selfArr = [limbs.0, limbs.1, limbs.2, limbs.3]
        let otherArr = [other.limbs.0, other.limbs.1, other.limbs.2, other.limbs.3]
        var resultArr = [UInt64](repeating: 0, count: 4)

        for i in 0..<4 {
            let (sum1, c1) = selfArr[i].addingReportingOverflow(otherArr[i])
            let (sum2, c2) = sum1.addingReportingOverflow(carry)
            resultArr[i] = sum2
            carry = (c1 ? 1 : 0) + (c2 ? 1 : 0)
        }

        result = (resultArr[0], resultArr[1], resultArr[2], resultArr[3])
        return (BigInt256(limbs: result), carry != 0)
    }

    /// 减法
    func sub(_ other: BigInt256) -> (BigInt256, Bool) {
        var result = (UInt64(0), UInt64(0), UInt64(0), UInt64(0))
        var borrow: UInt64 = 0

        let selfArr = [limbs.0, limbs.1, limbs.2, limbs.3]
        let otherArr = [other.limbs.0, other.limbs.1, other.limbs.2, other.limbs.3]
        var resultArr = [UInt64](repeating: 0, count: 4)

        for i in 0..<4 {
            let (diff1, b1) = selfArr[i].subtractingReportingOverflow(otherArr[i])
            let (diff2, b2) = diff1.subtractingReportingOverflow(borrow)
            resultArr[i] = diff2
            borrow = (b1 ? 1 : 0) + (b2 ? 1 : 0)
        }

        result = (resultArr[0], resultArr[1], resultArr[2], resultArr[3])
        return (BigInt256(limbs: result), borrow != 0)
    }

    /// 乘法，返回512位结果
    func mul(_ other: BigInt256) -> [UInt64] {
        var result = [UInt64](repeating: 0, count: 8)
        let selfArr = [limbs.0, limbs.1, limbs.2, limbs.3]
        let otherArr = [other.limbs.0, other.limbs.1, other.limbs.2, other.limbs.3]

        for i in 0..<4 {
            var carry: UInt64 = 0
            for j in 0..<4 {
                let (high, low) = selfArr[i].multipliedFullWidth(by: otherArr[j])
                let (sum1, c1) = low.addingReportingOverflow(result[i + j])
                let (sum2, c2) = sum1.addingReportingOverflow(carry)
                result[i + j] = sum2
                carry = high &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
            }
            result[i + 4] = carry
        }

        return result
    }

    /// 模加法
    func modAdd(_ other: BigInt256, _ modulus: BigInt256) -> BigInt256 {
        let (sum, carry) = self.add(other)
        if carry || sum >= modulus {
            return sum.sub(modulus).0
        }
        return sum
    }

    /// 模减法
    func modSub(_ other: BigInt256, _ modulus: BigInt256) -> BigInt256 {
        let (diff, borrow) = self.sub(other)
        if borrow {
            return diff.add(modulus).0
        }
        return diff
    }

    /// 模乘法
    func modMul(_ other: BigInt256, _ modulus: BigInt256) -> BigInt256 {
        let product = self.mul(other)
        return BigInt256.modReduce512(product, modulus)
    }

    /// 模平方
    func modSquare(_ modulus: BigInt256) -> BigInt256 {
        return modMul(self, modulus)
    }

    /// 512位数模约减到256位
    static func modReduce512(_ value: [UInt64], _ modulus: BigInt256) -> BigInt256 {
        var remainder = value

        // 找到被除数的最高有效位
        var dividendBits = 512
        for i in stride(from: 7, through: 0, by: -1) {
            if remainder[i] != 0 {
                dividendBits = (i + 1) * 64 - remainder[i].leadingZeroBitCount
                break
            }
            if i == 0 {
                dividendBits = 0
            }
        }

        let modArr = [modulus.limbs.0, modulus.limbs.1, modulus.limbs.2, modulus.limbs.3]

        // 找到模数的最高有效位
        var modulusBits = 256
        for i in stride(from: 3, through: 0, by: -1) {
            if modArr[i] != 0 {
                modulusBits = (i + 1) * 64 - modArr[i].leadingZeroBitCount
                break
            }
            if i == 0 {
                modulusBits = 0
            }
        }

        if modulusBits == 0 {
            fatalError("Division by zero")
        }

        if dividendBits < modulusBits {
            return BigInt256(remainder[0], remainder[1], remainder[2], remainder[3])
        }

        let shiftAmount = dividendBits - modulusBits

        for shift in stride(from: shiftAmount, through: 0, by: -1) {
            let shiftedModulus = shiftLeft512(modArr, shift)

            if compare512(remainder, shiftedModulus) != -1 {
                remainder = sub512(remainder, shiftedModulus)
            }
        }

        return BigInt256(remainder[0], remainder[1], remainder[2], remainder[3])
    }

    private static func shiftLeft512(_ value: [UInt64], _ shift: Int) -> [UInt64] {
        var result = [UInt64](repeating: 0, count: 8)

        if shift == 0 {
            for i in 0..<4 {
                result[i] = value[i]
            }
            return result
        }

        let wordShift = shift / 64
        let bitShift = shift % 64

        if bitShift == 0 {
            for i in 0..<4 {
                if i + wordShift < 8 {
                    result[i + wordShift] = value[i]
                }
            }
        } else {
            for i in 0..<4 {
                if i + wordShift < 8 {
                    result[i + wordShift] |= value[i] << bitShift
                }
                if i + wordShift + 1 < 8 {
                    result[i + wordShift + 1] |= value[i] >> (64 - bitShift)
                }
            }
        }

        return result
    }

    private static func compare512(_ a: [UInt64], _ b: [UInt64]) -> Int {
        for i in stride(from: 7, through: 0, by: -1) {
            if a[i] > b[i] { return 1 }
            if a[i] < b[i] { return -1 }
        }
        return 0
    }

    private static func sub512(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] {
        var result = [UInt64](repeating: 0, count: 8)
        var borrow: UInt64 = 0

        for i in 0..<8 {
            let (diff1, b1) = a[i].subtractingReportingOverflow(b[i])
            let (diff2, b2) = diff1.subtractingReportingOverflow(borrow)
            result[i] = diff2
            borrow = (b1 ? 1 : 0) + (b2 ? 1 : 0)
        }

        return result
    }

    /// 模逆（使用费马小定理）
    func modInverse(_ modulus: BigInt256) -> BigInt256 {
        if isZero {
            fatalError("Cannot invert zero")
        }

        // a^(-1) = a^(p-2) mod p
        let (pMinus2, _) = modulus.sub(BigInt256(2, 0, 0, 0))
        return modPow(pMinus2, modulus)
    }

    /// 模幂运算
    func modPow(_ exp: BigInt256, _ modulus: BigInt256) -> BigInt256 {
        if exp.isZero {
            return BigInt256.one
        }

        var result = BigInt256.one
        var base = self
        let bitLen = exp.bitLength

        for i in 0..<bitLen {
            if exp.getBit(i) {
                result = result.modMul(base, modulus)
            }
            base = base.modSquare(modulus)
        }

        return result
    }

    /// 右移1位
    func shiftRight1() -> BigInt256 {
        var result = [UInt64](repeating: 0, count: 4)
        let arr = [limbs.0, limbs.1, limbs.2, limbs.3]

        for i in 0..<4 {
            result[i] = arr[i] >> 1
            if i < 3 {
                result[i] |= arr[i + 1] << 63
            }
        }

        return BigInt256(result[0], result[1], result[2], result[3])
    }

    /// 获取指定位
    func getBit(_ bit: Int) -> Bool {
        if bit >= 256 { return false }
        let word = bit / 64
        let bitInWord = bit % 64
        let arr = [limbs.0, limbs.1, limbs.2, limbs.3]
        return (arr[word] >> bitInWord) & 1 == 1
    }

    /// 获取最高有效位位置
    var bitLength: Int {
        let arr = [limbs.0, limbs.1, limbs.2, limbs.3]
        for i in stride(from: 3, through: 0, by: -1) {
            if arr[i] != 0 {
                return (i + 1) * 64 - arr[i].leadingZeroBitCount
            }
        }
        return 0
    }

    /// 与操作
    func and(_ other: BigInt256) -> BigInt256 {
        return BigInt256(
            limbs.0 & other.limbs.0,
            limbs.1 & other.limbs.1,
            limbs.2 & other.limbs.2,
            limbs.3 & other.limbs.3
        )
    }
}
