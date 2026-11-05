// 256位无符号整数实现（使用4个UInt64存储，小端序）

/// 512位乘积（8个UInt64，小端序）
typealias Wide512 = (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64)

// MARK: - 字级运算（无按数据分支）

/// Bool 转 0 或 1。不写成 `flag ? 1 : 0`：优化器曾把那种写法（经跳转线索化）编译成依赖进位的条件跳转，
/// 这里的按位重新解释没有可以被变成跳转的分支。Bool 的存储表示固定是 0 或 1。
@inline(__always)
func bitValue(_ flag: Bool) -> UInt64 {
    return UInt64(unsafeBitCast(flag, to: UInt8.self))
}

/// a + b + carry，carry 取 0 或 1
@inline(__always)
func addWithCarry(_ a: UInt64, _ b: UInt64, _ carry: inout UInt64) -> UInt64 {
    let (partial, overflow1) = a.addingReportingOverflow(b)
    let (sum, overflow2) = partial.addingReportingOverflow(carry)
    carry = bitValue(overflow1) | bitValue(overflow2)
    return sum
}

/// a - b - borrow，borrow 取 0 或 1
@inline(__always)
func subWithBorrow(_ a: UInt64, _ b: UInt64, _ borrow: inout UInt64) -> UInt64 {
    let (partial, overflow1) = a.subtractingReportingOverflow(b)
    let (difference, overflow2) = partial.subtractingReportingOverflow(borrow)
    borrow = bitValue(overflow1) | bitValue(overflow2)
    return difference
}

/// a * b + c + d，结果不会超过128位
@inline(__always)
func multiplyAdd(_ a: UInt64, _ b: UInt64, _ c: UInt64, _ d: UInt64) -> (high: UInt64, low: UInt64) {
    let (high, low) = a.multipliedFullWidth(by: b)
    let (partial, overflow1) = low.addingReportingOverflow(c)
    let (sum, overflow2) = partial.addingReportingOverflow(d)
    return (high &+ bitValue(overflow1) &+ bitValue(overflow2), sum)
}

/// x == 0 时返回全 1，否则返回 0
@inline(__always)
func zeroMask(_ x: UInt64) -> UInt64 {
    return ((x | (0 &- x)) &>> 63) &- 1
}

/// 优化屏障：原样返回 mask，但优化器无法知道返回值只可能是 0 或全 1。
/// LLVM 能认出 zeroMask 这样的写法，把 `x & mask` 变回比较加条件跳转（甚至跳过内存读取），
/// 而这里 optnone 且不内联，连“返回值等于参数”都推断不出来。用在依赖秘密数据的选择上。
@_optimize(none)
@inline(never)
func opaqueMask(_ mask: UInt64) -> UInt64 {
    return mask
}

// MARK: - BigInt256

public struct BigInt256: Comparable {
    var l0: UInt64  // 最低64位
    var l1: UInt64
    var l2: UInt64
    var l3: UInt64  // 最高64位

    public static let zero = BigInt256(0, 0, 0, 0)
    public static let one = BigInt256(1, 0, 0, 0)

    @inline(__always)
    init(_ l0: UInt64, _ l1: UInt64, _ l2: UInt64, _ l3: UInt64) {
        self.l0 = l0
        self.l1 = l1
        self.l2 = l2
        self.l3 = l3
    }

    // MARK: - Equatable & Comparable（可变时间，秘密数据请用 zeroMask 等掩码运算）

    public static func == (lhs: BigInt256, rhs: BigInt256) -> Bool {
        return lhs.l0 == rhs.l0 && lhs.l1 == rhs.l1 && lhs.l2 == rhs.l2 && lhs.l3 == rhs.l3
    }

    public static func < (lhs: BigInt256, rhs: BigInt256) -> Bool {
        if lhs.l3 != rhs.l3 { return lhs.l3 < rhs.l3 }
        if lhs.l2 != rhs.l2 { return lhs.l2 < rhs.l2 }
        if lhs.l1 != rhs.l1 { return lhs.l1 < rhs.l1 }
        return lhs.l0 < rhs.l0
    }

    // MARK: - 属性

    @inline(__always)
    var isZero: Bool {
        return (l0 | l1 | l2 | l3) == 0
    }

    @inline(__always)
    var isOne: Bool {
        return ((l0 ^ 1) | l1 | l2 | l3) == 0
    }

    /// 值为 0 时返回全 1，否则返回 0
    @inline(__always)
    var isZeroMask: UInt64 {
        return zeroMask(l0 | l1 | l2 | l3)
    }

    var bitLength: Int {
        if l3 != 0 { return 256 - l3.leadingZeroBitCount }
        if l2 != 0 { return 192 - l2.leadingZeroBitCount }
        if l1 != 0 { return 128 - l1.leadingZeroBitCount }
        if l0 != 0 { return 64 - l0.leadingZeroBitCount }
        return 0
    }

    // MARK: - 位操作

    @inline(__always)
    func limb(_ index: Int) -> UInt64 {
        switch index {
        case 0: return l0
        case 1: return l1
        case 2: return l2
        case 3: return l3
        default: return 0
        }
    }

    @inline(__always)
    func getBit(_ bit: Int) -> Bool {
        if bit >= 256 { return false }
        return (limb(bit &>> 6) &>> UInt64(truncatingIfNeeded: bit & 63)) & 1 == 1
    }

    /// 取从 position 开始的低位窗口（结果最多64位，由调用方掩码）。position 必须是公开值。
    @inline(__always)
    func bits(from position: Int) -> UInt64 {
        let word = position &>> 6
        let offset = UInt64(truncatingIfNeeded: position & 63)
        if offset == 0 {
            return limb(word)
        }
        return (limb(word) &>> offset) | (limb(word &+ 1) &<< (64 &- offset))
    }

    func shiftRight1() -> BigInt256 {
        return BigInt256(
            (l0 &>> 1) | (l1 &<< 63),
            (l1 &>> 1) | (l2 &<< 63),
            (l2 &>> 1) | (l3 &<< 63),
            l3 &>> 1
        )
    }

    func and(_ other: BigInt256) -> BigInt256 {
        return BigInt256(l0 & other.l0, l1 & other.l1, l2 & other.l2, l3 & other.l3)
    }

    /// 相等时返回全 1，否则返回 0，不依赖数据分支
    @inline(__always)
    static func equalMask(_ a: BigInt256, _ b: BigInt256) -> UInt64 {
        return zeroMask((a.l0 ^ b.l0) | (a.l1 ^ b.l1) | (a.l2 ^ b.l2) | (a.l3 ^ b.l3))
    }

    /// mask 为全 1 时取 a，为 0 时取 b
    @inline(__always)
    static func select(_ mask: UInt64, _ a: BigInt256, _ b: BigInt256) -> BigInt256 {
        return BigInt256(
            (a.l0 & mask) | (b.l0 & ~mask),
            (a.l1 & mask) | (b.l1 & ~mask),
            (a.l2 & mask) | (b.l2 & ~mask),
            (a.l3 & mask) | (b.l3 & ~mask)
        )
    }

    // MARK: - 算术运算

    @inline(__always)
    func addingWithCarry(_ other: BigInt256) -> (sum: BigInt256, carry: UInt64) {
        var carry: UInt64 = 0
        let s0 = addWithCarry(l0, other.l0, &carry)
        let s1 = addWithCarry(l1, other.l1, &carry)
        let s2 = addWithCarry(l2, other.l2, &carry)
        let s3 = addWithCarry(l3, other.l3, &carry)
        return (BigInt256(s0, s1, s2, s3), carry)
    }

    @inline(__always)
    func subtractingWithBorrow(_ other: BigInt256) -> (difference: BigInt256, borrow: UInt64) {
        var borrow: UInt64 = 0
        let d0 = subWithBorrow(l0, other.l0, &borrow)
        let d1 = subWithBorrow(l1, other.l1, &borrow)
        let d2 = subWithBorrow(l2, other.l2, &borrow)
        let d3 = subWithBorrow(l3, other.l3, &borrow)
        return (BigInt256(d0, d1, d2, d3), borrow)
    }

    @inline(__always)
    func add(_ other: BigInt256) -> (BigInt256, Bool) {
        let (sum, carry) = addingWithCarry(other)
        return (sum, carry != 0)
    }

    @inline(__always)
    func sub(_ other: BigInt256) -> (BigInt256, Bool) {
        let (difference, borrow) = subtractingWithBorrow(other)
        return (difference, borrow != 0)
    }

    /// 乘法，返回512位结果（Schoolbook 4x4）
    @inline(__always)
    func mul(_ other: BigInt256) -> Wide512 {
        let (a0, a1, a2, a3) = (l0, l1, l2, l3)
        let (b0, b1, b2, b3) = (other.l0, other.l1, other.l2, other.l3)

        var row = multiplyAdd(a0, b0, 0, 0)
        let r0 = row.low
        row = multiplyAdd(a0, b1, row.high, 0)
        var r1 = row.low
        row = multiplyAdd(a0, b2, row.high, 0)
        var r2 = row.low
        row = multiplyAdd(a0, b3, row.high, 0)
        var r3 = row.low
        var r4 = row.high

        row = multiplyAdd(a1, b0, r1, 0)
        r1 = row.low
        row = multiplyAdd(a1, b1, r2, row.high)
        r2 = row.low
        row = multiplyAdd(a1, b2, r3, row.high)
        r3 = row.low
        row = multiplyAdd(a1, b3, r4, row.high)
        r4 = row.low
        var r5 = row.high

        row = multiplyAdd(a2, b0, r2, 0)
        r2 = row.low
        row = multiplyAdd(a2, b1, r3, row.high)
        r3 = row.low
        row = multiplyAdd(a2, b2, r4, row.high)
        r4 = row.low
        row = multiplyAdd(a2, b3, r5, row.high)
        r5 = row.low
        var r6 = row.high

        row = multiplyAdd(a3, b0, r3, 0)
        r3 = row.low
        row = multiplyAdd(a3, b1, r4, row.high)
        r4 = row.low
        row = multiplyAdd(a3, b2, r5, row.high)
        r5 = row.low
        row = multiplyAdd(a3, b3, r6, row.high)
        r6 = row.low

        return (r0, r1, r2, r3, r4, r5, r6, row.high)
    }

    /// 专用平方运算，利用对称性减少乘法次数（10次乘法 vs mul的16次）
    @inline(__always)
    func square() -> Wide512 {
        // 交叉项 a[i]*a[j] (i<j) 出现两次，先累加一次，再整体左移1位
        var row = l0.multipliedFullWidth(by: l1)
        var r1 = row.low
        var r2 = row.high

        var mac = multiplyAdd(l0, l2, r2, 0)
        r2 = mac.low
        mac = multiplyAdd(l0, l3, mac.high, 0)
        var r3 = mac.low
        var r4 = mac.high

        // l1*l2 的低位进位必须先经 r3 传播到 r4，再计算溢出到 r5 的部分
        mac = multiplyAdd(l1, l2, r3, 0)
        r3 = mac.low
        mac = multiplyAdd(l1, l3, r4, mac.high)
        r4 = mac.low
        var r5 = mac.high

        mac = multiplyAdd(l2, l3, r5, 0)
        r5 = mac.low
        var r6 = mac.high

        let r7 = r6 &>> 63
        r6 = (r6 &<< 1) | (r5 &>> 63)
        r5 = (r5 &<< 1) | (r4 &>> 63)
        r4 = (r4 &<< 1) | (r3 &>> 63)
        r3 = (r3 &<< 1) | (r2 &>> 63)
        r2 = (r2 &<< 1) | (r1 &>> 63)
        r1 = r1 &<< 1

        // 加上对角项 a[i]^2
        var carry: UInt64 = 0
        row = l0.multipliedFullWidth(by: l0)
        let r0 = row.low
        r1 = addWithCarry(r1, row.high, &carry)
        row = l1.multipliedFullWidth(by: l1)
        r2 = addWithCarry(r2, row.low, &carry)
        r3 = addWithCarry(r3, row.high, &carry)
        row = l2.multipliedFullWidth(by: l2)
        r4 = addWithCarry(r4, row.low, &carry)
        r5 = addWithCarry(r5, row.high, &carry)
        row = l3.multipliedFullWidth(by: l3)
        r6 = addWithCarry(r6, row.low, &carry)
        let top = addWithCarry(r7, row.high, &carry)

        return (r0, r1, r2, r3, r4, r5, r6, top)
    }

    // MARK: - 模运算（SM2 的 p、n 走专用快速路径，其余模数走通用试商）

    @inline(__always)
    func modAdd(_ other: BigInt256, _ modulus: BigInt256) -> BigInt256 {
        let (sum, carry) = addingWithCarry(other)
        let (reduced, borrow) = sum.subtractingWithBorrow(modulus)
        // 溢出或 sum >= modulus 时取减去模数后的结果
        let useReduced = (0 &- carry) | zeroMask(borrow)
        return BigInt256.select(useReduced, reduced, sum)
    }

    @inline(__always)
    func modSub(_ other: BigInt256, _ modulus: BigInt256) -> BigInt256 {
        let (difference, borrow) = subtractingWithBorrow(other)
        let mask = 0 &- borrow
        var carry: UInt64 = 0
        let r0 = addWithCarry(difference.l0, modulus.l0 & mask, &carry)
        let r1 = addWithCarry(difference.l1, modulus.l1 & mask, &carry)
        let r2 = addWithCarry(difference.l2, modulus.l2 & mask, &carry)
        let r3 = addWithCarry(difference.l3, modulus.l3 & mask, &carry)
        return BigInt256(r0, r1, r2, r3)
    }

    func modMul(_ other: BigInt256, _ modulus: BigInt256) -> BigInt256 {
        return BigInt256.reduce(mul(other), modulus)
    }

    func modSquare(_ modulus: BigInt256) -> BigInt256 {
        return BigInt256.reduce(square(), modulus)
    }

    private static func reduce(_ value: Wide512, _ modulus: BigInt256) -> BigInt256 {
        if modulus == SM2Curve.p {
            return sm2ModReduceP(value)
        }
        if modulus == SM2Curve.n {
            return sm2ModReduceN(value)
        }
        return modReduce512(value, modulus)
    }

    /// 通用512位模约减：逐位移位相减。只用于 p、n 以外的模数，可变时间。
    static func modReduce512(_ value: Wide512, _ modulus: BigInt256) -> BigInt256 {
        let limbs = [value.0, value.1, value.2, value.3, value.4, value.5, value.6, value.7]
        guard let topIndex = limbs.lastIndex(where: { $0 != 0 }) else {
            return BigInt256.zero
        }
        let dividendBits = (topIndex + 1) * 64 - limbs[topIndex].leadingZeroBitCount
        if modulus.isZero {
            return BigInt256.zero  // 只有内部测试会走到通用路径；没有陷阱
        }

        var remainder = BigInt256.zero
        for bit in stride(from: dividendBits - 1, through: 0, by: -1) {
            let incoming = (limbs[bit >> 6] >> UInt64(bit & 63)) & 1
            let overflow = remainder.l3 >> 63
            remainder = BigInt256(
                (remainder.l0 << 1) | incoming,
                (remainder.l1 << 1) | (remainder.l0 >> 63),
                (remainder.l2 << 1) | (remainder.l1 >> 63),
                (remainder.l3 << 1) | (remainder.l2 >> 63)
            )
            if overflow != 0 || remainder >= modulus {
                remainder = remainder.sub(modulus).0
            }
        }
        return remainder
    }

    // MARK: - 模逆与模幂

    func modInverse(_ modulus: BigInt256) -> BigInt256 {
        if isZero {
            return BigInt256.zero  // 0 没有逆元；调用方负责事先保证非 0，这里不陷入陷阱
        }
        if modulus == SM2Curve.p {
            return FpElement(unchecked: self).invertedUnchecked().value
        }
        if modulus == SM2Curve.n {
            return ScalarField.invert(self)
        }
        let (exponent, _) = modulus.sub(BigInt256(2, 0, 0, 0))
        return modPow(exponent, modulus)
    }

    func modPow(_ exp: BigInt256, _ modulus: BigInt256) -> BigInt256 {
        if exp.isZero {
            return BigInt256.one
        }

        var result = BigInt256.one
        var base = self
        for bit in 0..<exp.bitLength {
            if exp.getBit(bit) {
                result = result.modMul(base, modulus)
            }
            base = base.modSquare(modulus)
        }
        return result
    }

    // MARK: - 序列化

    /// 解析十六进制（可带 0x 前缀，最多64位数字，不足时高位补0）。
    /// 这个接口无法抛错：任何不合法的输入（非十六进制字符、非 ASCII、超过256位）都返回 0。
    /// 0 不是合法私钥，所有使用它的入口都会干净地失败。要区分错误请用 `init?(hex:)`。
    public static func fromHex(_ hex: String) -> BigInt256 {
        var copy = hex
        return copy.withUTF8 { utf8 -> BigInt256? in
            var digits = utf8
            if digits.count >= 2, digits[0] == UInt8(ascii: "0"),
                digits[1] == UInt8(ascii: "x") || digits[1] == UInt8(ascii: "X")
            {
                digits = UnsafeBufferPointer(rebasing: digits[2...])
            }
            return parseHexDigits(digits)
        } ?? BigInt256.zero
    }

    /// 严格解析：恰好64个十六进制字符（大小写均可），否则返回 nil。
    public init?(hex: String) {
        var copy = hex
        let parsed = copy.withUTF8 { utf8 -> BigInt256? in
            return utf8.count == 64 ? BigInt256.parseHexDigits(utf8) : nil
        }
        guard let value = parsed else {
            return nil
        }
        self = value
    }

    /// 解析最多64个十六进制数字，不足时高位补0。解码本身无按数据的分支。
    private static func parseHexDigits(_ digits: UnsafeBufferPointer<UInt8>) -> BigInt256? {
        if digits.count > 64 {
            return nil
        }
        return withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 32) { buffer -> BigInt256? in
            guard let output = buffer.baseAddress else {
                return nil
            }
            output.initialize(repeating: 0, count: 32)
            defer { secureWipe(UnsafeMutableRawBufferPointer(buffer)) }
            let start = output + 32 - (digits.count + 1) / 2
            var valid: Bool
            if digits.count % 2 == 1 {
                // 奇数长度时最高位数字单独占一个字节
                var pair: (UInt8, UInt8) = (UInt8(ascii: "0"), digits[0])
                valid = withUnsafeBytes(of: &pair) { Hex.decode($0.bindMemory(to: UInt8.self), into: start) }
                valid = Hex.decode(UnsafeBufferPointer(rebasing: digits[1...]), into: start + 1) && valid
            } else {
                valid = Hex.decode(digits, into: start)
            }
            return valid ? fromBEPointer(UnsafePointer(output)) : nil
        }
    }

    @inline(__always)
    private static func readBigEndian(_ pointer: UnsafePointer<UInt8>) -> UInt64 {
        var value: UInt64 = 0
        for index in 0..<8 {
            value = (value &<< 8) | UInt64(pointer[index])
        }
        return value
    }

    /// 从恰好32字节的大端数据读取
    @inline(__always)
    static func fromBEPointer(_ pointer: UnsafePointer<UInt8>) -> BigInt256 {
        return BigInt256(
            readBigEndian(pointer + 24),
            readBigEndian(pointer + 16),
            readBigEndian(pointer + 8),
            readBigEndian(pointer)
        )
    }

    /// 超过32字节时取低32字节，不足时高位补0
    static func fromBEBytes(_ bytes: [UInt8]) -> BigInt256 {
        return bytes.withUnsafeBufferPointer { source in
            guard let base = source.baseAddress else {
                return BigInt256.zero
            }
            if source.count >= 32 {
                return fromBEPointer(base + source.count - 32)
            }
            return withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 32) { padded in
                guard let output = padded.baseAddress else {
                    return BigInt256.zero
                }
                let padding = 32 - source.count
                output.initialize(repeating: 0, count: padding)
                (output + padding).initialize(from: base, count: source.count)
                return fromBEPointer(UnsafePointer(output))
            }
        }
    }

    /// 写出32字节大端数据
    @inline(__always)
    func writeBE(to output: UnsafeMutablePointer<UInt8>) {
        for index in 0..<8 {
            let shift = UInt64(truncatingIfNeeded: 56 &- index &* 8)
            output[index] = UInt8(truncatingIfNeeded: l3 &>> shift)
            output[index &+ 8] = UInt8(truncatingIfNeeded: l2 &>> shift)
            output[index &+ 16] = UInt8(truncatingIfNeeded: l1 &>> shift)
            output[index &+ 24] = UInt8(truncatingIfNeeded: l0 &>> shift)
        }
    }

    func toBEBytes() -> [UInt8] {
        return [UInt8](unsafeUninitializedCapacity: 32) { buffer, initialized in
            if let base = buffer.baseAddress {
                writeBE(to: base)
            }
            initialized = 32
        }
    }

    func toHex() -> String {
        return Hex.encode(toBEBytes(), gap: Hex.uppercaseGap)
    }

    func toHexLower() -> String {
        return Hex.encode(toBEBytes())
    }
}

extension BigInt256: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    // BigInt256 也用来存放私钥，print、dump 和错误信息都不能泄露它的值。需要输出时显式调用内部的 toHex。
    public var description: String { return "BigInt256(<redacted>)" }
    public var debugDescription: String { return description }
    public var customMirror: Mirror { return Mirror(self, children: []) }
}
