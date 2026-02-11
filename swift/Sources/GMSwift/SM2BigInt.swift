// 256位无符号整数实现（使用4个UInt64存储，小端序）

import Foundation

public struct BigInt256: Comparable {
    // 使用独立属性代替元组，避免通过数组访问的开销
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

    // 兼容旧的limbs初始化方式
    init(limbs: (UInt64, UInt64, UInt64, UInt64)) {
        self.l0 = limbs.0
        self.l1 = limbs.1
        self.l2 = limbs.2
        self.l3 = limbs.3
    }

    // 兼容旧的limbs属性访问
    var limbs: (UInt64, UInt64, UInt64, UInt64) {
        get { (l0, l1, l2, l3) }
        set { l0 = newValue.0; l1 = newValue.1; l2 = newValue.2; l3 = newValue.3 }
    }

    // MARK: - 下标访问，避免创建数组
    @inline(__always)
    subscript(index: Int) -> UInt64 {
        get {
            switch index {
            case 0: return l0
            case 1: return l1
            case 2: return l2
            case 3: return l3
            default: return 0
            }
        }
        set {
            switch index {
            case 0: l0 = newValue
            case 1: l1 = newValue
            case 2: l2 = newValue
            case 3: l3 = newValue
            default: break
            }
        }
    }

    // MARK: - Equatable & Comparable

    public static func == (lhs: BigInt256, rhs: BigInt256) -> Bool {
        return lhs.l0 == rhs.l0 && lhs.l1 == rhs.l1 &&
               lhs.l2 == rhs.l2 && lhs.l3 == rhs.l3
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
        return l0 == 0 && l1 == 0 && l2 == 0 && l3 == 0
    }

    @inline(__always)
    var isOne: Bool {
        return l0 == 1 && l1 == 0 && l2 == 0 && l3 == 0
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
    func getBit(_ bit: Int) -> Bool {
        if bit >= 256 { return false }
        let word = bit >> 6        // bit / 64
        let bitInWord = bit & 63   // bit % 64
        switch word {
        case 0: return (l0 >> bitInWord) & 1 == 1
        case 1: return (l1 >> bitInWord) & 1 == 1
        case 2: return (l2 >> bitInWord) & 1 == 1
        case 3: return (l3 >> bitInWord) & 1 == 1
        default: return false
        }
    }

    func shiftRight1() -> BigInt256 {
        return BigInt256(
            (l0 >> 1) | (l1 << 63),
            (l1 >> 1) | (l2 << 63),
            (l2 >> 1) | (l3 << 63),
            l3 >> 1
        )
    }

    func and(_ other: BigInt256) -> BigInt256 {
        return BigInt256(
            l0 & other.l0,
            l1 & other.l1,
            l2 & other.l2,
            l3 & other.l3
        )
    }

    // MARK: - 算术运算（无临时数组分配）

    @inline(__always)
    func add(_ other: BigInt256) -> (BigInt256, Bool) {
        let (s0, c0) = l0.addingReportingOverflow(other.l0)
        let (s1a, c1a) = l1.addingReportingOverflow(other.l1)
        let (s1, c1b) = s1a.addingReportingOverflow(c0 ? 1 : 0)
        let carry1 = c1a || c1b
        let (s2a, c2a) = l2.addingReportingOverflow(other.l2)
        let (s2, c2b) = s2a.addingReportingOverflow(carry1 ? 1 : 0)
        let carry2 = c2a || c2b
        let (s3a, c3a) = l3.addingReportingOverflow(other.l3)
        let (s3, c3b) = s3a.addingReportingOverflow(carry2 ? 1 : 0)
        let carry3 = c3a || c3b
        return (BigInt256(s0, s1, s2, s3), carry3)
    }

    @inline(__always)
    func sub(_ other: BigInt256) -> (BigInt256, Bool) {
        let (d0, b0) = l0.subtractingReportingOverflow(other.l0)
        let (d1a, b1a) = l1.subtractingReportingOverflow(other.l1)
        let (d1, b1b) = d1a.subtractingReportingOverflow(b0 ? 1 : 0)
        let borrow1 = b1a || b1b
        let (d2a, b2a) = l2.subtractingReportingOverflow(other.l2)
        let (d2, b2b) = d2a.subtractingReportingOverflow(borrow1 ? 1 : 0)
        let borrow2 = b2a || b2b
        let (d3a, b3a) = l3.subtractingReportingOverflow(other.l3)
        let (d3, b3b) = d3a.subtractingReportingOverflow(borrow2 ? 1 : 0)
        let borrow3 = b3a || b3b
        return (BigInt256(d0, d1, d2, d3), borrow3)
    }

    /// 乘法，返回512位结果（8个UInt64，小端序）
    func mul(_ other: BigInt256) -> (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64) {
        // Schoolbook 4x4 乘法，直接使用属性访问，无数组分配
        var r0: UInt64 = 0, r1: UInt64 = 0, r2: UInt64 = 0, r3: UInt64 = 0
        var r4: UInt64 = 0, r5: UInt64 = 0, r6: UInt64 = 0, r7: UInt64 = 0

        // i = 0: self.l0 * other
        var carry: UInt64 = 0
        var hi: UInt64
        var lo: UInt64

        (hi, lo) = l0.multipliedFullWidth(by: other.l0)
        r0 = lo; carry = hi

        (hi, lo) = l0.multipliedFullWidth(by: other.l1)
        var (s, c1) = lo.addingReportingOverflow(carry)
        r1 = s; carry = hi &+ (c1 ? 1 : 0)

        (hi, lo) = l0.multipliedFullWidth(by: other.l2)
        (s, c1) = lo.addingReportingOverflow(carry)
        r2 = s; carry = hi &+ (c1 ? 1 : 0)

        (hi, lo) = l0.multipliedFullWidth(by: other.l3)
        (s, c1) = lo.addingReportingOverflow(carry)
        r3 = s; r4 = hi &+ (c1 ? 1 : 0)

        // i = 1: self.l1 * other
        carry = 0
        (hi, lo) = l1.multipliedFullWidth(by: other.l0)
        (s, c1) = lo.addingReportingOverflow(r1)
        r1 = s; carry = hi &+ (c1 ? 1 : 0)

        (hi, lo) = l1.multipliedFullWidth(by: other.l1)
        (s, c1) = lo.addingReportingOverflow(r2)
        var c2: Bool
        (s, c2) = s.addingReportingOverflow(carry)
        r2 = s; carry = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)

        (hi, lo) = l1.multipliedFullWidth(by: other.l2)
        (s, c1) = lo.addingReportingOverflow(r3)
        (s, c2) = s.addingReportingOverflow(carry)
        r3 = s; carry = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)

        (hi, lo) = l1.multipliedFullWidth(by: other.l3)
        (s, c1) = lo.addingReportingOverflow(r4)
        (s, c2) = s.addingReportingOverflow(carry)
        r4 = s; r5 = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)

        // i = 2: self.l2 * other
        carry = 0
        (hi, lo) = l2.multipliedFullWidth(by: other.l0)
        (s, c1) = lo.addingReportingOverflow(r2)
        r2 = s; carry = hi &+ (c1 ? 1 : 0)

        (hi, lo) = l2.multipliedFullWidth(by: other.l1)
        (s, c1) = lo.addingReportingOverflow(r3)
        (s, c2) = s.addingReportingOverflow(carry)
        r3 = s; carry = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)

        (hi, lo) = l2.multipliedFullWidth(by: other.l2)
        (s, c1) = lo.addingReportingOverflow(r4)
        (s, c2) = s.addingReportingOverflow(carry)
        r4 = s; carry = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)

        (hi, lo) = l2.multipliedFullWidth(by: other.l3)
        (s, c1) = lo.addingReportingOverflow(r5)
        (s, c2) = s.addingReportingOverflow(carry)
        r5 = s; r6 = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)

        // i = 3: self.l3 * other
        carry = 0
        (hi, lo) = l3.multipliedFullWidth(by: other.l0)
        (s, c1) = lo.addingReportingOverflow(r3)
        r3 = s; carry = hi &+ (c1 ? 1 : 0)

        (hi, lo) = l3.multipliedFullWidth(by: other.l1)
        (s, c1) = lo.addingReportingOverflow(r4)
        (s, c2) = s.addingReportingOverflow(carry)
        r4 = s; carry = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)

        (hi, lo) = l3.multipliedFullWidth(by: other.l2)
        (s, c1) = lo.addingReportingOverflow(r5)
        (s, c2) = s.addingReportingOverflow(carry)
        r5 = s; carry = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)

        (hi, lo) = l3.multipliedFullWidth(by: other.l3)
        (s, c1) = lo.addingReportingOverflow(r6)
        (s, c2) = s.addingReportingOverflow(carry)
        r6 = s; r7 = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)

        return (r0, r1, r2, r3, r4, r5, r6, r7)
    }

    /// 专用平方运算，利用对称性减少乘法次数（6次乘法 vs mul的16次）
    func square() -> (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64) {
        // 交叉项: a[i]*a[j] (i<j) 出现两次，只算一次然后左移1位
        // 对角项: a[i]^2 只出现一次

        // 先计算所有交叉项 (i < j) 累加到 r1..r7
        var r0: UInt64 = 0, r1: UInt64 = 0, r2: UInt64 = 0, r3: UInt64 = 0
        var r4: UInt64 = 0, r5: UInt64 = 0, r6: UInt64 = 0, r7: UInt64 = 0

        var hi: UInt64, lo: UInt64
        var s: UInt64, c1: Bool, c2: Bool, c3: Bool

        // l0 * l1 -> r1,r2 (no existing values to add to)
        (hi, lo) = l0.multipliedFullWidth(by: l1)
        r1 = lo; r2 = hi

        // l0 * l2 -> add to r2,r3
        (hi, lo) = l0.multipliedFullWidth(by: l2)
        (s, c1) = r2.addingReportingOverflow(lo)
        r2 = s; r3 = hi &+ (c1 ? 1 : 0)

        // l0 * l3 -> add to r3,r4
        (hi, lo) = l0.multipliedFullWidth(by: l3)
        (s, c1) = r3.addingReportingOverflow(lo)
        r3 = s; r4 = hi &+ (c1 ? 1 : 0)

        // l1 * l2 -> add to r3,r4 (需要正确传播carry)
        (hi, lo) = l1.multipliedFullWidth(by: l2)
        (s, c1) = r3.addingReportingOverflow(lo)
        r3 = s
        (s, c2) = r4.addingReportingOverflow(hi)
        (s, c3) = s.addingReportingOverflow(c1 ? 1 : 0)
        r4 = s; r5 = (c2 ? 1 : 0) &+ (c3 ? 1 : 0)

        // l1 * l3 -> add to r4,r5
        (hi, lo) = l1.multipliedFullWidth(by: l3)
        (s, c1) = r4.addingReportingOverflow(lo)
        r4 = s
        (s, c2) = r5.addingReportingOverflow(hi)
        (s, c3) = s.addingReportingOverflow(c1 ? 1 : 0)
        r5 = s; r6 = (c2 ? 1 : 0) &+ (c3 ? 1 : 0)

        // l2 * l3 -> add to r5,r6
        (hi, lo) = l2.multipliedFullWidth(by: l3)
        (s, c1) = r5.addingReportingOverflow(lo)
        r5 = s
        (s, c2) = r6.addingReportingOverflow(hi)
        (s, c3) = s.addingReportingOverflow(c1 ? 1 : 0)
        r6 = s; r7 = (c2 ? 1 : 0) &+ (c3 ? 1 : 0)

        // 交叉项 * 2（左移1位）
        r7 = (r7 << 1) | (r6 >> 63)
        r6 = (r6 << 1) | (r5 >> 63)
        r5 = (r5 << 1) | (r4 >> 63)
        r4 = (r4 << 1) | (r3 >> 63)
        r3 = (r3 << 1) | (r2 >> 63)
        r2 = (r2 << 1) | (r1 >> 63)
        r1 = r1 << 1

        // 加上对角项 a[i]^2
        (hi, lo) = l0.multipliedFullWidth(by: l0)
        r0 = lo
        (s, c1) = r1.addingReportingOverflow(hi)
        r1 = s
        var carry: UInt64 = c1 ? 1 : 0

        (hi, lo) = l1.multipliedFullWidth(by: l1)
        (s, c1) = r2.addingReportingOverflow(lo)
        (s, c2) = s.addingReportingOverflow(carry)
        r2 = s; carry = (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
        (s, c1) = r3.addingReportingOverflow(hi)
        (s, c2) = s.addingReportingOverflow(carry)
        r3 = s; carry = (c1 ? 1 : 0) &+ (c2 ? 1 : 0)

        (hi, lo) = l2.multipliedFullWidth(by: l2)
        (s, c1) = r4.addingReportingOverflow(lo)
        (s, c2) = s.addingReportingOverflow(carry)
        r4 = s; carry = (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
        (s, c1) = r5.addingReportingOverflow(hi)
        (s, c2) = s.addingReportingOverflow(carry)
        r5 = s; carry = (c1 ? 1 : 0) &+ (c2 ? 1 : 0)

        (hi, lo) = l3.multipliedFullWidth(by: l3)
        (s, c1) = r6.addingReportingOverflow(lo)
        (s, c2) = s.addingReportingOverflow(carry)
        r6 = s; carry = (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
        (s, c1) = r7.addingReportingOverflow(hi)
        (s, c2) = s.addingReportingOverflow(carry)
        r7 = s

        return (r0, r1, r2, r3, r4, r5, r6, r7)
    }

    // MARK: - 模运算

    @inline(__always)
    func modAdd(_ other: BigInt256, _ modulus: BigInt256) -> BigInt256 {
        let (sum, carry) = self.add(other)
        if carry || sum >= modulus {
            return sum.sub(modulus).0
        }
        return sum
    }

    @inline(__always)
    func modSub(_ other: BigInt256, _ modulus: BigInt256) -> BigInt256 {
        let (diff, borrow) = self.sub(other)
        if borrow {
            return diff.add(modulus).0
        }
        return diff
    }

    func modMul(_ other: BigInt256, _ modulus: BigInt256) -> BigInt256 {
        let product = self.mul(other)
        return BigInt256.modReduce512(product, modulus)
    }

    func modSquare(_ modulus: BigInt256) -> BigInt256 {
        let product = self.square()
        return BigInt256.modReduce512(product, modulus)
    }

    // MARK: - 512位模约减（通用版本，用于非SM2_P的模数）

    static func modReduce512(
        _ value: (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64),
        _ modulus: BigInt256
    ) -> BigInt256 {
        // 使用试商法（类似Knuth Algorithm D的简化版）
        var r0 = value.0, r1 = value.1, r2 = value.2, r3 = value.3
        var r4 = value.4, r5 = value.5, r6 = value.6, r7 = value.7

        // 找到被除数的最高有效位
        var dividendBits: Int
        if r7 != 0 { dividendBits = 512 - r7.leadingZeroBitCount }
        else if r6 != 0 { dividendBits = 448 - r6.leadingZeroBitCount }
        else if r5 != 0 { dividendBits = 384 - r5.leadingZeroBitCount }
        else if r4 != 0 { dividendBits = 320 - r4.leadingZeroBitCount }
        else if r3 != 0 { dividendBits = 256 - r3.leadingZeroBitCount }
        else if r2 != 0 { dividendBits = 192 - r2.leadingZeroBitCount }
        else if r1 != 0 { dividendBits = 128 - r1.leadingZeroBitCount }
        else if r0 != 0 { dividendBits = 64 - r0.leadingZeroBitCount }
        else { return BigInt256.zero }

        let modulusBits = modulus.bitLength
        if modulusBits == 0 { fatalError("Division by zero") }
        if dividendBits < modulusBits {
            return BigInt256(r0, r1, r2, r3)
        }

        let shiftAmount = dividendBits - modulusBits

        // 使用内联的512位操作避免数组分配
        for shift in stride(from: shiftAmount, through: 0, by: -1) {
            // 计算shifted modulus
            let wordShift = shift >> 6
            let bitShift = shift & 63

            var m0: UInt64 = 0, m1: UInt64 = 0, m2: UInt64 = 0, m3: UInt64 = 0
            var m4: UInt64 = 0, m5: UInt64 = 0, m6: UInt64 = 0, m7: UInt64 = 0

            if bitShift == 0 {
                switch wordShift {
                case 0: m0 = modulus.l0; m1 = modulus.l1; m2 = modulus.l2; m3 = modulus.l3
                case 1: m1 = modulus.l0; m2 = modulus.l1; m3 = modulus.l2; m4 = modulus.l3
                case 2: m2 = modulus.l0; m3 = modulus.l1; m4 = modulus.l2; m5 = modulus.l3
                case 3: m3 = modulus.l0; m4 = modulus.l1; m5 = modulus.l2; m6 = modulus.l3
                case 4: m4 = modulus.l0; m5 = modulus.l1; m6 = modulus.l2; m7 = modulus.l3
                default: break
                }
            } else {
                let rShift = 64 - bitShift
                let ml0 = modulus.l0, ml1 = modulus.l1, ml2 = modulus.l2, ml3 = modulus.l3
                // 将4个limb左移bitShift位，放到wordShift开始的位置
                let shifted0 = ml0 << bitShift
                let shifted1 = (ml1 << bitShift) | (ml0 >> rShift)
                let shifted2 = (ml2 << bitShift) | (ml1 >> rShift)
                let shifted3 = (ml3 << bitShift) | (ml2 >> rShift)
                let shifted4 = ml3 >> rShift

                switch wordShift {
                case 0: m0 = shifted0; m1 = shifted1; m2 = shifted2; m3 = shifted3; m4 = shifted4
                case 1: m1 = shifted0; m2 = shifted1; m3 = shifted2; m4 = shifted3; m5 = shifted4
                case 2: m2 = shifted0; m3 = shifted1; m4 = shifted2; m5 = shifted3; m6 = shifted4
                case 3: m3 = shifted0; m4 = shifted1; m5 = shifted2; m6 = shifted3; m7 = shifted4
                case 4: m4 = shifted0; m5 = shifted1; m6 = shifted2; m7 = shifted3
                default: break
                }
            }

            // 比较 remainder >= shifted_modulus
            var cmp = 0
            if cmp == 0 && r7 != m7 { cmp = r7 > m7 ? 1 : -1 }
            if cmp == 0 && r6 != m6 { cmp = r6 > m6 ? 1 : -1 }
            if cmp == 0 && r5 != m5 { cmp = r5 > m5 ? 1 : -1 }
            if cmp == 0 && r4 != m4 { cmp = r4 > m4 ? 1 : -1 }
            if cmp == 0 && r3 != m3 { cmp = r3 > m3 ? 1 : -1 }
            if cmp == 0 && r2 != m2 { cmp = r2 > m2 ? 1 : -1 }
            if cmp == 0 && r1 != m1 { cmp = r1 > m1 ? 1 : -1 }
            if cmp == 0 && r0 != m0 { cmp = r0 > m0 ? 1 : -1 }

            if cmp >= 0 {
                // remainder -= shifted_modulus
                var borrow: UInt64 = 0
                var (d, b): (UInt64, Bool)
                (d, b) = r0.subtractingReportingOverflow(m0); r0 = d; borrow = b ? 1 : 0
                (d, b) = r1.subtractingReportingOverflow(m1); let (d1b, b1b) = d.subtractingReportingOverflow(borrow)
                r1 = d1b; borrow = (b ? 1 : 0) + (b1b ? 1 : 0)
                (d, b) = r2.subtractingReportingOverflow(m2); let (d2b, b2b) = d.subtractingReportingOverflow(borrow)
                r2 = d2b; borrow = (b ? 1 : 0) + (b2b ? 1 : 0)
                (d, b) = r3.subtractingReportingOverflow(m3); let (d3b, b3b) = d.subtractingReportingOverflow(borrow)
                r3 = d3b; borrow = (b ? 1 : 0) + (b3b ? 1 : 0)
                (d, b) = r4.subtractingReportingOverflow(m4); let (d4b, b4b) = d.subtractingReportingOverflow(borrow)
                r4 = d4b; borrow = (b ? 1 : 0) + (b4b ? 1 : 0)
                (d, b) = r5.subtractingReportingOverflow(m5); let (d5b, b5b) = d.subtractingReportingOverflow(borrow)
                r5 = d5b; borrow = (b ? 1 : 0) + (b5b ? 1 : 0)
                (d, b) = r6.subtractingReportingOverflow(m6); let (d6b, b6b) = d.subtractingReportingOverflow(borrow)
                r6 = d6b; borrow = (b ? 1 : 0) + (b6b ? 1 : 0)
                (d, b) = r7.subtractingReportingOverflow(m7); let (d7b, _) = d.subtractingReportingOverflow(borrow)
                r7 = d7b
            }
        }

        return BigInt256(r0, r1, r2, r3)
    }

    // MARK: - 模逆与模幂

    func modInverse(_ modulus: BigInt256) -> BigInt256 {
        if isZero { fatalError("Cannot invert zero") }
        let (pMinus2, _) = modulus.sub(BigInt256(2, 0, 0, 0))
        return modPow(pMinus2, modulus)
    }

    func modPow(_ exp: BigInt256, _ modulus: BigInt256) -> BigInt256 {
        if exp.isZero { return BigInt256.one }

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

    // MARK: - 序列化

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

    static func fromBEBytes(_ bytes: [UInt8]) -> BigInt256 {
        var padded = [UInt8](repeating: 0, count: 32)
        let start = max(0, 32 - bytes.count)
        let copyLen = min(bytes.count, 32)
        for i in 0..<copyLen {
            padded[start + i] = bytes[bytes.count - copyLen + i]
        }

        // 直接解析4个limb，无临时数组
        func readU64BE(_ offset: Int) -> UInt64 {
            var v: UInt64 = 0
            for j in 0..<8 {
                v = (v << 8) | UInt64(padded[offset + j])
            }
            return v
        }

        let ll3 = readU64BE(0)
        let ll2 = readU64BE(8)
        let ll1 = readU64BE(16)
        let ll0 = readU64BE(24)
        return BigInt256(ll0, ll1, ll2, ll3)
    }

    func toBEBytes() -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 32)
        // l3 是最高位，写到bytes[0..7]
        for j in 0..<8 { bytes[7 - j] = UInt8(truncatingIfNeeded: l3 >> (j * 8)) }
        for j in 0..<8 { bytes[15 - j] = UInt8(truncatingIfNeeded: l2 >> (j * 8)) }
        for j in 0..<8 { bytes[23 - j] = UInt8(truncatingIfNeeded: l1 >> (j * 8)) }
        for j in 0..<8 { bytes[31 - j] = UInt8(truncatingIfNeeded: l0 >> (j * 8)) }
        return bytes
    }

    func toHex() -> String {
        let bytes = toBEBytes()
        return bytes.map { String(format: "%02X", $0) }.joined()
    }

    func toHexLower() -> String {
        return toHex().lowercased()
    }
}
