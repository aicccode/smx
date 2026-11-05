// SM3 密码杂凑算法（GB/T 32905）。
// SM3Core 是不含堆分配的值类型，内部调用可直接复制中间状态（例如 KDF）；SM3 是它的引用类型外壳。

/// SM3 压缩状态
struct SM3State {
    var a: UInt32 = 0x7380_166F
    var b: UInt32 = 0x4914_B2B9
    var c: UInt32 = 0x1724_42D7
    var d: UInt32 = 0xDA8A_0600
    var e: UInt32 = 0xA96F_30BC
    var f: UInt32 = 0x1631_38AA
    var g: UInt32 = 0xE38D_EE4D
    var h: UInt32 = 0xB0FB_0E4E

    @inline(__always)
    private static func rotl(_ x: UInt32, _ count: UInt32) -> UInt32 {
        return (x &<< count) | (x &>> (32 &- count))
    }

    @inline(__always)
    private static func p0(_ x: UInt32) -> UInt32 {
        return x ^ rotl(x, 9) ^ rotl(x, 17)
    }

    @inline(__always)
    private static func p1(_ x: UInt32) -> UInt32 {
        return x ^ rotl(x, 15) ^ rotl(x, 23)
    }

    /// 处理 blocks 个连续的64字节分组
    mutating func compress(_ input: UnsafePointer<UInt8>, blocks: Int) {
        withUnsafeTemporaryAllocation(of: UInt32.self, capacity: 68) { schedule in
            guard let w = schedule.baseAddress else {
                return
            }
            var block = input
            for _ in 0..<blocks {
                compressBlock(block, schedule: w)
                block += 64
            }
        }
    }

    /// 第 0...15 轮。调用方通过轮换实参代替逐轮搬移8个工作变量。
    @inline(__always)
    private static func roundEarly(
        _ a: UInt32, _ b: inout UInt32, _ c: UInt32, _ d: inout UInt32,
        _ e: UInt32, _ f: inout UInt32, _ g: UInt32, _ h: inout UInt32,
        _ w: UnsafePointer<UInt32>, _ index: Int, _ constant: inout UInt32
    ) {
        let a12 = rotl(a, 12)
        let ss1 = rotl(a12 &+ e &+ constant, 7)
        let ss2 = ss1 ^ a12
        d = (a ^ b ^ c) &+ d &+ ss2 &+ (w[index] ^ w[index &+ 4])
        h = p0((e ^ f ^ g) &+ h &+ ss1 &+ w[index])
        b = rotl(b, 9)
        f = rotl(f, 19)
        constant = rotl(constant, 1)
    }

    /// 第 16...63 轮
    @inline(__always)
    private static func roundLate(
        _ a: UInt32, _ b: inout UInt32, _ c: UInt32, _ d: inout UInt32,
        _ e: UInt32, _ f: inout UInt32, _ g: UInt32, _ h: inout UInt32,
        _ w: UnsafePointer<UInt32>, _ index: Int, _ constant: inout UInt32
    ) {
        let a12 = rotl(a, 12)
        let ss1 = rotl(a12 &+ e &+ constant, 7)
        let ss2 = ss1 ^ a12
        d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w[index] ^ w[index &+ 4])
        h = p0((((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w[index])
        b = rotl(b, 9)
        f = rotl(f, 19)
        constant = rotl(constant, 1)
    }

    @inline(__always)
    private mutating func compressBlock(_ block: UnsafePointer<UInt8>, schedule w: UnsafeMutablePointer<UInt32>) {
        let raw = UnsafeRawPointer(block)
        for index in 0..<16 {
            w[index] = UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: index &* 4, as: UInt32.self))
        }
        for index in 16..<68 {
            w[index] =
                SM3State.p1(w[index &- 16] ^ w[index &- 9] ^ SM3State.rotl(w[index &- 3], 15))
                ^ SM3State.rotl(w[index &- 13], 7) ^ w[index &- 6]
        }

        var (va, vb, vc, vd, ve, vf, vg, vh) = (a, b, c, d, e, f, g, h)
        let schedule = UnsafePointer(w)

        var constant: UInt32 = 0x79CC_4519
        for index in stride(from: 0, to: 16, by: 4) {
            SM3State.roundEarly(va, &vb, vc, &vd, ve, &vf, vg, &vh, schedule, index, &constant)
            SM3State.roundEarly(vd, &va, vb, &vc, vh, &ve, vf, &vg, schedule, index &+ 1, &constant)
            SM3State.roundEarly(vc, &vd, va, &vb, vg, &vh, ve, &vf, schedule, index &+ 2, &constant)
            SM3State.roundEarly(vb, &vc, vd, &va, vf, &vg, vh, &ve, schedule, index &+ 3, &constant)
        }

        // 0x7A879D8A 循环左移16位
        constant = 0x9D8A_7A87
        for index in stride(from: 16, to: 64, by: 4) {
            SM3State.roundLate(va, &vb, vc, &vd, ve, &vf, vg, &vh, schedule, index, &constant)
            SM3State.roundLate(vd, &va, vb, &vc, vh, &ve, vf, &vg, schedule, index &+ 1, &constant)
            SM3State.roundLate(vc, &vd, va, &vb, vg, &vh, ve, &vf, schedule, index &+ 2, &constant)
            SM3State.roundLate(vb, &vc, vd, &va, vf, &vg, vh, &ve, schedule, index &+ 3, &constant)
        }

        a ^= va
        b ^= vb
        c ^= vc
        d ^= vd
        e ^= ve
        f ^= vf
        g ^= vg
        h ^= vh
    }
}

/// 流式 SM3，64字节缓冲直接存放在结构体内
struct SM3Core {
    private var state = SM3State()
    private var buffer: (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64) = (0, 0, 0, 0, 0, 0, 0, 0)
    private var bufferOffset = 0
    private var byteCount = 0

    mutating func update(_ data: UnsafeBufferPointer<UInt8>) {
        guard var source = data.baseAddress else {
            return
        }
        var remaining = data.count
        byteCount += remaining

        if bufferOffset > 0 {
            let offset = bufferOffset
            let take = min(64 - offset, remaining)
            withUnsafeMutableBytes(of: &buffer) { raw in
                raw.baseAddress?.advanced(by: offset).copyMemory(from: source, byteCount: take)
            }
            bufferOffset += take
            source += take
            remaining -= take
            if bufferOffset == 64 {
                compressBuffer()
                bufferOffset = 0
            }
        }

        if remaining >= 64 {
            let blocks = remaining / 64
            state.compress(source, blocks: blocks)
            source += blocks * 64
            remaining -= blocks * 64
        }

        if remaining > 0 {
            withUnsafeMutableBytes(of: &buffer) { raw in
                raw.baseAddress?.copyMemory(from: source, byteCount: remaining)
            }
            bufferOffset = remaining
        }
    }

    @inline(__always)
    mutating func update(_ bytes: [UInt8]) {
        bytes.withUnsafeBufferPointer { update($0) }
    }

    mutating func update(_ string: String) {
        var string = string
        string.withUTF8 { update($0) }
    }

    /// 写入32字节大端表示
    @inline(__always)
    mutating func update(_ value: BigInt256) {
        withUnsafeTemporaryAllocation(of: UInt8.self, capacity: 32) { bytes in
            if let base = bytes.baseAddress {
                value.writeBE(to: base)
            }
            update(UnsafeBufferPointer(bytes))
        }
    }

    @inline(__always)
    mutating func update(byte: UInt8) {
        var byte = byte
        withUnsafePointer(to: &byte) { update(UnsafeBufferPointer(start: $0, count: 1)) }
    }

    private mutating func compressBuffer() {
        var pending = state
        withUnsafeBytes(of: &buffer) { raw in
            if let base = raw.bindMemory(to: UInt8.self).baseAddress {
                pending.compress(base, blocks: 1)
            }
        }
        state = pending
    }

    /// 填充并处理最后的分组，把摘要写入 output（32字节）。
    /// 结束后内部状态保持为填充之后的状态，缓冲偏移停留在56，这与历史实现一致。
    mutating func finalize(into output: UnsafeMutablePointer<UInt8>) {
        let bitLength = byteCount * 8
        let start = bufferOffset
        let needsExtraBlock = start + 1 > 56
        withUnsafeMutableBytes(of: &buffer) { raw in
            raw[start] = 0x80
            let end = needsExtraBlock ? 64 : 56
            for index in (start + 1)..<max(start + 1, end) {
                raw[index] = 0
            }
        }
        if needsExtraBlock {
            compressBuffer()
            withUnsafeMutableBytes(of: &buffer) { raw in
                for index in 0..<56 {
                    raw[index] = 0
                }
            }
        }
        withUnsafeMutableBytes(of: &buffer) { raw in
            raw.storeBytes(of: UInt64(truncatingIfNeeded: bitLength).bigEndian, toByteOffset: 56, as: UInt64.self)
        }
        compressBuffer()
        bufferOffset = 56

        let words = (state.a, state.b, state.c, state.d, state.e, state.f, state.g, state.h)
        withUnsafeBytes(of: words) { raw in
            for index in 0..<8 {
                let word = raw.load(fromByteOffset: index * 4, as: UInt32.self)
                output[index * 4] = UInt8(truncatingIfNeeded: word &>> 24)
                output[index * 4 + 1] = UInt8(truncatingIfNeeded: word &>> 16)
                output[index * 4 + 2] = UInt8(truncatingIfNeeded: word &>> 8)
                output[index * 4 + 3] = UInt8(truncatingIfNeeded: word)
            }
        }
    }

    mutating func finalize() -> [UInt8] {
        return [UInt8](unsafeUninitializedCapacity: 32) { buffer, initialized in
            if let base = buffer.baseAddress {
                finalize(into: base)
            }
            initialized = 32
        }
    }
}

final class SM3 {
    private var core = SM3Core()
    private var digest: [UInt8] = []

    func update(_ data: [UInt8]) -> SM3 {
        core.update(data)
        return self
    }

    func update(_ string: String) -> SM3 {
        core.update(string)
        return self
    }

    func finalize() -> SM3 {
        digest = core.finalize()
        return self
    }

    /// 大写十六进制摘要；finalize 之前返回空串
    func getHash() -> String {
        return Hex.encode(digest, gap: Hex.uppercaseGap)
    }

    /// 摘要字节；finalize 之前返回空数组
    func getHashBytes() -> [UInt8] {
        return digest
    }
}

func getSM3() -> SM3 {
    return SM3()
}
