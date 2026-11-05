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

    // 压缩函数在 SM3Compress.swift（由 Tools/gen_sm3_compress.py 生成）。
}

/// 流式 SM3，64字节缓冲直接存放在结构体内
struct SM3Core {
    private var state = SM3State()
    private var buffer: (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64) = (0, 0, 0, 0, 0, 0, 0, 0)
    private var bufferOffset = 0
    private var byteCount: UInt64 = 0
    private var overLimit = false
    private var finished = false

    /// 标准允许的最大输入：比特长度必须小于 2^64
    static let maximumByteCount: UInt64 = (1 << 61) - 1

    init() {}

    /// 测试入口：从指定的已处理字节数开始计数
    init(testingByteCount: UInt64) {
        byteCount = testingByteCount
    }

    var isOverLimit: Bool { return overLimit }

    mutating func update(_ data: UnsafeBufferPointer<UInt8>) {
        // 结束之后不再有合法的状态可以继续；复制一份再结束才能继续累积。
        if finished {
            overLimit = true
            return
        }
        guard var source = data.baseAddress else {
            return
        }
        var remaining = data.count
        let (total, overflow) = byteCount.addingReportingOverflow(UInt64(remaining))
        if overflow || total > SM3Core.maximumByteCount {
            // 不回绕：标记后忽略输入，finalize 不产生摘要
            overLimit = true
            return
        }
        byteCount = total

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

    /// 填充并处理最后的分组，把摘要写入 output（32字节），返回 true。
    /// 超过长度上限或已经结束过时不写入并返回 false，不会产生错误或陈旧的摘要。
    /// 值类型：复制后可以各自结束。
    @discardableResult
    mutating func finalize(into output: UnsafeMutablePointer<UInt8>) -> Bool {
        if finished || overLimit {
            overLimit = true
            return false
        }
        finished = true
        let bitLength = byteCount &<< 3
        let start = bufferOffset
        let needsExtraBlock = start + 1 > 56
        withUnsafeMutableBytes(of: &buffer) { raw in
            raw[start] = 0x80
            let end = needsExtraBlock ? 64 : 56
            if end > start + 1, let base = raw.baseAddress {
                (base + start + 1).initializeMemory(as: UInt8.self, repeating: 0, count: end - start - 1)
            }
        }
        if needsExtraBlock {
            compressBuffer()
            withUnsafeMutableBytes(of: &buffer) { raw in
                raw.baseAddress?.initializeMemory(as: UInt8.self, repeating: 0, count: 56)
            }
        }
        withUnsafeMutableBytes(of: &buffer) { raw in
            raw.storeBytes(of: bitLength.bigEndian, toByteOffset: 56, as: UInt64.self)
        }
        compressBuffer()
        bufferOffset = 0

        let raw = UnsafeMutableRawPointer(output)
        raw.storeBytes(of: state.a.bigEndian, toByteOffset: 0, as: UInt32.self)
        raw.storeBytes(of: state.b.bigEndian, toByteOffset: 4, as: UInt32.self)
        raw.storeBytes(of: state.c.bigEndian, toByteOffset: 8, as: UInt32.self)
        raw.storeBytes(of: state.d.bigEndian, toByteOffset: 12, as: UInt32.self)
        raw.storeBytes(of: state.e.bigEndian, toByteOffset: 16, as: UInt32.self)
        raw.storeBytes(of: state.f.bigEndian, toByteOffset: 20, as: UInt32.self)
        raw.storeBytes(of: state.g.bigEndian, toByteOffset: 24, as: UInt32.self)
        raw.storeBytes(of: state.h.bigEndian, toByteOffset: 28, as: UInt32.self)
        return true
    }

    /// 超过长度上限或已经结束过时返回空数组
    mutating func finalize() -> [UInt8] {
        if finished || overLimit {
            overLimit = true
            return []
        }
        return [UInt8](unsafeUninitializedCapacity: 32) { buffer, initialized in
            if let base = buffer.baseAddress {
                finalize(into: base)
            }
            initialized = 32
        }
    }
}

/// finalize 之前读取得到空值。finalize 可以重复调用，摘要不变。finalize 之后再 update 是误用：
/// 摘要被清除，之后一直得到空值，不会返回不包含新数据的旧摘要。
final class SM3 {
    private var core = SM3Core()
    private var digest: [UInt8] = []
    private var finished = false
    private var misused = false

    func update(_ data: [UInt8]) -> SM3 {
        if finished {
            markMisused()
        } else {
            core.update(data)
        }
        return self
    }

    func update(_ string: String) -> SM3 {
        if finished {
            markMisused()
        } else {
            core.update(string)
        }
        return self
    }

    private func markMisused() {
        misused = true
        digest = []
    }

    func finalize() -> SM3 {
        if !finished {
            finished = true
            digest = core.finalize()
        }
        return self
    }

    /// 大写十六进制摘要；未结束、误用或输入超过上限时返回空串
    func getHash() -> String {
        return Hex.encode(digest, gap: Hex.uppercaseGap)
    }

    /// 摘要字节；未结束、误用或输入超过上限时返回空数组
    func getHashBytes() -> [UInt8] {
        return digest
    }
}

func getSM3() -> SM3 {
    return SM3()
}
