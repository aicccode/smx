// 由 Tools/gen_sm3_compress.py 生成，请勿手改。
// SM3 压缩函数完全展开：消息扩展与轮函数交错，只保留16个滚动的扩展字，常量 T_j <<< j 预先算好，
// 工作变量通过改名而不是搬移来轮换。

extension SM3State {
    @inline(__always)
    private static func rotl(_ x: UInt32, _ count: UInt32) -> UInt32 {
        return (x &<< count) | (x &>> (32 &- count))
    }

    /// 处理 blocks 个连续的64字节分组
    mutating func compress(_ input: UnsafePointer<UInt8>, blocks: Int) {
        var (sa, sb, sc, sd, se, sf, sg, sh) = (a, b, c, d, e, f, g, h)
        var block = UnsafeRawPointer(input)
        var remaining = blocks
        while remaining > 0 {
            var w0 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 0, as: UInt32.self))
            var w1 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
            var w2 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 8, as: UInt32.self))
            var w3 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 12, as: UInt32.self))
            var w4 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 16, as: UInt32.self))
            var w5 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 20, as: UInt32.self))
            var w6 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 24, as: UInt32.self))
            var w7 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 28, as: UInt32.self))
            var w8 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 32, as: UInt32.self))
            var w9 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 36, as: UInt32.self))
            var w10 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 40, as: UInt32.self))
            var w11 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 44, as: UInt32.self))
            var w12 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 48, as: UInt32.self))
            var w13 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 52, as: UInt32.self))
            var w14 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 56, as: UInt32.self))
            var w15 = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: 60, as: UInt32.self))
            var (a, b, c, d, e, f, g, h) = (sa, sb, sc, sd, se, sf, sg, sh)
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0x79CC_4519, 7)
                let ss2 = ss1 ^ a12
                d = (a ^ b ^ c) &+ d &+ ss2 &+ (w0 ^ w4)
                let tt2 = (e ^ f ^ g) &+ h &+ ss1 &+ w0
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0xF398_8A32, 7)
                let ss2 = ss1 ^ a12
                c = (d ^ a ^ b) &+ c &+ ss2 &+ (w1 ^ w5)
                let tt2 = (h ^ e ^ f) &+ g &+ ss1 &+ w1
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0xE731_1465, 7)
                let ss2 = ss1 ^ a12
                b = (c ^ d ^ a) &+ b &+ ss2 &+ (w2 ^ w6)
                let tt2 = (g ^ h ^ e) &+ f &+ ss1 &+ w2
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0xCE62_28CB, 7)
                let ss2 = ss1 ^ a12
                a = (b ^ c ^ d) &+ a &+ ss2 &+ (w3 ^ w7)
                let tt2 = (f ^ g ^ h) &+ e &+ ss1 &+ w3
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0x9CC4_5197, 7)
                let ss2 = ss1 ^ a12
                d = (a ^ b ^ c) &+ d &+ ss2 &+ (w4 ^ w8)
                let tt2 = (e ^ f ^ g) &+ h &+ ss1 &+ w4
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0x3988_A32F, 7)
                let ss2 = ss1 ^ a12
                c = (d ^ a ^ b) &+ c &+ ss2 &+ (w5 ^ w9)
                let tt2 = (h ^ e ^ f) &+ g &+ ss1 &+ w5
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0x7311_465E, 7)
                let ss2 = ss1 ^ a12
                b = (c ^ d ^ a) &+ b &+ ss2 &+ (w6 ^ w10)
                let tt2 = (g ^ h ^ e) &+ f &+ ss1 &+ w6
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0xE622_8CBC, 7)
                let ss2 = ss1 ^ a12
                a = (b ^ c ^ d) &+ a &+ ss2 &+ (w7 ^ w11)
                let tt2 = (f ^ g ^ h) &+ e &+ ss1 &+ w7
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0xCC45_1979, 7)
                let ss2 = ss1 ^ a12
                d = (a ^ b ^ c) &+ d &+ ss2 &+ (w8 ^ w12)
                let tt2 = (e ^ f ^ g) &+ h &+ ss1 &+ w8
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0x988A_32F3, 7)
                let ss2 = ss1 ^ a12
                c = (d ^ a ^ b) &+ c &+ ss2 &+ (w9 ^ w13)
                let tt2 = (h ^ e ^ f) &+ g &+ ss1 &+ w9
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0x3114_65E7, 7)
                let ss2 = ss1 ^ a12
                b = (c ^ d ^ a) &+ b &+ ss2 &+ (w10 ^ w14)
                let tt2 = (g ^ h ^ e) &+ f &+ ss1 &+ w10
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0x6228_CBCE, 7)
                let ss2 = ss1 ^ a12
                a = (b ^ c ^ d) &+ a &+ ss2 &+ (w11 ^ w15)
                let tt2 = (f ^ g ^ h) &+ e &+ ss1 &+ w11
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w0 ^ w7 ^ SM3State.rotl(w13, 15)
                w0 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w3, 7) ^ w10
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0xC451_979C, 7)
                let ss2 = ss1 ^ a12
                d = (a ^ b ^ c) &+ d &+ ss2 &+ (w12 ^ w0)
                let tt2 = (e ^ f ^ g) &+ h &+ ss1 &+ w12
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w1 ^ w8 ^ SM3State.rotl(w14, 15)
                w1 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w4, 7) ^ w11
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0x88A3_2F39, 7)
                let ss2 = ss1 ^ a12
                c = (d ^ a ^ b) &+ c &+ ss2 &+ (w13 ^ w1)
                let tt2 = (h ^ e ^ f) &+ g &+ ss1 &+ w13
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w2 ^ w9 ^ SM3State.rotl(w15, 15)
                w2 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w5, 7) ^ w12
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0x1146_5E73, 7)
                let ss2 = ss1 ^ a12
                b = (c ^ d ^ a) &+ b &+ ss2 &+ (w14 ^ w2)
                let tt2 = (g ^ h ^ e) &+ f &+ ss1 &+ w14
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w3 ^ w10 ^ SM3State.rotl(w0, 15)
                w3 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w6, 7) ^ w13
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0x228C_BCE6, 7)
                let ss2 = ss1 ^ a12
                a = (b ^ c ^ d) &+ a &+ ss2 &+ (w15 ^ w3)
                let tt2 = (f ^ g ^ h) &+ e &+ ss1 &+ w15
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w4 ^ w11 ^ SM3State.rotl(w1, 15)
                w4 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w7, 7) ^ w14
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0x9D8A_7A87, 7)
                let ss2 = ss1 ^ a12
                d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w0 ^ w4)
                let tt2 = (((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w0
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w5 ^ w12 ^ SM3State.rotl(w2, 15)
                w5 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w8, 7) ^ w15
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0x3B14_F50F, 7)
                let ss2 = ss1 ^ a12
                c = ((d & a) | ((d | a) & b)) &+ c &+ ss2 &+ (w1 ^ w5)
                let tt2 = (((e ^ f) & h) ^ f) &+ g &+ ss1 &+ w1
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w6 ^ w13 ^ SM3State.rotl(w3, 15)
                w6 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w9, 7) ^ w0
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0x7629_EA1E, 7)
                let ss2 = ss1 ^ a12
                b = ((c & d) | ((c | d) & a)) &+ b &+ ss2 &+ (w2 ^ w6)
                let tt2 = (((h ^ e) & g) ^ e) &+ f &+ ss1 &+ w2
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w7 ^ w14 ^ SM3State.rotl(w4, 15)
                w7 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w10, 7) ^ w1
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0xEC53_D43C, 7)
                let ss2 = ss1 ^ a12
                a = ((b & c) | ((b | c) & d)) &+ a &+ ss2 &+ (w3 ^ w7)
                let tt2 = (((g ^ h) & f) ^ h) &+ e &+ ss1 &+ w3
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w8 ^ w15 ^ SM3State.rotl(w5, 15)
                w8 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w11, 7) ^ w2
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0xD8A7_A879, 7)
                let ss2 = ss1 ^ a12
                d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w4 ^ w8)
                let tt2 = (((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w4
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w9 ^ w0 ^ SM3State.rotl(w6, 15)
                w9 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w12, 7) ^ w3
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0xB14F_50F3, 7)
                let ss2 = ss1 ^ a12
                c = ((d & a) | ((d | a) & b)) &+ c &+ ss2 &+ (w5 ^ w9)
                let tt2 = (((e ^ f) & h) ^ f) &+ g &+ ss1 &+ w5
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w10 ^ w1 ^ SM3State.rotl(w7, 15)
                w10 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w13, 7) ^ w4
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0x629E_A1E7, 7)
                let ss2 = ss1 ^ a12
                b = ((c & d) | ((c | d) & a)) &+ b &+ ss2 &+ (w6 ^ w10)
                let tt2 = (((h ^ e) & g) ^ e) &+ f &+ ss1 &+ w6
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w11 ^ w2 ^ SM3State.rotl(w8, 15)
                w11 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w14, 7) ^ w5
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0xC53D_43CE, 7)
                let ss2 = ss1 ^ a12
                a = ((b & c) | ((b | c) & d)) &+ a &+ ss2 &+ (w7 ^ w11)
                let tt2 = (((g ^ h) & f) ^ h) &+ e &+ ss1 &+ w7
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w12 ^ w3 ^ SM3State.rotl(w9, 15)
                w12 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w15, 7) ^ w6
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0x8A7A_879D, 7)
                let ss2 = ss1 ^ a12
                d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w8 ^ w12)
                let tt2 = (((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w8
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w13 ^ w4 ^ SM3State.rotl(w10, 15)
                w13 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w0, 7) ^ w7
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0x14F5_0F3B, 7)
                let ss2 = ss1 ^ a12
                c = ((d & a) | ((d | a) & b)) &+ c &+ ss2 &+ (w9 ^ w13)
                let tt2 = (((e ^ f) & h) ^ f) &+ g &+ ss1 &+ w9
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w14 ^ w5 ^ SM3State.rotl(w11, 15)
                w14 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w1, 7) ^ w8
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0x29EA_1E76, 7)
                let ss2 = ss1 ^ a12
                b = ((c & d) | ((c | d) & a)) &+ b &+ ss2 &+ (w10 ^ w14)
                let tt2 = (((h ^ e) & g) ^ e) &+ f &+ ss1 &+ w10
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w15 ^ w6 ^ SM3State.rotl(w12, 15)
                w15 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w2, 7) ^ w9
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0x53D4_3CEC, 7)
                let ss2 = ss1 ^ a12
                a = ((b & c) | ((b | c) & d)) &+ a &+ ss2 &+ (w11 ^ w15)
                let tt2 = (((g ^ h) & f) ^ h) &+ e &+ ss1 &+ w11
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w0 ^ w7 ^ SM3State.rotl(w13, 15)
                w0 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w3, 7) ^ w10
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0xA7A8_79D8, 7)
                let ss2 = ss1 ^ a12
                d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w12 ^ w0)
                let tt2 = (((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w12
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w1 ^ w8 ^ SM3State.rotl(w14, 15)
                w1 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w4, 7) ^ w11
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0x4F50_F3B1, 7)
                let ss2 = ss1 ^ a12
                c = ((d & a) | ((d | a) & b)) &+ c &+ ss2 &+ (w13 ^ w1)
                let tt2 = (((e ^ f) & h) ^ f) &+ g &+ ss1 &+ w13
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w2 ^ w9 ^ SM3State.rotl(w15, 15)
                w2 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w5, 7) ^ w12
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0x9EA1_E762, 7)
                let ss2 = ss1 ^ a12
                b = ((c & d) | ((c | d) & a)) &+ b &+ ss2 &+ (w14 ^ w2)
                let tt2 = (((h ^ e) & g) ^ e) &+ f &+ ss1 &+ w14
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w3 ^ w10 ^ SM3State.rotl(w0, 15)
                w3 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w6, 7) ^ w13
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0x3D43_CEC5, 7)
                let ss2 = ss1 ^ a12
                a = ((b & c) | ((b | c) & d)) &+ a &+ ss2 &+ (w15 ^ w3)
                let tt2 = (((g ^ h) & f) ^ h) &+ e &+ ss1 &+ w15
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w4 ^ w11 ^ SM3State.rotl(w1, 15)
                w4 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w7, 7) ^ w14
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0x7A87_9D8A, 7)
                let ss2 = ss1 ^ a12
                d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w0 ^ w4)
                let tt2 = (((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w0
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w5 ^ w12 ^ SM3State.rotl(w2, 15)
                w5 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w8, 7) ^ w15
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0xF50F_3B14, 7)
                let ss2 = ss1 ^ a12
                c = ((d & a) | ((d | a) & b)) &+ c &+ ss2 &+ (w1 ^ w5)
                let tt2 = (((e ^ f) & h) ^ f) &+ g &+ ss1 &+ w1
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w6 ^ w13 ^ SM3State.rotl(w3, 15)
                w6 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w9, 7) ^ w0
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0xEA1E_7629, 7)
                let ss2 = ss1 ^ a12
                b = ((c & d) | ((c | d) & a)) &+ b &+ ss2 &+ (w2 ^ w6)
                let tt2 = (((h ^ e) & g) ^ e) &+ f &+ ss1 &+ w2
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w7 ^ w14 ^ SM3State.rotl(w4, 15)
                w7 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w10, 7) ^ w1
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0xD43C_EC53, 7)
                let ss2 = ss1 ^ a12
                a = ((b & c) | ((b | c) & d)) &+ a &+ ss2 &+ (w3 ^ w7)
                let tt2 = (((g ^ h) & f) ^ h) &+ e &+ ss1 &+ w3
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w8 ^ w15 ^ SM3State.rotl(w5, 15)
                w8 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w11, 7) ^ w2
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0xA879_D8A7, 7)
                let ss2 = ss1 ^ a12
                d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w4 ^ w8)
                let tt2 = (((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w4
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w9 ^ w0 ^ SM3State.rotl(w6, 15)
                w9 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w12, 7) ^ w3
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0x50F3_B14F, 7)
                let ss2 = ss1 ^ a12
                c = ((d & a) | ((d | a) & b)) &+ c &+ ss2 &+ (w5 ^ w9)
                let tt2 = (((e ^ f) & h) ^ f) &+ g &+ ss1 &+ w5
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w10 ^ w1 ^ SM3State.rotl(w7, 15)
                w10 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w13, 7) ^ w4
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0xA1E7_629E, 7)
                let ss2 = ss1 ^ a12
                b = ((c & d) | ((c | d) & a)) &+ b &+ ss2 &+ (w6 ^ w10)
                let tt2 = (((h ^ e) & g) ^ e) &+ f &+ ss1 &+ w6
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w11 ^ w2 ^ SM3State.rotl(w8, 15)
                w11 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w14, 7) ^ w5
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0x43CE_C53D, 7)
                let ss2 = ss1 ^ a12
                a = ((b & c) | ((b | c) & d)) &+ a &+ ss2 &+ (w7 ^ w11)
                let tt2 = (((g ^ h) & f) ^ h) &+ e &+ ss1 &+ w7
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w12 ^ w3 ^ SM3State.rotl(w9, 15)
                w12 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w15, 7) ^ w6
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0x879D_8A7A, 7)
                let ss2 = ss1 ^ a12
                d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w8 ^ w12)
                let tt2 = (((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w8
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w13 ^ w4 ^ SM3State.rotl(w10, 15)
                w13 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w0, 7) ^ w7
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0x0F3B_14F5, 7)
                let ss2 = ss1 ^ a12
                c = ((d & a) | ((d | a) & b)) &+ c &+ ss2 &+ (w9 ^ w13)
                let tt2 = (((e ^ f) & h) ^ f) &+ g &+ ss1 &+ w9
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w14 ^ w5 ^ SM3State.rotl(w11, 15)
                w14 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w1, 7) ^ w8
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0x1E76_29EA, 7)
                let ss2 = ss1 ^ a12
                b = ((c & d) | ((c | d) & a)) &+ b &+ ss2 &+ (w10 ^ w14)
                let tt2 = (((h ^ e) & g) ^ e) &+ f &+ ss1 &+ w10
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w15 ^ w6 ^ SM3State.rotl(w12, 15)
                w15 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w2, 7) ^ w9
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0x3CEC_53D4, 7)
                let ss2 = ss1 ^ a12
                a = ((b & c) | ((b | c) & d)) &+ a &+ ss2 &+ (w11 ^ w15)
                let tt2 = (((g ^ h) & f) ^ h) &+ e &+ ss1 &+ w11
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w0 ^ w7 ^ SM3State.rotl(w13, 15)
                w0 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w3, 7) ^ w10
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0x79D8_A7A8, 7)
                let ss2 = ss1 ^ a12
                d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w12 ^ w0)
                let tt2 = (((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w12
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w1 ^ w8 ^ SM3State.rotl(w14, 15)
                w1 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w4, 7) ^ w11
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0xF3B1_4F50, 7)
                let ss2 = ss1 ^ a12
                c = ((d & a) | ((d | a) & b)) &+ c &+ ss2 &+ (w13 ^ w1)
                let tt2 = (((e ^ f) & h) ^ f) &+ g &+ ss1 &+ w13
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w2 ^ w9 ^ SM3State.rotl(w15, 15)
                w2 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w5, 7) ^ w12
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0xE762_9EA1, 7)
                let ss2 = ss1 ^ a12
                b = ((c & d) | ((c | d) & a)) &+ b &+ ss2 &+ (w14 ^ w2)
                let tt2 = (((h ^ e) & g) ^ e) &+ f &+ ss1 &+ w14
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w3 ^ w10 ^ SM3State.rotl(w0, 15)
                w3 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w6, 7) ^ w13
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0xCEC5_3D43, 7)
                let ss2 = ss1 ^ a12
                a = ((b & c) | ((b | c) & d)) &+ a &+ ss2 &+ (w15 ^ w3)
                let tt2 = (((g ^ h) & f) ^ h) &+ e &+ ss1 &+ w15
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w4 ^ w11 ^ SM3State.rotl(w1, 15)
                w4 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w7, 7) ^ w14
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0x9D8A_7A87, 7)
                let ss2 = ss1 ^ a12
                d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w0 ^ w4)
                let tt2 = (((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w0
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w5 ^ w12 ^ SM3State.rotl(w2, 15)
                w5 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w8, 7) ^ w15
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0x3B14_F50F, 7)
                let ss2 = ss1 ^ a12
                c = ((d & a) | ((d | a) & b)) &+ c &+ ss2 &+ (w1 ^ w5)
                let tt2 = (((e ^ f) & h) ^ f) &+ g &+ ss1 &+ w1
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w6 ^ w13 ^ SM3State.rotl(w3, 15)
                w6 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w9, 7) ^ w0
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0x7629_EA1E, 7)
                let ss2 = ss1 ^ a12
                b = ((c & d) | ((c | d) & a)) &+ b &+ ss2 &+ (w2 ^ w6)
                let tt2 = (((h ^ e) & g) ^ e) &+ f &+ ss1 &+ w2
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w7 ^ w14 ^ SM3State.rotl(w4, 15)
                w7 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w10, 7) ^ w1
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0xEC53_D43C, 7)
                let ss2 = ss1 ^ a12
                a = ((b & c) | ((b | c) & d)) &+ a &+ ss2 &+ (w3 ^ w7)
                let tt2 = (((g ^ h) & f) ^ h) &+ e &+ ss1 &+ w3
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w8 ^ w15 ^ SM3State.rotl(w5, 15)
                w8 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w11, 7) ^ w2
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0xD8A7_A879, 7)
                let ss2 = ss1 ^ a12
                d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w4 ^ w8)
                let tt2 = (((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w4
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w9 ^ w0 ^ SM3State.rotl(w6, 15)
                w9 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w12, 7) ^ w3
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0xB14F_50F3, 7)
                let ss2 = ss1 ^ a12
                c = ((d & a) | ((d | a) & b)) &+ c &+ ss2 &+ (w5 ^ w9)
                let tt2 = (((e ^ f) & h) ^ f) &+ g &+ ss1 &+ w5
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w10 ^ w1 ^ SM3State.rotl(w7, 15)
                w10 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w13, 7) ^ w4
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0x629E_A1E7, 7)
                let ss2 = ss1 ^ a12
                b = ((c & d) | ((c | d) & a)) &+ b &+ ss2 &+ (w6 ^ w10)
                let tt2 = (((h ^ e) & g) ^ e) &+ f &+ ss1 &+ w6
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w11 ^ w2 ^ SM3State.rotl(w8, 15)
                w11 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w14, 7) ^ w5
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0xC53D_43CE, 7)
                let ss2 = ss1 ^ a12
                a = ((b & c) | ((b | c) & d)) &+ a &+ ss2 &+ (w7 ^ w11)
                let tt2 = (((g ^ h) & f) ^ h) &+ e &+ ss1 &+ w7
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w12 ^ w3 ^ SM3State.rotl(w9, 15)
                w12 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w15, 7) ^ w6
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0x8A7A_879D, 7)
                let ss2 = ss1 ^ a12
                d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w8 ^ w12)
                let tt2 = (((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w8
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w13 ^ w4 ^ SM3State.rotl(w10, 15)
                w13 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w0, 7) ^ w7
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0x14F5_0F3B, 7)
                let ss2 = ss1 ^ a12
                c = ((d & a) | ((d | a) & b)) &+ c &+ ss2 &+ (w9 ^ w13)
                let tt2 = (((e ^ f) & h) ^ f) &+ g &+ ss1 &+ w9
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w14 ^ w5 ^ SM3State.rotl(w11, 15)
                w14 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w1, 7) ^ w8
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0x29EA_1E76, 7)
                let ss2 = ss1 ^ a12
                b = ((c & d) | ((c | d) & a)) &+ b &+ ss2 &+ (w10 ^ w14)
                let tt2 = (((h ^ e) & g) ^ e) &+ f &+ ss1 &+ w10
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w15 ^ w6 ^ SM3State.rotl(w12, 15)
                w15 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w2, 7) ^ w9
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0x53D4_3CEC, 7)
                let ss2 = ss1 ^ a12
                a = ((b & c) | ((b | c) & d)) &+ a &+ ss2 &+ (w11 ^ w15)
                let tt2 = (((g ^ h) & f) ^ h) &+ e &+ ss1 &+ w11
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            do {
                let x = w0 ^ w7 ^ SM3State.rotl(w13, 15)
                w0 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w3, 7) ^ w10
            }
            do {
                let a12 = SM3State.rotl(a, 12)
                let ss1 = SM3State.rotl(a12 &+ e &+ 0xA7A8_79D8, 7)
                let ss2 = ss1 ^ a12
                d = ((a & b) | ((a | b) & c)) &+ d &+ ss2 &+ (w12 ^ w0)
                let tt2 = (((f ^ g) & e) ^ g) &+ h &+ ss1 &+ w12
                h = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                b = SM3State.rotl(b, 9)
                f = SM3State.rotl(f, 19)
            }
            do {
                let x = w1 ^ w8 ^ SM3State.rotl(w14, 15)
                w1 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w4, 7) ^ w11
            }
            do {
                let a12 = SM3State.rotl(d, 12)
                let ss1 = SM3State.rotl(a12 &+ h &+ 0x4F50_F3B1, 7)
                let ss2 = ss1 ^ a12
                c = ((d & a) | ((d | a) & b)) &+ c &+ ss2 &+ (w13 ^ w1)
                let tt2 = (((e ^ f) & h) ^ f) &+ g &+ ss1 &+ w13
                g = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                a = SM3State.rotl(a, 9)
                e = SM3State.rotl(e, 19)
            }
            do {
                let x = w2 ^ w9 ^ SM3State.rotl(w15, 15)
                w2 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w5, 7) ^ w12
            }
            do {
                let a12 = SM3State.rotl(c, 12)
                let ss1 = SM3State.rotl(a12 &+ g &+ 0x9EA1_E762, 7)
                let ss2 = ss1 ^ a12
                b = ((c & d) | ((c | d) & a)) &+ b &+ ss2 &+ (w14 ^ w2)
                let tt2 = (((h ^ e) & g) ^ e) &+ f &+ ss1 &+ w14
                f = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                d = SM3State.rotl(d, 9)
                h = SM3State.rotl(h, 19)
            }
            do {
                let x = w3 ^ w10 ^ SM3State.rotl(w0, 15)
                w3 = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w6, 7) ^ w13
            }
            do {
                let a12 = SM3State.rotl(b, 12)
                let ss1 = SM3State.rotl(a12 &+ f &+ 0x3D43_CEC5, 7)
                let ss2 = ss1 ^ a12
                a = ((b & c) | ((b | c) & d)) &+ a &+ ss2 &+ (w15 ^ w3)
                let tt2 = (((g ^ h) & f) ^ h) &+ e &+ ss1 &+ w15
                e = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)
                c = SM3State.rotl(c, 9)
                g = SM3State.rotl(g, 19)
            }
            sa ^= a
            sb ^= b
            sc ^= c
            sd ^= d
            se ^= e
            sf ^= f
            sg ^= g
            sh ^= h
            block += 64
            remaining -= 1
        }
        (a, b, c, d, e, f, g, h) = (sa, sb, sc, sd, se, sf, sg, sh)
    }
}
