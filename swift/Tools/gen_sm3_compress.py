#!/usr/bin/env python3
"""Generates Sources/GMSwift/SM3Compress.swift: the SM3 compression function fully unrolled.

The message expansion is interleaved with the rounds and kept in 16 rolling values, the 64 constants T_j <<< j are
literals, and the working variables are renamed instead of moved, as OpenSSL's sm3_local.h does. The digests are
checked by the GB/T 32905 vectors and the streaming tests. Usage: Tools/gen_sm3_compress.py > Sources/GMSwift/SM3Compress.swift
"""


def rotl(x, n):
    n %= 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def literal(value):
    text = "%08X" % value
    return "0x%s_%s" % (text[:4], text[4:])


out = []
emit = out.append
emit("// 由 Tools/gen_sm3_compress.py 生成，请勿手改。")
emit("// SM3 压缩函数完全展开：消息扩展与轮函数交错，只保留16个滚动的扩展字，常量 T_j <<< j 预先算好，")
emit("// 工作变量通过改名而不是搬移来轮换。")
emit("")
emit("extension SM3State {")
emit("    @inline(__always)")
emit("    private static func rotl(_ x: UInt32, _ count: UInt32) -> UInt32 {")
emit("        return (x &<< count) | (x &>> (32 &- count))")
emit("    }")
emit("")
emit("    /// 处理 blocks 个连续的64字节分组")
emit("    mutating func compress(_ input: UnsafePointer<UInt8>, blocks: Int) {")
emit("        var (sa, sb, sc, sd, se, sf, sg, sh) = (a, b, c, d, e, f, g, h)")
emit("        var block = UnsafeRawPointer(input)")
emit("        var remaining = blocks")
emit("        while remaining > 0 {")
for i in range(16):
    emit("            var w%d = UInt32(bigEndian: block.loadUnaligned(fromByteOffset: %d, as: UInt32.self))" % (i, i * 4))
emit("            var (a, b, c, d, e, f, g, h) = (sa, sb, sc, sd, se, sf, sg, sh)")
names = ["a", "b", "c", "d", "e", "f", "g", "h"]
for j in range(64):
    A, B, C, D, E, F, G, H = names
    # W[j+4] is needed in round j; for j >= 12 it has to be expanded first.
    if j >= 12:
        k = j + 4
        emit(
            "            do {\n"
            "                let x = w%d ^ w%d ^ SM3State.rotl(w%d, 15)\n"
            "                w%d = x ^ SM3State.rotl(x, 15) ^ SM3State.rotl(x, 23) ^ SM3State.rotl(w%d, 7) ^ w%d\n"
            "            }" % ((k - 16) % 16, (k - 9) % 16, (k - 3) % 16, k % 16, (k - 13) % 16, (k - 6) % 16)
        )
    t = rotl(0x79CC4519 if j < 16 else 0x7A879D8A, j)
    wj = "w%d" % (j % 16)
    wj4 = "w%d" % ((j + 4) % 16)
    ff = "(%s ^ %s ^ %s)" % (A, B, C) if j < 16 else "((%s & %s) | ((%s | %s) & %s))" % (A, B, A, B, C)
    gg = "(%s ^ %s ^ %s)" % (E, F, G) if j < 16 else "(((%s ^ %s) & %s) ^ %s)" % (F, G, E, G)
    emit("            do {")
    emit("                let a12 = SM3State.rotl(%s, 12)" % A)
    emit("                let ss1 = SM3State.rotl(a12 &+ %s &+ %s, 7)" % (E, literal(t)))
    emit("                let ss2 = ss1 ^ a12")
    emit("                %s = %s &+ %s &+ ss2 &+ (%s ^ %s)" % (D, ff, D, wj, wj4))
    emit("                let tt2 = %s &+ %s &+ ss1 &+ %s" % (gg, H, wj))
    emit("                %s = tt2 ^ SM3State.rotl(tt2, 9) ^ SM3State.rotl(tt2, 17)" % H)
    emit("                %s = SM3State.rotl(%s, 9)" % (B, B))
    emit("                %s = SM3State.rotl(%s, 19)" % (F, F))
    emit("            }")
    # new A = old D slot (holds TT1), B = old A, C = old B, D = old C; same for E..H
    names = [D, A, B, C, H, E, F, G]
emit("            sa ^= %s" % names[0])
emit("            sb ^= %s" % names[1])
emit("            sc ^= %s" % names[2])
emit("            sd ^= %s" % names[3])
emit("            se ^= %s" % names[4])
emit("            sf ^= %s" % names[5])
emit("            sg ^= %s" % names[6])
emit("            sh ^= %s" % names[7])
emit("            block += 64")
emit("            remaining -= 1")
emit("        }")
emit("        (a, b, c, d, e, f, g, h) = (sa, sb, sc, sd, se, sf, sg, sh)")
emit("    }")
emit("}")
print("\n".join(out))
