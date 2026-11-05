// SM4 S 盒的布尔电路实现（由 Tools/gen_sm4_sbox.py 生成，请勿手改；测试会在全部256个输入上与标准 S 盒比对）。
//
// S(x) = A * inv(A * x + c) + c，求逆放到塔式域 GF((2^4)^2) 中计算。没有查表，也没有依赖数据的分支或内存访问，
// 每个位平面上只有 XOR/AND。

// S 盒按位平面计算：每个字节只用最低位，一个 UInt64 一次计算8个 S 盒（两个分组各一个字）。

@inline(__always)
func sm4SBoxCircuit(
    _ x0: UInt64, _ x1: UInt64, _ x2: UInt64, _ x3: UInt64, _ x4: UInt64, _ x5: UInt64, _ x6: UInt64, _ x7: UInt64,
    one: UInt64
) -> (UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64, UInt64) {
    let t0 = x0 ^ x1
    let t1 = x2 ^ x5
    let t2 = x3 ^ x4
    let t3 = x6 ^ x7
    let t4 = x6 ^ t1
    let t5 = x0 ^ t4
    let t6 = x1 ^ x7
    let t7 = x2 ^ t3
    let t8 = x4 ^ x7
    let t9 = x5 ^ t0
    let t10 = t0 ^ t2
    let t11 = t0 ^ t8
    let t12 = t1 ^ t2
    let t13 = t2 ^ t3
    let t14 = t3 ^ t9
    let t15 = t4 ^ t10
    let t16 = t6 ^ t12
    let t17 = t16 ^ one
    let t18 = t14 ^ one
    let t19 = x6 ^ one
    let t20 = t15 ^ one
    let t21 = t19 ^ t7
    let t22 = t21 ^ t20
    let t23 = t11 ^ t7
    let t24 = t23 ^ t20
    let t25 = t13 ^ t17
    let t26 = t5 ^ t18
    let t27 = t7 ^ t25
    let t28 = t22 ^ t17
    let t29 = t19 ^ t26
    let t30 = t24 ^ t18
    let t31 = t11 & t13
    let t32 = t19 & t5
    let t33 = t11 ^ t19
    let t34 = t13 ^ t5
    let t35 = t33 & t34
    let t36 = t35 ^ t31
    let t37 = t36 ^ t32
    let t38 = t7 & t17
    let t39 = t20 & t18
    let t40 = t7 ^ t20
    let t41 = t17 ^ t18
    let t42 = t40 & t41
    let t43 = t42 ^ t38
    let t44 = t43 ^ t39
    let t45 = t11 ^ t7
    let t46 = t19 ^ t20
    let t47 = t13 ^ t17
    let t48 = t5 ^ t18
    let t49 = t45 & t47
    let t50 = t46 & t48
    let t51 = t45 ^ t46
    let t52 = t47 ^ t48
    let t53 = t51 & t52
    let t54 = t53 ^ t49
    let t55 = t54 ^ t50
    let t56 = t49 ^ t31
    let t57 = t56 ^ t38
    let t58 = t55 ^ t37
    let t59 = t58 ^ t44
    let t60 = t50 ^ t32
    let t61 = t60 ^ t39
    let t62 = t32 ^ t57
    let t63 = t38 ^ t61
    let t64 = t31 ^ t63
    let t65 = t37 ^ t63
    let t66 = t65 ^ t44
    let t67 = t62 ^ t44
    let t68 = t67 ^ t39
    let t69 = t59 ^ t39
    let t70 = t27 ^ t64
    let t71 = t28 ^ t66
    let t72 = t29 ^ t68
    let t73 = t30 ^ t69
    let t74 = t70 ^ t71
    let t75 = t74 ^ t72
    let t76 = t72 & t70
    let t77 = t75 ^ t76
    let t78 = t72 & t71
    let t79 = t77 ^ t78
    let t80 = t78 & t70
    let t81 = t79 ^ t80
    let t82 = t81 ^ t73
    let t83 = t73 & t72
    let t84 = t83 & t71
    let t85 = t82 ^ t84
    let t86 = t71 & t70
    let t87 = t86 ^ t76
    let t88 = t87 ^ t78
    let t89 = t88 ^ t73
    let t90 = t73 & t71
    let t91 = t89 ^ t90
    let t92 = t90 & t70
    let t93 = t91 ^ t92
    let t94 = t86 ^ t72
    let t95 = t94 ^ t76
    let t96 = t95 ^ t73
    let t97 = t73 & t70
    let t98 = t96 ^ t97
    let t99 = t83 & t70
    let t100 = t98 ^ t99
    let t101 = t71 ^ t72
    let t102 = t101 ^ t73
    let t103 = t102 ^ t97
    let t104 = t103 ^ t90
    let t105 = t104 ^ t83
    let t106 = t105 ^ t84
    let t107 = t11 & t85
    let t108 = t19 & t93
    let t109 = t11 ^ t19
    let t110 = t85 ^ t93
    let t111 = t109 & t110
    let t112 = t111 ^ t107
    let t113 = t112 ^ t108
    let t114 = t7 & t100
    let t115 = t20 & t106
    let t116 = t7 ^ t20
    let t117 = t100 ^ t106
    let t118 = t116 & t117
    let t119 = t118 ^ t114
    let t120 = t119 ^ t115
    let t121 = t11 ^ t7
    let t122 = t19 ^ t20
    let t123 = t85 ^ t100
    let t124 = t93 ^ t106
    let t125 = t121 & t123
    let t126 = t122 & t124
    let t127 = t121 ^ t122
    let t128 = t123 ^ t124
    let t129 = t127 & t128
    let t130 = t129 ^ t125
    let t131 = t130 ^ t126
    let t132 = t125 ^ t107
    let t133 = t132 ^ t114
    let t134 = t131 ^ t113
    let t135 = t134 ^ t120
    let t136 = t126 ^ t108
    let t137 = t136 ^ t115
    let t138 = t108 ^ t133
    let t139 = t114 ^ t137
    let t140 = t107 ^ t139
    let t141 = t113 ^ t139
    let t142 = t141 ^ t120
    let t143 = t138 ^ t120
    let t144 = t143 ^ t115
    let t145 = t135 ^ t115
    let t146 = t13 ^ t11
    let t147 = t5 ^ t19
    let t148 = t17 ^ t7
    let t149 = t18 ^ t20
    let t150 = t146 & t85
    let t151 = t147 & t93
    let t152 = t146 ^ t147
    let t153 = t85 ^ t93
    let t154 = t152 & t153
    let t155 = t154 ^ t150
    let t156 = t155 ^ t151
    let t157 = t148 & t100
    let t158 = t149 & t106
    let t159 = t148 ^ t149
    let t160 = t100 ^ t106
    let t161 = t159 & t160
    let t162 = t161 ^ t157
    let t163 = t162 ^ t158
    let t164 = t146 ^ t148
    let t165 = t147 ^ t149
    let t166 = t85 ^ t100
    let t167 = t93 ^ t106
    let t168 = t164 & t166
    let t169 = t165 & t167
    let t170 = t164 ^ t165
    let t171 = t166 ^ t167
    let t172 = t170 & t171
    let t173 = t172 ^ t168
    let t174 = t173 ^ t169
    let t175 = t168 ^ t150
    let t176 = t175 ^ t157
    let t177 = t174 ^ t156
    let t178 = t177 ^ t163
    let t179 = t169 ^ t151
    let t180 = t179 ^ t158
    let t181 = t151 ^ t176
    let t182 = t157 ^ t180
    let t183 = t150 ^ t182
    let t184 = t156 ^ t182
    let t185 = t184 ^ t163
    let t186 = t181 ^ t163
    let t187 = t186 ^ t158
    let t188 = t178 ^ t158
    let t189 = t183 ^ t140
    let t190 = t187 ^ t144
    let t191 = t185 ^ t188
    let t192 = t185 ^ t189
    let t193 = t140 ^ t191
    let t194 = t142 ^ t145
    let t195 = t183 ^ t190
    let t196 = t187 ^ t145
    let t197 = t188 ^ t189
    let t198 = t145 ^ t192
    let t199 = t189 ^ t196
    let t200 = t190 ^ t192
    let t201 = t190 ^ t194
    let t202 = t193 ^ t194
    let t203 = t198 ^ one
    let t204 = t195 ^ one
    let t205 = t193 ^ one
    let t206 = t200 ^ one
    let t207 = t197 ^ one
    return (t203, t204, t201, t199, t205, t202, t206, t207)
}

/// 对每个字节应用 S 盒
@inline(__always)
func sm4SubstituteBytes(_ value: UInt64) -> UInt64 {
    let one: UInt64 = 0x0101_0101_0101_0101
    let out = sm4SBoxCircuit(
        value & one, (value &>> 1) & one, (value &>> 2) & one, (value &>> 3) & one,
        (value &>> 4) & one, (value &>> 5) & one, (value &>> 6) & one, (value &>> 7) & one,
        one: one
    )
    var result = out.0
    result |= out.1 &<< 1
    result |= out.2 &<< 2
    result |= out.3 &<< 3
    result |= out.4 &<< 4
    result |= out.5 &<< 5
    result |= out.6 &<< 6
    result |= out.7 &<< 7
    return result
}

/// 对32位字的每个字节应用 S 盒（高32位的输入是0，结果丢弃）
@inline(__always)
func sm4SubstituteBytes(_ value: UInt32) -> UInt32 {
    return UInt32(truncatingIfNeeded: sm4SubstituteBytes(UInt64(value)))
}
