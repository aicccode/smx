using System.Runtime.CompilerServices;

namespace SMX;

/// <summary>
/// The SM4 S-box as a straight-line Boolean circuit, used wherever no hardware AES path exists. It contains no table,
/// no branch and no data-dependent memory access, so its timing does not depend on secret input as far as the runtime
/// executes the gates as written. Each byte of the word is an independent lane: bit i of every byte lives in one word.
/// The circuit is generated: SM4 is affine-equivalent to AES, whose inversion is computed in the tower field
/// GF(((2^2)^2)^2), 36 AND and 139 XOR gates. A unit test checks it against the standard S-box on all 256 inputs.
/// </summary>
internal static class Sm4SBoxCircuit
{
    private const uint One = 0x01010101;

    /// <summary>Applies the S-box to each of the four bytes of a word.</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static uint Substitute(uint word)
    {
        uint x0 = word & One;
        uint x1 = (word >> 1) & One;
        uint x2 = (word >> 2) & One;
        uint x3 = (word >> 3) & One;
        uint x4 = (word >> 4) & One;
        uint x5 = (word >> 5) & One;
        uint x6 = (word >> 6) & One;
        uint x7 = (word >> 7) & One;

        uint t0 = x4 ^ x7;
        uint t1 = x0 ^ x5;
        uint t2 = x2 ^ x6;
        uint t3 = x3 ^ t1;
        uint t4 = t2 ^ t3;
        uint t5 = x1 ^ t0;
        uint t6 = t0 ^ t4;
        uint t7 = x0 ^ t0;
        uint t8 = x6 ^ t1;
        uint t9 = t5 ^ t8;
        uint t10 = x3 ^ x4;
        uint t11 = x6 ^ t10;
        uint t12 = x5 ^ t5;
        uint t13 = x1 ^ t2;
        uint t14 = t6 ^ One;
        uint t15 = t13 ^ x1;
        uint t16 = t12 ^ t4;
        uint t17 = x1 ^ t15;
        uint t18 = x1 ^ t16;
        uint t19 = t17 ^ t4;
        uint t20 = t15 ^ x1;
        uint t21 = t19 ^ x1;
        uint t22 = t18 ^ t19;
        uint t23 = t22 ^ t15;
        uint t24 = t23 ^ x1;
        uint t25 = x1 & t11;
        uint t26 = t13 & t9;
        uint t27 = x1 ^ t13;
        uint t28 = t11 ^ t9;
        uint t29 = t27 & t28;
        uint t30 = t25 ^ t26;
        uint t31 = t29 ^ t26;
        uint t32 = t4 & t7;
        uint t33 = t12 & t14;
        uint t34 = t4 ^ t12;
        uint t35 = t7 ^ t14;
        uint t36 = t34 & t35;
        uint t37 = t32 ^ t33;
        uint t38 = t36 ^ t33;
        uint t39 = t13 ^ t12;
        uint t40 = x1 ^ t4;
        uint t41 = t9 ^ t14;
        uint t42 = t11 ^ t7;
        uint t43 = t40 & t42;
        uint t44 = t39 & t41;
        uint t45 = t40 ^ t39;
        uint t46 = t42 ^ t41;
        uint t47 = t45 & t46;
        uint t48 = t43 ^ t44;
        uint t49 = t47 ^ t44;
        uint t50 = t31 ^ t30;
        uint t51 = t31 ^ t37;
        uint t52 = t50 ^ t38;
        uint t53 = t48 ^ t37;
        uint t54 = t49 ^ t38;
        uint t55 = t20 ^ t51;
        uint t56 = t15 ^ t52;
        uint t57 = t21 ^ t53;
        uint t58 = t24 ^ t54;
        uint t59 = t9 ^ t11;
        uint t60 = t14 ^ t7;
        uint t61 = t11 ^ t59;
        uint t62 = t11 ^ t60;
        uint t63 = t61 ^ t7;
        uint t64 = t55 ^ t62;
        uint t65 = t56 ^ t63;
        uint t66 = t57 ^ t59;
        uint t67 = t58 ^ t11;
        uint t68 = t66 ^ t67;
        uint t69 = t67 ^ t68;
        uint t70 = t67 & t65;
        uint t71 = t66 & t64;
        uint t72 = t67 ^ t66;
        uint t73 = t65 ^ t64;
        uint t74 = t72 & t73;
        uint t75 = t70 ^ t71;
        uint t76 = t74 ^ t71;
        uint t77 = t67 ^ t75;
        uint t78 = t69 ^ t76;
        uint t79 = t64 ^ t65;
        uint t80 = t77 ^ t79;
        uint t81 = t78 ^ t65;
        uint t82 = t80 ^ t81;
        uint t83 = t64 ^ t66;
        uint t84 = t65 ^ t67;
        uint t85 = t84 & t81;
        uint t86 = t83 & t82;
        uint t87 = t84 ^ t83;
        uint t88 = t81 ^ t82;
        uint t89 = t87 & t88;
        uint t90 = t85 ^ t86;
        uint t91 = t89 ^ t86;
        uint t92 = t67 & t81;
        uint t93 = t66 & t82;
        uint t94 = t67 ^ t66;
        uint t95 = t81 ^ t82;
        uint t96 = t94 & t95;
        uint t97 = t92 ^ t93;
        uint t98 = t96 ^ t93;
        uint t99 = t14 ^ t12;
        uint t100 = t7 ^ t4;
        uint t101 = t9 ^ t13;
        uint t102 = t11 ^ x1;
        uint t103 = t102 & t98;
        uint t104 = t101 & t97;
        uint t105 = t102 ^ t101;
        uint t106 = t98 ^ t97;
        uint t107 = t105 & t106;
        uint t108 = t103 ^ t104;
        uint t109 = t107 ^ t104;
        uint t110 = t100 & t91;
        uint t111 = t99 & t90;
        uint t112 = t100 ^ t99;
        uint t113 = t91 ^ t90;
        uint t114 = t112 & t113;
        uint t115 = t110 ^ t111;
        uint t116 = t114 ^ t111;
        uint t117 = t101 ^ t99;
        uint t118 = t102 ^ t100;
        uint t119 = t97 ^ t90;
        uint t120 = t98 ^ t91;
        uint t121 = t118 & t120;
        uint t122 = t117 & t119;
        uint t123 = t118 ^ t117;
        uint t124 = t120 ^ t119;
        uint t125 = t123 & t124;
        uint t126 = t121 ^ t122;
        uint t127 = t125 ^ t122;
        uint t128 = t109 ^ t108;
        uint t129 = t109 ^ t115;
        uint t130 = t128 ^ t116;
        uint t131 = t126 ^ t115;
        uint t132 = t127 ^ t116;
        uint t133 = x1 & t98;
        uint t134 = t13 & t97;
        uint t135 = x1 ^ t13;
        uint t136 = t98 ^ t97;
        uint t137 = t135 & t136;
        uint t138 = t133 ^ t134;
        uint t139 = t137 ^ t134;
        uint t140 = t4 & t91;
        uint t141 = t12 & t90;
        uint t142 = t4 ^ t12;
        uint t143 = t91 ^ t90;
        uint t144 = t142 & t143;
        uint t145 = t140 ^ t141;
        uint t146 = t144 ^ t141;
        uint t147 = t13 ^ t12;
        uint t148 = x1 ^ t4;
        uint t149 = t97 ^ t90;
        uint t150 = t98 ^ t91;
        uint t151 = t148 & t150;
        uint t152 = t147 & t149;
        uint t153 = t148 ^ t147;
        uint t154 = t150 ^ t149;
        uint t155 = t153 & t154;
        uint t156 = t151 ^ t152;
        uint t157 = t155 ^ t152;
        uint t158 = t139 ^ t138;
        uint t159 = t139 ^ t145;
        uint t160 = t158 ^ t146;
        uint t161 = t156 ^ t145;
        uint t162 = t157 ^ t146;
        uint t163 = t132 ^ t161;
        uint t164 = t129 ^ t131;
        uint t165 = t159 ^ t164;
        uint t166 = t130 ^ t160;
        uint t167 = t163 ^ t165;
        uint t168 = t163 ^ t166;
        uint t169 = t130 ^ t165;
        uint t170 = t130 ^ t162;
        uint t171 = t163 ^ t170;
        uint t172 = t131 ^ t166;
        uint t173 = t159 ^ t161;
        uint t174 = t162 ^ t173;

        return ((t167 ^ One) << 0)
            | ((t168 ^ One) << 1)
            | ((t169) << 2)
            | ((t159) << 3)
            | ((t171 ^ One) << 4)
            | ((t131) << 5)
            | ((t172 ^ One) << 6)
            | ((t174 ^ One) << 7);
    }
}
