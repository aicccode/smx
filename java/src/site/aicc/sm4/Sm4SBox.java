package site.aicc.sm4;

/**
 * The SM4 S-box as a Boolean circuit, applied to the four bytes of an int in parallel.
 *
 * <p>Only AND and XOR on values derived from the input are used: no table lookup, no branch, and so
 * no memory access or control flow that depends on the input. The circuit computes the S-box's
 * algebraic form S(x) = A * (A * x + c)^-1 + c by mapping into the tower field GF(((2^2)^2)^2),
 * where inversion needs few gates. It was machine generated, and a test compares it with the S-box
 * table of GB/T 32907 on all 256 inputs in every byte position.
 */
final class Sm4SBox {
  private static final int LOW_BITS = 0x01010101;

  private Sm4SBox() {}

  /** Returns the S-box applied independently to each byte of x. */
  static int apply(int x) {
    int x0 = x;
    int x1 = x >>> 1;
    int x2 = x >>> 2;
    int x3 = x >>> 3;
    int x4 = x >>> 4;
    int x5 = x >>> 5;
    int x6 = x >>> 6;
    int x7 = x >>> 7;
    int ones = -1;
    int t0 = x0 ^ x4;
    int t1 = x6 ^ ones;
    int t2 = x1 ^ t0;
    int t3 = x2 ^ x3;
    int t4 = x5 ^ t2;
    int t5 = x7 ^ t1;
    int t6 = t3 ^ t4;
    int t7 = x1 ^ t1;
    int t8 = x2 ^ x7;
    int t9 = x4 ^ t3;
    int t10 = ones ^ t8;
    int t11 = t1 ^ t6;
    int t12 = t2 ^ t5;
    int t13 = t5 ^ t9;
    int t14 = t12 ^ t6;
    int t15 = t14 ^ t11;
    int t16 = t6 ^ t10;
    int t17 = t10 ^ t11;
    int t18 = t17 ^ t11;
    int t19 = t16 ^ t11;
    int t20 = t15 ^ t16;
    int t21 = t20 ^ t17;
    int t22 = t21 ^ t11;
    int t23 = t11 & t13;
    int t24 = t10 & x3;
    int t25 = t13 ^ x3;
    int t26 = t17 & t25;
    int t27 = t26 ^ t24;
    int t28 = t24 ^ t23;
    int t29 = t6 & t7;
    int t30 = t12 & t0;
    int t31 = t7 ^ t0;
    int t32 = t14 & t31;
    int t33 = t32 ^ t30;
    int t34 = t30 ^ t29;
    int t35 = t11 ^ t6;
    int t36 = t10 ^ t12;
    int t37 = t13 ^ t7;
    int t38 = x3 ^ t0;
    int t39 = t35 & t37;
    int t40 = t36 & t38;
    int t41 = t35 ^ t36;
    int t42 = t37 ^ t38;
    int t43 = t41 & t42;
    int t44 = t43 ^ t40;
    int t45 = t40 ^ t39;
    int t46 = t44 ^ t33;
    int t47 = t45 ^ t34;
    int t48 = t27 ^ t28;
    int t49 = t33 ^ t48;
    int t50 = t34 ^ t27;
    int t51 = t22 ^ t46;
    int t52 = t19 ^ t47;
    int t53 = t17 ^ t49;
    int t54 = t18 ^ t50;
    int t55 = t31 ^ t13;
    int t56 = t7 ^ x3;
    int t57 = t51 ^ t13;
    int t58 = t52 ^ t25;
    int t59 = t53 ^ t56;
    int t60 = t54 ^ t55;
    int t61 = t57 ^ t58;
    int t62 = t57 ^ t61;
    int t63 = t57 & t59;
    int t64 = t58 & t60;
    int t65 = t59 ^ t60;
    int t66 = t61 & t65;
    int t67 = t66 ^ t64;
    int t68 = t64 ^ t63;
    int t69 = t62 ^ t67;
    int t70 = t57 ^ t68;
    int t71 = t69 ^ t59;
    int t72 = t70 ^ t65;
    int t73 = t71 ^ t72;
    int t74 = t57 & t71;
    int t75 = t58 & t73;
    int t76 = t71 ^ t73;
    int t77 = t61 & t76;
    int t78 = t77 ^ t75;
    int t79 = t75 ^ t74;
    int t80 = t57 ^ t59;
    int t81 = t58 ^ t60;
    int t82 = t80 & t71;
    int t83 = t81 & t73;
    int t84 = t80 ^ t81;
    int t85 = t84 & t76;
    int t86 = t85 ^ t83;
    int t87 = t83 ^ t82;
    int t88 = t11 & t78;
    int t89 = t10 & t79;
    int t90 = t78 ^ t79;
    int t91 = t17 & t90;
    int t92 = t91 ^ t89;
    int t93 = t89 ^ t88;
    int t94 = t6 & t86;
    int t95 = t12 & t87;
    int t96 = t86 ^ t87;
    int t97 = t14 & t96;
    int t98 = t97 ^ t95;
    int t99 = t95 ^ t94;
    int t100 = t78 ^ t86;
    int t101 = t79 ^ t87;
    int t102 = t35 & t100;
    int t103 = t36 & t101;
    int t104 = t100 ^ t101;
    int t105 = t41 & t104;
    int t106 = t105 ^ t103;
    int t107 = t103 ^ t102;
    int t108 = t106 ^ t98;
    int t109 = t107 ^ t99;
    int t110 = t92 ^ t93;
    int t111 = t98 ^ t110;
    int t112 = t99 ^ t92;
    int t113 = t11 ^ t13;
    int t114 = t10 ^ x3;
    int t115 = t6 ^ t7;
    int t116 = t12 ^ t0;
    int t117 = t113 & t78;
    int t118 = t114 & t79;
    int t119 = t113 ^ t114;
    int t120 = t119 & t90;
    int t121 = t120 ^ t118;
    int t122 = t118 ^ t117;
    int t123 = t115 & t86;
    int t124 = t116 & t87;
    int t125 = t115 ^ t116;
    int t126 = t125 & t96;
    int t127 = t126 ^ t124;
    int t128 = t124 ^ t123;
    int t129 = t113 ^ t115;
    int t130 = t114 ^ t116;
    int t131 = t129 & t100;
    int t132 = t130 & t101;
    int t133 = t129 ^ t130;
    int t134 = t133 & t104;
    int t135 = t134 ^ t132;
    int t136 = t132 ^ t131;
    int t137 = t135 ^ t127;
    int t138 = t136 ^ t128;
    int t139 = t121 ^ t122;
    int t140 = t127 ^ t139;
    int t141 = t128 ^ t121;
    int t142 = t141 ^ ones;
    int t143 = t140 ^ t112;
    int t144 = t138 ^ t137;
    int t145 = t138 ^ t111;
    int t146 = t109 ^ t142;
    int t147 = t109 ^ t143;
    int t148 = t143 ^ t144;
    int t149 = t141 ^ t112;
    int t150 = t140 ^ t108;
    int t151 = t111 ^ t108;
    int t152 = t111 ^ t147;
    int t153 = t108 ^ t145;
    int t154 = ones ^ t147;
    int t155 = t142 ^ t148;
    int t156 = t142 ^ t151;
    int t157 = t145 ^ t146;
    int t158 = t146 ^ t150;
    int t159 = t149 ^ t153;
    return (t156 & LOW_BITS)
        | ((t157 & LOW_BITS) << 1)
        | ((t148 & LOW_BITS) << 2)
        | ((t159 & LOW_BITS) << 3)
        | ((t154 & LOW_BITS) << 4)
        | ((t152 & LOW_BITS) << 5)
        | ((t155 & LOW_BITS) << 6)
        | ((t158 & LOW_BITS) << 7);
  }
}
