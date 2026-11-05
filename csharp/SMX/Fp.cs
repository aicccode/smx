using System.Runtime.CompilerServices;

namespace SMX;

/// <summary>
/// Arithmetic modulo the SM2 prime p = 2^256 - 2^224 - 2^96 + 2^64 - 1. Operands may be any 256-bit value for Mul,
/// Square and Invert; results of those are fully reduced. Every operation here is free of branches and of memory
/// accesses that depend on the operand values.
/// </summary>
internal static class Fp
{
    private const ulong P0 = 0xFFFFFFFFFFFFFFFF;
    private const ulong P1 = 0xFFFFFFFF00000000;
    private const ulong P2 = 0xFFFFFFFFFFFFFFFF;
    private const ulong P3 = 0xFFFFFFFEFFFFFFFF;

    public static readonly BigInt256 P = new(P0, P1, P2, P3);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Add(in BigInt256 a, in BigInt256 b, out BigInt256 r)
    {
        ulong s0 = Bits.Add(a.L0, b.L0, 0, out ulong c);
        ulong s1 = Bits.Add(a.L1, b.L1, c, out c);
        ulong s2 = Bits.Add(a.L2, b.L2, c, out c);
        ulong s3 = Bits.Add(a.L3, b.L3, c, out ulong carry);
        ReduceOnce(s0, s1, s2, s3, carry, out r);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Sub(in BigInt256 a, in BigInt256 b, out BigInt256 r)
    {
        ulong d0 = Bits.Sub(a.L0, b.L0, 0, out ulong c);
        ulong d1 = Bits.Sub(a.L1, b.L1, c, out c);
        ulong d2 = Bits.Sub(a.L2, b.L2, c, out c);
        ulong d3 = Bits.Sub(a.L3, b.L3, c, out ulong borrow);
        ulong mask = Bits.MaskFromBit(borrow);

        r.L0 = Bits.Add(d0, P0 & mask, 0, out c);
        r.L1 = Bits.Add(d1, P1 & mask, c, out c);
        r.L2 = Bits.Add(d2, P2 & mask, c, out c);
        r.L3 = d3 + (P3 & mask) + c;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Double(in BigInt256 a, out BigInt256 r)
    {
        ulong a0 = a.L0, a1 = a.L1, a2 = a.L2, a3 = a.L3;
        ReduceOnce(a0 << 1, (a1 << 1) | (a0 >> 63), (a2 << 1) | (a1 >> 63), (a3 << 1) | (a2 >> 63), a3 >> 63, out r);
    }

    /// <summary>Subtracts p once when the 257-bit value given by the limbs and <paramref name="top"/> is at least p.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ReduceOnce(ulong s0, ulong s1, ulong s2, ulong s3, ulong top, out BigInt256 r)
    {
        ulong d0 = Bits.Sub(s0, P0, 0, out ulong c);
        ulong d1 = Bits.Sub(s1, P1, c, out c);
        ulong d2 = Bits.Sub(s2, P2, c, out c);
        ulong d3 = Bits.Sub(s3, P3, c, out ulong borrow);
        ulong keepReduced = Bits.MaskFromBit(top | (borrow ^ 1));

        r.L0 = Bits.Select(keepReduced, d0, s0);
        r.L1 = Bits.Select(keepReduced, d1, s1);
        r.L2 = Bits.Select(keepReduced, d2, s2);
        r.L3 = Bits.Select(keepReduced, d3, s3);
    }

    /// <summary>Brings any 256-bit value into [0, p). One subtraction suffices because 2p exceeds 2^256.</summary>
    public static void Canonicalize(in BigInt256 a, out BigInt256 r) => ReduceOnce(a.L0, a.L1, a.L2, a.L3, 0, out r);

    public static void Negate(in BigInt256 a, out BigInt256 r) => Sub(default, a, out r);

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void Mul(in BigInt256 a, in BigInt256 b, out BigInt256 r)
    {
        Wide512.Multiply(a, b, out var w);
        Reduce(w, out r);
    }

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void Square(in BigInt256 a, out BigInt256 r)
    {
        Wide512.Square(a, out var w);
        Reduce(w, out r);
    }

    /// <summary>
    /// Solinas reduction. With W8..W15 the upper 32-bit words, 2^(32*i) mod p is a small signed combination of the lower
    /// words, so each result word is a short sum that fits a signed 64-bit accumulator with room to spare.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Reduce(in Wide512 w, out BigInt256 r)
    {
        long w8 = (long)(uint)w.W4, w9 = (long)(w.W4 >> 32);
        long w10 = (long)(uint)w.W5, w11 = (long)(w.W5 >> 32);
        long w12 = (long)(uint)w.W6, w13 = (long)(w.W6 >> 32);
        long w14 = (long)(uint)w.W7, w15 = (long)(w.W7 >> 32);

        long s1415 = w14 + w15;
        long s1314 = w13 + w14;
        long s89 = w8 + w9;
        long s1011 = w10 + w11;
        long s1213 = w12 + w13;

        long c0 = (long)(uint)w.W0 + s89 + s1011 + w12 + w13 + w13 + s1415 + s1415;
        long c1 = (long)(w.W0 >> 32) + w9 + s1011 + s1213 + w14 + s1415 + w15;
        long c2 = (long)(uint)w.W1 - s89 - s1314;
        long c3 = (long)(w.W1 >> 32) + w8 + w11 + s1213 + w13 + s1415;
        long c4 = (long)(uint)w.W2 + w9 + w12 + s1314 + s1415;
        long c5 = (long)(w.W2 >> 32) + w10 + w13 + s1415 + s1415 - w14;
        long c6 = (long)(uint)w.W3 + w11 + s1415;
        long c7 = (long)(w.W3 >> 32) + s89 + s1011 + s1213 + s1213 + w14 + s1415 + w15 + w15;

        // Carry-propagate the columns into four limbs and a small non-negative top word.
        c1 += c0 >> 32;
        c2 += c1 >> 32;
        c3 += c2 >> 32;
        c4 += c3 >> 32;
        c5 += c4 >> 32;
        c6 += c5 >> 32;
        c7 += c6 >> 32;
        ulong top = (ulong)(c7 >> 32);

        ulong r0 = (ulong)(uint)c0 | ((ulong)c1 << 32);
        ulong r1 = (ulong)(uint)c2 | ((ulong)c3 << 32);
        ulong r2 = (ulong)(uint)c4 | ((ulong)c5 << 32);
        ulong r3 = (ulong)(uint)c6 | ((ulong)c7 << 32);

        // Fold the top word: top * 2^256 is congruent to top * (2^224 + 2^96 - 2^64 + 1).
        r0 = Bits.Add(r0, top, 0, out ulong c);
        r1 = Bits.Add(r1, (top << 32) - top, c, out c);
        r2 = Bits.Add(r2, 0, c, out c);
        r3 = Bits.Add(r3, top << 32, c, out c);

        // That can overflow only once, and then the remaining value is small enough for this fold not to carry.
        r0 = Bits.Add(r0, c, 0, out ulong c2Out);
        r1 = Bits.Add(r1, (c << 32) - c, c2Out, out c2Out);
        r2 = Bits.Add(r2, 0, c2Out, out c2Out);
        r3 += (c << 32) + c2Out;

        ReduceOnce(r0, r1, r2, r3, 0, out r);
    }

    /// <summary>a^-1 mod p, with zero mapping to zero. Constant time.</summary>
    public static void Invert(in BigInt256 a, out BigInt256 r)
    {
        ReduceOnce(a.L0, a.L1, a.L2, a.L3, 0, out var reduced);
        SafeGcd.Invert(reduced, SafeGcd.FieldPrime, out r);
    }
}
