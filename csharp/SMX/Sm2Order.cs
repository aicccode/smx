using System.Runtime.CompilerServices;

namespace SMX;

/// <summary>
/// Arithmetic modulo the SM2 group order n, by Montgomery multiplication with R = 2^256. Multiplication and inversion
/// have no branches or memory accesses that depend on their operands, so they are safe for private scalars and nonces.
/// </summary>
internal static class Sm2Order
{
    private const ulong N0 = 0x53BBF40939D54123;
    private const ulong N1 = 0x7203DF6B21C6052B;
    private const ulong N2 = 0xFFFFFFFFFFFFFFFF;
    private const ulong N3 = 0xFFFFFFFEFFFFFFFF;

    /// <summary>-n^-1 mod 2^64.</summary>
    private const ulong NegInverse = 0x327F9E8872350975;

    public static readonly BigInt256 N = new(N0, N1, N2, N3);

    /// <summary>R^2 mod n.</summary>
    private static readonly BigInt256 RSquared = new(0x901192AF7C114F20, 0x3464504ADE6FA2FA, 0x620FC84C3AFFE0D4, 0x1EB5E412A22B3D3B);

    /// <summary>Canonical a*b mod n for any 256-bit operands.</summary>
    public static void Mul(in BigInt256 a, in BigInt256 b, out BigInt256 r)
    {
        // For any operands a*b*R^-1 is below R + n, so the subtraction inside brings it into 256 bits though not yet below
        // n. Multiplying that by R^2 cancels the R^-1, and with R^2 below n this second result is fully reduced.
        MontgomeryMul(a, b, out var t);
        MontgomeryMul(t, RSquared, out r);
    }

    /// <summary>a^-1 mod n, with zero mapping to zero. Constant time.</summary>
    public static void Invert(in BigInt256 a, out BigInt256 r)
    {
        ReduceOnce(a, out var reduced);
        SafeGcd.Invert(reduced, SafeGcd.GroupOrder, out r);
    }

    /// <summary>All ones when k is a usable private key, 0 &lt; k &lt; n - 1, otherwise zero. Constant time.</summary>
    public static ulong PrivateKeyRangeMask(in BigInt256 k)
    {
        // n - 1 is excluded because signing divides by d + 1.
        k.Sub(new BigInt256(N0 - 1, N1, N2, N3), out ulong borrow);
        return Bits.MaskFromBit(borrow) & ~k.IsZeroMask();
    }

    /// <summary>All ones when 0 &lt; k &lt; n, otherwise zero. Constant time.</summary>
    public static ulong InRangeMask(in BigInt256 k)
    {
        k.Sub(N, out ulong borrow);
        return Bits.MaskFromBit(borrow) & ~k.IsZeroMask();
    }

    /// <summary>k mod n for any 256-bit k (one conditional subtraction suffices because n &gt; 2^255). Constant time.</summary>
    public static void ReduceOnce(in BigInt256 k, out BigInt256 r)
    {
        var d = k.Sub(N, out ulong borrow);
        r = BigInt256.Select(Bits.MaskFromBit(borrow), k, d);
    }

    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void MontgomeryMul(in BigInt256 a, in BigInt256 b, out BigInt256 r)
    {
        Wide512.Multiply(a, b, out var w);
        ulong t0 = w.W0, t1 = w.W1, t2 = w.W2, t3 = w.W3, t4 = w.W4, t5 = w.W5, t6 = w.W6, t7 = w.W7;

        ulong top = 0;
        Round(t0, ref t1, ref t2, ref t3, ref t4, ref top);
        Round(t1, ref t2, ref t3, ref t4, ref t5, ref top);
        Round(t2, ref t3, ref t4, ref t5, ref t6, ref top);
        Round(t3, ref t4, ref t5, ref t6, ref t7, ref top);

        ulong d0 = Bits.Sub(t4, N0, 0, out ulong c);
        ulong d1 = Bits.Sub(t5, N1, c, out c);
        ulong d2 = Bits.Sub(t6, N2, c, out c);
        ulong d3 = Bits.Sub(t7, N3, c, out ulong borrow);
        ulong keepReduced = Bits.MaskFromBit(top | (borrow ^ 1));

        r.L0 = Bits.Select(keepReduced, d0, t4);
        r.L1 = Bits.Select(keepReduced, d1, t5);
        r.L2 = Bits.Select(keepReduced, d2, t6);
        r.L3 = Bits.Select(keepReduced, d3, t7);
    }

    /// <summary>Adds the multiple of n that clears the lowest limb, accumulating the carry beyond the highest into top.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Round(ulong low, ref ulong t1, ref ulong t2, ref ulong t3, ref ulong t4, ref ulong top)
    {
        ulong m = low * NegInverse;
        ulong carry = 0;
        Bits.MulAdd(m, N0, low, ref carry);
        t1 = Bits.MulAdd(m, N1, t1, ref carry);
        t2 = Bits.MulAdd(m, N2, t2, ref carry);
        t3 = Bits.MulAdd(m, N3, t3, ref carry);
        t4 = Bits.Add(t4, carry, top, out top);
    }
}
