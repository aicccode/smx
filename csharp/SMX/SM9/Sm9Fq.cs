using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace SMX.SM9Internal;

/// <summary>
/// Montgomery multiplication on four 64-bit limbs for any odd 256-bit modulus m with m &gt; 2^255, given as constants so
/// that every caller gets a specialized copy. Inputs must lie in [0, m); the result does too. No branches or memory
/// accesses depend on the operand values.
/// </summary>
internal static class Mont256
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Mul(ulong a0, ulong a1, ulong a2, ulong a3, ulong b0, ulong b1, ulong b2, ulong b3,
        ulong m0, ulong m1, ulong m2, ulong m3, ulong mInv, out ulong r0, out ulong r1, out ulong r2, out ulong r3)
    {
        // CIOS: each round adds a * b_i, then cancels the lowest word with a multiple of m and shifts down one word.
        ulong t0, t1, t2, t3, t4, c;

        c = 0;
        t0 = Bits.MulAdd(a0, b0, 0, ref c);
        t1 = Bits.MulAdd(a1, b0, 0, ref c);
        t2 = Bits.MulAdd(a2, b0, 0, ref c);
        t3 = Bits.MulAdd(a3, b0, 0, ref c);
        t4 = c;
        Reduce(ref t0, ref t1, ref t2, ref t3, ref t4, 0, m0, m1, m2, m3, mInv);

        c = 0;
        t0 = Bits.MulAdd(a0, b1, t0, ref c);
        t1 = Bits.MulAdd(a1, b1, t1, ref c);
        t2 = Bits.MulAdd(a2, b1, t2, ref c);
        t3 = Bits.MulAdd(a3, b1, t3, ref c);
        t4 = Bits.Add(t4, c, 0, out c);
        Reduce(ref t0, ref t1, ref t2, ref t3, ref t4, c, m0, m1, m2, m3, mInv);

        c = 0;
        t0 = Bits.MulAdd(a0, b2, t0, ref c);
        t1 = Bits.MulAdd(a1, b2, t1, ref c);
        t2 = Bits.MulAdd(a2, b2, t2, ref c);
        t3 = Bits.MulAdd(a3, b2, t3, ref c);
        t4 = Bits.Add(t4, c, 0, out c);
        Reduce(ref t0, ref t1, ref t2, ref t3, ref t4, c, m0, m1, m2, m3, mInv);

        c = 0;
        t0 = Bits.MulAdd(a0, b3, t0, ref c);
        t1 = Bits.MulAdd(a1, b3, t1, ref c);
        t2 = Bits.MulAdd(a2, b3, t2, ref c);
        t3 = Bits.MulAdd(a3, b3, t3, ref c);
        t4 = Bits.Add(t4, c, 0, out c);
        Reduce(ref t0, ref t1, ref t2, ref t3, ref t4, c, m0, m1, m2, m3, mInv);
        ulong top = t4;

        // The value t0..t3 plus top * 2^256 is below 2m; subtract m once when it is at least m.
        ulong d0 = Bits.Sub(t0, m0, 0, out ulong b);
        ulong d1 = Bits.Sub(t1, m1, b, out b);
        ulong d2 = Bits.Sub(t2, m2, b, out b);
        ulong d3 = Bits.Sub(t3, m3, b, out b);
        ulong keep = Bits.MaskFromBit(top | (b ^ 1));
        r0 = Bits.Select(keep, d0, t0);
        r1 = Bits.Select(keep, d1, t1);
        r2 = Bits.Select(keep, d2, t2);
        r3 = Bits.Select(keep, d3, t3);
    }

    /// <summary>
    /// One Montgomery step on the six-word value t0..t5: adds k * m with k chosen to zero t0, then shifts down one word,
    /// leaving five words in t0..t4.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Reduce(ref ulong t0, ref ulong t1, ref ulong t2, ref ulong t3, ref ulong t4, ulong t5,
        ulong m0, ulong m1, ulong m2, ulong m3, ulong mInv)
    {
        ulong k = t0 * mInv;
        ulong c = 0;
        _ = Bits.MulAdd(k, m0, t0, ref c);
        t0 = Bits.MulAdd(k, m1, t1, ref c);
        t1 = Bits.MulAdd(k, m2, t2, ref c);
        t2 = Bits.MulAdd(k, m3, t3, ref c);
        t3 = Bits.Add(t4, c, 0, out c);
        t4 = t5 + c;
    }

    /// <summary>(a + b) mod m for a, b in [0, m).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Add(ulong a0, ulong a1, ulong a2, ulong a3, ulong b0, ulong b1, ulong b2, ulong b3,
        ulong m0, ulong m1, ulong m2, ulong m3, out ulong r0, out ulong r1, out ulong r2, out ulong r3)
    {
        ulong s0 = Bits.Add(a0, b0, 0, out ulong c);
        ulong s1 = Bits.Add(a1, b1, c, out c);
        ulong s2 = Bits.Add(a2, b2, c, out c);
        ulong s3 = Bits.Add(a3, b3, c, out ulong top);
        ulong d0 = Bits.Sub(s0, m0, 0, out ulong b);
        ulong d1 = Bits.Sub(s1, m1, b, out b);
        ulong d2 = Bits.Sub(s2, m2, b, out b);
        ulong d3 = Bits.Sub(s3, m3, b, out b);
        ulong keep = Bits.MaskFromBit(top | (b ^ 1));
        r0 = Bits.Select(keep, d0, s0);
        r1 = Bits.Select(keep, d1, s1);
        r2 = Bits.Select(keep, d2, s2);
        r3 = Bits.Select(keep, d3, s3);
    }

    /// <summary>(a - b) mod m for a, b in [0, m).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Sub(ulong a0, ulong a1, ulong a2, ulong a3, ulong b0, ulong b1, ulong b2, ulong b3,
        ulong m0, ulong m1, ulong m2, ulong m3, out ulong r0, out ulong r1, out ulong r2, out ulong r3)
    {
        ulong d0 = Bits.Sub(a0, b0, 0, out ulong b);
        ulong d1 = Bits.Sub(a1, b1, b, out b);
        ulong d2 = Bits.Sub(a2, b2, b, out b);
        ulong d3 = Bits.Sub(a3, b3, b, out b);
        ulong mask = Bits.MaskFromBit(b);
        r0 = Bits.Add(d0, m0 & mask, 0, out ulong c);
        r1 = Bits.Add(d1, m1 & mask, c, out c);
        r2 = Bits.Add(d2, m2 & mask, c, out c);
        r3 = d3 + (m3 & mask) + c;
    }

    /// <summary>All ones when a &lt; m (as 256-bit numbers), else zero.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong LessMask(ulong a0, ulong a1, ulong a2, ulong a3, ulong m0, ulong m1, ulong m2, ulong m3)
    {
        _ = Bits.Sub(a0, m0, 0, out ulong b);
        _ = Bits.Sub(a1, m1, b, out b);
        _ = Bits.Sub(a2, m2, b, out b);
        _ = Bits.Sub(a3, m3, b, out b);
        return Bits.MaskFromBit(b);
    }
}

/// <summary>
/// An element of the SM9 base field Fq, in Montgomery form (value * 2^256 mod q) on four little-endian limbs, always in
/// [0, q). Every operation is free of branches and memory accesses that depend on the values.
/// </summary>
internal struct Fq : ICurveField<Fq>
{
    public const ulong Q0 = 0xE56F9B27E351457D, Q1 = 0x21F2934B1A7AEEDB, Q2 = 0xD603AB4FF58EC745, Q3 = 0xB640000002A3A6F1;
    private const ulong QInv = 0x892BC42C2F2EE42B;
    private const ulong R0 = 0x1A9064D81CAEBA83, R1 = 0xDE0D6CB4E5851124, R2 = 0x29FC54B00A7138BA, R3 = 0x49BFFFFFFD5C590E;
    private const ulong RR0 = 0x27DEA312B417E2D2, RR1 = 0x88F8105FAE1A5D3F, RR2 = 0xE479B522D6706E7B, RR3 = 0x2EA795A656F62FBD;
    public const int ByteSize = 32;

    public ulong L0, L1, L2, L3;

    public Fq(ulong l0, ulong l1, ulong l2, ulong l3)
    {
        L0 = l0;
        L1 = l1;
        L2 = l2;
        L3 = l3;
    }

    public static Fq Zero => default;

    public static Fq One => new(R0, R1, R2, R3);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq Add(in Fq a, in Fq b)
    {
        Mont256.Add(a.L0, a.L1, a.L2, a.L3, b.L0, b.L1, b.L2, b.L3, Q0, Q1, Q2, Q3, out var r0, out var r1, out var r2, out var r3);
        return new Fq(r0, r1, r2, r3);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq Sub(in Fq a, in Fq b)
    {
        Mont256.Sub(a.L0, a.L1, a.L2, a.L3, b.L0, b.L1, b.L2, b.L3, Q0, Q1, Q2, Q3, out var r0, out var r1, out var r2, out var r3);
        return new Fq(r0, r1, r2, r3);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq Double(in Fq a) => Add(a, a);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq Neg(in Fq a) => Sub(default, a);

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static Fq Mul(in Fq a, in Fq b)
    {
        Mont256.Mul(a.L0, a.L1, a.L2, a.L3, b.L0, b.L1, b.L2, b.L3, Q0, Q1, Q2, Q3, QInv,
            out var r0, out var r1, out var r2, out var r3);
        return new Fq(r0, r1, r2, r3);
    }

    public static Fq Square(in Fq a) => Mul(a, a);

    /// <summary>a * 15, three times the coefficient b = 5 of E.</summary>
    public static Fq MulB3(in Fq a)
    {
        var a16 = Double(Double(Double(Double(a))));
        return Sub(a16, a);
    }

    public static Fq CurveB => FiveMont;

    private static readonly Fq FiveMont = FromCanonical(5, 0, 0, 0);

    /// <summary>a^e for a public exponent, by left-to-right square and multiply; constant time in a.</summary>
    public static Fq Pow(in Fq a, ReadOnlySpan<ulong> exponentLimbs)
    {
        Fq r = One;
        for (int limb = exponentLimbs.Length - 1; limb >= 0; limb--)
        {
            for (int bit = 63; bit >= 0; bit--)
            {
                r = Square(r);
                if (((exponentLimbs[limb] >> bit) & 1) != 0)
                {
                    r = Mul(r, a);
                }
            }
        }
        return r;
    }

    /// <summary>a^(q-2), so a^-1 for nonzero a and 0 for 0. The exponent is public, so the schedule is fixed.</summary>
    public static Fq Invert(in Fq a)
    {
        ReadOnlySpan<ulong> qMinus2 = [Q0 - 2, Q1, Q2, Q3];
        return Pow(a, qMinus2);
    }

    /// <summary>All ones when a is zero.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public readonly ulong IsZeroMask() => Bits.IsZeroMask(L0 | L1 | L2 | L3);

    public readonly bool IsZero => (L0 | L1 | L2 | L3) == 0;

    public readonly bool Equals(in Fq b) => ((L0 ^ b.L0) | (L1 ^ b.L1) | (L2 ^ b.L2) | (L3 ^ b.L3)) == 0;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq Select(ulong mask, in Fq ifSet, in Fq ifClear) => new(
        Bits.Select(mask, ifSet.L0, ifClear.L0), Bits.Select(mask, ifSet.L1, ifClear.L1),
        Bits.Select(mask, ifSet.L2, ifClear.L2), Bits.Select(mask, ifSet.L3, ifClear.L3));

    /// <summary>Converts a plain integer below q into Montgomery form.</summary>
    public static Fq FromCanonical(ulong l0, ulong l1, ulong l2, ulong l3)
    {
        Mont256.Mul(l0, l1, l2, l3, RR0, RR1, RR2, RR3, Q0, Q1, Q2, Q3, QInv, out var r0, out var r1, out var r2, out var r3);
        return new Fq(r0, r1, r2, r3);
    }

    /// <summary>Reads 32 big-endian bytes; false (with an arbitrary result) when the value is not below q.</summary>
    public static bool TryRead(ReadOnlySpan<byte> bytes, out Fq value)
    {
        ulong l3 = BinaryPrimitives.ReadUInt64BigEndian(bytes);
        ulong l2 = BinaryPrimitives.ReadUInt64BigEndian(bytes[8..]);
        ulong l1 = BinaryPrimitives.ReadUInt64BigEndian(bytes[16..]);
        ulong l0 = BinaryPrimitives.ReadUInt64BigEndian(bytes[24..]);
        ulong inRange = Mont256.LessMask(l0, l1, l2, l3, Q0, Q1, Q2, Q3);
        value = FromCanonical(l0 & inRange, l1 & inRange, l2 & inRange, l3 & inRange);
        return inRange != 0;
    }

    /// <summary>Parses a big-endian hex constant; for static tables only.</summary>
    public static Fq FromHexConstant(string hex)
    {
        var v = BigInt256.FromHex(hex);
        return FromCanonical(v.L0, v.L1, v.L2, v.L3);
    }

    /// <summary>The plain value as four limbs.</summary>
    public readonly void ToCanonical(out ulong l0, out ulong l1, out ulong l2, out ulong l3) =>
        Mont256.Mul(L0, L1, L2, L3, 1, 0, 0, 0, Q0, Q1, Q2, Q3, QInv, out l0, out l1, out l2, out l3);

    /// <summary>Writes the plain value as 32 big-endian bytes.</summary>
    public readonly void Write(Span<byte> output)
    {
        ToCanonical(out var l0, out var l1, out var l2, out var l3);
        BinaryPrimitives.WriteUInt64BigEndian(output, l3);
        BinaryPrimitives.WriteUInt64BigEndian(output[8..], l2);
        BinaryPrimitives.WriteUInt64BigEndian(output[16..], l1);
        BinaryPrimitives.WriteUInt64BigEndian(output[24..], l0);
    }
}
