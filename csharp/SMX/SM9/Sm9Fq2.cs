using System.Runtime.CompilerServices;

namespace SMX.SM9Internal;

/// <summary>Fq2 = Fq[u] / (u^2 + 2): the element A0 + A1 u. Constant time throughout.</summary>
internal struct Fq2 : ICurveField<Fq2>
{
    public Fq A0, A1;

    public Fq2(in Fq a0, in Fq a1)
    {
        A0 = a0;
        A1 = a1;
    }

    public static Fq2 Zero => default;

    public static Fq2 One => new(Fq.One, default);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq2 Add(in Fq2 a, in Fq2 b) => new(Fq.Add(a.A0, b.A0), Fq.Add(a.A1, b.A1));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq2 Sub(in Fq2 a, in Fq2 b) => new(Fq.Sub(a.A0, b.A0), Fq.Sub(a.A1, b.A1));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq2 Double(in Fq2 a) => new(Fq.Double(a.A0), Fq.Double(a.A1));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq2 Neg(in Fq2 a) => new(Fq.Neg(a.A0), Fq.Neg(a.A1));

    /// <summary>The Fq2/Fq conjugate A0 - A1 u, which is also the q-power Frobenius.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq2 Conj(in Fq2 a) => new(a.A0, Fq.Neg(a.A1));

    /// <summary>(a0 + a1 u)(b0 + b1 u) = a0 b0 - 2 a1 b1 + ((a0 + a1)(b0 + b1) - a0 b0 - a1 b1) u.</summary>
    public static Fq2 Mul(in Fq2 a, in Fq2 b)
    {
        var v0 = Fq.Mul(a.A0, b.A0);
        var v1 = Fq.Mul(a.A1, b.A1);
        var s = Fq.Mul(Fq.Add(a.A0, a.A1), Fq.Add(b.A0, b.A1));
        return new(Fq.Sub(v0, Fq.Double(v1)), Fq.Sub(s, Fq.Add(v0, v1)));
    }

    /// <summary>(a0 + a1 u)^2 = (a0 + a1)(a0 - 2 a1) + a0 a1 + 2 a0 a1 u.</summary>
    public static Fq2 Square(in Fq2 a)
    {
        var v = Fq.Mul(a.A0, a.A1);
        var s = Fq.Mul(Fq.Add(a.A0, a.A1), Fq.Sub(a.A0, Fq.Double(a.A1)));
        return new(Fq.Add(s, v), Fq.Double(v));
    }

    /// <summary>a * 15u, three times the coefficient b' = 5u of the twist: -30 a1 + 15 a0 u.</summary>
    public static Fq2 MulB3(in Fq2 a) => new(Fq.Neg(Fq.Double(Fq.MulB3(a.A1))), Fq.MulB3(a.A0));

    public static Fq2 CurveB => TwistB;

    private static readonly Fq2 TwistB = new(default, Fq.CurveB);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq2 MulFq(in Fq2 a, in Fq k) => new(Fq.Mul(a.A0, k), Fq.Mul(a.A1, k));

    /// <summary>a * u = -2 a1 + a0 u.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq2 MulU(in Fq2 a) => new(Fq.Neg(Fq.Double(a.A1)), a.A0);

    /// <summary>1 / (a0 + a1 u) = (a0 - a1 u) / (a0^2 + 2 a1^2); zero maps to zero.</summary>
    public static Fq2 Invert(in Fq2 a)
    {
        var norm = Fq.Add(Fq.Square(a.A0), Fq.Double(Fq.Square(a.A1)));
        var inv = Fq.Invert(norm);
        return new(Fq.Mul(a.A0, inv), Fq.Neg(Fq.Mul(a.A1, inv)));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq2 Select(ulong mask, in Fq2 ifSet, in Fq2 ifClear) =>
        new(Fq.Select(mask, ifSet.A0, ifClear.A0), Fq.Select(mask, ifSet.A1, ifClear.A1));

    public readonly ulong IsZeroMask() => A0.IsZeroMask() & A1.IsZeroMask();

    public readonly bool Equals(in Fq2 b) => A0.Equals(b.A0) & A1.Equals(b.A1);

    /// <summary>Writes a1 || a0, 64 bytes, the high component first.</summary>
    public readonly void Write(Span<byte> output)
    {
        A1.Write(output);
        A0.Write(output[Fq.ByteSize..]);
    }

    /// <summary>Reads a1 || a0; false when either coordinate is not below q.</summary>
    public static bool TryRead(ReadOnlySpan<byte> input, out Fq2 value)
    {
        bool ok1 = Fq.TryRead(input, out var a1);
        bool ok0 = Fq.TryRead(input[Fq.ByteSize..], out var a0);
        value = new Fq2(a0, a1);
        return ok0 & ok1;
    }
}

/// <summary>Fq4 = Fq2[v] / (v^2 - u): the element A + B v. Constant time throughout.</summary>
internal struct Fq4
{
    public Fq2 A, B;

    public Fq4(in Fq2 a, in Fq2 b)
    {
        A = a;
        B = b;
    }

    public static Fq4 One => new(Fq2.One, default);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq4 Add(in Fq4 x, in Fq4 y) => new(Fq2.Add(x.A, y.A), Fq2.Add(x.B, y.B));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq4 Sub(in Fq4 x, in Fq4 y) => new(Fq2.Sub(x.A, y.A), Fq2.Sub(x.B, y.B));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq4 Double(in Fq4 x) => new(Fq2.Double(x.A), Fq2.Double(x.B));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq4 Neg(in Fq4 x) => new(Fq2.Neg(x.A), Fq2.Neg(x.B));

    /// <summary>The Fq4/Fq2 conjugate A - B v, which is also the q^2-power Frobenius on Fq4.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq4 Conj(in Fq4 x) => new(x.A, Fq2.Neg(x.B));

    /// <summary>(a + b v)(c + d v) = a c + b d u + ((a + b)(c + d) - a c - b d) v.</summary>
    public static Fq4 Mul(in Fq4 x, in Fq4 y)
    {
        var ac = Fq2.Mul(x.A, y.A);
        var bd = Fq2.Mul(x.B, y.B);
        var s = Fq2.Mul(Fq2.Add(x.A, x.B), Fq2.Add(y.A, y.B));
        return new(Fq2.Add(ac, Fq2.MulU(bd)), Fq2.Sub(s, Fq2.Add(ac, bd)));
    }

    /// <summary>(a + b v)^2 = (a + b)(a + b u) - a b - a b u + 2 a b v.</summary>
    public static Fq4 Square(in Fq4 x)
    {
        var ab = Fq2.Mul(x.A, x.B);
        var s = Fq2.Mul(Fq2.Add(x.A, x.B), Fq2.Add(x.A, Fq2.MulU(x.B)));
        return new(Fq2.Sub(s, Fq2.Add(ab, Fq2.MulU(ab))), Fq2.Double(ab));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq4 MulFq2(in Fq4 x, in Fq2 k) => new(Fq2.Mul(x.A, k), Fq2.Mul(x.B, k));

    /// <summary>(a + b v) v = b u + a v.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq4 MulV(in Fq4 x) => new(Fq2.MulU(x.B), x.A);

    /// <summary>1 / (a + b v) = (a - b v) / (a^2 - b^2 u).</summary>
    public static Fq4 Invert(in Fq4 x)
    {
        var norm = Fq2.Sub(Fq2.Square(x.A), Fq2.MulU(Fq2.Square(x.B)));
        var inv = Fq2.Invert(norm);
        return new(Fq2.Mul(x.A, inv), Fq2.Neg(Fq2.Mul(x.B, inv)));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Fq4 Select(ulong mask, in Fq4 ifSet, in Fq4 ifClear) =>
        new(Fq2.Select(mask, ifSet.A, ifClear.A), Fq2.Select(mask, ifSet.B, ifClear.B));

    public readonly bool Equals(in Fq4 y) => A.Equals(y.A) & B.Equals(y.B);

    /// <summary>Writes b || a, 128 bytes.</summary>
    public readonly void Write(Span<byte> output)
    {
        B.Write(output);
        A.Write(output[(2 * Fq.ByteSize)..]);
    }
}
