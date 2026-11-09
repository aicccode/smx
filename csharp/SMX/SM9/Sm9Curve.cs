using System.Runtime.CompilerServices;

namespace SMX.SM9Internal;

/// <summary>The field operations the curve formulas need, implemented by <see cref="Fq"/> (G1) and <see cref="Fq2"/> (G2).</summary>
internal interface ICurveField<T> where T : unmanaged, ICurveField<T>
{
    static abstract T Zero { get; }
    static abstract T One { get; }
    static abstract T CurveB { get; }
    static abstract T Add(in T a, in T b);
    static abstract T Sub(in T a, in T b);
    static abstract T Double(in T a);
    static abstract T Neg(in T a);
    static abstract T Mul(in T a, in T b);
    static abstract T Square(in T a);
    static abstract T MulB3(in T a);
    static abstract T Invert(in T a);
    static abstract T Select(ulong mask, in T ifSet, in T ifClear);
    ulong IsZeroMask();
}

/// <summary>A point in homogeneous projective coordinates: (X : Y : Z) is the affine (X/Z, Y/Z); Z = 0 is the identity.</summary>
internal struct ProjPoint<T> where T : unmanaged, ICurveField<T>
{
    public T X, Y, Z;

    public ProjPoint(in T x, in T y, in T z)
    {
        X = x;
        Y = y;
        Z = z;
    }

    public static ProjPoint<T> Identity => new(T.Zero, T.One, T.Zero);

    public static ProjPoint<T> FromAffine(in T x, in T y) => new(x, y, T.One);

    public readonly bool IsIdentity => Z.IsZeroMask() != 0;
}

/// <summary>
/// Arithmetic on y^2 = x^3 + b over T with the complete formulas of Renes, Costello and Batina (2016, algorithms 7 and
/// 9 for a = 0). They hold for every pair of inputs, the identity and equal points included, on curves without points
/// of order two; E(Fq) has prime order N and the twist E'(Fq2) has odd order N (2q - N), so both qualify. Having no
/// exceptional cases, they need no branches at all.
/// </summary>
internal static class Curve<T> where T : unmanaged, ICurveField<T>
{
    private const int WindowBits = 4;
    private const int TableSize = 1 << WindowBits;

    public static ProjPoint<T> Add(in ProjPoint<T> p, in ProjPoint<T> q)
    {
        var t0 = T.Mul(p.X, q.X);
        var t1 = T.Mul(p.Y, q.Y);
        var t2 = T.Mul(p.Z, q.Z);
        var t3 = T.Mul(T.Add(p.X, p.Y), T.Add(q.X, q.Y));
        var t4 = T.Add(t0, t1);
        t3 = T.Sub(t3, t4);
        t4 = T.Mul(T.Add(p.Y, p.Z), T.Add(q.Y, q.Z));
        var x3 = T.Add(t1, t2);
        t4 = T.Sub(t4, x3);
        x3 = T.Mul(T.Add(p.X, p.Z), T.Add(q.X, q.Z));
        var y3 = T.Add(t0, t2);
        y3 = T.Sub(x3, y3);
        x3 = T.Double(t0);
        t0 = T.Add(x3, t0);
        t2 = T.MulB3(t2);
        var z3 = T.Add(t1, t2);
        t1 = T.Sub(t1, t2);
        y3 = T.MulB3(y3);
        x3 = T.Mul(t4, y3);
        t2 = T.Mul(t3, t1);
        x3 = T.Sub(t2, x3);
        y3 = T.Mul(y3, t0);
        t1 = T.Mul(t1, z3);
        y3 = T.Add(t1, y3);
        t0 = T.Mul(t0, t3);
        z3 = T.Mul(z3, t4);
        z3 = T.Add(z3, t0);
        return new(x3, y3, z3);
    }

    public static ProjPoint<T> Double(in ProjPoint<T> p)
    {
        var t0 = T.Square(p.Y);
        var z3 = T.Double(T.Double(T.Double(t0)));
        var t1 = T.Mul(p.Y, p.Z);
        var t2 = T.MulB3(T.Square(p.Z));
        var x3 = T.Mul(t2, z3);
        var y3 = T.Add(t0, t2);
        z3 = T.Mul(t1, z3);
        t1 = T.Double(t2);
        t2 = T.Add(t1, t2);
        t0 = T.Sub(t0, t2);
        y3 = T.Mul(t0, y3);
        y3 = T.Add(x3, y3);
        t1 = T.Mul(p.X, p.Y);
        x3 = T.Mul(t0, t1);
        x3 = T.Double(x3);
        return new(x3, y3, z3);
    }

    public static ProjPoint<T> Neg(in ProjPoint<T> p) => new(p.X, T.Neg(p.Y), p.Z);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ProjPoint<T> Select(ulong mask, in ProjPoint<T> ifSet, in ProjPoint<T> ifClear) =>
        new(T.Select(mask, ifSet.X, ifClear.X), T.Select(mask, ifSet.Y, ifClear.Y), T.Select(mask, ifSet.Z, ifClear.Z));

    /// <summary>
    /// [k]P for a secret 256-bit k (any value, reduced or not): a fixed 4-bit window over all 64 digits, with every table
    /// entry read on each lookup and chosen by mask, and complete formulas throughout, so nothing depends on k or P.
    /// </summary>
    [SkipLocalsInit]
    public static ProjPoint<T> Multiply(in ProjPoint<T> p, in BigInt256 k)
    {
        Span<ProjPoint<T>> table = stackalloc ProjPoint<T>[TableSize];
        table[0] = ProjPoint<T>.Identity;
        table[1] = p;
        for (int i = 2; i < TableSize; i++)
        {
            table[i] = (i & 1) == 0 ? Double(table[i / 2]) : Add(table[i - 1], p);
        }

        var r = Lookup(table, Digit(k, 63));
        for (int window = 62; window >= 0; window--)
        {
            r = Double(Double(Double(Double(r))));
            r = Add(r, Lookup(table, Digit(k, window)));
        }
        table.Clear();
        return r;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Digit(in BigInt256 k, int window)
    {
        int bit = window * WindowBits;
        ulong limb = (bit >> 6) switch
        {
            0 => k.L0,
            1 => k.L1,
            2 => k.L2,
            _ => k.L3,
        };
        return (limb >> (bit & 63)) & (TableSize - 1);
    }

    private static ProjPoint<T> Lookup(ReadOnlySpan<ProjPoint<T>> table, ulong digit)
    {
        var r = table[0];
        for (int i = 1; i < table.Length; i++)
        {
            r = Select(Bits.IsZeroMask((ulong)i ^ digit), table[i], r);
        }
        return r;
    }

    /// <summary>
    /// [k]P for a public 128-bit k by left-to-right double and add: variable time in k only, so P may be secret.
    /// </summary>
    public static ProjPoint<T> MultiplyPublic(in ProjPoint<T> p, UInt128 k)
    {
        var r = ProjPoint<T>.Identity;
        for (int bit = 127 - (int)UInt128.LeadingZeroCount(k); bit >= 0; bit--)
        {
            r = Double(r);
            if (((k >> bit) & 1) != 0)
            {
                r = Add(r, p);
            }
        }
        return r;
    }

    /// <summary>The affine coordinates; false for the identity, whose output coordinates are zero.</summary>
    public static bool ToAffine(in ProjPoint<T> p, out T x, out T y)
    {
        var zInv = T.Invert(p.Z);
        x = T.Mul(p.X, zInv);
        y = T.Mul(p.Y, zInv);
        return p.Z.IsZeroMask() == 0;
    }

    /// <summary>Whether affine (x, y) satisfies y^2 = x^3 + b.</summary>
    public static bool IsOnCurve(in T x, in T y)
    {
        var lhs = T.Square(y);
        var rhs = T.Add(T.Mul(T.Square(x), x), T.CurveB);
        return T.Sub(lhs, rhs).IsZeroMask() != 0;
    }

    /// <summary>Whether two projective points are the same point: X1 Z2 = X2 Z1 and Y1 Z2 = Y2 Z1.</summary>
    public static bool Equal(in ProjPoint<T> p, in ProjPoint<T> q)
    {
        var dx = T.Sub(T.Mul(p.X, q.Z), T.Mul(q.X, p.Z));
        var dy = T.Sub(T.Mul(p.Y, q.Z), T.Mul(q.Y, p.Z));
        bool pInf = p.IsIdentity, qInf = q.IsIdentity;
        return (pInf & qInf) | (!pInf & !qInf & (dx.IsZeroMask() & dy.IsZeroMask()) != 0);
    }
}

/// <summary>
/// Precomputed multiples j 2^(4i) B (j = 0..15, i = 0..63) of a fixed base point B, so that [k]B is 63 additions of
/// table entries with no doublings. Each entry is fetched by scanning its whole row with masks, so k may be secret.
/// </summary>
internal sealed class FixedBaseTable<T> where T : unmanaged, ICurveField<T>
{
    private const int WindowBits = 4;
    private const int RowSize = 1 << WindowBits;
    private const int Windows = 256 / WindowBits;

    private readonly ProjPoint<T>[] _table = new ProjPoint<T>[Windows * RowSize];

    public FixedBaseTable(in ProjPoint<T> basePoint)
    {
        var rowBase = basePoint;
        for (int i = 0; i < Windows; i++)
        {
            int row = i * RowSize;
            _table[row] = ProjPoint<T>.Identity;
            _table[row + 1] = rowBase;
            for (int j = 2; j < RowSize; j++)
            {
                _table[row + j] = (j & 1) == 0 ? Curve<T>.Double(_table[row + j / 2]) : Curve<T>.Add(_table[row + j - 1], rowBase);
            }
            rowBase = Curve<T>.Double(_table[row + RowSize / 2]);
        }
    }

    public ProjPoint<T> Multiply(in BigInt256 k)
    {
        var r = Lookup(0, k.L0 & (RowSize - 1));
        for (int i = 1; i < Windows; i++)
        {
            int bit = i * WindowBits;
            ulong limb = (bit >> 6) switch
            {
                0 => k.L0,
                1 => k.L1,
                2 => k.L2,
                _ => k.L3,
            };
            r = Curve<T>.Add(r, Lookup(i, (limb >> (bit & 63)) & (RowSize - 1)));
        }
        return r;
    }

    private ProjPoint<T> Lookup(int window, ulong digit)
    {
        ReadOnlySpan<ProjPoint<T>> row = _table.AsSpan(window * RowSize, RowSize);
        var r = row[0];
        for (int j = 1; j < RowSize; j++)
        {
            ulong mask = Bits.IsZeroMask((ulong)j ^ digit);
            r = new ProjPoint<T>(T.Select(mask, row[j].X, r.X), T.Select(mask, row[j].Y, r.Y), T.Select(mask, row[j].Z, r.Z));
        }
        return r;
    }
}
