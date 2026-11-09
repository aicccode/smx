using System.Numerics;
using System.Runtime.CompilerServices;

namespace SMX.SM9Internal;

/// <summary>
/// Fq12 = Fq4[w] / (w^3 - v): the element C0 + C1 w + C2 w^2, the representation of GB/T 38635. Equivalently, with
/// w^6 = u, coefficient x_j of w^j is C_j.A for j &lt; 3 and C_(j-3).B otherwise. Constant time throughout, except where
/// a method says its exponent is public.
/// </summary>
internal struct Fq12
{
    public const int ByteSize = 12 * Fq.ByteSize;

    public Fq4 C0, C1, C2;

    public Fq12(in Fq4 c0, in Fq4 c1, in Fq4 c2)
    {
        C0 = c0;
        C1 = c1;
        C2 = c2;
    }

    public static Fq12 One => new(Fq4.One, default, default);

    /// <summary>Frobenius constants gamma_k^j = u^(j (q^k - 1) / 6), all of which lie in Fq, for k = 1, 2, 3.</summary>
    private static readonly Fq[] Gamma1 = Constants(
        "3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b",
        "0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334",
        "6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011",
        "0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333",
        "2d40a38cf6983351711e5f99520347cc57d778a9f8ff4c8a4c949c7fa2a96686");

    private static readonly Fq[] Gamma2 = Constants(
        "0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65334",
        "0000000000000000f300000002a3a6f2780272354f8b78f4d5fc11967be65333",
        "b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c",
        "b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af249",
        "b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af24a");

    private static readonly Fq[] Gamma3 = Constants(
        "6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011",
        "b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457c",
        "49db721a269967c4e0a8debc0783182f82555233139e9d63efbd7b54092c756c",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "6c648de5dc0a3f2cf55acc93ee0baf159f9d411806dc5177f5b21fd3da24d011");

    /// <summary>The BN parameter t, a public exponent of the hard part of the final exponentiation.</summary>
    internal const ulong T = 0x600000000058F98A;

    private const int WindowBits = 4;
    private const int TableSize = 1 << WindowBits;

    private static Fq[] Constants(params string[] hex)
    {
        var table = new Fq[6];
        table[0] = Fq.One;
        for (int i = 0; i < hex.Length; i++)
        {
            table[i + 1] = Fq.FromHexConstant(hex[i]);
        }
        return table;
    }

    public static Fq12 Mul(in Fq12 a, in Fq12 b)
    {
        // Karatsuba over the cubic extension, with w^3 = v.
        var v0 = Fq4.Mul(a.C0, b.C0);
        var v1 = Fq4.Mul(a.C1, b.C1);
        var v2 = Fq4.Mul(a.C2, b.C2);
        var t12 = Fq4.Mul(Fq4.Add(a.C1, a.C2), Fq4.Add(b.C1, b.C2));
        var t01 = Fq4.Mul(Fq4.Add(a.C0, a.C1), Fq4.Add(b.C0, b.C1));
        var t02 = Fq4.Mul(Fq4.Add(a.C0, a.C2), Fq4.Add(b.C0, b.C2));
        var c0 = Fq4.Add(v0, Fq4.MulV(Fq4.Sub(t12, Fq4.Add(v1, v2))));
        var c1 = Fq4.Add(Fq4.Sub(t01, Fq4.Add(v0, v1)), Fq4.MulV(v2));
        var c2 = Fq4.Add(Fq4.Sub(t02, Fq4.Add(v0, v2)), v1);
        return new(c0, c1, c2);
    }

    public static Fq12 Square(in Fq12 a)
    {
        // Chung-Hasan SQR2.
        var s0 = Fq4.Square(a.C0);
        var s1 = Fq4.Double(Fq4.Mul(a.C1, a.C2));
        var s2 = Fq4.Square(Fq4.Add(Fq4.Sub(a.C0, a.C1), a.C2));
        var s3 = Fq4.Double(Fq4.Mul(a.C0, a.C1));
        var s4 = Fq4.Square(a.C2);
        var c0 = Fq4.Add(s0, Fq4.MulV(s1));
        var c1 = Fq4.Add(s3, Fq4.MulV(s4));
        var c2 = Fq4.Sub(Fq4.Add(Fq4.Add(s1, s2), s3), Fq4.Add(s0, s4));
        return new(c0, c1, c2);
    }

    /// <summary>
    /// Multiplies by a line value l0 + l2 w^2 with l0 in Fq4 and l2 in Fq2, the shape every Miller loop line takes here.
    /// </summary>
    public static Fq12 MulLine(in Fq12 f, in Fq4 l0, in Fq2 l2)
    {
        var f0l0 = Fq4.Mul(f.C0, l0);
        var f1l0 = Fq4.Mul(f.C1, l0);
        var f2l0 = Fq4.Mul(f.C2, l0);
        var c0 = Fq4.Add(f0l0, Fq4.MulV(Fq4.MulFq2(f.C1, l2)));
        var c1 = Fq4.Add(f1l0, Fq4.MulV(Fq4.MulFq2(f.C2, l2)));
        var c2 = Fq4.Add(f2l0, Fq4.MulFq2(f.C0, l2));
        return new(c0, c1, c2);
    }

    /// <summary>f^(q^6): C0' - C1' w + C2' w^2 with ' the Fq4 conjugate. On the cyclotomic subgroup this is the inverse.</summary>
    public static Fq12 Conj(in Fq12 a) => new(Fq4.Conj(a.C0), Fq4.Neg(Fq4.Conj(a.C1)), Fq4.Conj(a.C2));

    public static Fq12 Invert(in Fq12 a)
    {
        // Inverse in the cubic extension over Fq4, with w^3 = v.
        var t0 = Fq4.Sub(Fq4.Square(a.C0), Fq4.MulV(Fq4.Mul(a.C1, a.C2)));
        var t1 = Fq4.Sub(Fq4.MulV(Fq4.Square(a.C2)), Fq4.Mul(a.C0, a.C1));
        var t2 = Fq4.Sub(Fq4.Square(a.C1), Fq4.Mul(a.C0, a.C2));
        var norm = Fq4.Add(Fq4.Mul(a.C0, t0), Fq4.MulV(Fq4.Add(Fq4.Mul(a.C2, t1), Fq4.Mul(a.C1, t2))));
        var inv = Fq4.Invert(norm);
        return new(Fq4.Mul(t0, inv), Fq4.Mul(t1, inv), Fq4.Mul(t2, inv));
    }

    /// <summary>f^(q^k) for k = 1, 2 or 3: each x_j w^j becomes conj^k(x_j) gamma_k^j w^j.</summary>
    public static Fq12 Frobenius(in Fq12 a, int k)
    {
        var g = k switch
        {
            1 => Gamma1,
            2 => Gamma2,
            3 => Gamma3,
            _ => throw new ArgumentOutOfRangeException(nameof(k)),
        };
        bool odd = (k & 1) != 0;
        return new(
            new Fq4(Coefficient(a.C0.A, g[0], odd), Coefficient(a.C0.B, g[3], odd)),
            new Fq4(Coefficient(a.C1.A, g[1], odd), Coefficient(a.C1.B, g[4], odd)),
            new Fq4(Coefficient(a.C2.A, g[2], odd), Coefficient(a.C2.B, g[5], odd)));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Fq2 Coefficient(in Fq2 x, in Fq gamma, bool conjugate) =>
        Fq2.MulFq(conjugate ? Fq2.Conj(x) : x, gamma);

    /// <summary>
    /// Granger-Scott squaring, valid only in the cyclotomic subgroup (after the easy part of the final exponentiation):
    /// for f = a + b w + c w^2, f^2 = (3a^2 - 2a') + (3 v c^2 + 2b') w + (3b^2 - 2c') w^2 with ' the Fq4 conjugate.
    /// </summary>
    public static Fq12 CyclotomicSquare(in Fq12 f)
    {
        var a2 = Fq4.Square(f.C0);
        var b2 = Fq4.Square(f.C1);
        var c2v = Fq4.MulV(Fq4.Square(f.C2));
        var c0 = Fq4.Add(Fq4.Double(Fq4.Sub(a2, Fq4.Conj(f.C0))), a2);
        var c1 = Fq4.Add(Fq4.Double(Fq4.Add(c2v, Fq4.Conj(f.C1))), c2v);
        var c2 = Fq4.Add(Fq4.Double(Fq4.Sub(b2, Fq4.Conj(f.C2))), b2);
        return new(c0, c1, c2);
    }

    /// <summary>f^e in the cyclotomic subgroup for a public exponent; variable time in e only.</summary>
    public static Fq12 CyclotomicPowPublic(in Fq12 f, ulong e)
    {
        var r = f;
        for (int bit = 62 - BitOperations.LeadingZeroCount(e); bit >= 0; bit--)
        {
            r = CyclotomicSquare(r);
            if (((e >> bit) & 1) != 0)
            {
                r = Mul(r, f);
            }
        }
        return r;
    }

    /// <summary>
    /// f^k in the cyclotomic subgroup for a secret 256-bit k: a fixed 4-bit window over all 64 digits, each table entry
    /// fetched by scanning the whole table with masks, so the schedule and memory accesses do not depend on k.
    /// </summary>
    [SkipLocalsInit]
    public static Fq12 CyclotomicPowSecret(in Fq12 f, in BigInt256 k)
    {
        Span<Fq12> table = stackalloc Fq12[TableSize];
        table[0] = One;
        table[1] = f;
        for (int i = 2; i < TableSize; i++)
        {
            table[i] = (i & 1) == 0 ? CyclotomicSquare(table[i / 2]) : Mul(table[i - 1], f);
        }

        var r = Lookup(table, Digit(k, 63));
        for (int window = 62; window >= 0; window--)
        {
            for (int j = 0; j < WindowBits; j++)
            {
                r = CyclotomicSquare(r);
            }
            var entry = Lookup(table, Digit(k, window));
            r = Mul(r, entry);
        }
        table.Clear();
        return r;
    }

    /// <summary>lambda = q mod N = 6t^2: on GT, of order N, the Frobenius f -> f^q is f -> f^lambda.</summary>
    internal static readonly BigInt256 Lambda = new(0x0000b98b0cb27658, 0xd8000000019062ed, 0, 0);

    /// <summary>floor(2^383 / lambda), for the Barrett division in <see cref="SplitExponent"/>.</summary>
    private static readonly BigInt256 LambdaReciprocal = new(0x34fd5362eb8960be, 0x5ff7861020f5d4a6, 0x48b283c737327b26, 0x97b425ed08620e19);

    /// <summary>
    /// k = k0 + k1 lambda with 0 &lt;= k0 &lt; lambda (128 bits) and k1 &lt; 2^129, in constant time: the quotient estimate
    /// floor(k mu / 2^383) is at most one below the true quotient, and one masked correction fixes it.
    /// </summary>
    internal static void SplitExponent(in BigInt256 k, out BigInt256 k0, out BigInt256 k1)
    {
        Wide512.Multiply(k, LambdaReciprocal, out var w);
        var q = new BigInt256((w.W5 >> 63) | (w.W6 << 1), (w.W6 >> 63) | (w.W7 << 1), w.W7 >> 63, 0);
        Wide512.Multiply(q, Lambda, out var p);
        var r = k.Sub(new BigInt256(p.W0, p.W1, p.W2, p.W3), out _);
        var d = r.Sub(Lambda, out ulong borrow);
        ulong over = Bits.MaskFromBit(borrow ^ 1);
        k0 = BigInt256.Select(over, d, r);
        k1 = q.Add(new BigInt256(over & 1, 0, 0, 0), out _);
    }

    /// <summary>
    /// f^k for f in GT (order N) and a secret 256-bit k, as f^k0 (f^q)^k1 with the split of <see cref="SplitExponent"/>:
    /// two 4-bit fixed-window tables (the second is the Frobenius image of the first) share one 132-bit chain of
    /// squarings. All 33 digits of both halves are processed and every lookup scans its whole table, so neither the
    /// schedule nor the memory accesses depend on k.
    /// </summary>
    [SkipLocalsInit]
    public static Fq12 PowGt(in Fq12 f, in BigInt256 k)
    {
        SplitExponent(k, out var k0, out var k1);
        Span<Fq12> table = stackalloc Fq12[TableSize];
        Span<Fq12> frobTable = stackalloc Fq12[TableSize];
        table[0] = One;
        table[1] = f;
        for (int i = 2; i < TableSize; i++)
        {
            table[i] = (i & 1) == 0 ? CyclotomicSquare(table[i / 2]) : Mul(table[i - 1], f);
        }
        for (int i = 0; i < TableSize; i++)
        {
            frobTable[i] = Frobenius(table[i], 1);
        }

        const int Windows = 33;
        var r = Mul(Lookup(table, Digit(k0, Windows - 1)), Lookup(frobTable, Digit(k1, Windows - 1)));
        for (int window = Windows - 2; window >= 0; window--)
        {
            for (int j = 0; j < WindowBits; j++)
            {
                r = CyclotomicSquare(r);
            }
            r = Mul(r, Lookup(table, Digit(k0, window)));
            r = Mul(r, Lookup(frobTable, Digit(k1, window)));
        }
        table.Clear();
        frobTable.Clear();
        k0 = default;
        k1 = default;
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

    private static Fq12 Lookup(ReadOnlySpan<Fq12> table, ulong digit)
    {
        Fq12 r = default;
        for (int i = 0; i < table.Length; i++)
        {
            ulong mask = Bits.IsZeroMask((ulong)i ^ digit);
            r = Select(mask, table[i], r);
        }
        return r;
    }

    public static Fq12 Select(ulong mask, in Fq12 ifSet, in Fq12 ifClear) => new(
        Fq4.Select(mask, ifSet.C0, ifClear.C0), Fq4.Select(mask, ifSet.C1, ifClear.C1), Fq4.Select(mask, ifSet.C2, ifClear.C2));

    public readonly bool Equals(in Fq12 b) => C0.Equals(b.C0) & C1.Equals(b.C1) & C2.Equals(b.C2);

    /// <summary>The 384-byte form of GB/T 38635: c2 || c1 || c0.</summary>
    public readonly void Write(Span<byte> output)
    {
        C2.Write(output);
        C1.Write(output[(4 * Fq.ByteSize)..]);
        C0.Write(output[(8 * Fq.ByteSize)..]);
    }

    public readonly byte[] ToBytes()
    {
        var b = new byte[ByteSize];
        Write(b);
        return b;
    }
}
