namespace SMX.SM9Internal;

/// <summary>
/// The R-ate pairing of GB/T 38635 with a = 6t + 2. The Miller loop keeps T in Jacobian coordinates over Fq2 and
/// evaluates each line at P without inversions; every line is a multiple, by a factor in Fq2, of the affine line
/// (y_T - lambda x_T) + lambda x_P w^2 - y_P v of the reference, so it has the sparse shape l0 + l2 w^2 and the factor
/// vanishes in the final exponentiation. The loop's schedule depends only on the public a, and its arithmetic is
/// branch-free, so the pairing is constant time in both points (which matters when one is a user's private key).
/// </summary>
internal static class Sm9Pairing
{
    private static readonly UInt128 LoopCount = (UInt128)Fq12.T * 6 + 2;

    /// <summary>Constants of the Frobenius on the twist: pi(x, y) = (conj(x) PiX, conj(y) PiY).</summary>
    private static readonly Fq PiX = Fq.FromHexConstant("b640000002a3a6f0e303ab4ff2eb2052a9f02115caef75e70f738991676af24a");
    private static readonly Fq PiY = Fq.FromHexConstant("49db721a269967c4e0a8debc0783182f82555233139e9d63efbd7b54092c756c");

    /// <summary>e(P, Q) for affine P in G1 and Q in G2; 1 when either is the identity.</summary>
    public static Fq12 Pair(in G1Affine p, in G2Affine q)
    {
        if (p.Infinity || q.Infinity)
        {
            return Fq12.One;
        }
        return FinalExponentiation(MillerLoop(p.X, p.Y, q.X, q.Y));
    }

    internal static void TwistFrobenius(in Fq2 x, in Fq2 y, out Fq2 fx, out Fq2 fy)
    {
        fx = Fq2.MulFq(Fq2.Conj(x), PiX);
        fy = Fq2.MulFq(Fq2.Conj(y), PiY);
    }

    internal static Fq12 MillerLoop(in Fq xP, in Fq yP, in Fq2 xQ, in Fq2 yQ)
    {
        var negYP = Fq.Neg(yP);
        Fq2 x = xQ, y = yQ, z = Fq2.One;
        var f = Fq12.One;

        int top = 127 - (int)UInt128.LeadingZeroCount(LoopCount);
        for (int bit = top - 1; bit >= 0; bit--)
        {
            DoubleStep(ref x, ref y, ref z, xP, negYP, out var l0, out var l2);
            f = bit == top - 1 ? Fq12.MulLine(Fq12.One, l0, l2) : Fq12.MulLine(Fq12.Square(f), l0, l2);
            if (((LoopCount >> bit) & 1) != 0)
            {
                AddStep(ref x, ref y, ref z, xQ, yQ, xP, negYP, out l0, out l2);
                f = Fq12.MulLine(f, l0, l2);
            }
        }

        TwistFrobenius(xQ, yQ, out var x1, out var y1);
        TwistFrobenius(x1, y1, out var x2, out var y2);
        AddStep(ref x, ref y, ref z, x1, y1, xP, negYP, out var m0, out var m2);
        f = Fq12.MulLine(f, m0, m2);
        AddStep(ref x, ref y, ref z, x2, Fq2.Neg(y2), xP, negYP, out m0, out m2);
        return Fq12.MulLine(f, m0, m2);
    }

    /// <summary>
    /// T = 2T with T = (X, Y, Z) Jacobian (x = X/Z^2, y = Y/Z^3), and the tangent at the old T evaluated at P, scaled by
    /// 2 Y Z^3: l0 = (2Y^2 - 3X^3) + (-y_P 2Y Z^3) v and l2 = 3X^2 Z^2 x_P.
    /// </summary>
    private static void DoubleStep(ref Fq2 x, ref Fq2 y, ref Fq2 z, in Fq xP, in Fq negYP, out Fq4 l0, out Fq2 l2)
    {
        var a = Fq2.Square(x);
        var b = Fq2.Square(y);
        var c = Fq2.Square(b);
        var zz = Fq2.Square(z);
        var d = Fq2.Double(Fq2.Sub(Fq2.Square(Fq2.Add(x, b)), Fq2.Add(a, c)));
        var e = Fq2.Add(Fq2.Double(a), a);
        var x3 = Fq2.Sub(Fq2.Square(e), Fq2.Double(d));
        var c8 = Fq2.Double(Fq2.Double(Fq2.Double(c)));
        var y3 = Fq2.Sub(Fq2.Mul(e, Fq2.Sub(d, x3)), c8);
        var z3 = Fq2.Sub(Fq2.Square(Fq2.Add(y, z)), Fq2.Add(b, zz));

        l0 = new Fq4(Fq2.Sub(Fq2.Double(b), Fq2.Mul(e, x)), Fq2.MulFq(Fq2.Mul(z3, zz), negYP));
        l2 = Fq2.MulFq(Fq2.Mul(e, zz), xP);
        x = x3;
        y = y3;
        z = z3;
    }

    /// <summary>
    /// T = T + Q for affine Q, and the line through T and Q evaluated at P, scaled by Z3 = Z H:
    /// l0 = (y_Q Z3 - R x_Q) + (-y_P Z3) v and l2 = R x_P, with H = x_Q Z^2 - X and R = y_Q Z^3 - Y.
    /// </summary>
    private static void AddStep(ref Fq2 x, ref Fq2 y, ref Fq2 z, in Fq2 xQ, in Fq2 yQ, in Fq xP, in Fq negYP, out Fq4 l0, out Fq2 l2)
    {
        var zz = Fq2.Square(z);
        var u2 = Fq2.Mul(xQ, zz);
        var s2 = Fq2.Mul(yQ, Fq2.Mul(z, zz));
        var h = Fq2.Sub(u2, x);
        var r = Fq2.Sub(s2, y);
        var z3 = Fq2.Mul(z, h);
        var hh = Fq2.Square(h);
        var hhh = Fq2.Mul(h, hh);
        var v = Fq2.Mul(x, hh);
        var x3 = Fq2.Sub(Fq2.Sub(Fq2.Square(r), hhh), Fq2.Double(v));
        var y3 = Fq2.Sub(Fq2.Mul(r, Fq2.Sub(v, x3)), Fq2.Mul(y, hhh));

        l0 = new Fq4(Fq2.Sub(Fq2.Mul(yQ, z3), Fq2.Mul(r, xQ)), Fq2.MulFq(z3, negYP));
        l2 = Fq2.MulFq(r, xP);
        x = x3;
        y = y3;
        z = z3;
    }

    /// <summary>f^((q^12 - 1) / N): the easy part (q^6 - 1)(q^2 + 1), then the hard part by the BN addition chain in t.</summary>
    internal static Fq12 FinalExponentiation(in Fq12 f)
    {
        var easy = Fq12.Mul(Fq12.Conj(f), Fq12.Invert(f));
        easy = Fq12.Mul(Fq12.Frobenius(easy, 2), easy);
        return HardPart(easy);
    }

    /// <summary>
    /// f^((q^4 - q^2 + 1) / N) for f in the cyclotomic subgroup, using the exact decomposition
    /// l0 + l1 q + l2 q^2 + q^3 with l0 = -36t^3 - 30t^2 - 18t - 2, l1 = -36t^3 - 18t^2 - 12t + 1, l2 = 6t^2 + 1
    /// (Scott et al., Devegili et al.), so the result equals the plain exponentiation of the reference.
    /// </summary>
    internal static Fq12 HardPart(in Fq12 f)
    {
        var fu = Fq12.CyclotomicPowPublic(f, Fq12.T);
        var fu2 = Fq12.CyclotomicPowPublic(fu, Fq12.T);
        var fu3 = Fq12.CyclotomicPowPublic(fu2, Fq12.T);

        var y0 = Fq12.Mul(Fq12.Mul(Fq12.Frobenius(f, 1), Fq12.Frobenius(f, 2)), Fq12.Frobenius(f, 3));
        var y1 = Fq12.Conj(f);
        var y2 = Fq12.Frobenius(fu2, 2);
        var y3 = Fq12.Conj(Fq12.Frobenius(fu, 1));
        var y4 = Fq12.Conj(Fq12.Mul(fu, Fq12.Frobenius(fu2, 1)));
        var y5 = Fq12.Conj(fu2);
        var y6 = Fq12.Conj(Fq12.Mul(fu3, Fq12.Frobenius(fu3, 1)));

        var t0 = Fq12.Mul(Fq12.Mul(Fq12.CyclotomicSquare(y6), y4), y5);
        var t1 = Fq12.Mul(Fq12.Mul(y3, y5), t0);
        t0 = Fq12.Mul(t0, y2);
        t1 = Fq12.CyclotomicSquare(Fq12.Mul(Fq12.CyclotomicSquare(t1), t0));
        t0 = Fq12.Mul(t1, y1);
        t1 = Fq12.Mul(t1, y0);
        return Fq12.Mul(Fq12.CyclotomicSquare(t0), t1);
    }
}
