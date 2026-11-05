using System.Globalization;
using System.Numerics;
using SMX;

namespace SMX.Tests;

/// <summary>
/// Differential tests of the group operations against a deliberately naive affine implementation on BigInteger, covering
/// the point at infinity, P+P, P+(-P), and the scalars around 0 and n, with both table-scan paths.
/// </summary>
[Collection("Hardware path switches")]
public class InternalGroupTests
{
    private static readonly BigInteger P = Big(Fp.P);
    private static readonly BigInteger N = Big(Sm2Order.N);
    private static readonly BigInteger A = P - 3;
    private static readonly BigInteger Two256 = BigInteger.One << 256;
    private static readonly RefPoint G = new(Big(Sm2Group.Gx), Big(Sm2Group.Gy));

    private readonly record struct RefPoint(BigInteger X, BigInteger Y, bool Infinity = false);

    private static BigInteger Big(in BigInt256 v) => BigInteger.Parse("0" + v.ToHex(), NumberStyles.HexNumber);

    private static BigInt256 FromBig(BigInteger v) => BigInt256.FromHex(((v % Two256 + Two256) % Two256).ToString("X").TrimStart('0').PadLeft(64, '0'));

    private static BigInteger Mod(BigInteger v) => (v % P + P) % P;

    private static RefPoint RefAdd(RefPoint p, RefPoint q)
    {
        if (p.Infinity)
        {
            return q;
        }
        if (q.Infinity)
        {
            return p;
        }
        BigInteger slope;
        if (p.X == q.X)
        {
            if (Mod(p.Y + q.Y) == 0)
            {
                return new RefPoint(0, 0, true);
            }
            slope = Mod((3 * p.X * p.X + A) * BigInteger.ModPow(2 * p.Y, P - 2, P));
        }
        else
        {
            slope = Mod((q.Y - p.Y) * BigInteger.ModPow(Mod(q.X - p.X), P - 2, P));
        }
        var x = Mod(slope * slope - p.X - q.X);
        return new RefPoint(x, Mod(slope * (p.X - x) - p.Y));
    }

    private static RefPoint RefMul(BigInteger k, RefPoint p)
    {
        var r = new RefPoint(0, 0, true);
        var b = p;
        while (k > 0)
        {
            if (!k.IsEven)
            {
                r = RefAdd(r, b);
            }
            b = RefAdd(b, b);
            k >>= 1;
        }
        return r;
    }

    private static ECPoint ToPoint(RefPoint p) => p.Infinity
        ? ECPoint.PointAtInfinity
        : ECPoint.Create(new FpElement(FromBig(p.X)), new FpElement(FromBig(p.Y)));

    private static void AssertSame(RefPoint expected, ECPoint actual)
    {
        Assert.Equal(expected.Infinity, actual.Infinity);
        if (!expected.Infinity)
        {
            Assert.Equal(expected.X, Big(actual.X.Value));
            Assert.Equal(expected.Y, Big(actual.Y.Value));
        }
    }

    private static IEnumerable<BigInteger> EdgeScalars()
    {
        BigInteger[] small = [0, 1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 63, 64, 65];
        foreach (var s in small)
        {
            yield return s;
            yield return N - s;
            yield return N + s;
        }
        yield return Two256 - 1;
        yield return Two256 - 2;
        yield return (N + 1) / 2;
        yield return (N - 1) / 2;
        yield return BigInteger.One << 255;
        yield return BigInteger.One << 128;
        yield return (BigInteger.One << 128) - 1;
    }

    private static IEnumerable<BigInteger> RandomScalars(int seed, int count)
    {
        var rng = new Random(seed);
        for (int i = 0; i < count; i++)
        {
            var bytes = new byte[33];
            rng.NextBytes(bytes);
            bytes[32] = 0;
            yield return new BigInteger(bytes) >> rng.Next(0, 2) * rng.Next(0, 200);
        }
    }

    [Fact]
    public void GeneratorMultiplyMatchesReferenceOnBothScanPaths()
    {
        var scalars = EdgeScalars().Concat(RandomScalars(1, 30)).ToArray();
        foreach (var useScalarScan in new[] { false, true })
        {
            Sm2Group.ForceScalarScan = useScalarScan;
            try
            {
                foreach (var k in scalars)
                {
                    var expected = RefMul(k % N, G);
                    Sm2Group.MultiplyGeneratorSecret(FromBig(k), out var r);
                    AssertSame(expected, Sm2Group.ToAffine(r));
                    AssertSame(expected, ECPoint.Generator().Multiply(FromBig(k)));
                }
            }
            finally
            {
                Sm2Group.ForceScalarScan = false;
            }
        }
    }

    [Fact]
    public void VariableBaseMultiplyMatchesReferenceOnBothScanPaths()
    {
        var bases = new[] { G, RefMul(2, G), RefMul(N - 1, G), RefMul(0x1234567, G) };
        var scalars = EdgeScalars().Concat(RandomScalars(2, 12)).ToArray();
        foreach (var useScalarScan in new[] { false, true })
        {
            Sm2Group.ForceScalarScan = useScalarScan;
            try
            {
                foreach (var b in bases)
                {
                    foreach (var k in scalars)
                    {
                        var expected = RefMul(k % N, b);
                        Sm2Group.MultiplySecret(JacobianPoint.FromAffine(ToPoint(b)), FromBig(k), out var r);
                        AssertSame(expected, Sm2Group.ToAffine(r));
                    }
                }
            }
            finally
            {
                Sm2Group.ForceScalarScan = false;
            }
        }
    }

    /// <summary>On another curve with the same a, the order differs from n, so scalars must not be reduced by n.</summary>
    [Fact]
    public void VariableBaseMultiplyIsCorrectOffTheCurve()
    {
        var p = new RefPoint(5, 7);
        foreach (var k in EdgeScalars().Concat(RandomScalars(3, 6)))
        {
            AssertSame(RefMul(k, p), ToPoint(p).Multiply(FromBig(k)));
        }
    }

    /// <summary>
    /// Scalars around n and 2n make the accumulator meet an equal table entry (first at n - 6), which needs the complete
    /// additions. These results come from small multiples because k mod n is small.
    /// </summary>
    [Fact]
    public void ScalarsNearTheOrderTakeTheCompletePathCorrectly()
    {
        var p = RefMul(0xABCDEF, G);
        var multiples = new RefPoint[201];
        multiples[0] = new RefPoint(0, 0, true);
        for (int i = 1; i < multiples.Length; i++)
        {
            multiples[i] = RefAdd(multiples[i - 1], p);
        }
        RefPoint Negated(RefPoint a) => a.Infinity ? a : new RefPoint(a.X, Mod(-a.Y));

        for (int s = 0; s <= 200; s++)
        {
            AssertSame(Negated(multiples[s]), ToPoint(p).Multiply(FromBig(N - s)));
            AssertSame(multiples[s], ToPoint(p).Multiply(FromBig(N + s)));
        }
    }

    /// <summary>The comb reduces its scalar and must never meet equal inputs, including just below n and at 2^(6i) d.</summary>
    [Fact]
    public void GeneratorMultiplyIsCorrectAroundWindowBoundaries()
    {
        var multiples = new RefPoint[301];
        multiples[0] = new RefPoint(0, 0, true);
        for (int i = 1; i < multiples.Length; i++)
        {
            multiples[i] = RefAdd(multiples[i - 1], G);
        }
        for (int s = 0; s <= 300; s++)
        {
            var negative = multiples[s].Infinity ? multiples[s] : new RefPoint(multiples[s].X, Mod(-multiples[s].Y));
            Sm2Group.MultiplyGeneratorSecret(FromBig(N - s), out var below);
            AssertSame(negative, Sm2Group.ToAffine(below));
            Sm2Group.MultiplyGeneratorSecret(FromBig(N + s), out var above);
            AssertSame(multiples[s], Sm2Group.ToAffine(above));
        }

        for (int window = 0; window < 43; window++)
        {
            foreach (var d in new[] { 1, 2, 15, 16, 31, 32, 33 })
            {
                foreach (var delta in new[] { -1, 0, 1 })
                {
                    var k = (d * (BigInteger.One << (6 * window)) + delta) % Two256;
                    var expected = RefMul(k % N, G);
                    Sm2Group.MultiplyGeneratorSecret(FromBig(k), out var r);
                    AssertSame(expected, Sm2Group.ToAffine(r));
                }
            }
        }
    }

    [Fact]
    public void TwinMultiplyMatchesReference()
    {
        var scalars = EdgeScalars().Concat(RandomScalars(4, 20)).ToArray();
        var q = RefMul(0xFEDCBA987654321, G);
        for (int i = 0; i < scalars.Length; i++)
        {
            var s = scalars[i];
            var t = scalars[(i * 7 + 3) % scalars.Length];
            var expected = RefAdd(RefMul(s % N, G), RefMul(t % N, q));
            Sm2Group.MultiplyTwinPublic(FromBig(s), FromBig(t), ToPoint(q), out var r);
            AssertSame(expected, Sm2Group.ToAffine(r));

            // Forms that cancel or double within the interleaved sum.
            Sm2Group.MultiplyTwinPublic(FromBig(s), FromBig(N - s % N), ToPoint(G), out var cancel);
            Assert.True(Sm2Group.ToAffine(cancel).Infinity);
            Sm2Group.MultiplyTwinPublic(FromBig(s), FromBig(s), ToPoint(G), out var twice);
            AssertSame(RefMul(2 * (s % N) % N, G), Sm2Group.ToAffine(twice));

            Sm2Group.MultiplyTwinPublic(FromBig(s), FromBig(t), ECPoint.PointAtInfinity, out var infinite);
            AssertSame(RefMul(s % N, G), Sm2Group.ToAffine(infinite));
        }
    }

    [Fact]
    public void SingleWnafMultiplyMatchesReference()
    {
        var q = RefMul(0x77777, G);
        foreach (var k in EdgeScalars().Concat(RandomScalars(5, 20)))
        {
            Sm2Group.MultiplyPublic(FromBig(k), ToPoint(q), out var r);
            AssertSame(RefMul(k % N, q), Sm2Group.ToAffine(r));
        }
        Sm2Group.MultiplyPublic(FromBig(5), ECPoint.PointAtInfinity, out var infinite);
        Assert.True(infinite.IsInfinity);
    }

    [Fact]
    public void SumsWithExceptionalInputsMatchReference()
    {
        var points = new[] { G, RefMul(2, G), RefMul(3, G), RefMul(N - 1, G), RefMul(N - 2, G), new RefPoint(0, 0, true) };
        foreach (var a in points)
        {
            foreach (var b in points)
            {
                AssertSame(RefAdd(a, b), ToPoint(a).Add(ToPoint(b)));

                var ja = JacobianPoint.FromAffine(ToPoint(a));
                var jb = JacobianPoint.FromAffine(ToPoint(b));
                Sm2Group.AddPublic(ja, jb, out var sum);
                AssertSame(RefAdd(a, b), Sm2Group.ToAffine(sum));

                if (!b.Infinity)
                {
                    Sm2Group.AddMixedPublic(ja, FromBig(b.X), FromBig(b.Y), out var mixed);
                    AssertSame(RefAdd(a, b), Sm2Group.ToAffine(mixed));
                }

                Sm2Group.ToAffine(ja, jb, out var fa, out var fb);
                AssertSame(a, fa);
                AssertSame(b, fb);
            }
            AssertSame(RefAdd(a, a), ToPoint(a).Twice());
            AssertSame(a.Infinity ? a : new RefPoint(a.X, Mod(-a.Y)), ToPoint(a).Negate());
        }
    }

    /// <summary>The inversion-free comparison in Verify against the plain definition, r == e.ModAdd(x, n).</summary>
    [Fact]
    public void SignatureComparisonMatchesDirectEvaluation()
    {
        var rng = new Random(6);
        BigInteger Pick()
        {
            var bytes = new byte[33];
            rng.NextBytes(bytes);
            bytes[32] = 0;
            return rng.Next(6) switch
            {
                0 => Two256 - 1 - new BigInteger(bytes) % 1000,
                1 => N - 1 - new BigInteger(bytes) % 1000,
                2 => N + new BigInteger(bytes) % 1000,
                3 => P - 1 - new BigInteger(bytes) % 1000,
                4 => new BigInteger(bytes) % 1000,
                _ => new BigInteger(bytes),
            };
        }

        int positives = 0;
        for (int i = 0; i < 4000; i++)
        {
            var e = FromBig(Pick());
            var x = FromBig(Pick() % P);
            var direct = e.ModAdd(x, Sm2Order.N);

            // A Jacobian representation of a point with that x. Only X and Z matter to the comparison.
            var z = FromBig(Pick() % (P - 1) + 1);
            Fp.Square(z, out var z2);
            Fp.Mul(x, z2, out var scaledX);
            var point = new JacobianPoint { X = scaledX, Z = z };

            if (Big(direct) < N)
            {
                Assert.True(SM2.MatchesSignatureR(e, direct, point));
                positives++;
            }

            var other = FromBig((Big(direct) + 1 + Pick() % 5) % N);
            Assert.Equal(direct == other, SM2.MatchesSignatureR(e, other, point));
        }
        Assert.True(positives > 3000);
    }

    /// <summary>Direct construction of the case where e + x overflows 2^256 and the result is below n.</summary>
    [Fact]
    public void SignatureComparisonHandlesOverflowingSum()
    {
        var e = FromBig(Two256 - 5);
        var r = FromBig(10);
        var x = FromBig(N + 15);
        Assert.Equal(r, e.ModAdd(x, Sm2Order.N));
        Assert.True(Big(x) < P);
        var point = new JacobianPoint { X = x, Z = BigInt256.One };
        Assert.True(SM2.MatchesSignatureR(e, r, point));
    }
}
