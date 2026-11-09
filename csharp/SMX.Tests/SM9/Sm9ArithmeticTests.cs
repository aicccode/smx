using System.Numerics;
using SMX.SM9Internal;

namespace SMX.Tests.SM9;

public class Sm9ArithmeticTests
{
    private static readonly BigInteger Q = BigInteger.Parse("0b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d", System.Globalization.NumberStyles.HexNumber);
    private static readonly BigInteger N = BigInteger.Parse("0b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25", System.Globalization.NumberStyles.HexNumber);

    private static Fq FqOf(BigInteger v)
    {
        var b = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        var padded = new byte[32];
        b.CopyTo(padded, 32 - b.Length);
        Assert.True(Fq.TryRead(padded, out var f));
        return f;
    }

    private static BigInteger Big(in Fq f)
    {
        var b = new byte[32];
        f.Write(b);
        return new BigInteger(b, isUnsigned: true, isBigEndian: true);
    }

    private static BigInteger RandomBelow(Random r, BigInteger m)
    {
        var b = new byte[40];
        r.NextBytes(b);
        return new BigInteger(b, isUnsigned: true) % m;
    }

    [Fact]
    public void FieldOperationsMatchBigInteger()
    {
        var r = new Random(7);
        var edge = new[] { BigInteger.Zero, BigInteger.One, Q - 1, Q - 2, (BigInteger.One << 255) % Q };
        for (int i = 0; i < 2000; i++)
        {
            var a = i < 25 ? edge[i % 5] : RandomBelow(r, Q);
            var b = i < 25 ? edge[i / 5] : RandomBelow(r, Q);
            Assert.Equal(a * b % Q, Big(Fq.Mul(FqOf(a), FqOf(b))));
            Assert.Equal((a + b) % Q, Big(Fq.Add(FqOf(a), FqOf(b))));
            Assert.Equal(((a - b) % Q + Q) % Q, Big(Fq.Sub(FqOf(a), FqOf(b))));
            Assert.Equal(15 * a % Q, Big(Fq.MulB3(FqOf(a))));
            if (!a.IsZero)
            {
                Assert.Equal(BigInteger.ModPow(a, Q - 2, Q), Big(Fq.Invert(FqOf(a))));
            }
        }
    }

    [Fact]
    public void ScalarOperationsMatchBigInteger()
    {
        var r = new Random(8);
        for (int i = 0; i < 500; i++)
        {
            var a = RandomBelow(r, N);
            var b = RandomBelow(r, N);
            var x = Scalar(a);
            var y = Scalar(b);
            Assert.Equal(a * b % N, Big(Sm9Scalar.Mul(x, y)));
            Assert.Equal((a + b) % N, Big(Sm9Scalar.Add(x, y)));
            Assert.Equal(((a - b) % N + N) % N, Big(Sm9Scalar.Sub(x, y)));
            if (!a.IsZero)
            {
                Assert.Equal(BigInteger.ModPow(a, N - 2, N), Big(Sm9Scalar.Invert(x)));
            }
        }
    }

    private static BigInt256 Scalar(BigInteger v)
    {
        var b = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        var padded = new byte[32];
        b.CopyTo(padded, 32 - b.Length);
        return BigInt256.FromBEBytes(padded);
    }

    private static BigInteger Big(in BigInt256 v) => new(v.ToBEBytes(), isUnsigned: true, isBigEndian: true);

    private static Fq12 RandomFq12(Random r)
    {
        Fq2 F2() => new(FqOf(RandomBelow(r, Q)), FqOf(RandomBelow(r, Q)));
        Fq4 F4() => new(F2(), F2());
        return new Fq12(F4(), F4(), F4());
    }

    [Fact]
    public void TowerIdentities()
    {
        var r = new Random(9);
        for (int i = 0; i < 20; i++)
        {
            var a = RandomFq12(r);
            var b = RandomFq12(r);
            var c = RandomFq12(r);
            Assert.True(Fq12.Mul(a, Fq12.Mul(b, c)).Equals(Fq12.Mul(Fq12.Mul(a, b), c)));
            Assert.True(Fq12.Square(a).Equals(Fq12.Mul(a, a)));
            Assert.True(Fq12.Mul(a, Fq12.Invert(a)).Equals(Fq12.One));

            // Frobenius is a ring homomorphism, with the k-th power the composition of k first powers.
            Assert.True(Fq12.Frobenius(Fq12.Mul(a, b), 1).Equals(Fq12.Mul(Fq12.Frobenius(a, 1), Fq12.Frobenius(b, 1))));
            Assert.True(Fq12.Frobenius(a, 2).Equals(Fq12.Frobenius(Fq12.Frobenius(a, 1), 1)));
            Assert.True(Fq12.Frobenius(a, 3).Equals(Fq12.Frobenius(Fq12.Frobenius(a, 2), 1)));

            // Cyclotomic elements: the easy part of the final exponentiation.
            var easy = Fq12.Mul(Fq12.Conj(a), Fq12.Invert(a));
            easy = Fq12.Mul(Fq12.Frobenius(easy, 2), easy);
            Assert.True(Fq12.CyclotomicSquare(easy).Equals(Fq12.Square(easy)));
            Assert.True(Fq12.Mul(easy, Fq12.Conj(easy)).Equals(Fq12.One));
        }
    }

    [Fact]
    public void HardPartMatchesPlainExponentiation()
    {
        var r = new Random(10);
        var a = RandomFq12(r);
        var easy = Fq12.Mul(Fq12.Conj(a), Fq12.Invert(a));
        easy = Fq12.Mul(Fq12.Frobenius(easy, 2), easy);
        var e = (BigInteger.Pow(Q, 4) - Q * Q + 1) / N;
        var expected = Fq12.One;
        var bytes = e.ToByteArray(isUnsigned: true, isBigEndian: true);
        foreach (var by in bytes)
        {
            for (int bit = 7; bit >= 0; bit--)
            {
                expected = Fq12.Square(expected);
                if (((by >> bit) & 1) != 0)
                {
                    expected = Fq12.Mul(expected, easy);
                }
            }
        }
        Assert.True(Sm9Pairing.HardPart(easy).Equals(expected));
    }

    [Fact]
    public void GeneratorsAndMasterKeys()
    {
        Assert.True(Curve<Fq>.IsOnCurve(G1Affine.Generator.X, G1Affine.Generator.Y));
        Assert.True(Curve<Fq2>.IsOnCurve(G2Affine.Generator.X, G2Affine.Generator.Y));
        Assert.True(G2Affine.IsInSubgroup(G2Affine.Generator));
        Assert.Equal(Sm9Vectors.Json.GetProperty("params").Str("P1"), G1Affine.Generator.ToHex());
        Assert.Equal(Sm9Vectors.Json.GetProperty("params").Str("P2"), G2Affine.Generator.ToHex());

        var sign = Sm9Vectors.Standard("sign");
        var ks = BigInt256.FromHex(sign.Str("master_private_key"));
        Assert.Equal(sign.Str("master_public_key"), G2Affine.Generator.Multiply(ks).ToHex());
        var enc = Sm9Vectors.Standard("encrypt");
        var ke = BigInt256.FromHex(enc.Str("master_private_key"));
        Assert.Equal(enc.Str("master_public_key"), G1Affine.Generator.Multiply(ke).ToHex());
        Assert.True(G1Affine.Generator.Multiply(Sm9Scalar.N).Infinity);
    }

    [Fact]
    public void PairingMatchesStandardExample()
    {
        var sign = Sm9Vectors.Standard("sign");
        Assert.True(G2Affine.TryParseHex(sign.Str("master_public_key"), out var ppub));
        var g = Sm9Pairing.Pair(G1Affine.Generator, ppub);
        Assert.Equal(sign.Str("pairing_g"), Convert.ToHexString(g.ToBytes()).ToLowerInvariant());
    }

    [Fact]
    public void PairingIsBilinear()
    {
        var a = new BigInt256(12345, 0, 0, 0);
        var b = new BigInt256(0xdeadbeef, 7, 0, 0);
        var e = Sm9Pairing.Pair(G1Affine.Generator, G2Affine.Generator);
        var lhs = Sm9Pairing.Pair(G1Affine.Generator.Multiply(a), G2Affine.Generator.Multiply(b));
        var ab = Sm9Scalar.Mul(a, b);
        Assert.True(lhs.Equals(Fq12.CyclotomicPowSecret(e, ab)));
        Assert.False(e.Equals(Fq12.One));
        Assert.True(Fq12.CyclotomicPowSecret(e, Sm9Scalar.N).Equals(Fq12.One));
    }

    [Fact]
    public void SubgroupCheckAgreesWithOrderCheck()
    {
        // T0: on the twist but not in G2. The cofactor h = 2q - N has the small factors 13 and 1621.
        var t0Hex = Sm9Vectors.Json.GetProperty("invalid_points").GetProperty("g2").EnumerateArray()
            .First(e => e.Str("name") == "not_in_subgroup").Str("value");
        var bytes = Convert.FromHexString(t0Hex);
        Assert.True(Fq2.TryRead(bytes.AsSpan(1, 64), out var x) & Fq2.TryRead(bytes.AsSpan(65, 64), out var y));
        var t0 = new G2Affine(x, y, false);
        var h = (2 * Q - N);
        var cases = new List<(G2Affine Point, bool InG2)>
        {
            (t0, false),
            (Mul(t0, h), true),
            (Mul(t0, h / 13), false),
            (Mul(t0, h / 1621), false),
            (Mul(Mul(t0, h / 13), N), false),
            (Mul(Mul(t0, h / 1621), N), false),
            (Mul(t0, 13 * 1621), false),
            (G2Affine.FromProjective(Curve<Fq2>.Add(t0.ToProjective(), G2Affine.Generator.ToProjective())), false),
            (G2Affine.Generator, true),
            (Mul(G2Affine.Generator, 0x123456789abcdefUL), true),
        };
        foreach (var (point, inG2) in cases)
        {
            Assert.False(point.Infinity);
            Assert.True(Curve<Fq2>.IsOnCurve(point.X, point.Y));
            Assert.Equal(inG2, G2Affine.IsInSubgroupByOrder(point));
            Assert.Equal(inG2, G2Affine.IsInSubgroup(point));
        }
    }

    private static G2Affine Mul(in G2Affine p, BigInteger k) => p.Multiply(Scalar(k));

    [Fact]
    public void FixedBaseTablesMatchVariableBase()
    {
        var r = new Random(11);
        var ks = new List<BigInteger> { 0, 1, 15, 16, N - 1, N, (BigInteger.One << 256) - 1 };
        for (int i = 0; i < 10; i++)
        {
            ks.Add(RandomBelow(r, N));
        }
        foreach (var k in ks)
        {
            var s = Scalar(k);
            Assert.True(Curve<Fq>.Equal(G1Affine.MultiplyGenerator(s), Curve<Fq>.Multiply(G1Affine.Generator.ToProjective(), s)));
            Assert.True(Curve<Fq2>.Equal(G2Affine.MultiplyGenerator(s), Curve<Fq2>.Multiply(G2Affine.Generator.ToProjective(), s)));
        }
        var big = new BigInt256(ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue);
        Assert.True(Curve<Fq>.Equal(G1Affine.MultiplyGenerator(big), Curve<Fq>.Multiply(G1Affine.Generator.ToProjective(), big)));
    }

    [Fact]
    public void ExponentSplitIsExact()
    {
        var lambda = BigInteger.Parse("0d8000000019062ed0000b98b0cb27658", System.Globalization.NumberStyles.HexNumber);
        var r = new Random(12);
        var ks = new List<BigInteger> { 0, 1, lambda - 1, lambda, lambda + 1, 2 * lambda, N - 1, N, (BigInteger.One << 256) - 1 };
        for (int i = 0; i < 2000; i++)
        {
            var b = new byte[32];
            r.NextBytes(b);
            ks.Add(new BigInteger(b, isUnsigned: true));
        }
        foreach (var k in ks)
        {
            Fq12.SplitExponent(Scalar(k), out var k0, out var k1);
            Assert.Equal(k / lambda, Big(k1));
            Assert.Equal(k % lambda, Big(k0));
        }
    }

    [Fact]
    public void GtPowerMatchesPlainWindow()
    {
        var g = Sm9Pairing.Pair(G1Affine.Generator, G2Affine.Generator);
        Assert.True(Fq12.Frobenius(g, 1).Equals(Fq12.CyclotomicPowSecret(g, Fq12.Lambda)));
        var r = new Random(13);
        var ks = new List<BigInteger> { 0, 1, 2, N - 1, N, N + 1, (BigInteger.One << 256) - 1 };
        for (int i = 0; i < 8; i++)
        {
            ks.Add(RandomBelow(r, N));
        }
        foreach (var k in ks)
        {
            Assert.True(Fq12.PowGt(g, Scalar(k)).Equals(Fq12.CyclotomicPowSecret(g, Scalar(k))));
        }
    }
}
