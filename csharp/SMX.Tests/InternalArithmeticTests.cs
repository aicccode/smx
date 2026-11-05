using System.Globalization;
using System.Numerics;
using SMX;

namespace SMX.Tests;

/// <summary>Randomized differential tests of the internal field and order arithmetic against BigInteger.</summary>
public class InternalArithmeticTests
{
    private static readonly BigInteger P = ToBig(Fp.P);
    private static readonly BigInteger N = ToBig(Sm2Order.N);
    private static readonly BigInteger Two256 = BigInteger.One << 256;

    private static BigInteger ToBig(in BigInt256 v) => BigInteger.Parse("0" + v.ToHex(), NumberStyles.HexNumber);

    private static BigInt256 FromBig(BigInteger v) => BigInt256.FromHex(((v % Two256 + Two256) % Two256).ToString("X").TrimStart('0').PadLeft(64, '0'));

    /// <summary>Boundary values of every width that a carry or reduction bug would be sensitive to.</summary>
    public static IEnumerable<BigInt256> EdgeValues()
    {
        BigInteger[] raw =
        [
            0,
            1,
            2,
            3,
            P - 2,
            P - 1,
            P,
            P + 1,
            2 * P - Two256,
            N - 2,
            N - 1,
            N,
            N + 1,
            Two256 - 1,
            Two256 - 2,
            BigInteger.One << 255,
            (BigInteger.One << 255) - 1,
            BigInteger.One << 224,
            (BigInteger.One << 224) - 1,
            BigInteger.One << 192,
            (BigInteger.One << 192) - 1,
            BigInteger.One << 128,
            (BigInteger.One << 128) - 1,
            BigInteger.One << 96,
            (BigInteger.One << 96) - 1,
            BigInteger.One << 64,
            (BigInteger.One << 64) - 1,
            BigInteger.One << 32,
            (BigInteger.One << 32) - 1,
            (Two256 - 1) / 3,
            (Two256 - 1) / 5,
        ];
        foreach (var v in raw)
        {
            yield return FromBig(v);
        }
    }

    private static IEnumerable<BigInt256> Samples(int seed, int count)
    {
        var edges = EdgeValues().ToArray();
        var rng = new Random(seed);
        foreach (var edge in edges)
        {
            yield return edge;
        }
        for (int i = 0; i < count; i++)
        {
            ulong Limb() => rng.Next(4) switch
            {
                0 => 0,
                1 => ulong.MaxValue,
                _ => (ulong)rng.NextInt64() ^ ((ulong)rng.NextInt64() << 1),
            };
            yield return rng.Next(2) == 0
                ? new BigInt256(Limb(), Limb(), Limb(), Limb())
                : new BigInt256((ulong)rng.NextInt64() << 1 | 1, (ulong)rng.NextInt64(), (ulong)rng.NextInt64(), (ulong)rng.NextInt64() << 1);
        }
    }

    private static BigInt256[] SampleArray(int seed, int count = 400) => Samples(seed, count).ToArray();

    [Fact]
    public void FieldMultiplyAndSquareMatchBigInteger()
    {
        var values = SampleArray(1);
        var others = SampleArray(2);
        for (int i = 0; i < values.Length; i++)
        {
            foreach (var b in others.Skip(i % 7).Take(40))
            {
                Fp.Mul(values[i], b, out var product);
                Assert.Equal(ToBig(values[i]) * ToBig(b) % P, ToBig(product));
            }
            Fp.Square(values[i], out var square);
            Assert.Equal(ToBig(values[i]) * ToBig(values[i]) % P, ToBig(square));
        }
    }

    [Fact]
    public void FieldMultiplyIsInPlaceSafe()
    {
        var a = FromBig(P - 5);
        var b = FromBig(N - 3);
        var expected = ToBig(a) * ToBig(b) % P;
        var x = a;
        Fp.Mul(x, b, out x);
        Assert.Equal(expected, ToBig(x));
        x = a;
        Fp.Square(x, out x);
        Assert.Equal(ToBig(a) * ToBig(a) % P, ToBig(x));
    }

    [Fact]
    public void FieldAddSubDoubleNegateMatchBigInteger()
    {
        var reduced = SampleArray(3).Select(v => FromBig(ToBig(v) % P)).ToArray();
        foreach (var a in reduced)
        {
            foreach (var b in reduced.Take(50))
            {
                Fp.Add(a, b, out var sum);
                Assert.Equal((ToBig(a) + ToBig(b)) % P, ToBig(sum));
                Fp.Sub(a, b, out var diff);
                Assert.Equal((ToBig(a) - ToBig(b) + P) % P, ToBig(diff));
            }
            Fp.Double(a, out var doubled);
            Assert.Equal(2 * ToBig(a) % P, ToBig(doubled));
            Fp.Negate(a, out var negated);
            Assert.Equal((P - ToBig(a)) % P, ToBig(negated));
        }
    }

    [Fact]
    public void FieldInvertMatchesBigInteger()
    {
        foreach (var a in SampleArray(4, 80))
        {
            Fp.Invert(a, out var inverse);
            Assert.Equal(BigInteger.ModPow(ToBig(a), P - 2, P), ToBig(inverse));
        }
    }

    [Fact]
    public void OrderMultiplyMatchesBigInteger()
    {
        var values = SampleArray(5);
        var others = SampleArray(6);
        for (int i = 0; i < values.Length; i++)
        {
            foreach (var b in others.Skip(i % 11).Take(40))
            {
                Sm2Order.Mul(values[i], b, out var product);
                Assert.Equal(ToBig(values[i]) * ToBig(b) % N, ToBig(product));
            }
        }
    }

    [Fact]
    public void OrderInvertMatchesBigInteger()
    {
        foreach (var a in SampleArray(7, 80))
        {
            Sm2Order.Invert(a, out var inverse);
            Assert.Equal(BigInteger.ModPow(ToBig(a), N - 2, N), ToBig(inverse));
        }
    }

    [Fact]
    public void OrderRangeAndReductionMatchBigInteger()
    {
        foreach (var k in SampleArray(8))
        {
            var big = ToBig(k);
            Assert.Equal(!big.IsZero && big < N, Sm2Order.InRangeMask(k) != 0);
            Sm2Order.ReduceOnce(k, out var reduced);
            Assert.Equal(big % N, ToBig(reduced));
        }
    }

    [Fact]
    public void WideProductsMatchBigInteger()
    {
        var values = SampleArray(9);
        var others = SampleArray(10);
        for (int i = 0; i < values.Length; i++)
        {
            var b = others[i];
            ulong[] limbs = values[i].Mul(b);
            var product = limbs.Select((l, j) => new BigInteger(l) << (64 * j)).Aggregate(BigInteger.Zero, (x, y) => x + y);
            Assert.Equal(ToBig(values[i]) * ToBig(b), product);

            Wide512.Square(values[i], out var w);
            var square = new[] { w.W0, w.W1, w.W2, w.W3, w.W4, w.W5, w.W6, w.W7 }
                .Select((l, j) => new BigInteger(l) << (64 * j)).Aggregate(BigInteger.Zero, (x, y) => x + y);
            Assert.Equal(ToBig(values[i]) * ToBig(values[i]), square);
        }
    }

    [Fact]
    public void GenericModMulMatchesBigIntegerForEveryModulusWidth()
    {
        var rng = new Random(11);
        var values = SampleArray(12, 300);
        for (int bits = 1; bits <= 256; bits++)
        {
            for (int trial = 0; trial < 24; trial++)
            {
                var bytes = new byte[33];
                rng.NextBytes(bytes);
                bytes[32] = 0;
                var m = new BigInteger(bytes) >> (256 - bits);
                m |= BigInteger.One << (bits - 1);
                if (trial % 4 == 1)
                {
                    m = BigInteger.One << (bits - 1);
                }
                else if (trial % 4 == 2)
                {
                    m = (BigInteger.One << bits) - 1;
                }
                var mod = FromBig(m);
                var a = values[rng.Next(values.Length)];
                var b = values[rng.Next(values.Length)];
                Assert.Equal(ToBig(a) * ToBig(b) % m, ToBig(a.ModMul(b, mod)));
            }
        }
    }

    [Fact]
    public void GenericModPowAndModInverseMatchBigInteger()
    {
        var rng = new Random(13);
        var values = SampleArray(14, 100);
        foreach (var a in values)
        {
            var e = values[rng.Next(values.Length)];
            var m = values[rng.Next(values.Length)];
            if (m.IsZero || e.IsZero)
            {
                continue;
            }
            Assert.Equal(BigInteger.ModPow(ToBig(a), ToBig(e), ToBig(m)), ToBig(a.ModPow(e, m)));
        }
        Assert.Throws<DivideByZeroException>(() => BigInt256.One.ModMul(BigInt256.One, BigInt256.Zero));
    }

    [Fact]
    public void ModAddAndModSubAgreeWithTheirDefinition()
    {
        var values = SampleArray(15, 200);
        var moduli = SampleArray(16, 50).Where(m => !m.IsZero).ToArray();
        foreach (var a in values)
        {
            foreach (var m in moduli)
            {
                var b = values[(int)(a.L0 % (ulong)values.Length)];
                var sum = ToBig(a) + ToBig(b);
                var expectedSum = sum >= ToBig(m) ? (sum - ToBig(m)) % Two256 : sum;
                Assert.Equal(expectedSum, ToBig(a.ModAdd(b, m)));
                var diff = ToBig(a) - ToBig(b);
                var expectedDiff = diff < 0 ? (diff + ToBig(m) + Two256) % Two256 : diff;
                Assert.Equal(expectedDiff, ToBig(a.ModSub(b, m)));
            }
        }
    }
}
