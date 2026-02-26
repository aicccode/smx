using SMX;

namespace SMX.Tests;

public class PointTests
{
    [Fact]
    public void GeneratorOnCurve()
    {
        var g = ECPoint.Generator();
        Assert.True(g.IsOnCurve());
    }

    [Fact]
    public void PointAdd()
    {
        var g = ECPoint.Generator();
        var g2 = g.Add(g);
        Assert.True(g2.IsOnCurve());
        var g3 = g2.Add(g);
        Assert.True(g3.IsOnCurve());
    }

    [Fact]
    public void PointTwice()
    {
        var g = ECPoint.Generator();
        var g2a = g.Twice();
        var g2b = g.Add(g);
        Assert.True(g2a.Equal(g2b));
    }

    [Fact]
    public void PointMultiply()
    {
        var g = ECPoint.Generator();
        var k = BigInt256.FromHex("3");
        var p = g.Multiply(k);
        Assert.True(p.IsOnCurve());

        var g2 = g.Twice();
        var g3 = g2.Add(g);
        Assert.True(p.Equal(g3));
    }

    [Fact]
    public void EncodeDecode()
    {
        var g = ECPoint.Generator();
        var encoded = g.ToEncoded();
        var decoded = ECPoint.FromEncoded(encoded);
        Assert.True(g.Equal(decoded));
    }

    [Fact]
    public void Infinity()
    {
        var g = ECPoint.Generator();
        var negG = g.Negate();
        var result = g.Add(negG);
        Assert.True(result.Infinity);
    }
}
