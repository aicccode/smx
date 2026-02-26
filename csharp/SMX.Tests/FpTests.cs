using SMX;

namespace SMX.Tests;

public class FpTests
{
    [Fact]
    public void Add()
    {
        var a = FpElement.FromHex("1");
        var b = FpElement.FromHex("2");
        var c = a.Add(b);
        Assert.Equal(BigInt256.FromHex("3"), c.Value);
    }

    [Fact]
    public void Sub()
    {
        var a = FpElement.FromHex("5");
        var b = FpElement.FromHex("3");
        var c = a.Sub(b);
        Assert.Equal(BigInt256.FromHex("2"), c.Value);
    }

    [Fact]
    public void Mul()
    {
        var a = FpElement.FromHex("3");
        var b = FpElement.FromHex("4");
        var c = a.Mul(b);
        Assert.Equal(BigInt256.FromHex("C"), c.Value);
    }

    [Fact]
    public void Invert()
    {
        var a = FpElement.FromHex("3");
        var inv = a.Invert();
        var product = a.Mul(inv);
        Assert.True(product.IsOne);
    }

    [Fact]
    public void Negate()
    {
        var a = FpElement.FromHex("1");
        var neg = a.Negate();
        var sum = a.Add(neg);
        Assert.True(sum.IsZero);
    }
}
