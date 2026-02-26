using SMX;

namespace SMX.Tests;

public class BigInt256Tests
{
    [Fact]
    public void FromHexRoundTrip()
    {
        var n = BigInt256.FromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
        Assert.Equal("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", n.ToHex());
    }

    [Fact]
    public void Add()
    {
        var a = BigInt256.FromHex("1");
        var b = BigInt256.FromHex("2");
        var c = a.Add(b, out _);
        Assert.Equal("0000000000000000000000000000000000000000000000000000000000000003", c.ToHex());
    }

    [Fact]
    public void Sub()
    {
        var a = BigInt256.FromHex("5");
        var b = BigInt256.FromHex("3");
        var c = a.Sub(b, out _);
        Assert.Equal("0000000000000000000000000000000000000000000000000000000000000002", c.ToHex());
    }

    [Fact]
    public void Mul()
    {
        var a = BigInt256.FromHex("3");
        var b = BigInt256.FromHex("4");
        var p = BigInt256.FromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
        var c = a.ModMul(b, p);
        Assert.Equal("000000000000000000000000000000000000000000000000000000000000000C", c.ToHex());
    }

    [Fact]
    public void ModInverse()
    {
        var a = BigInt256.FromHex("3");
        var p = BigInt256.FromHex("7");
        var inv = a.ModInverse(p);
        var product = a.ModMul(inv, p);
        Assert.True(product.IsOne);
    }
}
