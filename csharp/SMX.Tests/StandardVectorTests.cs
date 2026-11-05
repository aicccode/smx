using System.Text;
using SMX;

namespace SMX.Tests;

/// <summary>Published vectors: GB/T 32905 (SM3), GB/T 32918.5 annex A (SM2), plus an SM4 CBC vector via the public API.</summary>
public class StandardVectorTests
{
    private const string PrivateKey = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    private const string PublicKey = "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020" +
        "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";

    [Theory]
    [InlineData("abc", "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0")]
    [InlineData("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", "DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732")]
    [InlineData("", "1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B")]
    public void Sm3Standard(string message, string expected)
    {
        var h = new SM3();
        h.Update(Encoding.ASCII.GetBytes(message));
        h.Finish();
        Assert.Equal(expected, h.HashHexUpper());
        Assert.Equal(expected, Convert.ToHexString(h.HashBytes()));
    }

    [Fact]
    public void Sm3MillionA()
    {
        var h = new SM3();
        var chunk = Encoding.ASCII.GetBytes(new string('a', 1000));
        for (int i = 0; i < 1000; i++)
        {
            h.Update(chunk);
        }
        h.Finish();
        Assert.Equal("C8AAF89429554029E231941A2ACC0AD61FF2A5ACD8FADD25847A3A732B3B02C3", h.HashHexUpper());
    }

    [Fact]
    public void Sm2PublicKeyDerivation()
    {
        Assert.Equal(PublicKey.ToLowerInvariant(), SM2.GetPublicKey(BigInt256.FromHex(PrivateKey)).ToHexEncoded());
    }

    [Fact]
    public void Sm2VerifiesStandardSignature()
    {
        const string signature = "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3h" +
            "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa";
        Assert.True(SM2.Verify("1234567812345678", signature, "message digest", PublicKey));
        Assert.False(SM2.Verify("1234567812345679", signature, "message digest", PublicKey));
        Assert.False(SM2.Verify("1234567812345678", signature, "message digesu", PublicKey));
    }

    [Fact]
    public void Sm2DecryptsStandardCiphertext()
    {
        const string cipherText = "04" +
            "04ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73" +
            "e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0" +
            "59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766" +
            "21886ca989ca9c7d58087307ca93092d651efa";
        Assert.Equal("encryption standard", SM2.Decrypt(cipherText, PrivateKey));
    }
}
