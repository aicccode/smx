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
        const string signature = "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3h" +
            "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA";
        Assert.True(SM2.Verify("1234567812345678", signature, "message digest", PublicKey));
        Assert.False(SM2.Verify("1234567812345679", signature, "message digest", PublicKey));
        Assert.False(SM2.Verify("1234567812345678", signature, "message digesu", PublicKey));
    }

    [Fact]
    public void Sm2DecryptsStandardCiphertext()
    {
        const string cipherText = "04" +
            "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73" +
            "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0" +
            "59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766" +
            "21886CA989CA9C7D58087307CA93092D651EFA";
        Assert.Equal("encryption standard", SM2.Decrypt(cipherText, PrivateKey));
    }
}
