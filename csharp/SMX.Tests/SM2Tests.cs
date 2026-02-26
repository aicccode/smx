using SMX;

namespace SMX.Tests;

public class SM2Tests
{
    [Fact]
    public void KeyPairGeneration()
    {
        var (pri, pub) = SM2.GenKeyPair();
        Assert.Equal(64, pri.Length);
        Assert.Equal(130, pub.Length);
        Assert.StartsWith("04", pub);
    }

    [Fact]
    public void EncryptDecrypt()
    {
        var (pri, pub) = SM2.GenKeyPair();
        string message = "encryption standard";

        string encrypted = SM2.Encrypt(message, pub);
        string decrypted = SM2.Decrypt(encrypted, pri);

        Assert.Equal(message, decrypted);
    }

    [Fact]
    public void SignVerify()
    {
        var (pri, pub) = SM2.GenKeyPair();
        string userID = "ALICE123@YAHOO.COM";
        string message = "encryption standard";

        string signature = SM2.Sign(userID, message, pri);
        Assert.True(SM2.Verify(userID, signature, message, pub));
    }

    [Fact]
    public void SignVerifyWrongMessage()
    {
        var (pri, pub) = SM2.GenKeyPair();
        string userID = "ALICE123@YAHOO.COM";
        string message = "encryption standard";

        string signature = SM2.Sign(userID, message, pri);
        Assert.False(SM2.Verify(userID, signature, "wrong message", pub));
    }

    [Fact]
    public void KeyExchange()
    {
        string idA = "ALICE123@YAHOO.COM";
        string idB = "BILL456@YAHOO.COM";

        var dA = BigInt256.FromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE");
        var pA = SM2.GetPublicKey(dA);

        var ra = BigInt256.FromHex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
        var rA = SM2.GetPublicKey(ra);

        var dB = BigInt256.FromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53");
        var pB = SM2.GetPublicKey(dB);

        var rb = BigInt256.FromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
        var rB = SM2.GetPublicKey(rb);

        var resultB = SM2.GetSb(16, pA, rA, pB, dB, rB, rb, idA, idB);
        Assert.True(resultB.Success, resultB.Message);

        var sbBytes = HexUtils.HexToBytes(resultB.Sb);
        var resultA = SM2.GetSa(16, pB, rB, pA, dA, rA, ra, idA, idB, sbBytes);
        Assert.True(resultA.Success, resultA.Message);

        Assert.Equal(resultA.Ka, resultB.Kb);

        var saBytes = HexUtils.HexToBytes(resultA.Sa);
        Assert.True(SM2.CheckSa(resultB.V, resultB.Za, resultB.Zb, rA, rB, saBytes));
    }

    [Fact]
    public void UserSM3Z()
    {
        var (_, pub) = SM2.GenKeyPair();
        var point = SM2.DecodePoint(pub);
        // We can't directly call the private method, but we can verify via Sign/Verify
        // which uses it internally. This test just ensures no crash.
        Assert.True(point.IsOnCurve());
    }
}
