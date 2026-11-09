using System.Text;
using System.Text.Json;

namespace SMX.Tests.SM9;

/// <summary>Reproduces every vector of testvectors/sm9-vectors.json, in both directions where there are two.</summary>
public class Sm9VectorTests
{
    private static JsonElement ExtraCase(string kind, int index) => Sm9Vectors.Extra.GetProperty(kind)[index];

    [Fact]
    public void StandardSign()
    {
        var v = Sm9Vectors.Standard("sign");
        string mpk = v.Str("master_public_key");
        Assert.Equal(mpk, SMX.SM9.GetSignMasterPublicKey(v.Str("master_private_key")));
        string uid = v.Str("user_id");
        Assert.Equal(SMX.SM9.HidSign, v.Int("hid"));
        Assert.Equal(v.Str("user_private_key"), SMX.SM9.GenSignUserKey(v.Str("master_private_key"), uid, (byte)v.Int("hid")));
        var message = Encoding.UTF8.GetBytes(v.Str("message"));
        var sig = SMX.SM9.SignWithRandom(message, v.Str("user_private_key"), mpk, v.Str("r"));
        Assert.Equal(v.Str("signature"), sig);
        Assert.True(SMX.SM9.Verify(message, sig, uid, mpk));
        Assert.True(SMX.SM9.Verify(v.Str("message"), sig, uid, mpk));
    }

    [Theory]
    [MemberData(nameof(Sm9Vectors.Cases), "extra", "sign", MemberType = typeof(Sm9Vectors))]
    public void ExtraSign(int index)
    {
        var v = ExtraCase("sign", index);
        string msk = Sm9Vectors.Extra.Str("sign_master_private_key");
        string mpk = Sm9Vectors.Extra.Str("sign_master_public_key");
        Assert.Equal(mpk, SMX.SM9.GetSignMasterPublicKey(msk));
        Assert.Equal(v.Str("user_private_key"), SMX.SM9.GenSignUserKey(msk, v.Str("user_id")));
        var message = v.Hex("message_hex");
        var sig = SMX.SM9.SignWithRandom(message, v.Str("user_private_key"), mpk, v.Str("r"));
        Assert.Equal(v.Str("signature"), sig);
        Assert.True(SMX.SM9.Verify(message, sig, v.Str("user_id"), mpk));
    }

    [Fact]
    public void StandardEncapsulate()
    {
        var v = Sm9Vectors.Standard("encapsulate");
        CheckEncapsulation(v, v.Str("master_private_key"), v.Str("master_public_key"), (byte)v.Int("hid"));
    }

    [Theory]
    [MemberData(nameof(Sm9Vectors.Cases), "extra", "encapsulate", MemberType = typeof(Sm9Vectors))]
    public void ExtraEncapsulate(int index) => CheckEncapsulation(ExtraCase("encapsulate", index),
        Sm9Vectors.Extra.Str("enc_master_private_key"), Sm9Vectors.Extra.Str("enc_master_public_key"), SMX.SM9.HidEncrypt);

    private static void CheckEncapsulation(JsonElement v, string msk, string mpk, byte hid)
    {
        Assert.Equal(mpk, SMX.SM9.GetEncMasterPublicKey(msk));
        string uid = v.Str("user_id");
        Assert.Equal(v.Str("user_private_key"), SMX.SM9.GenEncUserKey(msk, uid, hid));
        var (key, ciphertext) = SMX.SM9.EncapsulateWithRandom(uid, mpk, v.Int("key_len"), v.Str("r"), hid);
        Assert.Equal(v.Str("key"), key);
        Assert.Equal(v.Str("ciphertext"), ciphertext);
        Assert.Equal(v.Str("key"), SMX.SM9.Decapsulate(ciphertext, uid, v.Str("user_private_key"), v.Int("key_len")));
    }

    [Fact]
    public void StandardEncrypt()
    {
        var v = Sm9Vectors.Standard("encrypt");
        CheckEncryption(v, v.Str("master_private_key"), v.Str("master_public_key"), Encoding.UTF8.GetBytes(v.Str("plaintext")), (byte)v.Int("hid"));
        Assert.Equal(v.Str("plaintext"), SMX.SM9.Decrypt(v.Str("ciphertext_stream"), v.Str("user_id"), v.Str("user_private_key")));
        Assert.Equal(v.Str("plaintext"), SMX.SM9.Decrypt(v.Str("ciphertext_sm4"), v.Str("user_id"), v.Str("user_private_key"), SMX.SM9EncryptMode.SM4));
    }

    [Theory]
    [MemberData(nameof(Sm9Vectors.Cases), "extra", "encrypt", MemberType = typeof(Sm9Vectors))]
    public void ExtraEncrypt(int index)
    {
        var v = ExtraCase("encrypt", index);
        CheckEncryption(v, Sm9Vectors.Extra.Str("enc_master_private_key"), Sm9Vectors.Extra.Str("enc_master_public_key"), v.Hex("plaintext_hex"), SMX.SM9.HidEncrypt);
    }

    private static void CheckEncryption(JsonElement v, string msk, string mpk, byte[] plaintext, byte hid)
    {
        string uid = v.Str("user_id");
        string de = v.Str("user_private_key");
        Assert.Equal(de, SMX.SM9.GenEncUserKey(msk, uid, hid));
        foreach (var (mode, name) in new[] { (SMX.SM9EncryptMode.Stream, "ciphertext_stream"), (SMX.SM9EncryptMode.SM4, "ciphertext_sm4") })
        {
            var ct = SMX.SM9.EncryptWithRandom(plaintext, uid, mpk, v.Str("r"), mode, hid);
            Assert.Equal(v.Str(name), ct);
            Assert.Equal(plaintext, SMX.SM9.DecryptToBytes(ct, uid, de, mode));
        }
    }

    [Fact]
    public void StandardExchange()
    {
        var v = Sm9Vectors.Standard("exchange");
        Assert.Equal(v.Str("master_public_key"), SMX.SM9.GetEncMasterPublicKey(v.Str("master_private_key")));
        CheckExchange(v, v.Str("master_private_key"), v.Str("master_public_key"), (byte)v.Int("hid"));
    }

    [Theory]
    [MemberData(nameof(Sm9Vectors.Cases), "extra", "exchange", MemberType = typeof(Sm9Vectors))]
    public void ExtraExchange(int index) => CheckExchange(ExtraCase("exchange", index),
        Sm9Vectors.Extra.Str("enc_master_private_key"), Sm9Vectors.Extra.Str("enc_master_public_key"), SMX.SM9.HidExchange);

    private static void CheckExchange(JsonElement v, string msk, string mpk, byte hid)
    {
        string idA = v.Str("id_a"), idB = v.Str("id_b");
        string deA = v.Str("user_private_key_a"), deB = v.Str("user_private_key_b");
        Assert.Equal(deA, SMX.SM9.GenEncUserKey(msk, idA, hid));
        Assert.Equal(deB, SMX.SM9.GenEncUserKey(msk, idB, hid));
        string ra = SMX.SM9.ExchangeInitWithRandom(idB, mpk, v.Str("r_a"), hid);
        string rb = SMX.SM9.ExchangeInitWithRandom(idA, mpk, v.Str("r_b"), hid);
        Assert.Equal(v.Str("R_a"), ra);
        Assert.Equal(v.Str("R_b"), rb);

        int klen = v.Int("key_len");
        var b = SMX.SM9.ExchangeRespond(klen, idA, idB, mpk, deB, v.Str("r_b"), rb, ra);
        Assert.True(b.Success, b.Message);
        Assert.Equal(v.Str("shared_key"), b.SharedKey);
        Assert.Equal(v.Str("s_b"), b.Sb);
        Assert.Equal(v.Str("s_a"), b.S2);

        var a = SMX.SM9.ExchangeConfirm(klen, idA, idB, mpk, deA, v.Str("r_a"), ra, rb, b.Sb);
        Assert.True(a.Success, a.Message);
        Assert.Equal(v.Str("shared_key"), a.SharedKey);
        Assert.Equal(v.Str("s_a"), a.Sa);
        Assert.True(SMX.SM9.ExchangeCheck(b.S2, a.Sa));
    }

    [Fact]
    public void MaxValidMasterKeyIsAccepted()
    {
        string max = Sm9Vectors.Json.Str("max_valid_master_private_key");
        Assert.Equal(130, SMX.SM9.GetEncMasterPublicKey(max).Length);
        Assert.Equal(258, SMX.SM9.GetSignMasterPublicKey(max).Length);
        Assert.Equal(130, SMX.SM9.GenSignUserKey(max, "id").Length);
    }
}
