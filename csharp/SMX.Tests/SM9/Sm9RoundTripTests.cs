using Api = SMX.SM9;
using Mode = SMX.SM9EncryptMode;

namespace SMX.Tests.SM9;

/// <summary>Random keys and messages: round trips, tampering, and every kind of mismatch.</summary>
public class Sm9RoundTripTests
{
    private static readonly (string Msk, string Mpk) SignMaster = Api.GenSignMasterKey();
    private static readonly (string Msk, string Mpk) EncMaster = Api.GenEncMasterKey();

    private static string Flip(string hex, int index)
    {
        var chars = hex.ToCharArray();
        chars[index] = chars[index] == '0' ? '1' : '0';
        return new string(chars);
    }

    [Fact]
    public void MasterKeysMatchTheirPublicKeys()
    {
        Assert.Equal(SignMaster.Mpk, Api.GetSignMasterPublicKey(SignMaster.Msk));
        Assert.Equal(EncMaster.Mpk, Api.GetEncMasterPublicKey(EncMaster.Msk));
        Assert.Equal(64, SignMaster.Msk.Length);
        Assert.Equal(258, SignMaster.Mpk.Length);
        Assert.Equal(130, EncMaster.Mpk.Length);
        Assert.NotEqual(Api.GenSignMasterKey().masterPrivateKey, Api.GenSignMasterKey().masterPrivateKey);
    }

    [Theory]
    [InlineData("")]
    [InlineData("alice@example.com")]
    [InlineData("张三")]
    public void SignVerifyRoundTripAndTampering(string id)
    {
        string ds = Api.GenSignUserKey(SignMaster.Msk, id);
        var random = new Random(id.Length);
        foreach (int length in new[] { 0, 1, 100, 1000 })
        {
            var message = new byte[length];
            random.NextBytes(message);
            string sig = Api.Sign(message, ds, SignMaster.Mpk);
            Assert.Equal(194, sig.Length);
            Assert.True(Api.Verify(message, sig, id, SignMaster.Mpk));
            Assert.NotEqual(sig, Api.Sign(message, ds, SignMaster.Mpk));

            // Tampered h, tampered S (off the curve or another point), tampered message.
            Assert.False(Api.Verify(message, Flip(sig, 10), id, SignMaster.Mpk));
            Assert.False(Api.Verify(message, Flip(sig, 100), id, SignMaster.Mpk));
            Assert.False(Api.Verify(message, Flip(sig, 193), id, SignMaster.Mpk));
            var altered = (byte[])message.Clone();
            if (length > 0)
            {
                altered[length / 2] ^= 1;
                Assert.False(Api.Verify(altered, sig, id, SignMaster.Mpk));
            }
            Assert.False(Api.Verify([.. message, 0], sig, id, SignMaster.Mpk));

            // Wrong ID, hid or master key.
            Assert.False(Api.Verify(message, sig, id + "x", SignMaster.Mpk));
            Assert.False(Api.Verify(message, sig, id, SignMaster.Mpk, Api.HidExchange));
            Assert.False(Api.Verify(message, sig, id, Api.GenSignMasterKey().masterPublicKey));
        }
        Assert.True(Api.Verify("text", Api.Sign("text", ds, SignMaster.Mpk), id, SignMaster.Mpk));
    }

    [Fact]
    public void SignatureFromAnotherUsersKeyDoesNotVerify()
    {
        string other = Api.GenSignUserKey(SignMaster.Msk, "mallory");
        string sig = Api.Sign("m", other, SignMaster.Mpk);
        Assert.False(Api.Verify("m", sig, "alice", SignMaster.Mpk));
        Assert.True(Api.Verify("m", sig, "mallory", SignMaster.Mpk));
    }

    [Theory]
    [InlineData(Mode.Stream)]
    [InlineData(Mode.SM4)]
    public void EncryptDecryptRoundTripAndTampering(Mode mode)
    {
        string id = "bob@example.com";
        string de = Api.GenEncUserKey(EncMaster.Msk, id);
        var random = new Random((int)mode);
        foreach (int length in new[] { 1, 15, 16, 17, 32, 1000 })
        {
            var message = new byte[length];
            random.NextBytes(message);
            string c = Api.Encrypt(message, id, EncMaster.Mpk, mode: mode);
            int c2Length = mode == Mode.SM4 ? (length / 16 + 1) * 16 : length;
            Assert.Equal(2 * (97 + c2Length), c.Length);
            Assert.Equal(message, Api.DecryptToBytes(c, id, de, mode));

            // Tampering anywhere in C1, C3 or C2 gives the same failure.
            foreach (int at in new[] { 3, 70, 129, 131, 193, 195, c.Length - 1 })
            {
                var ex = Assert.Throws<InvalidOperationException>(() => Api.DecryptToBytes(Flip(c, at), id, de, mode));
                Assert.Equal("decryption failed", ex.Message);
            }
            Assert.Throws<InvalidOperationException>(() => Api.DecryptToBytes(c, id + "x", de, mode));
            Assert.Throws<InvalidOperationException>(() => Api.DecryptToBytes(c, id, Api.GenEncUserKey(EncMaster.Msk, "carol"), mode));
            var otherMode = mode == Mode.SM4 ? Mode.Stream : Mode.SM4;
            if (c2Length == 16)
            {
                // With a 16-byte C2 both modes derive the same 48 KDF bytes, so C3 verifies in the other mode too (the
                // ciphertext does not record the mode); the result is just not the plaintext.
                Assert.NotEqual(message, Record.Exception(() => Api.DecryptToBytes(c, id, de, otherMode)) is null
                    ? Api.DecryptToBytes(c, id, de, otherMode) : null);
            }
            else
            {
                Assert.Throws<InvalidOperationException>(() => Api.DecryptToBytes(c, id, de, otherMode));
            }
        }
        Assert.Equal("你好, SM9", Api.Decrypt(Api.Encrypt("你好, SM9", id, EncMaster.Mpk, mode: mode), id, de, mode));
    }

    [Fact]
    public void DecryptRejectsInvalidUtf8AsTextButNotAsBytes()
    {
        string de = Api.GenEncUserKey(EncMaster.Msk, "bob");
        string c = Api.Encrypt([0xFF, 0xFE], "bob", EncMaster.Mpk);
        Assert.Equal(new byte[] { 0xFF, 0xFE }, Api.DecryptToBytes(c, "bob", de));
        Assert.Throws<InvalidOperationException>(() => Api.Decrypt(c, "bob", de));
    }

    [Fact]
    public void EncryptionWithAnotherHidNeedsTheMatchingKey()
    {
        string de = Api.GenEncUserKey(EncMaster.Msk, "bob", 0x7F);
        string c = Api.Encrypt("m", "bob", EncMaster.Mpk, 0x7F);
        Assert.Equal("m", Api.Decrypt(c, "bob", de));
        Assert.Throws<InvalidOperationException>(() => Api.Decrypt(c, "bob", Api.GenEncUserKey(EncMaster.Msk, "bob")));
    }

    [Fact]
    public void EncapsulationRoundTrip()
    {
        string de = Api.GenEncUserKey(EncMaster.Msk, "bob");
        foreach (int length in new[] { 1, 16, 32, 33, 1000 })
        {
            var (key, c) = Api.Encapsulate("bob", EncMaster.Mpk, length);
            Assert.Equal(2 * length, key.Length);
            Assert.Equal(key, Api.Decapsulate(c, "bob", de, length));
            Assert.NotEqual(key, Api.Decapsulate(c, "carol", de, length));
            Assert.NotEqual(key, Api.Decapsulate(c, "bob", Api.GenEncUserKey(EncMaster.Msk, "carol"), length));
            Assert.Throws<InvalidOperationException>(() => Api.Decapsulate(Flip(c, 100), "bob", de, length));
        }
    }

    [Fact]
    public void KeyExchangeRoundTrip()
    {
        string idA = "alice", idB = "bob";
        string deA = Api.GenEncUserKey(EncMaster.Msk, idA, Api.HidExchange);
        string deB = Api.GenEncUserKey(EncMaster.Msk, idB, Api.HidExchange);
        foreach (int klen in new[] { 1, 16, 100 })
        {
            var (ra, RA) = Api.ExchangeInit(idB, EncMaster.Mpk);
            var (rb, RB) = Api.ExchangeInit(idA, EncMaster.Mpk);
            var b = Api.ExchangeRespond(klen, idA, idB, EncMaster.Mpk, deB, rb, RB, RA);
            Assert.True(b.Success, b.Message);
            var a = Api.ExchangeConfirm(klen, idA, idB, EncMaster.Mpk, deA, ra, RA, RB, b.Sb);
            Assert.True(a.Success, a.Message);
            Assert.Equal(2 * klen, a.SharedKey.Length);
            Assert.Equal(a.SharedKey, b.SharedKey);
            Assert.True(Api.ExchangeCheck(b.S2, a.Sa));
            Assert.False(Api.ExchangeCheck(b.S2, b.Sb));
            Assert.False(Api.ExchangeCheck(b.S2, Flip(a.Sa, 5)));
            Assert.False(Api.ExchangeCheck(null!, a.Sa));
            Assert.False(Api.ExchangeCheck(b.S2, a.Sa[..62]));
        }
    }

    [Fact]
    public void KeyExchangeMismatchesAreDetected()
    {
        string idA = "alice", idB = "bob";
        string deA = Api.GenEncUserKey(EncMaster.Msk, idA, Api.HidExchange);
        string deB = Api.GenEncUserKey(EncMaster.Msk, idB, Api.HidExchange);
        var (ra, RA) = Api.ExchangeInit(idB, EncMaster.Mpk);
        var (rb, RB) = Api.ExchangeInit(idA, EncMaster.Mpk);
        var b = Api.ExchangeRespond(16, idA, idB, EncMaster.Mpk, deB, rb, RB, RA);
        Assert.True(b.Success);

        // A tampered or misdirected S_B, another responder, another key length for the confirmation key alike.
        var bad = Api.ExchangeConfirm(16, idA, idB, EncMaster.Mpk, deA, ra, RA, RB, Flip(b.Sb, 0));
        Assert.False(bad.Success);
        Assert.Equal("", bad.SharedKey);
        Assert.Equal("", bad.Sa);
        Assert.False(Api.ExchangeConfirm(16, idA, "carol", EncMaster.Mpk, deA, ra, RA, RB, b.Sb).Success);
        Assert.False(Api.ExchangeConfirm(16, idA, idB, EncMaster.Mpk, Api.GenEncUserKey(EncMaster.Msk, "eve", Api.HidExchange), ra, RA, RB, b.Sb).Success);
        Assert.False(Api.ExchangeConfirm(16, idA, idB, EncMaster.Mpk, deA, ra, RA, RB, null!).Success);
        Assert.False(Api.ExchangeConfirm(16, idA, idB, EncMaster.Mpk, deA, ra, RA, RB, b.Sb[..10]).Success);

        // A responder with the wrong key reaches a different key, so A rejects its S_B.
        var wrongB = Api.ExchangeRespond(16, idA, idB, EncMaster.Mpk, Api.GenEncUserKey(EncMaster.Msk, "eve", Api.HidExchange), rb, RB, RA);
        Assert.True(wrongB.Success);
        Assert.NotEqual(b.SharedKey, wrongB.SharedKey);
        Assert.False(Api.ExchangeConfirm(16, idA, idB, EncMaster.Mpk, deA, ra, RA, RB, wrongB.Sb).Success);

        // An attacker replacing R_A: B's key differs, and A's S_A does not match B's S_2.
        var (_, otherRA) = Api.ExchangeInit(idB, EncMaster.Mpk);
        var b2 = Api.ExchangeRespond(16, idA, idB, EncMaster.Mpk, deB, rb, RB, otherRA);
        Assert.True(b2.Success);
        Assert.False(Api.ExchangeConfirm(16, idA, idB, EncMaster.Mpk, deA, ra, RA, RB, b2.Sb).Success);

        foreach (int klen in new[] { 0, -1, 1024 * 1024 + 1 })
        {
            var r = Api.ExchangeRespond(klen, idA, idB, EncMaster.Mpk, deB, rb, RB, RA);
            Assert.False(r.Success);
            Assert.Equal("invalid key length", r.Message);
        }
        Assert.False(Api.ExchangeRespond(16, "a\uD800", idB, EncMaster.Mpk, deB, rb, RB, RA).Success);
        Assert.False(Api.ExchangeRespond(16, idA, idB, null!, deB, rb, RB, RA).Success);
        Assert.False(Api.ExchangeRespond(16, idA, idB, EncMaster.Mpk, null!, rb, RB, RA).Success);
    }
}
