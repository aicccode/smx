using System.Security.Cryptography;
using System.Text.Json;
using SMX.SM9Internal;
using Api = SMX.SM9;
using Mode = SMX.SM9EncryptMode;

namespace SMX.Tests.SM9;

/// <summary>Every invalid point, scalar and encoding is rejected, through every entry point that takes it.</summary>
public class Sm9ValidationTests
{
    private static readonly JsonElement Std = Sm9Vectors.Standard("sign");
    private static readonly JsonElement Enc = Sm9Vectors.Standard("encrypt");
    private static readonly JsonElement Kx = Sm9Vectors.Standard("exchange");
    private static readonly byte[] Message = "message"u8.ToArray();

    public static IEnumerable<object[]> InvalidG1() => Points("g1");

    public static IEnumerable<object[]> InvalidG2() => Points("g2");

    public static IEnumerable<object[]> InvalidScalars()
    {
        foreach (var e in Sm9Vectors.Json.GetProperty("invalid_scalars").EnumerateArray())
        {
            yield return [e.Str("name"), e.Str("value")];
        }
    }

    private static IEnumerable<object[]> Points(string group)
    {
        foreach (var e in Sm9Vectors.Json.GetProperty("invalid_points").GetProperty(group).EnumerateArray())
        {
            yield return [e.Str("name"), e.Str("value")];
        }
    }

    private static void Rejected(Action action)
    {
        var ex = Record.Exception(action);
        Assert.NotNull(ex);
        Assert.True(ex is ArgumentException or InvalidOperationException, ex.GetType().Name);
    }

    [Theory]
    [MemberData(nameof(InvalidG1))]
    public void InvalidG1PointsAreRejected(string name, string value)
    {
        _ = name;
        Assert.False(G1Affine.TryParseHex(value, out _));

        // As an encryption master public key.
        Assert.Throws<ArgumentException>(() => Api.Encrypt(Message, "Bob", value));
        Assert.Throws<ArgumentException>(() => Api.Encapsulate("Bob", value, 16));
        Assert.Throws<ArgumentException>(() => Api.ExchangeInit("Bob", value));
        Assert.False(Api.ExchangeRespond(16, "Alice", "Bob", value, Kx.Str("user_private_key_b"), Kx.Str("r_b"), Kx.Str("R_b"), Kx.Str("R_a")).Success);

        // As a signing user private key.
        Assert.Throws<ArgumentException>(() => Api.Sign(Message, value, Std.Str("master_public_key")));

        // As a KEM ciphertext, a C1, a signature's S and an exchange R.
        Rejected(() => Api.Decapsulate(value, "Bob", Enc.Str("user_private_key"), 32));
        string c = Enc.Str("ciphertext_stream");
        if (value.Length == 130)
        {
            Rejected(() => Api.DecryptToBytes(value + c[130..], "Bob", Enc.Str("user_private_key")));
        }
        string sig = Std.Str("signature");
        Assert.False(Api.Verify(Std.Str("message"), sig[..64] + value, "Alice", Std.Str("master_public_key")));
        var b = Api.ExchangeRespond(16, "Alice", "Bob", Kx.Str("master_public_key"), Kx.Str("user_private_key_b"), Kx.Str("r_b"), Kx.Str("R_b"), value);
        Assert.False(b.Success);
        var a = Api.ExchangeConfirm(16, "Alice", "Bob", Kx.Str("master_public_key"), Kx.Str("user_private_key_a"), Kx.Str("r_a"), Kx.Str("R_a"), value, Kx.Str("s_b"));
        Assert.False(a.Success);
        Assert.Equal("", a.SharedKey);
    }

    [Theory]
    [MemberData(nameof(InvalidG2))]
    public void InvalidG2PointsAreRejected(string name, string value)
    {
        Assert.False(G2Affine.TryParseHex(value, out _));

        // As a signing master public key.
        Assert.Throws<ArgumentException>(() => Api.Sign(Message, Std.Str("user_private_key"), value));
        Assert.False(Api.Verify(Std.Str("message"), Std.Str("signature"), "Alice", value));

        // As an encryption user private key.
        Rejected(() => Api.DecryptToBytes(Enc.Str("ciphertext_stream"), "Bob", value));
        Assert.Throws<ArgumentException>(() => Api.Decapsulate(Sm9Vectors.Standard("encapsulate").Str("ciphertext"), "Bob", value, 32));
        Assert.False(Api.ExchangeRespond(16, "Alice", "Bob", Kx.Str("master_public_key"), value, Kx.Str("r_b"), Kx.Str("R_b"), Kx.Str("R_a")).Success);
        Assert.False(Api.ExchangeConfirm(16, "Alice", "Bob", Kx.Str("master_public_key"), value, Kx.Str("r_a"), Kx.Str("R_a"), Kx.Str("R_b"), Kx.Str("s_b")).Success);

        if (name == "not_in_subgroup")
        {
            // The point is on the twist, so only the subgroup check stops it.
            var bytes = Convert.FromHexString(value);
            Assert.True(Fq2.TryRead(bytes.AsSpan(1, 64), out var x) & Fq2.TryRead(bytes.AsSpan(65, 64), out var y));
            Assert.True(Curve<Fq2>.IsOnCurve(x, y));
            Assert.False(G2Affine.IsInSubgroup(new G2Affine(x, y, false)));
        }
    }

    [Theory]
    [MemberData(nameof(InvalidScalars))]
    public void InvalidScalarsAreRejected(string name, string value)
    {
        _ = name;
        Assert.Throws<ArgumentException>(() => Api.GetSignMasterPublicKey(value));
        Assert.Throws<ArgumentException>(() => Api.GetEncMasterPublicKey(value));
        Assert.Throws<ArgumentException>(() => Api.GenSignUserKey(value, "Alice"));
        Assert.Throws<ArgumentException>(() => Api.GenEncUserKey(value, "Bob"));
        var b = Api.ExchangeRespond(16, "Alice", "Bob", Kx.Str("master_public_key"), Kx.Str("user_private_key_b"), value, Kx.Str("R_b"), Kx.Str("R_a"));
        Assert.False(b.Success);
        var a = Api.ExchangeConfirm(16, "Alice", "Bob", Kx.Str("master_public_key"), Kx.Str("user_private_key_a"), value, Kx.Str("R_a"), Kx.Str("R_b"), Kx.Str("s_b"));
        Assert.False(a.Success);
    }

    [Fact]
    public void SignatureScalarHOutOfRangeIsRejected()
    {
        string sig = Std.Str("signature");
        string n = "b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25";
        Assert.False(Api.Verify(Std.Str("message"), new string('0', 64) + sig[64..], "Alice", Std.Str("master_public_key")));
        Assert.False(Api.Verify(Std.Str("message"), n + sig[64..], "Alice", Std.Str("master_public_key")));
    }

    [Fact]
    public void KeysAcceptEitherCaseButSignaturesAndCiphertextsOnlyLowercase()
    {
        string mpk = Std.Str("master_public_key");
        string msk = Std.Str("master_private_key");
        Assert.Equal(mpk, Api.GetSignMasterPublicKey(msk.ToUpperInvariant()));
        Assert.Equal(Std.Str("user_private_key"), Api.GenSignUserKey(msk.ToUpperInvariant(), "Alice"));
        var message = System.Text.Encoding.UTF8.GetBytes(Std.Str("message"));
        Assert.Equal(Std.Str("signature"), Api.SignWithRandom(message, Std.Str("user_private_key").ToUpperInvariant(), mpk.ToUpperInvariant(), Std.Str("r")));
        Assert.True(Api.Verify(message, Std.Str("signature"), "Alice", mpk.ToUpperInvariant()));
        Assert.False(Api.Verify(message, Std.Str("signature").ToUpperInvariant(), "Alice", mpk));

        string de = Enc.Str("user_private_key");
        Assert.Equal(Enc.Str("plaintext"), Api.Decrypt(Enc.Str("ciphertext_stream"), "Bob", de.ToUpperInvariant()));
        Assert.Throws<ArgumentException>(() => Api.Decrypt(Enc.Str("ciphertext_stream").ToUpperInvariant(), "Bob", de));
        var kem = Sm9Vectors.Standard("encapsulate");
        Assert.Throws<ArgumentException>(() => Api.Decapsulate(kem.Str("ciphertext").ToUpperInvariant(), "Bob", de, 32));
        Assert.Equal(kem.Str("key"), Api.Decapsulate(kem.Str("ciphertext"), "Bob", de.ToUpperInvariant(), 32));

        var a = Api.ExchangeConfirm(16, "Alice", "Bob", Kx.Str("master_public_key"), Kx.Str("user_private_key_a"), Kx.Str("r_a"), Kx.Str("R_a"), Kx.Str("R_b"), Kx.Str("s_b").ToUpperInvariant());
        Assert.False(a.Success);
        Assert.False(Api.ExchangeCheck(Kx.Str("s_a"), Kx.Str("s_a").ToUpperInvariant()));
        Assert.True(Api.ExchangeCheck(Kx.Str("s_a"), Kx.Str("s_a")));
    }

    [Fact]
    public void MalformedCiphertextsAreRejected()
    {
        string de = Enc.Str("user_private_key");
        string c = Enc.Str("ciphertext_stream");
        Assert.Throws<ArgumentException>(() => Api.DecryptToBytes(c[..194], "Bob", de));
        Assert.Throws<ArgumentException>(() => Api.DecryptToBytes(c[..^1], "Bob", de));
        Assert.Throws<ArgumentException>(() => Api.DecryptToBytes(c[..^2] + "zz", "Bob", de));
        Assert.Throws<ArgumentException>(() => Api.DecryptToBytes(c, "Bob", de, (Mode)7));
        Assert.Throws<ArgumentNullException>(() => Api.DecryptToBytes(null!, "Bob", de));
        Assert.Throws<ArgumentNullException>(() => Api.DecryptToBytes(c, null!, de));
        Assert.Throws<ArgumentException>(() => Api.DecryptToBytes(c, "a\uD800", de));
        Assert.Throws<ArgumentException>(() => Api.Decapsulate(c[..130], "Bob", de, 0));
        Assert.Throws<ArgumentException>(() => Api.Decapsulate(c[..130], "Bob", de, 1024 * 1024 + 1));
    }

    [Fact]
    public void InvalidArgumentsToEncryptionAreRejected()
    {
        string mpk = Enc.Str("master_public_key");
        Assert.Throws<ArgumentException>(() => Api.Encrypt(Array.Empty<byte>(), "Bob", mpk));
        Assert.Throws<ArgumentException>(() => Api.Encrypt("", "Bob", mpk, mode: Mode.SM4));
        Assert.Throws<ArgumentException>(() => Api.Encrypt("a\uD800", "Bob", mpk));
        Assert.Throws<ArgumentException>(() => Api.Encrypt(Message, "a\uDC00", mpk));
        Assert.Throws<ArgumentException>(() => Api.Encrypt(Message, "Bob", mpk, mode: (Mode)2));
        Assert.Throws<ArgumentNullException>(() => Api.Encrypt((byte[])null!, "Bob", mpk));
        Assert.Throws<ArgumentNullException>(() => Api.Encrypt(Message, "Bob", null!));
        Assert.Throws<ArgumentException>(() => Api.Encapsulate("Bob", mpk, 0));
        Assert.Throws<ArgumentException>(() => Api.Encapsulate("Bob", mpk, 1024 * 1024 + 1));
        Assert.Throws<ArgumentException>(() => Api.Encapsulate("Bob", mpk.ToUpperInvariant()[..^2], 16));
    }

    [Fact]
    public void VerifyNeverThrows()
    {
        string mpk = Std.Str("master_public_key");
        string sig = Std.Str("signature");
        Assert.False(Api.Verify((byte[])null!, sig, "Alice", mpk));
        Assert.False(Api.Verify((string)null!, sig, "Alice", mpk));
        Assert.False(Api.Verify(Message, null!, "Alice", mpk));
        Assert.False(Api.Verify(Message, sig, null!, mpk));
        Assert.False(Api.Verify(Message, sig, "Alice", null!));
        Assert.False(Api.Verify("a\uD800", sig, "Alice", mpk));
        Assert.False(Api.Verify(Std.Str("message"), sig, "a\uD800", mpk));
        Assert.False(Api.Verify(Std.Str("message"), sig + "00", "Alice", mpk));
        Assert.False(Api.Verify(Std.Str("message"), sig[..64] + "05" + sig[66..], "Alice", mpk));
    }

    [Fact]
    public void ZeroT1IsAnError()
    {
        // ks = N - H1(ID || hid) makes t1 = 0.
        var id = "Alice"u8.ToArray();
        var h1 = Sm9Scalar.Hash(0x01, id, [Api.HidSign]);
        var ks = Sm9Scalar.Sub(default, h1);
        string hex = ks.ToHexLower();
        Assert.Throws<ArgumentException>(() => Api.GenSignUserKey(hex, "Alice"));
        Assert.Throws<ArgumentException>(() => Api.GenEncUserKey(hex, "Alice", Api.HidSign));

        // With that encryption master key, Q for this ID is the identity, so nothing can be encrypted to it.
        string mpk = Api.GetEncMasterPublicKey(hex);
        Assert.Throws<ArgumentException>(() => Api.Encrypt(Message, "Alice", mpk, Api.HidSign));
        Assert.NotEmpty(Api.GenSignUserKey(hex, "Bob"));
    }

    [Fact]
    public void RandomScalarsUseRejectionSamplingAndFailingGeneratorsAreErrors()
    {
        Assert.Throws<CryptographicException>(() => Api.NextScalar(b => b.Clear()));
        Assert.Throws<CryptographicException>(() => Api.NextScalar(b => b.Fill(0xFF)));
        int calls = 0;
        var n = Sm9Scalar.N.ToBEBytes();
        var k = Api.NextScalar(b =>
        {
            // First the order N itself, which must be rejected, then N - 1, the largest valid value.
            n.CopyTo(b);
            if (calls++ > 0)
            {
                b[31]--;
            }
        });
        Assert.Equal(2, calls);
        Assert.Equal(Sm9Scalar.NMinus1, k);
    }

    [Fact]
    public void HashToRangeMatchesStandardH1()
    {
        // GB/T 38635.5 A.2: H1("Alice" || 01) for the signing example.
        var h1 = Sm9Scalar.Hash(0x01, "Alice"u8, [0x01]);
        Assert.Equal("2acc468c3926b0bdb2767e99ff26e084de9ced8dbc7d5fbf418027b667862fab", h1.ToHexLower());
    }

    [Fact]
    public void PairingWithIdentityIsOne()
    {
        var oneG1 = new G1Affine(default, default, true);
        var oneG2 = new G2Affine(default, default, true);
        Assert.True(Sm9Pairing.Pair(oneG1, G2Affine.Generator).Equals(Fq12.One));
        Assert.True(Sm9Pairing.Pair(G1Affine.Generator, oneG2).Equals(Fq12.One));
    }
}
