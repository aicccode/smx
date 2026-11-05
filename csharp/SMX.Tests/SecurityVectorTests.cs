using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SMX;

namespace SMX.Tests;

/// <summary>Asserts every case of the shared, independently generated testvectors/security-vectors.json.</summary>
[Collection("Hardware path switches")]
public class SecurityVectorTests
{
    private static readonly JsonElement Root = Load();
    private static readonly JsonElement Sm2Vectors = Root.GetProperty("sm2");
    private static readonly JsonElement Sm3Vectors = Root.GetProperty("sm3");
    private static readonly JsonElement Sm4Vectors = Root.GetProperty("sm4");

    private static readonly string PublicKey = S(Sm2Vectors, "public_key");
    private static readonly string PrivateKey = S(Sm2Vectors, "private_key");
    private static readonly string UserId = S(Sm2Vectors, "user_id");
    private static readonly string Message = S(Sm2Vectors, "message");
    private static readonly string ValidSignature = S(Sm2Vectors, "r") + "h" + S(Sm2Vectors, "s");

    private static JsonElement Load()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "testvectors", "security-vectors.json")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return JsonDocument.Parse(File.ReadAllText(Path.Combine(dir!.FullName, "testvectors", "security-vectors.json"))).RootElement;
    }

    private static string S(JsonElement e, string name) => e.GetProperty(name).GetString()!;

    private static IEnumerable<JsonElement> Cases(JsonElement e, string name) => e.GetProperty(name).EnumerateArray();

    /// <summary>Failure must be the convention for that function, never another exception type.</summary>
    private static void AssertInvalidArgument(Action action, string caseName)
    {
        try
        {
            action();
        }
        catch (ArgumentException)
        {
            return;
        }
        catch (Exception ex)
        {
            Assert.Fail($"{caseName}: threw {ex.GetType().Name}");
        }
        Assert.Fail($"{caseName}: accepted");
    }

    [Fact]
    public void ValidSm2VectorsStillWork()
    {
        Assert.True(SM2.Verify(UserId, ValidSignature, Message, PublicKey));
        Assert.Equal(S(Sm2Vectors, "plaintext"), SM2.Decrypt(S(Sm2Vectors, "ciphertext"), PrivateKey));
        Assert.Equal(PublicKey, SM2.GetPublicKey(BigInt256.FromHex(PrivateKey)).ToHexEncoded());

        var d = BigInt256.FromHex(PrivateKey);
        var k = BigInt256.FromHex(S(Sm2Vectors, "nonce_k"));
        var e = SM2.MessageDigest(UserId, Message, SM2.GetPublicKey(d));
        Sm2Order.Invert(d.Add(BigInt256.One, out _), out var inverse);
        Assert.True(SM2.TrySign(e, d, inverse, k, ECPoint.Generator().Multiply(k).X.Value, out var r, out var s));
        Assert.Equal(S(Sm2Vectors, "r"), r.ToHexLower());
        Assert.Equal(S(Sm2Vectors, "s"), s.ToHexLower());
    }

    [Fact]
    public void InvalidPublicKeysAreRejectedAtEveryEntryPoint()
    {
        var valid = SM2.DecodePoint(PublicKey);
        var ownD = BigInt256.FromHex(PrivateKey);
        foreach (var c in Cases(Sm2Vectors, "invalid_public_keys"))
        {
            string name = S(c, "name");
            string value = S(c, "value");
            Assert.False(SM2.Verify(UserId, ValidSignature, Message, value), name);
            AssertInvalidArgument(() => SM2.Encrypt("m", value), name);
            AssertInvalidArgument(() => SM2.DecodePoint(value), name);
            AssertInvalidArgument(() => ECPoint.FromHexEncoded(value), name);

            // Key exchange takes points, which a caller may have assembled by hand from any 65-byte encoding.
            if (value.Length == 130 && value.All(Uri.IsHexDigit))
            {
                var raw = new ECPoint
                {
                    X = new FpElement { Value = BigInt256.FromHex(value[2..66]) },
                    Y = new FpElement { Value = BigInt256.FromHex(value[66..]) },
                };
                if (value.StartsWith("04", StringComparison.Ordinal))
                {
                    Assert.False(raw.IsOnCurve(), name);
                    Assert.False(SM2.GetSb(16, raw, valid, valid, ownD, valid, ownD, "a", "b").Success, name);
                    Assert.False(SM2.GetSb(16, valid, raw, valid, ownD, valid, ownD, "a", "b").Success, name);
                    Assert.False(SM2.GetSb(16, valid, valid, raw, ownD, valid, ownD, "a", "b").Success, name);
                    Assert.False(SM2.GetSb(16, valid, valid, valid, ownD, raw, ownD, "a", "b").Success, name);
                    Assert.False(SM2.GetSa(16, raw, valid, valid, ownD, valid, ownD, "a", "b", new byte[32]).Success, name);
                    Assert.False(SM2.GetSa(16, valid, raw, valid, ownD, valid, ownD, "a", "b", new byte[32]).Success, name);
                    AssertInvalidArgument(() => raw.Multiply(ownD), name);
                    AssertInvalidArgument(() => raw.Add(valid), name);
                }
            }
        }
    }

    [Fact]
    public void InvalidPrivateKeysFailCleanly()
    {
        var cipher = S(Sm2Vectors, "ciphertext");
        foreach (var c in Cases(Sm2Vectors, "invalid_private_keys"))
        {
            string name = S(c, "name");
            string value = S(c, "value");
            AssertInvalidArgument(() => SM2.Sign(UserId, Message, value), name);
            AssertInvalidArgument(() => SM2.Decrypt(cipher, value), name);

            if (value.Length == 64 && value.All(Uri.IsHexDigit))
            {
                var d = BigInt256.FromHex(value);
                AssertInvalidArgument(() => SM2.GetPublicKey(d), name);
                var p = SM2.DecodePoint(PublicKey);
                Assert.False(SM2.GetSb(16, p, p, p, d, p, BigInt256.One, "a", "b").Success, name);
                Assert.False(SM2.GetSb(16, p, p, p, BigInt256.One, p, d, "a", "b").Success, name);
                Assert.False(SM2.GetSa(16, p, p, p, d, p, BigInt256.One, "a", "b", new byte[32]).Success, name);
                Assert.False(SM2.GetSa(16, p, p, p, BigInt256.One, p, d, "a", "b", new byte[32]).Success, name);
            }
        }
    }

    [Fact]
    public void LargestValidPrivateKeyWorks()
    {
        var hex = S(Sm2Vectors, "n_minus_2_is_max_valid_private_key");
        var pub = SM2.GetPublicKey(BigInt256.FromHex(hex)).ToHexEncoded();
        Assert.True(SM2.Verify("id", SM2.Sign("id", "m", hex), "m", pub));
        Assert.Equal("text", SM2.Decrypt(SM2.Encrypt("text", pub), hex));
    }

    [Fact]
    public void InvalidSignaturesVerifyFalse()
    {
        foreach (var c in Cases(Sm2Vectors, "invalid_signatures"))
        {
            Assert.False(SM2.Verify(UserId, S(c, "r") + "h" + S(c, "s"), Message, PublicKey), S(c, "name"));
        }
    }

    [Fact]
    public void InvalidCiphertextsFailCleanly()
    {
        foreach (var c in Cases(Sm2Vectors, "invalid_ciphertexts"))
        {
            string name = S(c, "name");
            string value = S(c, "value");
            try
            {
                SM2.Decrypt(value, PrivateKey);
                Assert.Fail(name + ": accepted");
            }
            catch (ArgumentException)
            {
            }
            catch (InvalidOperationException)
            {
            }
        }
    }

    [Fact]
    public void UserIdBoundaryIsExact()
    {
        int max = Sm2Vectors.GetProperty("user_id_max_bytes").GetInt32();
        int first = Sm2Vectors.GetProperty("user_id_first_invalid_bytes").GetInt32();
        var (pri, pub) = SM2.GenKeyPair();
        var point = SM2.DecodePoint(pub);
        var d = BigInt256.FromHex(pri);

        string longest = new('u', max);
        var signature = SM2.Sign(longest, "m", pri);
        Assert.True(SM2.Verify(longest, signature, "m", pub));
        Assert.True(SM2.GetSb(16, point, point, point, d, point, d, longest, longest).Success);

        // Also when the excess comes from multi-byte characters: the limit is in bytes.
        foreach (var tooLong in new[] { new string('u', first), new string('u', 65536 / 8), new string('国', first / 3 + 1) })
        {
            AssertInvalidArgument(() => SM2.Sign(tooLong, "m", pri), "sign");
            Assert.False(SM2.Verify(tooLong, signature, "m", pub));
            Assert.False(SM2.GetSb(16, point, point, point, d, point, d, tooLong, "b").Success);
            Assert.False(SM2.GetSb(16, point, point, point, d, point, d, "a", tooLong).Success);
            Assert.False(SM2.GetSa(16, point, point, point, d, point, d, tooLong, "b", new byte[32]).Success);
        }
    }

    private static string HashZeros(long megabytes)
    {
        var chunk = new byte[1024 * 1024];
        var h = new SM3();
        for (long i = 0; i < megabytes; i++)
        {
            h.Update(chunk);
        }
        h.Finish();
        return Convert.ToHexString(h.HashBytes()).ToLowerInvariant();
    }

    [Fact]
    public void Sm3LengthIsCorrectAt512MiB() => Assert.Equal(S(Sm3Vectors, "zeros_512_mib"), HashZeros(512));

    [Fact]
    public void Sm3LengthIsCorrectAt1024MiB() => Assert.Equal(S(Sm3Vectors, "zeros_1024_mib"), HashZeros(1024));

    private static void OnEverySm4Path(Action action)
    {
        foreach (var (software, noAvx2) in new[] { (false, false), (false, true), (true, false) })
        {
            Sm4Core.ForceSoftware = software;
            Sm4Core.ForceNoAvx2 = noAvx2;
            try
            {
                action();
            }
            finally
            {
                Sm4Core.ForceSoftware = false;
                Sm4Core.ForceNoAvx2 = false;
            }
        }
    }

    private static SM4 VectorSm4()
    {
        var c = new SM4();
        c.SetKey(Convert.FromHexString(S(Sm4Vectors, "key")), Convert.FromHexString(S(Sm4Vectors, "iv")));
        return c;
    }

    [Fact]
    public void Sm4ValidVectors()
    {
        OnEverySm4Path(() =>
        {
            var c = VectorSm4();
            string plain = S(Sm4Vectors, "valid_padded_plaintext");
            Assert.Equal(S(Sm4Vectors, "valid_padded_ciphertext"), c.Encrypt(plain));
            Assert.Equal(plain, c.Decrypt(S(Sm4Vectors, "valid_padded_ciphertext")));
            Assert.Equal("", c.Decrypt(S(Sm4Vectors, "valid_full_padding_block_ciphertext")));
            Assert.Equal(S(Sm4Vectors, "valid_full_padding_block_ciphertext"), c.Encrypt(""));
        });
    }

    [Fact]
    public void Sm4RejectsEveryOtherKeyAndIvSize()
    {
        var c = VectorSm4();
        var before = c.Encrypt("x");
        foreach (var length in Sm4Vectors.GetProperty("invalid_key_lengths_bytes").EnumerateArray().Select(e => e.GetInt32()))
        {
            AssertInvalidArgument(() => c.SetKey(new byte[length], new byte[16]), "key " + length);
        }
        foreach (var length in Sm4Vectors.GetProperty("invalid_iv_lengths_bytes").EnumerateArray().Select(e => e.GetInt32()))
        {
            AssertInvalidArgument(() => c.SetKey(new byte[16], new byte[length]), "iv " + length);
        }

        // A rejected SetKey leaves the previous key in force.
        Assert.Equal(before, c.Encrypt("x"));
    }

    [Fact]
    public void Sm4AllDecryptFailuresLookTheSame()
    {
        OnEverySm4Path(() =>
        {
            var c = VectorSm4();
            var messages = new HashSet<string>();
            void Check(string ciphertext, string name)
            {
                var ex = Assert.Throws<ArgumentException>(() => c.Decrypt(ciphertext));
                Assert.True(ex.GetType() == typeof(ArgumentException), name);
                messages.Add(ex.Message);
            }

            foreach (var e in Cases(Sm4Vectors, "invalid_paddings"))
            {
                Check(S(e, "value"), S(e, "name"));
            }
            foreach (var length in Sm4Vectors.GetProperty("invalid_ciphertext_lengths_bytes").EnumerateArray().Select(e => e.GetInt32()))
            {
                Check(new string('a', length * 2), "length " + length);
            }
            Check("abc", "odd digits");
            Check(new string('z', 32), "not hex");
            Check("0x" + new string('a', 30), "prefix");
            Assert.Single(messages);
        });
    }
}
