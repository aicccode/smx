using System.Security.Cryptography;
using System.Text;
using SMX;

namespace SMX.Tests;

/// <summary>Regression tests for the problems found in the security review, beyond the shared vectors.</summary>
public class HardeningTests
{
    private const string PrivateKey = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";
    private static readonly string PublicKey = SM2.GetPublicKey(BigInt256.FromHex(PrivateKey)).ToHexEncoded();
    private static readonly BigInt256 N = ECPoint.SM2_N;
    private static readonly BigInt256 P = FpElement.SM2_P;

    private static ECPoint Point() => SM2.DecodePoint(PublicKey);

    [Fact]
    public void RngFailureSurfacesAndNothingIsFabricated()
    {
        Assert.Throws<CryptographicException>(() => SM2.NextNonce(_ => throw new CryptographicException("rng down")));
        Assert.Throws<CryptographicException>(() => SM2.NextPrivateKey(_ => throw new CryptographicException("rng down")));
    }

    [Fact]
    public void BrokenRngOutputEndsInErrorNotAHang()
    {
        Assert.Throws<CryptographicException>(() => SM2.NextNonce(b => b.Clear()));
        Assert.Throws<CryptographicException>(() => SM2.NextNonce(b => b.Fill(0xFF)));
        Assert.Throws<CryptographicException>(() => SM2.NextPrivateKey(b => b.Clear()));
    }

    /// <summary>Rejection sampling at the exact bounds, on values fed in through a scripted source.</summary>
    [Fact]
    public void ScalarRangesAreExact()
    {
        BigInt256 nMinus1 = N.Sub(BigInt256.One, out _);
        BigInt256 nMinus2 = nMinus1.Sub(BigInt256.One, out _);

        SM2.RandomSource Scripted(params BigInt256[] values)
        {
            int i = 0;
            return b => values[i++].WriteBigEndian(b);
        }

        Assert.Equal(nMinus1, SM2.NextNonce(Scripted(N, BigInt256.Zero, nMinus1)));
        Assert.Equal(nMinus2, SM2.NextPrivateKey(Scripted(N, nMinus1, BigInt256.Zero, nMinus2)));
        Assert.Equal(BigInt256.One, SM2.NextPrivateKey(Scripted(BigInt256.Zero, BigInt256.One)));
    }

    [Fact]
    public void GeneratedKeysAndNoncesRoundTrip()
    {
        for (int i = 0; i < 50; i++)
        {
            var (pri, pub) = SM2.GenKeyPair();
            Assert.Equal(64, pri.Length);
            Assert.True(SM2.Verify("id", SM2.Sign("id", "message", pri), "message", pub));
            Assert.Equal("plain", SM2.Decrypt(SM2.Encrypt("plain", pub), pri));
        }
    }

    [Fact]
    public void InfinityIsNotOnCurveAndNotAKey()
    {
        Assert.False(ECPoint.PointAtInfinity.IsOnCurve());
        Assert.Throws<ArgumentException>(() => ECPoint.FromEncoded([]));
        Assert.Throws<ArgumentException>(() => ECPoint.FromEncoded([0x00]));

        // The forgery that was possible against an empty public key.
        Assert.False(SM2.Verify("a", new string('1', 64) + "h" + new string('1', 64), "m", ""));
    }

    [Fact]
    public void UnreducedCoordinatesAreRejected()
    {
        // An x whose alias x + p still fits in 256 bits. Reducing it would quietly accept a second encoding of a point.
        var small = BigInt256.One;
        var aliased = small.Add(P, out _);
        Assert.Throws<ArgumentException>(() => new FpElement(aliased));
        Assert.Throws<ArgumentException>(() => new FpElement(P));
        Assert.Throws<ArgumentException>(() => ECPoint.FromHexEncoded("04" + aliased.ToHexLower() + new string('0', 64)));
        var handBuilt = new ECPoint { X = new FpElement { Value = aliased }, Y = FpElement.One };
        Assert.False(handBuilt.IsOnCurve());
    }

    [Fact]
    public void FieldOperationsStayCorrectForAHandBuiltValue()
    {
        var aliasOfOne = new FpElement { Value = BigInt256.One.Add(P, out _) };
        Assert.True(aliasOfOne.IsOne);
        Assert.Equal(FpElement.One, aliasOfOne);
        Assert.True(new FpElement { Value = P }.IsZero);
        Assert.Throws<InvalidOperationException>(() => new FpElement { Value = P }.Invert());
        Assert.Equal(new BigInt256(2, 0, 0, 0), aliasOfOne.Add(aliasOfOne).Value);
        Assert.Equal(BigInt256.Zero, new FpElement { Value = P }.Negate().Value);
    }

    [Fact]
    public void NumbersAndBytesAreNeverTruncated()
    {
        Assert.Throws<ArgumentException>(() => BigInt256.FromHex(new string('1', 65)));
        Assert.Throws<ArgumentException>(() => BigInt256.FromHex("ff" + new string('0', 64)));
        Assert.Throws<ArgumentException>(() => BigInt256.FromBEBytes(new byte[33]));
        Assert.Throws<ArgumentException>(() => BigInt256.FromHex(""));
        Assert.Throws<ArgumentException>(() => BigInt256.FromHex("0x"));
        Assert.Throws<ArgumentException>(() => BigInt256.FromHex("0x0xAB"));
        Assert.Throws<ArgumentException>(() => HexUtils.HexToBytes("abc"));
        Assert.Equal(new BigInt256(0xAB, 0, 0, 0), BigInt256.FromHex("0xAB"));
        Assert.Equal(new BigInt256(0xA, 0, 0, 0), BigInt256.FromHex("A"));
    }

    [Fact]
    public void ErrorsDoNotQuoteInput()
    {
        var secretLooking = "7" + new string('Q', 63);
        var ex = Assert.Throws<ArgumentException>(() => SM2.Sign("a", "m", secretLooking));
        Assert.DoesNotContain("Q", ex.Message);
        ex = Assert.Throws<ArgumentException>(() => HexUtils.HexToBytes("QQ"));
        Assert.DoesNotContain("Q", ex.Message);
        ex = Assert.Throws<ArgumentException>(() => BigInt256.FromHex("QQ"));
        Assert.DoesNotContain("Q", ex.Message);
        Assert.DoesNotContain("3945", BigInt256.FromHex(PrivateKey).ToString());
    }

    [Fact]
    public void TextWithoutUtf8FormIsRejectedInsteadOfCollapsing()
    {
        // Lone surrogates used to be replaced, making different strings sign and encrypt as the same bytes.
        const string A = "a\uD800";
        const string B = "a\uD801";
        var signature = SM2.Sign("id", "a�", PrivateKey);
        Assert.False(SM2.Verify("id", signature, A, PublicKey));
        Assert.False(SM2.Verify("id", signature, B, PublicKey));
        Assert.Throws<EncoderFallbackException>(() => SM2.Sign("id", A, PrivateKey));
        Assert.Throws<EncoderFallbackException>(() => SM2.Sign(A, "m", PrivateKey));
        Assert.Throws<EncoderFallbackException>(() => SM2.Encrypt(A, PublicKey));
        var c = new SM4();
        c.SetKey(new byte[16], new byte[16]);
        Assert.Throws<EncoderFallbackException>(() => c.Encrypt(A));
        var pt = Point();
        Assert.False(SM2.GetSb(16, pt, pt, pt, BigInt256.One, pt, BigInt256.One, A, "b").Success);
    }

    [Fact]
    public void NullsFollowTheFailureConvention()
    {
        var pt = Point();
        var d = BigInt256.One;
        Assert.False(SM2.Verify(null!, "h", "m", PublicKey));
        Assert.False(SM2.Verify("a", null!, "m", PublicKey));
        Assert.False(SM2.Verify("a", "h", null!, PublicKey));
        Assert.False(SM2.Verify("a", "h", "m", null!));
        Assert.False(SM2.CheckSa(pt, null!, new byte[32], pt, pt, new byte[32]));
        Assert.False(SM2.CheckSa(pt, new byte[32], null!, pt, pt, new byte[32]));
        Assert.False(SM2.CheckSa(pt, new byte[32], new byte[32], pt, pt, null!));
        Assert.False(SM2.GetSb(16, pt, pt, pt, d, pt, d, null!, "b").Success);
        Assert.False(SM2.GetSa(16, pt, pt, pt, d, pt, d, "a", null!, new byte[32]).Success);
        Assert.False(SM2.GetSa(16, pt, pt, pt, d, pt, d, "a", "b", null!).Success);
        Assert.Throws<ArgumentNullException>(() => SM2.Encrypt(null!, PublicKey));
        Assert.Throws<ArgumentNullException>(() => SM2.Decrypt(null!, PrivateKey));
        Assert.Throws<ArgumentNullException>(() => SM2.Sign("a", "m", null!));
        Assert.Throws<ArgumentNullException>(() => BigInt256.FromHex(null!));
        Assert.Throws<ArgumentNullException>(() => HexUtils.HexToBytes(null!));
        Assert.Throws<ArgumentNullException>(() => new SM3().Update(null!));
        Assert.Throws<ArgumentNullException>(() => new SM4().SetKey(null!, new byte[16]));
    }

    private static (ECPoint PA, ECPoint RA, ECPoint PB, ECPoint RB, BigInt256 DA, BigInt256 Ra, BigInt256 DB, BigInt256 Rb) ExchangeKeys()
    {
        var dA = BigInt256.FromHex("6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE");
        var ra = BigInt256.FromHex("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563");
        var dB = BigInt256.FromHex("5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53");
        var rb = BigInt256.FromHex("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80");
        return (SM2.GetPublicKey(dA), SM2.GetPublicKey(ra), SM2.GetPublicKey(dB), SM2.GetPublicKey(rb), dA, ra, dB, rb);
    }

    [Fact]
    public void KeyExchangeBoundsAndConfirmationLengths()
    {
        var k = ExchangeKeys();
        foreach (var bad in new[] { 0, -1, int.MinValue, 1024 * 1024 + 1, int.MaxValue })
        {
            Assert.False(SM2.GetSb(bad, k.PA, k.RA, k.PB, k.DB, k.RB, k.Rb, "a", "b").Success);
            Assert.False(SM2.GetSa(bad, k.PB, k.RB, k.PA, k.DA, k.RA, k.Ra, "a", "b", new byte[32]).Success);
        }

        foreach (var keyLength in new[] { 1, 16, 33, 1024 * 1024 })
        {
            var b = SM2.GetSb(keyLength, k.PA, k.RA, k.PB, k.DB, k.RB, k.Rb, "a", "b");
            Assert.True(b.Success, b.Message);
            var sb = HexUtils.HexToBytes(b.Sb);
            var a = SM2.GetSa(keyLength, k.PB, k.RB, k.PA, k.DA, k.RA, k.Ra, "a", "b", sb);
            Assert.True(a.Success, a.Message);
            Assert.Equal(b.Kb, a.Ka);
            Assert.Equal(keyLength * 2, a.Ka.Length);

            var sa = HexUtils.HexToBytes(a.Sa);
            Assert.True(SM2.CheckSa(b.V, b.Za, b.Zb, k.RA, k.RB, sa));
            foreach (var shortValue in new[] { Array.Empty<byte>(), sa[..31], sa[..1] })
            {
                Assert.False(SM2.CheckSa(b.V, b.Za, b.Zb, k.RA, k.RB, shortValue));
                Assert.False(SM2.GetSa(keyLength, k.PB, k.RB, k.PA, k.DA, k.RA, k.Ra, "a", "b", shortValue).Success);
            }
            Assert.False(SM2.CheckSa(b.V, b.Za[..31], b.Zb, k.RA, k.RB, sa));
            Assert.False(SM2.CheckSa(ECPoint.PointAtInfinity, b.Za, b.Zb, k.RA, k.RB, sa));
        }
    }

    /// <summary>
    /// Found by the round-trip fuzz: a check for an all-zero derived key failed one exchange in 256 at this key length.
    /// Over this many exchanges an all-zero byte is near certain, and the exchange must still succeed.
    /// </summary>
    [Fact]
    public void ShortExchangedKeysMayBeZero()
    {
        var k = ExchangeKeys();
        var dA = k.DA;
        int zeroKeys = 0;
        for (int i = 0; i < 4000; i++)
        {
            var b = SM2.GetSb(1, k.PA, k.RA, k.PB, k.DB, k.RB, k.Rb, "a" + i, "b");
            Assert.True(b.Success, b.Message);
            var a = SM2.GetSa(1, k.PB, k.RB, k.PA, dA, k.RA, k.Ra, "a" + i, "b", HexUtils.HexToBytes(b.Sb));
            Assert.True(a.Success, a.Message);
            Assert.Equal(b.Kb, a.Ka);
            zeroKeys += b.Kb == "00" ? 1 : 0;
        }
        Assert.True(zeroKeys > 0);
    }

    /// <summary>t = d + x*r mod n = 0 gives V at infinity, which must be reported, with no shared key.</summary>
    [Fact]
    public void KeyExchangeRejectsInfinityResult()
    {
        var k = ExchangeKeys();

        // Choose dB so that tb = dB + xBar2 * rb is exactly n, with xBar2 derived from RB as the protocol does.
        var x = k.RB.X.Value;
        var xBar = new BigInt256(x.L0, (x.L1 & 0x7FFFFFFFFFFFFFFF) | 0x8000000000000000, 0, 0);
        var dB = BigInt256.Zero.ModSub(xBar.ModMul(k.Rb, N), N);
        var result = SM2.GetSb(16, k.PA, k.RA, SM2.GetPublicKey(dB), dB, k.RB, k.Rb, "a", "b");
        Assert.False(result.Success);
        Assert.Equal("V is point at infinity", result.Message);
    }

    [Fact]
    public void GroupOperationsRejectInvalidPoints()
    {
        var off = new ECPoint { X = FpElement.One, Y = FpElement.One };
        var zero = default(ECPoint);
        var good = Point();
        foreach (var bad in new[] { off, zero })
        {
            Assert.Throws<ArgumentException>(() => bad.Multiply(BigInt256.One));
            Assert.Throws<ArgumentException>(() => bad.Add(good));
            Assert.Throws<ArgumentException>(() => good.Add(bad));
            Assert.Throws<ArgumentException>(() => good.Subtract(bad));
            Assert.Throws<ArgumentException>(() => bad.Twice());
            Assert.Throws<ArgumentException>(() => bad.Negate());
            Assert.Throws<ArgumentException>(() => ECPoint.Create(bad.X, bad.Y));
        }
        Assert.Throws<ArgumentException>(() => ECPoint.FromHex("1", "1"));
    }

    [Fact]
    public void GenericArithmeticRejectsWhatHasNoAnswer()
    {
        Assert.Throws<ArgumentException>(() => BigInt256.One.ModInverse(BigInt256.Zero));
        Assert.Throws<ArgumentException>(() => BigInt256.Zero.ModInverse(N));
        Assert.Throws<ArgumentException>(() => BigInt256.Zero.ModInverse(P));
        Assert.Throws<ArgumentException>(() => new BigInt256(2, 0, 0, 0).ModInverse(new BigInt256(4, 0, 0, 0)));
        Assert.Throws<ArgumentException>(() => new BigInt256(5, 0, 0, 0).ModInverse(BigInt256.One));
        Assert.False(BigInt256.One.GetBit(-1));
        Assert.False(BigInt256.One.GetBit(int.MinValue));
        Assert.False(BigInt256.One.GetBit(int.MaxValue));
    }

    [Fact]
    public void Sm3RefusesToOverflowItsLengthField()
    {
        var h = Sm3Hasher.CreateWithLengthForTest(Sm3Hasher.MaxMessageBytes - 1);
        h.UpdateByte(0);
        bool threw = false;
        try
        {
            h.UpdateByte(0);
        }
        catch (ArgumentException)
        {
            threw = true;
        }
        Assert.True(threw);

        var h2 = Sm3Hasher.CreateWithLengthForTest(Sm3Hasher.MaxMessageBytes - 4);
        threw = false;
        try
        {
            h2.Update(new byte[5]);
        }
        catch (ArgumentException)
        {
            threw = true;
        }
        Assert.True(threw);
    }

    [Fact]
    public void Sm4RefusesToRunWithoutAKey()
    {
        // It used to run with all-zero round keys.
        Assert.Throws<InvalidOperationException>(() => new SM4().Encrypt("x"));
        Assert.Throws<InvalidOperationException>(() => new SM4().Decrypt(new string('0', 32)));
    }

    [Fact]
    public void Sm4RejectsPlaintextThatIsNotUtf8WithTheSameError()
    {
        // A two-byte plaintext 0xFF 0xFE, correctly padded and encrypted, produced directly with the core.
        var key = new byte[16];
        var rk = new uint[Sm4Core.RoundCount];
        Sm4Core.ExpandKey(key, rk);
        var block = new byte[16];
        block[0] = 0xFF;
        block[1] = 0xFE;
        block.AsSpan(2).Fill(14);
        Sm4Core.EncryptCbc(rk, new byte[16], block);
        var c = new SM4();
        c.SetKey(key, new byte[16]);
        var ex = Assert.Throws<ArgumentException>(() => c.Decrypt(HexUtils.BytesToHex(block)));
        Assert.Equal("Invalid ciphertext", ex.Message);
    }

    /// <summary>A concurrent SetKey must never let Encrypt see a mix of the old and new key schedules or IV.</summary>
    [Fact]
    public async Task Sm4SetKeyIsAtomicForConcurrentUse()
    {
        var keyA = new byte[16];
        var keyB = Enumerable.Repeat((byte)0xB7, 16).ToArray();
        var ivA = Enumerable.Repeat((byte)0x11, 16).ToArray();
        var ivB = Enumerable.Repeat((byte)0x22, 16).ToArray();

        var one = new SM4();
        one.SetKey(keyA, ivA);
        string expectedA = one.Encrypt("concurrent");
        one.SetKey(keyB, ivB);
        string expectedB = one.Encrypt("concurrent");

        var shared = new SM4();
        shared.SetKey(keyA, ivA);
        using var stop = new CancellationTokenSource();
        var writer = Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                shared.SetKey(keyA, ivA);
                shared.SetKey(keyB, ivB);
            }
        });
        try
        {
            for (int i = 0; i < 200_000; i++)
            {
                var c = shared.Encrypt("concurrent");
                Assert.True(c == expectedA || c == expectedB, "saw a torn key schedule");
            }
        }
        finally
        {
            stop.Cancel();
            await writer;
        }
    }

    /// <summary>The lazily built tables must come out right whichever thread gets there first.</summary>
    [Fact]
    public void ParallelUseGivesConsistentResults()
    {
        var expected = SM2.GetPublicKey(BigInt256.FromHex(PrivateKey)).ToHexEncoded();
        Parallel.For(0, 64, _ =>
        {
            Assert.Equal(expected, SM2.GetPublicKey(BigInt256.FromHex(PrivateKey)).ToHexEncoded());
            Assert.True(SM2.Verify("id", SM2.Sign("id", "m", PrivateKey), "m", PublicKey));
        });
    }

    [Fact]
    public void Sm4DecryptCannotBeTrickedByEncodingVariants()
    {
        var c = new SM4();
        c.SetKey(new byte[16], new byte[16]);
        var cipher = c.Encrypt("text");
        Assert.Equal("text", c.Decrypt(cipher.ToUpperInvariant()));
        Assert.Throws<ArgumentException>(() => c.Decrypt("0x" + cipher));
        Assert.Throws<ArgumentException>(() => c.Decrypt(" " + cipher));
        Assert.Throws<ArgumentException>(() => c.Decrypt(cipher + "\n"));
    }
}
