using System.Text;
using SMX;

namespace SMX.Tests;

[CollectionDefinition("Hardware path switches", DisableParallelization = true)]
public class HardwarePathSwitches
{
}

/// <summary>SM4 must match the published vectors and tables; the hex paths (vector, scalar) must agree with one another.</summary>
[Collection("Hardware path switches")]
public class InternalSymmetricTests
{
    private static readonly byte[] StandardKey = Convert.FromHexString("0123456789ABCDEFFEDCBA9876543210");

    /// <summary>The published S-box (GB/T 32907), kept apart from the library's copy so that a typo in either shows.</summary>
    private static readonly byte[] StandardSBox = Convert.FromHexString(
        "D690E9FECCE13DB716B614C228FB2C052B679A762ABE04C3AA441326498606999C4250F491EF987A33540B43EDCFAC62" +
        "E4B31CA9C908E89580DF94FA758F3FA64707A7FCF37317BA83593C19E6854FA8686B81B27164DA8BF8EB0F4B70569D35" +
        "1E240E5E6358D1A225227C3B01217887D40046579FD327524C3602E7A0C4C89EEABF8AD240C738B5A3F7F2CEF96115A1" +
        "E0AE5DA49B341A55AD933230F58CB1E31DF6E22E8266CA60C02923AB0D534E6FD5DB3745DEFD8E2F03FF6A726D6C5B51" +
        "8D1BAF92BBDDBC7F11D95C411F105AD80AC13188A5CD7BBD2D74D012B8E5B4B08969974A0C96777E65B9F109C56EC684" +
        "18F07DEC3ADC4D2079EE5F3ED7CB3948");

    [Fact]
    public void Sm4TablesMatchStandardSBoxForAllBytesInAllPositions()
    {
        Assert.Equal(StandardSBox, Sm4Core.SBox.ToArray());
        for (int i = 0; i < 256; i++)
        {
            for (int position = 0; position < 4; position++)
            {
                uint b = (uint)StandardSBox[i] << (24 - 8 * position);
                uint round = b ^ uint.RotateLeft(b, 2) ^ uint.RotateLeft(b, 10) ^ uint.RotateLeft(b, 18) ^ uint.RotateLeft(b, 24);
                uint key = b ^ uint.RotateLeft(b, 13) ^ uint.RotateLeft(b, 23);
                Assert.Equal(round, Sm4Core.RoundTable[256 * position + i]);
                Assert.Equal(key, Sm4Core.KeyTable[256 * position + i]);
            }
        }
    }

    [Fact]
    public void Sm4StandardSingleBlockAndKeySchedule()
    {
        var rk = new uint[Sm4Core.RoundCount];
        Sm4Core.ExpandKey(StandardKey, rk);
        Assert.Equal(0xF12186F9u, rk[0]);
        Assert.Equal(0x9124A012u, rk[31]);

        var block = (byte[])StandardKey.Clone();
        Sm4Core.EncryptBlock(rk, block);
        Assert.Equal("681EDF34D206965E86B3E94F536E4246", Convert.ToHexString(block));

        Sm4Core.DecryptCbc(rk, new byte[16], block);
        Assert.Equal(Convert.ToHexString(StandardKey), Convert.ToHexString(block));
    }

    [Fact]
    public void Sm4StandardMillionIterations()
    {
        var rk = new uint[Sm4Core.RoundCount];
        Sm4Core.ExpandKey(StandardKey, rk);
        var block = (byte[])StandardKey.Clone();
        for (int i = 0; i < 1_000_000; i++)
        {
            Sm4Core.EncryptBlock(rk, block);
        }
        Assert.Equal("595298C7C6FD271F0402F804C33D3F66", Convert.ToHexString(block));
    }

    [Fact]
    public void Sm4PathsAgreeForEveryLength()
    {
        var rng = new Random(1);
        var key = new byte[16];
        var iv = new byte[16];
        rng.NextBytes(key);
        rng.NextBytes(iv);
        for (int blocks = 0; blocks <= 40; blocks++)
        {
            var plain = new byte[blocks * 16];
            rng.NextBytes(plain);

            byte[]? referenceCipher = null;
            var rk = new uint[Sm4Core.RoundCount];
            Sm4Core.ExpandKey(key, rk);

            var cipher = (byte[])plain.Clone();
            Sm4Core.EncryptCbc(rk, iv, cipher);
            referenceCipher ??= cipher;
            Assert.Equal(referenceCipher, cipher);

            var back = (byte[])cipher.Clone();
            Sm4Core.DecryptCbc(rk, iv, back);
            Assert.Equal(plain, back);

            // CBC by definition, one block at a time through the single-block primitive.
            var expected = new byte[plain.Length];
            var chain = (byte[])iv.Clone();
            for (int i = 0; i < blocks; i++)
            {
                var block = plain.AsSpan(i * 16, 16).ToArray();
                for (int j = 0; j < 16; j++)
                {
                    block[j] ^= chain[j];
                }
                Sm4Core.EncryptBlock(rk, block);
                block.CopyTo(expected, i * 16);
                chain = block;
            }
            Assert.Equal(expected, cipher);
        }
    }

    [Fact]
    public void Sm4PublicApiMatchesOnEveryPath()
    {
        var c = new SM4();
        c.SetKey(Encoding.ASCII.GetBytes("157224F19FD4C080"), Encoding.ASCII.GetBytes("65B06A99625C008A"));

        const string Plain = "国密SM4对称加密算法";
        var cipher = c.Encrypt(Plain);
        Assert.Equal("09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc", cipher);
        Assert.Equal(Plain, c.Decrypt(cipher));
    }

    [Fact]
    public void HexVectorAndScalarPathsAgree()
    {
        var rng = new Random(2);
        foreach (var length in Enumerable.Range(0, 70).Concat([255, 256, 1000]))
        {
            var bytes = new byte[length];
            rng.NextBytes(bytes);
            var expectedLower = string.Concat(bytes.Select(b => b.ToString("x2")));
            var expectedUpper = expectedLower.ToUpperInvariant();
            var mixed = string.Concat(expectedLower.Select((c, i) => i % 3 == 0 ? char.ToUpperInvariant(c) : c));
            foreach (var scalar in new[] { false, true })
            {
                HexUtils.ForceScalar = scalar;
                try
                {
                    Assert.Equal(expectedLower, HexUtils.BytesToHex(bytes));
                    Assert.Equal(expectedUpper, HexUtils.BytesToHexUpper(bytes));
                    Assert.Equal(bytes, HexUtils.HexToBytes(expectedLower));
                    Assert.Equal(bytes, HexUtils.HexToBytes(expectedUpper));
                    Assert.Equal(bytes, HexUtils.HexToBytes(mixed));
                }
                finally
                {
                    HexUtils.ForceScalar = false;
                }
            }
        }
    }

    [Fact]
    public void HexRejectsEveryInvalidCharacterAtEveryVectorPosition()
    {
        var valid = new HashSet<char>("0123456789abcdefABCDEF");
        var samples = Enumerable.Range(0, 256).Select(i => (char)i).Concat(new[] { 'İ', 'Ł', '１', '￿', (char)('0' + 0x100), (char)('a' + 0x100) }).Where(c => !valid.Contains(c)).ToArray();
        foreach (var scalar in new[] { false, true })
        {
            HexUtils.ForceScalar = scalar;
            try
            {
                foreach (var c in samples)
                {
                    foreach (var position in new[] { 0, 1, 2, 15, 16, 31, 32, 33, 47, 63 })
                    {
                        var chars = new string('a', 64).ToCharArray();
                        chars[position] = c;
                        var ex = Assert.Throws<ArgumentException>(() => HexUtils.HexToBytes(new string(chars)));
                        Assert.Equal("Invalid hex character", ex.Message);
                    }
                }
            }
            finally
            {
                HexUtils.ForceScalar = false;
            }
        }
    }

    [Fact]
    public void Sm3StreamingSplitsMatchOneShot()
    {
        var rng = new Random(3);
        var data = new byte[1000];
        rng.NextBytes(data);
        var whole = Sm3Hash(data);
        for (int split = 0; split <= 200; split++)
        {
            var h = new SM3();
            h.Update(data[..split]);
            h.Update(data[split..]);
            h.Finish();
            Assert.Equal(whole, h.HashHexUpper());
        }
    }

    [Fact]
    public void Sm3CounterDigestMatchesPlainHashing()
    {
        var rng = new Random(4);
        Span<byte> digest = stackalloc byte[32];
        foreach (var prefixLength in Enumerable.Range(0, 140))
        {
            var prefix = new byte[prefixLength];
            rng.NextBytes(prefix);
            var hasher = Sm3Hasher.Create();
            hasher.Update(prefix);
            hasher.FinishWithCounter(0x01020304, digest);

            // Using it must leave the state reusable.
            hasher.FinishWithCounter(0x01020304, digest);
            Assert.Equal(Sm3Hash([.. prefix, 1, 2, 3, 4]), Convert.ToHexString(digest));
        }
    }

    private static string Sm3Hash(byte[] data)
    {
        var h = new SM3();
        h.Update(data);
        h.Finish();
        return h.HashHexUpper();
    }

    [Fact]
    public void Sm3DigestIsOnlyReadableWhenItExists()
    {
        var h = new SM3();
        Assert.Throws<InvalidOperationException>(() => h.HashBytes());
        Assert.Throws<InvalidOperationException>(() => h.HashHexUpper());

        h.Update(Encoding.ASCII.GetBytes("abc"));
        Assert.Throws<InvalidOperationException>(() => h.HashBytes());
        h.Finish();
        var expected = h.HashHexUpper();
        Assert.Equal("66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0", expected);

        // Scribbling on a returned digest changes nothing later.
        var bytes = h.HashBytes();
        bytes[0] ^= 0xFF;
        Assert.Equal(expected, h.HashHexUpper());
        Assert.Equal(expected, Convert.ToHexString(h.HashBytes()));

        // Finish twice fails, leaving the digest readable; it never turns into the empty-message hash.
        Assert.Throws<InvalidOperationException>(() => h.Finish());
        Assert.Equal(expected, h.HashHexUpper());

        // Updating starts a new message, and the old digest stops being readable.
        h.UpdateByte((byte)'x');
        Assert.Throws<InvalidOperationException>(() => h.HashHexUpper());
        h.Finish();
        Assert.NotEqual(expected, h.HashHexUpper());

        h.Update([]);
        h.Finish();
        Assert.Equal("1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B", h.HashHexUpper());
    }

    [Fact]
    public void Sm3OfNoUpdatesIsTheEmptyHash()
    {
        var h = new SM3();
        h.Finish();
        Assert.Equal("1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B", h.HashHexUpper());
    }

    [Fact]
    public void Sm2SignFollowsStandardWithFixedNonce()
    {
        var d = BigInt256.FromHex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        var k = BigInt256.FromHex("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21");
        var publicKey = SM2.GetPublicKey(d);
        var e = SM2.MessageDigest("1234567812345678", "message digest", publicKey);
        Sm2Order.Invert(d.Add(BigInt256.One, out _), out var inverse);
        var noncePoint = ECPoint.Generator().Multiply(k);

        Assert.True(SM2.TrySign(e, d, inverse, k, noncePoint.X.Value, out var r, out var s));
        Assert.Equal("F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3", r.ToHex());
        Assert.Equal("B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA", s.ToHex());
    }
}
