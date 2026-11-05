using System.Text;
using SMX;

namespace SMX.Tests;

[CollectionDefinition("Hardware path switches", DisableParallelization = true)]
public class HardwarePathSwitches
{
}

/// <summary>SM4 and hex paths (hardware, AVX2, scalar) must agree with published vectors and with one another.</summary>
[Collection("Hardware path switches")]
public class InternalSymmetricTests
{
    private static readonly byte[] StandardKey = Convert.FromHexString("0123456789ABCDEFFEDCBA9876543210");

    /// <summary>Runs the action once per implementation path this machine can actually execute.</summary>
    private static void OnEveryPath(Action action)
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

    [Fact]
    public void Sm4StandardSingleBlockAndKeySchedule()
    {
        OnEveryPath(() =>
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
        });
    }

    [Fact]
    public void Sm4StandardMillionIterations()
    {
        OnEveryPath(() =>
        {
            var rk = new uint[Sm4Core.RoundCount];
            Sm4Core.ExpandKey(StandardKey, rk);
            var block = (byte[])StandardKey.Clone();
            for (int i = 0; i < 1_000_000; i++)
            {
                Sm4Core.EncryptBlock(rk, block);
            }
            Assert.Equal("595298C7C6FD271F0402F804C33D3F66", Convert.ToHexString(block));
        });
    }

    [Fact]
    public void Sm4HardwareSubstitutionMatchesTableForAllBytesInAllPositions()
    {
        if (!Sm4Core.HardwareAvailable)
        {
            return;
        }
        for (int i = 0; i < 256; i++)
        {
            uint expected = Sm4Core.SBox[i];
            for (int shift = 0; shift < 32; shift += 8)
            {
                uint fill = 0x5A5A5A5A & ~(0xFFu << shift);
                uint fillOutput = (uint)Sm4Core.SBox[0x5A] * 0x01010101u & ~(0xFFu << shift);
                Assert.Equal((expected << shift) | fillOutput, Sm4Core.SubstituteWithHardware(fill | ((uint)i << shift)));
            }
        }
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
            OnEveryPath(() =>
            {
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
            });
        }
    }

    [Fact]
    public void Sm4PublicApiMatchesOnEveryPath()
    {
        OnEveryPath(() =>
        {
            var c = new SM4();
            c.SetKey(Encoding.UTF8.GetBytes("this is the key"), Encoding.UTF8.GetBytes("this is the iv"));
            const string Plain = "国密SM4对称加密算法";
            var cipher = c.Encrypt(Plain);
            Assert.Equal("09908004c24cece806ee6dc2d6a3d154907048fb96d0201a8c47f4f1e03995bc", cipher);
            Assert.Equal(Plain, c.Decrypt(cipher));
        });
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
                        Assert.Equal($"Invalid hex character: {c}", ex.Message);
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
    public void Sm3ResultsBehaveAsBefore()
    {
        var h = new SM3();
        Assert.Equal("", h.HashHexUpper());
        Assert.Empty(h.HashBytes());
        h.Update(Encoding.ASCII.GetBytes("abc"));
        h.Finish();

        // The hex form is unaffected by callers scribbling on the array they were handed.
        var bytes = h.HashBytes();
        var expected = h.HashHexUpper();
        bytes[0] ^= 0xFF;
        Assert.Equal(expected, h.HashHexUpper());
        Assert.Same(bytes, h.HashBytes());
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
