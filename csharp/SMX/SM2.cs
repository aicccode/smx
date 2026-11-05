using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using System.Text;

namespace SMX;

public class SM2KeySwapParams
{
    public string Sa { get; set; } = "";
    public string Sb { get; set; } = "";
    public string Ka { get; set; } = "";
    public string Kb { get; set; } = "";
    public ECPoint V { get; set; }
    public byte[] Za { get; set; } = [];
    public byte[] Zb { get; set; } = [];
    public bool Success { get; set; }
    public string Message { get; set; } = "";
}

public static class SM2
{
    private const int CoordinateSize = 32;
    private const int HashSize = Sm3Hasher.DigestSize;
    private const int C1Size = 65;
    private const int C1HexLength = C1Size * 2;
    private const int C3HexLength = HashSize * 2;
    private const int StackUtf8Chars = 170;
    private const int ScalarHexLength = CoordinateSize * 2;

    /// <summary>The fixed part of the Z hash input: curve parameters a, b, Gx and Gy.</summary>
    private static readonly byte[] CurveParameters = BuildCurveParameters();

    private static byte[] BuildCurveParameters()
    {
        var o = new byte[4 * CoordinateSize];
        ECPoint.SM2_A.Value.WriteBigEndian(o);
        ECPoint.SM2_B.Value.WriteBigEndian(o.AsSpan(CoordinateSize));
        Sm2Group.Gx.WriteBigEndian(o.AsSpan(2 * CoordinateSize));
        Sm2Group.Gy.WriteBigEndian(o.AsSpan(3 * CoordinateSize));
        return o;
    }

    public static (string privateKey, string publicKey) GenKeyPair()
    {
        var pri = NextScalar();
        Sm2Group.MultiplyGeneratorSecret(pri, out var pub);
        return (pri.ToHex(), Sm2Group.ToAffine(pub).ToHexEncoded());
    }

    public static string Encrypt(string plaintext, string publicKey)
    {
        int messageLength = Encoding.UTF8.GetByteCount(plaintext);
        if (messageLength == 0)
        {
            throw new ArgumentException("plaintext cannot be empty");
        }

        var pubPoint = ECPoint.FromHexEncoded(publicKey);
        if (!pubPoint.IsOnCurve())
        {
            throw new ArgumentException("invalid public key");
        }

        // One buffer laid out as C1 || C3 || C2; C2 starts as the plaintext and is enciphered in place.
        var output = new byte[C1Size + HashSize + messageLength];
        Span<byte> c1Out = output.AsSpan(0, C1Size);
        Span<byte> c3Out = output.AsSpan(C1Size, HashSize);
        Span<byte> c2 = output.AsSpan(C1Size + HashSize);
        Encoding.UTF8.GetBytes(plaintext, c2);
        var basePoint = JacobianPoint.FromAffine(pubPoint);

        while (true)
        {
            var k = NextScalar();
            Sm2Group.MultiplyGeneratorSecret(k, out var c1Jacobian);
            Sm2Group.MultiplySecret(basePoint, k, out var p2Jacobian);
            if (p2Jacobian.IsInfinity)
            {
                continue;
            }
            Sm2Group.ToAffine(c1Jacobian, p2Jacobian, out var c1, out var p2);

            // C3 covers the plaintext, so it is hashed before the keystream goes in. An all-zero keystream leaves the
            // buffer unchanged, which is exactly the state the retry needs.
            HashWithPoint(p2, c2, c3Out);
            if (KdfXor(p2, c2))
            {
                c1.WriteUncompressed(c1Out);
                return HexUtils.BytesToHex(output);
            }
        }
    }

    public static string Decrypt(string ciphertext, string privateKey)
    {
        if (ciphertext.Length < C1HexLength + C3HexLength)
        {
            throw new ArgumentException("ciphertext too short");
        }

        ReadOnlySpan<char> text = ciphertext;
        var c1 = ECPoint.FromHexEncoded(text[..C1HexLength]);
        if (!c1.IsOnCurve())
        {
            throw new ArgumentException("invalid C1 point");
        }

        var c3 = HexUtils.HexToBytes(text.Slice(C1HexLength, C3HexLength));
        var c2 = HexUtils.HexToBytes(text[(C1HexLength + C3HexLength)..]);

        var d = BigInt256.FromHex(privateKey);
        var p2 = c1.Multiply(d);
        if (p2.Infinity)
        {
            throw new InvalidOperationException("invalid decryption");
        }

        KdfXor(p2, c2);

        Span<byte> computedC3 = stackalloc byte[HashSize];
        HashWithPoint(p2, c2, computedC3);
        if (!CryptographicOperations.FixedTimeEquals(computedC3, c3))
        {
            throw new InvalidOperationException("decryption verification failed");
        }

        return Encoding.UTF8.GetString(c2);
    }

    public static string Sign(string userID, string message, string privateKey)
    {
        var d = BigInt256.FromHex(privateKey);
        var k = NextScalar();

        // The public key and the first nonce point are normalized together to share one field inversion.
        Sm2Group.MultiplyGeneratorSecret(d, out var publicJacobian);
        Sm2Group.MultiplyGeneratorSecret(k, out var nonceJacobian);
        Sm2Group.ToAffine(publicJacobian, nonceJacobian, out var publicKey, out var noncePoint);

        var e = MessageDigest(userID, message, publicKey);
        Sm2Order.Invert(d.Add(BigInt256.One, out _), out var dPlus1Inverse);

        while (true)
        {
            if (TrySign(e, d, dPlus1Inverse, k, noncePoint.X.Value, out var r, out var s))
            {
                Span<char> chars = stackalloc char[2 * ScalarHexLength + 1];
                Span<byte> bytes = stackalloc byte[CoordinateSize];
                r.WriteBigEndian(bytes);
                HexUtils.EncodeLower(bytes, chars);
                chars[ScalarHexLength] = 'h';
                s.WriteBigEndian(bytes);
                HexUtils.EncodeLower(bytes, chars[(ScalarHexLength + 1)..]);
                return new string(chars);
            }

            k = NextScalar();
            Sm2Group.MultiplyGeneratorSecret(k, out nonceJacobian);
            noncePoint = Sm2Group.ToAffine(nonceJacobian);
        }
    }

    /// <summary>The signing equations for a given nonce; false when the standard requires drawing a new one.</summary>
    internal static bool TrySign(in BigInt256 e, in BigInt256 d, in BigInt256 dPlus1Inverse, in BigInt256 k, in BigInt256 nonceX, out BigInt256 r, out BigInt256 s)
    {
        s = default;
        r = e.ModAdd(nonceX, Sm2Order.N);
        if (r.IsZero)
        {
            return false;
        }

        var rk = r.Add(k, out _);
        if (rk == Sm2Order.N)
        {
            return false;
        }

        Sm2Order.Mul(r, d, out var rd);
        var kMinusRd = k.ModSub(rd, Sm2Order.N);
        Sm2Order.Mul(kMinusRd, dPlus1Inverse, out s);
        return !s.IsZero;
    }

    public static bool Verify(string userID, string signature, string message, string publicKey)
    {
        int separator = signature.IndexOf('h');
        if (separator < 0 || signature.IndexOf('h', separator + 1) >= 0)
        {
            return false;
        }

        var r = BigInt256.FromHex(signature.AsSpan(0, separator));
        var s = BigInt256.FromHex(signature.AsSpan(separator + 1));

        if ((Sm2Order.InRangeMask(r) & Sm2Order.InRangeMask(s)) == 0)
        {
            return false;
        }

        var pubPoint = ECPoint.FromHexEncoded(publicKey);
        if (!pubPoint.IsOnCurve())
        {
            return false;
        }

        var e = MessageDigest(userID, message, pubPoint);

        var t = r.ModAdd(s, Sm2Order.N);
        if (t.IsZero)
        {
            return false;
        }

        // Everything in this computation is public, so it may run in variable time.
        Sm2Group.MultiplyTwinPublic(s, t, pubPoint, out var point);
        if (point.IsInfinity)
        {
            return false;
        }
        return MatchesSignatureR(e, r, point);
    }

    /// <summary>
    /// Tests whether r = e + x (the same reduction as <see cref="BigInt256.ModAdd"/>, modulo n) where x is the affine x
    /// of a finite point, without the field inversion: each candidate value c of x is checked as c * Z^2 = X. Candidates
    /// are r - e when non-negative, and r + n - e taken modulo 2^256, which includes the case where e + x overflows.
    /// </summary>
    internal static bool MatchesSignatureR(in BigInt256 e, in BigInt256 r, in JacobianPoint point)
    {
        Fp.Square(point.Z, out var zSquared);

        var withoutWrap = r.Sub(e, out ulong borrow);
        if (borrow == 0 && IsAffineX(withoutWrap, zSquared, point.X))
        {
            return true;
        }

        var plusN = r.Add(Sm2Order.N, out ulong carry);
        var withWrap = plusN.Sub(e, out ulong wrapBorrow);
        bool representable = carry == wrapBorrow || wrapBorrow != 0;
        return representable && IsAffineX(withWrap, zSquared, point.X);
    }

    private static bool IsAffineX(in BigInt256 candidate, in BigInt256 zSquared, in BigInt256 x)
    {
        if (candidate.Compare(Fp.P) >= 0)
        {
            return false;
        }
        Fp.Mul(candidate, zSquared, out var scaled);
        return scaled == x;
    }

    public static SM2KeySwapParams GetSb(int byteLen, ECPoint pA, ECPoint rA, ECPoint pB,
        BigInt256 dB, ECPoint rB, BigInt256 rb, string idA, string idB)
    {
        var result = new SM2KeySwapParams();

        var x2 = CalcX(rB.X.Value);
        var tb = CalcT(rb, dB, x2);

        if (!rA.IsOnCurve())
        {
            result.Message = "RA point is not on curve";
            return result;
        }

        var x1 = CalcX(rA.X.Value);
        var v = CalcPoint(tb, x1, pA, rA);
        if (v.Infinity)
        {
            result.Message = "V is point at infinity";
            return result;
        }

        var za = UserZ(idA, pA);
        var zb = UserZ(idB, pB);

        var kb = KdfKeySwap(byteLen, v, za, zb);
        var sb = CreateS(0x02, v, za, zb, rA, rB);

        result.Sb = HexUtils.BytesToHex(sb);
        result.Kb = HexUtils.BytesToHex(kb);
        result.V = v;
        result.Za = za;
        result.Zb = zb;
        result.Success = true;
        return result;
    }

    public static SM2KeySwapParams GetSa(int byteLen, ECPoint pB, ECPoint rB, ECPoint pA,
        BigInt256 dA, ECPoint rA, BigInt256 ra, string idA, string idB, byte[] sb)
    {
        var result = new SM2KeySwapParams();

        var x1 = CalcX(rA.X.Value);
        var ta = CalcT(ra, dA, x1);

        if (!rB.IsOnCurve())
        {
            result.Message = "RB point is not on curve";
            return result;
        }

        var x2 = CalcX(rB.X.Value);
        var u = CalcPoint(ta, x2, pB, rB);
        if (u.Infinity)
        {
            result.Message = "U is point at infinity";
            return result;
        }

        var za = UserZ(idA, pA);
        var zb = UserZ(idB, pB);

        var ka = KdfKeySwap(byteLen, u, za, zb);
        var s1 = CreateS(0x02, u, za, zb, rA, rB);

        if (!CryptographicOperations.FixedTimeEquals(s1, sb))
        {
            result.Message = "B's verification value does not match";
            return result;
        }

        var sa = CreateS(0x03, u, za, zb, rA, rB);
        result.Sa = HexUtils.BytesToHex(sa);
        result.Ka = HexUtils.BytesToHex(ka);
        result.Success = true;
        return result;
    }

    public static bool CheckSa(ECPoint v, byte[] za, byte[] zb, ECPoint rA, ECPoint rB, byte[] sa)
    {
        var s2 = CreateS(0x03, v, za, zb, rA, rB);
        return CryptographicOperations.FixedTimeEquals(s2, sa);
    }

    public static ECPoint DecodePoint(string hexStr) => ECPoint.FromHexEncoded(hexStr);

    public static ECPoint GetPublicKey(BigInt256 privateKey) => ECPoint.Generator().Multiply(privateKey);

    // --- internal helpers ---

    /// <summary>A uniformly random scalar in [1, n-1], from the system CSPRNG by rejection sampling.</summary>
    private static BigInt256 NextScalar()
    {
        Span<byte> bytes = stackalloc byte[CoordinateSize];
        while (true)
        {
            RandomNumberGenerator.Fill(bytes);
            var candidate = BigInt256.FromBigEndian(bytes);
            if (Sm2Order.InRangeMask(candidate) != 0)
            {
                CryptographicOperations.ZeroMemory(bytes);
                return candidate;
            }
        }
    }

    /// <summary>SM3(x || data || y), as used for C3.</summary>
    private static void HashWithPoint(in ECPoint p, ReadOnlySpan<byte> data, Span<byte> digest)
    {
        Span<byte> coordinate = stackalloc byte[CoordinateSize];
        var h = Sm3Hasher.Create();
        p.X.Value.WriteBigEndian(coordinate);
        h.Update(coordinate);
        h.Update(data);
        p.Y.Value.WriteBigEndian(coordinate);
        h.Update(coordinate);
        h.Finish(digest);
    }

    /// <summary>XORs the KDF(x || y) stream into data; returns false when the whole stream was zero.</summary>
    private static bool KdfXor(in ECPoint p2, Span<byte> data)
    {
        var prefix = Sm3Hasher.Create();
        UpdateCoordinates(ref prefix, p2);
        return KdfXor(prefix, data);
    }

    private static byte[] KdfKeySwap(int keyLength, in ECPoint vu, byte[] za, byte[] zb)
    {
        var key = new byte[keyLength];
        var prefix = Sm3Hasher.Create();
        UpdateCoordinates(ref prefix, vu);
        prefix.Update(za);
        prefix.Update(zb);
        KdfXor(prefix, key);
        return key;
    }

    /// <summary>
    /// The KDF: blocks SM3(prefix || counter) for a big-endian counter from 1. The prefix's absorbed state is reused,
    /// so a long stream costs one compression per 32 bytes rather than one per 64 bytes of prefix as well.
    /// </summary>
    [SkipLocalsInit]
    private static bool KdfXor(in Sm3Hasher prefix, Span<byte> data)
    {
        Span<byte> block = stackalloc byte[HashSize];
        ulong seen = 0;
        uint counter = 1;
        for (int offset = 0; offset < data.Length; offset += HashSize)
        {
            prefix.FinishWithCounter(counter++, block);

            int count = Math.Min(HashSize, data.Length - offset);
            if (count == HashSize)
            {
                var words = MemoryMarshal.Cast<byte, ulong>(block);
                seen |= words[0] | words[1] | words[2] | words[3];
                ref byte target = ref MemoryMarshal.GetReference(data[offset..]);
                (Vector256.Create<byte>(block) ^ Vector256.LoadUnsafe(ref target)).StoreUnsafe(ref target);
                continue;
            }

            var tail = data[offset..];
            for (int i = 0; i < count; i++)
            {
                seen |= block[i];
                tail[i] ^= block[i];
            }
        }
        return seen != 0;
    }

    private static void UpdateCoordinates(ref Sm3Hasher h, in ECPoint p)
    {
        Span<byte> coordinates = stackalloc byte[2 * CoordinateSize];
        p.X.Value.WriteBigEndian(coordinates);
        p.Y.Value.WriteBigEndian(coordinates[CoordinateSize..]);
        h.Update(coordinates);
    }

    private static void UpdateUtf8(ref Sm3Hasher h, string text)
    {
        if (text.Length <= StackUtf8Chars)
        {
            Span<byte> bytes = stackalloc byte[StackUtf8Chars * 3];
            int written = Encoding.UTF8.GetBytes(text, bytes);
            h.Update(bytes[..written]);
        }
        else
        {
            h.Update(Encoding.UTF8.GetBytes(text));
        }
    }

    private static void ComputeZ(string userID, in ECPoint publicKey, Span<byte> z)
    {
        // The length field is 16 bits; identities of 8 KiB or more wrap, as they always have here.
        int idByteCount = Encoding.UTF8.GetByteCount(userID);
        ushort entl = (ushort)(idByteCount * 8);
        Span<byte> entlBytes = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(entlBytes, entl);

        var h = Sm3Hasher.Create();
        h.Update(entlBytes);
        UpdateUtf8(ref h, userID);
        h.Update(CurveParameters);
        UpdateCoordinates(ref h, publicKey);
        h.Finish(z);
    }

    private static byte[] UserZ(string userID, in ECPoint publicKey)
    {
        var z = new byte[HashSize];
        ComputeZ(userID, publicKey, z);
        return z;
    }

    /// <summary>e = SM3(Z || message) as an integer.</summary>
    internal static BigInt256 MessageDigest(string userID, string message, in ECPoint publicKey)
    {
        Span<byte> digest = stackalloc byte[HashSize];
        ComputeZ(userID, publicKey, digest);
        var h = Sm3Hasher.Create();
        h.Update(digest);
        UpdateUtf8(ref h, message);
        h.Finish(digest);
        return BigInt256.FromBigEndian(digest);
    }

    /// <summary>x-bar = 2^127 + (x mod 2^127).</summary>
    private static BigInt256 CalcX(in BigInt256 x) => new(x.L0, (x.L1 & 0x7FFFFFFFFFFFFFFF) | 0x8000000000000000, 0, 0);

    private static BigInt256 CalcT(in BigInt256 r, in BigInt256 d, in BigInt256 xBar)
    {
        Sm2Order.Mul(xBar, r, out var xr);
        return d.ModAdd(xr, Sm2Order.N);
    }

    /// <summary>t * (p + xBar * r). xBar comes from a public point; t involves private keys.</summary>
    private static ECPoint CalcPoint(in BigInt256 t, in BigInt256 xBar, in ECPoint p, in ECPoint r)
    {
        Sm2Group.MultiplyPublic(xBar, r, out var sum);
        if (!p.Infinity)
        {
            Sm2Group.AddMixedPublic(sum, p.X.Value, p.Y.Value, out sum);
        }
        Sm2Group.MultiplySecret(sum, t, out var result);
        return Sm2Group.ToAffine(result);
    }

    private static byte[] CreateS(byte tag, in ECPoint vu, byte[] za, byte[] zb, in ECPoint ra, in ECPoint rb)
    {
        Span<byte> coordinate = stackalloc byte[CoordinateSize];
        Span<byte> inner = stackalloc byte[HashSize];

        var h = Sm3Hasher.Create();
        vu.X.Value.WriteBigEndian(coordinate);
        h.Update(coordinate);
        h.Update(za);
        h.Update(zb);
        UpdateCoordinates(ref h, ra);
        UpdateCoordinates(ref h, rb);
        h.Finish(inner);

        var outer = Sm3Hasher.Create();
        outer.UpdateByte(tag);
        vu.Y.Value.WriteBigEndian(coordinate);
        outer.Update(coordinate);
        outer.Update(inner);
        var result = new byte[HashSize];
        outer.Finish(result);
        return result;
    }
}
