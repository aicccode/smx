using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;

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

/// <summary>
/// SM2 sign, verify, encrypt, decrypt and key exchange. Hex must have its exact length and no prefix. Keys may use either
/// case; signatures and ciphertexts must be lowercase, as this library writes them. Failures: <see cref="Verify"/> and <see cref="CheckSa"/> return false, GetSa and GetSb
/// report through <see cref="SM2KeySwapParams.Success"/>, and everything else throws <see cref="ArgumentException"/> for
/// invalid input and <see cref="InvalidOperationException"/> for ciphertext that fails verification.
/// <see cref="CryptographicException"/> means the system random generator failed or returned unusable output.
/// </summary>
public static class SM2
{
    private const int CoordinateSize = 32;
    private const int HashSize = Sm3Hasher.DigestSize;
    private const int C1Size = 65;
    private const int C1HexLength = C1Size * 2;
    private const int C3HexLength = HashSize * 2;
    private const int Utf8ChunkChars = 170;

    /// <summary>Room for one more character, the half of a surrogate pair the encoder may carry over from the last piece.</summary>
    private const int Utf8ChunkBytes = (Utf8ChunkChars + 1) * 3;
    private const int ScalarHexLength = CoordinateSize * 2;
    private const int MaxUserIdBytes = 8191;
    private const int MaxExchangeKeyBytes = 1024 * 1024;
    private const int ExpectedConfirmationSize = HashSize;

    /// <summary>Attempts before concluding the RNG is broken: any one draw is rejected with probability about 2^-32.</summary>
    private const int MaxRandomDraws = 128;

    /// <summary>Attempts at signing or encrypting, each of which can fail only with negligible probability.</summary>
    private const int MaxNonceAttempts = 16;

    private const string InvalidPrivateKey = "invalid private key";
    private const string InvalidPublicKey = "invalid public key";
    private const string DecryptionFailed = "decryption verification failed";

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>A source of random bytes, replaced only by tests to exercise failures.</summary>
    internal delegate void RandomSource(Span<byte> output);

    private static readonly RandomSource SystemRandom = RandomNumberGenerator.Fill;

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

    /// <summary>Generates a private key uniformly in [1, n-2] from the system CSPRNG, and its public key.</summary>
    /// <exception cref="CryptographicException">The system random generator failed.</exception>
    public static (string privateKey, string publicKey) GenKeyPair()
    {
        var pri = NextPrivateKey(SystemRandom);
        Sm2Group.MultiplyGeneratorSecret(pri, out var pub);
        return (pri.ToHex(), Sm2Group.ToAffine(pub).ToHexEncoded());
    }

    /// <summary>Encrypts the UTF-8 form of the text, giving C1 || C3 || C2 in lowercase hex.</summary>
    /// <exception cref="ArgumentException">Empty or unencodable text, or an invalid public key.</exception>
    /// <exception cref="CryptographicException">The system random generator failed.</exception>
    public static string Encrypt(string plaintext, string publicKey)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(publicKey);
        int messageLength = StrictUtf8.GetByteCount(plaintext);
        if (messageLength == 0)
        {
            throw new ArgumentException("plaintext cannot be empty");
        }
        if (messageLength > HexUtils.MaxHexBytes - C1Size - HashSize)
        {
            throw new ArgumentException("plaintext too long");
        }

        if (!ECPoint.TryParse(publicKey, out var pubPoint))
        {
            throw new ArgumentException(InvalidPublicKey);
        }

        // One buffer laid out as C1 || C3 || C2; C2 starts as the plaintext and is enciphered in place.
        var output = new byte[C1Size + HashSize + messageLength];
        Span<byte> c1Out = output.AsSpan(0, C1Size);
        Span<byte> c3Out = output.AsSpan(C1Size, HashSize);
        Span<byte> c2 = output.AsSpan(C1Size + HashSize);
        StrictUtf8.GetBytes(plaintext, c2);
        var basePoint = JacobianPoint.FromAffine(pubPoint);

        for (int attempt = 0; attempt < MaxNonceAttempts; attempt++)
        {
            var k = NextNonce(SystemRandom);
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
        CryptographicOperations.ZeroMemory(output);
        throw new CryptographicException("encryption failed");
    }

    /// <summary>
    /// Decrypts C1 || C3 || C2 in lowercase hex, exactly as <see cref="Encrypt"/> writes it, to text. C2 must not be empty
    /// and the plaintext must be valid UTF-8. UTF-8 validation runs whether or not C3 matched, so both failures do the same
    /// work apart from content-dependent time in that validation. Use <see cref="DecryptToBytes"/> for data that is not text.
    /// </summary>
    /// <exception cref="ArgumentException">Malformed ciphertext, or an invalid private key.</exception>
    /// <exception cref="InvalidOperationException">The ciphertext does not verify under this key.</exception>
    public static string Decrypt(string ciphertext, string privateKey)
    {
        var plaintext = DecipherAndVerify(ciphertext, privateKey, out bool verified);
        try
        {
            bool utf8Valid = Utf8.IsValid(plaintext);
            if (!verified | !utf8Valid)
            {
                throw new InvalidOperationException(DecryptionFailed);
            }
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Decrypts as <see cref="Decrypt"/> does, to bytes, with no UTF-8 step. The caller should clear the result when done.
    /// </summary>
    /// <exception cref="ArgumentException">Malformed ciphertext, or an invalid private key.</exception>
    /// <exception cref="InvalidOperationException">The ciphertext does not verify under this key.</exception>
    public static byte[] DecryptToBytes(string ciphertext, string privateKey)
    {
        var plaintext = DecipherAndVerify(ciphertext, privateKey, out bool verified);
        if (!verified)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new InvalidOperationException(DecryptionFailed);
        }
        return plaintext;
    }

    private static byte[] DecipherAndVerify(string ciphertext, string privateKey, out bool verified)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(privateKey);
        if (ciphertext.Length <= C1HexLength + C3HexLength)
        {
            throw new ArgumentException("ciphertext too short");
        }
        if ((ciphertext.Length & 1) != 0 || !HexUtils.IsLowerCaseOnly(ciphertext))
        {
            throw new ArgumentException("invalid ciphertext");
        }

        ReadOnlySpan<char> text = ciphertext;
        if (!ECPoint.TryParse(text[..C1HexLength], out var c1))
        {
            throw new ArgumentException("invalid C1 point");
        }

        Span<byte> c3 = stackalloc byte[HashSize];
        var c2 = new byte[(ciphertext.Length - C1HexLength - C3HexLength) / 2];
        if (!HexUtils.TryDecode(text.Slice(C1HexLength, C3HexLength), c3)
            || !HexUtils.TryDecode(text[(C1HexLength + C3HexLength)..], c2))
        {
            throw new ArgumentException("invalid ciphertext");
        }

        var d = ParsePrivateKey(privateKey);
        Sm2Group.MultiplySecret(JacobianPoint.FromAffine(c1), d, out var p2Jacobian);
        var p2 = Sm2Group.ToAffine(p2Jacobian);
        if (p2.Infinity)
        {
            throw new InvalidOperationException(DecryptionFailed);
        }

        bool keystreamUsable = KdfXor(p2, c2);
        Span<byte> computedC3 = stackalloc byte[HashSize];
        HashWithPoint(p2, c2, computedC3);
        verified = CryptographicOperations.FixedTimeEquals(computedC3, c3) & keystreamUsable;
        return c2;
    }

    /// <summary>Signs and returns r and s in lowercase hex, joined by "h". The user ID may be up to 8191 UTF-8 bytes.</summary>
    /// <exception cref="ArgumentException">An invalid private key, or text that is too long or not encodable.</exception>
    /// <exception cref="CryptographicException">The system random generator failed.</exception>
    public static string Sign(string userID, string message, string privateKey)
    {
        ArgumentNullException.ThrowIfNull(userID);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(privateKey);
        var d = ParsePrivateKey(privateKey);
        var k = NextNonce(SystemRandom);

        // The public key and the first nonce point are normalized together to share one field inversion.
        Sm2Group.MultiplyGeneratorSecret(d, out var publicJacobian);
        Sm2Group.MultiplyGeneratorSecret(k, out var nonceJacobian);
        Sm2Group.ToAffine(publicJacobian, nonceJacobian, out var publicKey, out var noncePoint);

        var e = MessageDigest(userID, message, publicKey);
        Sm2Order.Invert(d.Add(BigInt256.One, out _), out var dPlus1Inverse);

        for (int attempt = 0; attempt < MaxNonceAttempts; attempt++)
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

            k = NextNonce(SystemRandom);
            Sm2Group.MultiplyGeneratorSecret(k, out nonceJacobian);
            noncePoint = Sm2Group.ToAffine(nonceJacobian);
        }
        throw new CryptographicException("signing failed");
    }

    /// <summary>The signing equations for a given nonce; false when the standard requires drawing a new one.</summary>
    internal static bool TrySign(in BigInt256 e, in BigInt256 d, in BigInt256 dPlus1Inverse, in BigInt256 k, in BigInt256 nonceX, out BigInt256 r, out BigInt256 s)
    {
        s = default;

        // Both e and x can be at or above n, so each is reduced before the modular addition assumes otherwise.
        Sm2Order.ReduceOnce(e, out var eReduced);
        Sm2Order.ReduceOnce(nonceX, out var xReduced);
        r = eReduced.ModAdd(xReduced, Sm2Order.N);
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

    /// <summary>
    /// True only for a signature of exactly 64 lowercase hex digits for each of r and s, joined by "h", as
    /// <see cref="Sign"/> writes it, so that a signature has one string form, and valid for the exact encoding of a valid
    /// public key. Every kind of invalid input, null included, gives false; this never throws for them.
    /// </summary>
    public static bool Verify(string userID, string signature, string message, string publicKey)
    {
        if (userID is null || signature is null || message is null || publicKey is null)
        {
            return false;
        }

        if (signature.Length != 2 * ScalarHexLength + 1 || signature[ScalarHexLength] != 'h')
        {
            return false;
        }

        ReadOnlySpan<char> text = signature;
        if (!HexUtils.IsLowerCaseOnly(text))
        {
            return false;
        }
        if (!BigInt256.TryParseExact(text[..ScalarHexLength], out var r)
            || !BigInt256.TryParseExact(text[(ScalarHexLength + 1)..], out var s))
        {
            return false;
        }

        if ((Sm2Order.InRangeMask(r) & Sm2Order.InRangeMask(s)) == 0)
        {
            return false;
        }

        if (!ECPoint.TryParse(publicKey, out var pubPoint))
        {
            return false;
        }

        BigInt256 e;
        try
        {
            e = MessageDigest(userID, message, pubPoint);
        }
        catch (ArgumentException)
        {
            // The ID is too long, or some text has no UTF-8 form. No signature can cover those.
            return false;
        }

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
    /// Tests whether r = (e + x) mod n, where x is the affine x of a finite point, without the field inversion. Since x
    /// lies in [0, p) and p exceeds n, its candidates are c = (r - e) mod n and c + n, each checked as c * Z^2 = X.
    /// </summary>
    internal static bool MatchesSignatureR(in BigInt256 e, in BigInt256 r, in JacobianPoint point)
    {
        Fp.Square(point.Z, out var zSquared);
        Sm2Order.ReduceOnce(e, out var eReduced);
        var candidate = r.ModSub(eReduced, Sm2Order.N);
        if (IsAffineX(candidate, zSquared, point.X))
        {
            return true;
        }

        var plusN = candidate.Add(Sm2Order.N, out ulong carry);
        return carry == 0 && IsAffineX(plusN, zSquared, point.X);
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

    /// <summary>
    /// Responder's step of key exchange. Validates all points and private values. Fails through Success and Message, with a
    /// key length outside 1 to 1 MiB bytes, an invalid point or private value, or a user ID over 8191 bytes.
    /// </summary>
    public static SM2KeySwapParams GetSb(int byteLen, ECPoint pA, ECPoint rA, ECPoint pB,
        BigInt256 dB, ECPoint rB, BigInt256 rb, string idA, string idB)
    {
        var result = new SM2KeySwapParams();

        if (!rA.IsOnCurve())
        {
            result.Message = "RA point is not on curve";
            return result;
        }

        var failure = ValidateExchange(byteLen, pA, pB, rB, dB, rb, idA, idB);
        if (failure != null)
        {
            result.Message = failure;
            return result;
        }

        var x2 = CalcX(rB.X.Value);
        var tb = CalcT(rb, dB, x2);
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
        CryptographicOperations.ZeroMemory(kb);
        result.V = v;
        result.Za = za;
        result.Zb = zb;
        result.Success = true;
        return result;
    }

    /// <summary>
    /// Initiator's step of key exchange, with the same validation as <see cref="GetSb"/>. The confirmation value from B
    /// must be exactly 32 bytes and match; the comparison is constant time.
    /// </summary>
    public static SM2KeySwapParams GetSa(int byteLen, ECPoint pB, ECPoint rB, ECPoint pA,
        BigInt256 dA, ECPoint rA, BigInt256 ra, string idA, string idB, byte[] sb)
    {
        var result = new SM2KeySwapParams();

        if (!rB.IsOnCurve())
        {
            result.Message = "RB point is not on curve";
            return result;
        }

        var failure = ValidateExchange(byteLen, pA, pB, rA, dA, ra, idA, idB);
        if (failure != null)
        {
            result.Message = failure;
            return result;
        }

        if (sb == null || sb.Length != ExpectedConfirmationSize)
        {
            result.Message = "B's verification value does not match";
            return result;
        }

        var x1 = CalcX(rA.X.Value);
        var ta = CalcT(ra, dA, x1);
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
            CryptographicOperations.ZeroMemory(ka);
            result.Message = "B's verification value does not match";
            return result;
        }

        var sa = CreateS(0x03, u, za, zb, rA, rB);
        result.Sa = HexUtils.BytesToHex(sa);
        result.Ka = HexUtils.BytesToHex(ka);
        CryptographicOperations.ZeroMemory(ka);
        result.Success = true;
        return result;
    }

    /// <summary>Checks everything shared by both sides of the exchange; returns the failure, or null when all is valid.</summary>
    private static string? ValidateExchange(int byteLen, in ECPoint pA, in ECPoint pB, in ECPoint ownR, in BigInt256 ownD, in BigInt256 ownEphemeral, string idA, string idB)
    {
        if (byteLen < 1 || byteLen > MaxExchangeKeyBytes)
        {
            return "invalid key length";
        }
        if (!pA.IsOnCurve() || !pB.IsOnCurve() || !ownR.IsOnCurve())
        {
            return InvalidPublicKey;
        }
        if ((Sm2Order.PrivateKeyRangeMask(ownD) & Sm2Order.PrivateKeyRangeMask(ownEphemeral)) == 0)
        {
            return InvalidPrivateKey;
        }
        return IsUsableUserId(idA) && IsUsableUserId(idB) ? null : "invalid user ID";
    }

    private static bool IsUsableUserId(string id)
    {
        if (id is null)
        {
            return false;
        }
        try
        {
            return StrictUtf8.GetByteCount(id) <= MaxUserIdBytes;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Responder's final check of A's confirmation value. Gives false for invalid points, a Z value or confirmation that
    /// is not exactly 32 bytes, or a mismatch. The comparison is constant time.
    /// </summary>
    public static bool CheckSa(ECPoint v, byte[] za, byte[] zb, ECPoint rA, ECPoint rB, byte[] sa)
    {
        if (za == null || zb == null || sa == null
            || za.Length != HashSize || zb.Length != HashSize || sa.Length != ExpectedConfirmationSize)
        {
            return false;
        }
        if (!v.IsOnCurve() || !rA.IsOnCurve() || !rB.IsOnCurve())
        {
            return false;
        }
        var s2 = CreateS(0x03, v, za, zb, rA, rB);
        return CryptographicOperations.FixedTimeEquals(s2, sa);
    }

    /// <exception cref="ArgumentNullException"><paramref name="hexStr"/> is null.</exception>
    /// <exception cref="ArgumentException">The input is not an exact encoding of a point on the curve.</exception>
    public static ECPoint DecodePoint(string hexStr) => ECPoint.FromHexEncoded(hexStr);

    /// <summary>The public key of a private key in [1, n-2].</summary>
    /// <exception cref="ArgumentException">The private key is out of range.</exception>
    public static ECPoint GetPublicKey(BigInt256 privateKey)
    {
        if (Sm2Order.PrivateKeyRangeMask(privateKey) == 0)
        {
            throw new ArgumentException(InvalidPrivateKey);
        }
        Sm2Group.MultiplyGeneratorSecret(privateKey, out var result);
        return Sm2Group.ToAffine(result);
    }

    // --- internal helpers ---

    /// <summary>Exactly 64 hex digits, in [1, n-2]. The check examines all digits and limbs; the error says nothing else.</summary>
    private static BigInt256 ParsePrivateKey(ReadOnlySpan<char> hex)
    {
        bool wellFormed = BigInt256.TryParseExact(hex, out var d);
        if (!wellFormed || Sm2Order.PrivateKeyRangeMask(d) == 0)
        {
            throw new ArgumentException(InvalidPrivateKey);
        }
        return d;
    }

    /// <summary>A uniformly random signature or encryption nonce in [1, n-1], by rejection sampling.</summary>
    internal static BigInt256 NextNonce(RandomSource random) => NextScalar(random, static (in BigInt256 k) => Sm2Order.InRangeMask(k));

    /// <summary>A uniformly random private key in [1, n-2], by rejection sampling.</summary>
    internal static BigInt256 NextPrivateKey(RandomSource random) => NextScalar(random, static (in BigInt256 k) => Sm2Order.PrivateKeyRangeMask(k));

    private delegate ulong RangeMask(in BigInt256 k);

    private static BigInt256 NextScalar(RandomSource random, RangeMask inRange)
    {
        Span<byte> bytes = stackalloc byte[CoordinateSize];
        for (int attempt = 0; attempt < MaxRandomDraws; attempt++)
        {
            random(bytes);
            var candidate = BigInt256.FromBigEndian(bytes);
            if (inRange(candidate) != 0)
            {
                CryptographicOperations.ZeroMemory(bytes);
                return candidate;
            }
        }
        CryptographicOperations.ZeroMemory(bytes);
        throw new CryptographicException("random generator returned no usable value");
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
        h.Wipe();
        CryptographicOperations.ZeroMemory(coordinate);
    }

    /// <summary>XORs the KDF(x || y) stream into data; returns false when the whole stream was zero.</summary>
    private static bool KdfXor(in ECPoint p2, Span<byte> data)
    {
        var prefix = Sm3Hasher.Create();
        UpdateCoordinates(ref prefix, p2);
        bool usable = KdfXor(prefix, data);
        prefix.Wipe();
        return usable;
    }

    /// <summary>
    /// The exchanged key. Unlike encryption's keystream, an all-zero result is not rejected: the standard has no such step,
    /// and for a one-byte key it is an ordinary outcome of one exchange in 256.
    /// </summary>
    private static byte[] KdfKeySwap(int keyLength, in ECPoint vu, byte[] za, byte[] zb)
    {
        var key = new byte[keyLength];
        var prefix = Sm3Hasher.Create();
        UpdateCoordinates(ref prefix, vu);
        prefix.Update(za);
        prefix.Update(zb);
        KdfXor(prefix, key);
        prefix.Wipe();
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
        CryptographicOperations.ZeroMemory(block);
        return seen != 0;
    }

    private static void UpdateCoordinates(ref Sm3Hasher h, in ECPoint p)
    {
        Span<byte> coordinates = stackalloc byte[2 * CoordinateSize];
        p.X.Value.WriteBigEndian(coordinates);
        p.Y.Value.WriteBigEndian(coordinates[CoordinateSize..]);
        h.Update(coordinates);
        CryptographicOperations.ZeroMemory(coordinates);
    }

    /// <summary>
    /// Hashes the text's UTF-8 form piece by piece, so that text of any length needs no large buffer and cannot run out of
    /// memory here. The stateful encoder keeps surrogate pairs that straddle two pieces together and rejects lone ones.
    /// </summary>
    private static void UpdateUtf8(ref Sm3Hasher h, string text)
    {
        Span<byte> bytes = stackalloc byte[Utf8ChunkBytes];
        if (text.Length <= Utf8ChunkChars)
        {
            h.Update(bytes[..StrictUtf8.GetBytes(text, bytes)]);
            return;
        }

        var encoder = StrictUtf8.GetEncoder();
        ReadOnlySpan<char> rest = text;
        while (!rest.IsEmpty)
        {
            var piece = rest[..Math.Min(rest.Length, Utf8ChunkChars)];
            rest = rest[piece.Length..];
            int written = encoder.GetBytes(piece, bytes, flush: rest.IsEmpty);
            h.Update(bytes[..written]);
        }
    }

    private static void ComputeZ(string userID, in ECPoint publicKey, Span<byte> z)
    {
        // The length field holds a bit count in 16 bits, so longer identities cannot be represented. GetByteCount also
        // rejects text with no UTF-8 form, which could otherwise collide with a different string after replacement.
        int idByteCount = StrictUtf8.GetByteCount(userID);
        if (idByteCount > MaxUserIdBytes)
        {
            throw new ArgumentException("user ID too long");
        }
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
        h.Wipe();

        CryptographicOperations.ZeroMemory(coordinate);

        var outer = Sm3Hasher.Create();
        outer.UpdateByte(tag);
        vu.Y.Value.WriteBigEndian(coordinate);
        outer.Update(coordinate);
        outer.Update(inner);
        var result = new byte[HashSize];
        outer.Finish(result);
        outer.Wipe();
        CryptographicOperations.ZeroMemory(coordinate);
        CryptographicOperations.ZeroMemory(inner);
        return result;
    }
}
