using System.Security.Cryptography;
using System.Text;
using SMX.SM9Internal;

namespace SMX;

/// <summary>How <see cref="SM9.Encrypt(byte[], string, string, byte, SM9EncryptMode)"/> enciphers C2. The ciphertext does not record it.</summary>
public enum SM9EncryptMode
{
    /// <summary>C2 = M xor K1 with a KDF keystream as long as the message (the default of GB/T 38635.4).</summary>
    Stream = 0,

    /// <summary>C2 = SM4-ECB(K1, PKCS#7(M)) with a 16-byte K1, the block cipher mode of the standard's example.</summary>
    SM4 = 1,
}

/// <summary>The outcome of one side of SM9 key exchange. All values are lowercase hex; empty on failure.</summary>
public class SM9ExchangeResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = "";
    public string SharedKey { get; set; } = "";

    /// <summary>Responder only: S_B, sent to the initiator.</summary>
    public string Sb { get; set; } = "";

    /// <summary>Responder only: S_2, the value the initiator's S_A must equal; keep it for <see cref="SM9.ExchangeCheck"/>.</summary>
    public string S2 { get; set; } = "";

    /// <summary>Initiator only: S_A, sent to the responder.</summary>
    public string Sa { get; set; } = "";
}

/// <summary>
/// SM9 identity-based cryptography (GB/T 38635): key generation, signatures, key encapsulation, encryption and key
/// exchange. The conventions are those of <see cref="SM2"/>. Keys, public points and random values are hex of either
/// case and of exact length; signatures, ciphertexts and confirmation values must be lowercase, as this library writes
/// them. User identities are strings, hashed as strict UTF-8; empty identities are allowed. Failures:
/// <see cref="Verify(byte[], string, string, string, byte)"/> and <see cref="ExchangeCheck"/> return false, the exchange
/// steps report through <see cref="SM9ExchangeResult.Success"/>, and everything else throws
/// <see cref="ArgumentException"/> for invalid input and <see cref="InvalidOperationException"/> for a ciphertext that
/// does not decrypt. <see cref="CryptographicException"/> means the system random generator failed.
/// <para>
/// Secret scalars drive G1, G2 and GT exponentiations with a fixed window and masked full-table lookups, over
/// fixed-width Montgomery arithmetic with no secret-dependent branches; the pairing is constant time in both points.
/// </para>
/// </summary>
public static partial class SM9
{
    public const byte HidSign = 0x01;
    public const byte HidExchange = 0x02;
    public const byte HidEncrypt = 0x03;

    private const int ScalarSize = Sm9Scalar.ScalarSize;
    private const int ScalarHexLength = 2 * ScalarSize;
    private const int HashSize = Sm3Hasher.DigestSize;
    private const int SignatureSize = ScalarSize + G1Affine.EncodedSize;
    private const int MaxKeyBytes = 1024 * 1024;
    private const int MaxRandomDraws = 128;
    private const int MaxNonceAttempts = 16;

    private const string InvalidMasterPrivateKey = "invalid master private key";
    private const string InvalidMasterPublicKey = "invalid master public key";
    private const string InvalidUserPrivateKey = "invalid user private key";
    private const string InvalidUserId = "invalid user ID";
    private const string InvalidKeyLength = "invalid key length";
    private const string ZeroT1 = "t1 is zero for this master key and user ID; generate a new master key";

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private static readonly SM2.RandomSource SystemRandom = RandomNumberGenerator.Fill;

    // ------------------------------------------------------------------ keys

    /// <summary>A signing master key pair: ks uniform in [1, N-1] and Ppub-s = [ks]P2 (a G2 point).</summary>
    /// <exception cref="CryptographicException">The system random generator failed.</exception>
    public static (string masterPrivateKey, string masterPublicKey) GenSignMasterKey()
    {
        var ks = NextScalar(SystemRandom);
        return (Sm9Scalar.ToHex(ks), G2Affine.FromProjective(G2Affine.MultiplyGenerator(ks)).ToHex());
    }

    /// <summary>Ppub-s = [ks]P2 for a signing master private key.</summary>
    /// <exception cref="ArgumentException">The master private key is invalid.</exception>
    public static string GetSignMasterPublicKey(string masterPrivateKey) =>
        G2Affine.FromProjective(G2Affine.MultiplyGenerator(ParseScalar(masterPrivateKey, InvalidMasterPrivateKey))).ToHex();

    /// <summary>The signing private key ds = [ks / (H1(ID || hid) + ks)]P1 of a user (a G1 point).</summary>
    /// <exception cref="ArgumentException">An invalid master key or ID, or t1 = 0 for this pair (then use a new master key).</exception>
    public static string GenSignUserKey(string masterPrivateKey, string userId, byte hid = HidSign)
    {
        var ks = ParseScalar(masterPrivateKey, InvalidMasterPrivateKey);
        var t2 = UserKeyScalar(ks, IdBytes(userId), hid);
        return G1Affine.FromProjective(G1Affine.MultiplyGenerator(t2)).ToHex();
    }

    /// <summary>An encryption master key pair: ke uniform in [1, N-1] and Ppub-e = [ke]P1 (a G1 point).</summary>
    /// <exception cref="CryptographicException">The system random generator failed.</exception>
    public static (string masterPrivateKey, string masterPublicKey) GenEncMasterKey()
    {
        var ke = NextScalar(SystemRandom);
        return (Sm9Scalar.ToHex(ke), G1Affine.FromProjective(G1Affine.MultiplyGenerator(ke)).ToHex());
    }

    /// <summary>Ppub-e = [ke]P1 for an encryption master private key.</summary>
    /// <exception cref="ArgumentException">The master private key is invalid.</exception>
    public static string GetEncMasterPublicKey(string masterPrivateKey) =>
        G1Affine.FromProjective(G1Affine.MultiplyGenerator(ParseScalar(masterPrivateKey, InvalidMasterPrivateKey))).ToHex();

    /// <summary>
    /// The encryption (and key exchange) private key de = [ke / (H1(ID || hid) + ke)]P2 of a user (a G2 point). Key
    /// exchange keys use <see cref="HidExchange"/>.
    /// </summary>
    /// <exception cref="ArgumentException">An invalid master key or ID, or t1 = 0 for this pair (then use a new master key).</exception>
    public static string GenEncUserKey(string masterPrivateKey, string userId, byte hid = HidEncrypt)
    {
        var ke = ParseScalar(masterPrivateKey, InvalidMasterPrivateKey);
        var t2 = UserKeyScalar(ke, IdBytes(userId), hid);
        return G2Affine.FromProjective(G2Affine.MultiplyGenerator(t2)).ToHex();
    }

    /// <summary>t2 = s * (H1(ID || hid) + s)^-1 mod N, all in constant time apart from the t1 = 0 check.</summary>
    private static BigInt256 UserKeyScalar(in BigInt256 masterKey, byte[] id, byte hid)
    {
        var t1 = Sm9Scalar.Add(H1(id, hid), masterKey);
        if (t1.IsZero)
        {
            throw new ArgumentException(ZeroT1);
        }
        return Sm9Scalar.Mul(masterKey, Sm9Scalar.Invert(t1));
    }

    // ------------------------------------------------------------------ signatures

    /// <summary>Signs the UTF-8 form of the text; see <see cref="Sign(byte[], string, string)"/>.</summary>
    /// <exception cref="ArgumentException">Text with no UTF-8 form, or an invalid key.</exception>
    /// <exception cref="CryptographicException">The system random generator failed.</exception>
    public static string Sign(string message, string userPrivateKey, string masterPublicKey)
    {
        ArgumentNullException.ThrowIfNull(message);
        return Sign(StrictUtf8.GetBytes(message), userPrivateKey, masterPublicKey);
    }

    /// <summary>Signs with the user's signing key ds; returns h || S, 97 bytes, in lowercase hex.</summary>
    /// <exception cref="ArgumentException">An invalid user private key or signing master public key.</exception>
    /// <exception cref="CryptographicException">The system random generator failed.</exception>
    public static string Sign(byte[] message, string userPrivateKey, string masterPublicKey)
    {
        ArgumentNullException.ThrowIfNull(message);
        var ds = ParseG1(userPrivateKey, InvalidUserPrivateKey);
        var master = SignMaster(masterPublicKey);
        for (int attempt = 0; attempt < MaxNonceAttempts; attempt++)
        {
            var r = NextScalar(SystemRandom);
            if (TrySign(message, ds, master.G, r, out var signature))
            {
                return signature;
            }
        }
        throw new CryptographicException("signing failed");
    }

    /// <summary>Signs with a given r, for known-answer tests.</summary>
    internal static string SignWithRandom(byte[] message, string userPrivateKey, string masterPublicKey, string rHex)
    {
        var ds = ParseG1(userPrivateKey, InvalidUserPrivateKey);
        var master = SignMaster(masterPublicKey);
        var r = ParseScalar(rHex, "invalid r");
        return TrySign(message, ds, master.G, r, out var signature)
            ? signature
            : throw new InvalidOperationException("l = 0 for this r");
    }

    /// <summary>w = g^r, h = H2(M || w), l = (r - h) mod N, S = [l]ds; false when l = 0, which needs a new r.</summary>
    private static bool TrySign(byte[] message, in G1Affine ds, in Fq12 g, in BigInt256 r, out string signature)
    {
        signature = "";
        var w = Fq12.PowGt(g, r);
        var h = H2(message, w);
        var l = Sm9Scalar.Sub(r, h);
        if (l.IsZero)
        {
            return false;
        }

        var s = ds.Multiply(l);
        Span<byte> output = stackalloc byte[SignatureSize];
        h.WriteBigEndian(output);
        s.Encode(output[ScalarSize..]);
        signature = HexUtils.ToHexLower(output);
        return true;
    }

    /// <summary>Verifies a signature on the UTF-8 form of the text; false for text with no UTF-8 form.</summary>
    public static bool Verify(string message, string signature, string userId, string masterPublicKey, byte hid = HidSign)
    {
        if (message is null)
        {
            return false;
        }
        byte[] bytes;
        try
        {
            bytes = StrictUtf8.GetBytes(message);
        }
        catch (ArgumentException)
        {
            return false;
        }
        return Verify(bytes, signature, userId, masterPublicKey, hid);
    }

    /// <summary>
    /// True only for a signature of exactly 194 lowercase hex digits, h in [1, N-1] and S a valid G1 point, that verifies
    /// for the ID and the signing master public key. Every kind of invalid input, null included, gives false.
    /// </summary>
    public static bool Verify(byte[] message, string signature, string userId, string masterPublicKey, byte hid = HidSign)
    {
        if (message is null || signature is null || userId is null || masterPublicKey is null)
        {
            return false;
        }
        if (signature.Length != 2 * SignatureSize || !HexUtils.IsLowerCaseOnly(signature))
        {
            return false;
        }

        ReadOnlySpan<char> text = signature;
        if (!BigInt256.TryParseExact(text[..ScalarHexLength], out var h) || Sm9Scalar.InRangeMask(h) == 0)
        {
            return false;
        }
        if (!G1Affine.TryParseHex(text[ScalarHexLength..], out var s))
        {
            return false;
        }
        if (!TryGetId(userId, out var id) || !TrySignMaster(masterPublicKey, out var master))
        {
            return false;
        }

        // Everything here is public, so variable time would be acceptable; the shared routines are used as they are.
        var t = Fq12.PowGt(master.G, h);
        var p = G2Affine.FromProjective(Curve<Fq2>.Add(G2Affine.MultiplyGenerator(H1(id, hid)), master.Point.ToProjective()));
        var u = Sm9Pairing.Pair(s, p);
        var w = Fq12.Mul(u, t);
        var expected = H2(message, w);
        return expected == h;
    }

    // ------------------------------------------------------------------ shared helpers

    private static BigInt256 H1(ReadOnlySpan<byte> id, byte hid)
    {
        ReadOnlySpan<byte> hidByte = [hid];
        return Sm9Scalar.Hash(0x01, id, hidByte);
    }

    private static BigInt256 H2(ReadOnlySpan<byte> message, in Fq12 w)
    {
        Span<byte> wBytes = stackalloc byte[Fq12.ByteSize];
        w.Write(wBytes);
        var h = Sm9Scalar.Hash(0x02, message, wBytes);
        CryptographicOperations.ZeroMemory(wBytes);
        return h;
    }

    private static byte[] IdBytes(string userId)
    {
        ArgumentNullException.ThrowIfNull(userId);
        try
        {
            return StrictUtf8.GetBytes(userId);
        }
        catch (ArgumentException)
        {
            throw new ArgumentException(InvalidUserId);
        }
    }

    private static bool TryGetId(string? userId, out byte[] id)
    {
        id = [];
        if (userId is null)
        {
            return false;
        }
        try
        {
            id = StrictUtf8.GetBytes(userId);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static BigInt256 ParseScalar(string? hex, string error)
    {
        if (hex is null)
        {
            throw new ArgumentNullException(nameof(hex), error);
        }
        return Sm9Scalar.TryParse(hex, out var k) ? k : throw new ArgumentException(error);
    }

    private static G1Affine ParseG1(string? hex, string error)
    {
        if (hex is null)
        {
            throw new ArgumentNullException(nameof(hex), error);
        }
        return G1Affine.TryParseHex(hex, out var p) ? p : throw new ArgumentException(error);
    }

    private static G2Affine ParseG2(string? hex, string error)
    {
        if (hex is null)
        {
            throw new ArgumentNullException(nameof(hex), error);
        }
        return G2Affine.TryParseHex(hex, out var p) ? p : throw new ArgumentException(error);
    }

    /// <summary>A uniformly random scalar in [1, N-1] by rejection sampling; a failing generator is an error.</summary>
    internal static BigInt256 NextScalar(SM2.RandomSource random)
    {
        Span<byte> bytes = stackalloc byte[ScalarSize];
        for (int attempt = 0; attempt < MaxRandomDraws; attempt++)
        {
            random(bytes);
            var candidate = BigInt256.FromBigEndian(bytes);
            if (Sm9Scalar.InRangeMask(candidate) != 0)
            {
                CryptographicOperations.ZeroMemory(bytes);
                return candidate;
            }
        }
        CryptographicOperations.ZeroMemory(bytes);
        throw new CryptographicException("random generator returned no usable value");
    }

    /// <summary>True when every byte is zero; all bytes are examined, with no early exit.</summary>
    private static bool IsAllZero(ReadOnlySpan<byte> data)
    {
        int seen = 0;
        foreach (var b in data)
        {
            seen |= b;
        }
        return seen == 0;
    }

    // ------------------------------------------------------------------ master public key caches

    /// <summary>A validated master public key and its fixed pairing value, reused while the same key keeps coming.</summary>
    private sealed class SignMasterEntry(string hex, G2Affine point, Fq12 g)
    {
        public readonly string Hex = hex;
        public readonly G2Affine Point = point;
        public readonly Fq12 G = g;
    }

    private sealed class EncMasterEntry(string hex, G1Affine point, Fq12 g)
    {
        public readonly string Hex = hex;
        public readonly G1Affine Point = point;
        public readonly Fq12 G = g;
    }

    private static SignMasterEntry? _signMaster;
    private static EncMasterEntry? _encMaster;

    /// <summary>The signing master public key with g = e(P1, Ppub-s); the subgroup check and pairing run once per key.</summary>
    private static bool TrySignMaster(string hex, out SignMasterEntry entry)
    {
        var cached = Volatile.Read(ref _signMaster);
        if (cached != null && string.Equals(cached.Hex, hex, StringComparison.Ordinal))
        {
            entry = cached;
            return true;
        }
        entry = null!;
        if (!G2Affine.TryParseHex(hex, out var point))
        {
            return false;
        }
        entry = new SignMasterEntry(hex, point, Sm9Pairing.Pair(G1Affine.Generator, point));
        Volatile.Write(ref _signMaster, entry);
        return true;
    }

    private static SignMasterEntry SignMaster(string? hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        return TrySignMaster(hex, out var entry) ? entry : throw new ArgumentException(InvalidMasterPublicKey);
    }

    /// <summary>The encryption master public key with g = e(Ppub-e, P2), computed once per key.</summary>
    private static bool TryEncMaster(string? hex, out EncMasterEntry entry)
    {
        entry = null!;
        if (hex is null)
        {
            return false;
        }
        var cached = Volatile.Read(ref _encMaster);
        if (cached != null && string.Equals(cached.Hex, hex, StringComparison.Ordinal))
        {
            entry = cached;
            return true;
        }
        if (!G1Affine.TryParseHex(hex, out var point))
        {
            return false;
        }
        entry = new EncMasterEntry(hex, point, Sm9Pairing.Pair(point, G2Affine.Generator));
        Volatile.Write(ref _encMaster, entry);
        return true;
    }

    private static EncMasterEntry EncMaster(string? hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        return TryEncMaster(hex, out var entry) ? entry : throw new ArgumentException(InvalidMasterPublicKey);
    }

    /// <summary>Q = [H1(ID || hid)]P1 + Ppub-e, the point that encryption and key exchange target for an identity.</summary>
    private static G1Affine UserPoint(byte[] id, byte hid, in G1Affine masterPublic)
    {
        var sum = Curve<Fq>.Add(G1Affine.MultiplyGenerator(H1(id, hid)), masterPublic.ToProjective());
        var q = G1Affine.FromProjective(sum);
        if (q.Infinity)
        {
            // Only when Ppub-e = -[H1]P1, i.e. t1 = 0 for this ID: no key can exist for it.
            throw new ArgumentException(InvalidMasterPublicKey);
        }
        return q;
    }
}
