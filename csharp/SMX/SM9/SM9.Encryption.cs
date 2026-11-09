using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;
using SMX.SM9Internal;

namespace SMX;

public static partial class SM9
{
    private const int MacKeySize = 32;
    private const int Sm4KeySize = 16;
    private const int Sm4BlockSize = 16;
    private const int C1Size = G1Affine.EncodedSize;
    private const int HeaderSize = C1Size + HashSize;
    private const string DecryptionFailed = "decryption failed";
    private const string InvalidCiphertext = "invalid ciphertext";

    // ------------------------------------------------------------------ KEM

    /// <summary>
    /// Key encapsulation for an identity: returns a key of <paramref name="keyLength"/> bytes (1 to 1 MiB) and the
    /// ciphertext C = [r]Q_B, a G1 point, both in lowercase hex.
    /// </summary>
    /// <exception cref="ArgumentException">An invalid ID, encryption master public key or key length.</exception>
    /// <exception cref="CryptographicException">The system random generator failed.</exception>
    public static (string key, string ciphertext) Encapsulate(string userId, string masterPublicKey, int keyLength, byte hid = HidEncrypt)
    {
        CheckKeyLength(keyLength);
        var (id, master, qb) = PrepareEncryption(userId, masterPublicKey, hid);
        for (int attempt = 0; attempt < MaxNonceAttempts; attempt++)
        {
            var r = NextScalar(SystemRandom);
            if (TryEncapsulate(id, qb, master.G, r, keyLength, out var result))
            {
                return result;
            }
        }
        throw new CryptographicException("encapsulation failed");
    }

    /// <summary>Encapsulation with a given r, for known-answer tests.</summary>
    internal static (string key, string ciphertext) EncapsulateWithRandom(string userId, string masterPublicKey, int keyLength, string rHex, byte hid = HidEncrypt)
    {
        CheckKeyLength(keyLength);
        var (id, master, qb) = PrepareEncryption(userId, masterPublicKey, hid);
        var r = ParseScalar(rHex, "invalid r");
        return TryEncapsulate(id, qb, master.G, r, keyLength, out var result)
            ? result
            : throw new InvalidOperationException("all-zero key for this r");
    }

    private static bool TryEncapsulate(byte[] id, in G1Affine qb, in Fq12 g, in BigInt256 r, int keyLength, out (string, string) result)
    {
        result = default;
        var c = qb.Multiply(r);
        var w = Fq12.PowGt(g, r);
        var key = new byte[keyLength];
        DeriveKey(c, w, id, key);
        if (IsAllZero(key))
        {
            return false;
        }
        result = (HexUtils.BytesToHex(key), c.ToHex());
        CryptographicOperations.ZeroMemory(key);
        return true;
    }

    /// <summary>Recovers the encapsulated key with the user's encryption private key de (a G2 point).</summary>
    /// <exception cref="ArgumentException">A malformed ciphertext (C must be lowercase), ID, key or key length.</exception>
    /// <exception cref="InvalidOperationException">C is not a valid point, or the derived key is all zero.</exception>
    public static string Decapsulate(string ciphertext, string userId, string userPrivateKey, int keyLength)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (ciphertext.Length != 2 * C1Size || !HexUtils.IsLowerCaseOnly(ciphertext))
        {
            throw new ArgumentException(InvalidCiphertext);
        }
        var id = IdBytes(userId);
        CheckKeyLength(keyLength);
        var de = ParseG2(userPrivateKey, InvalidUserPrivateKey);
        if (!G1Affine.TryParseHex(ciphertext, out var c))
        {
            throw new InvalidOperationException(DecryptionFailed);
        }
        var w = Sm9Pairing.Pair(c, de);
        var key = new byte[keyLength];
        DeriveKey(c, w, id, key);
        try
        {
            return IsAllZero(key) ? throw new InvalidOperationException(DecryptionFailed) : HexUtils.BytesToHex(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    // ------------------------------------------------------------------ encryption

    /// <summary>Encrypts the UTF-8 form of the text; see <see cref="Encrypt(byte[], string, string, byte, SM9EncryptMode)"/>.</summary>
    /// <exception cref="ArgumentException">Empty or unencodable text, an invalid ID or master public key.</exception>
    /// <exception cref="CryptographicException">The system random generator failed.</exception>
    public static string Encrypt(string plaintext, string userId, string masterPublicKey, byte hid = HidEncrypt, SM9EncryptMode mode = SM9EncryptMode.Stream)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        byte[] bytes;
        try
        {
            bytes = StrictUtf8.GetBytes(plaintext);
        }
        catch (ArgumentException)
        {
            throw new ArgumentException("plaintext has no UTF-8 form");
        }
        try
        {
            return Encrypt(bytes, userId, masterPublicKey, hid, mode);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Encrypts for an identity: C1 || C3 || C2 in lowercase hex, with C1 = [r]Q_B (65 bytes with the 04 prefix), C3 the
    /// SM3 MAC (32 bytes) and C2 the enciphered message. The mode is not recorded; the receiver must use the same one.
    /// </summary>
    /// <exception cref="ArgumentException">An empty plaintext, an invalid ID, master public key or mode.</exception>
    /// <exception cref="CryptographicException">The system random generator failed.</exception>
    public static string Encrypt(byte[] plaintext, string userId, string masterPublicKey, byte hid = HidEncrypt, SM9EncryptMode mode = SM9EncryptMode.Stream)
    {
        CheckPlaintext(plaintext, mode);
        var (id, master, qb) = PrepareEncryption(userId, masterPublicKey, hid);
        for (int attempt = 0; attempt < MaxNonceAttempts; attempt++)
        {
            var r = NextScalar(SystemRandom);
            if (TryEncrypt(plaintext, id, qb, master.G, r, mode, out var ciphertext))
            {
                return ciphertext;
            }
        }
        throw new CryptographicException("encryption failed");
    }

    /// <summary>Encryption with a given r, for known-answer tests.</summary>
    internal static string EncryptWithRandom(byte[] plaintext, string userId, string masterPublicKey, string rHex, SM9EncryptMode mode, byte hid = HidEncrypt)
    {
        CheckPlaintext(plaintext, mode);
        var (id, master, qb) = PrepareEncryption(userId, masterPublicKey, hid);
        var r = ParseScalar(rHex, "invalid r");
        return TryEncrypt(plaintext, id, qb, master.G, r, mode, out var ciphertext)
            ? ciphertext
            : throw new InvalidOperationException("all-zero K1 for this r");
    }

    private static void CheckPlaintext(byte[] plaintext, SM9EncryptMode mode)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        if (plaintext.Length == 0)
        {
            throw new ArgumentException("plaintext cannot be empty");
        }
        if (mode is not (SM9EncryptMode.Stream or SM9EncryptMode.SM4))
        {
            throw new ArgumentException("invalid encryption mode");
        }
        if (plaintext.Length > HexUtils.MaxHexBytes - HeaderSize - Sm4BlockSize)
        {
            throw new ArgumentException("plaintext too long");
        }
    }

    /// <summary>The ID bytes, the validated master public key with its pairing value, and Q_B = [H1(ID || hid)]P1 + Ppub-e.</summary>
    private static (byte[] id, EncMasterEntry master, G1Affine qb) PrepareEncryption(string userId, string masterPublicKey, byte hid)
    {
        var id = IdBytes(userId);
        var master = EncMaster(masterPublicKey);
        return (id, master, UserPoint(id, hid, master.Point));
    }

    private static bool TryEncrypt(byte[] message, byte[] id, in G1Affine qb, in Fq12 g, in BigInt256 r, SM9EncryptMode mode, out string ciphertext)
    {
        ciphertext = "";
        var c1 = qb.Multiply(r);
        var w = Fq12.PowGt(g, r);
        bool block = mode == SM9EncryptMode.SM4;
        int k1Length = block ? Sm4KeySize : message.Length;
        var k = new byte[k1Length + MacKeySize];
        try
        {
            DeriveKey(c1, w, id, k);
            var k1 = k.AsSpan(0, k1Length);
            if (IsAllZero(k1))
            {
                return false;
            }

            int c2Length = block ? (message.Length / Sm4BlockSize + 1) * Sm4BlockSize : message.Length;
            var output = new byte[HeaderSize + c2Length];
            var c2 = output.AsSpan(HeaderSize);
            if (block)
            {
                message.CopyTo(c2);
                c2[message.Length..].Fill((byte)(c2Length - message.Length));
                Sm4Ecb(k1, c2, encrypt: true);
            }
            else
            {
                for (int i = 0; i < message.Length; i++)
                {
                    c2[i] = (byte)(message[i] ^ k1[i]);
                }
            }
            Mac(k.AsSpan(k1Length), c2, output.AsSpan(C1Size, HashSize));
            c1.Encode(output);
            ciphertext = HexUtils.BytesToHex(output);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(k);
        }
    }

    /// <summary>Decrypts to text; also fails, with the same error, when the plaintext is not valid UTF-8.</summary>
    /// <exception cref="ArgumentException">A malformed ciphertext, ID, private key or mode.</exception>
    /// <exception cref="InvalidOperationException">The ciphertext does not decrypt under this key, ID and mode.</exception>
    public static string Decrypt(string ciphertext, string userId, string userPrivateKey, SM9EncryptMode mode = SM9EncryptMode.Stream)
    {
        var plaintext = DecryptToBytes(ciphertext, userId, userPrivateKey, mode);
        try
        {
            return Utf8.IsValid(plaintext) ? Encoding.UTF8.GetString(plaintext) : throw new InvalidOperationException(DecryptionFailed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Decrypts C1 || C3 || C2 (lowercase hex, as <see cref="Encrypt(byte[], string, string, byte, SM9EncryptMode)"/>
    /// writes it) with the user's encryption private key de. C3 is compared in constant time before anything is
    /// deciphered or unpadded, and every failure past the format check gives the same error.
    /// </summary>
    /// <exception cref="ArgumentException">A malformed ciphertext, ID, private key or mode.</exception>
    /// <exception cref="InvalidOperationException">The ciphertext does not decrypt under this key, ID and mode.</exception>
    public static byte[] DecryptToBytes(string ciphertext, string userId, string userPrivateKey, SM9EncryptMode mode = SM9EncryptMode.Stream)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (ciphertext.Length <= 2 * HeaderSize || (ciphertext.Length & 1) != 0 || !HexUtils.IsLowerCaseOnly(ciphertext))
        {
            throw new ArgumentException(InvalidCiphertext);
        }
        if (mode is not (SM9EncryptMode.Stream or SM9EncryptMode.SM4))
        {
            throw new ArgumentException("invalid encryption mode");
        }
        var bytes = new byte[ciphertext.Length / 2];
        if (!HexUtils.TryDecode(ciphertext, bytes))
        {
            throw new ArgumentException(InvalidCiphertext);
        }
        var id = IdBytes(userId);
        var de = ParseG2(userPrivateKey, InvalidUserPrivateKey);

        if (!G1Affine.TryDecode(bytes.AsSpan(0, C1Size), out var c1))
        {
            throw new InvalidOperationException(DecryptionFailed);
        }
        var c3 = bytes.AsSpan(C1Size, HashSize);
        var c2 = bytes.AsSpan(HeaderSize);
        bool block = mode == SM9EncryptMode.SM4;
        int k1Length = block ? Sm4KeySize : c2.Length;

        var w = Sm9Pairing.Pair(c1, de);
        var k = new byte[k1Length + MacKeySize];
        try
        {
            DeriveKey(c1, w, id, k);
            var k1 = k.AsSpan(0, k1Length);
            Span<byte> mac = stackalloc byte[HashSize];
            Mac(k.AsSpan(k1Length), c2, mac);
            bool verified = CryptographicOperations.FixedTimeEquals(mac, c3) & !IsAllZero(k1);
            if (block)
            {
                verified &= c2.Length % Sm4BlockSize == 0;
            }
            if (!verified)
            {
                throw new InvalidOperationException(DecryptionFailed);
            }

            if (!block)
            {
                var plain = c2.ToArray();
                for (int i = 0; i < plain.Length; i++)
                {
                    plain[i] ^= k1[i];
                }
                return plain;
            }

            Sm4Ecb(k1, c2, encrypt: false);
            int padLength = PaddingLength(c2);
            if (padLength == 0)
            {
                CryptographicOperations.ZeroMemory(c2);
                throw new InvalidOperationException(DecryptionFailed);
            }
            var result = c2[..^padLength].ToArray();
            CryptographicOperations.ZeroMemory(c2);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(k);
        }
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>KDF(C.xy || w || ID, output.Length).</summary>
    private static void DeriveKey(in G1Affine c, in Fq12 w, ReadOnlySpan<byte> id, Span<byte> output)
    {
        Span<byte> buffer = stackalloc byte[G1Affine.CoordinatesSize + Fq12.ByteSize];
        c.WriteCoordinates(buffer);
        w.Write(buffer[G1Affine.CoordinatesSize..]);
        var h = Sm3Hasher.Create();
        h.Update(buffer);
        h.Update(id);
        Sm9Scalar.Kdf(h, output);
        h.Wipe();
        CryptographicOperations.ZeroMemory(buffer);
    }

    /// <summary>MAC(K2, Z) = SM3(Z || K2).</summary>
    private static void Mac(ReadOnlySpan<byte> k2, ReadOnlySpan<byte> data, Span<byte> digest)
    {
        var h = Sm3Hasher.Create();
        h.Update(data);
        h.Update(k2);
        h.Finish(digest);
        h.Wipe();
    }

    private static void Sm4Ecb(ReadOnlySpan<byte> key, Span<byte> data, bool encrypt)
    {
        Span<uint> roundKeys = stackalloc uint[Sm4Core.RoundCount];
        Sm4Core.ExpandKey(key, roundKeys);
        Span<byte> zeroIv = stackalloc byte[Sm4BlockSize];
        zeroIv.Clear();
        for (int offset = 0; offset < data.Length; offset += Sm4BlockSize)
        {
            var blockData = data.Slice(offset, Sm4BlockSize);
            if (encrypt)
            {
                Sm4Core.EncryptBlock(roundKeys, blockData);
            }
            else
            {
                // CBC over a single block with a zero IV is exactly ECB.
                Sm4Core.DecryptCbc(roundKeys, zeroIv, blockData);
            }
        }
        roundKeys.Clear();
    }

    /// <summary>
    /// The PKCS#7 padding length, or zero when invalid; all of the last block is examined without branches. It runs only
    /// after the MAC has verified, so it cannot act as a padding oracle.
    /// </summary>
    private static int PaddingLength(ReadOnlySpan<byte> input)
    {
        var lastBlock = input[^Sm4BlockSize..];
        int padLength = lastBlock[^1];
        int bad = ((padLength - 1) | (Sm4BlockSize - padLength)) >> 31;
        for (int i = 0; i < Sm4BlockSize; i++)
        {
            int inPadding = (Sm4BlockSize - i - padLength - 1) >> 31;
            bad |= inPadding & (lastBlock[i] ^ padLength) & 0xFF;
        }
        int isBad = (bad | -bad) >> 31;
        return padLength & ~isBad;
    }

    private static void CheckKeyLength(int keyLength)
    {
        if (keyLength < 1 || keyLength > MaxKeyBytes)
        {
            throw new ArgumentException(InvalidKeyLength);
        }
    }
}
