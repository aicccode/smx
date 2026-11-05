using System.Security.Cryptography;
using System.Text;

namespace SMX;

/// <summary>
/// SM4 in CBC mode with PKCS#7 padding; ciphertext is lowercase hex.
/// <para>
/// <b>CBC gives confidentiality only, with no integrity.</b> An attacker who can alter ciphertext can alter the plaintext
/// in predictable ways, and if they can also learn whether decryption succeeded, they can recover the plaintext (a padding
/// oracle). Authenticate ciphertext separately, for example with a MAC over the IV and ciphertext, and check that before
/// calling <see cref="Decrypt"/>.
/// </para>
/// <para>
/// The IV given to <see cref="SetKey"/> is used for every message until the next SetKey, which makes equal plaintexts
/// produce equal ciphertexts and leaks common prefixes. Use a fresh, unpredictable IV per message by calling SetKey again.
/// </para>
/// <para>Encrypt and Decrypt may run concurrently, also with SetKey: each call uses one complete key and IV pair.</para>
/// </summary>
public class SM4
{
    private const int BlockSize = 16;
    private const string InvalidCiphertext = "Invalid ciphertext";
    private const string KeyNotSet = "SetKey must be called before use";

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private KeySchedule? _keys;

    /// <summary>An immutable key and IV, replaced as a whole so that no caller ever sees half of an update.</summary>
    private sealed class KeySchedule(uint[] roundKeys, byte[] iv)
    {
        public readonly uint[] RoundKeys = roundKeys;
        public readonly byte[] Iv = iv;
    }

    /// <summary>Sets the key and IV, each exactly 16 bytes. Other sizes are rejected: nothing is hashed, padded or truncated.</summary>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ArgumentException">An argument is not 16 bytes. The previous key, if any, stays in place.</exception>
    public void SetKey(byte[] key, byte[] iv)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(iv);
        if (key.Length != BlockSize)
        {
            throw new ArgumentException("SM4 key must be exactly 16 bytes");
        }
        if (iv.Length != BlockSize)
        {
            throw new ArgumentException("SM4 IV must be exactly 16 bytes");
        }

        var roundKeys = new uint[Sm4Core.RoundCount];
        Sm4Core.ExpandKey(key, roundKeys);
        Volatile.Write(ref _keys, new KeySchedule(roundKeys, (byte[])iv.Clone()));
    }

    /// <summary>Encrypts the UTF-8 form of the text. Text that has no UTF-8 form, as with a lone surrogate, is rejected.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="plaintext"/> is null.</exception>
    /// <exception cref="ArgumentException">The text is not encodable, or its ciphertext would not fit in a string.</exception>
    /// <exception cref="InvalidOperationException">No key has been set.</exception>
    public string Encrypt(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var keys = Volatile.Read(ref _keys) ?? throw new InvalidOperationException(KeyNotSet);

        int byteCount = StrictUtf8.GetByteCount(plaintext);
        if (byteCount > HexUtils.MaxHexBytes - BlockSize)
        {
            throw new ArgumentException("Plaintext too long");
        }
        int padLength = BlockSize - byteCount % BlockSize;
        var buffer = new byte[byteCount + padLength];
        StrictUtf8.GetBytes(plaintext, buffer);
        buffer.AsSpan(byteCount).Fill((byte)padLength);

        Sm4Core.EncryptCbc(keys.RoundKeys, keys.Iv, buffer);
        return HexUtils.BytesToHex(buffer);
    }

    /// <summary>
    /// Decrypts hex ciphertext. Every failure of the ciphertext (bad hex, length, padding or UTF-8) raises the same
    /// exception with the same message. Padding is validated without early exit, but whether a call succeeds is
    /// inherently visible: see the class remarks about authenticating ciphertext first.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="ciphertext"/> is null.</exception>
    /// <exception cref="ArgumentException">The ciphertext is invalid.</exception>
    /// <exception cref="InvalidOperationException">No key has been set.</exception>
    public string Decrypt(string ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        var keys = Volatile.Read(ref _keys) ?? throw new InvalidOperationException(KeyNotSet);

        int byteLength = ciphertext.Length / 2;
        if ((ciphertext.Length & 1) != 0 || byteLength == 0 || byteLength % BlockSize != 0)
        {
            throw new ArgumentException(InvalidCiphertext);
        }

        var buffer = new byte[byteLength];
        try
        {
            if (!HexUtils.TryDecode(ciphertext, buffer))
            {
                throw new ArgumentException(InvalidCiphertext);
            }

            Sm4Core.DecryptCbc(keys.RoundKeys, keys.Iv, buffer);
            int padLength = PaddingLength(buffer);
            if (padLength == 0)
            {
                throw new ArgumentException(InvalidCiphertext);
            }

            try
            {
                return StrictUtf8.GetString(buffer, 0, buffer.Length - padLength);
            }
            catch (DecoderFallbackException)
            {
                throw new ArgumentException(InvalidCiphertext);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>
    /// The PKCS#7 padding length, or zero when invalid. Every byte of the last block is examined with no branch on its
    /// value, whatever the result.
    /// </summary>
    private static int PaddingLength(ReadOnlySpan<byte> input)
    {
        var lastBlock = input[^BlockSize..];
        int padLength = lastBlock[^1];

        // All ones when padLength is 0 or above 16.
        int bad = ((padLength - 1) | (BlockSize - padLength)) >> 31;
        for (int i = 0; i < BlockSize; i++)
        {
            // All ones for positions inside the claimed padding, which must all equal its length.
            int inPadding = (BlockSize - i - padLength - 1) >> 31;
            bad |= inPadding & (lastBlock[i] ^ padLength) & 0xFF;
        }

        // All ones when anything failed, otherwise zero.
        int isBad = (bad | -bad) >> 31;
        return padLength & ~isBad;
    }
}
