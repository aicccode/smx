using System.Text;

namespace SMX;

/// <summary>SM4 in CBC mode with PKCS#7 padding; ciphertext is lowercase hex.</summary>
public class SM4
{
    private const int BlockSize = 16;

    private readonly uint[] _roundKeys = new uint[Sm4Core.RoundCount];
    private readonly byte[] _iv = new byte[BlockSize];

    public void SetKey(byte[] key, byte[] iv)
    {
        var keyBytes = PrepareKey(key);
        var ivBytes = PrepareKey(iv);
        Sm4Core.ExpandKey(keyBytes, _roundKeys);
        ivBytes.CopyTo(_iv, 0);
    }

    /// <summary>
    /// Inputs of any other length than 16 bytes become the first 16 uppercase hex characters of their SM3 hash.
    /// That is only 64 bits of the digest, but it is the format this library interoperates with.
    /// </summary>
    private static byte[] PrepareKey(byte[] input)
    {
        if (input.Length == BlockSize)
        {
            return input;
        }
        var h = Sm3Hasher.Create();
        h.Update(input);
        Span<byte> digest = stackalloc byte[Sm3Hasher.DigestSize];
        h.Finish(digest);
        var key = new byte[BlockSize];
        Encoding.ASCII.GetBytes(HexUtils.ToHexUpper(digest[..(BlockSize / 2)]), key);
        return key;
    }

    public string Encrypt(string plaintext)
    {
        int byteCount = Encoding.UTF8.GetByteCount(plaintext);
        int padLength = BlockSize - byteCount % BlockSize;
        var buffer = new byte[byteCount + padLength];
        Encoding.UTF8.GetBytes(plaintext, buffer);
        buffer.AsSpan(byteCount).Fill((byte)padLength);

        Sm4Core.EncryptCbc(_roundKeys, _iv, buffer);
        return HexUtils.BytesToHex(buffer);
    }

    public string Decrypt(string ciphertext)
    {
        var buffer = HexUtils.HexToBytes(ciphertext);
        if (buffer.Length % BlockSize != 0)
        {
            throw new ArgumentException("Invalid ciphertext length");
        }

        Sm4Core.DecryptCbc(_roundKeys, _iv, buffer);
        return Encoding.UTF8.GetString(buffer.AsSpan(0, UnpaddedLength(buffer)));
    }

    /// <summary>Validates PKCS#7 padding, examining all of the last block regardless of where it first goes wrong.</summary>
    private static int UnpaddedLength(ReadOnlySpan<byte> input)
    {
        if (input.IsEmpty)
        {
            return 0;
        }
        int padLength = input[^1];
        int bad = ((padLength - 1) | (BlockSize - padLength)) >> 31;
        var lastBlock = input[^BlockSize..];
        for (int i = 0; i < BlockSize; i++)
        {
            // Position counted from the end; bytes within the padding must equal the padding length.
            int position = BlockSize - i;
            int inPadding = (position - padLength - 1) >> 31;
            bad |= inPadding & (lastBlock[i] ^ padLength);
        }
        if (bad != 0)
        {
            throw new ArgumentException("Invalid padding");
        }
        return input.Length - padLength;
    }
}
