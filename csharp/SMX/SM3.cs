using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SMX;

/// <summary>
/// Streaming SM3 hash; the working state lives in <see cref="Sm3Hasher"/> so internal callers need no heap. An instance
/// holds mutable state and is not safe for concurrent use. Finish resets it for a new message.
/// </summary>
public class SM3
{
    private Sm3Hasher _hasher = Sm3Hasher.Create();
    private byte[] _hashBytes = [];
    private BigInt256 _digest;
    private bool _hasDigest;

    /// <exception cref="ArgumentException">The message would exceed the SM3 limit of 2^61 - 1 bytes.</exception>
    public void UpdateByte(byte b) => _hasher.UpdateByte(b);

    /// <exception cref="ArgumentNullException"><paramref name="data"/> is null.</exception>
    /// <exception cref="ArgumentException">The message would exceed the SM3 limit of 2^61 - 1 bytes.</exception>
    public void Update(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        _hasher.Update(data);
    }

    public void Finish()
    {
        var digest = new byte[Sm3Hasher.DigestSize];
        _hasher.Finish(digest);
        _hashBytes = digest;
        _digest = BigInt256.FromBigEndian(digest);
        _hasDigest = true;
        _hasher = Sm3Hasher.Create();
    }

    public byte[] HashBytes() => _hashBytes;

    public string HashHexUpper() => _hasDigest ? _digest.ToHex() : "";
}

/// <summary>SM3 hashing state as a plain struct; copying it forks the hash, which the KDFs use to reuse a shared prefix.</summary>
internal struct Sm3Hasher
{
    public const int DigestSize = 32;
    private const int BlockSize = 64;
    private const int LengthOffset = BlockSize - sizeof(ulong);

    /// <summary>The bit length field is 64 bits wide, which limits a message to this many bytes.</summary>
    internal const ulong MaxMessageBytes = (1UL << 61) - 1;

    private Sm3State _state;
    private ulong _totalBytes;
    private int _bufferedBytes;
    private BlockBuffer _buffer;

    [InlineArray(BlockSize)]
    private struct BlockBuffer
    {
        private byte _first;
    }

    public static Sm3Hasher Create()
    {
        Sm3Hasher h = default;
        h._state = Sm3State.Initial;
        return h;
    }

    /// <summary>A hasher that has notionally absorbed this many bytes already, to test the length limit.</summary>
    internal static Sm3Hasher CreateWithLengthForTest(ulong totalBytes)
    {
        Sm3Hasher h = Create();
        h._totalBytes = totalBytes;
        return h;
    }

    /// <summary>Best-effort erasure of absorbed data and chaining state, for hashers that held secrets.</summary>
    public void Wipe()
    {
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(new Span<Sm3Hasher>(ref this)));
    }

    private readonly void CheckLength(ulong additional)
    {
        if (additional > MaxMessageBytes - _totalBytes)
        {
            throw new ArgumentException("SM3 message too long");
        }
    }

    public void UpdateByte(byte b)
    {
        CheckLength(1);
        Span<byte> buffer = _buffer;
        buffer[_bufferedBytes++] = b;
        _totalBytes++;
        if (_bufferedBytes == BlockSize)
        {
            Sm3Compress.Blocks(ref _state, buffer);
            _bufferedBytes = 0;
        }
    }

    public void Update(ReadOnlySpan<byte> data)
    {
        CheckLength((ulong)data.Length);
        _totalBytes += (ulong)data.Length;
        Span<byte> buffer = _buffer;

        if (_bufferedBytes != 0)
        {
            int space = BlockSize - _bufferedBytes;
            if (data.Length < space)
            {
                data.CopyTo(buffer[_bufferedBytes..]);
                _bufferedBytes += data.Length;
                return;
            }
            data[..space].CopyTo(buffer[_bufferedBytes..]);
            Sm3Compress.Blocks(ref _state, buffer);
            data = data[space..];
            _bufferedBytes = 0;
        }

        int whole = data.Length & ~(BlockSize - 1);
        if (whole != 0)
        {
            Sm3Compress.Blocks(ref _state, data[..whole]);
        }
        data[whole..].CopyTo(buffer);
        _bufferedBytes = data.Length - whole;
    }

    /// <summary>
    /// The digest of the absorbed data followed by a big-endian counter, leaving this state as it is. When counter and
    /// padding fit the current block, that block is assembled directly, without first copying the whole hasher.
    /// </summary>
    [SkipLocalsInit]
    public readonly void FinishWithCounter(uint counter, Span<byte> digest)
    {
        const int PaddedCounterSize = sizeof(uint) + 1 + sizeof(ulong);
        if (_bufferedBytes > BlockSize - PaddedCounterSize)
        {
            var fork = this;
            Span<byte> counterBytes = stackalloc byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(counterBytes, counter);
            fork.Update(counterBytes);
            fork.Finish(digest);
            return;
        }

        Span<byte> block = stackalloc byte[BlockSize];
        ReadOnlySpan<byte> buffered = _buffer;
        buffered[.._bufferedBytes].CopyTo(block);
        BinaryPrimitives.WriteUInt32BigEndian(block[_bufferedBytes..], counter);
        block[_bufferedBytes + sizeof(uint)] = 0x80;
        block[(_bufferedBytes + sizeof(uint) + 1)..LengthOffset].Clear();
        BinaryPrimitives.WriteUInt64BigEndian(block[LengthOffset..], (_totalBytes + sizeof(uint)) << 3);

        var state = _state;
        Sm3Compress.Blocks(ref state, block);
        state.WriteBigEndian(digest);
        CryptographicOperations.ZeroMemory(block);
    }

    /// <summary>Pads with the 64-bit message bit length and writes the digest.</summary>
    public void Finish(Span<byte> digest)
    {
        Span<byte> buffer = _buffer;
        ulong bitLength = _totalBytes << 3;

        buffer[_bufferedBytes] = 0x80;
        buffer[(_bufferedBytes + 1)..].Clear();
        if (_bufferedBytes >= BlockSize - sizeof(ulong))
        {
            Sm3Compress.Blocks(ref _state, buffer);
            buffer.Clear();
        }
        BinaryPrimitives.WriteUInt64BigEndian(buffer[LengthOffset..], bitLength);
        Sm3Compress.Blocks(ref _state, buffer);
        _state.WriteBigEndian(digest);
    }
}
