using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace SMX;

/// <summary>Streaming SM3 hash; the working state lives in <see cref="Sm3Hasher"/> so internal callers need no heap.</summary>
public class SM3
{
    private Sm3Hasher _hasher = Sm3Hasher.Create();
    private byte[] _hashBytes = [];
    private BigInt256 _digest;
    private bool _hasDigest;

    public void UpdateByte(byte b) => _hasher.UpdateByte(b);

    public void Update(byte[] data) => _hasher.Update(data);

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
    private const int LengthOffset = BlockSize - sizeof(uint);

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
        Unsafe.SkipInit(out Sm3Hasher h);
        h._state = Sm3State.Initial;
        h._totalBytes = 0;
        h._bufferedBytes = 0;
        return h;
    }

    public void UpdateByte(byte b)
    {
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
        BinaryPrimitives.WriteUInt32BigEndian(block[LengthOffset..], (uint)((_totalBytes + sizeof(uint)) << 3));

        var state = _state;
        Sm3Compress.Blocks(ref state, block);
        state.WriteBigEndian(digest);
    }

    /// <summary>
    /// Pads and writes the digest. Only the low 32 bits of the message bit length are encoded, as the library has always
    /// done, so results differ from standard SM3 for messages of 2^32 bits (512 MiB) or more.
    /// </summary>
    public void Finish(Span<byte> digest)
    {
        Span<byte> buffer = _buffer;
        uint bitLength = (uint)(_totalBytes << 3);

        buffer[_bufferedBytes] = 0x80;
        buffer[(_bufferedBytes + 1)..].Clear();
        if (_bufferedBytes >= BlockSize - sizeof(ulong))
        {
            Sm3Compress.Blocks(ref _state, buffer);
            buffer.Clear();
        }
        BinaryPrimitives.WriteUInt32BigEndian(buffer[LengthOffset..], bitLength);
        Sm3Compress.Blocks(ref _state, buffer);
        _state.WriteBigEndian(digest);
    }
}
