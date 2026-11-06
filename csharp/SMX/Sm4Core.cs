using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SMX;

/// <summary>
/// The SM4 block cipher with CBC helpers, built for speed: the round function and the key schedule use secret-indexed
/// table lookups (the S-box combined with the linear transform, four 256-entry tables), as OpenSSL and BouncyCastle do.
/// <b>This is not cache-timing resistant</b>: code that shares the CPU caches can learn key and data bits. The
/// <c>security</c> branch of this repository keeps a constant-time SM4.
/// <para>
/// The constant-time version had an AES-NI path (AESENCLAST between two affine maps) for x86. With these tables it lost
/// on every operation and length measured, CBC decryption of 1 MiB included, so it is gone; every platform runs the
/// same code.
/// </para>
/// </summary>
internal static class Sm4Core
{
    public const int RoundCount = 32;
    private const int BlockSize = 16;

    private static ReadOnlySpan<uint> SystemParameter => [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

    private static ReadOnlySpan<uint> FixedParameter =>
    [
        0x00070e15,
        0x1c232a31,
        0x383f464d,
        0x545b6269,
        0x70777e85,
        0x8c939aa1,
        0xa8afb6bd,
        0xc4cbd2d9,
        0xe0e7eef5,
        0xfc030a11,
        0x181f262d,
        0x343b4249,
        0x50575e65,
        0x6c737a81,
        0x888f969d,
        0xa4abb2b9,
        0xc0c7ced5,
        0xdce3eaf1,
        0xf8ff060d,
        0x141b2229,
        0x30373e45,
        0x4c535a61,
        0x686f767d,
        0x848b9299,
        0xa0a7aeb5,
        0xbcc3cad1,
        0xd8dfe6ed,
        0xf4fb0209,
        0x10171e25,
        0x2c333a41,
        0x484f565d,
        0x646b7279,
    ];

    /// <summary>The S-box from GB/T 32907.</summary>
    internal static ReadOnlySpan<byte> SBox =>
    [
        0xd6,
        0x90,
        0xe9,
        0xfe,
        0xcc,
        0xe1,
        0x3d,
        0xb7,
        0x16,
        0xb6,
        0x14,
        0xc2,
        0x28,
        0xfb,
        0x2c,
        0x05,
        0x2b,
        0x67,
        0x9a,
        0x76,
        0x2a,
        0xbe,
        0x04,
        0xc3,
        0xaa,
        0x44,
        0x13,
        0x26,
        0x49,
        0x86,
        0x06,
        0x99,
        0x9c,
        0x42,
        0x50,
        0xf4,
        0x91,
        0xef,
        0x98,
        0x7a,
        0x33,
        0x54,
        0x0b,
        0x43,
        0xed,
        0xcf,
        0xac,
        0x62,
        0xe4,
        0xb3,
        0x1c,
        0xa9,
        0xc9,
        0x08,
        0xe8,
        0x95,
        0x80,
        0xdf,
        0x94,
        0xfa,
        0x75,
        0x8f,
        0x3f,
        0xa6,
        0x47,
        0x07,
        0xa7,
        0xfc,
        0xf3,
        0x73,
        0x17,
        0xba,
        0x83,
        0x59,
        0x3c,
        0x19,
        0xe6,
        0x85,
        0x4f,
        0xa8,
        0x68,
        0x6b,
        0x81,
        0xb2,
        0x71,
        0x64,
        0xda,
        0x8b,
        0xf8,
        0xeb,
        0x0f,
        0x4b,
        0x70,
        0x56,
        0x9d,
        0x35,
        0x1e,
        0x24,
        0x0e,
        0x5e,
        0x63,
        0x58,
        0xd1,
        0xa2,
        0x25,
        0x22,
        0x7c,
        0x3b,
        0x01,
        0x21,
        0x78,
        0x87,
        0xd4,
        0x00,
        0x46,
        0x57,
        0x9f,
        0xd3,
        0x27,
        0x52,
        0x4c,
        0x36,
        0x02,
        0xe7,
        0xa0,
        0xc4,
        0xc8,
        0x9e,
        0xea,
        0xbf,
        0x8a,
        0xd2,
        0x40,
        0xc7,
        0x38,
        0xb5,
        0xa3,
        0xf7,
        0xf2,
        0xce,
        0xf9,
        0x61,
        0x15,
        0xa1,
        0xe0,
        0xae,
        0x5d,
        0xa4,
        0x9b,
        0x34,
        0x1a,
        0x55,
        0xad,
        0x93,
        0x32,
        0x30,
        0xf5,
        0x8c,
        0xb1,
        0xe3,
        0x1d,
        0xf6,
        0xe2,
        0x2e,
        0x82,
        0x66,
        0xca,
        0x60,
        0xc0,
        0x29,
        0x23,
        0xab,
        0x0d,
        0x53,
        0x4e,
        0x6f,
        0xd5,
        0xdb,
        0x37,
        0x45,
        0xde,
        0xfd,
        0x8e,
        0x2f,
        0x03,
        0xff,
        0x6a,
        0x72,
        0x6d,
        0x6c,
        0x5b,
        0x51,
        0x8d,
        0x1b,
        0xaf,
        0x92,
        0xbb,
        0xdd,
        0xbc,
        0x7f,
        0x11,
        0xd9,
        0x5c,
        0x41,
        0x1f,
        0x10,
        0x5a,
        0xd8,
        0x0a,
        0xc1,
        0x31,
        0x88,
        0xa5,
        0xcd,
        0x7b,
        0xbd,
        0x2d,
        0x74,
        0xd0,
        0x12,
        0xb8,
        0xe5,
        0xb4,
        0xb0,
        0x89,
        0x69,
        0x97,
        0x4a,
        0x0c,
        0x96,
        0x77,
        0x7e,
        0x65,
        0xb9,
        0xf1,
        0x09,
        0xc5,
        0x6e,
        0xc6,
        0x84,
        0x18,
        0xf0,
        0x7d,
        0xec,
        0x3a,
        0xdc,
        0x4d,
        0x20,
        0x79,
        0xee,
        0x5f,
        0x3e,
        0xd7,
        0xcb,
        0x39,
        0x48,
    ];

    /// <summary>
    /// The round transform T = L(S(x)) as four tables of 256 entries: entry 256 * i + b is L applied to S(b) placed in
    /// byte i of the word, counting from the most significant.
    /// </summary>
    internal static readonly uint[] RoundTable = BuildTable(b => b ^ BitOperations.RotateLeft(b, 2) ^ BitOperations.RotateLeft(b, 10) ^ BitOperations.RotateLeft(b, 18) ^ BitOperations.RotateLeft(b, 24));

    /// <summary>The key schedule's transform T' = L'(S(x)), laid out like <see cref="RoundTable"/>.</summary>
    internal static readonly uint[] KeyTable = BuildTable(b => b ^ BitOperations.RotateLeft(b, 13) ^ BitOperations.RotateLeft(b, 23));

    private static uint[] BuildTable(Func<uint, uint> linear)
    {
        var table = new uint[4 * 256];
        for (int i = 0; i < 4; i++)
        {
            for (int b = 0; b < 256; b++)
            {
                table[256 * i + b] = linear((uint)SBox[b] << (24 - 8 * i));
            }
        }
        return table;
    }

    /// <summary>Applies one of the tables to the four bytes of x.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Lookup(ref uint table, uint x) =>
        Unsafe.Add(ref table, (nuint)(x >> 24))
        ^ Unsafe.Add(ref table, 256 + (nuint)((x >> 16) & 0xFF))
        ^ Unsafe.Add(ref table, 512 + (nuint)((x >> 8) & 0xFF))
        ^ Unsafe.Add(ref table, 768 + (nuint)(x & 0xFF));

    /// <summary>Expands a 16-byte key into the 32 encryption round keys.</summary>
    public static void ExpandKey(ReadOnlySpan<byte> key, Span<uint> roundKeys)
    {
        ReadOnlySpan<uint> fk = SystemParameter;
        ReadOnlySpan<uint> ck = FixedParameter;
        ref uint table = ref MemoryMarshal.GetArrayDataReference(KeyTable);
        uint k0 = BinaryPrimitives.ReadUInt32BigEndian(key) ^ fk[0];
        uint k1 = BinaryPrimitives.ReadUInt32BigEndian(key[4..]) ^ fk[1];
        uint k2 = BinaryPrimitives.ReadUInt32BigEndian(key[8..]) ^ fk[2];
        uint k3 = BinaryPrimitives.ReadUInt32BigEndian(key[12..]) ^ fk[3];
        for (int i = 0; i < RoundCount; i += 4)
        {
            k0 ^= Lookup(ref table, k1 ^ k2 ^ k3 ^ ck[i]);
            k1 ^= Lookup(ref table, k2 ^ k3 ^ k0 ^ ck[i + 1]);
            k2 ^= Lookup(ref table, k3 ^ k0 ^ k1 ^ ck[i + 2]);
            k3 ^= Lookup(ref table, k0 ^ k1 ^ k2 ^ ck[i + 3]);
            roundKeys[i] = k0;
            roundKeys[i + 1] = k1;
            roundKeys[i + 2] = k2;
            roundKeys[i + 3] = k3;
        }
    }

    /// <summary>Encrypts one block in place, without chaining.</summary>
    public static void EncryptBlock(ReadOnlySpan<uint> roundKeys, Span<byte> block)
    {
        Span<byte> zero = stackalloc byte[BlockSize];
        zero.Clear();
        EncryptCbc(roundKeys, zero, block[..BlockSize]);
    }

    /// <summary>
    /// CBC-encrypts whole blocks in place. Chaining makes this serial: one block at a time.
    /// </summary>
    public static void EncryptCbc(ReadOnlySpan<uint> roundKeys, ReadOnlySpan<byte> iv, Span<byte> data)
    {
        CheckSizes(roundKeys, iv, data);
        ref uint rk = ref MemoryMarshal.GetReference(roundKeys);
        ref uint table = ref MemoryMarshal.GetArrayDataReference(RoundTable);
        ref byte p = ref MemoryMarshal.GetReference(data);
        uint c0 = BinaryPrimitives.ReadUInt32BigEndian(iv);
        uint c1 = BinaryPrimitives.ReadUInt32BigEndian(iv[4..]);
        uint c2 = BinaryPrimitives.ReadUInt32BigEndian(iv[8..]);
        uint c3 = BinaryPrimitives.ReadUInt32BigEndian(iv[12..]);
        for (nuint offset = 0; offset < (nuint)data.Length; offset += BlockSize)
        {
            uint x0 = Load(ref p, offset) ^ c0;
            uint x1 = Load(ref p, offset + 4) ^ c1;
            uint x2 = Load(ref p, offset + 8) ^ c2;
            uint x3 = Load(ref p, offset + 12) ^ c3;
            for (nuint i = 0; i < RoundCount; i += 4)
            {
                x0 ^= Lookup(ref table, x1 ^ x2 ^ x3 ^ Unsafe.Add(ref rk, i));
                x1 ^= Lookup(ref table, x2 ^ x3 ^ x0 ^ Unsafe.Add(ref rk, i + 1));
                x2 ^= Lookup(ref table, x3 ^ x0 ^ x1 ^ Unsafe.Add(ref rk, i + 2));
                x3 ^= Lookup(ref table, x0 ^ x1 ^ x2 ^ Unsafe.Add(ref rk, i + 3));
            }
            c0 = x3;
            c1 = x2;
            c2 = x1;
            c3 = x0;
            Store(ref p, offset, c0);
            Store(ref p, offset + 4, c1);
            Store(ref p, offset + 8, c2);
            Store(ref p, offset + 12, c3);
        }
    }

    /// <summary>
    /// CBC-decrypts whole blocks in place. Blocks do not depend on one another here, so four (then two, then one) run
    /// their rounds interleaved: each round waits on the previous one of its block, and interleaving overlaps the lookups.
    /// </summary>
    public static void DecryptCbc(ReadOnlySpan<uint> roundKeys, ReadOnlySpan<byte> iv, Span<byte> data)
    {
        CheckSizes(roundKeys, iv, data);
        ref uint rk = ref MemoryMarshal.GetReference(roundKeys);
        ref byte p = ref MemoryMarshal.GetReference(data);
        Chain chain = new(BinaryPrimitives.ReadUInt32BigEndian(iv), BinaryPrimitives.ReadUInt32BigEndian(iv[4..]),
            BinaryPrimitives.ReadUInt32BigEndian(iv[8..]), BinaryPrimitives.ReadUInt32BigEndian(iv[12..]));
        nuint length = (nuint)data.Length;
        nuint offset = 0;
        for (; offset + 4 * BlockSize <= length; offset += 4 * BlockSize)
        {
            DecryptFour(ref rk, ref Unsafe.Add(ref p, offset), ref chain);
        }
        if (offset + 2 * BlockSize <= length)
        {
            DecryptTwo(ref rk, ref Unsafe.Add(ref p, offset), ref chain);
            offset += 2 * BlockSize;
        }
        if (offset < length)
        {
            DecryptOne(ref rk, ref Unsafe.Add(ref p, offset), ref chain);
        }
    }

    /// <summary>The block loops read and write through unchecked references, so sizes are enforced at this one gate.</summary>
    private static void CheckSizes(ReadOnlySpan<uint> roundKeys, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
    {
        if (roundKeys.Length != RoundCount || iv.Length != BlockSize || data.Length % BlockSize != 0)
        {
            throw new ArgumentException("Invalid SM4 buffer size");
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Load(ref byte p, nuint offset)
    {
        uint v = Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref p, offset));
        return BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(v) : v;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Store(ref byte p, nuint offset, uint value) =>
        Unsafe.WriteUnaligned(ref Unsafe.Add(ref p, offset), BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness(value) : value);

    /// <summary>The previous ciphertext block as four big-endian words.</summary>
    private record struct Chain(uint W0, uint W1, uint W2, uint W3);

    private static void DecryptOne(ref uint rk, ref byte p, ref Chain chain)
    {
        ref uint t = ref MemoryMarshal.GetArrayDataReference(RoundTable);
        uint c0 = Load(ref p, 0), c1 = Load(ref p, 4), c2 = Load(ref p, 8), c3 = Load(ref p, 12);
        uint a0 = c0, a1 = c1, a2 = c2, a3 = c3;
        for (nuint i = RoundCount; i > 0; i -= 4)
        {
            a0 ^= Lookup(ref t, a1 ^ a2 ^ a3 ^ Unsafe.Add(ref rk, i - 1));
            a1 ^= Lookup(ref t, a2 ^ a3 ^ a0 ^ Unsafe.Add(ref rk, i - 2));
            a2 ^= Lookup(ref t, a3 ^ a0 ^ a1 ^ Unsafe.Add(ref rk, i - 3));
            a3 ^= Lookup(ref t, a0 ^ a1 ^ a2 ^ Unsafe.Add(ref rk, i - 4));
        }
        Store(ref p, 0, a3 ^ chain.W0);
        Store(ref p, 4, a2 ^ chain.W1);
        Store(ref p, 8, a1 ^ chain.W2);
        Store(ref p, 12, a0 ^ chain.W3);
        chain = new(c0, c1, c2, c3);
    }

    private static void DecryptTwo(ref uint rk, ref byte p, ref Chain chain)
    {
        ref uint t = ref MemoryMarshal.GetArrayDataReference(RoundTable);
        uint a0 = Load(ref p, 0), a1 = Load(ref p, 4), a2 = Load(ref p, 8), a3 = Load(ref p, 12);
        uint b0 = Load(ref p, 16), b1 = Load(ref p, 20), b2 = Load(ref p, 24), b3 = Load(ref p, 28);
        for (nuint i = RoundCount; i > 0; i -= 4)
        {
            uint k = Unsafe.Add(ref rk, i - 1);
            a0 ^= Lookup(ref t, a1 ^ a2 ^ a3 ^ k);
            b0 ^= Lookup(ref t, b1 ^ b2 ^ b3 ^ k);
            k = Unsafe.Add(ref rk, i - 2);
            a1 ^= Lookup(ref t, a2 ^ a3 ^ a0 ^ k);
            b1 ^= Lookup(ref t, b2 ^ b3 ^ b0 ^ k);
            k = Unsafe.Add(ref rk, i - 3);
            a2 ^= Lookup(ref t, a3 ^ a0 ^ a1 ^ k);
            b2 ^= Lookup(ref t, b3 ^ b0 ^ b1 ^ k);
            k = Unsafe.Add(ref rk, i - 4);
            a3 ^= Lookup(ref t, a0 ^ a1 ^ a2 ^ k);
            b3 ^= Lookup(ref t, b0 ^ b1 ^ b2 ^ k);
        }
        // The ciphertext is reloaded for chaining rather than kept live through the rounds.
        uint c0 = Load(ref p, 0), c1 = Load(ref p, 4), c2 = Load(ref p, 8), c3 = Load(ref p, 12);
        uint d0 = Load(ref p, 16), d1 = Load(ref p, 20), d2 = Load(ref p, 24), d3 = Load(ref p, 28);
        Store(ref p, 0, a3 ^ chain.W0);
        Store(ref p, 4, a2 ^ chain.W1);
        Store(ref p, 8, a1 ^ chain.W2);
        Store(ref p, 12, a0 ^ chain.W3);
        Store(ref p, 16, b3 ^ c0);
        Store(ref p, 20, b2 ^ c1);
        Store(ref p, 24, b1 ^ c2);
        Store(ref p, 28, b0 ^ c3);
        chain = new(d0, d1, d2, d3);
    }

    private static void DecryptFour(ref uint rk, ref byte p, ref Chain chain)
    {
        ref uint t = ref MemoryMarshal.GetArrayDataReference(RoundTable);
        uint a0 = Load(ref p, 0), a1 = Load(ref p, 4), a2 = Load(ref p, 8), a3 = Load(ref p, 12);
        uint b0 = Load(ref p, 16), b1 = Load(ref p, 20), b2 = Load(ref p, 24), b3 = Load(ref p, 28);
        uint c0 = Load(ref p, 32), c1 = Load(ref p, 36), c2 = Load(ref p, 40), c3 = Load(ref p, 44);
        uint d0 = Load(ref p, 48), d1 = Load(ref p, 52), d2 = Load(ref p, 56), d3 = Load(ref p, 60);
        for (nuint i = RoundCount; i > 0; i -= 4)
        {
            uint k = Unsafe.Add(ref rk, i - 1);
            a0 ^= Lookup(ref t, a1 ^ a2 ^ a3 ^ k);
            b0 ^= Lookup(ref t, b1 ^ b2 ^ b3 ^ k);
            c0 ^= Lookup(ref t, c1 ^ c2 ^ c3 ^ k);
            d0 ^= Lookup(ref t, d1 ^ d2 ^ d3 ^ k);
            k = Unsafe.Add(ref rk, i - 2);
            a1 ^= Lookup(ref t, a2 ^ a3 ^ a0 ^ k);
            b1 ^= Lookup(ref t, b2 ^ b3 ^ b0 ^ k);
            c1 ^= Lookup(ref t, c2 ^ c3 ^ c0 ^ k);
            d1 ^= Lookup(ref t, d2 ^ d3 ^ d0 ^ k);
            k = Unsafe.Add(ref rk, i - 3);
            a2 ^= Lookup(ref t, a3 ^ a0 ^ a1 ^ k);
            b2 ^= Lookup(ref t, b3 ^ b0 ^ b1 ^ k);
            c2 ^= Lookup(ref t, c3 ^ c0 ^ c1 ^ k);
            d2 ^= Lookup(ref t, d3 ^ d0 ^ d1 ^ k);
            k = Unsafe.Add(ref rk, i - 4);
            a3 ^= Lookup(ref t, a0 ^ a1 ^ a2 ^ k);
            b3 ^= Lookup(ref t, b0 ^ b1 ^ b2 ^ k);
            c3 ^= Lookup(ref t, c0 ^ c1 ^ c2 ^ k);
            d3 ^= Lookup(ref t, d0 ^ d1 ^ d2 ^ k);
        }
        // Output block j is the cipher output XOR ciphertext block j - 1, so write from the last block backwards
        // while the earlier ciphertext is still in memory.
        Chain last = new(Load(ref p, 48), Load(ref p, 52), Load(ref p, 56), Load(ref p, 60));
        Store(ref p, 48, d3 ^ Load(ref p, 32));
        Store(ref p, 52, d2 ^ Load(ref p, 36));
        Store(ref p, 56, d1 ^ Load(ref p, 40));
        Store(ref p, 60, d0 ^ Load(ref p, 44));
        Store(ref p, 32, c3 ^ Load(ref p, 16));
        Store(ref p, 36, c2 ^ Load(ref p, 20));
        Store(ref p, 40, c1 ^ Load(ref p, 24));
        Store(ref p, 44, c0 ^ Load(ref p, 28));
        Store(ref p, 16, b3 ^ Load(ref p, 0));
        Store(ref p, 20, b2 ^ Load(ref p, 4));
        Store(ref p, 24, b1 ^ Load(ref p, 8));
        Store(ref p, 28, b0 ^ Load(ref p, 12));
        Store(ref p, 0, a3 ^ chain.W0);
        Store(ref p, 4, a2 ^ chain.W1);
        Store(ref p, 8, a1 ^ chain.W2);
        Store(ref p, 12, a0 ^ chain.W3);
        chain = last;
    }
}
