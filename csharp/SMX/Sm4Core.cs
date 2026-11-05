using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace SMX;

/// <summary>
/// The SM4 block cipher with CBC helpers. On x86 with AES-NI and SSSE3 the S-box is evaluated by AESENCLAST between two
/// affine maps, which involves no secret-indexed memory. The AES and SM4 S-boxes are affine equivalent, as shown in
/// Saarinen's sm4ni work; a unit test checks the mapping for all 256 inputs. CBC decryption runs eight blocks at a time
/// with AVX2, otherwise four.
///
/// Elsewhere the portable path uses T-tables: 4 KiB of lookups indexed by secret data. That is the same kind of
/// cache-timing exposure as the S-box lookup it replaces, on a somewhat larger footprint, and is acceptable only because
/// no hardware path exists there.
/// </summary>
internal static class Sm4Core
{
    public const int RoundCount = 32;
    private const int BlockSize = 16;

    /// <summary>Set by tests to exercise the portable path on hardware that has AES-NI.</summary>
    internal static bool ForceSoftware { get; set; }

    /// <summary>Set by tests to exercise the four-block path on hardware that has AVX2.</summary>
    internal static bool ForceNoAvx2 { get; set; }

    private static bool UseHardware => HardwareAvailable && !ForceSoftware;

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

    /// <summary>S-box output moved through the linear transform L, one table per input byte position.</summary>
    private static readonly uint[] TTable = BuildTTable();

    private static uint[] BuildTTable()
    {
        var table = new uint[256 * 4];
        for (int i = 0; i < 256; i++)
        {
            uint s = SBox[i];
            uint t = s ^ BitOperations.RotateLeft(s, 2) ^ BitOperations.RotateLeft(s, 10) ^ BitOperations.RotateLeft(s, 18) ^ BitOperations.RotateLeft(s, 24);
            table[i] = BitOperations.RotateLeft(t, 24);
            table[256 + i] = BitOperations.RotateLeft(t, 16);
            table[512 + i] = BitOperations.RotateLeft(t, 8);
            table[768 + i] = t;
        }
        return table;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint TableRound(ref uint table, uint x) =>
        Unsafe.Add(ref table, (nint)(x >> 24))
        ^ Unsafe.Add(ref table, 256 + (nint)((x >> 16) & 0xFF))
        ^ Unsafe.Add(ref table, 512 + (nint)((x >> 8) & 0xFF))
        ^ Unsafe.Add(ref table, 768 + (nint)(x & 0xFF));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint TableSubstitute(uint a)
    {
        ReadOnlySpan<byte> box = SBox;
        return (uint)box[(int)(a >> 24)] << 24 | (uint)box[(int)(a >> 16) & 0xFF] << 16 | (uint)box[(int)(a >> 8) & 0xFF] << 8 | box[(int)a & 0xFF];
    }

    /// <summary>The S-box applied to each byte of a word via AES-NI; callers must check <see cref="HardwareAvailable"/>.</summary>
    internal static uint SubstituteWithHardware(uint word) => AesNi.SubstituteWord(word);

    internal static bool HardwareAvailable => Aes.IsSupported && Ssse3.IsSupported;

    /// <summary>Expands a 16-byte key into the 32 encryption round keys.</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void ExpandKey(ReadOnlySpan<byte> key, Span<uint> roundKeys)
    {
        ReadOnlySpan<uint> fk = SystemParameter;
        ReadOnlySpan<uint> ck = FixedParameter;
        uint k0 = BinaryPrimitives.ReadUInt32BigEndian(key) ^ fk[0];
        uint k1 = BinaryPrimitives.ReadUInt32BigEndian(key[4..]) ^ fk[1];
        uint k2 = BinaryPrimitives.ReadUInt32BigEndian(key[8..]) ^ fk[2];
        uint k3 = BinaryPrimitives.ReadUInt32BigEndian(key[12..]) ^ fk[3];

        bool hardware = UseHardware;
        for (int i = 0; i < RoundCount; i++)
        {
            uint input = k1 ^ k2 ^ k3 ^ ck[i];
            uint b = hardware ? AesNi.SubstituteWord(input) : TableSubstitute(input);
            uint next = k0 ^ b ^ BitOperations.RotateLeft(b, 13) ^ BitOperations.RotateLeft(b, 23);
            roundKeys[i] = next;
            k0 = k1;
            k1 = k2;
            k2 = k3;
            k3 = next;
        }
    }

    /// <summary>Encrypts one block in place, without chaining.</summary>
    public static void EncryptBlock(ReadOnlySpan<uint> roundKeys, Span<byte> block)
    {
        Span<byte> zero = stackalloc byte[BlockSize];
        zero.Clear();
        EncryptCbc(roundKeys, zero, block[..BlockSize]);
    }

    /// <summary>CBC-encrypts whole blocks in place. Chaining makes this serial, so it runs one block at a time.</summary>
    public static void EncryptCbc(ReadOnlySpan<uint> roundKeys, ReadOnlySpan<byte> iv, Span<byte> data)
    {
        if (UseHardware)
        {
            AesNi.EncryptCbc(roundKeys, iv, data);
        }
        else
        {
            EncryptCbcSoftware(roundKeys, iv, data);
        }
    }

    /// <summary>CBC-decrypts whole blocks in place.</summary>
    public static void DecryptCbc(ReadOnlySpan<uint> roundKeys, ReadOnlySpan<byte> iv, Span<byte> data)
    {
        if (UseHardware)
        {
            AesNi.DecryptCbc(roundKeys, iv, data);
        }
        else
        {
            DecryptCbcSoftware(roundKeys, iv, data);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void EncryptCbcSoftware(ReadOnlySpan<uint> roundKeys, ReadOnlySpan<byte> iv, Span<byte> data)
    {
        ref uint table = ref MemoryMarshal.GetArrayDataReference(TTable);
        ref uint rk = ref MemoryMarshal.GetReference(roundKeys);
        uint c0 = BinaryPrimitives.ReadUInt32BigEndian(iv);
        uint c1 = BinaryPrimitives.ReadUInt32BigEndian(iv[4..]);
        uint c2 = BinaryPrimitives.ReadUInt32BigEndian(iv[8..]);
        uint c3 = BinaryPrimitives.ReadUInt32BigEndian(iv[12..]);

        for (int offset = 0; offset < data.Length; offset += BlockSize)
        {
            var block = data.Slice(offset, BlockSize);
            uint x0 = BinaryPrimitives.ReadUInt32BigEndian(block) ^ c0;
            uint x1 = BinaryPrimitives.ReadUInt32BigEndian(block[4..]) ^ c1;
            uint x2 = BinaryPrimitives.ReadUInt32BigEndian(block[8..]) ^ c2;
            uint x3 = BinaryPrimitives.ReadUInt32BigEndian(block[12..]) ^ c3;
            for (int i = 0; i < RoundCount; i += 4)
            {
                x0 ^= TableRound(ref table, x1 ^ x2 ^ x3 ^ Unsafe.Add(ref rk, i));
                x1 ^= TableRound(ref table, x2 ^ x3 ^ x0 ^ Unsafe.Add(ref rk, i + 1));
                x2 ^= TableRound(ref table, x3 ^ x0 ^ x1 ^ Unsafe.Add(ref rk, i + 2));
                x3 ^= TableRound(ref table, x0 ^ x1 ^ x2 ^ Unsafe.Add(ref rk, i + 3));
            }
            c0 = x3;
            c1 = x2;
            c2 = x1;
            c3 = x0;
            BinaryPrimitives.WriteUInt32BigEndian(block, c0);
            BinaryPrimitives.WriteUInt32BigEndian(block[4..], c1);
            BinaryPrimitives.WriteUInt32BigEndian(block[8..], c2);
            BinaryPrimitives.WriteUInt32BigEndian(block[12..], c3);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void DecryptCbcSoftware(ReadOnlySpan<uint> roundKeys, ReadOnlySpan<byte> iv, Span<byte> data)
    {
        ref uint table = ref MemoryMarshal.GetArrayDataReference(TTable);
        ref uint rk = ref MemoryMarshal.GetReference(roundKeys);
        uint c0 = BinaryPrimitives.ReadUInt32BigEndian(iv);
        uint c1 = BinaryPrimitives.ReadUInt32BigEndian(iv[4..]);
        uint c2 = BinaryPrimitives.ReadUInt32BigEndian(iv[8..]);
        uint c3 = BinaryPrimitives.ReadUInt32BigEndian(iv[12..]);

        for (int offset = 0; offset < data.Length; offset += BlockSize)
        {
            var block = data.Slice(offset, BlockSize);
            uint n0 = BinaryPrimitives.ReadUInt32BigEndian(block);
            uint n1 = BinaryPrimitives.ReadUInt32BigEndian(block[4..]);
            uint n2 = BinaryPrimitives.ReadUInt32BigEndian(block[8..]);
            uint n3 = BinaryPrimitives.ReadUInt32BigEndian(block[12..]);
            uint x0 = n0, x1 = n1, x2 = n2, x3 = n3;
            for (int i = RoundCount - 1; i >= 0; i -= 4)
            {
                x0 ^= TableRound(ref table, x1 ^ x2 ^ x3 ^ Unsafe.Add(ref rk, i));
                x1 ^= TableRound(ref table, x2 ^ x3 ^ x0 ^ Unsafe.Add(ref rk, i - 1));
                x2 ^= TableRound(ref table, x3 ^ x0 ^ x1 ^ Unsafe.Add(ref rk, i - 2));
                x3 ^= TableRound(ref table, x0 ^ x1 ^ x2 ^ Unsafe.Add(ref rk, i - 3));
            }
            BinaryPrimitives.WriteUInt32BigEndian(block, x3 ^ c0);
            BinaryPrimitives.WriteUInt32BigEndian(block[4..], x2 ^ c1);
            BinaryPrimitives.WriteUInt32BigEndian(block[8..], x1 ^ c2);
            BinaryPrimitives.WriteUInt32BigEndian(block[12..], x0 ^ c3);
            c0 = n0;
            c1 = n1;
            c2 = n2;
            c3 = n3;
        }
    }

    /// <summary>The AES-NI path. Only called when <see cref="UseHardware"/> holds.</summary>
    private static class AesNi
    {
        private static Vector128<byte> PreLow => Vector128.Create(0x9197E2E474720701UL, 0xC7C1B4B222245157UL).AsByte();
        private static Vector128<byte> PreHigh => Vector128.Create(0xE240AB09EB49A200UL, 0xF052B91BF95BB012UL).AsByte();
        private static Vector128<byte> PostLow => Vector128.Create(0x5B67F2CEA19D0834UL, 0xEDD14478172BBE82UL).AsByte();
        private static Vector128<byte> PostHigh => Vector128.Create(0xAE7201DD73AFDC00UL, 0x11CDBE62CC1063BFUL).AsByte();

        /// <summary>Undoes the ShiftRows step inside AESENCLAST, keeping each byte in its 32-bit lane.</summary>
        private static Vector128<byte> InverseShiftRows =>
            Vector128.Create((byte)0x00, 0x0d, 0x0a, 0x07, 0x04, 0x01, 0x0e, 0x0b, 0x08, 0x05, 0x02, 0x0f, 0x0c, 0x09, 0x06, 0x03);

        private static Vector128<byte> Rotate8 =>
            Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);

        private static Vector128<byte> Rotate16 =>
            Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);

        private static Vector128<byte> Rotate24 =>
            Vector128.Create((byte)1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);

        /// <summary>Applies the SM4 S-box to every byte of the vector.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Substitute(Vector128<byte> x)
        {
            var low = Vector128.Create((byte)0x0F);
            var y = Ssse3.Shuffle(PreLow, x & low) ^ Ssse3.Shuffle(PreHigh, Sse2.ShiftRightLogical(x.AsUInt32(), 4).AsByte() & low);
            y = Aes.EncryptLast(Ssse3.Shuffle(y, InverseShiftRows), Vector128<byte>.Zero);
            return Ssse3.Shuffle(PostLow, y & low) ^ Ssse3.Shuffle(PostHigh, Sse2.ShiftRightLogical(y.AsUInt32(), 4).AsByte() & low);
        }

        /// <summary>Applies S and then the round's linear transform L to all four 32-bit lanes.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Round(Vector128<uint> x)
        {
            var b = Substitute(x.AsByte());
            var t = (b ^ Ssse3.Shuffle(b, Rotate8) ^ Ssse3.Shuffle(b, Rotate16)).AsUInt32();
            var rotated2 = Sse2.ShiftLeftLogical(t, 2) | Sse2.ShiftRightLogical(t, 30);
            return rotated2 ^ b.AsUInt32() ^ Ssse3.Shuffle(b, Rotate24).AsUInt32();
        }

        public static uint SubstituteWord(uint word) =>
            Substitute(Vector128.CreateScalarUnsafe(word).AsByte()).AsUInt32().ToScalar();

        /// <summary>
        /// CBC is serial, so this path is bound by the latency of one round rather than by throughput. Each state word
        /// therefore stays in lane 0 of its own vector for the whole block: moving words through general registers would
        /// add several cycles per round. The other lanes hold ignored values.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static void EncryptCbc(ReadOnlySpan<uint> roundKeys, ReadOnlySpan<byte> iv, Span<byte> data)
        {
            ref uint rk = ref MemoryMarshal.GetReference(roundKeys);
            ref byte start = ref MemoryMarshal.GetReference(data);
            var byteSwap = ByteSwap32;
            var chain = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(iv));

            for (int offset = 0; offset < data.Length; offset += BlockSize)
            {
                var block = Ssse3.Shuffle(Vector128.LoadUnsafe(ref start, (nuint)offset) ^ chain, byteSwap).AsUInt32();
                var x0 = block;
                var x1 = Sse2.Shuffle(block, 1);
                var x2 = Sse2.Shuffle(block, 2);
                var x3 = Sse2.Shuffle(block, 3);
                for (int i = 0; i < RoundCount; i += 4)
                {
                    x0 ^= Round(x1 ^ x2 ^ x3 ^ Vector128.CreateScalarUnsafe(Unsafe.Add(ref rk, i)));
                    x1 ^= Round(x2 ^ x3 ^ x0 ^ Vector128.CreateScalarUnsafe(Unsafe.Add(ref rk, i + 1)));
                    x2 ^= Round(x3 ^ x0 ^ x1 ^ Vector128.CreateScalarUnsafe(Unsafe.Add(ref rk, i + 2)));
                    x3 ^= Round(x0 ^ x1 ^ x2 ^ Vector128.CreateScalarUnsafe(Unsafe.Add(ref rk, i + 3)));
                }

                // The cipher's final swap: output words are x3, x2, x1, x0.
                var low = Sse2.UnpackLow(x3, x2).AsUInt64();
                var high = Sse2.UnpackLow(x1, x0).AsUInt64();
                chain = Ssse3.Shuffle(Sse2.UnpackLow(low, high).AsByte(), byteSwap);
                chain.StoreUnsafe(ref start, (nuint)offset);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static void DecryptCbc(ReadOnlySpan<uint> roundKeys, ReadOnlySpan<byte> iv, Span<byte> data)
        {
            Span<byte> previous = stackalloc byte[BlockSize];
            iv[..BlockSize].CopyTo(previous);
            ref byte start = ref MemoryMarshal.GetReference(data);
            ref uint rk = ref MemoryMarshal.GetReference(roundKeys);

            int offset = 0;
            if (Avx2.IsSupported && !ForceNoAvx2)
            {
                offset = DecryptEight(ref rk, previous, ref start, data.Length);
            }
            for (; offset + 4 * BlockSize <= data.Length; offset += 4 * BlockSize)
            {
                var p0 = Vector128.LoadUnsafe(ref start, (nuint)offset);
                var p1 = Vector128.LoadUnsafe(ref start, (nuint)(offset + BlockSize));
                var p2 = Vector128.LoadUnsafe(ref start, (nuint)(offset + 2 * BlockSize));
                var p3 = Vector128.LoadUnsafe(ref start, (nuint)(offset + 3 * BlockSize));

                // Rearrange four big-endian blocks into four vectors of same-position words.
                var byteSwap = ByteSwap32;
                var a = Ssse3.Shuffle(p0, byteSwap).AsUInt32();
                var b = Ssse3.Shuffle(p1, byteSwap).AsUInt32();
                var c = Ssse3.Shuffle(p2, byteSwap).AsUInt32();
                var d = Ssse3.Shuffle(p3, byteSwap).AsUInt32();
                Transpose(ref a, ref b, ref c, ref d);

                for (int i = RoundCount - 1; i >= 0; i -= 4)
                {
                    a ^= Round(b ^ c ^ d ^ Vector128.Create(Unsafe.Add(ref rk, i)));
                    b ^= Round(c ^ d ^ a ^ Vector128.Create(Unsafe.Add(ref rk, i - 1)));
                    c ^= Round(d ^ a ^ b ^ Vector128.Create(Unsafe.Add(ref rk, i - 2)));
                    d ^= Round(a ^ b ^ c ^ Vector128.Create(Unsafe.Add(ref rk, i - 3)));
                }

                // The cipher's final swap reverses the word order within each block.
                Transpose(ref d, ref c, ref b, ref a);
                var o0 = Ssse3.Shuffle(d.AsByte(), byteSwap) ^ Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(previous));
                var o1 = Ssse3.Shuffle(c.AsByte(), byteSwap) ^ p0;
                var o2 = Ssse3.Shuffle(b.AsByte(), byteSwap) ^ p1;
                var o3 = Ssse3.Shuffle(a.AsByte(), byteSwap) ^ p2;
                o0.StoreUnsafe(ref start, (nuint)offset);
                o1.StoreUnsafe(ref start, (nuint)(offset + BlockSize));
                o2.StoreUnsafe(ref start, (nuint)(offset + 2 * BlockSize));
                o3.StoreUnsafe(ref start, (nuint)(offset + 3 * BlockSize));
                p3.StoreUnsafe(ref MemoryMarshal.GetReference(previous));
            }

            if (offset < data.Length)
            {
                DecryptTail(roundKeys, previous, data[offset..]);
            }
        }

        /// <summary>
        /// CBC-decrypts as many groups of eight blocks as fit, returning the offset reached. There is no 256-bit AESENCLAST
        /// in .NET 8, so only that step is split into two 128-bit halves; everything else runs in 256-bit registers.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        private static int DecryptEight(ref uint rk, Span<byte> previous, ref byte start, int length)
        {
            ref byte chain = ref MemoryMarshal.GetReference(previous);
            var byteSwap = Vector256.Create(ByteSwap32, ByteSwap32);
            int offset = 0;
            for (; offset + 8 * BlockSize <= length; offset += 8 * BlockSize)
            {
                var c01 = Vector256.LoadUnsafe(ref start, (nuint)offset);
                var c23 = Vector256.LoadUnsafe(ref start, (nuint)(offset + 2 * BlockSize));
                var c45 = Vector256.LoadUnsafe(ref start, (nuint)(offset + 4 * BlockSize));
                var c67 = Vector256.LoadUnsafe(ref start, (nuint)(offset + 6 * BlockSize));
                var last = c67.GetUpper();

                // Each 128-bit lane transposes on its own, so pair blocks (0,4), (1,5), (2,6) and (3,7).
                var a = Avx2.Shuffle(Vector256.Create(c01.GetLower(), c45.GetLower()), byteSwap).AsUInt32();
                var b = Avx2.Shuffle(Vector256.Create(c01.GetUpper(), c45.GetUpper()), byteSwap).AsUInt32();
                var c = Avx2.Shuffle(Vector256.Create(c23.GetLower(), c67.GetLower()), byteSwap).AsUInt32();
                var d = Avx2.Shuffle(Vector256.Create(c23.GetUpper(), c67.GetUpper()), byteSwap).AsUInt32();
                Transpose(ref a, ref b, ref c, ref d);

                for (int i = RoundCount - 1; i >= 0; i -= 4)
                {
                    a ^= Round(b ^ c ^ d ^ Vector256.Create(Unsafe.Add(ref rk, i)));
                    b ^= Round(c ^ d ^ a ^ Vector256.Create(Unsafe.Add(ref rk, i - 1)));
                    c ^= Round(d ^ a ^ b ^ Vector256.Create(Unsafe.Add(ref rk, i - 2)));
                    d ^= Round(a ^ b ^ c ^ Vector256.Create(Unsafe.Add(ref rk, i - 3)));
                }

                Transpose(ref d, ref c, ref b, ref a);
                var o0 = Avx2.Shuffle(d.AsByte(), byteSwap);
                var o1 = Avx2.Shuffle(c.AsByte(), byteSwap);
                var o2 = Avx2.Shuffle(b.AsByte(), byteSwap);
                var o3 = Avx2.Shuffle(a.AsByte(), byteSwap);

                // Plaintext i is the block-cipher output XOR ciphertext i-1 (the previous group's last for i = 0).
                var chained = Vector128.LoadUnsafe(ref chain);
                (Vector256.Create(o0.GetLower(), o1.GetLower()) ^ Vector256.Create(chained, c01.GetLower())).StoreUnsafe(ref start, (nuint)offset);
                (Vector256.Create(o2.GetLower(), o3.GetLower()) ^ Vector256.Create(c01.GetUpper(), c23.GetLower())).StoreUnsafe(ref start, (nuint)(offset + 2 * BlockSize));
                (Vector256.Create(o0.GetUpper(), o1.GetUpper()) ^ Vector256.Create(c23.GetUpper(), c45.GetLower())).StoreUnsafe(ref start, (nuint)(offset + 4 * BlockSize));
                (Vector256.Create(o2.GetUpper(), o3.GetUpper()) ^ Vector256.Create(c45.GetUpper(), c67.GetLower())).StoreUnsafe(ref start, (nuint)(offset + 6 * BlockSize));
                last.StoreUnsafe(ref chain);
            }
            return offset;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<uint> Round(Vector256<uint> x)
        {
            var low = Vector256.Create((byte)0x0F);
            var v = x.AsByte();
            var y = Avx2.Shuffle(Vector256.Create(PreLow, PreLow), v & low) ^ Avx2.Shuffle(Vector256.Create(PreHigh, PreHigh), Avx2.ShiftRightLogical(v.AsUInt32(), 4).AsByte() & low);
            y = Avx2.Shuffle(y, Vector256.Create(InverseShiftRows, InverseShiftRows));
            y = Vector256.Create(Aes.EncryptLast(y.GetLower(), Vector128<byte>.Zero), Aes.EncryptLast(y.GetUpper(), Vector128<byte>.Zero));
            var b = Avx2.Shuffle(Vector256.Create(PostLow, PostLow), y & low) ^ Avx2.Shuffle(Vector256.Create(PostHigh, PostHigh), Avx2.ShiftRightLogical(y.AsUInt32(), 4).AsByte() & low);

            var t = (b ^ Avx2.Shuffle(b, Vector256.Create(Rotate8, Rotate8)) ^ Avx2.Shuffle(b, Vector256.Create(Rotate16, Rotate16))).AsUInt32();
            var rotated2 = Avx2.ShiftLeftLogical(t, 2) | Avx2.ShiftRightLogical(t, 30);
            return rotated2 ^ b.AsUInt32() ^ Avx2.Shuffle(b, Vector256.Create(Rotate24, Rotate24)).AsUInt32();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Transpose(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
        {
            var t0 = Avx2.UnpackLow(a, b);
            var t1 = Avx2.UnpackHigh(a, b);
            var t2 = Avx2.UnpackLow(c, d);
            var t3 = Avx2.UnpackHigh(c, d);
            a = Avx2.UnpackLow(t0.AsUInt64(), t2.AsUInt64()).AsUInt32();
            b = Avx2.UnpackHigh(t0.AsUInt64(), t2.AsUInt64()).AsUInt32();
            c = Avx2.UnpackLow(t1.AsUInt64(), t3.AsUInt64()).AsUInt32();
            d = Avx2.UnpackHigh(t1.AsUInt64(), t3.AsUInt64()).AsUInt32();
        }

        /// <summary>Handles the final one to three blocks by decrypting them in a full-width batch of the same vector code.</summary>
        private static void DecryptTail(ReadOnlySpan<uint> roundKeys, ReadOnlySpan<byte> previous, Span<byte> data)
        {
            Span<byte> scratch = stackalloc byte[4 * BlockSize];
            scratch.Clear();
            data.CopyTo(scratch);
            DecryptCbc(roundKeys, previous, scratch);
            scratch[..data.Length].CopyTo(data);
        }

        private static Vector128<byte> ByteSwap32 =>
            Vector128.Create((byte)3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Transpose(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
        {
            var t0 = Sse2.UnpackLow(a, b);
            var t1 = Sse2.UnpackHigh(a, b);
            var t2 = Sse2.UnpackLow(c, d);
            var t3 = Sse2.UnpackHigh(c, d);
            a = Sse2.UnpackLow(t0.AsUInt64(), t2.AsUInt64()).AsUInt32();
            b = Sse2.UnpackHigh(t0.AsUInt64(), t2.AsUInt64()).AsUInt32();
            c = Sse2.UnpackLow(t1.AsUInt64(), t3.AsUInt64()).AsUInt32();
            d = Sse2.UnpackHigh(t1.AsUInt64(), t3.AsUInt64()).AsUInt32();
        }
    }
}
