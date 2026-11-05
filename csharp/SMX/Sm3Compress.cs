using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SMX;

/// <summary>SM3 chaining value.</summary>
internal struct Sm3State
{
    public uint A, B, C, D, E, F, G, H;

    public static Sm3State Initial => new()
    {
        A = 0x7380166F,
        B = 0x4914B2B9,
        C = 0x172442D7,
        D = 0xDA8A0600,
        E = 0xA96F30BC,
        F = 0x163138AA,
        G = 0xE38DEE4D,
        H = 0xB0FB0E4E,
    };

    public readonly void WriteBigEndian(Span<byte> o)
    {
        BinaryPrimitives.WriteUInt32BigEndian(o, A);
        BinaryPrimitives.WriteUInt32BigEndian(o[4..], B);
        BinaryPrimitives.WriteUInt32BigEndian(o[8..], C);
        BinaryPrimitives.WriteUInt32BigEndian(o[12..], D);
        BinaryPrimitives.WriteUInt32BigEndian(o[16..], E);
        BinaryPrimitives.WriteUInt32BigEndian(o[20..], F);
        BinaryPrimitives.WriteUInt32BigEndian(o[24..], G);
        BinaryPrimitives.WriteUInt32BigEndian(o[28..], H);
    }
}

/// <summary>
/// The SM3 compression function. Rounds are written out so that the eight state words stay in place and only their
/// names rotate, with each round constant T(j) rotated in advance.
/// </summary>
internal static class Sm3Compress
{
    private const int WordsPerBlock = 68;

    /// <summary>Absorbs whole 64-byte blocks.</summary>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static unsafe void Blocks(ref Sm3State state, ReadOnlySpan<byte> blocks)
    {
        uint* w = stackalloc uint[WordsPerBlock];
        uint a = state.A, b = state.B, c = state.C, d = state.D;
        uint e = state.E, f = state.F, g = state.G, h = state.H;
        ref byte input = ref MemoryMarshal.GetReference(blocks);

        for (int offset = 0; offset + 64 <= blocks.Length; offset += 64)
        {
            for (int j = 0; j < 16; j++)
            {
                w[j] = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, offset + j * 4)));
            }
            for (int j = 16; j < WordsPerBlock; j++)
            {
                uint x = w[j - 16] ^ w[j - 9] ^ uint.RotateLeft(w[j - 3], 15);
                w[j] = x ^ uint.RotateLeft(x, 15) ^ uint.RotateLeft(x, 23) ^ uint.RotateLeft(w[j - 13], 7) ^ w[j - 6];
            }

            uint a0 = a, b0 = b, c0 = c, d0 = d, e0 = e, f0 = f, g0 = g, h0 = h;
            uint a12, ss1;

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0x79CC4519, 7);
            d += (a ^ b ^ c) + (ss1 ^ a12) + (w[0] ^ w[4]);
            h += (e ^ f ^ g) + ss1 + w[0];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0xF3988A32, 7);
            c += (d ^ a ^ b) + (ss1 ^ a12) + (w[1] ^ w[5]);
            g += (h ^ e ^ f) + ss1 + w[1];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0xE7311465, 7);
            b += (c ^ d ^ a) + (ss1 ^ a12) + (w[2] ^ w[6]);
            f += (g ^ h ^ e) + ss1 + w[2];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0xCE6228CB, 7);
            a += (b ^ c ^ d) + (ss1 ^ a12) + (w[3] ^ w[7]);
            e += (f ^ g ^ h) + ss1 + w[3];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0x9CC45197, 7);
            d += (a ^ b ^ c) + (ss1 ^ a12) + (w[4] ^ w[8]);
            h += (e ^ f ^ g) + ss1 + w[4];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0x3988A32F, 7);
            c += (d ^ a ^ b) + (ss1 ^ a12) + (w[5] ^ w[9]);
            g += (h ^ e ^ f) + ss1 + w[5];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0x7311465E, 7);
            b += (c ^ d ^ a) + (ss1 ^ a12) + (w[6] ^ w[10]);
            f += (g ^ h ^ e) + ss1 + w[6];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0xE6228CBC, 7);
            a += (b ^ c ^ d) + (ss1 ^ a12) + (w[7] ^ w[11]);
            e += (f ^ g ^ h) + ss1 + w[7];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0xCC451979, 7);
            d += (a ^ b ^ c) + (ss1 ^ a12) + (w[8] ^ w[12]);
            h += (e ^ f ^ g) + ss1 + w[8];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0x988A32F3, 7);
            c += (d ^ a ^ b) + (ss1 ^ a12) + (w[9] ^ w[13]);
            g += (h ^ e ^ f) + ss1 + w[9];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0x311465E7, 7);
            b += (c ^ d ^ a) + (ss1 ^ a12) + (w[10] ^ w[14]);
            f += (g ^ h ^ e) + ss1 + w[10];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0x6228CBCE, 7);
            a += (b ^ c ^ d) + (ss1 ^ a12) + (w[11] ^ w[15]);
            e += (f ^ g ^ h) + ss1 + w[11];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0xC451979C, 7);
            d += (a ^ b ^ c) + (ss1 ^ a12) + (w[12] ^ w[16]);
            h += (e ^ f ^ g) + ss1 + w[12];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0x88A32F39, 7);
            c += (d ^ a ^ b) + (ss1 ^ a12) + (w[13] ^ w[17]);
            g += (h ^ e ^ f) + ss1 + w[13];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0x11465E73, 7);
            b += (c ^ d ^ a) + (ss1 ^ a12) + (w[14] ^ w[18]);
            f += (g ^ h ^ e) + ss1 + w[14];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0x228CBCE6, 7);
            a += (b ^ c ^ d) + (ss1 ^ a12) + (w[15] ^ w[19]);
            e += (f ^ g ^ h) + ss1 + w[15];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0x9D8A7A87, 7);
            d += (((a ^ b) & c) ^ (a & b)) + (ss1 ^ a12) + (w[16] ^ w[20]);
            h += (((f ^ g) & e) ^ g) + ss1 + w[16];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0x3B14F50F, 7);
            c += (((d ^ a) & b) ^ (d & a)) + (ss1 ^ a12) + (w[17] ^ w[21]);
            g += (((e ^ f) & h) ^ f) + ss1 + w[17];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0x7629EA1E, 7);
            b += (((c ^ d) & a) ^ (c & d)) + (ss1 ^ a12) + (w[18] ^ w[22]);
            f += (((h ^ e) & g) ^ e) + ss1 + w[18];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0xEC53D43C, 7);
            a += (((b ^ c) & d) ^ (b & c)) + (ss1 ^ a12) + (w[19] ^ w[23]);
            e += (((g ^ h) & f) ^ h) + ss1 + w[19];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0xD8A7A879, 7);
            d += (((a ^ b) & c) ^ (a & b)) + (ss1 ^ a12) + (w[20] ^ w[24]);
            h += (((f ^ g) & e) ^ g) + ss1 + w[20];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0xB14F50F3, 7);
            c += (((d ^ a) & b) ^ (d & a)) + (ss1 ^ a12) + (w[21] ^ w[25]);
            g += (((e ^ f) & h) ^ f) + ss1 + w[21];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0x629EA1E7, 7);
            b += (((c ^ d) & a) ^ (c & d)) + (ss1 ^ a12) + (w[22] ^ w[26]);
            f += (((h ^ e) & g) ^ e) + ss1 + w[22];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0xC53D43CE, 7);
            a += (((b ^ c) & d) ^ (b & c)) + (ss1 ^ a12) + (w[23] ^ w[27]);
            e += (((g ^ h) & f) ^ h) + ss1 + w[23];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0x8A7A879D, 7);
            d += (((a ^ b) & c) ^ (a & b)) + (ss1 ^ a12) + (w[24] ^ w[28]);
            h += (((f ^ g) & e) ^ g) + ss1 + w[24];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0x14F50F3B, 7);
            c += (((d ^ a) & b) ^ (d & a)) + (ss1 ^ a12) + (w[25] ^ w[29]);
            g += (((e ^ f) & h) ^ f) + ss1 + w[25];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0x29EA1E76, 7);
            b += (((c ^ d) & a) ^ (c & d)) + (ss1 ^ a12) + (w[26] ^ w[30]);
            f += (((h ^ e) & g) ^ e) + ss1 + w[26];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0x53D43CEC, 7);
            a += (((b ^ c) & d) ^ (b & c)) + (ss1 ^ a12) + (w[27] ^ w[31]);
            e += (((g ^ h) & f) ^ h) + ss1 + w[27];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0xA7A879D8, 7);
            d += (((a ^ b) & c) ^ (a & b)) + (ss1 ^ a12) + (w[28] ^ w[32]);
            h += (((f ^ g) & e) ^ g) + ss1 + w[28];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0x4F50F3B1, 7);
            c += (((d ^ a) & b) ^ (d & a)) + (ss1 ^ a12) + (w[29] ^ w[33]);
            g += (((e ^ f) & h) ^ f) + ss1 + w[29];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0x9EA1E762, 7);
            b += (((c ^ d) & a) ^ (c & d)) + (ss1 ^ a12) + (w[30] ^ w[34]);
            f += (((h ^ e) & g) ^ e) + ss1 + w[30];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0x3D43CEC5, 7);
            a += (((b ^ c) & d) ^ (b & c)) + (ss1 ^ a12) + (w[31] ^ w[35]);
            e += (((g ^ h) & f) ^ h) + ss1 + w[31];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0x7A879D8A, 7);
            d += (((a ^ b) & c) ^ (a & b)) + (ss1 ^ a12) + (w[32] ^ w[36]);
            h += (((f ^ g) & e) ^ g) + ss1 + w[32];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0xF50F3B14, 7);
            c += (((d ^ a) & b) ^ (d & a)) + (ss1 ^ a12) + (w[33] ^ w[37]);
            g += (((e ^ f) & h) ^ f) + ss1 + w[33];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0xEA1E7629, 7);
            b += (((c ^ d) & a) ^ (c & d)) + (ss1 ^ a12) + (w[34] ^ w[38]);
            f += (((h ^ e) & g) ^ e) + ss1 + w[34];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0xD43CEC53, 7);
            a += (((b ^ c) & d) ^ (b & c)) + (ss1 ^ a12) + (w[35] ^ w[39]);
            e += (((g ^ h) & f) ^ h) + ss1 + w[35];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0xA879D8A7, 7);
            d += (((a ^ b) & c) ^ (a & b)) + (ss1 ^ a12) + (w[36] ^ w[40]);
            h += (((f ^ g) & e) ^ g) + ss1 + w[36];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0x50F3B14F, 7);
            c += (((d ^ a) & b) ^ (d & a)) + (ss1 ^ a12) + (w[37] ^ w[41]);
            g += (((e ^ f) & h) ^ f) + ss1 + w[37];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0xA1E7629E, 7);
            b += (((c ^ d) & a) ^ (c & d)) + (ss1 ^ a12) + (w[38] ^ w[42]);
            f += (((h ^ e) & g) ^ e) + ss1 + w[38];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0x43CEC53D, 7);
            a += (((b ^ c) & d) ^ (b & c)) + (ss1 ^ a12) + (w[39] ^ w[43]);
            e += (((g ^ h) & f) ^ h) + ss1 + w[39];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0x879D8A7A, 7);
            d += (((a ^ b) & c) ^ (a & b)) + (ss1 ^ a12) + (w[40] ^ w[44]);
            h += (((f ^ g) & e) ^ g) + ss1 + w[40];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0x0F3B14F5, 7);
            c += (((d ^ a) & b) ^ (d & a)) + (ss1 ^ a12) + (w[41] ^ w[45]);
            g += (((e ^ f) & h) ^ f) + ss1 + w[41];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0x1E7629EA, 7);
            b += (((c ^ d) & a) ^ (c & d)) + (ss1 ^ a12) + (w[42] ^ w[46]);
            f += (((h ^ e) & g) ^ e) + ss1 + w[42];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0x3CEC53D4, 7);
            a += (((b ^ c) & d) ^ (b & c)) + (ss1 ^ a12) + (w[43] ^ w[47]);
            e += (((g ^ h) & f) ^ h) + ss1 + w[43];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0x79D8A7A8, 7);
            d += (((a ^ b) & c) ^ (a & b)) + (ss1 ^ a12) + (w[44] ^ w[48]);
            h += (((f ^ g) & e) ^ g) + ss1 + w[44];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0xF3B14F50, 7);
            c += (((d ^ a) & b) ^ (d & a)) + (ss1 ^ a12) + (w[45] ^ w[49]);
            g += (((e ^ f) & h) ^ f) + ss1 + w[45];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0xE7629EA1, 7);
            b += (((c ^ d) & a) ^ (c & d)) + (ss1 ^ a12) + (w[46] ^ w[50]);
            f += (((h ^ e) & g) ^ e) + ss1 + w[46];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0xCEC53D43, 7);
            a += (((b ^ c) & d) ^ (b & c)) + (ss1 ^ a12) + (w[47] ^ w[51]);
            e += (((g ^ h) & f) ^ h) + ss1 + w[47];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0x9D8A7A87, 7);
            d += (((a ^ b) & c) ^ (a & b)) + (ss1 ^ a12) + (w[48] ^ w[52]);
            h += (((f ^ g) & e) ^ g) + ss1 + w[48];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0x3B14F50F, 7);
            c += (((d ^ a) & b) ^ (d & a)) + (ss1 ^ a12) + (w[49] ^ w[53]);
            g += (((e ^ f) & h) ^ f) + ss1 + w[49];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0x7629EA1E, 7);
            b += (((c ^ d) & a) ^ (c & d)) + (ss1 ^ a12) + (w[50] ^ w[54]);
            f += (((h ^ e) & g) ^ e) + ss1 + w[50];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0xEC53D43C, 7);
            a += (((b ^ c) & d) ^ (b & c)) + (ss1 ^ a12) + (w[51] ^ w[55]);
            e += (((g ^ h) & f) ^ h) + ss1 + w[51];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0xD8A7A879, 7);
            d += (((a ^ b) & c) ^ (a & b)) + (ss1 ^ a12) + (w[52] ^ w[56]);
            h += (((f ^ g) & e) ^ g) + ss1 + w[52];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0xB14F50F3, 7);
            c += (((d ^ a) & b) ^ (d & a)) + (ss1 ^ a12) + (w[53] ^ w[57]);
            g += (((e ^ f) & h) ^ f) + ss1 + w[53];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0x629EA1E7, 7);
            b += (((c ^ d) & a) ^ (c & d)) + (ss1 ^ a12) + (w[54] ^ w[58]);
            f += (((h ^ e) & g) ^ e) + ss1 + w[54];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0xC53D43CE, 7);
            a += (((b ^ c) & d) ^ (b & c)) + (ss1 ^ a12) + (w[55] ^ w[59]);
            e += (((g ^ h) & f) ^ h) + ss1 + w[55];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0x8A7A879D, 7);
            d += (((a ^ b) & c) ^ (a & b)) + (ss1 ^ a12) + (w[56] ^ w[60]);
            h += (((f ^ g) & e) ^ g) + ss1 + w[56];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0x14F50F3B, 7);
            c += (((d ^ a) & b) ^ (d & a)) + (ss1 ^ a12) + (w[57] ^ w[61]);
            g += (((e ^ f) & h) ^ f) + ss1 + w[57];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0x29EA1E76, 7);
            b += (((c ^ d) & a) ^ (c & d)) + (ss1 ^ a12) + (w[58] ^ w[62]);
            f += (((h ^ e) & g) ^ e) + ss1 + w[58];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0x53D43CEC, 7);
            a += (((b ^ c) & d) ^ (b & c)) + (ss1 ^ a12) + (w[59] ^ w[63]);
            e += (((g ^ h) & f) ^ h) + ss1 + w[59];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a12 = uint.RotateLeft(a, 12);
            ss1 = uint.RotateLeft(a12 + e + 0xA7A879D8, 7);
            d += (((a ^ b) & c) ^ (a & b)) + (ss1 ^ a12) + (w[60] ^ w[64]);
            h += (((f ^ g) & e) ^ g) + ss1 + w[60];
            b = uint.RotateLeft(b, 9);
            f = uint.RotateLeft(f, 19);
            h ^= uint.RotateLeft(h, 9) ^ uint.RotateLeft(h, 17);

            a12 = uint.RotateLeft(d, 12);
            ss1 = uint.RotateLeft(a12 + h + 0x4F50F3B1, 7);
            c += (((d ^ a) & b) ^ (d & a)) + (ss1 ^ a12) + (w[61] ^ w[65]);
            g += (((e ^ f) & h) ^ f) + ss1 + w[61];
            a = uint.RotateLeft(a, 9);
            e = uint.RotateLeft(e, 19);
            g ^= uint.RotateLeft(g, 9) ^ uint.RotateLeft(g, 17);

            a12 = uint.RotateLeft(c, 12);
            ss1 = uint.RotateLeft(a12 + g + 0x9EA1E762, 7);
            b += (((c ^ d) & a) ^ (c & d)) + (ss1 ^ a12) + (w[62] ^ w[66]);
            f += (((h ^ e) & g) ^ e) + ss1 + w[62];
            d = uint.RotateLeft(d, 9);
            h = uint.RotateLeft(h, 19);
            f ^= uint.RotateLeft(f, 9) ^ uint.RotateLeft(f, 17);

            a12 = uint.RotateLeft(b, 12);
            ss1 = uint.RotateLeft(a12 + f + 0x3D43CEC5, 7);
            a += (((b ^ c) & d) ^ (b & c)) + (ss1 ^ a12) + (w[63] ^ w[67]);
            e += (((g ^ h) & f) ^ h) + ss1 + w[63];
            c = uint.RotateLeft(c, 9);
            g = uint.RotateLeft(g, 19);
            e ^= uint.RotateLeft(e, 9) ^ uint.RotateLeft(e, 17);

            a ^= a0;
            b ^= b0;
            c ^= c0;
            d ^= d0;
            e ^= e0;
            f ^= f0;
            g ^= g0;
            h ^= h0;
        }

        // The expanded schedule of a block can derive from secrets; do not leave it on the stack.
        CryptographicOperations.ZeroMemory(new Span<byte>(w, WordsPerBlock * sizeof(uint)));

        state.A = a;
        state.B = b;
        state.C = c;
        state.D = d;
        state.E = e;
        state.F = f;
        state.G = g;
        state.H = h;
    }
}
