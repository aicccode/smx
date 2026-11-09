using System.Security.Cryptography;

namespace SMX.SM9Internal;

/// <summary>
/// Arithmetic modulo the group order N on plain (not Montgomery) 256-bit values, and the SM9 hash functions. All
/// operations on scalars are constant time.
/// </summary>
internal static class Sm9Scalar
{
    private const ulong N0 = 0xE56EE19CD69ECF25, N1 = 0x49F2934B18EA8BEE, N2 = 0xD603AB4FF58EC744, N3 = 0xB640000002A3A6F1;
    private const ulong NInv = 0x1D02662351974B53;
    private const ulong RR0 = 0x7598CD79CD750C35, RR1 = 0xE4A08110BB6DAEAB, RR2 = 0xBFEE4BAE7D78A1F9, RR3 = 0x8894F5D163695D0E;

    public static readonly BigInt256 N = new(N0, N1, N2, N3);
    public static readonly BigInt256 NMinus1 = new(N0 - 1, N1, N2, N3);

    public const int ScalarSize = 32;
    public const int HashSize = Sm3Hasher.DigestSize;

    /// <summary>All ones when 1 &lt;= k &lt;= N-1.</summary>
    public static ulong InRangeMask(in BigInt256 k) =>
        Mont256.LessMask(k.L0, k.L1, k.L2, k.L3, N0, N1, N2, N3) & ~Bits.IsZeroMask(k.L0 | k.L1 | k.L2 | k.L3);

    public static BigInt256 Add(in BigInt256 a, in BigInt256 b)
    {
        Mont256.Add(a.L0, a.L1, a.L2, a.L3, b.L0, b.L1, b.L2, b.L3, N0, N1, N2, N3, out var r0, out var r1, out var r2, out var r3);
        return new BigInt256(r0, r1, r2, r3);
    }

    public static BigInt256 Sub(in BigInt256 a, in BigInt256 b)
    {
        Mont256.Sub(a.L0, a.L1, a.L2, a.L3, b.L0, b.L1, b.L2, b.L3, N0, N1, N2, N3, out var r0, out var r1, out var r2, out var r3);
        return new BigInt256(r0, r1, r2, r3);
    }

    private static BigInt256 MontMul(in BigInt256 a, in BigInt256 b)
    {
        Mont256.Mul(a.L0, a.L1, a.L2, a.L3, b.L0, b.L1, b.L2, b.L3, N0, N1, N2, N3, NInv, out var r0, out var r1, out var r2, out var r3);
        return new BigInt256(r0, r1, r2, r3);
    }

    /// <summary>a * b mod N for a, b in [0, N).</summary>
    public static BigInt256 Mul(in BigInt256 a, in BigInt256 b) => MontMul(MontMul(a, b), new BigInt256(RR0, RR1, RR2, RR3));

    /// <summary>a^-1 mod N by Fermat (a^(N-2)), with zero mapping to zero; the exponent is public.</summary>
    public static BigInt256 Invert(in BigInt256 a)
    {
        var rr = new BigInt256(RR0, RR1, RR2, RR3);
        var aMont = MontMul(a, rr);
        var r = MontMul(BigInt256.One, rr);
        ReadOnlySpan<ulong> e = [N0 - 2, N1, N2, N3];
        for (int limb = 3; limb >= 0; limb--)
        {
            for (int bit = 63; bit >= 0; bit--)
            {
                r = MontMul(r, r);
                if (((e[limb] >> bit) & 1) != 0)
                {
                    r = MontMul(r, aMont);
                }
            }
        }
        return MontMul(r, BigInt256.One);
    }

    /// <summary>
    /// H1 (tag 1) or H2 (tag 2) of GB/T 38635.2 on the concatenation of the parts: Ha = SM3(tag || Z || 1) || the first
    /// 8 bytes of SM3(tag || Z || 2), and the result (Ha mod (N-1)) + 1, in [1, N-1].
    /// </summary>
    public static BigInt256 Hash(byte tag, ReadOnlySpan<byte> part1, ReadOnlySpan<byte> part2 = default)
    {
        var h = Sm3Hasher.Create();
        h.UpdateByte(tag);
        h.Update(part1);
        h.Update(part2);
        return HashFinish(ref h);
    }

    /// <summary>Completes <see cref="Hash"/> from a hasher that has absorbed tag || Z.</summary>
    public static BigInt256 HashFinish(ref Sm3Hasher h)
    {
        Span<byte> ha = stackalloc byte[2 * HashSize];
        h.FinishWithCounter(1, ha);
        h.FinishWithCounter(2, ha[HashSize..]);
        h.Wipe();

        // Ha is 40 bytes: the top 32 form a value below 2^256 < 2(N-1), reduced with one subtraction; then each of the
        // remaining 64 bits is shifted in with a conditional subtraction, all without branches.
        var r = ReduceOnceNMinus1(BigInt256.FromBigEndian(ha[..32]), 0);
        for (int i = 32; i < 40; i++)
        {
            for (int bit = 7; bit >= 0; bit--)
            {
                ulong top = r.L3 >> 63;
                var doubled = new BigInt256(
                    (r.L0 << 1) | (ulong)(uint)((ha[i] >> bit) & 1),
                    (r.L1 << 1) | (r.L0 >> 63),
                    (r.L2 << 1) | (r.L1 >> 63),
                    (r.L3 << 1) | (r.L2 >> 63));
                r = ReduceOnceNMinus1(doubled, top);
            }
        }
        CryptographicOperations.ZeroMemory(ha);
        return Add(r, BigInt256.One);
    }

    /// <summary>Subtracts N-1 once when the 257-bit value (top, v) is at least N-1.</summary>
    private static BigInt256 ReduceOnceNMinus1(in BigInt256 v, ulong top)
    {
        var m = NMinus1;
        ulong d0 = Bits.Sub(v.L0, m.L0, 0, out ulong b);
        ulong d1 = Bits.Sub(v.L1, m.L1, b, out b);
        ulong d2 = Bits.Sub(v.L2, m.L2, b, out b);
        ulong d3 = Bits.Sub(v.L3, m.L3, b, out b);
        ulong keep = Bits.MaskFromBit(top | (b ^ 1));
        return new BigInt256(Bits.Select(keep, d0, v.L0), Bits.Select(keep, d1, v.L1),
            Bits.Select(keep, d2, v.L2), Bits.Select(keep, d3, v.L3));
    }

    /// <summary>
    /// Writes KDF(Z, output.Length): SM3(Z || ct) blocks for a 32-bit big-endian ct from 1, from a hasher that has absorbed
    /// Z. The absorbed state is reused for every block.
    /// </summary>
    public static void Kdf(in Sm3Hasher prefix, Span<byte> output)
    {
        Span<byte> block = stackalloc byte[HashSize];
        uint counter = 1;
        for (int offset = 0; offset < output.Length; offset += HashSize)
        {
            prefix.FinishWithCounter(counter++, block);
            int count = Math.Min(HashSize, output.Length - offset);
            block[..count].CopyTo(output[offset..]);
        }
        CryptographicOperations.ZeroMemory(block);
    }

    /// <summary>Exactly 64 hex digits of either case, in [1, N-1]; every digit and limb is examined either way.</summary>
    public static bool TryParse(string? hex, out BigInt256 k)
    {
        k = default;
        if (hex is null)
        {
            return false;
        }
        bool wellFormed = BigInt256.TryParseExact(hex, out k);
        return wellFormed & InRangeMask(k) != 0;
    }

    public static string ToHex(in BigInt256 k)
    {
        Span<byte> bytes = stackalloc byte[ScalarSize];
        k.WriteBigEndian(bytes);
        var s = HexUtils.ToHexLower(bytes);
        CryptographicOperations.ZeroMemory(bytes);
        return s;
    }
}
