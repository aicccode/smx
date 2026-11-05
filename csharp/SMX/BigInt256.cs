using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace SMX;

/// <summary>
/// 256-bit unsigned integer stored as 4 ulong limbs in little-endian order.
/// L0 is the least significant 64-bit word.
/// <para>
/// Add, Sub, ModAdd, ModSub, and ModMul or ModInverse with modulus SM2_N or SM2_P run in constant time. With any other
/// modulus, and always in ModPow's exponent, they do not: do not use those with secrets.
/// </para>
/// </summary>
public struct BigInt256 : IEquatable<BigInt256>
{
    private const int ByteSize = 32;

    public ulong L0, L1, L2, L3;

    public BigInt256(ulong l0, ulong l1, ulong l2, ulong l3)
    {
        L0 = l0;
        L1 = l1;
        L2 = l2;
        L3 = l3;
    }

    public static readonly BigInt256 Zero = new(0, 0, 0, 0);
    public static readonly BigInt256 One = new(1, 0, 0, 0);

    /// <summary>
    /// Parses a number: up to 64 hex digits of either case, at least one, with an optional single "0x" prefix. Shorter
    /// values are left-padded with zeros because that keeps the same number. Longer values are rejected, where earlier
    /// versions silently dropped the high digits. Keys and signatures must use exact 64-digit parsing instead.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="s"/> is null.</exception>
    /// <exception cref="ArgumentException">The input is not such a number.</exception>
    public static BigInt256 FromHex(string s)
    {
        ArgumentNullException.ThrowIfNull(s);
        ReadOnlySpan<char> digits = s;
        if (digits.Length >= 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X'))
        {
            digits = digits[2..];
        }
        if (digits.IsEmpty || digits.Length > 2 * ByteSize)
        {
            throw new ArgumentException("Invalid hex number");
        }

        Span<char> padded = stackalloc char[2 * ByteSize];
        padded[..^digits.Length].Fill('0');
        digits.CopyTo(padded[^digits.Length..]);
        bool valid = TryParseExact(padded, out var value);
        padded.Clear();
        return valid ? value : throw new ArgumentException("Invalid hex number");
    }

    /// <summary>Parses exactly 64 hex digits of either case, examining them all, with no prefix.</summary>
    internal static bool TryParseExact(ReadOnlySpan<char> s, out BigInt256 value)
    {
        Span<byte> bytes = stackalloc byte[ByteSize];
        bool valid = HexUtils.TryDecode(s, bytes);
        value = FromBigEndian(bytes);
        CryptographicOperations.ZeroMemory(bytes);
        return valid;
    }

    /// <summary>A big-endian number of at most 32 bytes; shorter input is left-padded with zeros.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="b"/> is null.</exception>
    /// <exception cref="ArgumentException">The input is longer than 32 bytes. Earlier versions kept the low 32 bytes.</exception>
    public static BigInt256 FromBEBytes(byte[] b)
    {
        ArgumentNullException.ThrowIfNull(b);
        if (b.Length > ByteSize)
        {
            throw new ArgumentException("Value exceeds 256 bits");
        }
        Span<byte> padded = stackalloc byte[ByteSize];
        padded[..^b.Length].Clear();
        b.CopyTo(padded[^b.Length..]);
        var value = FromBigEndian(padded);
        CryptographicOperations.ZeroMemory(padded);
        return value;
    }

    /// <summary>Reads exactly 32 big-endian bytes.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static BigInt256 FromBigEndian(ReadOnlySpan<byte> b) => new(
        BinaryPrimitives.ReadUInt64BigEndian(b[24..]),
        BinaryPrimitives.ReadUInt64BigEndian(b[16..]),
        BinaryPrimitives.ReadUInt64BigEndian(b[8..]),
        BinaryPrimitives.ReadUInt64BigEndian(b));

    /// <summary>Writes exactly 32 big-endian bytes.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal readonly void WriteBigEndian(Span<byte> o)
    {
        BinaryPrimitives.WriteUInt64BigEndian(o, L3);
        BinaryPrimitives.WriteUInt64BigEndian(o[8..], L2);
        BinaryPrimitives.WriteUInt64BigEndian(o[16..], L1);
        BinaryPrimitives.WriteUInt64BigEndian(o[24..], L0);
    }

    public readonly byte[] ToBEBytes()
    {
        var o = new byte[32];
        WriteBigEndian(o);
        return o;
    }

    public readonly string ToHex()
    {
        Span<byte> b = stackalloc byte[32];
        WriteBigEndian(b);
        return HexUtils.ToHexUpper(b);
    }

    public readonly string ToHexLower()
    {
        Span<byte> b = stackalloc byte[32];
        WriteBigEndian(b);
        return HexUtils.ToHexLower(b);
    }

    public readonly bool IsZero => (L0 | L1 | L2 | L3) == 0;
    public readonly bool IsOne => ((L0 ^ 1) | L1 | L2 | L3) == 0;

    public readonly int Compare(in BigInt256 b)
    {
        if (L3 != b.L3)
        {
            return L3 > b.L3 ? 1 : -1;
        }
        if (L2 != b.L2)
        {
            return L2 > b.L2 ? 1 : -1;
        }
        if (L1 != b.L1)
        {
            return L1 > b.L1 ? 1 : -1;
        }
        if (L0 != b.L0)
        {
            return L0 > b.L0 ? 1 : -1;
        }
        return 0;
    }

    public readonly BigInt256 Add(in BigInt256 b, out ulong carry)
    {
        BigInt256 r;
        r.L0 = Bits.Add(L0, b.L0, 0, out ulong c);
        r.L1 = Bits.Add(L1, b.L1, c, out c);
        r.L2 = Bits.Add(L2, b.L2, c, out c);
        r.L3 = Bits.Add(L3, b.L3, c, out carry);
        return r;
    }

    public readonly BigInt256 Sub(in BigInt256 b, out ulong borrow)
    {
        BigInt256 r;
        r.L0 = Bits.Sub(L0, b.L0, 0, out ulong c);
        r.L1 = Bits.Sub(L1, b.L1, c, out c);
        r.L2 = Bits.Sub(L2, b.L2, c, out c);
        r.L3 = Bits.Sub(L3, b.L3, c, out borrow);
        return r;
    }

    /// <summary>Full 512-bit product as ulong[8] (little-endian).</summary>
    public readonly ulong[] Mul(in BigInt256 b)
    {
        Wide512.Multiply(this, b, out var w);
        return [w.W0, w.W1, w.W2, w.W3, w.W4, w.W5, w.W6, w.W7];
    }

    /// <summary>Constant time in the operands.</summary>
    public readonly BigInt256 ModAdd(in BigInt256 b, in BigInt256 m)
    {
        var sum = Add(b, out ulong carry);
        var reduced = sum.Sub(m, out ulong borrow);
        return Select(Bits.MaskFromBit(carry | (borrow ^ 1)), reduced, sum);
    }

    /// <summary>Constant time in the operands.</summary>
    public readonly BigInt256 ModSub(in BigInt256 b, in BigInt256 m)
    {
        var diff = Sub(b, out ulong borrow);
        ulong mask = Bits.MaskFromBit(borrow);
        return diff.Add(new BigInt256(m.L0 & mask, m.L1 & mask, m.L2 & mask, m.L3 & mask), out _);
    }

    /// <exception cref="ArgumentException"><paramref name="m"/> is zero.</exception>
    public readonly BigInt256 ModMul(in BigInt256 b, in BigInt256 m)
    {
        if (m == Sm2Order.N)
        {
            Sm2Order.Mul(this, b, out var r);
            return r;
        }
        if (m == Fp.P)
        {
            Fp.Mul(this, b, out var r);
            return r;
        }
        Wide512.Multiply(this, b, out var w);
        return w.Mod(m);
    }

    /// <exception cref="ArgumentException"><paramref name="m"/> is zero.</exception>
    public readonly BigInt256 ModSquare(in BigInt256 m)
    {
        if (m == Fp.P)
        {
            return SM2ModSquareP();
        }
        return ModMul(this, m);
    }

    public readonly BigInt256 SM2ModMulP(in BigInt256 b)
    {
        Fp.Mul(this, b, out var r);
        return r;
    }

    public readonly BigInt256 SM2ModSquareP()
    {
        Fp.Square(this, out var r);
        return r;
    }

    /// <summary>The inverse modulo a prime m. The result is checked: anything without an inverse is rejected.</summary>
    /// <exception cref="ArgumentException">No inverse was found: the value is 0 modulo m, or m is not a prime above 1.</exception>
    public readonly BigInt256 ModInverse(in BigInt256 m)
    {
        BigInt256 r;
        if (m == Sm2Order.N)
        {
            Sm2Order.Invert(this, out r);
        }
        else if (m == Fp.P)
        {
            Fp.Invert(this, out r);
        }
        else
        {
            if (m.IsZero)
            {
                throw new ArgumentException("Modulus must not be zero");
            }
            var pMinus2 = m.Sub(new BigInt256(2, 0, 0, 0), out _);
            r = ModPow(pMinus2, m);
        }
        if (!ModMul(r, m).IsOne)
        {
            throw new ArgumentException("Value has no inverse for this modulus");
        }
        return r;
    }

    /// <summary>Left-to-right binary exponentiation. Timing depends on <paramref name="exp"/>, so keep it public.</summary>
    /// <exception cref="ArgumentException"><paramref name="m"/> is zero.</exception>
    public readonly BigInt256 ModPow(in BigInt256 exp, in BigInt256 m)
    {
        if (exp.IsZero)
        {
            return One;
        }
        // The first multiplication reduces the base, so that a modulus of one yields zero for any exponent.
        var result = One.ModMul(this, m);
        for (int i = exp.BitLength() - 2; i >= 0; i--)
        {
            result = result.ModSquare(m);
            if (exp.GetBit(i))
            {
                result = result.ModMul(this, m);
            }
        }
        return result;
    }

    public readonly bool GetBit(int i)
    {
        if (i is < 0 or >= 256)
        {
            return false;
        }
        int bit = i % 64;
        ulong v = (i / 64) switch
        {
            0 => L0,
            1 => L1,
            2 => L2,
            _ => L3,
        };
        return ((v >> bit) & 1) == 1;
    }

    public readonly int BitLength()
    {
        if (L3 != 0)
        {
            return 256 - BitOperations.LeadingZeroCount(L3);
        }
        if (L2 != 0)
        {
            return 192 - BitOperations.LeadingZeroCount(L2);
        }
        if (L1 != 0)
        {
            return 128 - BitOperations.LeadingZeroCount(L1);
        }
        if (L0 != 0)
        {
            return 64 - BitOperations.LeadingZeroCount(L0);
        }
        return 0;
    }

    public readonly BigInt256 And(in BigInt256 b) => new(L0 & b.L0, L1 & b.L1, L2 & b.L2, L3 & b.L3);

    public readonly BigInt256 ShiftRight1() => new(
        (L0 >> 1) | (L1 << 63),
        (L1 >> 1) | (L2 << 63),
        (L2 >> 1) | (L3 << 63),
        L3 >> 1);

    public readonly BigInt256 ShiftLeft1() => new(
        L0 << 1,
        (L1 << 1) | (L0 >> 63),
        (L2 << 1) | (L1 >> 63),
        (L3 << 1) | (L2 >> 63));

    /// <summary>All ones when the value is zero, otherwise zero. Constant time.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal readonly ulong IsZeroMask() => Bits.IsZeroMask(L0 | L1 | L2 | L3);

    /// <summary>Constant-time selection on a mask of all ones or all zeros.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static BigInt256 Select(ulong mask, in BigInt256 ifSet, in BigInt256 ifClear) => new(
        Bits.Select(mask, ifSet.L0, ifClear.L0),
        Bits.Select(mask, ifSet.L1, ifClear.L1),
        Bits.Select(mask, ifSet.L2, ifClear.L2),
        Bits.Select(mask, ifSet.L3, ifClear.L3));

    public readonly bool Equals(BigInt256 other) => ((L0 ^ other.L0) | (L1 ^ other.L1) | (L2 ^ other.L2) | (L3 ^ other.L3)) == 0;
    public override readonly bool Equals(object? obj) => obj is BigInt256 b && Equals(b);
    public override readonly int GetHashCode() => HashCode.Combine(L0, L1, L2, L3);
    public static bool operator ==(BigInt256 a, BigInt256 b) => a.Equals(b);
    public static bool operator !=(BigInt256 a, BigInt256 b) => !a.Equals(b);
}
