using System.Numerics;

namespace SMX;

/// <summary>
/// 256-bit unsigned integer stored as 4 ulong limbs in little-endian order.
/// limbs[0] is the least significant 64-bit word.
/// </summary>
public struct BigInt256 : IEquatable<BigInt256>
{
    public ulong L0, L1, L2, L3;

    public BigInt256(ulong l0, ulong l1, ulong l2, ulong l3)
    {
        L0 = l0; L1 = l1; L2 = l2; L3 = l3;
    }

    public static readonly BigInt256 Zero = new(0, 0, 0, 0);
    public static readonly BigInt256 One = new(1, 0, 0, 0);

    public static BigInt256 FromHex(string s)
    {
        if (s.StartsWith("0x") || s.StartsWith("0X"))
            s = s[2..];
        if (s.Length % 2 == 1)
            s = "0" + s;
        var b = HexUtils.HexToBytes(s);
        var padded = new byte[32];
        int start = 32 - b.Length;
        if (start < 0) { b = b[^32..]; start = 0; }
        Array.Copy(b, 0, padded, start, b.Length);
        return FromBEBytes(padded);
    }

    public static BigInt256 FromBEBytes(byte[] b)
    {
        var padded = new byte[32];
        int start = 32 - b.Length;
        if (start < 0) { b = b[^32..]; start = 0; }
        Array.Copy(b, 0, padded, start, b.Length);

        BigInt256 r = default;
        for (int i = 0; i < 4; i++)
        {
            int off = (3 - i) * 8;
            ulong v = (ulong)padded[off] << 56 | (ulong)padded[off + 1] << 48 |
                      (ulong)padded[off + 2] << 40 | (ulong)padded[off + 3] << 32 |
                      (ulong)padded[off + 4] << 24 | (ulong)padded[off + 5] << 16 |
                      (ulong)padded[off + 6] << 8 | (ulong)padded[off + 7];
            switch (i)
            {
                case 0: r.L0 = v; break;
                case 1: r.L1 = v; break;
                case 2: r.L2 = v; break;
                case 3: r.L3 = v; break;
            }
        }
        return r;
    }

    public byte[] ToBEBytes()
    {
        var o = new byte[32];
        void Write(int off, ulong v)
        {
            o[off] = (byte)(v >> 56); o[off + 1] = (byte)(v >> 48);
            o[off + 2] = (byte)(v >> 40); o[off + 3] = (byte)(v >> 32);
            o[off + 4] = (byte)(v >> 24); o[off + 5] = (byte)(v >> 16);
            o[off + 6] = (byte)(v >> 8); o[off + 7] = (byte)v;
        }
        Write(0, L3); Write(8, L2); Write(16, L1); Write(24, L0);
        return o;
    }

    public string ToHex() => HexUtils.BytesToHexUpper(ToBEBytes());
    public string ToHexLower() => HexUtils.BytesToHex(ToBEBytes());

    public bool IsZero => L0 == 0 && L1 == 0 && L2 == 0 && L3 == 0;
    public bool IsOne => L0 == 1 && L1 == 0 && L2 == 0 && L3 == 0;

    public int Compare(in BigInt256 b)
    {
        if (L3 != b.L3) return L3 > b.L3 ? 1 : -1;
        if (L2 != b.L2) return L2 > b.L2 ? 1 : -1;
        if (L1 != b.L1) return L1 > b.L1 ? 1 : -1;
        if (L0 != b.L0) return L0 > b.L0 ? 1 : -1;
        return 0;
    }

    public BigInt256 Add(in BigInt256 b, out ulong carry)
    {
        BigInt256 r;
        ulong c;
        (r.L0, c) = Add64(L0, b.L0, 0);
        (r.L1, c) = Add64(L1, b.L1, c);
        (r.L2, c) = Add64(L2, b.L2, c);
        (r.L3, carry) = Add64(L3, b.L3, c);
        return r;
    }

    public BigInt256 Sub(in BigInt256 b, out ulong borrow)
    {
        BigInt256 r;
        ulong bw;
        (r.L0, bw) = Sub64(L0, b.L0, 0);
        (r.L1, bw) = Sub64(L1, b.L1, bw);
        (r.L2, bw) = Sub64(L2, b.L2, bw);
        (r.L3, borrow) = Sub64(L3, b.L3, bw);
        return r;
    }

    private static (ulong sum, ulong carry) Add64(ulong a, ulong b, ulong carryIn)
    {
        ulong s = a + b;
        ulong c1 = s < a ? 1UL : 0UL;
        ulong r = s + carryIn;
        ulong c2 = r < s ? 1UL : 0UL;
        return (r, c1 + c2);
    }

    private static (ulong diff, ulong borrow) Sub64(ulong a, ulong b, ulong borrowIn)
    {
        ulong d = a - b;
        ulong b1 = d > a ? 1UL : 0UL;
        ulong r = d - borrowIn;
        ulong b2 = r > d ? 1UL : 0UL;
        return (r, b1 + b2);
    }

    /// <summary>Full 512-bit product as ulong[8] (little-endian).</summary>
    public ulong[] Mul(in BigInt256 b)
    {
        var result = new ulong[8];
        ulong[] aLimbs = [L0, L1, L2, L3];
        ulong[] bLimbs = [b.L0, b.L1, b.L2, b.L3];

        for (int i = 0; i < 4; i++)
        {
            ulong carry = 0;
            for (int j = 0; j < 4; j++)
            {
                ulong hi = Math.BigMul(aLimbs[i], bLimbs[j], out ulong lo);
                lo += result[i + j];
                if (lo < result[i + j]) hi++;
                lo += carry;
                if (lo < carry) hi++;
                result[i + j] = lo;
                carry = hi;
            }
            result[i + 4] = carry;
        }
        return result;
    }

    public BigInt256 ModAdd(in BigInt256 b, in BigInt256 m)
    {
        var sum = Add(b, out ulong carry);
        if (carry != 0 || sum.Compare(m) >= 0)
            return sum.Sub(m, out _);
        return sum;
    }

    public BigInt256 ModSub(in BigInt256 b, in BigInt256 m)
    {
        var diff = Sub(b, out ulong borrow);
        if (borrow != 0)
            return diff.Add(m, out _);
        return diff;
    }

    public BigInt256 ModMul(in BigInt256 b, in BigInt256 m)
    {
        var product = Mul(b);
        return ModReduce512(product, m);
    }

    public BigInt256 ModSquare(in BigInt256 m) => ModMul(this, m);

    public BigInt256 SM2ModMulP(in BigInt256 b)
    {
        var product = Mul(b);
        return SM2ModReduceP(product);
    }

    public BigInt256 SM2ModSquareP()
    {
        var product = Mul(this);
        return SM2ModReduceP(product);
    }

    /// <summary>
    /// Fast modular reduction for SM2 prime p = 2^256 - 2^224 - 2^96 + 2^64 - 1.
    /// Solinas reduction using signed 32-bit word accumulator.
    /// </summary>
    private static BigInt256 SM2ModReduceP(ulong[] c)
    {
        long W(int i) => (i % 2 == 0)
            ? (long)(c[i / 2] & 0xFFFFFFFF)
            : (long)(c[i / 2] >> 32);

        long[][] R =
        [
            [1, 0, -1, 1, 0, 0, 0, 1],   // R_8
            [1, 1, -1, 0, 1, 0, 0, 1],   // R_9
            [1, 1, 0, 0, 0, 1, 0, 1],    // R_10
            [1, 1, 0, 1, 0, 0, 1, 1],    // R_11
            [1, 1, 0, 1, 1, 0, 0, 2],    // R_12
            [2, 1, -1, 2, 1, 1, 0, 2],   // R_13
            [2, 2, -1, 1, 2, 1, 1, 2],   // R_14
            [2, 2, 0, 1, 1, 2, 1, 3],    // R_15
        ];

        var acc = new long[9];
        for (int j = 0; j < 8; j++)
        {
            acc[j] = W(j);
            for (int i = 0; i < 8; i++)
                acc[j] += W(i + 8) * R[i][j];
        }

        // Propagate carries
        for (int i = 0; i < 8; i++)
        {
            long carry = acc[i] >> 32;
            acc[i] &= 0xFFFFFFFF;
            acc[i + 1] += carry;
        }

        // Handle overflow
        long overflow = acc[8];
        if (overflow != 0)
        {
            acc[0] += overflow;
            acc[2] -= overflow;
            acc[3] += overflow;
            acc[7] += overflow;
            acc[8] = 0;

            for (int i = 0; i < 8; i++)
            {
                long carry = acc[i] >> 32;
                acc[i] &= 0xFFFFFFFF;
                acc[i + 1] += carry;
            }

            long overflow2 = acc[8];
            if (overflow2 != 0)
            {
                acc[0] += overflow2;
                acc[2] -= overflow2;
                acc[3] += overflow2;
                acc[7] += overflow2;
                acc[8] = 0;
                for (int i = 0; i < 8; i++)
                {
                    long carry = acc[i] >> 32;
                    acc[i] &= 0xFFFFFFFF;
                    acc[i + 1] += carry;
                }
            }
        }

        // Handle negative values
        for (int i = 0; i < 8; i++)
        {
            while (acc[i] < 0)
            {
                acc[i] += 0x100000000L;
                acc[i + 1] -= 1;
            }
        }

        var result = new BigInt256(
            (ulong)acc[0] | ((ulong)acc[1] << 32),
            (ulong)acc[2] | ((ulong)acc[3] << 32),
            (ulong)acc[4] | ((ulong)acc[5] << 32),
            (ulong)acc[6] | ((ulong)acc[7] << 32)
        );

        var sm2P = new BigInt256(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF);
        while (result.Compare(sm2P) >= 0)
            result = result.Sub(sm2P, out _);

        return result;
    }

    private static BigInt256 ModReduce512(ulong[] value, in BigInt256 modulus)
    {
        var remainder = new ulong[8];
        Array.Copy(value, remainder, 8);

        int dividendBits = 0;
        for (int i = 7; i >= 0; i--)
        {
            if (remainder[i] != 0)
            {
                dividendBits = (i + 1) * 64 - BitOperations.LeadingZeroCount(remainder[i]);
                break;
            }
        }

        int modulusBits = 0;
        ulong[] mLimbs = [modulus.L0, modulus.L1, modulus.L2, modulus.L3];
        for (int i = 3; i >= 0; i--)
        {
            if (mLimbs[i] != 0)
            {
                modulusBits = (i + 1) * 64 - BitOperations.LeadingZeroCount(mLimbs[i]);
                break;
            }
        }

        if (modulusBits == 0) throw new DivideByZeroException();

        if (dividendBits < modulusBits)
            return new BigInt256(remainder[0], remainder[1], remainder[2], remainder[3]);

        int shiftAmount = dividendBits - modulusBits;
        for (int shift = shiftAmount; shift >= 0; shift--)
        {
            var shifted = ShiftLeft512(mLimbs, shift);
            if (Compare512(remainder, shifted) >= 0)
                remainder = Sub512(remainder, shifted);
        }

        return new BigInt256(remainder[0], remainder[1], remainder[2], remainder[3]);
    }

    private static ulong[] ShiftLeft512(ulong[] value, int shift)
    {
        var result = new ulong[8];
        if (shift == 0) { Array.Copy(value, result, 4); return result; }
        int wordShift = shift / 64;
        int bitShift = shift % 64;
        if (bitShift == 0)
        {
            for (int i = 0; i < 4; i++)
                if (i + wordShift < 8) result[i + wordShift] = value[i];
        }
        else
        {
            for (int i = 0; i < 4; i++)
            {
                if (i + wordShift < 8) result[i + wordShift] |= value[i] << bitShift;
                if (i + wordShift + 1 < 8) result[i + wordShift + 1] |= value[i] >> (64 - bitShift);
            }
        }
        return result;
    }

    private static int Compare512(ulong[] a, ulong[] b)
    {
        for (int i = 7; i >= 0; i--)
        {
            if (a[i] > b[i]) return 1;
            if (a[i] < b[i]) return -1;
        }
        return 0;
    }

    private static ulong[] Sub512(ulong[] a, ulong[] b)
    {
        var result = new ulong[8];
        ulong borrow = 0;
        for (int i = 0; i < 8; i++)
        {
            ulong diff = a[i] - b[i];
            ulong b1 = diff > a[i] ? 1UL : 0UL;
            ulong r = diff - borrow;
            ulong b2 = r > diff ? 1UL : 0UL;
            result[i] = r;
            borrow = b1 + b2;
        }
        return result;
    }

    public BigInt256 ModInverse(in BigInt256 m)
    {
        var two = new BigInt256(2, 0, 0, 0);
        var pMinus2 = m.Sub(two, out _);
        return ModPow(pMinus2, m);
    }

    public BigInt256 ModPow(in BigInt256 exp, in BigInt256 m)
    {
        if (exp.IsZero) return One;
        var result = One;
        var b = this;
        int bitLen = exp.BitLength();
        for (int i = 0; i < bitLen; i++)
        {
            if (exp.GetBit(i))
                result = result.ModMul(b, m);
            b = b.ModSquare(m);
        }
        return result;
    }

    public bool GetBit(int i)
    {
        if (i >= 256) return false;
        int word = i / 64;
        int bit = i % 64;
        ulong v = word switch { 0 => L0, 1 => L1, 2 => L2, _ => L3 };
        return ((v >> bit) & 1) == 1;
    }

    public int BitLength()
    {
        if (L3 != 0) return 256 - BitOperations.LeadingZeroCount(L3);
        if (L2 != 0) return 192 - BitOperations.LeadingZeroCount(L2);
        if (L1 != 0) return 128 - BitOperations.LeadingZeroCount(L1);
        if (L0 != 0) return 64 - BitOperations.LeadingZeroCount(L0);
        return 0;
    }

    public BigInt256 And(in BigInt256 b) => new(L0 & b.L0, L1 & b.L1, L2 & b.L2, L3 & b.L3);

    public BigInt256 ShiftRight1()
    {
        return new BigInt256(
            (L0 >> 1) | (L1 << 63),
            (L1 >> 1) | (L2 << 63),
            (L2 >> 1) | (L3 << 63),
            L3 >> 1
        );
    }

    public BigInt256 ShiftLeft1()
    {
        return new BigInt256(
            L0 << 1,
            (L1 << 1) | (L0 >> 63),
            (L2 << 1) | (L1 >> 63),
            (L3 << 1) | (L2 >> 63)
        );
    }

    public bool Equals(BigInt256 other) => L0 == other.L0 && L1 == other.L1 && L2 == other.L2 && L3 == other.L3;
    public override bool Equals(object? obj) => obj is BigInt256 b && Equals(b);
    public override int GetHashCode() => HashCode.Combine(L0, L1, L2, L3);
    public static bool operator ==(BigInt256 a, BigInt256 b) => a.Equals(b);
    public static bool operator !=(BigInt256 a, BigInt256 b) => !a.Equals(b);
}
