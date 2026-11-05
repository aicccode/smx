using System.Runtime.CompilerServices;

namespace SMX;

/// <summary>512-bit intermediate product; stack-only replacement for the ulong[8] the public Mul has to return.</summary>
internal struct Wide512
{
    public ulong W0, W1, W2, W3, W4, W5, W6, W7;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Multiply(in BigInt256 a, in BigInt256 b, out Wide512 r)
    {
        ulong a0 = a.L0, a1 = a.L1, a2 = a.L2, a3 = a.L3;
        ulong b0 = b.L0, b1 = b.L1, b2 = b.L2, b3 = b.L3;

        ulong carry = 0;
        ulong t0 = Bits.MulAdd(a0, b0, 0, ref carry);
        ulong t1 = Bits.MulAdd(a0, b1, 0, ref carry);
        ulong t2 = Bits.MulAdd(a0, b2, 0, ref carry);
        ulong t3 = Bits.MulAdd(a0, b3, 0, ref carry);
        ulong t4 = carry;

        carry = 0;
        t1 = Bits.MulAdd(a1, b0, t1, ref carry);
        t2 = Bits.MulAdd(a1, b1, t2, ref carry);
        t3 = Bits.MulAdd(a1, b2, t3, ref carry);
        t4 = Bits.MulAdd(a1, b3, t4, ref carry);
        ulong t5 = carry;

        carry = 0;
        t2 = Bits.MulAdd(a2, b0, t2, ref carry);
        t3 = Bits.MulAdd(a2, b1, t3, ref carry);
        t4 = Bits.MulAdd(a2, b2, t4, ref carry);
        t5 = Bits.MulAdd(a2, b3, t5, ref carry);
        ulong t6 = carry;

        carry = 0;
        t3 = Bits.MulAdd(a3, b0, t3, ref carry);
        t4 = Bits.MulAdd(a3, b1, t4, ref carry);
        t5 = Bits.MulAdd(a3, b2, t5, ref carry);
        t6 = Bits.MulAdd(a3, b3, t6, ref carry);

        r.W0 = t0;
        r.W1 = t1;
        r.W2 = t2;
        r.W3 = t3;
        r.W4 = t4;
        r.W5 = t5;
        r.W6 = t6;
        r.W7 = carry;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Square(in BigInt256 a, out Wide512 r)
    {
        ulong a0 = a.L0, a1 = a.L1, a2 = a.L2, a3 = a.L3;

        // Off-diagonal products once.
        ulong carry = 0;
        ulong t1 = Bits.MulAdd(a0, a1, 0, ref carry);
        ulong t2 = Bits.MulAdd(a0, a2, 0, ref carry);
        ulong t3 = Bits.MulAdd(a0, a3, 0, ref carry);
        ulong t4 = carry;

        carry = 0;
        t3 = Bits.MulAdd(a1, a2, t3, ref carry);
        t4 = Bits.MulAdd(a1, a3, t4, ref carry);
        ulong t5 = carry;

        carry = 0;
        t5 = Bits.MulAdd(a2, a3, t5, ref carry);
        ulong t6 = carry;

        // Double them, then add the squares on the diagonal.
        ulong t7 = t6 >> 63;
        t6 = (t6 << 1) | (t5 >> 63);
        t5 = (t5 << 1) | (t4 >> 63);
        t4 = (t4 << 1) | (t3 >> 63);
        t3 = (t3 << 1) | (t2 >> 63);
        t2 = (t2 << 1) | (t1 >> 63);
        t1 <<= 1;

        ulong h0 = Bits.MulHigh(a0, a0, out ulong t0);
        ulong h1 = Bits.MulHigh(a1, a1, out ulong l1);
        ulong h2 = Bits.MulHigh(a2, a2, out ulong l2);
        ulong h3 = Bits.MulHigh(a3, a3, out ulong l3);

        t1 = Bits.Add(t1, h0, 0, out ulong c);
        t2 = Bits.Add(t2, l1, c, out c);
        t3 = Bits.Add(t3, h1, c, out c);
        t4 = Bits.Add(t4, l2, c, out c);
        t5 = Bits.Add(t5, h2, c, out c);
        t6 = Bits.Add(t6, l3, c, out c);
        t7 += h3 + c;

        r.W0 = t0;
        r.W1 = t1;
        r.W2 = t2;
        r.W3 = t3;
        r.W4 = t4;
        r.W5 = t5;
        r.W6 = t6;
        r.W7 = t7;
    }

    /// <summary>Remainder modulo an arbitrary non-zero modulus (Knuth algorithm D). Not constant time.</summary>
    [SkipLocalsInit]
    public readonly BigInt256 Mod(in BigInt256 modulus)
    {
        int bits = modulus.BitLength();
        if (bits == 0)
        {
            throw new DivideByZeroException();
        }

        int n = (bits + 63) / 64;
        int shift = 64 * n - bits;

        // Normalize so the divisor's top bit is set; the dividend gains one limb for the shifted-out bits.
        Span<ulong> v = stackalloc ulong[4];
        Span<ulong> u = stackalloc ulong[9];
        v[0] = modulus.L0;
        v[1] = modulus.L1;
        v[2] = modulus.L2;
        v[3] = modulus.L3;
        ShiftLeft(v, shift);
        u[0] = W0;
        u[1] = W1;
        u[2] = W2;
        u[3] = W3;
        u[4] = W4;
        u[5] = W5;
        u[6] = W6;
        u[7] = W7;
        u[8] = 0;
        ShiftLeft(u, shift);

        ulong top = v[n - 1];
        ulong next = n >= 2 ? v[n - 2] : 0;
        for (int j = 8 - n; j >= 0; j--)
        {
            ulong qhat = EstimateQuotient(u[j + n], u[j + n - 1], n + j >= 2 ? u[j + n - 2] : 0, top, next);

            // Multiply and subtract; add the divisor back in the rare case the estimate was one too large.
            ulong mulCarry = 0;
            ulong borrow = 0;
            for (int i = 0; i < n; i++)
            {
                ulong product = Bits.MulAdd(qhat, v[i], 0, ref mulCarry);
                u[i + j] = Bits.Sub(u[i + j], product, borrow, out borrow);
            }
            u[j + n] = Bits.Sub(u[j + n], mulCarry, borrow, out borrow);
            if (borrow != 0)
            {
                ulong addCarry = 0;
                for (int i = 0; i < n; i++)
                {
                    u[i + j] = Bits.Add(u[i + j], v[i], addCarry, out addCarry);
                }
                u[j + n] += addCarry;
            }
        }

        ShiftRight(u[..(n + 1)], shift);
        return new BigInt256(u[0], n > 1 ? u[1] : 0, n > 2 ? u[2] : 0, n > 3 ? u[3] : 0);
    }

    private static ulong EstimateQuotient(ulong u2, ulong u1, ulong u0, ulong top, ulong next)
    {
        if (u2 >= top)
        {
            return ulong.MaxValue;
        }
        var numerator = new UInt128(u2, u1);
        ulong qhat = (ulong)(numerator / top);
        ulong rhat = (ulong)(numerator - (UInt128)qhat * top);
        while (true)
        {
            ulong hi = Math.BigMul(qhat, next, out ulong lo);
            if (hi < rhat || (hi == rhat && lo <= u0))
            {
                return qhat;
            }
            qhat--;
            ulong sum = rhat + top;
            if (sum < rhat)
            {
                return qhat;
            }
            rhat = sum;
        }
    }

    private static void ShiftLeft(Span<ulong> x, int shift)
    {
        if (shift == 0)
        {
            return;
        }
        for (int i = x.Length - 1; i > 0; i--)
        {
            x[i] = x[i] << shift | x[i - 1] >> (64 - shift);
        }
        x[0] <<= shift;
    }

    private static void ShiftRight(Span<ulong> x, int shift)
    {
        if (shift == 0)
        {
            return;
        }
        for (int i = 0; i < x.Length - 1; i++)
        {
            x[i] = x[i] >> shift | x[i + 1] << (64 - shift);
        }
        x[^1] >>= shift;
    }
}
