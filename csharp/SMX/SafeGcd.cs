using System.Runtime.CompilerServices;

namespace SMX;

/// <summary>
/// Constant-time modular inversion by Bernstein-Yang "safegcd" divsteps, following the design of libsecp256k1's
/// modinv64 (the variant with zeta and 59 divsteps per batch; ten batches, i.e. 590 divsteps, are proven sufficient for
/// any 256-bit odd modulus). Several times faster than Fermat exponentiation, with no branch or memory access that
/// depends on the input. Numbers are held as five signed limbs of 62 bits; the top limb carries the sign.
/// </summary>
internal static class SafeGcd
{
    private const ulong Mask62 = (1UL << 62) - 1;
    private const int Batches = 10;
    private const int DivstepsPerBatch = 59;

    /// <summary>A modulus in limb form with its inverse modulo 2^62.</summary>
    internal readonly struct Modulus(long v0, long v1, long v2, long v3, long v4, ulong inverse62)
    {
        public readonly long V0 = v0, V1 = v1, V2 = v2, V3 = v3, V4 = v4;
        public readonly ulong Inverse62 = inverse62;
    }

    public static readonly Modulus FieldPrime = new(
        0x3FFFFFFFFFFFFFFF, 0x3FFFFFFC00000003, 0x3FFFFFFFFFFFFFFF, 0x3FFFFFBFFFFFFFFF, 0xFF, 0x3FFFFFFFFFFFFFFF);

    public static readonly Modulus GroupOrder = new(
        0x13BBF40939D54123, 0x80F7DAC871814AD, 0x3FFFFFFFFFFFFFF7, 0x3FFFFFBFFFFFFFFF, 0xFF, 0xD8061778DCAF68B);

    private struct Signed62
    {
        public long V0, V1, V2, V3, V4;
    }

    /// <summary>The 2x2 matrix accumulated by one batch of divsteps, scaled by 2^62.</summary>
    private struct Transition
    {
        public long U, V, Q, R;
    }

    /// <summary>A signed 128-bit accumulator, kept in two locals by the JIT once inlined.</summary>
    private struct Accumulator
    {
        private ulong _low;
        private long _high;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void AddProduct(long a, long b)
        {
            // Unsigned high word corrected for the operands' signs, followed by a 128-bit add.
            ulong high = Bits.MulHigh((ulong)a, (ulong)b, out ulong low);
            high -= (ulong)((a >> 63) & b) + (ulong)((b >> 63) & a);
            ulong sum = _low + low;
            _high += (long)high + (long)Bits.Below(sum, low);
            _low = sum;
        }

        public readonly ulong Low => _low;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void ShiftRight62()
        {
            _low = (_low >> 62) | ((ulong)_high << 2);
            _high >>= 62;
        }

        /// <summary>The remaining value, which by the algorithm's bounds fits one limb.</summary>
        public readonly long Value => (long)_low;
    }

    /// <summary>x^-1 mod m for 0 &lt;= x &lt; m; zero maps to zero.</summary>
    [SkipLocalsInit]
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void Invert(in BigInt256 x, in Modulus modulus, out BigInt256 result)
    {
        Signed62 d = default;
        Signed62 e = default;
        e.V0 = 1;
        Signed62 f = default;
        f.V0 = modulus.V0;
        f.V1 = modulus.V1;
        f.V2 = modulus.V2;
        f.V3 = modulus.V3;
        f.V4 = modulus.V4;
        Signed62 g = ToSigned62(x);

        long zeta = -1;
        for (int batch = 0; batch < Batches; batch++)
        {
            Divsteps(ref zeta, (ulong)f.V0, (ulong)g.V0, out Transition t);
            UpdateDe(ref d, ref e, t, modulus);
            UpdateFg(ref f, ref g, t);
        }

        // Now f is +1 or -1 (or +-m for x = 0, where d is zero anyway), and d * sign(f) is the inverse.
        result = Normalize(d, f.V4, modulus);
    }

    private static Signed62 ToSigned62(in BigInt256 a)
    {
        Signed62 r;
        r.V0 = (long)(a.L0 & Mask62);
        r.V1 = (long)(((a.L0 >> 62) | (a.L1 << 2)) & Mask62);
        r.V2 = (long)(((a.L1 >> 60) | (a.L2 << 4)) & Mask62);
        r.V3 = (long)(((a.L2 >> 58) | (a.L3 << 6)) & Mask62);
        r.V4 = (long)(a.L3 >> 56);
        return r;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Divsteps(ref long zeta, ulong f0, ulong g0, out Transition t)
    {
        // The matrix starts as 8 times the identity because the caller shifts by 62 after only 59 steps.
        ulong u = 8, v = 0, q = 0, r = 8;
        ulong f = f0, g = g0;
        ulong z = (ulong)zeta;
        for (int i = 0; i < DivstepsPerBatch; i++)
        {
            ulong mask1 = (ulong)((long)z >> 63);
            ulong mask2 = 0 - (g & 1);

            ulong x = (f ^ mask1) - mask1;
            ulong y = (u ^ mask1) - mask1;
            ulong w = (v ^ mask1) - mask1;

            g += x & mask2;
            q += y & mask2;
            r += w & mask2;

            mask1 &= mask2;
            z = (z ^ mask1) - 1;

            f += g & mask1;
            u += q & mask1;
            v += r & mask1;

            g >>= 1;
            u <<= 1;
            v <<= 1;
        }
        zeta = (long)z;
        t.U = (long)u;
        t.V = (long)v;
        t.Q = (long)q;
        t.R = (long)r;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Step(ref long fi, ref long gi, long f, long g, in Transition t, ref Accumulator cf, ref Accumulator cg)
    {
        cf.AddProduct(t.U, f);
        cf.AddProduct(t.V, g);
        cg.AddProduct(t.Q, f);
        cg.AddProduct(t.R, g);
        fi = (long)(cf.Low & Mask62);
        gi = (long)(cg.Low & Mask62);
        cf.ShiftRight62();
        cg.ShiftRight62();
    }

    /// <summary>(f, g) = t * (f, g) / 2^62. The division is exact by construction of the matrix.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void UpdateFg(ref Signed62 f, ref Signed62 g, in Transition t)
    {
        long f0 = f.V0, f1 = f.V1, f2 = f.V2, f3 = f.V3, f4 = f.V4;
        long g0 = g.V0, g1 = g.V1, g2 = g.V2, g3 = g.V3, g4 = g.V4;
        Accumulator cf = default, cg = default;
        long discard0 = 0, discard1 = 0;
        Step(ref discard0, ref discard1, f0, g0, t, ref cf, ref cg);
        Step(ref f.V0, ref g.V0, f1, g1, t, ref cf, ref cg);
        Step(ref f.V1, ref g.V1, f2, g2, t, ref cf, ref cg);
        Step(ref f.V2, ref g.V2, f3, g3, t, ref cf, ref cg);
        Step(ref f.V3, ref g.V3, f4, g4, t, ref cf, ref cg);
        f.V4 = cf.Value;
        g.V4 = cg.Value;
    }

    /// <summary>
    /// (d, e) = t * (d, e) / 2^62 mod m. A multiple of the modulus is added to make the division exact, chosen also to
    /// keep both results in the range (-2m, m) that the algorithm's bounds assume.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void UpdateDe(ref Signed62 d, ref Signed62 e, in Transition t, in Modulus m)
    {
        long d0 = d.V0, d1 = d.V1, d2 = d.V2, d3 = d.V3, d4 = d.V4;
        long e0 = e.V0, e1 = e.V1, e2 = e.V2, e3 = e.V3, e4 = e.V4;

        long signD = d4 >> 63;
        long signE = e4 >> 63;
        long md = (t.U & signD) + (t.V & signE);
        long me = (t.Q & signD) + (t.R & signE);

        Accumulator cd = default, ce = default;
        cd.AddProduct(t.U, d0);
        cd.AddProduct(t.V, e0);
        ce.AddProduct(t.Q, d0);
        ce.AddProduct(t.R, e0);

        // Choose the top bits of the correction so that the low 62 bits of the sum vanish.
        md -= (long)((m.Inverse62 * cd.Low + (ulong)md) & Mask62);
        me -= (long)((m.Inverse62 * ce.Low + (ulong)me) & Mask62);
        cd.AddProduct(m.V0, md);
        ce.AddProduct(m.V0, me);
        cd.ShiftRight62();
        ce.ShiftRight62();

        StepDe(ref d.V0, ref e.V0, d1, e1, m.V1, t, md, me, ref cd, ref ce);
        StepDe(ref d.V1, ref e.V1, d2, e2, m.V2, t, md, me, ref cd, ref ce);
        StepDe(ref d.V2, ref e.V2, d3, e3, m.V3, t, md, me, ref cd, ref ce);
        StepDe(ref d.V3, ref e.V3, d4, e4, m.V4, t, md, me, ref cd, ref ce);
        d.V4 = cd.Value;
        e.V4 = ce.Value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void StepDe(ref long di, ref long ei, long d, long e, long modulusLimb, in Transition t, long md, long me, ref Accumulator cd, ref Accumulator ce)
    {
        cd.AddProduct(t.U, d);
        cd.AddProduct(t.V, e);
        ce.AddProduct(t.Q, d);
        ce.AddProduct(t.R, e);
        cd.AddProduct(modulusLimb, md);
        ce.AddProduct(modulusLimb, me);
        di = (long)(cd.Low & Mask62);
        ei = (long)(ce.Low & Mask62);
        cd.ShiftRight62();
        ce.ShiftRight62();
    }

    /// <summary>From d in (-2m, m), with the sign to apply given by the top limb of f, to canonical form in [0, m).</summary>
    private static BigInt256 Normalize(in Signed62 value, long signSource, in Modulus m)
    {
        long r0 = value.V0, r1 = value.V1, r2 = value.V2, r3 = value.V3, r4 = value.V4;

        // Add m if negative, leaving (-m, m).
        long add = r4 >> 63;
        r0 += m.V0 & add;
        r1 += m.V1 & add;
        r2 += m.V2 & add;
        r3 += m.V3 & add;
        r4 += m.V4 & add;

        // Negate if f was negative.
        long negate = signSource >> 63;
        r0 = (r0 ^ negate) - negate;
        r1 = (r1 ^ negate) - negate;
        r2 = (r2 ^ negate) - negate;
        r3 = (r3 ^ negate) - negate;
        r4 = (r4 ^ negate) - negate;

        Propagate(ref r0, ref r1, ref r2, ref r3, ref r4);

        // Add m once more if negative, leaving [0, m).
        add = r4 >> 63;
        r0 += m.V0 & add;
        r1 += m.V1 & add;
        r2 += m.V2 & add;
        r3 += m.V3 & add;
        r4 += m.V4 & add;

        Propagate(ref r0, ref r1, ref r2, ref r3, ref r4);

        return new BigInt256(
            (ulong)r0 | ((ulong)r1 << 62),
            ((ulong)r1 >> 2) | ((ulong)r2 << 60),
            ((ulong)r2 >> 4) | ((ulong)r3 << 58),
            ((ulong)r3 >> 6) | ((ulong)r4 << 56));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Propagate(ref long r0, ref long r1, ref long r2, ref long r3, ref long r4)
    {
        r1 += r0 >> 62;
        r0 &= (long)Mask62;
        r2 += r1 >> 62;
        r1 &= (long)Mask62;
        r3 += r2 >> 62;
        r2 &= (long)Mask62;
        r4 += r3 >> 62;
        r3 &= (long)Mask62;
    }
}
