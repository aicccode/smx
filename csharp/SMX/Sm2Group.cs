using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace SMX;

/// <summary>A point in Jacobian coordinates: (X/Z^2, Y/Z^3), with Z = 0 meaning the point at infinity.</summary>
internal struct JacobianPoint
{
    public BigInt256 X, Y, Z;

    public readonly bool IsInfinity => Z.IsZero;

    public static JacobianPoint FromAffine(in ECPoint p)
    {
        JacobianPoint r;
        r.X = p.X.Value;
        r.Y = p.Y.Value;
        r.Z = p.Infinity ? default : BigInt256.One;
        return r;
    }
}

/// <summary>A point with Z = 1 in the precomputed tables. No flag: table entries are never the point at infinity.</summary>
internal struct AffineEntry
{
    public BigInt256 X, Y;
}

/// <summary>
/// Group operations on y^2 = x^3 - 3x + b. Every public entry point validates its points before they arrive here.
///
/// Timing, as far as managed code can promise it: the *Secret operations execute the same instructions and touch the
/// same memory for every scalar, using masks instead of branches and scanning whole tables. The JIT does not formally
/// guarantee this (the optimized code has been inspected; tier-0 code emits set-condition instructions from the same
/// source), and secrets in temporaries cannot be reliably wiped from the managed stack or from copies the GC moved. The *Public
/// operations branch on their scalars and may be used only when those are public, as in signature verification.
/// </summary>
internal static class Sm2Group
{
    public static readonly BigInt256 Gx = new(0x715A4589334C74C7, 0x8FE30BBFF2660BE1, 0x5F9904466A39C994, 0x32C4AE2C1F198119);
    public static readonly BigInt256 Gy = new(0x02DF32E52139F0A0, 0xD0A9877CC62A4740, 0x59BDCEE36B692153, 0xBC3736A2F4F6779C);

    // Variable-base window: signed digits in -16..16, so 16 stored multiples for 52 additions.
    private const int VariableWindowBits = 5;
    private const int VariableTableSize = 1 << (VariableWindowBits - 1);
    private const int VariableWindows = (256 + VariableWindowBits) / VariableWindowBits;

    // Fixed-base comb: signed digits in -32..32 over 43 tables of the multiples of 2^(6i) G.
    private const int CombWindowBits = 6;
    private const int CombTableSize = 1 << (CombWindowBits - 1);
    private const int CombWindows = (256 + CombWindowBits) / CombWindowBits;

    // wNAF widths for verification. G's table is static, so it can be much wider than one built per call.
    private const int PublicWidth = 5;
    private const int GeneratorWidth = 9;
    private const int MaxNafDigits = 258;

    /// <summary>dbl-2001-b for a = -3. Z = 0 and Y = 0 both give Z3 = 0, the point at infinity, without a special case.</summary>
    [SkipLocalsInit]
    public static void Double(in JacobianPoint p, out JacobianPoint r)
    {
        Fp.Square(p.Z, out var delta);
        Fp.Square(p.Y, out var gamma);
        Fp.Mul(p.X, gamma, out var beta);

        // alpha = 3 * (X - delta) * (X + delta)
        Fp.Sub(p.X, delta, out var t0);
        Fp.Add(p.X, delta, out var t1);
        Fp.Mul(t0, t1, out t0);
        Fp.Double(t0, out var alpha);
        Fp.Add(alpha, t0, out alpha);

        // Z3 = (Y + Z)^2 - gamma - delta
        Fp.Add(p.Y, p.Z, out var z3);
        Fp.Square(z3, out z3);
        Fp.Sub(z3, gamma, out z3);
        Fp.Sub(z3, delta, out z3);

        // X3 = alpha^2 - 8 * beta
        Fp.Double(beta, out var beta4);
        Fp.Double(beta4, out beta4);
        Fp.Double(beta4, out var beta8);
        Fp.Square(alpha, out var x3);
        Fp.Sub(x3, beta8, out x3);

        // Y3 = alpha * (4 * beta - X3) - 8 * gamma^2
        Fp.Sub(beta4, x3, out var y3);
        Fp.Mul(alpha, y3, out y3);
        Fp.Square(gamma, out gamma);
        Fp.Double(gamma, out gamma);
        Fp.Double(gamma, out gamma);
        Fp.Double(gamma, out gamma);
        Fp.Sub(y3, gamma, out y3);

        r.X = x3;
        r.Y = y3;
        r.Z = z3;
    }

    /// <summary>
    /// The generic sum of p and an affine point, with the intermediates that decide the exceptional cases. Those cases
    /// come out as H = 0, giving Z3 = 0: correct for p = -q, but needing a doubling for p = q.
    /// </summary>
    [SkipLocalsInit]
    private static void AddMixedFormula(in JacobianPoint p, in BigInt256 qx, in BigInt256 qy, out JacobianPoint r, out BigInt256 h, out BigInt256 s)
    {
        Fp.Square(p.Z, out var z1z1);
        Fp.Mul(qx, z1z1, out var u2);
        Fp.Mul(qy, p.Z, out var s2);
        Fp.Mul(s2, z1z1, out s2);
        Fp.Sub(u2, p.X, out h);
        Fp.Sub(s2, p.Y, out s);

        Fp.Square(h, out var hh);
        Fp.Mul(hh, h, out var hhh);
        Fp.Mul(p.X, hh, out var v);
        Fp.Square(s, out var x3);
        Fp.Sub(x3, hhh, out x3);
        Fp.Double(v, out var twoV);
        Fp.Sub(x3, twoV, out x3);
        Fp.Sub(v, x3, out var y3);
        Fp.Mul(s, y3, out y3);
        Fp.Mul(p.Y, hhh, out var t);
        Fp.Sub(y3, t, out y3);
        Fp.Mul(p.Z, h, out var z3);

        r.X = x3;
        r.Y = y3;
        r.Z = z3;
    }

    /// <summary>The generic sum of two Jacobian points; see <see cref="AddMixedFormula"/> for the exceptional cases.</summary>
    [SkipLocalsInit]
    private static void AddFormula(in JacobianPoint p, in JacobianPoint q, out JacobianPoint r, out BigInt256 h, out BigInt256 s)
    {
        Fp.Square(p.Z, out var z1z1);
        Fp.Square(q.Z, out var z2z2);
        Fp.Mul(p.X, z2z2, out var u1);
        Fp.Mul(q.X, z1z1, out var u2);
        Fp.Mul(p.Y, q.Z, out var s1);
        Fp.Mul(s1, z2z2, out s1);
        Fp.Mul(q.Y, p.Z, out var s2);
        Fp.Mul(s2, z1z1, out s2);
        Fp.Sub(u2, u1, out h);
        Fp.Sub(s2, s1, out s);

        Fp.Square(h, out var hh);
        Fp.Mul(hh, h, out var hhh);
        Fp.Mul(u1, hh, out var v);
        Fp.Square(s, out var x3);
        Fp.Sub(x3, hhh, out x3);
        Fp.Double(v, out var twoV);
        Fp.Sub(x3, twoV, out x3);
        Fp.Sub(v, x3, out var y3);
        Fp.Mul(s, y3, out y3);
        Fp.Mul(s1, hhh, out var t);
        Fp.Sub(y3, t, out y3);
        Fp.Mul(p.Z, q.Z, out var z3);
        Fp.Mul(z3, h, out z3);

        r.X = x3;
        r.Y = y3;
        r.Z = z3;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Select(ulong mask, in JacobianPoint ifSet, in JacobianPoint ifClear, out JacobianPoint r)
    {
        r.X = BigInt256.Select(mask, ifSet.X, ifClear.X);
        r.Y = BigInt256.Select(mask, ifSet.Y, ifClear.Y);
        r.Z = BigInt256.Select(mask, ifSet.Z, ifClear.Z);
    }

    /// <summary>
    /// Constant-time complete addition: the doubling is always computed too and selected by mask when p = q, so that no
    /// control flow depends on whether a secret scalar reached that case.
    /// </summary>
    private static void AddSecret(in JacobianPoint p, in JacobianPoint q, out JacobianPoint r)
    {
        AddFormula(p, q, out var sum, out var h, out var s);
        ulong pInfinite = p.Z.IsZeroMask();
        ulong qInfinite = q.Z.IsZeroMask();
        ulong same = h.IsZeroMask() & s.IsZeroMask() & ~pInfinite & ~qInfinite;
        Double(p, out var doubled);
        Select(same, doubled, sum, out sum);
        Select(pInfinite, q, sum, out sum);
        Select(qInfinite, p, sum, out r);
    }

    /// <summary>Recodes bits [offset-1, offset+width) of k into a signed digit, using only arithmetic on the bits.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int BoothDigit(in BigInt256 k, int offset, int width, out ulong negative)
    {
        uint window = offset == 0
            ? (uint)ExtractBits(k, 0, width) << 1
            : (uint)ExtractBits(k, offset - 1, width + 1);
        uint sign = window >> width;
        uint fullMask = (1u << (width + 1)) - 1;
        uint folded = (window ^ (0 - sign)) & fullMask;
        negative = sign;
        return (int)((folded >> 1) + (folded & 1));
    }

    /// <summary>Reads count bits starting at a public position. Beyond bit 255 they read as zero.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong ExtractBits(in BigInt256 k, int position, int count)
    {
        ReadOnlySpan<ulong> limbs = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef(in k.L0), 4);
        int index = position >> 6;
        int shift = position & 63;
        ulong low = index < 4 ? limbs[index] >> shift : 0;
        ulong high = shift != 0 && index + 1 < 4 ? limbs[index + 1] << (64 - shift) : 0;
        return (low | high) & ((1UL << count) - 1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void NegateIf(ulong negativeBit, ref BigInt256 y)
    {
        Fp.Negate(y, out var negated);
        y = BigInt256.Select(Bits.MaskFromBit(negativeBit), negated, y);
    }

    /// <summary>
    /// k*p for a secret k, by a fixed window with constant-time table lookups. p itself is treated as public: an infinite
    /// or degenerate input may be detected by branches. Doublings and additions always alternate in the same pattern.
    /// </summary>
    [SkipLocalsInit]
    public static void MultiplySecret(in JacobianPoint p, in BigInt256 k, out JacobianPoint r)
    {
        if (p.IsInfinity)
        {
            r = default;
            return;
        }

        Span<JacobianPoint> table = stackalloc JacobianPoint[VariableTableSize];
        table[0] = p;
        for (int i = 1; i < VariableTableSize; i += 2)
        {
            Double(table[i / 2], out table[i]);
            if (i + 1 < VariableTableSize)
            {
                AddSecret(table[i], table[0], out table[i + 1]);
            }
        }

        JacobianPoint q = default;
        for (int window = VariableWindows - 1; window >= 0; window--)
        {
            for (int j = 0; j < VariableWindowBits; j++)
            {
                Double(q, out q);
            }
            int digit = BoothDigit(k, window * VariableWindowBits, VariableWindowBits, out ulong negative);
            LookupJacobian(table, digit, out var entry);
            NegateIf(negative, ref entry.Y);
            AddSecret(q, entry, out q);
        }
        r = q;
    }

    /// <summary>Copies table[digit - 1], or an all-zero (infinite) point for digit 0, reading every entry.</summary>
    private static void LookupJacobian(ReadOnlySpan<JacobianPoint> table, int digit, out JacobianPoint result)
    {
        Unsafe.SkipInit(out result);
        ScanTable(MemoryMarshal.AsBytes(table), Unsafe.SizeOf<JacobianPoint>(), digit, MemoryMarshal.AsBytes(new Span<JacobianPoint>(ref result)));
    }

    /// <summary>ORs together every table entry masked by whether its 1-based position equals the digit.</summary>
    private static void ScanTable(ReadOnlySpan<byte> table, int entrySize, int digit, Span<byte> result)
    {
        ref byte source = ref MemoryMarshal.GetReference(table);
        ref byte target = ref MemoryMarshal.GetReference(result);
        int count = table.Length / entrySize;
        result.Clear();

        if (Vector256.IsHardwareAccelerated && !ForceScalarScan)
        {
            for (int i = 0; i < count; i++)
            {
                var mask = Vector256.Create(Bits.IsZeroMask((ulong)(long)(digit - 1 - i))).AsByte();
                for (int word = 0; word < entrySize; word += 32)
                {
                    var merged = Vector256.LoadUnsafe(ref target, (nuint)word) | (Vector256.LoadUnsafe(ref source, (nuint)(i * entrySize + word)) & mask);
                    merged.StoreUnsafe(ref target, (nuint)word);
                }
            }
            return;
        }

        for (int i = 0; i < count; i++)
        {
            ulong mask = Bits.IsZeroMask((ulong)(long)(digit - 1 - i));
            for (int word = 0; word < entrySize; word += 8)
            {
                ref byte slot = ref Unsafe.Add(ref target, word);
                ulong merged = Unsafe.ReadUnaligned<ulong>(ref slot) | (Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, i * entrySize + word)) & mask);
                Unsafe.WriteUnaligned(ref slot, merged);
            }
        }
    }

    /// <summary>Set by tests to exercise the scalar table scan on hardware that has AVX2.</summary>
    internal static bool ForceScalarScan { get; set; }

    /// <summary>k*G for a secret k of any 256-bit value, using the fixed-base comb. Constant time.</summary>
    public static void MultiplyGeneratorSecret(in BigInt256 scalar, out JacobianPoint r)
    {
        // Reducing first is what rules out equal finite inputs. Windows run upward, so the accumulator m is below half of
        // the entry d*2^(6i) in magnitude, and m = +-entry modulo n would need k = 0 or a sum past n. Only an infinite
        // accumulator or a zero digit remains, and both are handled by masks below.
        Sm2Order.ReduceOnce(scalar, out var k);
        ReadOnlySpan<AffineEntry> tables = GeneratorComb.Entries;
        JacobianPoint q = default;
        Span<AffineEntry> entrySpan = stackalloc AffineEntry[1];
        for (int window = 0; window < CombWindows; window++)
        {
            int digit = BoothDigit(k, window * CombWindowBits, CombWindowBits, out ulong negative);
            ScanTable(
                MemoryMarshal.AsBytes(tables.Slice(window * CombTableSize, CombTableSize)),
                Unsafe.SizeOf<AffineEntry>(),
                digit,
                MemoryMarshal.AsBytes(entrySpan));
            ref AffineEntry entry = ref entrySpan[0];
            NegateIf(negative, ref entry.Y);

            AddMixedFormula(q, entry.X, entry.Y, out var sum, out _, out _);
            ulong accumulatorInfinite = q.Z.IsZeroMask();
            ulong digitIsZero = Bits.IsZeroMask((ulong)(long)digit);
            sum.X = BigInt256.Select(accumulatorInfinite, entry.X, sum.X);
            sum.Y = BigInt256.Select(accumulatorInfinite, entry.Y, sum.Y);
            sum.Z = BigInt256.Select(accumulatorInfinite, BigInt256.One, sum.Z);
            Select(digitIsZero, q, sum, out q);
        }
        r = q;
    }

    /// <summary>The comb table: for each window i, the affine multiples j * 2^(6i) G for j in 1..32.</summary>
    private static class GeneratorComb
    {
        public static readonly AffineEntry[] Entries = Build();

        private static AffineEntry[] Build()
        {
            var points = new JacobianPoint[CombWindows * CombTableSize];
            JacobianPoint windowBase = new() { X = Gx, Y = Gy, Z = BigInt256.One };
            for (int window = 0; window < CombWindows; window++)
            {
                int start = window * CombTableSize;
                points[start] = windowBase;
                for (int j = 1; j < CombTableSize; j++)
                {
                    AddPublic(points[start + j - 1], windowBase, out points[start + j]);
                }

                // The last entry is 32 times the base; one more doubling makes the next base, 64 = 2^6 times it.
                Double(points[start + CombTableSize - 1], out windowBase);
            }
            return NormalizeAll(points);
        }
    }

    /// <summary>Odd multiples 1, 3, 5, ... of G in affine form, for the wNAF in verification.</summary>
    private static class GeneratorOddMultiples
    {
        public static readonly AffineEntry[] Entries = Build();

        private static AffineEntry[] Build()
        {
            var points = new JacobianPoint[1 << (GeneratorWidth - 2)];
            points[0] = new JacobianPoint { X = Gx, Y = Gy, Z = BigInt256.One };
            Double(points[0], out var twice);
            for (int i = 1; i < points.Length; i++)
            {
                AddPublic(points[i - 1], twice, out points[i]);
            }
            return NormalizeAll(points);
        }
    }

    /// <summary>Batch conversion to affine with one inversion (Montgomery's trick). Inputs must be finite.</summary>
    private static AffineEntry[] NormalizeAll(JacobianPoint[] points)
    {
        var products = new BigInt256[points.Length];
        var running = BigInt256.One;
        for (int i = 0; i < points.Length; i++)
        {
            products[i] = running;
            Fp.Mul(running, points[i].Z, out running);
        }
        Fp.Invert(running, out var inverse);

        var result = new AffineEntry[points.Length];
        for (int i = points.Length - 1; i >= 0; i--)
        {
            Fp.Mul(inverse, products[i], out var zInverse);
            Fp.Mul(inverse, points[i].Z, out inverse);
            Fp.Square(zInverse, out var z2);
            Fp.Mul(points[i].X, z2, out result[i].X);
            Fp.Mul(z2, zInverse, out var z3);
            Fp.Mul(points[i].Y, z3, out result[i].Y);
        }
        return result;
    }

    /// <summary>Addition that branches on the exceptional cases. For public points only.</summary>
    public static void AddPublic(in JacobianPoint p, in JacobianPoint q, out JacobianPoint r)
    {
        if (p.IsInfinity)
        {
            r = q;
            return;
        }
        if (q.IsInfinity)
        {
            r = p;
            return;
        }
        AddFormula(p, q, out var sum, out var h, out var s);
        if (h.IsZero && s.IsZero)
        {
            Double(p, out r);
            return;
        }
        r = sum;
    }

    /// <summary>Addition of an affine point that branches on the exceptional cases. For public points only.</summary>
    public static void AddMixedPublic(in JacobianPoint p, in BigInt256 qx, in BigInt256 qy, out JacobianPoint r)
    {
        if (p.IsInfinity)
        {
            r = new JacobianPoint { X = qx, Y = qy, Z = BigInt256.One };
            return;
        }
        AddMixedFormula(p, qx, qy, out var sum, out var h, out var s);
        if (h.IsZero && s.IsZero)
        {
            Double(p, out r);
            return;
        }
        r = sum;
    }

    /// <summary>
    /// Writes the width-w non-adjacent form of a public scalar: digits are zero or odd with magnitude below 2^(w-1), and
    /// at most one in any w consecutive positions is non-zero.
    /// </summary>
    private static void RecodeNaf(in BigInt256 k, int width, Span<short> digits)
    {
        digits.Clear();
        int carry = 0;
        int position = 0;
        while (position <= 256)
        {
            if (((int)ExtractBits(k, position, 1) ^ carry) == 0)
            {
                position++;
                continue;
            }
            int word = (int)ExtractBits(k, position, width) + carry;
            carry = (word >> (width - 1)) & 1;
            digits[position] = (short)(word - (carry << width));
            position += width;
        }
    }

    /// <summary>s*G + t*q for public scalars and a public point, by interleaved wNAF. Not constant time.</summary>
    [SkipLocalsInit]
    public static void MultiplyTwinPublic(in BigInt256 s, in BigInt256 t, in ECPoint q, out JacobianPoint r)
    {
        Span<short> nafG = stackalloc short[MaxNafDigits];
        Span<short> nafQ = stackalloc short[MaxNafDigits];
        Span<JacobianPoint> table = stackalloc JacobianPoint[1 << (PublicWidth - 2)];

        RecodeNaf(s, GeneratorWidth, nafG);
        bool useQ = !q.Infinity;
        if (useQ)
        {
            RecodeNaf(t, PublicWidth, nafQ);
            BuildOddMultiples(q, table);
        }
        else
        {
            nafQ.Clear();
        }

        AffineEntry[] generator = GeneratorOddMultiples.Entries;
        JacobianPoint a = default;
        for (int i = Math.Max(nafG.LastIndexOfAnyExcept((short)0), nafQ.LastIndexOfAnyExcept((short)0)); i >= 0; i--)
        {
            Double(a, out a);
            int dg = nafG[i];
            if (dg > 0)
            {
                ref AffineEntry e = ref generator[dg >> 1];
                AddMixedPublic(a, e.X, e.Y, out a);
            }
            else if (dg < 0)
            {
                ref AffineEntry e = ref generator[(-dg) >> 1];
                Fp.Negate(e.Y, out var ny);
                AddMixedPublic(a, e.X, ny, out a);
            }
            int dq = nafQ[i];
            if (dq > 0)
            {
                AddPublic(a, table[dq >> 1], out a);
            }
            else if (dq < 0)
            {
                ref JacobianPoint e = ref table[(-dq) >> 1];
                var n = e;
                Fp.Negate(e.Y, out n.Y);
                AddPublic(a, n, out a);
            }
        }
        r = a;
    }

    /// <summary>k*q for a public scalar and point. Not constant time.</summary>
    [SkipLocalsInit]
    public static void MultiplyPublic(in BigInt256 k, in ECPoint q, out JacobianPoint r)
    {
        if (q.Infinity)
        {
            r = default;
            return;
        }
        Span<short> naf = stackalloc short[MaxNafDigits];
        Span<JacobianPoint> table = stackalloc JacobianPoint[1 << (PublicWidth - 2)];
        RecodeNaf(k, PublicWidth, naf);
        BuildOddMultiples(q, table);

        JacobianPoint a = default;
        for (int i = naf.LastIndexOfAnyExcept((short)0); i >= 0; i--)
        {
            Double(a, out a);
            int d = naf[i];
            if (d > 0)
            {
                AddPublic(a, table[d >> 1], out a);
            }
            else if (d < 0)
            {
                ref JacobianPoint e = ref table[(-d) >> 1];
                var n = e;
                Fp.Negate(e.Y, out n.Y);
                AddPublic(a, n, out a);
            }
        }
        r = a;
    }

    private static void BuildOddMultiples(in ECPoint q, Span<JacobianPoint> table)
    {
        table[0] = JacobianPoint.FromAffine(q);
        Double(table[0], out var twice);
        for (int i = 1; i < table.Length; i++)
        {
            AddPublic(table[i - 1], twice, out table[i]);
        }
    }

    public static ECPoint ToAffine(in JacobianPoint p)
    {
        if (p.IsInfinity)
        {
            return ECPoint.PointAtInfinity;
        }
        Fp.Invert(p.Z, out var zInverse);
        return AffineFrom(p, zInverse);
    }

    /// <summary>Normalizes two points with a single inversion.</summary>
    public static void ToAffine(in JacobianPoint a, in JacobianPoint b, out ECPoint affineA, out ECPoint affineB)
    {
        if (a.IsInfinity || b.IsInfinity)
        {
            affineA = ToAffine(a);
            affineB = ToAffine(b);
            return;
        }
        Fp.Mul(a.Z, b.Z, out var product);
        Fp.Invert(product, out var inverse);
        Fp.Mul(inverse, b.Z, out var aInverse);
        Fp.Mul(inverse, a.Z, out var bInverse);
        affineA = AffineFrom(a, aInverse);
        affineB = AffineFrom(b, bInverse);
    }

    private static ECPoint AffineFrom(in JacobianPoint p, in BigInt256 zInverse)
    {
        Fp.Square(zInverse, out var z2);
        Fp.Mul(z2, zInverse, out var z3);
        Fp.Mul(p.X, z2, out var x);
        Fp.Mul(p.Y, z3, out var y);
        return new ECPoint
        {
            X = new FpElement { Value = x },
            Y = new FpElement { Value = y },
            Infinity = false,
        };
    }
}
