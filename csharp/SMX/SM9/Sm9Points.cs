namespace SMX.SM9Internal;

/// <summary>An affine point of G1 = E(Fq), y^2 = x^3 + 5, or the identity.</summary>
internal readonly struct G1Affine
{
    public const int EncodedSize = 1 + 2 * Fq.ByteSize;
    public const int CoordinatesSize = 2 * Fq.ByteSize;

    public readonly Fq X, Y;
    public readonly bool Infinity;

    public G1Affine(in Fq x, in Fq y, bool infinity)
    {
        X = x;
        Y = y;
        Infinity = infinity;
    }

    public static readonly G1Affine Generator = new(
        Fq.FromHexConstant("93de051d62bf718ff5ed0704487d01d6e1e4086909dc3280e8c4e4817c66dddd"),
        Fq.FromHexConstant("21fe8dda4f21e607631065125c395bbc1c1c00cbfa6024350c464cd70a3ea616"), false);

    public ProjPoint<Fq> ToProjective() => Infinity ? ProjPoint<Fq>.Identity : ProjPoint<Fq>.FromAffine(X, Y);

    public static G1Affine FromProjective(in ProjPoint<Fq> p)
    {
        bool finite = Curve<Fq>.ToAffine(p, out var x, out var y);
        return new G1Affine(x, y, !finite);
    }

    /// <summary>[k]P with a regular schedule; k may be secret.</summary>
    public G1Affine Multiply(in BigInt256 k) => FromProjective(Curve<Fq>.Multiply(ToProjective(), k));

    private static readonly Lazy<FixedBaseTable<Fq>> GeneratorTable = new(() => new FixedBaseTable<Fq>(Generator.ToProjective()));

    /// <summary>[k]P1 from the precomputed table; k may be secret.</summary>
    public static ProjPoint<Fq> MultiplyGenerator(in BigInt256 k) => GeneratorTable.Value.Multiply(k);

    /// <summary>
    /// Decodes 04 || x || y: both coordinates below q and on the curve. The identity has no such encoding, and E(Fq) has
    /// prime order, so every decoded point is a valid element of G1.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> encoded, out G1Affine point)
    {
        point = default;
        if (encoded.Length != EncodedSize || encoded[0] != 0x04)
        {
            return false;
        }
        bool okX = Fq.TryRead(encoded.Slice(1, Fq.ByteSize), out var x);
        bool okY = Fq.TryRead(encoded.Slice(1 + Fq.ByteSize, Fq.ByteSize), out var y);
        if (!(okX & okY) || !Curve<Fq>.IsOnCurve(x, y))
        {
            return false;
        }
        point = new G1Affine(x, y, false);
        return true;
    }

    /// <summary>Hex of either case, exactly 130 digits, then <see cref="TryDecode"/>.</summary>
    public static bool TryParseHex(ReadOnlySpan<char> hex, out G1Affine point)
    {
        point = default;
        Span<byte> bytes = stackalloc byte[EncodedSize];
        return HexUtils.TryDecode(hex, bytes) && TryDecode(bytes, out point);
    }

    /// <summary>x || y, 64 bytes, as used inside hashes. The identity must not reach here.</summary>
    public void WriteCoordinates(Span<byte> output)
    {
        X.Write(output);
        Y.Write(output[Fq.ByteSize..]);
    }

    public void Encode(Span<byte> output)
    {
        output[0] = 0x04;
        WriteCoordinates(output[1..]);
    }

    public string ToHex()
    {
        Span<byte> bytes = stackalloc byte[EncodedSize];
        Encode(bytes);
        return HexUtils.ToHexLower(bytes);
    }
}

/// <summary>An affine point of G2, on the twist y^2 = x^3 + 5u over Fq2, or the identity.</summary>
internal readonly struct G2Affine
{
    public const int EncodedSize = 1 + 4 * Fq.ByteSize;

    public readonly Fq2 X, Y;
    public readonly bool Infinity;

    public G2Affine(in Fq2 x, in Fq2 y, bool infinity)
    {
        X = x;
        Y = y;
        Infinity = infinity;
    }

    public static readonly G2Affine Generator = new(
        new Fq2(Fq.FromHexConstant("3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b"),
            Fq.FromHexConstant("85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141")),
        new Fq2(Fq.FromHexConstant("a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7"),
            Fq.FromHexConstant("17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96")), false);

    public ProjPoint<Fq2> ToProjective() => Infinity ? ProjPoint<Fq2>.Identity : ProjPoint<Fq2>.FromAffine(X, Y);

    public static G2Affine FromProjective(in ProjPoint<Fq2> p)
    {
        bool finite = Curve<Fq2>.ToAffine(p, out var x, out var y);
        return new G2Affine(x, y, !finite);
    }

    public G2Affine Multiply(in BigInt256 k) => FromProjective(Curve<Fq2>.Multiply(ToProjective(), k));

    private static readonly Lazy<FixedBaseTable<Fq2>> GeneratorTable = new(() => new FixedBaseTable<Fq2>(Generator.ToProjective()));

    /// <summary>[k]P2 from the precomputed table; k may be secret.</summary>
    public static ProjPoint<Fq2> MultiplyGenerator(in BigInt256 k) => GeneratorTable.Value.Multiply(k);

    /// <summary>q mod N = 6t^2, the eigenvalue of the twist Frobenius pi on G2.</summary>
    private static readonly UInt128 FrobeniusEigenvalue = new(0xd8000000019062ed, 0x0000b98b0cb27658);

    /// <summary>
    /// Decodes 04 || x1 || x0 || y1 || y0: all four coordinates below q, on the twist, and in the order-N subgroup. The
    /// twist has a large cofactor, so the subgroup check is essential: without it, points of other orders would pass.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> encoded, out G2Affine point)
    {
        point = default;
        if (encoded.Length != EncodedSize || encoded[0] != 0x04)
        {
            return false;
        }
        bool okX = Fq2.TryRead(encoded.Slice(1, 2 * Fq.ByteSize), out var x);
        bool okY = Fq2.TryRead(encoded.Slice(1 + 2 * Fq.ByteSize, 2 * Fq.ByteSize), out var y);
        if (!(okX & okY) || !Curve<Fq2>.IsOnCurve(x, y))
        {
            return false;
        }
        var candidate = new G2Affine(x, y, false);
        if (!IsInSubgroup(candidate))
        {
            return false;
        }
        point = candidate;
        return true;
    }

    /// <summary>
    /// Membership in G2 by pi(Q) = [6t^2]Q, equivalent to [N]Q = O at half the cost. On G2, pi acts as q mod N = 6t^2.
    /// Conversely, write Q = G + T with G in G2 and T of order dividing the cofactor h = 2q - N; if pi(T) = [6t^2]T with
    /// T not O, some prime l dividing the order of T (so l | h) has 6t^2 as an eigenvalue of pi on E'[l], hence divides
    /// (6t^2)^2 - (6t^2 + 1) 6t^2 + q = N by Cayley-Hamilton, contradicting gcd(h, N) = 1. The schedule depends only on
    /// the public constant, and the formulas are complete, so this is constant time in Q (a private key comes here).
    /// </summary>
    internal static bool IsInSubgroup(in G2Affine q)
    {
        Sm9Pairing.TwistFrobenius(q.X, q.Y, out var fx, out var fy);
        var lambdaQ = Curve<Fq2>.MultiplyPublic(q.ToProjective(), FrobeniusEigenvalue);
        return Curve<Fq2>.Equal(lambdaQ, ProjPoint<Fq2>.FromAffine(fx, fy));
    }

    /// <summary>The direct check [N]Q = O, kept for tests.</summary>
    internal static bool IsInSubgroupByOrder(in G2Affine q) => Curve<Fq2>.Multiply(q.ToProjective(), Sm9Scalar.N).IsIdentity;

    public static bool TryParseHex(ReadOnlySpan<char> hex, out G2Affine point)
    {
        point = default;
        Span<byte> bytes = stackalloc byte[EncodedSize];
        return HexUtils.TryDecode(hex, bytes) && TryDecode(bytes, out point);
    }

    public void Encode(Span<byte> output)
    {
        output[0] = 0x04;
        X.Write(output[1..]);
        Y.Write(output[(1 + 2 * Fq.ByteSize)..]);
    }

    public string ToHex()
    {
        Span<byte> bytes = stackalloc byte[EncodedSize];
        Encode(bytes);
        return HexUtils.ToHexLower(bytes);
    }
}
