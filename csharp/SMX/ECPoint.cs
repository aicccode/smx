namespace SMX;

/// <summary>
/// Affine point on the SM2 elliptic curve.
/// Internal computations use Jacobian coordinates for performance.
/// </summary>
public struct ECPoint
{
    public static readonly FpElement SM2_A = new()
    {
        Value = new BigInt256(0xFFFFFFFFFFFFFFFC, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF),
    };

    public static readonly FpElement SM2_B = new()
    {
        Value = new BigInt256(0xDDBCBD414D940E93, 0xF39789F515AB8F92, 0x4D5A9E4BCF6509A7, 0x28E9FA9E9D9F5E34),
    };

    public static readonly FpElement SM2_GX = new() { Value = Sm2Group.Gx };

    public static readonly FpElement SM2_GY = new() { Value = Sm2Group.Gy };

    public static readonly BigInt256 SM2_N = Sm2Order.N;

    public FpElement X, Y;
    public bool Infinity;

    public static ECPoint Create(FpElement x, FpElement y) => new() { X = x, Y = y, Infinity = false };
    public static ECPoint PointAtInfinity => new() { Infinity = true };
    public static ECPoint Generator() => Create(SM2_GX, SM2_GY);

    public static ECPoint FromHex(string xHex, string yHex) =>
        Create(FpElement.FromHex(xHex), FpElement.FromHex(yHex));

    public static ECPoint FromEncoded(byte[] data)
    {
        _ = data.Length;
        return FromEncoded(data.AsSpan());
    }

    internal static ECPoint FromEncoded(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return PointAtInfinity;
        }
        if (data[0] != 0x04 || data.Length != 65)
        {
            throw new ArgumentException("Invalid point encoding");
        }
        return Create(new FpElement(BigInt256.FromBigEndian(data[1..33])), new FpElement(BigInt256.FromBigEndian(data[33..])));
    }

    public static ECPoint FromHexEncoded(string s)
    {
        _ = s.Length;
        return FromHexEncoded(s.AsSpan());
    }

    internal static ECPoint FromHexEncoded(ReadOnlySpan<char> s)
    {
        // The usual case is exactly one uncompressed point with no prefix.
        if (s.Length == 130 && s[1] != 'x' && s[1] != 'X')
        {
            Span<byte> buffer = stackalloc byte[65];
            HexUtils.DecodeEven(s, buffer);
            return FromEncoded((ReadOnlySpan<byte>)buffer);
        }
        return FromEncoded(HexUtils.HexToBytes(s));
    }

    public readonly byte[] ToEncoded()
    {
        if (Infinity)
        {
            return [0x00];
        }
        var result = new byte[65];
        WriteUncompressed(result);
        return result;
    }

    internal readonly void WriteUncompressed(Span<byte> o)
    {
        o[0] = 0x04;
        X.Value.WriteBigEndian(o[1..]);
        Y.Value.WriteBigEndian(o[33..]);
    }

    public readonly string ToHexEncoded()
    {
        if (Infinity)
        {
            return "00";
        }
        Span<byte> buffer = stackalloc byte[65];
        WriteUncompressed(buffer);
        return HexUtils.ToHexLower(buffer);
    }

    public readonly ECPoint Negate()
    {
        if (Infinity)
        {
            return PointAtInfinity;
        }
        return new ECPoint { X = X, Y = Y.Negate(), Infinity = false };
    }

    public readonly bool IsOnCurve()
    {
        if (Infinity)
        {
            return true;
        }

        // y^2 = x^3 + a*x + b => y^2 = (x^2 + a)*x + b
        var lhs = Y.Square();
        var rhs = X.Square().Add(SM2_A).Mul(X).Add(SM2_B);
        return lhs == rhs;
    }

    public readonly bool Equal(ECPoint q)
    {
        if (Infinity && q.Infinity)
        {
            return true;
        }
        if (Infinity || q.Infinity)
        {
            return false;
        }
        return X == q.X && Y == q.Y;
    }

    public readonly ECPoint Add(ECPoint q)
    {
        if (Infinity)
        {
            return q;
        }
        if (q.Infinity)
        {
            return this;
        }
        var jp = JacobianPoint.FromAffine(this);
        Sm2Group.AddMixedPublic(jp, q.X.Value, q.Y.Value, out var sum);
        return Sm2Group.ToAffine(sum);
    }

    public readonly ECPoint Twice()
    {
        if (Infinity || Y.IsZero)
        {
            return PointAtInfinity;
        }
        var jp = JacobianPoint.FromAffine(this);
        Sm2Group.Double(jp, out var doubled);
        return Sm2Group.ToAffine(doubled);
    }

    public readonly ECPoint Subtract(ECPoint q) => Add(q.Negate());

    /// <summary>
    /// k times this point, treating k as secret: see <see cref="Sm2Group"/> for what that means in managed code.
    /// Multiples of the standard generator use a precomputed comb, built once on first use.
    /// </summary>
    public readonly ECPoint Multiply(in BigInt256 k)
    {
        if (k.IsZero || Infinity)
        {
            return PointAtInfinity;
        }
        if (k.IsOne)
        {
            return this;
        }

        JacobianPoint result;
        if (X.Value == Sm2Group.Gx && Y.Value == Sm2Group.Gy)
        {
            Sm2Group.MultiplyGeneratorSecret(k, out result);
        }
        else
        {
            Sm2Group.MultiplySecret(JacobianPoint.FromAffine(this), k, out result);
        }
        return Sm2Group.ToAffine(result);
    }
}
