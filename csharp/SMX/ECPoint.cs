namespace SMX;

/// <summary>
/// Affine point on the SM2 elliptic curve. The fields are public, so a value might hold anything: every parser and
/// arithmetic operation validates its points, and rejects coordinates at or above p and points off the curve with an
/// <see cref="ArgumentException"/>. Internal computations use Jacobian coordinates for performance.
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

    private const int EncodedSize = 65;

    public FpElement X, Y;
    public bool Infinity;

    /// <exception cref="ArgumentException">The coordinates are out of range or not on the curve.</exception>
    public static ECPoint Create(FpElement x, FpElement y)
    {
        var p = new ECPoint { X = x, Y = y, Infinity = false };
        p.RequireOnCurve();
        return p;
    }

    public static ECPoint PointAtInfinity => new() { Infinity = true };
    public static ECPoint Generator() => new() { X = SM2_GX, Y = SM2_GY };

    /// <summary>Builds a point from two coordinates of exactly 64 hex digits each.</summary>
    /// <exception cref="ArgumentNullException">A coordinate is null.</exception>
    /// <exception cref="ArgumentException">The input is not an exact encoding of a point on the curve.</exception>
    public static ECPoint FromHex(string xHex, string yHex)
    {
        ArgumentNullException.ThrowIfNull(xHex);
        ArgumentNullException.ThrowIfNull(yHex);
        Span<byte> buffer = stackalloc byte[EncodedSize - 1];
        if (!HexUtils.TryDecode(xHex, buffer[..32]) || !HexUtils.TryDecode(yHex, buffer[32..]))
        {
            throw new ArgumentException("Invalid point encoding");
        }
        return TryFromCoordinates(buffer, out var p) ? p : throw new ArgumentException("Invalid point encoding");
    }

    /// <summary>Decodes exactly 65 bytes: 0x04, x and y. The point at infinity has no encoding that is accepted here.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="data"/> is null.</exception>
    /// <exception cref="ArgumentException">The input is not an exact encoding of a point on the curve.</exception>
    public static ECPoint FromEncoded(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length != EncodedSize || data[0] != 0x04 || !TryFromCoordinates(data.AsSpan(1), out var p))
        {
            throw new ArgumentException("Invalid point encoding");
        }
        return p;
    }

    /// <summary>Decodes exactly 130 hex digits of either case, with no prefix, encoding as in <see cref="FromEncoded(byte[])"/>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="s"/> is null.</exception>
    /// <exception cref="ArgumentException">The input is not an exact encoding of a point on the curve.</exception>
    public static ECPoint FromHexEncoded(string s)
    {
        ArgumentNullException.ThrowIfNull(s);
        return TryParse(s, out var p) ? p : throw new ArgumentException("Invalid point encoding");
    }

    /// <summary>The non-throwing form used by the protocol code. Success means canonical, in range, on the curve.</summary>
    internal static bool TryParse(ReadOnlySpan<char> s, out ECPoint p)
    {
        Span<byte> buffer = stackalloc byte[EncodedSize];
        p = default;
        return HexUtils.TryDecode(s, buffer) && buffer[0] == 0x04 && TryFromCoordinates(buffer[1..], out p);
    }

    private static bool TryFromCoordinates(ReadOnlySpan<byte> coordinates, out ECPoint p)
    {
        p = new ECPoint
        {
            X = new FpElement { Value = BigInt256.FromBigEndian(coordinates[..32]) },
            Y = new FpElement { Value = BigInt256.FromBigEndian(coordinates[32..]) },
        };
        return p.IsOnCurve();
    }

    public readonly byte[] ToEncoded()
    {
        if (Infinity)
        {
            return [0x00];
        }
        var result = new byte[EncodedSize];
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
        Span<byte> buffer = stackalloc byte[EncodedSize];
        WriteUncompressed(buffer);
        return HexUtils.ToHexLower(buffer);
    }

    /// <exception cref="ArgumentException">The point is not valid.</exception>
    public readonly ECPoint Negate()
    {
        if (Infinity)
        {
            return PointAtInfinity;
        }
        RequireOnCurve();
        return new ECPoint { X = X, Y = Y.Negate(), Infinity = false };
    }

    /// <summary>
    /// True only for a finite point with canonical coordinates that satisfies the curve equation. The point at infinity
    /// is the group identity, not a usable public key, so it answers false. Earlier versions answered true for it.
    /// </summary>
    public readonly bool IsOnCurve()
    {
        if (Infinity || !IsCanonical(X.Value) || !IsCanonical(Y.Value))
        {
            return false;
        }

        // y^2 = x^3 + a*x + b => y^2 = (x^2 + a)*x + b
        var lhs = Y.Square();
        var rhs = X.Square().Add(SM2_A).Mul(X).Add(SM2_B);
        return lhs == rhs;
    }

    private static bool IsCanonical(in BigInt256 v)
    {
        v.Sub(Fp.P, out ulong borrow);
        return borrow != 0;
    }

    private readonly void RequireOnCurve()
    {
        if (!IsOnCurve())
        {
            throw new ArgumentException("Point is not on the curve");
        }
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

    /// <summary>The group sum. The identity is allowed here as either operand and as a result.</summary>
    /// <exception cref="ArgumentException">A finite operand is not a valid point.</exception>
    public readonly ECPoint Add(ECPoint q)
    {
        if (Infinity)
        {
            q.RequireValidOrInfinity();
            return q;
        }
        RequireOnCurve();
        if (q.Infinity)
        {
            return this;
        }
        q.RequireOnCurve();
        var jp = JacobianPoint.FromAffine(this);
        Sm2Group.AddMixedPublic(jp, q.X.Value, q.Y.Value, out var sum);
        return Sm2Group.ToAffine(sum);
    }

    private readonly void RequireValidOrInfinity()
    {
        if (!Infinity)
        {
            RequireOnCurve();
        }
    }

    /// <exception cref="ArgumentException">The point is not valid.</exception>
    public readonly ECPoint Twice()
    {
        if (Infinity)
        {
            return PointAtInfinity;
        }
        RequireOnCurve();
        var jp = JacobianPoint.FromAffine(this);
        Sm2Group.Double(jp, out var doubled);
        return Sm2Group.ToAffine(doubled);
    }

    /// <exception cref="ArgumentException">A finite operand is not a valid point.</exception>
    public readonly ECPoint Subtract(ECPoint q) => Add(q.Negate());

    /// <summary>
    /// k times this point, treating k as secret: see <see cref="Sm2Group"/> for what that means in managed code. Any
    /// 256-bit k is a correct group multiple, including zero and multiples of the order, which give the point at infinity.
    /// Multiples of the standard generator use a precomputed comb, built once on first use.
    /// </summary>
    /// <exception cref="ArgumentException">The point is not valid.</exception>
    public readonly ECPoint Multiply(in BigInt256 k)
    {
        if (Infinity)
        {
            return PointAtInfinity;
        }
        RequireOnCurve();

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
