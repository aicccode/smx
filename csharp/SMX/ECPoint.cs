namespace SMX;

/// <summary>
/// Affine point on the SM2 elliptic curve.
/// Internal computations use Jacobian coordinates for performance.
/// </summary>
public struct ECPoint
{
    public static readonly FpElement SM2_A = new() { Value = new BigInt256(
        0xFFFFFFFFFFFFFFFC, 0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF
    )};

    public static readonly FpElement SM2_B = new() { Value = new BigInt256(
        0xDDBCBD414D940E93, 0xF39789F515AB8F92,
        0x4D5A9E4BCF6509A7, 0x28E9FA9E9D9F5E34
    )};

    public static readonly FpElement SM2_GX = new() { Value = new BigInt256(
        0x715A4589334C74C7, 0x8FE30BBFF2660BE1,
        0x5F9904466A39C994, 0x32C4AE2C1F198119
    )};

    public static readonly FpElement SM2_GY = new() { Value = new BigInt256(
        0x02DF32E52139F0A0, 0xD0A9877CC62A4740,
        0x59BDCEE36B692153, 0xBC3736A2F4F6779C
    )};

    public static readonly BigInt256 SM2_N = new(
        0x53BBF40939D54123, 0x7203DF6B21C6052B,
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF
    );

    public FpElement X, Y;
    public bool Infinity;

    public static ECPoint Create(FpElement x, FpElement y) => new() { X = x, Y = y, Infinity = false };
    public static ECPoint PointAtInfinity => new() { X = FpElement.Zero, Y = FpElement.Zero, Infinity = true };
    public static ECPoint Generator() => Create(SM2_GX, SM2_GY);

    public static ECPoint FromHex(string xHex, string yHex) =>
        Create(FpElement.FromHex(xHex), FpElement.FromHex(yHex));

    public static ECPoint FromEncoded(byte[] data)
    {
        if (data.Length == 0) return PointAtInfinity;
        if (data[0] != 0x04 || data.Length != 65)
            throw new ArgumentException("Invalid point encoding");
        var xBytes = new byte[32];
        var yBytes = new byte[32];
        Array.Copy(data, 1, xBytes, 0, 32);
        Array.Copy(data, 33, yBytes, 0, 32);
        return Create(new FpElement(BigInt256.FromBEBytes(xBytes)), new FpElement(BigInt256.FromBEBytes(yBytes)));
    }

    public static ECPoint FromHexEncoded(string s)
    {
        var b = HexUtils.HexToBytes(s);
        return FromEncoded(b);
    }

    public byte[] ToEncoded()
    {
        if (Infinity) return [0x00];
        var result = new byte[65];
        result[0] = 0x04;
        var xb = X.ToBEBytes();
        var yb = Y.ToBEBytes();
        Array.Copy(xb, 0, result, 1, 32);
        Array.Copy(yb, 0, result, 33, 32);
        return result;
    }

    public string ToHexEncoded() => HexUtils.BytesToHex(ToEncoded());

    public ECPoint Negate()
    {
        if (Infinity) return PointAtInfinity;
        return new ECPoint { X = X, Y = Y.Negate(), Infinity = false };
    }

    public bool IsOnCurve()
    {
        if (Infinity) return true;
        // y^2 = x^3 + a*x + b => y^2 = (x^2 + a)*x + b
        var lhs = Y.Square();
        var rhs = X.Square().Add(SM2_A).Mul(X).Add(SM2_B);
        return lhs == rhs;
    }

    public bool Equal(ECPoint q)
    {
        if (Infinity && q.Infinity) return true;
        if (Infinity || q.Infinity) return false;
        return X == q.X && Y == q.Y;
    }

    public ECPoint Add(ECPoint q)
    {
        if (Infinity) return q;
        if (q.Infinity) return this;
        var jp = JacobianPoint.FromAffine(this);
        return jp.AddAffine(q).ToAffine();
    }

    public ECPoint Twice()
    {
        if (Infinity || Y.IsZero) return PointAtInfinity;
        var jp = JacobianPoint.FromAffine(this);
        return jp.Double().ToAffine();
    }

    public ECPoint Subtract(ECPoint q) => Add(q.Negate());

    public ECPoint Multiply(in BigInt256 k)
    {
        if (k.IsZero || Infinity) return PointAtInfinity;
        if (k.IsOne) return this;

        var result = JacobianPoint.Identity;
        int bitLen = k.BitLength();
        for (int i = bitLen - 1; i >= 0; i--)
        {
            result = result.Double();
            if (k.GetBit(i))
                result = result.AddAffine(this);
        }
        return result.ToAffine();
    }

    /// <summary>Internal Jacobian-coordinate point for efficient computation.</summary>
    private struct JacobianPoint
    {
        public FpElement X, Y, Z;

        public static JacobianPoint Identity => new() { X = FpElement.One, Y = FpElement.One, Z = FpElement.Zero };

        public static JacobianPoint FromAffine(ECPoint p)
        {
            if (p.Infinity) return Identity;
            return new JacobianPoint { X = p.X, Y = p.Y, Z = FpElement.One };
        }

        public ECPoint ToAffine()
        {
            if (Z.IsZero) return ECPoint.PointAtInfinity;
            var zInv = Z.Invert();
            var zInv2 = zInv.Square();
            var zInv3 = zInv2.Mul(zInv);
            var x = X.Mul(zInv2);
            var y = Y.Mul(zInv3);
            return ECPoint.Create(x, y);
        }

        /// <summary>Point doubling using a=-3 optimization (dbl-2001-b).</summary>
        public JacobianPoint Double()
        {
            if (Z.IsZero || Y.IsZero) return Identity;

            var delta = Z.Square();
            var gamma = Y.Square();
            var beta = X.Mul(gamma);

            // alpha = 3*(X1-delta)*(X1+delta) (using a=-3)
            var alpha = X.Sub(delta).Mul(X.Add(delta)).Triple();

            // X3 = alpha^2 - 8*beta
            var beta8 = beta.Double().Double().Double();
            var x3 = alpha.Square().Sub(beta8);

            // Z3 = (Y1+Z1)^2 - gamma - delta
            var z3 = Y.Add(Z).Square().Sub(gamma).Sub(delta);

            // Y3 = alpha*(4*beta - X3) - 8*gamma^2
            var beta4 = beta.Double().Double();
            var gammaSq8 = gamma.Square().Double().Double().Double();
            var y3 = alpha.Mul(beta4.Sub(x3)).Sub(gammaSq8);

            return new JacobianPoint { X = x3, Y = y3, Z = z3 };
        }

        /// <summary>Mixed addition (Jacobian + affine).</summary>
        public JacobianPoint AddAffine(ECPoint q)
        {
            if (q.Infinity) return this;
            if (Z.IsZero) return FromAffine(q);

            var z1z1 = Z.Square();
            var u2 = q.X.Mul(z1z1);
            var s2 = q.Y.Mul(Z).Mul(z1z1);
            var h = u2.Sub(X);
            var r = s2.Sub(Y);

            if (h.IsZero)
            {
                if (r.IsZero) return Double();
                return Identity;
            }

            var hh = h.Square();
            var hhh = hh.Mul(h);
            var x1hh = X.Mul(hh);
            var x3 = r.Square().Sub(hhh).Sub(x1hh.Double());
            var y3 = r.Mul(x1hh.Sub(x3)).Sub(Y.Mul(hhh));
            var z3 = Z.Mul(h);

            return new JacobianPoint { X = x3, Y = y3, Z = z3 };
        }
    }
}
