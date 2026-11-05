namespace SMX;

/// <summary>
/// Finite field element modulo SM2_P. The constructor rejects values that are not canonical. The Value field is public
/// and can be set to anything, so every operation here first brings it into range and so stays mathematically correct.
/// </summary>
public struct FpElement : IEquatable<FpElement>
{
    public static readonly BigInt256 SM2_P = Fp.P;

    public BigInt256 Value;

    /// <exception cref="ArgumentException">v is not below SM2_P.</exception>
    public FpElement(BigInt256 v)
    {
        v.Sub(Fp.P, out ulong borrow);
        if (borrow == 0)
        {
            throw new ArgumentException("Field element out of range");
        }
        Value = v;
    }

    /// <inheritdoc cref="BigInt256.FromHex(string)"/>
    public static FpElement FromHex(string s) => new(BigInt256.FromHex(s));
    public static FpElement Zero => default;
    public static FpElement One => new() { Value = BigInt256.One };

    private readonly BigInt256 Canonical
    {
        get
        {
            Fp.Canonicalize(Value, out var reduced);
            return reduced;
        }
    }

    public readonly bool IsZero => Canonical.IsZero;
    public readonly bool IsOne => Canonical.IsOne;

    public readonly FpElement Add(FpElement b)
    {
        Fp.Add(Canonical, b.Canonical, out var r);
        return new FpElement { Value = r };
    }

    public readonly FpElement Sub(FpElement b)
    {
        Fp.Sub(Canonical, b.Canonical, out var r);
        return new FpElement { Value = r };
    }

    public readonly FpElement Mul(FpElement b)
    {
        Fp.Mul(Value, b.Value, out var r);
        return new FpElement { Value = r };
    }

    public readonly FpElement Square()
    {
        Fp.Square(Value, out var r);
        return new FpElement { Value = r };
    }

    public readonly FpElement Negate()
    {
        Fp.Negate(Canonical, out var r);
        return new FpElement { Value = r };
    }

    /// <exception cref="InvalidOperationException">The element is zero.</exception>
    public readonly FpElement Invert()
    {
        if (IsZero)
        {
            throw new InvalidOperationException("Cannot invert zero");
        }
        Fp.Invert(Value, out var r);
        return new FpElement { Value = r };
    }

    /// <exception cref="InvalidOperationException"><paramref name="b"/> is zero.</exception>
    public readonly FpElement Div(FpElement b) => Mul(b.Invert());

    public readonly FpElement Double()
    {
        Fp.Double(Canonical, out var r);
        return new FpElement { Value = r };
    }

    public readonly FpElement Triple()
    {
        var a = Canonical;
        Fp.Double(a, out var r);
        Fp.Add(r, a, out r);
        return new FpElement { Value = r };
    }

    public readonly BigInt256 ToBigInt() => Canonical;
    public readonly byte[] ToBEBytes() => Canonical.ToBEBytes();
    public readonly string ToHex() => Canonical.ToHex();

    public readonly bool Equals(FpElement other) => Canonical == other.Canonical;
    public override readonly bool Equals(object? obj) => obj is FpElement f && Equals(f);
    public override readonly int GetHashCode() => Canonical.GetHashCode();
    public static bool operator ==(FpElement a, FpElement b) => a.Equals(b);
    public static bool operator !=(FpElement a, FpElement b) => !a.Equals(b);
}
