namespace SMX;

/// <summary>
/// Finite field element modulo SM2_P.
/// </summary>
public struct FpElement : IEquatable<FpElement>
{
    public static readonly BigInt256 SM2_P = Fp.P;

    public BigInt256 Value;

    public FpElement(BigInt256 v)
    {
        var reduced = v.Sub(Fp.P, out ulong borrow);
        Value = BigInt256.Select(Bits.MaskFromBit(borrow), v, reduced);
    }

    public static FpElement FromHex(string s) => new(BigInt256.FromHex(s));
    public static FpElement Zero => default;
    public static FpElement One => new() { Value = BigInt256.One };

    public readonly bool IsZero => Value.IsZero;
    public readonly bool IsOne => Value.IsOne;

    public readonly FpElement Add(FpElement b)
    {
        Fp.Add(Value, b.Value, out var r);
        return new FpElement { Value = r };
    }

    public readonly FpElement Sub(FpElement b)
    {
        Fp.Sub(Value, b.Value, out var r);
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
        if (IsZero)
        {
            return this;
        }
        Fp.Negate(Value, out var r);
        return new FpElement { Value = r };
    }

    public readonly FpElement Invert()
    {
        if (IsZero)
        {
            throw new InvalidOperationException("Cannot invert zero");
        }
        Fp.Invert(Value, out var r);
        return new FpElement { Value = r };
    }

    public readonly FpElement Div(FpElement b) => Mul(b.Invert());

    public readonly FpElement Double()
    {
        Fp.Double(Value, out var r);
        return new FpElement { Value = r };
    }

    public readonly FpElement Triple()
    {
        Fp.Double(Value, out var r);
        Fp.Add(r, Value, out r);
        return new FpElement { Value = r };
    }

    public readonly BigInt256 ToBigInt() => Value;
    public readonly byte[] ToBEBytes() => Value.ToBEBytes();
    public readonly string ToHex() => Value.ToHex();

    public readonly bool Equals(FpElement other) => Value == other.Value;
    public override readonly bool Equals(object? obj) => obj is FpElement f && Equals(f);
    public override readonly int GetHashCode() => Value.GetHashCode();
    public static bool operator ==(FpElement a, FpElement b) => a.Equals(b);
    public static bool operator !=(FpElement a, FpElement b) => !a.Equals(b);
}
