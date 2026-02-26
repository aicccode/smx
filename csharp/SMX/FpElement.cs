namespace SMX;

/// <summary>
/// Finite field element modulo SM2_P.
/// </summary>
public struct FpElement : IEquatable<FpElement>
{
    public static readonly BigInt256 SM2_P = new(
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000,
        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFFFF
    );

    public BigInt256 Value;

    public FpElement(BigInt256 v)
    {
        if (v.Compare(SM2_P) >= 0)
            v = v.ModSub(SM2_P, SM2_P);
        Value = v;
    }

    public static FpElement FromHex(string s) => new(BigInt256.FromHex(s));
    public static FpElement Zero => new() { Value = BigInt256.Zero };
    public static FpElement One => new() { Value = BigInt256.One };

    public bool IsZero => Value.IsZero;
    public bool IsOne => Value.IsOne;

    public FpElement Add(FpElement b) => new() { Value = Value.ModAdd(b.Value, SM2_P) };
    public FpElement Sub(FpElement b) => new() { Value = Value.ModSub(b.Value, SM2_P) };
    public FpElement Mul(FpElement b) => new() { Value = Value.SM2ModMulP(b.Value) };
    public FpElement Square() => new() { Value = Value.SM2ModSquareP() };

    public FpElement Negate()
    {
        if (IsZero) return this;
        return new FpElement { Value = SM2_P.ModSub(Value, SM2_P) };
    }

    public FpElement Invert()
    {
        if (IsZero) throw new InvalidOperationException("Cannot invert zero");
        var two = new BigInt256(2, 0, 0, 0);
        var pMinus2 = SM2_P.Sub(two, out _);
        var result = BigInt256.One;
        var b = Value;
        int bitLen = pMinus2.BitLength();
        for (int i = 0; i < bitLen; i++)
        {
            if (pMinus2.GetBit(i))
                result = result.SM2ModMulP(b);
            b = b.SM2ModSquareP();
        }
        return new FpElement { Value = result };
    }

    public FpElement Div(FpElement b) => Mul(b.Invert());
    public FpElement Double() => Add(this);
    public FpElement Triple() => Double().Add(this);

    public BigInt256 ToBigInt() => Value;
    public byte[] ToBEBytes() => Value.ToBEBytes();
    public string ToHex() => Value.ToHex();

    public bool Equals(FpElement other) => Value == other.Value;
    public override bool Equals(object? obj) => obj is FpElement f && Equals(f);
    public override int GetHashCode() => Value.GetHashCode();
    public static bool operator ==(FpElement a, FpElement b) => a.Equals(b);
    public static bool operator !=(FpElement a, FpElement b) => !a.Equals(b);
}
