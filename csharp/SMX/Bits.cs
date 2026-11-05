using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace SMX;

/// <summary>
/// Branch-free word primitives. .NET 8 exposes no add-with-carry intrinsic, so carries are recovered from the sign bit
/// of a bitwise expression (the same identities as Go's math/bits); none of these branch or index memory on their inputs.
/// </summary>
internal static class Bits
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Add(ulong a, ulong b, ulong carryIn, out ulong carryOut)
    {
        ulong sum = a + b + carryIn;
        carryOut = ((a & b) | ((a | b) & ~sum)) >> 63;
        return sum;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Sub(ulong a, ulong b, ulong borrowIn, out ulong borrowOut)
    {
        ulong diff = a - b - borrowIn;
        borrowOut = ((~a & b) | (~(a ^ b) & diff)) >> 63;
        return diff;
    }

    /// <summary>Returns <c>x * y + add + carry</c> as a low word, leaving the high word in <paramref name="carry"/>.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong MulAdd(ulong x, ulong y, ulong add, ref ulong carry)
    {
        ulong hi = MulHigh(x, y, out ulong lo);
        lo += add;
        hi += Below(lo, add);
        lo += carry;
        carry = hi + Below(lo, carry);
        return lo;
    }

    /// <summary>
    /// The full 128-bit product. Where BMI2 exists this takes the two halves from separate multiplications, because in
    /// .NET 8 the out parameter of Math.BigMul forces a store and reload of the low word on every call.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong MulHigh(ulong x, ulong y, out ulong low)
    {
        if (Bmi2.X64.IsSupported)
        {
            low = x * y;
            return Bmi2.X64.MultiplyNoFlags(x, y);
        }
        return Math.BigMul(x, y, out low);
    }

    /// <summary>1 when a &lt; b, else 0: a compare and a set-condition instruction, with no branch even in unoptimized JIT tiers.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Below(ulong a, ulong b)
    {
        bool below = a < b;
        return Unsafe.BitCast<bool, byte>(below);
    }

    /// <summary>All ones when <paramref name="x"/> is zero, otherwise zero.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong IsZeroMask(ulong x) => ((x | (0 - x)) >> 63) - 1;

    /// <summary>All ones when <paramref name="bit"/> is 1, zero when it is 0.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong MaskFromBit(ulong bit) => 0 - bit;

    /// <summary>Selects <paramref name="ifSet"/> when the mask is all ones and <paramref name="ifClear"/> when it is zero.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong Select(ulong mask, ulong ifSet, ulong ifClear) => (ifSet & mask) | (ifClear & ~mask);
}
