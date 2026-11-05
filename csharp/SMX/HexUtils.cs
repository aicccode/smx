using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace SMX;

/// <summary>
/// Hex conversion. All paths use arithmetic or vector shuffles over constant tables rather than indexing by the data,
/// because private keys pass through here.
/// </summary>
public static class HexUtils
{
    private const byte LowerCaseBit = 0x20;
    private const byte UpperCaseBit = 0;
    private const int StackHexLimit = 128;

    /// <summary>Set by tests to exercise the scalar paths on hardware that has vector support.</summary>
    internal static bool ForceScalar { get; set; }

    public static string BytesToHex(byte[] bytes) => ToHexString(bytes, LowerCaseBit);

    public static string BytesToHexUpper(byte[] bytes) => ToHexString(bytes, UpperCaseBit);

    public static byte[] HexToBytes(string hex)
    {
        _ = hex.Length;
        return HexToBytes(hex.AsSpan());
    }

    private static string ToHexString(byte[] bytes, byte caseBit)
    {
        return string.Create(bytes.Length * 2, (bytes, caseBit), static (chars, state) =>
            Encode(state.bytes, chars, state.caseBit));
    }

    internal static string ToHexLower(ReadOnlySpan<byte> bytes) => ToHexString(bytes, LowerCaseBit);

    internal static string ToHexUpper(ReadOnlySpan<byte> bytes) => ToHexString(bytes, UpperCaseBit);

    private static string ToHexString(ReadOnlySpan<byte> bytes, byte caseBit)
    {
        if (bytes.Length > StackHexLimit)
        {
            return ToHexString(bytes.ToArray(), caseBit);
        }
        Span<char> chars = stackalloc char[bytes.Length * 2];
        Encode(bytes, chars, caseBit);
        return new string(chars);
    }

    /// <summary>Writes lowercase hex of <paramref name="bytes"/> to <paramref name="chars"/>.</summary>
    internal static void EncodeLower(ReadOnlySpan<byte> bytes, Span<char> chars) => Encode(bytes, chars, LowerCaseBit);

    private static void Encode(ReadOnlySpan<byte> bytes, Span<char> chars, byte caseBit)
    {
        int i = 0;
        if (Ssse3.IsSupported && !ForceScalar)
        {
            i = EncodeVector(bytes, chars, caseBit);
        }

        int letterOffset = 'A' + caseBit - 10 - '0';
        for (; i < bytes.Length; i++)
        {
            chars[i * 2] = NibbleToChar(bytes[i] >> 4, letterOffset);
            chars[i * 2 + 1] = NibbleToChar(bytes[i] & 0x0F, letterOffset);
        }
    }

    private static int EncodeVector(ReadOnlySpan<byte> bytes, Span<char> chars, byte caseBit)
    {
        var digits = Vector128.Create(
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7', (byte)'8', (byte)'9',
            (byte)('A' | caseBit), (byte)('B' | caseBit), (byte)('C' | caseBit), (byte)('D' | caseBit), (byte)('E' | caseBit), (byte)('F' | caseBit));
        var lowNibble = Vector128.Create((byte)0x0F);
        ref byte src = ref MemoryMarshal.GetReference(bytes);
        ref ushort dst = ref Unsafe.As<char, ushort>(ref MemoryMarshal.GetReference(chars));

        int i = 0;
        for (; i + 16 <= bytes.Length; i += 16)
        {
            var v = Vector128.LoadUnsafe(ref src, (nuint)i);
            var hi = Ssse3.Shuffle(digits, Vector128.ShiftRightLogical(v.AsUInt16(), 4).AsByte() & lowNibble);
            var lo = Ssse3.Shuffle(digits, v & lowNibble);
            var (c0, c1) = Vector128.Widen(Sse2.UnpackLow(hi, lo));
            var (c2, c3) = Vector128.Widen(Sse2.UnpackHigh(hi, lo));
            c0.StoreUnsafe(ref dst, (nuint)(i * 2));
            c1.StoreUnsafe(ref dst, (nuint)(i * 2 + 8));
            c2.StoreUnsafe(ref dst, (nuint)(i * 2 + 16));
            c3.StoreUnsafe(ref dst, (nuint)(i * 2 + 24));
        }
        return i;
    }

    /// <summary>'0' + n, plus the gap to the letters when n exceeds 9, computed without a branch.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static char NibbleToChar(int n, int letterOffset) => (char)('0' + n + (((9 - n) >> 31) & letterOffset));

    internal static byte[] HexToBytes(ReadOnlySpan<char> hex)
    {
        if (hex.Length >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        {
            hex = hex[2..];
        }

        // An odd length means an implied leading zero nibble.
        var bytes = new byte[(hex.Length + 1) / 2];
        if ((hex.Length & 1) == 1)
        {
            bytes[0] = (byte)CharToNibble(hex[0]);
            DecodeEven(hex[1..], bytes.AsSpan(1));
        }
        else
        {
            DecodeEven(hex, bytes);
        }
        return bytes;
    }

    /// <summary>Decodes an even number of hex digits; throws for the first invalid character in reading order.</summary>
    internal static void DecodeEven(ReadOnlySpan<char> hex, Span<byte> bytes)
    {
        int i = 0;
        if (Ssse3.IsSupported && !ForceScalar)
        {
            i = DecodeVector(hex, bytes);
        }
        for (; i < hex.Length / 2; i++)
        {
            bytes[i] = (byte)((CharToNibble(hex[i * 2]) << 4) | CharToNibble(hex[i * 2 + 1]));
        }
    }

    /// <summary>Decodes whole 32-digit groups and stops at the first group holding an invalid digit.</summary>
    private static int DecodeVector(ReadOnlySpan<char> hex, Span<byte> bytes)
    {
        ref ushort src = ref Unsafe.As<char, ushort>(ref MemoryMarshal.GetReference(hex));
        ref byte dst = ref MemoryMarshal.GetReference(bytes);
        int count = hex.Length / 2;
        int i = 0;
        for (; i + 16 <= count; i += 16)
        {
            var c0 = Vector128.LoadUnsafe(ref src, (nuint)(i * 2));
            var c1 = Vector128.LoadUnsafe(ref src, (nuint)(i * 2 + 8));
            var c2 = Vector128.LoadUnsafe(ref src, (nuint)(i * 2 + 16));
            var c3 = Vector128.LoadUnsafe(ref src, (nuint)(i * 2 + 24));

            // Saturating pack: any character above 0xFF becomes 0x00 or 0xFF, both of which are rejected below.
            if (!TryNibbles(Sse2.PackUnsignedSaturate(c0.AsInt16(), c1.AsInt16()), out var n0)
                || !TryNibbles(Sse2.PackUnsignedSaturate(c2.AsInt16(), c3.AsInt16()), out var n1))
            {
                break;
            }

            // Each pair h,l becomes h*16 + l in a 16-bit lane; packing then yields sixteen output bytes.
            var weights = Vector128.Create((ushort)0x0110).AsSByte();
            var packed = Sse2.PackUnsignedSaturate(Ssse3.MultiplyAddAdjacent(n0, weights), Ssse3.MultiplyAddAdjacent(n1, weights));
            packed.StoreUnsafe(ref dst, (nuint)i);
        }
        return i;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool TryNibbles(Vector128<byte> chars, out Vector128<byte> nibbles)
    {
        // Digits map to 0..9 and letters of either case to 0..5, with everything else wrapping above those ranges.
        // Comparing as signed after a bias of 0x80 is the unsigned comparison SSE2 lacks.
        var bias = Vector128.Create((byte)0x80);
        var digit = chars - Vector128.Create((byte)'0');
        var letter = (chars | Vector128.Create((byte)0x20)) - Vector128.Create((byte)'a');
        var digitMask = Vector128.LessThan((digit ^ bias).AsSByte(), Vector128.Create(unchecked((sbyte)(10 ^ 0x80)))).AsByte();
        var letterMask = Vector128.LessThan((letter ^ bias).AsSByte(), Vector128.Create(unchecked((sbyte)(6 ^ 0x80)))).AsByte();
        nibbles = (digit & digitMask) | ((letter + Vector128.Create((byte)10)) & letterMask);
        return (digitMask | letterMask) == Vector128<byte>.AllBitsSet;
    }

    private static int CharToNibble(char c)
    {
        // Branch-free classification, so that a valid digit's value does not influence control flow.
        int digit = c - '0';
        int letter = (c | 0x20) - 'a';
        int isDigit = ((digit | (9 - digit)) >> 31) + 1;
        int isLetter = ((letter | (5 - letter)) >> 31) + 1;
        if ((isDigit | isLetter) == 0)
        {
            throw new ArgumentException($"Invalid hex character: {c}");
        }
        return (digit & -isDigit) | ((letter + 10) & -isLetter);
    }
}
