using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace SMX;

/// <summary>
/// Hex conversion. All paths use arithmetic or vector shuffles over constant tables rather than indexing by the data,
/// and decoding examines every digit before reporting a failure, because private keys pass through here. Error messages
/// never quote the input.
/// </summary>
public static class HexUtils
{
    private const byte LowerCaseBit = 0x20;
    private const byte UpperCaseBit = 0;
    private const int StackHexLimit = 128;

    /// <summary>The largest byte count whose hex fits in a .NET string (limited to about 2^30 characters).</summary>
    internal const int MaxHexBytes = 0x1FFFFFE0;

    /// <summary>Set by tests to exercise the scalar paths on hardware that has vector support.</summary>
    internal static bool ForceScalar { get; set; }

    /// <exception cref="ArgumentNullException"><paramref name="bytes"/> is null.</exception>
    /// <exception cref="ArgumentException">The input is too long for its hex form to fit in a string.</exception>
    public static string BytesToHex(byte[] bytes) => ToHexString(bytes, LowerCaseBit);

    /// <inheritdoc cref="BytesToHex"/>
    public static string BytesToHexUpper(byte[] bytes) => ToHexString(bytes, UpperCaseBit);

    /// <summary>
    /// Decodes an even number of hex digits of either case, with an optional single "0x" prefix. Unlike earlier versions,
    /// odd lengths are rejected rather than padded.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="hex"/> is null.</exception>
    /// <exception cref="ArgumentException">The input is not valid hex.</exception>
    public static byte[] HexToBytes(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        ReadOnlySpan<char> digits = hex;
        if (digits.Length >= 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X'))
        {
            digits = digits[2..];
        }
        if ((digits.Length & 1) != 0)
        {
            throw new ArgumentException("Invalid hex length");
        }
        var bytes = new byte[digits.Length / 2];
        if (!TryDecode(digits, bytes))
        {
            throw new ArgumentException("Invalid hex character");
        }
        return bytes;
    }

    private static string ToHexString(byte[] bytes, byte caseBit)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length > MaxHexBytes)
        {
            throw new ArgumentException("Input too long to convert to hex");
        }
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
        // The vector path writes through unchecked references.
        ArgumentOutOfRangeException.ThrowIfLessThan(chars.Length, bytes.Length * 2);
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

    /// <summary>
    /// False when the input holds an uppercase hex digit. Signatures and ciphertexts are public and have one canonical
    /// form, the lowercase this library writes; otherwise one value would have many strings, defeating replay caches.
    /// </summary>
    internal static bool IsLowerCaseOnly(ReadOnlySpan<char> hex) => hex.IndexOfAnyInRange('A', 'F') < 0;

    /// <summary>
    /// Decodes exactly bytes.Length * 2 hex digits of either case with no prefix. Every digit is processed whether or not
    /// an earlier one was invalid. False means the input was wrong and the output contents are meaningless.
    /// </summary>
    internal static bool TryDecode(ReadOnlySpan<char> hex, Span<byte> bytes)
    {
        if (hex.Length != bytes.Length * 2)
        {
            return false;
        }

        int i = 0;
        bool valid = true;
        if (Ssse3.IsSupported && !ForceScalar)
        {
            i = DecodeVector(hex, bytes, out valid);
        }

        int invalid = 0;
        for (; i < bytes.Length; i++)
        {
            int high = CharToNibble(hex[i * 2], ref invalid);
            int low = CharToNibble(hex[i * 2 + 1], ref invalid);
            bytes[i] = (byte)((high << 4) | low);
        }
        return valid & invalid == 0;
    }

    private static int DecodeVector(ReadOnlySpan<char> hex, Span<byte> bytes, out bool valid)
    {
        ref ushort src = ref Unsafe.As<char, ushort>(ref MemoryMarshal.GetReference(hex));
        ref byte dst = ref MemoryMarshal.GetReference(bytes);
        var weights = Vector128.Create((ushort)0x0110).AsSByte();
        var allValid = Vector128<byte>.AllBitsSet;

        int i = 0;
        for (; i + 16 <= bytes.Length; i += 16)
        {
            var c0 = Vector128.LoadUnsafe(ref src, (nuint)(i * 2));
            var c1 = Vector128.LoadUnsafe(ref src, (nuint)(i * 2 + 8));
            var c2 = Vector128.LoadUnsafe(ref src, (nuint)(i * 2 + 16));
            var c3 = Vector128.LoadUnsafe(ref src, (nuint)(i * 2 + 24));

            // Saturating pack: any character above 0xFF becomes 0x00 or 0xFF, both of which are rejected below.
            var n0 = Nibbles(Sse2.PackUnsignedSaturate(c0.AsInt16(), c1.AsInt16()), ref allValid);
            var n1 = Nibbles(Sse2.PackUnsignedSaturate(c2.AsInt16(), c3.AsInt16()), ref allValid);

            // Each pair h,l becomes h*16 + l in a 16-bit lane; packing then yields sixteen output bytes.
            var packed = Sse2.PackUnsignedSaturate(Ssse3.MultiplyAddAdjacent(n0, weights), Ssse3.MultiplyAddAdjacent(n1, weights));
            packed.StoreUnsafe(ref dst, (nuint)i);
        }
        valid = allValid == Vector128<byte>.AllBitsSet;
        return i;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<byte> Nibbles(Vector128<byte> chars, ref Vector128<byte> allValid)
    {
        // Digits map to 0..9 and letters of either case to 0..5, with everything else wrapping above those ranges.
        // Comparing as signed after a bias of 0x80 is the unsigned comparison SSE2 lacks.
        var bias = Vector128.Create((byte)0x80);
        var digit = chars - Vector128.Create((byte)'0');
        var letter = (chars | Vector128.Create((byte)0x20)) - Vector128.Create((byte)'a');
        var digitMask = Vector128.LessThan((digit ^ bias).AsSByte(), Vector128.Create(unchecked((sbyte)(10 ^ 0x80)))).AsByte();
        var letterMask = Vector128.LessThan((letter ^ bias).AsSByte(), Vector128.Create(unchecked((sbyte)(6 ^ 0x80)))).AsByte();
        allValid &= digitMask | letterMask;
        return (digit & digitMask) | ((letter + Vector128.Create((byte)10)) & letterMask);
    }

    /// <summary>The digit's value, or an arbitrary value with a bit set in <paramref name="invalid"/>. No branches.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int CharToNibble(char c, ref int invalid)
    {
        int digit = c - '0';
        int letter = (c | 0x20) - 'a';
        int isDigit = ((digit | (9 - digit)) >> 31) + 1;
        int isLetter = ((letter | (5 - letter)) >> 31) + 1;
        invalid |= (isDigit | isLetter) ^ 1;
        return (digit & -isDigit) | ((letter + 10) & -isLetter);
    }
}
