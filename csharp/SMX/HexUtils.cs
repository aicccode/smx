namespace SMX;

public static class HexUtils
{
    private static readonly char[] HexCharsLower = "0123456789abcdef".ToCharArray();
    private static readonly char[] HexCharsUpper = "0123456789ABCDEF".ToCharArray();

    public static string BytesToHex(byte[] bytes)
    {
        var chars = new char[bytes.Length * 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            chars[i * 2] = HexCharsLower[bytes[i] >> 4];
            chars[i * 2 + 1] = HexCharsLower[bytes[i] & 0x0F];
        }
        return new string(chars);
    }

    public static string BytesToHexUpper(byte[] bytes)
    {
        var chars = new char[bytes.Length * 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            chars[i * 2] = HexCharsUpper[bytes[i] >> 4];
            chars[i * 2 + 1] = HexCharsUpper[bytes[i] & 0x0F];
        }
        return new string(chars);
    }

    public static byte[] HexToBytes(string hex)
    {
        if (hex.StartsWith("0x") || hex.StartsWith("0X"))
            hex = hex[2..];
        if (hex.Length % 2 == 1)
            hex = "0" + hex;
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)((HexCharToNibble(hex[i * 2]) << 4) | HexCharToNibble(hex[i * 2 + 1]));
        }
        return bytes;
    }

    private static int HexCharToNibble(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw new ArgumentException($"Invalid hex character: {c}");
    }
}
