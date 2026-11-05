package site.aicc.sm2.util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Data type conversion utilities. Invalid input raises {@link IllegalArgumentException}.
 *
 * <p>Keys pass through the hex functions, so these use arithmetic instead of lookup tables and do
 * not branch on digit values, and their error messages never quote the input.
 */
public class ConvertUtil {
  /** Largest output or input handled by conversions whose size the caller chooses. */
  private static final int MAX_CONVERSION_BYTES = 1 << 24;

  private static final int MAX_HEX_INPUT_BYTES = (Integer.MAX_VALUE - 16) / 2;
  private static final int HEX_LETTER_OFFSET_LOWER = 'a' - '0' - 10;
  private static final int HEX_LETTER_OFFSET_UPPER = 'A' - '0' - 10;

  /** Compares without an early exit; only the lengths are not hidden. */
  public static boolean byteArrayEqual(byte[] a, byte[] b) {
    if (a == b) {
      return true;
    }
    if (a == null || b == null) {
      return false;
    }
    if (a.length != b.length) {
      return false;
    }
    int diff = 0;
    for (int i = 0; i != a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  /** Reads {@code len} little-endian 32-bit words as an unsigned number. */
  public static BigInteger toBigInteger(int len, int[] x) {
    if (x == null || len < 0 || len > x.length || len > MAX_CONVERSION_BYTES >> 2) {
      throw new IllegalArgumentException("Invalid word array");
    }
    byte[] bs = new byte[len << 2];
    for (int i = 0; i < len; ++i) {
      intToBigEndian(x[i], bs, (len - 1 - i) << 2);
    }
    return new BigInteger(1, bs);
  }

  /** Encodes a value in [0, 2^256) as exactly 32 big-endian bytes. */
  public static byte[] bigIntegerTo32Bytes(BigInteger n) {
    if (n == null || n.signum() < 0 || n.bitLength() > 256) {
      throw new IllegalArgumentException("Value does not fit in 32 bytes");
    }
    byte[] raw = n.toByteArray();
    byte[] out = new byte[32];
    int count = Math.min(raw.length, 32);
    System.arraycopy(raw, raw.length - count, out, 32 - count, count);
    return out;
  }

  /** Encodes a non-negative value as exactly {@code length} big-endian bytes. */
  public static byte[] asUnsignedByteArray(int length, BigInteger value) {
    if (value == null || value.signum() < 0) {
      throw new IllegalArgumentException("Value must be non-negative");
    }
    if (length < 0 || length > MAX_CONVERSION_BYTES) {
      throw new IllegalArgumentException("Invalid length");
    }
    if (value.bitLength() > length * 8L) {
      throw new IllegalArgumentException("Value cannot be represented in the given length");
    }
    byte[] raw = value.toByteArray();
    byte[] out = new byte[length];
    int count = Math.min(raw.length, length);
    System.arraycopy(raw, raw.length - count, out, length - count, count);
    return out;
  }

  /** Reads a range of bytes as an unsigned big-endian number. */
  public static BigInteger fromUnsignedByteArray(byte[] buf, int off, int length) {
    checkRange(buf, off, length);
    if (off == 0 && length == buf.length) {
      return new BigInteger(1, buf);
    }
    byte[] mag = new byte[length];
    System.arraycopy(buf, off, mag, 0, length);
    return new BigInteger(1, mag);
  }

  public static String byteToHex(byte[] bytes) {
    return getHexString(bytes, false);
  }

  /**
   * Decodes hex of even length with digits 0-9, a-f and A-F, nothing else. Signs and non-ASCII
   * digits are rejected, so every byte string has only its two case forms as encodings.
   *
   * @throws NumberFormatException for an invalid digit (an {@link IllegalArgumentException})
   */
  public static byte[] hexToByte(String hex) {
    if (hex == null || hex.length() % 2 != 0) {
      throw new IllegalArgumentException("Input is not a hex string");
    }
    int length = hex.length();
    byte[] b = new byte[length / 2];
    int invalid = 0;
    for (int i = 0, j = 0; i < length; i += 2, j++) {
      int hi = hexDigit(hex.charAt(i));
      int lo = hexDigit(hex.charAt(i + 1));
      invalid |= hi | lo;
      b[j] = (byte) (hi << 4 | lo);
    }
    if (invalid < 0) {
      throw new NumberFormatException("Input is not a hex string");
    }
    return b;
  }

  /**
   * Decodes hex in the one form this library emits for ciphertexts and signatures: even length and
   * digits 0-9, a-f only. A second spelling of the same value would let a replay or dedup cache
   * keyed on the string be bypassed.
   *
   * @throws IllegalArgumentException for anything else
   */
  public static byte[] canonicalHexToByte(String hex) {
    if (hex == null) {
      throw new IllegalArgumentException("Input is not a hex string");
    }
    int upper = 0;
    for (int i = 0, n = hex.length(); i < n; i++) {
      int letter = hex.charAt(i) - 'A';
      upper |= ~(letter | (5 - letter)) >> 31;
    }
    if (upper != 0) {
      throw new IllegalArgumentException("Input is not a hex string");
    }
    return hexToByte(hex);
  }

  /** Returns the digit's value, or -1, using no branch or table indexed by the character. */
  private static int hexDigit(int c) {
    int decimal = c - '0';
    int letter = (c | 0x20) - 'a';
    int notDecimal = (decimal | (9 - decimal)) >> 31;
    int notLetter = (letter | (5 - letter)) >> 31;
    return (decimal & ~notDecimal) | ((letter + 10) & ~notLetter) | (notDecimal & notLetter);
  }

  /** Splits a non-negative number into little-endian 32-bit words. */
  public static int[] fromBigInteger(int bits, BigInteger x) {
    if (x == null || x.signum() < 0 || bits < 0 || bits > MAX_CONVERSION_BYTES * 8L) {
      throw new IllegalArgumentException("Invalid value");
    }
    if (x.bitLength() > bits) {
      throw new IllegalArgumentException("Value does not fit");
    }
    int[] z = new int[(int) ((bits + 31L) >> 5)];
    BigInteger rest = x;
    int i = 0;
    while (rest.signum() != 0) {
      z[i++] = rest.intValue();
      rest = rest.shiftRight(32);
    }
    return z;
  }

  /** Returns a bit of a little-endian word array; bits beyond the array read as 0. */
  public static int getBit(int[] x, int bit) {
    if (x == null || bit < 0) {
      throw new IllegalArgumentException("Invalid bit position");
    }
    int w = bit >> 5;
    return w < x.length ? (x[w] >>> (bit & 31)) & 1 : 0;
  }

  /** Encodes bytes as hex in the requested case. */
  public static String getHexString(byte[] bytes, boolean upperCase) {
    if (bytes == null || bytes.length > MAX_HEX_INPUT_BYTES) {
      throw new IllegalArgumentException("Invalid input for hex encoding");
    }
    int letterOffset = upperCase ? HEX_LETTER_OFFSET_UPPER : HEX_LETTER_OFFSET_LOWER;
    byte[] hex = new byte[bytes.length * 2];
    for (int j = 0, o = 0; j < bytes.length; j++, o += 2) {
      int v = bytes[j] & 0xFF;
      hex[o] = (byte) hexChar(v >>> 4, letterOffset);
      hex[o + 1] = (byte) hexChar(v & 0x0F, letterOffset);
    }
    return new String(hex, StandardCharsets.ISO_8859_1);
  }

  private static int hexChar(int nibble, int letterOffset) {
    return nibble + '0' + (((9 - nibble) >> 31) & letterOffset);
  }

  /** Writes an int as four big-endian bytes at {@code off}. */
  public static void intToBigEndian(int n, byte[] bs, int off) {
    checkRange(bs, off, 4);
    bs[off] = (byte) (n >>> 24);
    bs[off + 1] = (byte) (n >>> 16);
    bs[off + 2] = (byte) (n >>> 8);
    bs[off + 3] = (byte) (n);
  }

  /**
   * Encodes text as UTF-8, rejecting unpaired surrogates. {@link String#getBytes} would replace
   * them with '?', so two different strings would hash, sign or encrypt to the same bytes.
   */
  public static byte[] utf8Bytes(String text) {
    if (text == null) {
      throw new IllegalArgumentException("Text is null");
    }
    for (int i = 0, n = text.length(); i < n; i++) {
      char c = text.charAt(i);
      if (Character.isSurrogate(c)) {
        boolean paired =
            Character.isHighSurrogate(c)
                && i + 1 < n
                && Character.isLowSurrogate(text.charAt(i + 1));
        if (!paired) {
          throw new IllegalArgumentException("Text is not valid Unicode");
        }
        i++;
      }
    }
    return text.getBytes(StandardCharsets.UTF_8);
  }

  private static void checkRange(byte[] buf, int off, int length) {
    if (buf == null || off < 0 || length < 0 || length > buf.length - off) {
      throw new IllegalArgumentException("Invalid array range");
    }
  }
}
