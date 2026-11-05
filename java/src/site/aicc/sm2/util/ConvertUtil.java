package site.aicc.sm2.util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Data type conversion utilities. */
public class ConvertUtil {

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
    // No early exit: this compares MACs and hash values.
    int diff = 0;
    for (int i = 0; i != a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  public static BigInteger toBigInteger(int len, int[] x) {
    byte[] bs = new byte[len << 2];
    for (int i = 0; i < len; ++i) {
      int x_i = x[i];
      if (x_i != 0) {
        intToBigEndian(x_i, bs, (len - 1 - i) << 2);
      }
    }
    return new BigInteger(1, bs);
  }

  public static byte[] bigIntegerTo32Bytes(BigInteger n) {
    byte[] tmpd;
    if (n == null) {
      return null;
    }
    byte[] nArray = n.toByteArray();
    if (nArray.length == 33) {
      tmpd = new byte[32];
      System.arraycopy(nArray, 1, tmpd, 0, 32);
    } else if (nArray.length == 32) {
      tmpd = nArray;
    } else {
      tmpd = new byte[32];
      System.arraycopy(nArray, 0, tmpd, 32 - nArray.length, nArray.length);
    }
    return tmpd;
  }

  public static byte[] asUnsignedByteArray(int length, BigInteger value) {
    byte[] bytes = value.toByteArray();
    if (bytes.length == length) {
      return bytes;
    }
    int start = bytes[0] == 0 ? 1 : 0;
    int count = bytes.length - start;
    if (count > length) {
      throw new IllegalArgumentException("Value cannot be represented in the given length");
    }
    byte[] tmp = new byte[length];
    System.arraycopy(bytes, start, tmp, tmp.length - count, count);
    return tmp;
  }

  public static BigInteger fromUnsignedByteArray(byte[] buf, int off, int length) {
    byte[] mag = buf;
    if (off != 0 || length != buf.length) {
      mag = new byte[length];
      System.arraycopy(buf, off, mag, 0, length);
    }
    return new BigInteger(1, mag);
  }

  public static String byteToHex(byte[] bytes) {
    return getHexString(bytes, false);
  }

  public static byte[] hexToByte(String hex) throws IllegalArgumentException {
    if (hex.length() % 2 != 0) {
      throw new IllegalArgumentException("Input is not a hex string");
    }
    int length = hex.length();
    byte[] digits = HEX_DIGITS;
    byte[] b = new byte[length / 2];
    for (int i = 0, j = 0; i < length; i += 2, j++) {
      char a = hex.charAt(i);
      char c = hex.charAt(i + 1);
      int hi = a < 128 ? digits[a] : -1;
      int lo = c < 128 ? digits[c] : -1;
      if ((hi | lo) < 0) {
        // Signs and non-ASCII digits keep Integer.parseInt semantics.
        b[j] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
      } else {
        b[j] = (byte) (hi << 4 | lo);
      }
    }
    return b;
  }

  public static int[] fromBigInteger(int bits, BigInteger x) {
    if (x.signum() < 0 || x.bitLength() > bits) {
      throw new IllegalArgumentException();
    }
    int len = (bits + 31) >> 5;
    int[] z = new int[len];
    int i = 0;
    while (x.signum() != 0) {
      z[i++] = x.intValue();
      x = x.shiftRight(32);
    }
    return z;
  }

  public static int getBit(int[] x, int bit) {
    if (bit == 0) {
      return x[0] & 1;
    }
    int w = bit >> 5;
    if (w < 0 || w >= x.length) {
      return 0;
    }
    int b = bit & 31;
    return (x[w] >>> b) & 1;
  }

  private static final byte[] HEX_UPPER = "0123456789ABCDEF".getBytes(StandardCharsets.ISO_8859_1);
  private static final byte[] HEX_LOWER = "0123456789abcdef".getBytes(StandardCharsets.ISO_8859_1);

  /** Value of each ASCII hex digit, -1 for everything else. */
  private static final byte[] HEX_DIGITS = new byte[128];

  static {
    Arrays.fill(HEX_DIGITS, (byte) -1);
    for (int i = 0; i < 10; i++) {
      HEX_DIGITS['0' + i] = (byte) i;
    }
    for (int i = 0; i < 6; i++) {
      HEX_DIGITS['a' + i] = (byte) (10 + i);
      HEX_DIGITS['A' + i] = (byte) (10 + i);
    }
  }

  public static String getHexString(byte[] bytes, boolean upperCase) {
    byte[] alphabet = upperCase ? HEX_UPPER : HEX_LOWER;
    byte[] hexChars = new byte[bytes.length * 2];
    for (int j = 0, o = 0; j < bytes.length; j++, o += 2) {
      int v = bytes[j] & 0xFF;
      hexChars[o] = alphabet[v >>> 4];
      hexChars[o + 1] = alphabet[v & 0x0F];
    }
    return new String(hexChars, StandardCharsets.ISO_8859_1);
  }

  public static void intToBigEndian(int n, byte[] bs, int off) {
    bs[off] = (byte) (n >>> 24);
    bs[++off] = (byte) (n >>> 16);
    bs[++off] = (byte) (n >>> 8);
    bs[++off] = (byte) (n);
  }
}
