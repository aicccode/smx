package site.aicc.sm2.util;

import java.math.BigInteger;

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
        for (int i = 0; i != a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }
        return true;
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
        byte[] tmpd = null;
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
            for (int i = 0; i < 32 - nArray.length; i++) {
                tmpd[i] = 0;
            }
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
        char[] arr = hex.toCharArray();
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0, j = 0, l = hex.length(); i < l; i++, j++) {
            String swap = "" + arr[i++] + arr[i];
            int byteint = Integer.parseInt(swap, 16) & 0xFF;
            b[j] = (byte) byteint;
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

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String getHexString(byte[] bytes, boolean upperCase) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return upperCase ? new String(hexChars).toUpperCase() : new String(hexChars).toLowerCase();
    }

    public static void intToBigEndian(int n, byte[] bs, int off) {
        bs[off] = (byte) (n >>> 24);
        bs[++off] = (byte) (n >>> 16);
        bs[++off] = (byte) (n >>> 8);
        bs[++off] = (byte) (n);
    }

}
