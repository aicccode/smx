package site.aicc.sm4;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import site.aicc.sm3.SM3;

/**
 * SM4 block cipher in CBC mode with PKCS#7 padding (GB/T 32907).
 *
 * <p>The round function uses a single 1 KB lookup table that combines the S-box and the linear
 * transform L. Java offers no AES-NI/GFNI access, so there is no hardware path to prefer. Like the
 * plain S-box lookups it replaces, indexing a table with secret data is exposed to cache-timing
 * attacks by a co-located attacker; this is a limit of table-based software SM4.
 */
public class SM4 {
  private static final short[] SBOX = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
  };

  private static final int[] FK = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

  private static final int[] CK = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
  };

  /** S-box output passed through L: x ^ x<<<2 ^ x<<<10 ^ x<<<18 ^ x<<<24, for the top byte. */
  private static final int[] T = new int[256];

  private static final byte[] HEX_LOWER = "0123456789abcdef".getBytes(StandardCharsets.ISO_8859_1);
  private static final byte[] HEX_UPPER = "0123456789ABCDEF".getBytes(StandardCharsets.ISO_8859_1);

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

  static {
    for (int i = 0; i < 256; i++) {
      int b = SBOX[i] << 24;
      T[i] =
          b
              ^ Integer.rotateLeft(b, 2)
              ^ Integer.rotateLeft(b, 10)
              ^ Integer.rotateLeft(b, 18)
              ^ Integer.rotateLeft(b, 24);
    }
  }

  private final int[] roundKeys = new int[32];
  private final int[] decryptKeys = new int[32];
  private byte[] iv = new byte[16];

  /** Encrypts the UTF-8 encoding of the text; returns lower-case hex. */
  public String encrypt(String text) throws IOException {
    return processBlocks(text.getBytes(StandardCharsets.UTF_8), iv.clone(), true);
  }

  /** Decrypts hex and removes the padding; returns the text decoded as UTF-8. */
  public String decrypt(String text) throws IOException {
    return processBlocks(hex2Bytes(text), iv.clone(), false);
  }

  /** Sets key and IV, either as hex or as text. */
  public SM4 setKey(String key, String iv, boolean hex) {
    if (hex) {
      setKey(hex2Bytes(key), hex2Bytes(iv));
    } else {
      setKey(key, iv);
    }
    return this;
  }

  private void setKey(byte[] keyBytes, byte[] ivBytes) {
    this.initKey(keyBytes, ivBytes);
  }

  private void setKey(String keyString, String ivString) {
    SM3 sm3 = new SM3();
    byte[] key = keyString.getBytes(StandardCharsets.UTF_8);
    if (key.length != 16) {
      key = hashToBlock(sm3, key);
    }
    byte[] ivBytes = ivString.getBytes(StandardCharsets.UTF_8);
    if (ivBytes.length != 16) {
      ivBytes = hashToBlock(sm3, ivBytes);
    }
    this.initKey(key, ivBytes);
  }

  /** First 16 characters of the upper-case hex digest, as bytes; a format fixed by the baseline. */
  private static byte[] hashToBlock(SM3 sm3, byte[] data) {
    String digest = sm3.update(data, 0, data.length).finish().getHashCode();
    return digest.substring(0, 16).getBytes(StandardCharsets.ISO_8859_1);
  }

  private void initKey(byte[] key, byte[] ivBytes) {
    int[] masterKey = new int[4];
    for (int i = 0, offset = 0; i < key.length / 4; i++, offset += 4) {
      masterKey[i] = readInt(key, offset);
    }
    int k0 = masterKey[0] ^ FK[0];
    int k1 = masterKey[1] ^ FK[1];
    int k2 = masterKey[2] ^ FK[2];
    int k3 = masterKey[3] ^ FK[3];
    int[] rk = roundKeys;
    for (int i = 0; i < 32; i += 4) {
      k0 ^= keyRound(k1 ^ k2 ^ k3 ^ CK[i]);
      rk[i] = k0;
      k1 ^= keyRound(k2 ^ k3 ^ k0 ^ CK[i + 1]);
      rk[i + 1] = k1;
      k2 ^= keyRound(k3 ^ k0 ^ k1 ^ CK[i + 2]);
      rk[i + 2] = k2;
      k3 ^= keyRound(k0 ^ k1 ^ k2 ^ CK[i + 3]);
      rk[i + 3] = k3;
    }
    for (int i = 0; i < 32; i++) {
      decryptKeys[i] = rk[31 - i];
    }
    this.iv = Arrays.copyOf(ivBytes, 16);
  }

  private static int keyRound(int a) {
    int b =
        SBOX[a >>> 24] << 24
            | SBOX[(a >>> 16) & 0xFF] << 16
            | SBOX[(a >>> 8) & 0xFF] << 8
            | SBOX[a & 0xFF];
    return b ^ Integer.rotateLeft(b, 13) ^ Integer.rotateLeft(b, 23);
  }

  private static int readInt(byte[] b, int off) {
    return b[off] << 24
        | (b[off + 1] & 0xFF) << 16
        | (b[off + 2] & 0xFF) << 8
        | (b[off + 3] & 0xFF);
  }

  private static void writeInt(byte[] b, int off, int v) {
    b[off] = (byte) (v >>> 24);
    b[off + 1] = (byte) (v >>> 16);
    b[off + 2] = (byte) (v >>> 8);
    b[off + 3] = (byte) v;
  }

  private String processBlocks(byte[] input, byte[] cbcVector, boolean encrypt) {
    if (encrypt) {
      byte[] padded = applyPkcs7Padding(input);
      encryptCbc(padded, cbcVector);
      return bytes2Hex(padded, false);
    }
    int length = input.length & ~15;
    decryptCbc(input, length, cbcVector);
    int pad = input[length - 1];
    if (pad >= 0 && pad <= length) {
      return new String(input, 0, length - pad, StandardCharsets.UTF_8);
    }
    // An invalid padding byte has always been tolerated in this exact way.
    byte[] blocks = Arrays.copyOf(input, length);
    return new String(Arrays.copyOfRange(blocks, 0, length - pad), StandardCharsets.UTF_8);
  }

  private void encryptCbc(byte[] data, byte[] cbcVector) {
    int[] t = T;
    int[] rk = roundKeys;
    int c0 = readInt(cbcVector, 0);
    int c1 = readInt(cbcVector, 4);
    int c2 = readInt(cbcVector, 8);
    int c3 = readInt(cbcVector, 12);
    for (int off = 0; off < data.length; off += 16) {
      int x0 = readInt(data, off) ^ c0;
      int x1 = readInt(data, off + 4) ^ c1;
      int x2 = readInt(data, off + 8) ^ c2;
      int x3 = readInt(data, off + 12) ^ c3;
      for (int i = 0; i < 32; i += 4) {
        int a = x1 ^ x2 ^ x3 ^ rk[i];
        x0 ^=
            t[a >>> 24]
                ^ Integer.rotateLeft(t[(a >>> 16) & 0xFF], 24)
                ^ Integer.rotateLeft(t[(a >>> 8) & 0xFF], 16)
                ^ Integer.rotateLeft(t[a & 0xFF], 8);
        a = x2 ^ x3 ^ x0 ^ rk[i + 1];
        x1 ^=
            t[a >>> 24]
                ^ Integer.rotateLeft(t[(a >>> 16) & 0xFF], 24)
                ^ Integer.rotateLeft(t[(a >>> 8) & 0xFF], 16)
                ^ Integer.rotateLeft(t[a & 0xFF], 8);
        a = x3 ^ x0 ^ x1 ^ rk[i + 2];
        x2 ^=
            t[a >>> 24]
                ^ Integer.rotateLeft(t[(a >>> 16) & 0xFF], 24)
                ^ Integer.rotateLeft(t[(a >>> 8) & 0xFF], 16)
                ^ Integer.rotateLeft(t[a & 0xFF], 8);
        a = x0 ^ x1 ^ x2 ^ rk[i + 3];
        x3 ^=
            t[a >>> 24]
                ^ Integer.rotateLeft(t[(a >>> 16) & 0xFF], 24)
                ^ Integer.rotateLeft(t[(a >>> 8) & 0xFF], 16)
                ^ Integer.rotateLeft(t[a & 0xFF], 8);
      }
      c0 = x3;
      c1 = x2;
      c2 = x1;
      c3 = x0;
      writeInt(data, off, c0);
      writeInt(data, off + 4, c1);
      writeInt(data, off + 8, c2);
      writeInt(data, off + 12, c3);
    }
  }

  private void decryptCbc(byte[] data, int length, byte[] cbcVector) {
    int[] t = T;
    int[] rk = decryptKeys;
    int c0 = readInt(cbcVector, 0);
    int c1 = readInt(cbcVector, 4);
    int c2 = readInt(cbcVector, 8);
    int c3 = readInt(cbcVector, 12);
    for (int off = 0; off < length; off += 16) {
      int n0 = readInt(data, off);
      int n1 = readInt(data, off + 4);
      int n2 = readInt(data, off + 8);
      int n3 = readInt(data, off + 12);
      int x0 = n0;
      int x1 = n1;
      int x2 = n2;
      int x3 = n3;
      for (int i = 0; i < 32; i += 4) {
        int a = x1 ^ x2 ^ x3 ^ rk[i];
        x0 ^=
            t[a >>> 24]
                ^ Integer.rotateLeft(t[(a >>> 16) & 0xFF], 24)
                ^ Integer.rotateLeft(t[(a >>> 8) & 0xFF], 16)
                ^ Integer.rotateLeft(t[a & 0xFF], 8);
        a = x2 ^ x3 ^ x0 ^ rk[i + 1];
        x1 ^=
            t[a >>> 24]
                ^ Integer.rotateLeft(t[(a >>> 16) & 0xFF], 24)
                ^ Integer.rotateLeft(t[(a >>> 8) & 0xFF], 16)
                ^ Integer.rotateLeft(t[a & 0xFF], 8);
        a = x3 ^ x0 ^ x1 ^ rk[i + 2];
        x2 ^=
            t[a >>> 24]
                ^ Integer.rotateLeft(t[(a >>> 16) & 0xFF], 24)
                ^ Integer.rotateLeft(t[(a >>> 8) & 0xFF], 16)
                ^ Integer.rotateLeft(t[a & 0xFF], 8);
        a = x0 ^ x1 ^ x2 ^ rk[i + 3];
        x3 ^=
            t[a >>> 24]
                ^ Integer.rotateLeft(t[(a >>> 16) & 0xFF], 24)
                ^ Integer.rotateLeft(t[(a >>> 8) & 0xFF], 16)
                ^ Integer.rotateLeft(t[a & 0xFF], 8);
      }
      writeInt(data, off, x3 ^ c0);
      writeInt(data, off + 4, x2 ^ c1);
      writeInt(data, off + 8, x1 ^ c2);
      writeInt(data, off + 12, x0 ^ c3);
      c0 = n0;
      c1 = n1;
      c2 = n2;
      c3 = n3;
    }
  }

  private static byte[] applyPkcs7Padding(byte[] input) {
    int pad = 16 - input.length % 16;
    byte[] out = Arrays.copyOf(input, input.length + pad);
    Arrays.fill(out, input.length, out.length, (byte) pad);
    return out;
  }

  /** Encodes bytes as hex in the requested case. */
  public static String bytes2Hex(byte[] bytes, boolean upperCase) {
    byte[] alphabet = upperCase ? HEX_UPPER : HEX_LOWER;
    byte[] hexChars = new byte[bytes.length * 2];
    for (int j = 0, o = 0; j < bytes.length; j++, o += 2) {
      int v = bytes[j] & 0xFF;
      hexChars[o] = alphabet[v >>> 4];
      hexChars[o + 1] = alphabet[v & 0x0F];
    }
    return new String(hexChars, StandardCharsets.ISO_8859_1);
  }

  /** Decodes hex; an odd length fails on the unpaired last digit, as it always has. */
  private static byte[] hex2Bytes(String hex) {
    int length = hex.length();
    byte[] digits = HEX_DIGITS;
    byte[] b = new byte[length / 2];
    for (int i = 0, j = 0; i < length; i += 2, j++) {
      if (i + 1 == length) {
        throw new ArrayIndexOutOfBoundsException(length);
      }
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
}
