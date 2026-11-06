package site.aicc.sm4;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import site.aicc.sm2.util.ConvertUtil;

/**
 * SM4 block cipher in CBC mode with PKCS#7 padding (GB/T 32907).
 *
 * <p><b>CBC alone gives no integrity.</b> Anyone can alter a ciphertext undetected, and if an
 * attacker can see whether decryption succeeds, that alone is a padding oracle which reveals
 * plaintext. Authenticate ciphertexts separately (encrypt-then-MAC) before calling {@link
 * #decrypt}.
 *
 * <p><b>The IV is fixed by {@link #setKey}</b> and is used for every message until the next call,
 * so equal messages give equal ciphertexts and messages with a common prefix reveal it. Call {@code
 * setKey} with a new random IV for each message under a key.
 *
 * <p><b>Not cache-timing resistant.</b> This is the high-performance variant: the cipher and the
 * key schedule use secret-indexed table lookups (four 256-entry T-tables that combine the S-box
 * with the linear transform, and the S-box table itself for the key schedule), as OpenSSL and
 * BouncyCastle do. An attacker who shares the CPU cache with this process can learn key material
 * from access timing. The {@code security} branch of this project has a constant-time SM4 whose
 * S-box is a Boolean circuit; use it when such attackers are in scope. Instances may be shared
 * between threads: each operation sees one complete key and IV.
 */
public class SM4 {
  private static final int KEY_BYTES = 16;
  private static final int BLOCK_BYTES = 16;

  /** Largest plaintext whose padded ciphertext still fits a hex String. */
  private static final int MAX_PLAINTEXT_BYTES = (Integer.MAX_VALUE - 64) / 2;

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

  /** The S-box table of GB/T 32907. Indexed by secret bytes: see the class comment. */
  static final byte[] SBOX = {
    (byte) 0xd6,
    (byte) 0x90,
    (byte) 0xe9,
    (byte) 0xfe,
    (byte) 0xcc,
    (byte) 0xe1,
    0x3d,
    (byte) 0xb7,
    0x16,
    (byte) 0xb6,
    0x14,
    (byte) 0xc2,
    0x28,
    (byte) 0xfb,
    0x2c,
    0x05,
    0x2b,
    0x67,
    (byte) 0x9a,
    0x76,
    0x2a,
    (byte) 0xbe,
    0x04,
    (byte) 0xc3,
    (byte) 0xaa,
    0x44,
    0x13,
    0x26,
    0x49,
    (byte) 0x86,
    0x06,
    (byte) 0x99,
    (byte) 0x9c,
    0x42,
    0x50,
    (byte) 0xf4,
    (byte) 0x91,
    (byte) 0xef,
    (byte) 0x98,
    0x7a,
    0x33,
    0x54,
    0x0b,
    0x43,
    (byte) 0xed,
    (byte) 0xcf,
    (byte) 0xac,
    0x62,
    (byte) 0xe4,
    (byte) 0xb3,
    0x1c,
    (byte) 0xa9,
    (byte) 0xc9,
    0x08,
    (byte) 0xe8,
    (byte) 0x95,
    (byte) 0x80,
    (byte) 0xdf,
    (byte) 0x94,
    (byte) 0xfa,
    0x75,
    (byte) 0x8f,
    0x3f,
    (byte) 0xa6,
    0x47,
    0x07,
    (byte) 0xa7,
    (byte) 0xfc,
    (byte) 0xf3,
    0x73,
    0x17,
    (byte) 0xba,
    (byte) 0x83,
    0x59,
    0x3c,
    0x19,
    (byte) 0xe6,
    (byte) 0x85,
    0x4f,
    (byte) 0xa8,
    0x68,
    0x6b,
    (byte) 0x81,
    (byte) 0xb2,
    0x71,
    0x64,
    (byte) 0xda,
    (byte) 0x8b,
    (byte) 0xf8,
    (byte) 0xeb,
    0x0f,
    0x4b,
    0x70,
    0x56,
    (byte) 0x9d,
    0x35,
    0x1e,
    0x24,
    0x0e,
    0x5e,
    0x63,
    0x58,
    (byte) 0xd1,
    (byte) 0xa2,
    0x25,
    0x22,
    0x7c,
    0x3b,
    0x01,
    0x21,
    0x78,
    (byte) 0x87,
    (byte) 0xd4,
    0x00,
    0x46,
    0x57,
    (byte) 0x9f,
    (byte) 0xd3,
    0x27,
    0x52,
    0x4c,
    0x36,
    0x02,
    (byte) 0xe7,
    (byte) 0xa0,
    (byte) 0xc4,
    (byte) 0xc8,
    (byte) 0x9e,
    (byte) 0xea,
    (byte) 0xbf,
    (byte) 0x8a,
    (byte) 0xd2,
    0x40,
    (byte) 0xc7,
    0x38,
    (byte) 0xb5,
    (byte) 0xa3,
    (byte) 0xf7,
    (byte) 0xf2,
    (byte) 0xce,
    (byte) 0xf9,
    0x61,
    0x15,
    (byte) 0xa1,
    (byte) 0xe0,
    (byte) 0xae,
    0x5d,
    (byte) 0xa4,
    (byte) 0x9b,
    0x34,
    0x1a,
    0x55,
    (byte) 0xad,
    (byte) 0x93,
    0x32,
    0x30,
    (byte) 0xf5,
    (byte) 0x8c,
    (byte) 0xb1,
    (byte) 0xe3,
    0x1d,
    (byte) 0xf6,
    (byte) 0xe2,
    0x2e,
    (byte) 0x82,
    0x66,
    (byte) 0xca,
    0x60,
    (byte) 0xc0,
    0x29,
    0x23,
    (byte) 0xab,
    0x0d,
    0x53,
    0x4e,
    0x6f,
    (byte) 0xd5,
    (byte) 0xdb,
    0x37,
    0x45,
    (byte) 0xde,
    (byte) 0xfd,
    (byte) 0x8e,
    0x2f,
    0x03,
    (byte) 0xff,
    0x6a,
    0x72,
    0x6d,
    0x6c,
    0x5b,
    0x51,
    (byte) 0x8d,
    0x1b,
    (byte) 0xaf,
    (byte) 0x92,
    (byte) 0xbb,
    (byte) 0xdd,
    (byte) 0xbc,
    0x7f,
    0x11,
    (byte) 0xd9,
    0x5c,
    0x41,
    0x1f,
    0x10,
    0x5a,
    (byte) 0xd8,
    0x0a,
    (byte) 0xc1,
    0x31,
    (byte) 0x88,
    (byte) 0xa5,
    (byte) 0xcd,
    0x7b,
    (byte) 0xbd,
    0x2d,
    0x74,
    (byte) 0xd0,
    0x12,
    (byte) 0xb8,
    (byte) 0xe5,
    (byte) 0xb4,
    (byte) 0xb0,
    (byte) 0x89,
    0x69,
    (byte) 0x97,
    0x4a,
    0x0c,
    (byte) 0x96,
    0x77,
    0x7e,
    0x65,
    (byte) 0xb9,
    (byte) 0xf1,
    0x09,
    (byte) 0xc5,
    0x6e,
    (byte) 0xc6,
    (byte) 0x84,
    0x18,
    (byte) 0xf0,
    0x7d,
    (byte) 0xec,
    0x3a,
    (byte) 0xdc,
    0x4d,
    0x20,
    0x79,
    (byte) 0xee,
    0x5f,
    0x3e,
    (byte) 0xd7,
    (byte) 0xcb,
    0x39,
    0x48,
  };

  /**
   * T-tables: {@code T0[x] = L(S(x) << 24)}, and T1, T2, T3 are T0 rotated right by 8, 16 and 24
   * bits, so the round function's T(a) is four lookups and three XORs.
   */
  static final int[] T0 = new int[256];

  static final int[] T1 = new int[256];
  static final int[] T2 = new int[256];
  static final int[] T3 = new int[256];

  static {
    for (int x = 0; x < 256; x++) {
      int b = (SBOX[x] & 0xFF) << 24;
      int t =
          b
              ^ Integer.rotateLeft(b, 2)
              ^ Integer.rotateLeft(b, 10)
              ^ Integer.rotateLeft(b, 18)
              ^ Integer.rotateLeft(b, 24);
      T0[x] = t;
      T1[x] = Integer.rotateRight(t, 8);
      T2[x] = Integer.rotateRight(t, 16);
      T3[x] = Integer.rotateRight(t, 24);
    }
  }

  /** An immutable key and IV, replaced as a unit so concurrent users never see a mixture. */
  private static final class KeyState {
    final int[] encryptKeys;
    final int[] decryptKeys;
    final byte[] iv;

    KeyState(int[] encryptKeys, int[] decryptKeys, byte[] iv) {
      this.encryptKeys = encryptKeys;
      this.decryptKeys = decryptKeys;
      this.iv = iv;
    }
  }

  private volatile KeyState keyState;

  /**
   * Receives each decode's result. A volatile write cannot be optimized away, so the JIT must keep
   * the decoding work on the failure path, where the decoded text itself goes unused.
   */
  private static volatile int decodedLengthSink;

  private KeyState requireKey() {
    KeyState state = keyState;
    if (state == null) {
      throw new IllegalArgumentException("SM4 key is not set");
    }
    return state;
  }

  /**
   * Encrypts the UTF-8 encoding of the text; returns lower-case hex.
   *
   * @throws IllegalArgumentException when no key is set, or the text is null, too long or not valid
   *     Unicode
   */
  public String encrypt(String text) throws IOException {
    byte[] plain = ConvertUtil.utf8Bytes(text);
    try {
      KeyState state = requireKey();
      return processBlocks(state, plain, state.iv.clone(), true);
    } finally {
      Arrays.fill(plain, (byte) 0);
    }
  }

  /**
   * Decrypts lower-case hex and removes the padding; returns the text decoded as UTF-8, where bytes
   * that are not valid UTF-8 become U+FFFD. Every malformed input and every padding failure raises
   * the same exception with the same message. This does not authenticate; see the class comment.
   *
   * <p>The whole decrypted buffer is decoded whether or not the padding is valid, so that decoding
   * time does not reveal the padding check. Decoding time still varies with the plaintext's
   * content; {@link #decryptToBytes} has no decoding step.
   *
   * @throws IllegalArgumentException when no key is set or the input is rejected
   */
  public String decrypt(String text) throws IOException {
    KeyState state = requireKey();
    return processBlocks(state, decodeCiphertext(text), state.iv.clone(), false);
  }

  /**
   * Decrypts lower-case hex and removes the padding, returning the plaintext bytes with no text
   * decoding: for binary data, and for callers avoiding UTF-8 timing. Failures are as for {@link
   * #decrypt}, and this does not authenticate either.
   *
   * @throws IllegalArgumentException when no key is set or the input is rejected
   */
  public byte[] decryptToBytes(String text) {
    KeyState state = requireKey();
    byte[] input = decodeCiphertext(text);
    try {
      int kept = decryptAndCheck(state, input, state.iv.clone());
      if (kept < 0) {
        throw decryptionFailure();
      }
      return Arrays.copyOf(input, kept);
    } finally {
      Arrays.fill(input, (byte) 0);
    }
  }

  private static byte[] decodeCiphertext(String text) {
    try {
      return ConvertUtil.canonicalHexToByte(text);
    } catch (IllegalArgumentException e) {
      throw decryptionFailure();
    }
  }

  /**
   * Sets the key and IV: 32 hex digits each when {@code hex} is true, otherwise strings whose UTF-8
   * encoding is exactly 16 bytes. Anything else raises {@link IllegalArgumentException} and keeps
   * the previous key; other sizes are never hashed, truncated or padded into a key.
   */
  public SM4 setKey(String key, String iv, boolean hex) {
    if (key == null || iv == null) {
      throw new IllegalArgumentException("SM4 key and IV must be 16 bytes");
    }
    byte[] keyBytes = hex ? ConvertUtil.hexToByte(key) : ConvertUtil.utf8Bytes(key);
    try {
      byte[] ivBytes = hex ? ConvertUtil.hexToByte(iv) : ConvertUtil.utf8Bytes(iv);
      if (keyBytes.length != KEY_BYTES || ivBytes.length != BLOCK_BYTES) {
        throw new IllegalArgumentException("SM4 key and IV must be 16 bytes");
      }
      this.keyState = expandKey(keyBytes, ivBytes);
    } finally {
      Arrays.fill(keyBytes, (byte) 0);
    }
    return this;
  }

  private static KeyState expandKey(byte[] key, byte[] iv) {
    int k0 = readInt(key, 0) ^ FK[0];
    int k1 = readInt(key, 4) ^ FK[1];
    int k2 = readInt(key, 8) ^ FK[2];
    int k3 = readInt(key, 12) ^ FK[3];
    int[] rk = new int[32];
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
    int[] reversed = new int[32];
    for (int i = 0; i < 32; i++) {
      reversed[i] = rk[31 - i];
    }
    return new KeyState(rk, reversed, iv.clone());
  }

  /** The key schedule's T': the S-box (by table) followed by L'. */
  private static int keyRound(int a) {
    int b =
        (SBOX[a >>> 24] & 0xFF) << 24
            | (SBOX[(a >>> 16) & 0xFF] & 0xFF) << 16
            | (SBOX[(a >>> 8) & 0xFF] & 0xFF) << 8
            | (SBOX[a & 0xFF] & 0xFF);
    return b ^ Integer.rotateLeft(b, 13) ^ Integer.rotateLeft(b, 23);
  }

  /** The round function's T: the S-box followed by L, by T-table lookups. */
  private static int roundT(int a) {
    return T0[a >>> 24] ^ T1[(a >>> 16) & 0xFF] ^ T2[(a >>> 8) & 0xFF] ^ T3[a & 0xFF];
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
    return processBlocks(requireKey(), input, cbcVector, encrypt);
  }

  /** Takes the state as an argument so that one operation can only ever see one key and IV. */
  private static String processBlocks(
      KeyState state, byte[] input, byte[] cbcVector, boolean encrypt) {
    if (encrypt) {
      byte[] padded = applyPkcs7Padding(input);
      encryptCbc(padded, cbcVector, state.encryptKeys);
      return ConvertUtil.getHexString(padded, false);
    }
    try {
      int kept = decryptAndCheck(state, input, cbcVector);
      // Same bytes through the same decoder on both outcomes, before the outcome is acted on. The
      // padding bytes decode to one char each, so the text is a prefix of the decoded buffer.
      String decoded = new String(input, 0, input.length, StandardCharsets.UTF_8);
      decodedLengthSink = decoded.length();
      if (kept < 0) {
        throw decryptionFailure();
      }
      return decoded.substring(0, decoded.length() - (input.length - kept));
    } finally {
      Arrays.fill(input, (byte) 0);
    }
  }

  /** Decrypts in place and returns the plaintext length, or -1 for bad length or padding. */
  private static int decryptAndCheck(KeyState state, byte[] input, byte[] cbcVector) {
    if (input.length == 0 || input.length % BLOCK_BYTES != 0) {
      throw decryptionFailure();
    }
    decryptCbc(input, cbcVector, state.decryptKeys);
    return validatedPlainLength(input);
  }

  /**
   * Checks PKCS#7 padding over the whole last block with no early exit. Returns the plaintext
   * length or -1, with the same operations for every padding value.
   */
  private static int validatedPlainLength(byte[] data) {
    int length = data.length;
    int pad = data[length - 1] & 0xFF;
    int bad = ((pad - 1) | (BLOCK_BYTES - pad)) >> 31;
    int diff = 0;
    for (int i = 1; i <= BLOCK_BYTES; i++) {
      int inPadding = (i - pad - 1) >> 31;
      diff |= ((data[length - i] & 0xFF) ^ pad) & inPadding;
    }
    bad |= (diff | -diff) >> 31;
    return ((length - pad) & ~bad) | bad;
  }

  /** The one error for every kind of rejected ciphertext. */
  private static IllegalArgumentException decryptionFailure() {
    return new IllegalArgumentException("SM4 decryption failed");
  }

  private static void encryptCbc(byte[] data, byte[] cbcVector, int[] rk) {
    int c0 = readInt(cbcVector, 0);
    int c1 = readInt(cbcVector, 4);
    int c2 = readInt(cbcVector, 8);
    int c3 = readInt(cbcVector, 12);
    for (int off = 0; off < data.length; off += BLOCK_BYTES) {
      int x0 = readInt(data, off) ^ c0;
      int x1 = readInt(data, off + 4) ^ c1;
      int x2 = readInt(data, off + 8) ^ c2;
      int x3 = readInt(data, off + 12) ^ c3;
      for (int i = 0; i < 32; i += 4) {
        x0 ^= roundT(x1 ^ x2 ^ x3 ^ rk[i]);
        x1 ^= roundT(x2 ^ x3 ^ x0 ^ rk[i + 1]);
        x2 ^= roundT(x3 ^ x0 ^ x1 ^ rk[i + 2]);
        x3 ^= roundT(x0 ^ x1 ^ x2 ^ rk[i + 3]);
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

  /**
   * CBC decryption has no chain between blocks, so four blocks go through the rounds together:
   * their table lookups overlap, which roughly doubles throughput over one block at a time.
   */
  private static void decryptCbc(byte[] data, byte[] cbcVector, int[] rk) {
    int c0 = readInt(cbcVector, 0);
    int c1 = readInt(cbcVector, 4);
    int c2 = readInt(cbcVector, 8);
    int c3 = readInt(cbcVector, 12);
    int off = 0;
    for (; off + 4 * BLOCK_BYTES <= data.length; off += 4 * BLOCK_BYTES) {
      int a0 = readInt(data, off);
      int a1 = readInt(data, off + 4);
      int a2 = readInt(data, off + 8);
      int a3 = readInt(data, off + 12);
      int b0 = readInt(data, off + 16);
      int b1 = readInt(data, off + 20);
      int b2 = readInt(data, off + 24);
      int b3 = readInt(data, off + 28);
      int e0 = readInt(data, off + 32);
      int e1 = readInt(data, off + 36);
      int e2 = readInt(data, off + 40);
      int e3 = readInt(data, off + 44);
      int f0 = readInt(data, off + 48);
      int f1 = readInt(data, off + 52);
      int f2 = readInt(data, off + 56);
      int f3 = readInt(data, off + 60);
      int w0 = a0;
      int w1 = a1;
      int w2 = a2;
      int w3 = a3;
      int x0 = b0;
      int x1 = b1;
      int x2 = b2;
      int x3 = b3;
      int y0 = e0;
      int y1 = e1;
      int y2 = e2;
      int y3 = e3;
      int z0 = f0;
      int z1 = f1;
      int z2 = f2;
      int z3 = f3;
      for (int i = 0; i < 32; i += 4) {
        int k = rk[i];
        w0 ^= roundT(w1 ^ w2 ^ w3 ^ k);
        x0 ^= roundT(x1 ^ x2 ^ x3 ^ k);
        y0 ^= roundT(y1 ^ y2 ^ y3 ^ k);
        z0 ^= roundT(z1 ^ z2 ^ z3 ^ k);
        k = rk[i + 1];
        w1 ^= roundT(w2 ^ w3 ^ w0 ^ k);
        x1 ^= roundT(x2 ^ x3 ^ x0 ^ k);
        y1 ^= roundT(y2 ^ y3 ^ y0 ^ k);
        z1 ^= roundT(z2 ^ z3 ^ z0 ^ k);
        k = rk[i + 2];
        w2 ^= roundT(w3 ^ w0 ^ w1 ^ k);
        x2 ^= roundT(x3 ^ x0 ^ x1 ^ k);
        y2 ^= roundT(y3 ^ y0 ^ y1 ^ k);
        z2 ^= roundT(z3 ^ z0 ^ z1 ^ k);
        k = rk[i + 3];
        w3 ^= roundT(w0 ^ w1 ^ w2 ^ k);
        x3 ^= roundT(x0 ^ x1 ^ x2 ^ k);
        y3 ^= roundT(y0 ^ y1 ^ y2 ^ k);
        z3 ^= roundT(z0 ^ z1 ^ z2 ^ k);
      }
      writeInt(data, off, w3 ^ c0);
      writeInt(data, off + 4, w2 ^ c1);
      writeInt(data, off + 8, w1 ^ c2);
      writeInt(data, off + 12, w0 ^ c3);
      writeInt(data, off + 16, x3 ^ a0);
      writeInt(data, off + 20, x2 ^ a1);
      writeInt(data, off + 24, x1 ^ a2);
      writeInt(data, off + 28, x0 ^ a3);
      writeInt(data, off + 32, y3 ^ b0);
      writeInt(data, off + 36, y2 ^ b1);
      writeInt(data, off + 40, y1 ^ b2);
      writeInt(data, off + 44, y0 ^ b3);
      writeInt(data, off + 48, z3 ^ e0);
      writeInt(data, off + 52, z2 ^ e1);
      writeInt(data, off + 56, z1 ^ e2);
      writeInt(data, off + 60, z0 ^ e3);
      c0 = f0;
      c1 = f1;
      c2 = f2;
      c3 = f3;
    }
    for (; off < data.length; off += BLOCK_BYTES) {
      int n0 = readInt(data, off);
      int n1 = readInt(data, off + 4);
      int n2 = readInt(data, off + 8);
      int n3 = readInt(data, off + 12);
      int x0 = n0;
      int x1 = n1;
      int x2 = n2;
      int x3 = n3;
      for (int i = 0; i < 32; i += 4) {
        x0 ^= roundT(x1 ^ x2 ^ x3 ^ rk[i]);
        x1 ^= roundT(x2 ^ x3 ^ x0 ^ rk[i + 1]);
        x2 ^= roundT(x3 ^ x0 ^ x1 ^ rk[i + 2]);
        x3 ^= roundT(x0 ^ x1 ^ x2 ^ rk[i + 3]);
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
    if (input.length > MAX_PLAINTEXT_BYTES) {
      throw new IllegalArgumentException("Input too long for SM4");
    }
    int pad = BLOCK_BYTES - input.length % BLOCK_BYTES;
    byte[] out = Arrays.copyOf(input, input.length + pad);
    Arrays.fill(out, input.length, out.length, (byte) pad);
    return out;
  }

  /** Encodes bytes as hex in the requested case. */
  public static String bytes2Hex(byte[] bytes, boolean upperCase) {
    return ConvertUtil.getHexString(bytes, upperCase);
  }
}
