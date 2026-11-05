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
 * <p>The S-box is a Boolean circuit ({@link Sm4SBox}), so neither the cipher nor the key schedule
 * makes a secret-dependent table lookup. Java exposes no AES-NI, GFNI or SIMD to Java 8 code, so
 * this software path is the only one. Instances may be shared between threads: each operation sees
 * one complete key and IV.
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
   * Decrypts hex and removes the padding; returns the text decoded as UTF-8, where bytes that are
   * not valid UTF-8 become U+FFFD. Every malformed input and every padding failure raises the same
   * exception with the same message. This does not authenticate; see the class comment.
   *
   * @throws IllegalArgumentException when no key is set or the input is rejected
   */
  public String decrypt(String text) throws IOException {
    KeyState state = requireKey();
    byte[] input;
    try {
      input = ConvertUtil.hexToByte(text);
    } catch (IllegalArgumentException e) {
      throw decryptionFailure();
    }
    return processBlocks(state, input, state.iv.clone(), false);
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

  private static int keyRound(int a) {
    int b = Sm4SBox.apply(a);
    return b ^ Integer.rotateLeft(b, 13) ^ Integer.rotateLeft(b, 23);
  }

  /** The round function's T: the S-box followed by the linear transform L. */
  private static int roundT(int a) {
    int b = Sm4SBox.apply(a);
    return b
        ^ Integer.rotateLeft(b, 2)
        ^ Integer.rotateLeft(b, 10)
        ^ Integer.rotateLeft(b, 18)
        ^ Integer.rotateLeft(b, 24);
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
    if (input.length == 0 || input.length % BLOCK_BYTES != 0) {
      throw decryptionFailure();
    }
    try {
      decryptCbc(input, cbcVector, state.decryptKeys);
      int kept = validatedPlainLength(input);
      if (kept < 0) {
        throw decryptionFailure();
      }
      return new String(input, 0, kept, StandardCharsets.UTF_8);
    } finally {
      Arrays.fill(input, (byte) 0);
    }
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

  private static void decryptCbc(byte[] data, byte[] cbcVector, int[] rk) {
    int c0 = readInt(cbcVector, 0);
    int c1 = readInt(cbcVector, 4);
    int c2 = readInt(cbcVector, 8);
    int c3 = readInt(cbcVector, 12);
    for (int off = 0; off < data.length; off += BLOCK_BYTES) {
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
