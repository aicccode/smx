package site.aicc.sm3;

import java.nio.charset.StandardCharsets;

/**
 * SM3 cryptographic hash algorithm (GB/T 32905).
 *
 * <p>Whole blocks are compressed straight from the caller's array, and one schedule array serves
 * every block, so hashing allocates only per instance and per result.
 */
public class SM3 {
  private static final int[] IV = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
  };

  /** Round constants rotated by the round number, as the standard's T_j <<< j. */
  private static final int[] ROUND_CONSTANTS = new int[64];

  private static final char[] HEX = "0123456789ABCDEF".toCharArray();

  static {
    for (int j = 0; j < 16; j++) {
      ROUND_CONSTANTS[j] = Integer.rotateLeft(0x79CC4519, j);
    }
    for (int j = 16; j < 64; j++) {
      ROUND_CONSTANTS[j] = Integer.rotateLeft(0x7A879D8A, j);
    }
  }

  private final int[] state = IV.clone();
  private final int[] schedule = new int[68];
  private final byte[] blockBuffer = new byte[64];
  private int bufferOffset;

  /**
   * Message length in bits, deliberately 32 bits wide: the padding has always encoded the length
   * modulo 2^32, so inputs of 512 MiB or more hash differently from the standard. Widening it would
   * change those digests, so it is kept and reported.
   */
  private int bitLength;

  private int[] digestWords;
  private String hexResult;
  private byte[] hashBytes;

  /** Absorbs one byte. */
  public SM3 update(byte data) {
    blockBuffer[bufferOffset++] = data;
    bitLength += 8;
    if (bufferOffset == 64) {
      compress(blockBuffer, 0, 1);
      bufferOffset = 0;
    }
    return this;
  }

  /** Absorbs the UTF-8 encoding of a string. */
  public SM3 update(String data) {
    byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
    return this.update(bytes, 0, bytes.length);
  }

  /** Absorbs {@code length} bytes from {@code data}; a non-positive length is a no-op. */
  public SM3 update(byte[] data, int inOffset, int length) {
    if (length <= 0) {
      return this;
    }
    if (inOffset < 0 || length > data.length - inOffset) {
      throw new ArrayIndexOutOfBoundsException(
          "offset " + inOffset + ", length " + length + ", array " + data.length);
    }
    bitLength += length << 3;
    int offset = inOffset;
    int remaining = length;
    if (bufferOffset > 0) {
      int take = Math.min(64 - bufferOffset, remaining);
      System.arraycopy(data, offset, blockBuffer, bufferOffset, take);
      bufferOffset += take;
      offset += take;
      remaining -= take;
      if (bufferOffset < 64) {
        return this;
      }
      compress(blockBuffer, 0, 1);
      bufferOffset = 0;
    }
    int blocks = remaining >>> 6;
    if (blocks > 0) {
      compress(data, offset, blocks);
      offset += blocks << 6;
      remaining -= blocks << 6;
    }
    if (remaining > 0) {
      System.arraycopy(data, offset, blockBuffer, 0, remaining);
      bufferOffset = remaining;
    }
    return this;
  }

  /** The upper-case hex digest of the last {@link #finish()}, or null before the first one. */
  public String getHashCode() {
    if (hexResult == null && digestWords != null) {
      char[] chars = new char[64];
      for (int i = 0; i < 8; i++) {
        int word = digestWords[i];
        for (int j = 7; j >= 0; j--) {
          chars[i * 8 + j] = HEX[word & 0xF];
          word >>>= 4;
        }
      }
      hexResult = new String(chars);
    }
    return hexResult;
  }

  /** The digest of the last {@link #finish()}, or null before the first one. */
  public byte[] getHashBytes() {
    return this.hashBytes;
  }

  /** Completes the hash, publishes the result and resets to the initial state. */
  public SM3 finish() {
    pad();
    byte[] bytes = new byte[32];
    writeState(bytes, 0);
    this.hashBytes = bytes;
    this.digestWords = state.clone();
    this.hexResult = null;
    reset();
    return this;
  }

  /**
   * Completes the hash, writes the 32-byte digest to {@code out} and resets to the initial state.
   * Allocation-free alternative to {@link #finish()}; results of earlier finishes stay published.
   */
  public void finishInto(byte[] out, int outOffset) {
    pad();
    writeState(out, outOffset);
    reset();
  }

  /** Makes this instance continue from the state of {@code other}, a cheap midstate restore. */
  public void copyFrom(SM3 other) {
    System.arraycopy(other.state, 0, state, 0, 8);
    System.arraycopy(other.blockBuffer, 0, blockBuffer, 0, other.bufferOffset);
    bufferOffset = other.bufferOffset;
    bitLength = other.bitLength;
  }

  private void pad() {
    byte[] buffer = blockBuffer;
    int offset = bufferOffset;
    buffer[offset++] = (byte) 0x80;
    if (offset > 56) {
      while (offset < 64) {
        buffer[offset++] = 0;
      }
      compress(buffer, 0, 1);
      offset = 0;
    }
    while (offset < 60) {
      buffer[offset++] = 0;
    }
    int bits = bitLength;
    buffer[60] = (byte) (bits >>> 24);
    buffer[61] = (byte) (bits >>> 16);
    buffer[62] = (byte) (bits >>> 8);
    buffer[63] = (byte) bits;
    compress(buffer, 0, 1);
  }

  private void writeState(byte[] out, int outOffset) {
    int o = outOffset;
    for (int i = 0; i < 8; i++) {
      int word = state[i];
      out[o] = (byte) (word >>> 24);
      out[o + 1] = (byte) (word >>> 16);
      out[o + 2] = (byte) (word >>> 8);
      out[o + 3] = (byte) word;
      o += 4;
    }
  }

  private void reset() {
    System.arraycopy(IV, 0, state, 0, 8);
    bufferOffset = 0;
    bitLength = 0;
  }

  private void compress(byte[] data, int offset, int blocks) {
    int[] w = schedule;
    int[] t = ROUND_CONSTANTS;
    int[] v = state;
    int v0 = v[0];
    int v1 = v[1];
    int v2 = v[2];
    int v3 = v[3];
    int v4 = v[4];
    int v5 = v[5];
    int v6 = v[6];
    int v7 = v[7];
    int off = offset;
    for (int block = 0; block < blocks; block++) {
      for (int j = 0; j < 16; j++) {
        w[j] =
            data[off] << 24
                | (data[off + 1] & 0xFF) << 16
                | (data[off + 2] & 0xFF) << 8
                | (data[off + 3] & 0xFF);
        off += 4;
      }
      for (int j = 16; j < 68; j++) {
        int x = w[j - 16] ^ w[j - 9] ^ Integer.rotateLeft(w[j - 3], 15);
        w[j] =
            x
                ^ Integer.rotateLeft(x, 15)
                ^ Integer.rotateLeft(x, 23)
                ^ Integer.rotateLeft(w[j - 13], 7)
                ^ w[j - 6];
      }
      int a = v0;
      int b = v1;
      int c = v2;
      int d = v3;
      int e = v4;
      int f = v5;
      int g = v6;
      int h = v7;
      int a12;
      int ss1;
      int tt;
      // Four rounds per iteration with the registers renamed instead of moved.
      for (int j = 0; j < 16; j += 4) {
        a12 = Integer.rotateLeft(a, 12);
        ss1 = Integer.rotateLeft(a12 + e + t[j], 7);
        d += (a ^ b ^ c) + (ss1 ^ a12) + (w[j] ^ w[j + 4]);
        tt = h + (e ^ f ^ g) + ss1 + w[j];
        b = Integer.rotateLeft(b, 9);
        f = Integer.rotateLeft(f, 19);
        h = tt ^ Integer.rotateLeft(tt, 9) ^ Integer.rotateLeft(tt, 17);

        a12 = Integer.rotateLeft(d, 12);
        ss1 = Integer.rotateLeft(a12 + h + t[j + 1], 7);
        c += (d ^ a ^ b) + (ss1 ^ a12) + (w[j + 1] ^ w[j + 5]);
        tt = g + (h ^ e ^ f) + ss1 + w[j + 1];
        a = Integer.rotateLeft(a, 9);
        e = Integer.rotateLeft(e, 19);
        g = tt ^ Integer.rotateLeft(tt, 9) ^ Integer.rotateLeft(tt, 17);

        a12 = Integer.rotateLeft(c, 12);
        ss1 = Integer.rotateLeft(a12 + g + t[j + 2], 7);
        b += (c ^ d ^ a) + (ss1 ^ a12) + (w[j + 2] ^ w[j + 6]);
        tt = f + (g ^ h ^ e) + ss1 + w[j + 2];
        d = Integer.rotateLeft(d, 9);
        h = Integer.rotateLeft(h, 19);
        f = tt ^ Integer.rotateLeft(tt, 9) ^ Integer.rotateLeft(tt, 17);

        a12 = Integer.rotateLeft(b, 12);
        ss1 = Integer.rotateLeft(a12 + f + t[j + 3], 7);
        a += (b ^ c ^ d) + (ss1 ^ a12) + (w[j + 3] ^ w[j + 7]);
        tt = e + (f ^ g ^ h) + ss1 + w[j + 3];
        c = Integer.rotateLeft(c, 9);
        g = Integer.rotateLeft(g, 19);
        e = tt ^ Integer.rotateLeft(tt, 9) ^ Integer.rotateLeft(tt, 17);
      }
      for (int j = 16; j < 64; j += 4) {
        a12 = Integer.rotateLeft(a, 12);
        ss1 = Integer.rotateLeft(a12 + e + t[j], 7);
        d += ((a & b) | (c & (a | b))) + (ss1 ^ a12) + (w[j] ^ w[j + 4]);
        tt = h + (((f ^ g) & e) ^ g) + ss1 + w[j];
        b = Integer.rotateLeft(b, 9);
        f = Integer.rotateLeft(f, 19);
        h = tt ^ Integer.rotateLeft(tt, 9) ^ Integer.rotateLeft(tt, 17);

        a12 = Integer.rotateLeft(d, 12);
        ss1 = Integer.rotateLeft(a12 + h + t[j + 1], 7);
        c += ((d & a) | (b & (d | a))) + (ss1 ^ a12) + (w[j + 1] ^ w[j + 5]);
        tt = g + (((e ^ f) & h) ^ f) + ss1 + w[j + 1];
        a = Integer.rotateLeft(a, 9);
        e = Integer.rotateLeft(e, 19);
        g = tt ^ Integer.rotateLeft(tt, 9) ^ Integer.rotateLeft(tt, 17);

        a12 = Integer.rotateLeft(c, 12);
        ss1 = Integer.rotateLeft(a12 + g + t[j + 2], 7);
        b += ((c & d) | (a & (c | d))) + (ss1 ^ a12) + (w[j + 2] ^ w[j + 6]);
        tt = f + (((h ^ e) & g) ^ e) + ss1 + w[j + 2];
        d = Integer.rotateLeft(d, 9);
        h = Integer.rotateLeft(h, 19);
        f = tt ^ Integer.rotateLeft(tt, 9) ^ Integer.rotateLeft(tt, 17);

        a12 = Integer.rotateLeft(b, 12);
        ss1 = Integer.rotateLeft(a12 + f + t[j + 3], 7);
        a += ((b & c) | (d & (b | c))) + (ss1 ^ a12) + (w[j + 3] ^ w[j + 7]);
        tt = e + (((g ^ h) & f) ^ h) + ss1 + w[j + 3];
        c = Integer.rotateLeft(c, 9);
        g = Integer.rotateLeft(g, 19);
        e = tt ^ Integer.rotateLeft(tt, 9) ^ Integer.rotateLeft(tt, 17);
      }
      v0 ^= a;
      v1 ^= b;
      v2 ^= c;
      v3 ^= d;
      v4 ^= e;
      v5 ^= f;
      v6 ^= g;
      v7 ^= h;
    }
    v[0] = v0;
    v[1] = v1;
    v[2] = v2;
    v[3] = v3;
    v[4] = v4;
    v[5] = v5;
    v[6] = v6;
    v[7] = v7;
  }
}
