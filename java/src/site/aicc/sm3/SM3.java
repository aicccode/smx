package site.aicc.sm3;

import java.util.Arrays;
import site.aicc.sm2.util.ConvertUtil;

/**
 * SM3 cryptographic hash algorithm (GB/T 32905). An instance is stateful and not thread-safe.
 *
 * <p>Whole blocks are compressed straight from the caller's array, and one schedule array serves
 * every block, so hashing allocates only per instance and per result. The input buffer and message
 * schedule are cleared whenever a hash completes, because SM2 hashes shared secrets.
 */
public class SM3 {
  /** Longest message: the length field holds 2^64 - 1 bits, and this keeps it whole bytes. */
  private static final long MAX_MESSAGE_BYTES = (1L << 61) - 1;

  private static final int[] IV = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
  };

  /** Round constants rotated by the round number, as the standard's T_j <<< j. */
  private static final int[] ROUND_CONSTANTS = new int[64];

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

  /** Bytes absorbed so far. */
  private long messageBytes;

  private int[] digestWords;
  private String hexResult;
  private byte[] hashBytes;

  private void addLength(long length) {
    if (length > MAX_MESSAGE_BYTES - messageBytes) {
      throw new IllegalArgumentException("Message too long for SM3");
    }
    messageBytes += length;
    clearPublished();
  }

  /** New input makes the last result stale, so it can no longer be read. */
  private void clearPublished() {
    digestWords = null;
    hexResult = null;
    hashBytes = null;
  }

  private static IllegalStateException noDigest() {
    return new IllegalStateException("No completed SM3 hash");
  }

  /** Absorbs one byte. */
  public SM3 update(byte data) {
    addLength(1);
    blockBuffer[bufferOffset++] = data;
    if (bufferOffset == 64) {
      compress(blockBuffer, 0, 1);
      bufferOffset = 0;
    }
    return this;
  }

  /** Absorbs the UTF-8 encoding of a string; rejects null and unpaired surrogates. */
  public SM3 update(String data) {
    byte[] bytes = ConvertUtil.utf8Bytes(data);
    return this.update(bytes, 0, bytes.length);
  }

  /** Absorbs {@code length} bytes from {@code data}; an invalid range changes nothing. */
  public SM3 update(byte[] data, int inOffset, int length) {
    if (data == null || inOffset < 0 || length < 0 || length > data.length - inOffset) {
      throw new IllegalArgumentException("Invalid input range");
    }
    addLength(length);
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

  /**
   * The upper-case hex digest from {@link #finish()}.
   *
   * @throws IllegalStateException when no hash has finished, or input has been added since
   */
  public String getHashCode() {
    if (digestWords == null) {
      throw noDigest();
    }
    if (hexResult == null) {
      byte[] bytes = new byte[32];
      for (int i = 0; i < 8; i++) {
        ConvertUtil.intToBigEndian(digestWords[i], bytes, i * 4);
      }
      hexResult = ConvertUtil.getHexString(bytes, true);
    }
    return hexResult;
  }

  /**
   * The digest from {@link #finish()}.
   *
   * @throws IllegalStateException when no hash has finished, or input has been added since
   */
  public byte[] getHashBytes() {
    if (hashBytes == null) {
      throw noDigest();
    }
    return this.hashBytes;
  }

  /**
   * Completes the hash, publishes the result and resets to the initial state. The instance is then
   * a new hash: another finish with no input in between gives the digest of the empty message.
   */
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
   * Allocation-free alternative to {@link #finish()}, which publishes nothing and clears any
   * earlier result. A range that cannot hold the digest raises {@link IllegalArgumentException} and
   * keeps the state.
   */
  public void finishInto(byte[] out, int outOffset) {
    if (out == null || outOffset < 0 || outOffset > out.length - 32) {
      throw new IllegalArgumentException("Invalid output range");
    }
    pad();
    writeState(out, outOffset);
    clearPublished();
    reset();
  }

  /** Makes this instance continue from the state of {@code other}, a cheap midstate restore. */
  public void copyFrom(SM3 other) {
    if (other == null) {
      throw new IllegalArgumentException("Source is null");
    }
    if (other == this) {
      return;
    }
    System.arraycopy(other.state, 0, state, 0, 8);
    System.arraycopy(other.blockBuffer, 0, blockBuffer, 0, 64);
    bufferOffset = other.bufferOffset;
    messageBytes = other.messageBytes;
    clearPublished();
  }

  private void pad() {
    byte[] buffer = blockBuffer;
    int offset = bufferOffset;
    long bits = messageBytes << 3;
    buffer[offset++] = (byte) 0x80;
    if (offset > 56) {
      Arrays.fill(buffer, offset, 64, (byte) 0);
      compress(buffer, 0, 1);
      offset = 0;
    }
    Arrays.fill(buffer, offset, 56, (byte) 0);
    ConvertUtil.intToBigEndian((int) (bits >>> 32), buffer, 56);
    ConvertUtil.intToBigEndian((int) bits, buffer, 60);
    compress(buffer, 0, 1);
  }

  private void writeState(byte[] out, int outOffset) {
    for (int i = 0; i < 8; i++) {
      ConvertUtil.intToBigEndian(state[i], out, outOffset + i * 4);
    }
  }

  private void reset() {
    System.arraycopy(IV, 0, state, 0, 8);
    Arrays.fill(blockBuffer, (byte) 0);
    Arrays.fill(schedule, 0);
    bufferOffset = 0;
    messageBytes = 0;
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
