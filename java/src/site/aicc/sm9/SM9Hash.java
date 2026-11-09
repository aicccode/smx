package site.aicc.sm9;

import java.math.BigInteger;
import java.util.Arrays;
import site.aicc.sm3.SM3;

/** The SM3-based functions of GB/T 38635: H1, H2, the KDF and the hash of concatenations. */
final class SM9Hash {
  private static final BigInteger N_MINUS_1 = Fn.N_BIG.subtract(BigInteger.ONE);

  /** Bytes of Ha: hlen = 8 * ceil(5 * 256 / 32) = 320 bits. */
  private static final int HA_BYTES = 40;

  private SM9Hash() {}

  /** H1(Z) = H(0x01, Z). */
  static int[] h1(byte[]... z) {
    return h((byte) 1, z);
  }

  /** H2(Z) = H(0x02, Z). */
  static int[] h2(byte[]... z) {
    return h((byte) 2, z);
  }

  /** (SM3(tag || Z || 1) || SM3(tag || Z || 2)[0..8)) mod (N - 1) + 1, a public value. */
  private static int[] h(byte tag, byte[][] z) {
    SM3 base = new SM3();
    base.update(tag);
    for (byte[] part : z) {
      base.update(part, 0, part.length);
    }
    byte[] block = new byte[64];
    SM3 sm3 = new SM3();
    for (int ct = 1; ct <= 2; ct++) {
      sm3.copyFrom(base);
      sm3.update(counter(ct), 0, 4);
      sm3.finishInto(block, 32 * (ct - 1));
    }
    BigInteger ha = new BigInteger(1, Arrays.copyOf(block, HA_BYTES));
    return Fn.fromBigInteger(ha.mod(N_MINUS_1).add(BigInteger.ONE));
  }

  private static byte[] counter(int ct) {
    return new byte[] {(byte) (ct >>> 24), (byte) (ct >>> 16), (byte) (ct >>> 8), (byte) ct};
  }

  /** KDF(Z, klen): SM3(Z || ct) for ct = 1, 2, ..., truncated to klen bytes. Z is hashed once. */
  static byte[] kdf(int klen, byte[]... z) {
    SM3 base = new SM3();
    for (byte[] part : z) {
      base.update(part, 0, part.length);
    }
    byte[] out = new byte[klen];
    byte[] block = new byte[32];
    SM3 sm3 = new SM3();
    int ct = 1;
    for (int off = 0; off < klen; off += 32, ct++) {
      sm3.copyFrom(base);
      sm3.update(counter(ct), 0, 4);
      sm3.finishInto(block, 0);
      System.arraycopy(block, 0, out, off, Math.min(32, klen - off));
    }
    Arrays.fill(block, (byte) 0);
    base.finishInto(block, 0);
    Arrays.fill(block, (byte) 0);
    return out;
  }

  /** SM3 of the concatenation of the parts. */
  static byte[] sm3(byte[]... parts) {
    SM3 sm3 = new SM3();
    for (byte[] part : parts) {
      sm3.update(part, 0, part.length);
    }
    byte[] out = new byte[32];
    sm3.finishInto(out, 0);
    return out;
  }

  /** Returns true when every byte of the range is zero, with no early exit. */
  static boolean isAllZero(byte[] data, int off, int len) {
    int x = 0;
    for (int i = 0; i < len; i++) {
      x |= data[off + i];
    }
    return x == 0;
  }
}
