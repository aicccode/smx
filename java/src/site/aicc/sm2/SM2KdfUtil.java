package site.aicc.sm2;

import java.util.Arrays;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;

/** Shared KDF (Key Derivation Function) utility for SM2 cipher and key exchange. */
final class SM2KdfUtil {
  private static final int HASH_BYTES = 32;

  /** True when every byte in the range is zero; visits them all. */
  static boolean isAllZero(byte[] data, int offset, int length) {
    int any = 0;
    for (int i = 0; i < length; i++) {
      any |= data[offset + i];
    }
    return any == 0;
  }

  private SM2KdfUtil() {}

  /**
   * Derives keylen bytes as SM3(x || y || za || zb || counter) for counter = 1, 2, ... The common
   * prefix is hashed once; each counter value then only continues from that saved state.
   */
  static byte[] kdf(int keylen, AbstractECPoint point, byte[] za, byte[] zb) {
    if (keylen < 0 || point == null || point.isInfinity()) {
      throw new IllegalArgumentException("Invalid KDF input");
    }
    byte[] result = new byte[keylen];
    if (keylen == 0) {
      return result;
    }
    // An int length is far below the standard's limit of (2^32 - 1) * 32 bytes; computed in long so
    // that lengths near Integer.MAX_VALUE cannot wrap.
    int blocks = (int) ((keylen + (long) HASH_BYTES - 1) / HASH_BYTES);
    SM3 prefix = new SM3();
    byte[] px = point.getXCoord().getEncoded();
    prefix.update(px, 0, px.length);
    byte[] py = point.getYCoord().getEncoded();
    prefix.update(py, 0, py.length);
    if (za != null) {
      prefix.update(za, 0, za.length);
    }
    if (zb != null) {
      prefix.update(zb, 0, zb.length);
    }
    SM3 sm3 = new SM3();
    byte[] ctBytes = new byte[4];
    int offset = 0;
    for (int ct = 1; ct < blocks; ct++, offset += HASH_BYTES) {
      sm3.copyFrom(prefix);
      ConvertUtil.intToBigEndian(ct, ctBytes, 0);
      sm3.update(ctBytes, 0, 4);
      sm3.finishInto(result, offset);
    }
    // The last block may be partial.
    sm3.copyFrom(prefix);
    ConvertUtil.intToBigEndian(blocks, ctBytes, 0);
    sm3.update(ctBytes, 0, 4);
    byte[] last = new byte[HASH_BYTES];
    sm3.finishInto(last, 0);
    System.arraycopy(last, 0, result, offset, keylen - offset);
    Arrays.fill(last, (byte) 0);
    Arrays.fill(px, (byte) 0);
    Arrays.fill(py, (byte) 0);
    prefix.finishInto(last, 0);
    Arrays.fill(last, (byte) 0);
    return result;
  }
}
