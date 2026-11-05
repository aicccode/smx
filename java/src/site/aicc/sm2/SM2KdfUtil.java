package site.aicc.sm2;

import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;

/** Shared KDF (Key Derivation Function) utility for SM2 cipher and key exchange. */
final class SM2KdfUtil {
  private static final int HASH_BYTES = 32;

  private SM2KdfUtil() {}

  /**
   * Derives keylen bytes as SM3(x || y || za || zb || counter) for counter = 1, 2, ... The common
   * prefix is hashed once; each counter value then only continues from that saved state.
   */
  static byte[] kdf(int keylen, AbstractECPoint point, byte[] za, byte[] zb) {
    byte[] result = new byte[keylen];
    int blocks = (keylen + HASH_BYTES - 1) / HASH_BYTES;
    if (blocks <= 0) {
      return result;
    }
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
    return result;
  }
}
