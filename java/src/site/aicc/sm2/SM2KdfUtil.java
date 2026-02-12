package site.aicc.sm2;

import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;

/** Shared KDF (Key Derivation Function) utility for SM2 cipher and key exchange. */
class SM2KdfUtil {

    private SM2KdfUtil() {
    }

    static byte[] kdf(int keylen, AbstractECPoint point, byte[] za, byte[] zb) {
        byte[] result = new byte[keylen];
        int ct = 0x00000001;
        for (int i = 0; i < (keylen + 31) / 32; i++) {
            SM3 sm3 = new SM3();
            byte[] px = point.getXCoord().getEncoded();
            sm3.update(px, 0, px.length);
            byte[] py = point.getYCoord().getEncoded();
            sm3.update(py, 0, py.length);
            if (za != null) {
                sm3.update(za, 0, za.length);
            }
            if (zb != null) {
                sm3.update(zb, 0, zb.length);
            }
            byte[] ctBytes = new byte[4];
            ConvertUtil.intToBigEndian(ct, ctBytes, 0);
            sm3.update(ctBytes, 0, 4);
            sm3.finish();
            if (i == ((keylen + 31) / 32 - 1) && (keylen % 32) != 0) {
                System.arraycopy(sm3.getHashBytes(), 0, result, 32 * (ct - 1), keylen % 32);
            } else {
                System.arraycopy(sm3.getHashBytes(), 0, result, 32 * (ct - 1), 32);
            }
            ct++;
        }
        return result;
    }
}
