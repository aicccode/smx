package site.aicc.sm2;

import java.io.IOException;
import java.math.BigInteger;

import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.keygen.ECPrivateKey;
import site.aicc.sm2.keygen.ECPublicKey;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;

/** SM2 encryption/decryption and signature core. */
public class SM2Cipher {

    private static final int C1_HEX_LENGTH = 130;
    private static final int C3_HEX_LENGTH = 64;

    private AbstractECPoint p2;
    private SM3 sm3c3;

    protected static String encrypt(byte[] publicKey, byte[] data, SM2Initializer init) throws IOException {
        if (publicKey == null || publicKey.length == 0) {
            return null;
        }
        if (data == null || data.length == 0) {
            return null;
        }
        byte[] source = new byte[data.length];
        System.arraycopy(data, 0, source, 0, data.length);
        SM2Cipher cipher = new SM2Cipher();
        AbstractECPoint userPublicKey = init.decodePoint(publicKey);
        AbstractECPoint c1 = cipher.initEnc(init, userPublicKey);
        cipher.encryptData(source);
        byte[] c3 = new byte[32];
        cipher.doFinal(c3);
        return ConvertUtil.byteToHex(c1.getEncoded()) + ConvertUtil.byteToHex(c3) + ConvertUtil.byteToHex(source);
    }

    protected static byte[] decrypt(byte[] privateKey, byte[] encryptedData, SM2Initializer init) throws IOException {
        if (privateKey == null || privateKey.length == 0) {
            return null;
        }
        if (encryptedData == null || encryptedData.length == 0) {
            return null;
        }
        // C1(130)||C3(64)||C2
        String data = ConvertUtil.byteToHex(encryptedData);
        byte[] c1Bytes = ConvertUtil.hexToByte(data.substring(0, C1_HEX_LENGTH));
        byte[] c3 = ConvertUtil.hexToByte(data.substring(C1_HEX_LENGTH, C1_HEX_LENGTH + C3_HEX_LENGTH));
        byte[] c2 = ConvertUtil.hexToByte(data.substring(C1_HEX_LENGTH + C3_HEX_LENGTH, 2 * encryptedData.length));
        BigInteger userPrivateKey = new BigInteger(1, privateKey);
        AbstractECPoint c1 = init.decodePoint(c1Bytes);
        SM2Cipher cipher = new SM2Cipher();
        cipher.initDec(init, userPrivateKey, c1);
        cipher.decryptData(c2);
        byte[] v = new byte[32];
        cipher.doFinal(v);
        if (!ConvertUtil.byteArrayEqual(v, c3)) {
            throw new IllegalArgumentException("Decryption failed");
        }
        return c2;
    }

    protected static String sm2Sign(String userId, byte[] privatekey, byte[] sourceData, SM2Initializer init) throws Exception {
        BigInteger intPrivateKey = new BigInteger(privatekey);
        AbstractECPoint pA = init.getPublicKey(intPrivateKey);
        byte[] zA = init.userSM3Z(ConvertUtil.hexToByte(userId), pA);
        SM3 sm3 = new SM3();
        sm3.update(zA, 0, zA.length);
        sm3.update(sourceData, 0, sourceData.length);
        sm3.finish();
        BigInteger e = new BigInteger(1, sm3.getHashBytes());
        BigInteger k = null;
        AbstractECPoint kp = null;
        BigInteger r = null;
        BigInteger s = null;
        do {
            do {
                ECKeyPair keypair = init.genKeyPair();
                ECPrivateKey ecpriv = (ECPrivateKey) keypair.getPrivate();
                ECPublicKey ecpub = (ECPublicKey) keypair.getPublic();
                k = ecpriv.getD();
                kp = ecpub.getQ();
                r = e.add(kp.getXCoord().toBigInteger());
                r = r.mod(init.getN());
            } while (r.equals(BigInteger.ZERO) || r.add(k).equals(init.getN()) || r.toString(16).length() != 64);
            BigInteger da1 = intPrivateKey.add(BigInteger.ONE);
            da1 = da1.modInverse(init.getN());
            s = r.multiply(intPrivateKey);
            s = k.subtract(s).mod(init.getN());
            s = da1.multiply(s).mod(init.getN());
        } while (s.equals(BigInteger.ZERO) || (s.toString(16).length() != 64));
        return (ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(r)) + "h" + ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(s)));
    }

    protected static boolean sm2SignVerify(String userId, byte[] publicKey, byte[] sourceData, String signData, SM2Initializer init) {
        try {
            byte[] formatedPubKey;
            if (publicKey.length == 64) {
                formatedPubKey = new byte[65];
                formatedPubKey[0] = 0x04;
                System.arraycopy(publicKey, 0, formatedPubKey, 1, publicKey.length);
            } else {
                formatedPubKey = publicKey;
            }
            AbstractECPoint userKey = init.decodePoint(formatedPubKey);
            SM3 sm3 = new SM3();
            byte[] z = init.userSM3Z(ConvertUtil.hexToByte(userId), userKey);
            sm3.update(z, 0, z.length);
            sm3.update(sourceData, 0, sourceData.length);
            sm3.finish();
            String sr = signData.split("h")[0];
            String ss = signData.split("h")[1];
            BigInteger r = new BigInteger(sr, 16);
            BigInteger s = new BigInteger(ss, 16);
            BigInteger e = new BigInteger(1, sm3.getHashBytes());
            BigInteger t = r.add(s).mod(init.getN());
            BigInteger R = null;
            if (!t.equals(BigInteger.ZERO)) {
                AbstractECPoint x1y1 = init.getG().multiply(s);
                x1y1 = x1y1.add(userKey.multiply(t));
                R = e.add(x1y1.getXCoord().toBigInteger()).mod(init.getN());
            }
            return r.equals(R);
        } catch (IllegalArgumentException e) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private byte[] kdf(int keylen) {
        return SM2KdfUtil.kdf(keylen, this.p2, null, null);
    }

    protected AbstractECPoint initEnc(SM2Initializer init, AbstractECPoint userPublicKey) {
        ECKeyPair key = init.genKeyPair();
        ECPrivateKey ecpriv = (ECPrivateKey) key.getPrivate();
        ECPublicKey ecpub = (ECPublicKey) key.getPublic();
        BigInteger k = ecpriv.getD();
        AbstractECPoint c1 = ecpub.getQ();

        this.p2 = userPublicKey.multiply(k);
        byte[] p2x = p2.getXCoord().getEncoded();
        this.sm3c3 = new SM3();
        this.sm3c3.update(p2x, 0, p2x.length);
        return c1;
    }

    private void encryptData(byte[] data) {
        this.sm3c3.update(data, 0, data.length);
        byte[] key = kdf(data.length);
        for (int i = 0; i < data.length; i++) {
            data[i] ^= key[i];
        }
    }

    protected void initDec(SM2Initializer init, BigInteger privateKey, AbstractECPoint c1) {
        init.validatePoint(c1.getXCoord().toBigInteger(), c1.getYCoord().toBigInteger());
        this.p2 = c1.multiply(privateKey);
        byte[] p2x = p2.getXCoord().getEncoded();
        this.sm3c3 = new SM3();
        this.sm3c3.update(p2x, 0, p2x.length);
    }

    private void decryptData(byte[] data) {
        byte[] key = kdf(data.length);
        for (int i = 0; i < data.length; i++) {
            data[i] ^= key[i];
        }
        this.sm3c3.update(data, 0, data.length);
    }

    private void doFinal(byte[] c3) {
        byte[] p = ConvertUtil.bigIntegerTo32Bytes(p2.getYCoord().toBigInteger());
        this.sm3c3.update(p, 0, p.length);
        this.sm3c3.finish();
        System.arraycopy(this.sm3c3.getHashBytes(), 0, c3, 0, c3.length);
    }
}
