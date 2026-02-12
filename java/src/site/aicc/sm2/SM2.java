package site.aicc.sm2;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.keygen.ECPrivateKey;
import site.aicc.sm2.ec.DoubleAndAddMultiplier;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.keygen.ECPublicKey;
import site.aicc.sm2.util.ConvertUtil;

/** SM2 elliptic curve public key cryptographic algorithm. */
public class SM2 {
    private static final String[] params = new String[] {
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
    };

    private static final SM2Initializer init;
    static {
        init = new SM2Initializer(params, new DoubleAndAddMultiplier());
    }

    protected static SM2Initializer getSM2Initializer() {
        return init;
    }

    public static ECKeyPair genSM2KeyPair() {
        ECKeyPair key = null;
        while (true) {
            key = init.genKeyPair();
            int priLength = ((ECPrivateKey) key.getPrivate()).getD().toByteArray().length;
            AbstractECPoint q = ((ECPublicKey) key.getPublic()).getQ();
            int pubLength = q.getXCoord().toBigInteger().toByteArray().length + q.getYCoord().toBigInteger().toByteArray().length;
            if (priLength == 32 && pubLength == 64) {
                break;
            }
        }
        return key;
    }

    public static AbstractECPoint decodePoint(String publicKey){
        return init.decodePoint(ConvertUtil.hexToByte(publicKey));
    }

    public static AbstractECPoint getPublicKey(BigInteger privateKey){
        return init.getPublicKey(privateKey);
    }

    public static String sm2Encrypt(String content, String publicKey) throws IllegalArgumentException, IOException {
        return SM2Cipher.encrypt(ConvertUtil.hexToByte(publicKey), content.getBytes(StandardCharsets.UTF_8), init);
    }

    public static String sm2Decrypt(String content, String privateKey) throws IllegalArgumentException, IOException {
        byte[] decrypt = SM2Cipher.decrypt(ConvertUtil.hexToByte(privateKey), ConvertUtil.hexToByte(content), init);
        return new String(decrypt, StandardCharsets.UTF_8);
    }

    public static String sm2Sign(String userId, String content, String privateKey) throws IllegalArgumentException, Exception {
        content = ConvertUtil.byteToHex(content.getBytes(StandardCharsets.UTF_8)).toLowerCase();
        return SM2Cipher.sm2Sign(ConvertUtil.byteToHex(userId.getBytes(StandardCharsets.UTF_8)), ConvertUtil.hexToByte(privateKey), ConvertUtil.hexToByte(content), init);
    }

    public static boolean sm2VerifySign(String userId, String signature, String content, String publicKey) {
        content = ConvertUtil.byteToHex(content.getBytes(StandardCharsets.UTF_8)).toLowerCase();
        return SM2Cipher.sm2SignVerify(ConvertUtil.byteToHex(userId.getBytes(StandardCharsets.UTF_8)), ConvertUtil.hexToByte(publicKey), ConvertUtil.hexToByte(content), signature, init);
    }

    public static SM2KeySwapParams getSb(int byteLen, AbstractECPoint pA, AbstractECPoint Ra, AbstractECPoint pB, BigInteger dB, AbstractECPoint Rb, BigInteger rb, String IDa, String IDb) {
        return SM2KeySwap.getSb(init, byteLen, pA, Ra, pB, dB, Rb, rb, IDa, IDb);
    }

    public static SM2KeySwapParams getSa(int byteLen, AbstractECPoint pB, AbstractECPoint Rb, AbstractECPoint pA, BigInteger dA, AbstractECPoint Ra, BigInteger ra, String IDa, String IDb, byte[] Sb) {
        return SM2KeySwap.getSa(init, byteLen, pB, Rb, pA, dA, Ra, ra, IDa, IDb, Sb);
    }

    public static boolean checkSa(AbstractECPoint V, byte[] Za, byte[] Zb, AbstractECPoint Ra, AbstractECPoint Rb, byte[] Sa) {
        return SM2KeySwap.checkSa(V, Za, Zb, Ra, Rb, Sa);
    }

}
