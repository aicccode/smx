package site.aicc.sm2;

import java.io.IOException;
import java.math.BigInteger;

import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.keygen.ECPrivateKey;
import site.aicc.sm2.keygen.ECPublicKey;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.util.ConvertUtil;
import site.aicc.sm3.SM3;
//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : SM2算法核心类</p>
*     </li>
*     <li>
*       <h4> 使用示例(Example)：</h4>
*       <p></p>
*       <p></p>
*     </li>
*     <li>
*       <h3>版本历史</h3>
*       <ul>
*           <li>Version : 1.00</li>
*           <li>Date : 2020-09-29 | 下午08:11:32</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class SM2Cipher {

    private AbstractECPoint p2;
    private SM3 sm3c3;

    /**
     * 加密
     * @param publicKey
     * @param data
     * @param init
     * @return
     * @throws IOException
     */
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
        // 加密
        cipher.Encrypt(source);
        byte[] c3 = new byte[32];
        cipher.Dofinal(c3);
        // C1 | C3 | C2
        return ConvertUtil.byteToHex(c1.getEncoded()) + ConvertUtil.byteToHex(c3) + ConvertUtil.byteToHex(source);
    }
    /**
     * 解密
     * @param privateKey
     * @param encryptedData
     * @param init
     * @return
     * @throws IOException
     */
    protected static byte[] decrypt(byte[] privateKey, byte[] encryptedData, SM2Initializer init) throws IOException {
        if (privateKey == null || privateKey.length == 0) {
            return null;
        }
        if (encryptedData == null || encryptedData.length == 0) {
            return null;
        }
        // C1(130)||C3(64)||C2
        String data = ConvertUtil.byteToHex(encryptedData);
        byte[] c1Bytes = ConvertUtil.hexToByte(data.substring(0, 130));
        byte[] c3 = ConvertUtil.hexToByte(data.substring(130, 130 + 64));
        byte[] c2 = ConvertUtil.hexToByte(data.substring(194, 2 * encryptedData.length));
        BigInteger userPrivateKey = new BigInteger(1, privateKey);
        AbstractECPoint c1 = init.decodePoint(c1Bytes);
        SM2Cipher cipher = new SM2Cipher();
        cipher.initDec(init, userPrivateKey, c1);
        cipher.Decrypt(c2);
        byte[] v = new byte[32];
        cipher.Dofinal(v);
        // 验证v与c3相等
        if (!ConvertUtil.byteArrayEqual(v, c3)) {
            throw new IllegalArgumentException("解密失败");
        }
        // 明文
        return c2;
    }

    /**
     * 生成签名
     * @param userId
     * @param privatekey
     * @param sourceData
     * @param init
     * @return
     * @throws Exception
     */
    protected static String sm2Sign(String userId, byte[] privatekey, byte[] sourceData, SM2Initializer init) throws Exception {
        BigInteger intPrivateKey = new BigInteger(privatekey);
        AbstractECPoint pA = init.getPublicKey(intPrivateKey);
        byte[] zA = init.userSM3Z(ConvertUtil.hexToByte(userId), pA);
        SM3 sm3 = new SM3();
        sm3.update(zA, 0, zA.length);
        sm3.update(sourceData, 0, sourceData.length);
        sm3.finish();
        BigInteger e = new BigInteger(1, sm3.getHashBytes());
        // 计算签名
        BigInteger k = null;
        AbstractECPoint kp = null;
        BigInteger r = null;
        BigInteger s = null;
        do {
            // 生成随机数k
            do {
                ECKeyPair keypair = init.genKeyPair();
                ECPrivateKey ecpriv = (ECPrivateKey) keypair.getPrivate();
                ECPublicKey ecpub = (ECPublicKey) keypair.getPublic();
                k = ecpriv.getD();
                kp = ecpub.getQ();
                // 国密测试参数
                //@formatter:off
                // k = new BigInteger("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F", 16);
                // kp = init.decodePoint( ConvertUtil.hexToByte("04" + "110FCDA57615705D5E7B9324AC4B856D23E6D9188B2AE47759514657CE25D112" + "1C65D68A4A08601DF24B431E0CAB4EBE084772B3817E85811A8510B2DF7ECA1A"));
                //@formatter:on
                r = e.add(kp.getXCoord().toBigInteger());
                r = r.mod(init.getN());
            } while (r.equals(BigInteger.ZERO) || r.add(k).equals(init.getN()) || r.toString(16).length() != 64);
            // 计算s
            BigInteger da1 = intPrivateKey.add(BigInteger.ONE);
            da1 = da1.modInverse(init.getN());
            s = r.multiply(intPrivateKey);
            s = k.subtract(s).mod(init.getN());
            s = da1.multiply(s).mod(init.getN());
        } while (s.equals(BigInteger.ZERO) || (s.toString(16).length() != 64));
        return (ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(r)) + "h" + ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(s)));
    }
    /**
     * 签名验证
     * @param userId
     * @param publicKey
     * @param sourceData
     * @param signData
     * @param init
     * @return
     */
    protected static boolean sm2SignVerify(String userId, byte[] publicKey, byte[] sourceData, String signData, SM2Initializer init) {
        try {
            byte[] formatedPubKey;
            if (publicKey.length == 64) {
                formatedPubKey = new byte[65];
                // 非压缩软加密
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
            e.printStackTrace();
            return false;
        }
    }

    // 密钥派生函数KDF
    private byte[] KDF(int keylen) {
        byte[] result = new byte[keylen];
        int ct = 0x00000001;
        for (int i = 0; i < (keylen + 31) / 32; i++) {
            SM3 sm3 = new SM3();
            byte[] p2x = this.p2.getXCoord().getEncoded();
            sm3.update(p2x, 0, p2x.length);
            byte[] p2y = this.p2.getYCoord().getEncoded();
            sm3.update(p2y, 0, p2y.length);
            byte[] ctBytes = new byte[4];
            ConvertUtil.intToBigEndian(ct, ctBytes, 0);
            sm3.update(ctBytes, 0, 4);
            sm3.finish();
            // 最后一段
            if (i == ((keylen + 31) / 32 - 1) && (keylen % 32) != 0) {
                System.arraycopy(sm3.getHashBytes(), 0, result, 32 * (ct - 1), keylen % 32);
            } else {
                System.arraycopy(sm3.getHashBytes(), 0, result, 32 * (ct - 1), 32);
            }
            ct++;
        }
        return result;
    }
    
        /**
     * 初始化加密器
     * @param init
     * @param userPublicKey
     * @return
     */
    protected AbstractECPoint initEnc(SM2Initializer init, AbstractECPoint userPublicKey) {
        ECKeyPair key = init.genKeyPair();
        ECPrivateKey ecpriv = (ECPrivateKey) key.getPrivate();
        ECPublicKey ecpub = (ECPublicKey) key.getPublic();
        // 6.1 A1随机数k
         BigInteger k = ecpriv.getD();
         AbstractECPoint c1 = ecpub.getQ();

        // 国密测试随机数
         //BigInteger k = new BigInteger("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F",16);
        // 6.1 A2 C1 = [k]G
        // 国密测试c1计算
        //AbstractECPoint c1 = init.getG().multiply(k);


        // 6.1 A4
        // 密钥派生初始Z
        this.p2 = userPublicKey.multiply(k);
        byte p2x[] = p2.getXCoord().getEncoded();
        // C3 X2
        this.sm3c3 = new SM3();
        this.sm3c3.update(p2x, 0, p2x.length);
        return c1;
    }

     private void Encrypt(byte data[]) {
        // C3 M
        this.sm3c3.update(data, 0, data.length);
        byte[] key = KDF(data.length);
        for (int i = 0; i < data.length; i++) {
            data[i] ^= key[i];
        }
    }
    /**
     * 初始化解密器
     * @param init
     * @param privateKey
     * @param c1
     */
    protected void initDec(SM2Initializer init, BigInteger privateKey, AbstractECPoint c1) {
        // 验证C1满足椭圆曲线方程
        init.validatePoint(c1.getXCoord().toBigInteger(), c1.getYCoord().toBigInteger());
        this.p2 = c1.multiply(privateKey);
        // 初始化密钥
        byte p2x[] = p2.getXCoord().getEncoded();
        // C3
        this.sm3c3 = new SM3();
        this.sm3c3.update(p2x, 0, p2x.length);
    }

    private void Decrypt(byte data[]) {
        // 解密过程与加密一样
        byte[] key = KDF(data.length);
        for (int i = 0; i < data.length; i++) {
            data[i] ^= key[i];
        }
        // C3 M
        this.sm3c3.update(data, 0, data.length);
    }
    
    private void Dofinal(byte c3[]) {
        // C3 Y2
        byte p[] = ConvertUtil.bigIntegerTo32Bytes(p2.getYCoord().toBigInteger());
        this.sm3c3.update(p, 0, p.length);
        this.sm3c3.finish();
        System.arraycopy(this.sm3c3.getHashBytes(), 0, c3, 0, c3.length);
    }
}
