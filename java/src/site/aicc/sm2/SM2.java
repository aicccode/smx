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

//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : SM2椭圆曲线公钥密码算法(Public Key Cryptographic Algorithm SM2 Based on Elliptic Curves)</p>
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
*           <li>Date : 2020-09-30 | 下午21:02:02</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class SM2 {
    //@formatter:off
    // 方程 y^2 = x^3 + ax + b
    /* SM2 国密算法推荐参数*/
    private static final String[] params = new String[] {
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
    };
    /*密钥交换协议测试参数
    private static final String[] params = new String[] {
            "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",//p
            "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",//a
            "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",//b
            "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",//n
            "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",//gx
            "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"//gy
    };*/
    /* 国密测试参数
    private static final String[] params = new String[]{
          "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
          "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
          "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
          "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
          "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
          "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2" 
    };*/

    //@formatter:on
    // 国密参数构造的椭圆曲线计算器
    private static final SM2Initializer init;
    static {
        // 两种倍点计算算法(需要实现其他算法可自行实现)
        init = new SM2Initializer(params, new DoubleAndAddMultiplier());
        // init = new SM2Initializer(params,new NAFwMultiplier());
    }

    /**
     * 测试使用
     * 
     * @return
     */
    protected static SM2Initializer getSM2Initializer() {
        return init;
    }

    /**
     * 256位随机密钥对生成
     * 
     * @return
     */
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

    /**
     * 公钥加密
     * 
     * @param content
     * @param publicKey
     * @return
     * @throws IllegalArgumentException
     * @throws IOException
     */
    public static String sm2Encrypt(String content, String publicKey) throws IllegalArgumentException, IOException {
        String encrypt = SM2Cipher.encrypt(ConvertUtil.hexToByte(publicKey), content.getBytes(StandardCharsets.UTF_8), init);
        return encrypt;
    }

    /**
     * 私钥解密
     * 
     * @param content
     * @param privateKey
     * @return
     * @throws IllegalArgumentException
     * @throws IOException
     */
    public static String sm2Decrypt(String content, String privateKey) throws IllegalArgumentException, IOException {
        byte[] decrypt = SM2Cipher.decrypt(ConvertUtil.hexToByte(privateKey), ConvertUtil.hexToByte(content), init);
        return new String(decrypt, StandardCharsets.UTF_8);
    }

    /**
     * 签名
     * 
     * @param userId
     * @param content
     * @param privateKey
     * @return
     * @throws IllegalArgumentException
     * @throws Exception
     */
    public static String sm2Sign(String userId, String content, String privateKey) throws IllegalArgumentException, Exception {
        content = ConvertUtil.byteToHex(content.getBytes(StandardCharsets.UTF_8)).toLowerCase();
        return SM2Cipher.sm2Sign(ConvertUtil.byteToHex(userId.getBytes(StandardCharsets.UTF_8)), ConvertUtil.hexToByte(privateKey), ConvertUtil.hexToByte(content), init);
    }

    /**
     * 签名验证
     * 
     * @param userId
     * @param signature
     * @param content
     * @param publicKey
     * @return
     */
    public static boolean sm2VerifySign(String userId, String signature, String content, String publicKey) {
        content = ConvertUtil.byteToHex(content.getBytes(StandardCharsets.UTF_8)).toLowerCase();
        return SM2Cipher.sm2SignVerify(ConvertUtil.byteToHex(userId.getBytes(StandardCharsets.UTF_8)), ConvertUtil.hexToByte(publicKey), ConvertUtil.hexToByte(content), signature, init);
    }
    
    /**
     * B用户收到A用户发送的信息后，调用本方法，计算出己方密钥，并将Sb发送回A用户
     * 
     * @param byteLen 协商的密钥长度（单位，字节）
     * @param pA      A用户证书公钥
     * @param Ra      A用户随机公钥
     * @param pB      B用户证书公钥
     * @param dB      B用户证书私钥
     * @param Rb      B用户随机公钥
     * @param rb      B用户随机私钥
     * @param IDa     A用户标识
     * @param IDb     B用户标识
     * @return Sb(发送给用户A) Kb(用户B端协商出的密钥，禁止发送！！！)
     */
    public static SM2KeySwapParams getSb(int byteLen, AbstractECPoint pA, AbstractECPoint Ra, AbstractECPoint pB, BigInteger dB, AbstractECPoint Rb, BigInteger rb, String IDa, String IDb) {
        return SM2KeySwap.getSb(init, byteLen, pA, Ra, pB, dB, Rb, rb, IDa, IDb);
    }
    /**
     * A 用户收到B用户返回的Sb后，计算出A侧密钥，并计算出Sa发回给B用户验证
     * @param byteLen 协商的密钥长度（单位，字节）
     * @param pB      用户B证书公钥
     * @param Rb      用户B随机公钥
     * @param pA      用户A证书公钥
     * @param dA      用户A证书私钥
     * @param Ra      用户A随机公钥
     * @param ra      用户A随机私钥
     * @param IDa     A用户标识
     * @param IDb     B用户标识
     * @param Sb      B用户计算的验证值
     * @return Sa(发送给用户B) Ka(用户A端协商出的密钥，禁止发送！！！)
     */
    public static SM2KeySwapParams getSa(int byteLen, AbstractECPoint pB, AbstractECPoint Rb, AbstractECPoint pA, BigInteger dA, AbstractECPoint Ra, BigInteger ra, String IDa, String IDb, byte[] Sb) {
        return SM2KeySwap.getSa(init, byteLen, pB, Rb, pA, dA, Ra, ra, IDa, IDb, Sb);
    }
    /**
     * 用户B收到用户A返回的验证值后，验证密钥协商结果是否正常
     * 
     * @param V  用户之前计算的V
     * @param Za 之前计算的Za
     * @param Zb 之前计算的Zb
     * @param Ra 用户A随机公钥
     * @param Rb 用户B随机公钥
     * @param Sa 用户A返回的验证值
     */
    public static boolean checkSa(AbstractECPoint V, byte[] Za, byte[] Zb, AbstractECPoint Ra, AbstractECPoint Rb, byte[] Sa) {
        return SM2KeySwap.checkSa(V, Za, Zb, Ra, Rb, Sa);
    }

}
