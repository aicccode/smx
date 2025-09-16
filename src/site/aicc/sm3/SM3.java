package site.aicc.sm3;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : SM3密码杂凑算法 (SM3 Cryptographic Hash Algorithm)</p>
*     </li>
*     <li>
*       <h4> 使用示例(Example)：</h4>
*       <p>// 多次调用update 只需调用一次finish</p>
*       <p>String hash = new SM3()</p>
*       <p>.update("abc".getBytes(), 0, "abc".getBytes().length)</p>
*       <p>.update("def".getBytes(), 0, "def".getBytes().length)</p>
*       <p>.finish()</p>
*       <p>.getHashCode();</p>
*     </li>
*     <li>
*       <h3>版本历史</h3>
*       <ul>
*           <li>Version : 1.00</li>
*           <li>Date : 2020-09-24 | 上午01:24:10</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class SM3 {
    // 初始IV常量
    private static final int[] IV = new int[] { 0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E };

    private int[] V;

    // 512bit 缓存
    private byte[] buff512Bit;
    // 缓存指针
    private int buffPoint;
    // 总长度
    private int dataLength;
    // 最终结果String
    private String hashValue;
    // 最终结果Bytes
    private byte[] hashBytes;

    public SM3() {
        buff512Bit = new byte[64];
        this.buffPoint = 0;
        this.dataLength = 0;
        V = Arrays.copyOfRange(IV, 0, IV.length);
    }

    /**
     * 输入单个字节
     * 
     * @param data
     * @return
     */
    public SM3 update(byte data) {
        buff512Bit[buffPoint++] = data;
        dataLength += 8;
        // 够一个块，立即处理
        if (buffPoint == 64) {
            // 迭代压缩
            processFullBuff(buff512Bit);
            buffPoint = 0;
        }
        return this;
    }

    /**
     * 输入字符串
     *
     * @param data
     * @return
     */
    public SM3 update(String data) {
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        return this.update(bytes,0,bytes.length);
    }

    /**
     * 输入字节数组
     * 
     * @param data
     * @param inOffset
     * @param length
     * @return
     */
    public SM3 update(byte[] data, int inOffset, int length) {
        for (int i = 0; i < length; i++) {
            buff512Bit[buffPoint++] = data[inOffset + i];
            dataLength += 8;
            // 够一个块，立即处理
            if (buffPoint == 64) {
                // 迭代压缩
                processFullBuff(buff512Bit);
                buffPoint = 0;
            }
        }
        return this;
    }

    /**
     * 获取最终的杂凑值，获取之前必须先调用finish
     * 
     * @return 咋凑值 hexString
     */
    public String getHashCode() {
        return this.hashValue;
    }

    /**
     * 获取最终的杂凑值，获取之前必须先调用finish
     * 
     * @return 咋凑值 byte数组
     */
    public byte[] getHashBytes() {
        return this.hashBytes;
    }

    /**
     * 结束输入，处理最终块
     * 
     * @return
     */
    public SM3 finish() {
        // 最后一个块处理
        byte[] end = Arrays.copyOfRange(buff512Bit, 0, buffPoint);
        int blockLen = end.length * 8;
        // 1
        byte one = (byte) 128;
        // 需填0长度
        int fillZeroLen = (512 - (blockLen + 65) % 512) - 7;
        // 总长度Bit
        int allLen = fillZeroLen + blockLen + 65 + 7;
        // 总长度Byte
        int allByteLen = allLen / 8;
        //
        byte[] buff = new byte[allByteLen];
        // 填充数据
        for (int i = 0; i < allByteLen; i++) {
            if (i < end.length) {
                // 填充消息
                buff[i] = end[i];
            } else if (i == end.length) {
                // 填充1
                buff[i] = one;
            } else if (i > allByteLen - 5) {
                // 最后四字节填充全部数据的总长度
                buff[i] = (byte) ((dataLength >> (allByteLen - i - 1) * 8) & 0xFF);
            } else {
                // 填充0
                buff[i] = 0;
            }
        }
        // 当剩余缓存中内容大于等于448位时，这里会有两个块
        for (int i = 0; i < allLen / 512; i++) {
            byte[] block = Arrays.copyOfRange(buff, i * 512 / 8, (i + 1) * 512 / 8);
            // 迭代压缩
            processFullBuff(block);
        }
        // 记录杂凑值，重置本实例
        generatorHashString();
        reset();
        return this;
    }

    private void generatorHashString() {
        this.hashBytes = new byte[32];
        int off = 0;
        for (int i = 0; i < V.length; i++) {
            hashBytes[off] = (byte) ((V[i] >>> 24) & 0xff);
            hashBytes[++off] = (byte) ((V[i] >>> 16) & 0xff);
            hashBytes[++off] = (byte) ((V[i] >>> 8) & 0xff);
            hashBytes[++off] = (byte) (V[i] & 0xff);
            off++;
        }
        // 转16进制大写串
        String result = "";
        for (int i = 0; i < hashBytes.length; i++) {
            result += Integer.toString((hashBytes[i] & 0xff) + 0x100, 16).substring(1);
        }
        this.hashValue = result.toUpperCase();
    }

    private void reset() {
        V = Arrays.copyOfRange(IV, 0, IV.length);
        buffPoint = 0;
        dataLength = 0;
    }

    private void processFullBuff(byte[] block) {
        // 消息扩展至132个字
        int[] w = new int[68];
        int offset = 0;
        // w0 ~ w15
        for (int j = 0; j < 16; j++) {
            int h1 =  (block[offset] & 0xff) << 24;
            int h2 =  (block[++offset] & 0xff) << 16;
            int h3 =  (block[++offset] & 0xff) << 8;
            int h4  = (block[++offset] & 0xff);
            w[j] = (h1 | h2 | h3 | h4);
            offset++;
        }
        // w16 ~ w67
        for (int j = 16; j < 68; j++) {
            int wj3 = w[j - 3];
            int r15 = ((wj3 << 15) | (wj3 >>> (32 - 15)));
            int wj13 = w[j - 13];
            int r7 = ((wj13 << 7) | (wj13 >>> (32 - 7)));
            w[j] = P1(w[j - 16] ^ w[j - 9] ^ r15) ^ r7 ^ w[j - 6];
        }
        // w'0 ~ w'63
        int[] w2 = new int[64];
        for (int j = 0; j < w2.length; j++) {
            w2[j] = w[j] ^ w[j + 4];
        }

        // 压缩函数
        int A = V[0];
        int B = V[1];
        int C = V[2];
        int D = V[3];
        int E = V[4];
        int F = V[5];
        int G = V[6];
        int H = V[7];
        for (int j = 0; j < 64; j++) {
            int A12 = ((A << 12) | (A >>> (32 - 12)));
            // 常量 Tj
            int T_j = j < 16 ? ((0x79CC4519 << j) | (0x79CC4519 >>> (32 - j))) : ((0x7A879D8A << (j % 32)) | (0x7A879D8A >>> (32 - (j % 32))));
            int S_S = A12 + E + T_j;
            int SS1 = ((S_S << 7) | (S_S >>> (32 - 7)));
            int SS2 = SS1 ^ A12;
            int TT1 = j < 16 ? ((A ^ B ^ C) + D + SS2 + w2[j]) : (FF1(A, B, C) + D + SS2 + w2[j]);
            int TT2 = j < 16 ? ((E ^ F ^ G) + H + SS1 + w[j]) : (GG1(E, F, G) + H + SS1 + w[j]);
            D = C;
            C = ((B << 9) | (B >>> (32 - 9)));
            B = A;
            A = TT1;
            H = G;
            G = ((F << 19) | (F >>> (32 - 19)));
            F = E;
            E = P0(TT2);
        }
        V[0] ^= A;
        V[1] ^= B;
        V[2] ^= C;
        V[3] ^= D;
        V[4] ^= E;
        V[5] ^= F;
        V[6] ^= G;
        V[7] ^= H;
    }

    private int FF1(int X, int Y, int Z) {
        return (X & Y) | (X & Z) | (Y & Z);
    }

    private int GG1(int x, int y, int z) {
        return (x & y) | ((~x) & z);
    }

    private int P0(int x) {
        int x9 = (x << 9) | (x >>> (32 - 9));
        int x17 = (x << 17) | (x >>> (32 - 17));
        return x ^ x9 ^ x17;
    }

    private int P1(int x) {
        int x15 = (x << 15) | (x >>> (32 - 15));
        int x23 = (x << 23) | (x >>> (32 - 23));
        return x ^ x15 ^ x23;
    }

}
