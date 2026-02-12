package site.aicc.sm3;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** SM3 cryptographic hash algorithm. */
public class SM3 {
    private static final int[] IV = new int[] { 0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E };

    private int[] V;

    private byte[] blockBuffer;
    private int bufferOffset;
    private int dataLength;
    private String hexResult;
    private byte[] hashBytes;

    public SM3() {
        blockBuffer = new byte[64];
        this.bufferOffset = 0;
        this.dataLength = 0;
        V = Arrays.copyOfRange(IV, 0, IV.length);
    }

    public SM3 update(byte data) {
        blockBuffer[bufferOffset++] = data;
        dataLength += 8;
        if (bufferOffset == 64) {
            compressBlock(blockBuffer);
            bufferOffset = 0;
        }
        return this;
    }

    public SM3 update(String data) {
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        return this.update(bytes,0,bytes.length);
    }

    public SM3 update(byte[] data, int inOffset, int length) {
        for (int i = 0; i < length; i++) {
            blockBuffer[bufferOffset++] = data[inOffset + i];
            dataLength += 8;
            if (bufferOffset == 64) {
                compressBlock(blockBuffer);
                bufferOffset = 0;
            }
        }
        return this;
    }

    public String getHashCode() {
        return this.hexResult;
    }

    public byte[] getHashBytes() {
        return this.hashBytes;
    }

    public SM3 finish() {
        byte[] end = Arrays.copyOfRange(blockBuffer, 0, bufferOffset);
        int blockLen = end.length * 8;
        byte one = (byte) 128;
        int fillZeroLen = (512 - (blockLen + 65) % 512) - 7;
        int allLen = fillZeroLen + blockLen + 65 + 7;
        int allByteLen = allLen / 8;
        byte[] buff = new byte[allByteLen];
        for (int i = 0; i < allByteLen; i++) {
            if (i < end.length) {
                buff[i] = end[i];
            } else if (i == end.length) {
                buff[i] = one;
            } else if (i > allByteLen - 5) {
                buff[i] = (byte) ((dataLength >> (allByteLen - i - 1) * 8) & 0xFF);
            } else {
                buff[i] = 0;
            }
        }
        for (int i = 0; i < allLen / 512; i++) {
            byte[] block = Arrays.copyOfRange(buff, i * 512 / 8, (i + 1) * 512 / 8);
            compressBlock(block);
        }
        computeHashResult();
        reset();
        return this;
    }

    private void computeHashResult() {
        this.hashBytes = new byte[32];
        int off = 0;
        for (int i = 0; i < V.length; i++) {
            hashBytes[off] = (byte) ((V[i] >>> 24) & 0xff);
            hashBytes[++off] = (byte) ((V[i] >>> 16) & 0xff);
            hashBytes[++off] = (byte) ((V[i] >>> 8) & 0xff);
            hashBytes[++off] = (byte) (V[i] & 0xff);
            off++;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hashBytes.length; i++) {
            sb.append(Integer.toString((hashBytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        this.hexResult = sb.toString().toUpperCase();
    }

    private void reset() {
        V = Arrays.copyOfRange(IV, 0, IV.length);
        bufferOffset = 0;
        dataLength = 0;
    }

    private void compressBlock(byte[] block) {
        int[] w = new int[68];
        int offset = 0;
        for (int j = 0; j < 16; j++) {
            int h1 =  (block[offset] & 0xff) << 24;
            int h2 =  (block[++offset] & 0xff) << 16;
            int h3 =  (block[++offset] & 0xff) << 8;
            int h4  = (block[++offset] & 0xff);
            w[j] = (h1 | h2 | h3 | h4);
            offset++;
        }
        for (int j = 16; j < 68; j++) {
            int wj3 = w[j - 3];
            int r15 = ((wj3 << 15) | (wj3 >>> (32 - 15)));
            int wj13 = w[j - 13];
            int r7 = ((wj13 << 7) | (wj13 >>> (32 - 7)));
            w[j] = P1(w[j - 16] ^ w[j - 9] ^ r15) ^ r7 ^ w[j - 6];
        }
        int[] wPrime = new int[64];
        for (int j = 0; j < wPrime.length; j++) {
            wPrime[j] = w[j] ^ w[j + 4];
        }

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
            int roundConstant = j < 16 ? ((0x79CC4519 << j) | (0x79CC4519 >>> (32 - j))) : ((0x7A879D8A << (j % 32)) | (0x7A879D8A >>> (32 - (j % 32))));
            int rotatedSum = A12 + E + roundConstant;
            int SS1 = ((rotatedSum << 7) | (rotatedSum >>> (32 - 7)));
            int SS2 = SS1 ^ A12;
            int TT1 = j < 16 ? ((A ^ B ^ C) + D + SS2 + wPrime[j]) : (FF1(A, B, C) + D + SS2 + wPrime[j]);
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
