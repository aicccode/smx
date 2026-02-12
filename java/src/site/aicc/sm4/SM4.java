package site.aicc.sm4;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import site.aicc.sm3.SM3;

/** SM4 block cipher algorithm. */
public class SM4 {
    private static final short[] S_BOX_TABLE = {
            0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
            0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
            0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
            0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
            0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
            0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
            0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
            0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
            0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
            0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
            0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
            0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
            0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
            0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
            0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48};

    private byte sbox(byte input) {
        return (byte) S_BOX_TABLE[input & 0xFF];
    }

    private static final int[] FK = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

    private static final int[] CK = {
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279 };

    private int[] roundKeys = new int[32];
    private byte[] iv = new byte[16];

    public String encrypt(String text) throws IOException {
        return processBlocks(text.getBytes(StandardCharsets.UTF_8), Arrays.copyOfRange(iv, 0, iv.length), true);
    }

    public String decrypt(String text) throws IOException {
        return processBlocks(hex2Bytes(text), Arrays.copyOfRange(iv, 0, iv.length), false);
    }

    public SM4 setKey(String key, String iv, boolean hex) {
        if (hex) {
            setKey(hex2Bytes(key), hex2Bytes(iv));
        } else {
            setKey(key, iv);
        }
        return this;
    }

    private void setKey(byte[] keyBytes, byte[] ivBytes) {
        this.initKey(keyBytes, ivBytes);
    }

    private void setKey(String keyString, String ivString) {
        byte[] key = keyString.getBytes(StandardCharsets.UTF_8);
        SM3 sm3 = new SM3();
        if (key.length != 16) {
            key = new byte[16];
            String hashKey = sm3.update(keyString.getBytes(StandardCharsets.UTF_8), 0, keyString.getBytes(StandardCharsets.UTF_8).length).finish().getHashCode();
            byte[] sm3Bytes = hashKey.getBytes();
            System.arraycopy(sm3Bytes, 0, key, 0, 16);
        }

        byte[] iv = ivString.getBytes(StandardCharsets.UTF_8);
        if (iv.length != 16) {
            iv = new byte[16];
            String hashIv = sm3.update(ivString.getBytes(StandardCharsets.UTF_8), 0, ivString.getBytes(StandardCharsets.UTF_8).length).finish().getHashCode();
            byte[] sm3Bytes = hashIv.getBytes();
            System.arraycopy(sm3Bytes, 0, iv, 0, 16);
        }
        this.initKey(key, iv);
    }

    private void initKey(byte[] key, byte[] iv) {
        int[] masterKey = new int[4];
        int offset = 0;
        for (int i = 0; i < key.length / 4; i++) {
            masterKey[i] = (((key[offset] & 0xff) << 24) | ((key[++offset] & 0xff) << 16) | ((key[++offset] & 0xff) << 8) | (key[++offset] & 0xff));
            offset++;
        }

        int[] K = new int[36];
        K[0] = masterKey[0] ^ FK[0];
        K[1] = masterKey[1] ^ FK[1];
        K[2] = masterKey[2] ^ FK[2];
        K[3] = masterKey[3] ^ FK[3];
        for (int i = 0; i < 32; i++) {
            K[i + 4] = (K[i] ^ transformTPrime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]));
            roundKeys[i] = K[i + 4];
        }
        this.iv = Arrays.copyOfRange(iv, 0, 16);
    }

    private String processBlocks(byte[] input, byte[] cbcVector, boolean encrypt) throws IOException {
        if (encrypt) {
            input = applyPkcs7Padding(input);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        for (int j = 0; j < input.length / 16; j++) {
            int[] X = new int[36];
            byte[] nextiv = Arrays.copyOfRange(input, offset, offset + 16);
            for (int i = 0; i < 4; i++) {
                if (encrypt) {
                    int x1 = ((input[offset] ^ cbcVector[offset % 16]) & 0xff) << 24;
                    int x2 = ((input[++offset] ^ cbcVector[offset % 16]) & 0xff) << 16;
                    int x3 = ((input[++offset] ^ cbcVector[offset % 16]) & 0xff) << 8;
                    int x4 = (input[++offset] ^ cbcVector[offset % 16]) & 0xff;
                    X[i] = x1 | x2 | x3 | x4 ;
                } else {
                    X[i] = (((input[offset] & 0xff) << 24) | ((input[++offset] & 0xff) << 16) | ((input[++offset] & 0xff) << 8) | ((input[++offset] & 0xff)));
                }

                offset++;
            }
            for (int i = 0; i < 32; i++) {
                X[i + 4] = roundFunction(X[i], X[i + 1], X[i + 2], X[i + 3], encrypt ? roundKeys[i] : roundKeys[31 - i]);
            }
            int[] lastFour = Arrays.copyOfRange(X, 32, 36);
            int[] reversed = reverseOrder(lastFour);
            byte[] outputBlock = new byte[16];
            int index = 0;
            for (int i = 0; i < 4; i++) {
                outputBlock[index] = (byte) ((reversed[i] >>> 24) & 0xff);
                outputBlock[++index] = (byte) ((reversed[i] >>> 16) & 0xff);
                outputBlock[++index] = (byte) ((reversed[i] >>> 8) & 0xff);
                outputBlock[++index] = (byte) (reversed[i] & 0xff);
                index++;
            }
            if (encrypt) {
                System.arraycopy(outputBlock, 0, cbcVector, 0, 16);
            } else {
                for (int i = 0; i < outputBlock.length; i++) {
                    outputBlock[i] ^= cbcVector[i];
                }
                System.arraycopy(nextiv, 0, cbcVector, 0, 16);
            }
            out.write(outputBlock);
        }
        if (encrypt) {
            return bytes2Hex(out.toByteArray(),false);
        } else {
            byte[] bs = out.toByteArray();
            return new String(Arrays.copyOfRange(bs, 0, bs.length - bs[bs.length - 1]), StandardCharsets.UTF_8);
        }

    }

    private int roundFunction(int x0, int x1, int x2, int x3, int rk) {
        return x0 ^ transformT(x1 ^ x2 ^ x3 ^ rk);
    }

    private int transformT(int a) {
        byte[] abs = int2Bytes(a);
        for (int i = 0; i < abs.length; i++) {
            abs[i] = sbox(abs[i]);
        }
        int b = bytes2Int(abs);
        return b ^ ((b << 2) | (b >>> (32 - 2))) ^ ((b << 10) | (b >>> (32 - 10))) ^ ((b << 18) | (b >>> (32 - 18))) ^ ((b << 24) | (b >>> (32 - 24)));
    }

    private int transformTPrime(int a) {
        byte[] abs = int2Bytes(a);
        for (int i = 0; i < abs.length; i++) {
            abs[i] = sbox(abs[i]);
        }
        int b = bytes2Int(abs);
        return b ^ ((b << 13) | (b >>> (32 - 13))) ^ ((b << 23) | (b >>> (32 - 23)));
    }

    private int[] reverseOrder(int[] A) {
        A[0] = A[0] ^ A[3];
        A[3] = A[0] ^ A[3];
        A[0] = A[0] ^ A[3];
        A[1] = A[1] ^ A[2];
        A[2] = A[1] ^ A[2];
        A[1] = A[1] ^ A[2];
        return A;
    }

    private byte[] applyPkcs7Padding(byte[] input) {
        byte t = (byte) (16 - input.length % 16);
        byte[] out = new byte[input.length + t];
        System.arraycopy(input, 0, out, 0, input.length);
        for (int i = 0; i < t; i++){
            out[input.length + i] = t;
        }
        return out;
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytes2Hex(byte[] bytes, boolean upperCase) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return upperCase ? new String(hexChars).toUpperCase() : new String(hexChars).toLowerCase();
    }

    private static byte[] hex2Bytes(String hex) {
        char[] chars = hex.toCharArray();
        byte[] bs = new byte[chars.length / 2];
        int point = 0;
        for (int i = 0; i < hex.length(); i++) {
            bs[point++] = (byte) (Integer.parseInt("" + chars[i++] + chars[i], 16) & 0xFF);
        }
        return bs;
    }

    private static int bytes2Int(byte[] b) {
        int n = (b[0] & 0xff) << 24 | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);
        return n;
    }

    private static byte[] int2Bytes(int n) {
        byte[] b = new byte[4];
        b[0] = (byte) (0xFF & n >> 24);
        b[1] = (byte) (0xFF & n >> 16);
        b[2] = (byte) (0xFF & n >> 8);
        b[3] = (byte) (0xFF & n);
        return b;
    }
}
