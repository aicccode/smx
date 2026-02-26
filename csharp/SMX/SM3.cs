using System.Numerics;

namespace SMX;

public class SM3
{
    private static readonly uint[] IV =
    [
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
    ];

    private uint[] _v = new uint[8];
    private readonly byte[] _buff = new byte[64];
    private int _buffLen;
    private ulong _dataBitsLen;
    private byte[] _hashBytes = Array.Empty<byte>();
    private string _hashHexStr = "";

    public SM3()
    {
        Array.Copy(IV, _v, 8);
    }

    private void Reset()
    {
        Array.Copy(IV, _v, 8);
        _buffLen = 0;
        _dataBitsLen = 0;
    }

    public void UpdateByte(byte b)
    {
        _buff[_buffLen] = b;
        _buffLen++;
        _dataBitsLen += 8;
        if (_buffLen == 64)
        {
            ProcessBlock(_buff);
            _buffLen = 0;
        }
    }

    public void Update(byte[] data)
    {
        foreach (var b in data)
            UpdateByte(b);
    }

    public void Finish()
    {
        var end = new byte[_buffLen];
        Array.Copy(_buff, end, _buffLen);

        int blockLenBits = _buffLen * 8;
        int dataLenBits = (int)(_dataBitsLen & 0xFFFFFFFF);

        int fillZeroLenBits = (512 - (blockLenBits + 65) % 512) - 7;
        int allLenBits = fillZeroLenBits + blockLenBits + 65 + 7;
        int allByteLen = allLenBits / 8;

        var buf = new byte[allByteLen];
        for (int i = 0; i < allByteLen; i++)
        {
            if (i < end.Length)
                buf[i] = end[i];
            else if (i == end.Length)
                buf[i] = 0x80;
            else if (i > allByteLen - 5)
            {
                int shift = (allByteLen - i - 1) * 8;
                buf[i] = (byte)((dataLenBits >> shift) & 0xFF);
            }
        }

        int blocks = allLenBits / 512;
        for (int i = 0; i < blocks; i++)
        {
            var block = new byte[64];
            Array.Copy(buf, i * 64, block, 0, 64);
            ProcessBlock(block);
        }

        GenerateHashString();
        Reset();
    }

    public byte[] HashBytes() => _hashBytes;
    public string HashHexUpper() => _hashHexStr;

    private void GenerateHashString()
    {
        var o = new byte[32];
        int off = 0;
        foreach (var v in _v)
        {
            o[off] = (byte)(v >> 24);
            o[off + 1] = (byte)(v >> 16);
            o[off + 2] = (byte)(v >> 8);
            o[off + 3] = (byte)v;
            off += 4;
        }
        _hashBytes = o;
        _hashHexStr = HexUtils.BytesToHexUpper(o);
    }

    private void ProcessBlock(byte[] block)
    {
        var w = new uint[68];
        for (int j = 0; j < 16; j++)
        {
            int o = j * 4;
            w[j] = (uint)block[o] << 24 | (uint)block[o + 1] << 16 |
                   (uint)block[o + 2] << 8 | (uint)block[o + 3];
        }
        for (int j = 16; j < 68; j++)
        {
            uint r15 = BitOperations.RotateLeft(w[j - 3], 15);
            uint r7 = BitOperations.RotateLeft(w[j - 13], 7);
            w[j] = P1(w[j - 16] ^ w[j - 9] ^ r15) ^ r7 ^ w[j - 6];
        }
        var w2 = new uint[64];
        for (int j = 0; j < 64; j++)
            w2[j] = w[j] ^ w[j + 4];

        uint a = _v[0], b = _v[1], c = _v[2], d = _v[3];
        uint e = _v[4], f = _v[5], g = _v[6], h = _v[7];

        for (int j = 0; j < 64; j++)
        {
            uint a12 = BitOperations.RotateLeft(a, 12);
            uint tj = j < 16
                ? BitOperations.RotateLeft(0x79CC4519u, j)
                : BitOperations.RotateLeft(0x7A879D8Au, j % 32);
            uint ss = a12 + e + tj;
            uint ss1 = BitOperations.RotateLeft(ss, 7);
            uint ss2 = ss1 ^ a12;

            uint tt1, tt2;
            if (j < 16)
            {
                tt1 = (a ^ b ^ c) + d + ss2 + w2[j];
                tt2 = (e ^ f ^ g) + h + ss1 + w[j];
            }
            else
            {
                tt1 = FF1(a, b, c) + d + ss2 + w2[j];
                tt2 = GG1(e, f, g) + h + ss1 + w[j];
            }
            d = c;
            c = BitOperations.RotateLeft(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = BitOperations.RotateLeft(f, 19);
            f = e;
            e = P0(tt2);
        }

        _v[0] ^= a; _v[1] ^= b; _v[2] ^= c; _v[3] ^= d;
        _v[4] ^= e; _v[5] ^= f; _v[6] ^= g; _v[7] ^= h;
    }

    private static uint FF1(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);
    private static uint GG1(uint x, uint y, uint z) => (x & y) | (~x & z);
    private static uint P0(uint x) => x ^ BitOperations.RotateLeft(x, 9) ^ BitOperations.RotateLeft(x, 17);
    private static uint P1(uint x) => x ^ BitOperations.RotateLeft(x, 15) ^ BitOperations.RotateLeft(x, 23);
}
