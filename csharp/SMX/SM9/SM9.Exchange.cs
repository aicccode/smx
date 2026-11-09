using System.Security.Cryptography;
using SMX.SM9Internal;

namespace SMX;

public static partial class SM9
{
    private const byte TagB = 0x82;
    private const byte TagA = 0x83;
    private const string ConfirmationMismatch = "S_B does not match";

    /// <summary>
    /// First step for either side of key exchange: a secret r uniform in [1, N-1] and R = [r]Q_peer with
    /// Q_peer = [H1(ID_peer || hid)]P1 + Ppub-e. Keep r secret and pass it to the next step; send R to the peer.
    /// </summary>
    /// <exception cref="ArgumentException">An invalid peer ID or encryption master public key.</exception>
    /// <exception cref="CryptographicException">The system random generator failed.</exception>
    public static (string r, string R) ExchangeInit(string peerId, string masterPublicKey, byte hid = HidExchange)
    {
        var (_, _, q) = PrepareEncryption(peerId, masterPublicKey, hid);
        var r = NextScalar(SystemRandom);
        return (Sm9Scalar.ToHex(r), q.Multiply(r).ToHex());
    }

    /// <summary>Exchange initiation with a given r, for known-answer tests.</summary>
    internal static string ExchangeInitWithRandom(string peerId, string masterPublicKey, string rHex, byte hid = HidExchange)
    {
        var (_, _, q) = PrepareEncryption(peerId, masterPublicKey, hid);
        return q.Multiply(ParseScalar(rHex, "invalid r")).ToHex();
    }

    /// <summary>
    /// Responder B's step: from A's R_A and B's own r_B and R_B (from <see cref="ExchangeInit"/> with ID_A), gives the
    /// shared key, S_B to send to A, and S_2 to keep for <see cref="ExchangeCheck"/>. Every failure (a key length outside
    /// 1 to 1 MiB, an invalid ID, key, random value or point) is reported through Success and Message.
    /// </summary>
    public static SM9ExchangeResult ExchangeRespond(int keyLength, string idA, string idB, string masterPublicKey,
        string userPrivateKeyB, string rB, string RB, string RA)
    {
        var result = new SM9ExchangeResult();
        if (!TryPrepareExchange(keyLength, idA, idB, masterPublicKey, userPrivateKeyB, rB, RB, RA, result,
                out var ctx, out var deB, out var r, out var ownR, out var peerR))
        {
            return result;
        }

        var g1 = Sm9Pairing.Pair(peerR, deB);
        var g2 = Fq12.PowGt(ctx.G, r);
        var g3 = Fq12.PowGt(g1, r);
        var transcript = new Transcript(ctx.IdA, ctx.IdB, peerR, ownR, g1, g2, g3);
        try
        {
            result.SharedKey = transcript.SharedKey(keyLength);
            result.Sb = HexUtils.BytesToHex(transcript.Confirmation(TagB));
            result.S2 = HexUtils.BytesToHex(transcript.Confirmation(TagA));
            result.Success = true;
            return result;
        }
        finally
        {
            transcript.Wipe();
        }
    }

    /// <summary>
    /// Initiator A's step: from B's R_B and S_B and A's own r_A and R_A, checks S_B in constant time and only then gives
    /// the shared key and S_A to send to B. Failures, a mismatched S_B included, are reported through Success and Message.
    /// S_B must be 64 lowercase hex digits.
    /// </summary>
    public static SM9ExchangeResult ExchangeConfirm(int keyLength, string idA, string idB, string masterPublicKey,
        string userPrivateKeyA, string rA, string RA, string RB, string sB)
    {
        var result = new SM9ExchangeResult();
        if (!TryPrepareExchange(keyLength, idA, idB, masterPublicKey, userPrivateKeyA, rA, RA, RB, result,
                out var ctx, out var deA, out var r, out var ownR, out var peerR))
        {
            return result;
        }

        Span<byte> expected = stackalloc byte[HashSize];
        bool wellFormed = TryDecodeConfirmation(sB, expected);

        var g1 = Fq12.PowGt(ctx.G, r);
        var g2 = Sm9Pairing.Pair(peerR, deA);
        var g3 = Fq12.PowGt(g2, r);
        var transcript = new Transcript(ctx.IdA, ctx.IdB, ownR, peerR, g1, g2, g3);
        try
        {
            var s1 = transcript.Confirmation(TagB);
            if (!(CryptographicOperations.FixedTimeEquals(s1, expected) & wellFormed))
            {
                result.Message = ConfirmationMismatch;
                return result;
            }
            result.SharedKey = transcript.SharedKey(keyLength);
            result.Sa = HexUtils.BytesToHex(transcript.Confirmation(TagA));
            result.Success = true;
            return result;
        }
        finally
        {
            transcript.Wipe();
        }
    }

    /// <summary>
    /// Responder B's final check that A's S_A equals the S_2 from <see cref="ExchangeRespond"/>, in constant time. False
    /// for anything that is not 64 lowercase hex digits on both sides, or a mismatch.
    /// </summary>
    public static bool ExchangeCheck(string s2, string sa)
    {
        Span<byte> a = stackalloc byte[HashSize];
        Span<byte> b = stackalloc byte[HashSize];
        bool ok = TryDecodeConfirmation(s2, a) & TryDecodeConfirmation(sa, b);
        return CryptographicOperations.FixedTimeEquals(a, b) & ok;
    }

    private static bool TryDecodeConfirmation(string? hex, Span<byte> output)
    {
        output.Clear();
        return hex is not null && hex.Length == 2 * HashSize && HexUtils.IsLowerCaseOnly(hex) && HexUtils.TryDecode(hex, output);
    }

    private sealed class ExchangeContext(byte[] idA, byte[] idB, Fq12 g)
    {
        public readonly byte[] IdA = idA;
        public readonly byte[] IdB = idB;
        public readonly Fq12 G = g;
    }

    /// <summary>Validates everything both steps share; on failure sets the message and returns false.</summary>
    private static bool TryPrepareExchange(int keyLength, string idA, string idB, string masterPublicKey,
        string userPrivateKey, string ownRandom, string ownPoint, string peerPoint, SM9ExchangeResult result,
        out ExchangeContext ctx, out G2Affine de, out BigInt256 r, out G1Affine ownR, out G1Affine peerR)
    {
        ctx = null!;
        de = default;
        r = default;
        ownR = default;
        peerR = default;
        if (keyLength < 1 || keyLength > MaxKeyBytes)
        {
            result.Message = InvalidKeyLength;
            return false;
        }
        if (!TryGetId(idA, out var a) || !TryGetId(idB, out var b))
        {
            result.Message = InvalidUserId;
            return false;
        }
        if (!TryEncMaster(masterPublicKey, out var master))
        {
            result.Message = InvalidMasterPublicKey;
            return false;
        }
        if (userPrivateKey is null || !G2Affine.TryParseHex(userPrivateKey, out de))
        {
            result.Message = InvalidUserPrivateKey;
            return false;
        }
        if (!Sm9Scalar.TryParse(ownRandom, out r))
        {
            result.Message = "invalid random value";
            return false;
        }
        if (ownPoint is null || !G1Affine.TryParseHex(ownPoint, out ownR))
        {
            result.Message = "invalid own R point";
            return false;
        }
        if (peerPoint is null || !G1Affine.TryParseHex(peerPoint, out peerR))
        {
            result.Message = "invalid peer R point";
            return false;
        }
        ctx = new ExchangeContext(a, b, master.G);
        return true;
    }

    /// <summary>The serialized values both sides hash: ID_A || ID_B || R_A.xy || R_B.xy and g1, g2, g3.</summary>
    private readonly struct Transcript
    {
        private readonly byte[] _tail;
        private readonly byte[] _g;

        public Transcript(byte[] idA, byte[] idB, in G1Affine ra, in G1Affine rb, in Fq12 g1, in Fq12 g2, in Fq12 g3)
        {
            _tail = new byte[idA.Length + idB.Length + 2 * G1Affine.CoordinatesSize];
            idA.CopyTo(_tail, 0);
            idB.CopyTo(_tail, idA.Length);
            ra.WriteCoordinates(_tail.AsSpan(idA.Length + idB.Length));
            rb.WriteCoordinates(_tail.AsSpan(idA.Length + idB.Length + G1Affine.CoordinatesSize));
            _g = new byte[3 * Fq12.ByteSize];
            g1.Write(_g);
            g2.Write(_g.AsSpan(Fq12.ByteSize));
            g3.Write(_g.AsSpan(2 * Fq12.ByteSize));
        }

        /// <summary>SK = KDF(ID_A || ID_B || R_A || R_B || g1 || g2 || g3, klen).</summary>
        public string SharedKey(int keyLength)
        {
            var h = Sm3Hasher.Create();
            h.Update(_tail);
            h.Update(_g);
            var key = new byte[keyLength];
            Sm9Scalar.Kdf(h, key);
            h.Wipe();
            var hex = HexUtils.BytesToHex(key);
            CryptographicOperations.ZeroMemory(key);
            return hex;
        }

        /// <summary>SM3(tag || g1 || SM3(g2 || g3 || ID_A || ID_B || R_A || R_B)).</summary>
        public byte[] Confirmation(byte tag)
        {
            Span<byte> inner = stackalloc byte[HashSize];
            var h = Sm3Hasher.Create();
            h.Update(_g.AsSpan(Fq12.ByteSize));
            h.Update(_tail);
            h.Finish(inner);
            h.Wipe();

            var outer = Sm3Hasher.Create();
            outer.UpdateByte(tag);
            outer.Update(_g.AsSpan(0, Fq12.ByteSize));
            outer.Update(inner);
            var digest = new byte[HashSize];
            outer.Finish(digest);
            outer.Wipe();
            CryptographicOperations.ZeroMemory(inner);
            return digest;
        }

        public void Wipe()
        {
            CryptographicOperations.ZeroMemory(_g);
        }
    }
}
