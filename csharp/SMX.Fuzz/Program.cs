// Seeded malformed-input harness for every public entry point. It asserts only the failure convention: each function
// returns, or throws one of its documented exception types, and never hangs. Round-trip properties run alongside.
//
//   dotnet run -c Release --project SMX.Fuzz [-- --cases 200000 --seed 1 --filter text]
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using SMX;

int cases = 200_000;
int seed = 1;
string? filter = null;
for (int i = 0; i + 1 < args.Length; i += 2)
{
    switch (args[i])
    {
        case "--cases":
            cases = int.Parse(args[i + 1]);
            break;
        case "--seed":
            seed = int.Parse(args[i + 1]);
            break;
        case "--filter":
            filter = args[i + 1];
            break;
        default:
            throw new ArgumentException($"unknown option {args[i]}");
    }
}

var (validPri, validPub) = SM2.GenKeyPair();
var validSig = SM2.Sign("id", "message", validPri);
var validCipher = SM2.Encrypt("plaintext", validPub);
var validD = BigInt256.FromHex(validPri);
var validPoint = ECPoint.FromHexEncoded(validPub);
var sm4 = new SM4();
sm4.SetKey(new byte[16], new byte[16]);
var validSm4 = sm4.Encrypt("some plaintext for the mutator");
var exchangeB = SM2.GetSb(16, validPoint, validPoint, validPoint, validD, validPoint, validD, "a", "b");
var validSb = HexUtils.HexToBytes(exchangeB.Sb);

// --- generators ---

const string HexDigits = "0123456789abcdefABCDEF";
string[] oddChars = ["", " ", "\n", "\0", "g", "z", "h", "x", "0x", "-", "+", "é", "１", "\uD800", "\uDC00", "😀", "￿", "ـ"];

string RandomText(Random r)
{
    int kind = r.Next(4);
    int length = r.Next(5) == 0 ? r.Next(0, 9000) : r.Next(0, 80);
    var sb = new StringBuilder(length);
    for (int i = 0; i < length; i++)
    {
        sb.Append(kind switch
        {
            0 => (char)r.Next(0x20, 0x7F),
            1 => (char)r.Next(0, 0x10000),
            2 => HexDigits[r.Next(HexDigits.Length)],
            _ => "aé国😀"[r.Next(4)],
        });
    }
    return sb.ToString();
}

string? Mutate(Random r, string valid)
{
    var s = valid;
    int ops = r.Next(1, 4);
    for (int op = 0; op < ops; op++)
    {
        int at = s.Length == 0 ? 0 : r.Next(s.Length);
        s = r.Next(9) switch
        {
            0 => s.Length == 0 ? s : s[..at] + HexDigits[r.Next(HexDigits.Length)] + s[(at + 1)..],
            1 => s[..at] + oddChars[r.Next(oddChars.Length)] + s[at..],
            2 => s.Length == 0 ? s : s.Remove(at, 1),
            3 => s[..at],
            4 => s + new string('f', r.Next(1, 70)),
            5 => new string('0', r.Next(1, 70)) + s,
            6 => "0x" + s,
            7 => s.ToUpperInvariant(),
            _ => s.Length == 0 ? s : s[..at] + (char)r.Next(0, 0x10000) + s[(at + 1)..],
        };
    }
    return s;
}

string? HexInput(Random r, string valid)
{
    return r.Next(20) switch
    {
        0 => null,
        1 => "",
        2 or 3 => RandomText(r),
        4 => valid,
        _ => Mutate(r, valid),
    };
}

byte[] Bytes(Random r, int maximum)
{
    var b = new byte[r.Next(0, maximum)];
    r.NextBytes(b);
    return b;
}

BigInt256 Big(Random r)
{
    ulong Limb() => r.Next(4) switch
    {
        0 => 0,
        1 => ulong.MaxValue,
        2 => (ulong)r.Next(0, 3),
        _ => (ulong)r.NextInt64() ^ ((ulong)r.NextInt64() << 1),
    };
    return r.Next(6) switch
    {
        0 => BigInt256.Zero,
        1 => BigInt256.One,
        2 => ECPoint.SM2_N.Add(new BigInt256((ulong)r.Next(0, 4), 0, 0, 0), out _).Sub(new BigInt256(2, 0, 0, 0), out _),
        3 => FpElement.SM2_P.Sub(new BigInt256((ulong)r.Next(0, 3), 0, 0, 0), out _),
        _ => new BigInt256(Limb(), Limb(), Limb(), Limb()),
    };
}

FpElement Fe(Random r) => new() { Value = Big(r) };

ECPoint Pt(Random r)
{
    switch (r.Next(6))
    {
        case 0:
            return ECPoint.PointAtInfinity;
        case 1:
            return validPoint;
        case 2:
            return ECPoint.Generator();
        case 3:
            return new ECPoint { X = validPoint.X, Y = Fe(r), Infinity = r.Next(8) == 0 };
        default:
            return new ECPoint { X = Fe(r), Y = Fe(r), Infinity = r.Next(8) == 0 };
    }
}

byte[]? MaybeBytes(Random r, int maximum) => r.Next(20) == 0 ? null : Bytes(r, maximum);

byte[]? ThirtyTwoOrNot(Random r) => r.Next(3) == 0 ? MaybeBytes(r, 64) : (byte[])validSb.Clone();

string? MaybeId(Random r) => r.Next(10) switch
{
    0 => null,
    1 => new string('i', r.Next(8180, 8200)),
    2 => new string('国', r.Next(2720, 2740)),
    3 => "a\uD800",
    _ => RandomText(r),
};

int KeyLength(Random r) => r.Next(6) switch
{
    0 => int.MinValue,
    1 => int.MaxValue,
    2 => r.Next(),
    3 => -r.Next(),
    4 => 1024 * 1024 + r.Next(0, 3),
    _ => r.Next(0, 200),
};

// --- the table: name, function, and what it may throw ---

Type[] argumentOnly = [typeof(ArgumentException)];
Type[] argumentOrState = [typeof(ArgumentException), typeof(InvalidOperationException)];
Type[] nothing = [];

var table = new List<(string Name, Type[] Allowed, Action<Random> Run)>
{
    ("HexUtils.BytesToHex", argumentOnly, r => HexUtils.BytesToHex(r.Next(50) == 0 ? null! : Bytes(r, 300))),
    ("HexUtils.BytesToHexUpper", argumentOnly, r => HexUtils.BytesToHexUpper(r.Next(50) == 0 ? null! : Bytes(r, 300))),
    ("HexUtils.HexToBytes", argumentOnly, r => HexUtils.HexToBytes(HexInput(r, validPub)!)),
    ("BigInt256.FromHex", argumentOnly, r => BigInt256.FromHex(HexInput(r, validPri)!)),
    ("BigInt256.FromBEBytes", argumentOnly, r => BigInt256.FromBEBytes(MaybeBytes(r, 70)!)),
    ("BigInt256.ToBEBytes", nothing, r => Big(r).ToBEBytes()),
    ("BigInt256.ToHex", nothing, r => Big(r).ToHex()),
    ("BigInt256.ToHexLower", nothing, r => Big(r).ToHexLower()),
    ("BigInt256.Compare", nothing, r => Big(r).Compare(Big(r))),
    ("BigInt256.Add", nothing, r => Big(r).Add(Big(r), out _)),
    ("BigInt256.Sub", nothing, r => Big(r).Sub(Big(r), out _)),
    ("BigInt256.Mul", nothing, r => Big(r).Mul(Big(r))),
    ("BigInt256.ModAdd", nothing, r => Big(r).ModAdd(Big(r), Big(r))),
    ("BigInt256.ModSub", nothing, r => Big(r).ModSub(Big(r), Big(r))),
    ("BigInt256.ModMul", argumentOnly, r => Big(r).ModMul(Big(r), Big(r))),
    ("BigInt256.ModSquare", argumentOnly, r => Big(r).ModSquare(Big(r))),
    ("BigInt256.SM2ModMulP", nothing, r => Big(r).SM2ModMulP(Big(r))),
    ("BigInt256.SM2ModSquareP", nothing, r => Big(r).SM2ModSquareP()),
    ("BigInt256.ModInverse", argumentOnly, r => Big(r).ModInverse(r.Next(2) == 0 ? Big(r) : new BigInt256((ulong)r.Next(0, 1000), 0, 0, 0))),
    ("BigInt256.ModPow", argumentOnly, r => Big(r).ModPow(r.Next(50) == 0 ? Big(r) : new BigInt256((ulong)r.Next(0, 4096), 0, 0, 0), Big(r))),
    ("BigInt256.GetBit", nothing, r => Big(r).GetBit(r.Next(4) == 0 ? r.Next(int.MinValue, int.MaxValue) : r.Next(-5, 262))),
    ("BigInt256.BitLength", nothing, r => Big(r).BitLength()),
    ("BigInt256.And", nothing, r => Big(r).And(Big(r))),
    ("BigInt256.ShiftRight1", nothing, r => Big(r).ShiftRight1()),
    ("BigInt256.ShiftLeft1", nothing, r => Big(r).ShiftLeft1()),
    ("FpElement.ctor", argumentOnly, r => _ = new FpElement(Big(r))),
    ("FpElement.FromHex", argumentOnly, r => FpElement.FromHex(HexInput(r, validPri)!)),
    ("FpElement.Add", nothing, r => Fe(r).Add(Fe(r))),
    ("FpElement.Sub", nothing, r => Fe(r).Sub(Fe(r))),
    ("FpElement.Mul", nothing, r => Fe(r).Mul(Fe(r))),
    ("FpElement.Square", nothing, r => Fe(r).Square()),
    ("FpElement.Negate", nothing, r => Fe(r).Negate()),
    ("FpElement.Invert", argumentOrState, r => Fe(r).Invert()),
    ("FpElement.Div", argumentOrState, r => Fe(r).Div(Fe(r))),
    ("FpElement.Double", nothing, r => Fe(r).Double()),
    ("FpElement.Triple", nothing, r => Fe(r).Triple()),
    ("FpElement.ToBEBytes", nothing, r => Fe(r).ToBEBytes()),
    ("ECPoint.Create", argumentOnly, r => ECPoint.Create(Fe(r), Fe(r))),
    ("ECPoint.FromHex", argumentOnly, r => ECPoint.FromHex(HexInput(r, validPri)!, HexInput(r, validPri)!)),
    ("ECPoint.FromEncoded", argumentOnly, r => ECPoint.FromEncoded(r.Next(3) == 0 ? validPoint.ToEncoded() : MaybeBytes(r, 80)!)),
    ("ECPoint.FromHexEncoded", argumentOnly, r => ECPoint.FromHexEncoded(HexInput(r, validPub)!)),
    ("ECPoint.ToEncoded", nothing, r => Pt(r).ToEncoded()),
    ("ECPoint.ToHexEncoded", nothing, r => Pt(r).ToHexEncoded()),
    ("ECPoint.Negate", argumentOnly, r => Pt(r).Negate()),
    ("ECPoint.IsOnCurve", nothing, r => Pt(r).IsOnCurve()),
    ("ECPoint.Equal", nothing, r => Pt(r).Equal(Pt(r))),
    ("ECPoint.Add", argumentOnly, r => Pt(r).Add(Pt(r))),
    ("ECPoint.Twice", argumentOnly, r => Pt(r).Twice()),
    ("ECPoint.Subtract", argumentOnly, r => Pt(r).Subtract(Pt(r))),
    ("ECPoint.Multiply", argumentOnly, r => Pt(r).Multiply(Big(r))),
    ("SM2.GenKeyPair", nothing, _ => SM2.GenKeyPair()),
    ("SM2.Encrypt", argumentOnly, r => SM2.Encrypt(r.Next(4) == 0 ? MaybeId(r)! : "m", HexInput(r, validPub)!)),
    ("SM2.Decrypt", argumentOrState, r => SM2.Decrypt(HexInput(r, validCipher)!, r.Next(3) == 0 ? HexInput(r, validPri)! : validPri)),
    ("SM2.Sign", argumentOnly, r => SM2.Sign(MaybeId(r)!, r.Next(4) == 0 ? MaybeId(r)! : "m", r.Next(2) == 0 ? HexInput(r, validPri)! : validPri)),
    ("SM2.Verify", nothing, r => SM2.Verify(r.Next(4) == 0 ? MaybeId(r)! : "id", HexInput(r, validSig)!, r.Next(4) == 0 ? MaybeId(r)! : "message", r.Next(3) == 0 ? HexInput(r, validPub)! : validPub)),
    ("SM2.GetSb", nothing, r => SM2.GetSb(KeyLength(r), Pt(r), Pt(r), Pt(r), Big(r), Pt(r), Big(r), MaybeId(r)!, MaybeId(r)!)),
    ("SM2.GetSa", nothing, r => SM2.GetSa(KeyLength(r), Pt(r), Pt(r), Pt(r), Big(r), Pt(r), Big(r), MaybeId(r)!, MaybeId(r)!, ThirtyTwoOrNot(r)!)),
    ("SM2.CheckSa", nothing, r => SM2.CheckSa(Pt(r), ThirtyTwoOrNot(r)!, ThirtyTwoOrNot(r)!, Pt(r), Pt(r), ThirtyTwoOrNot(r)!)),
    ("SM2.DecodePoint", argumentOnly, r => SM2.DecodePoint(HexInput(r, validPub)!)),
    ("SM2.GetPublicKey", argumentOnly, r => SM2.GetPublicKey(Big(r))),
    ("SM3.UpdateByte", nothing, r =>
    {
        var h = new SM3();
        for (int i = r.Next(0, 130); i > 0; i--)
        {
            h.UpdateByte((byte)i);
        }
        h.Finish();
        h.HashHexUpper();
    }),
    ("SM3.Update", argumentOnly, r =>
    {
        var h = new SM3();
        h.Update(MaybeBytes(r, 300)!);
        h.Finish();
        h.Finish();
        h.HashBytes();
    }),
    ("SM4.SetKey", argumentOnly, r => new SM4().SetKey(MaybeBytes(r, 20)!, r.Next(2) == 0 ? new byte[16] : MaybeBytes(r, 20)!)),
    ("SM4.Encrypt", argumentOrState, r =>
    {
        var c = new SM4();
        if (r.Next(10) != 0)
        {
            c.SetKey(new byte[16], new byte[16]);
        }
        c.Encrypt(MaybeId(r)!);
    }),
    ("SM4.Decrypt", argumentOrState, r =>
    {
        var c = new SM4();
        if (r.Next(10) != 0)
        {
            c.SetKey(new byte[16], new byte[16]);
        }
        c.Decrypt(HexInput(r, validSm4)!);
    }),

    // Round-trip properties on valid data; any failure here is a defect, so nothing may be thrown.
    ("RoundTrip.Hex", nothing, r =>
    {
        var b = Bytes(r, 200);
        Require(HexUtils.HexToBytes(HexUtils.BytesToHex(b)).AsSpan().SequenceEqual(b));
        Require(HexUtils.HexToBytes(HexUtils.BytesToHexUpper(b)).AsSpan().SequenceEqual(b));
    }),
    ("RoundTrip.Sm4", nothing, r =>
    {
        var key = new byte[16];
        var iv = new byte[16];
        r.NextBytes(key);
        r.NextBytes(iv);
        var c = new SM4();
        c.SetKey(key, iv);
        var text = new string((char)r.Next(0x21, 0x7E), r.Next(0, 200));
        Require(c.Decrypt(c.Encrypt(text)) == text);
    }),
    ("RoundTrip.Sm2Encrypt", nothing, r =>
    {
        var text = new string((char)r.Next(0x21, 0x7E), r.Next(1, 200));
        Require(SM2.Decrypt(SM2.Encrypt(text, validPub), validPri) == text);
    }),
    ("RoundTrip.Sm2Sign", nothing, r =>
    {
        var text = new string((char)r.Next(0x21, 0x7E), r.Next(0, 200));
        var (pri, pub) = SM2.GenKeyPair();
        var signature = SM2.Sign("id", text, pri);
        Require(SM2.Verify("id", signature, text, pub));
        Require(!SM2.Verify("id", signature, text + "x", pub));
    }),
    ("RoundTrip.KeyExchange", nothing, r =>
    {
        var (da, pa) = SM2.GenKeyPair();
        var (ra, rap) = SM2.GenKeyPair();
        var (db, pb) = SM2.GenKeyPair();
        var (rb, rbp) = SM2.GenKeyPair();
        var pA = SM2.DecodePoint(pa);
        var rA = SM2.DecodePoint(rap);
        var pB = SM2.DecodePoint(pb);
        var rB = SM2.DecodePoint(rbp);
        int keyLength = r.Next(1, 100);
        var b = SM2.GetSb(keyLength, pA, rA, pB, BigInt256.FromHex(db), rB, BigInt256.FromHex(rb), "a", "b");
        Require(b.Success);
        var a = SM2.GetSa(keyLength, pB, rB, pA, BigInt256.FromHex(da), rA, BigInt256.FromHex(ra), "a", "b", HexUtils.HexToBytes(b.Sb));
        Require(a.Success && a.Ka == b.Kb);
        Require(SM2.CheckSa(b.V, b.Za, b.Zb, rA, rB, HexUtils.HexToBytes(a.Sa)));
    }),
};

// --- the runner ---

var failures = new ConcurrentQueue<string>();
var progress = new ConcurrentDictionary<string, long>();
var results = new ConcurrentBag<(string Name, long Cases, long Rejected, double Seconds)>();
var selected = table.Where(t => filter == null || t.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
var all = Stopwatch.StartNew();
using var done = new CancellationTokenSource();

// Watchdog: a case that never returns would stall a function's counter while the rest finish.
var watchdog = Task.Run(async () =>
{
    var last = new Dictionary<string, (long Count, long Time)>();
    while (!done.IsCancellationRequested)
    {
        await Task.Delay(5000);
        foreach (var (name, count) in progress)
        {
            if (count < cases && last.TryGetValue(name, out var previous) && previous.Count == count)
            {
                if (all.ElapsedMilliseconds - previous.Time > 300_000)
                {
                    Console.Error.WriteLine($"HANG in {name} after {count} cases");
                    Environment.Exit(2);
                }
                continue;
            }
            last[name] = (count, all.ElapsedMilliseconds);
        }
    }
});

Parallel.ForEach(selected, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, entry =>
{
    var random = new Random(HashCode.Combine(seed, StableHash(entry.Name)));
    var watch = Stopwatch.StartNew();
    long rejected = 0;
    for (int i = 0; i < cases; i++)
    {
        progress[entry.Name] = i;
        try
        {
            entry.Run(random);
        }
        catch (Exception ex) when (entry.Allowed.Any(t => t.IsInstanceOfType(ex)))
        {
            rejected++;
        }
        catch (Exception ex)
        {
            failures.Enqueue($"{entry.Name} case {i}: {ex.GetType().Name}: {ex.Message}");
            if (failures.Count > 40)
            {
                break;
            }
        }
    }
    progress[entry.Name] = cases;
    results.Add((entry.Name, cases, rejected, watch.Elapsed.TotalSeconds));
});
done.Cancel();

foreach (var r in results.OrderBy(r => r.Name, StringComparer.Ordinal))
{
    Console.WriteLine($"{r.Name,-28} {r.Cases,9} cases {r.Rejected,9} rejected {r.Seconds,8:F1} s");
}
Console.WriteLine($"{selected.Count} functions, {cases} cases each, seed {seed}, {all.Elapsed.TotalSeconds:F0} s, {failures.Count} failures");
foreach (var f in failures.Take(40))
{
    Console.WriteLine(f);
}
return failures.IsEmpty ? 0 : 1;

static void Require(bool condition)
{
    if (!condition)
    {
        throw new InvalidDataException("round-trip property failed");
    }
}

static int StableHash(string s)
{
    int h = 17;
    foreach (char c in s)
    {
        h = h * 31 + c;
    }
    return h;
}
