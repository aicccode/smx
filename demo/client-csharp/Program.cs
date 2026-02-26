using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SMX;

const string serverUrl = "http://localhost:8080";
const string ida = "csharp-client@demo.aicc";

Console.WriteLine("=== SM2 Key Exchange Demo (C# Client) ===");
Console.WriteLine();

// Generate A-side certificate keypair
var (daHex, paHex) = SM2.GenKeyPair();
Console.WriteLine("Generated A certificate keypair:");
Console.WriteLine($"  Private key (dA): {daHex}");
Console.WriteLine($"  Public key (pA): {paHex}");

// Generate A-side random keypair
var (raHex, raPubHex) = SM2.GenKeyPair();
Console.WriteLine("\nGenerated A random keypair:");
Console.WriteLine($"  Private key (ra): {raHex}");
Console.WriteLine($"  Public key (Ra): {raPubHex}");

int keyLen = 16;

using var http = new HttpClient(new HttpClientHandler { UseProxy = false });

async Task<T> PostJson<T>(string url, object req)
{
    var json = JsonSerializer.Serialize(req);
    var content = new StringContent(json, Encoding.UTF8, "application/json");
    var response = await http.PostAsync(url, content);
    var respJson = await response.Content.ReadAsStringAsync();
    Console.WriteLine($"Response: {respJson}");
    return JsonSerializer.Deserialize<T>(respJson)!;
}

// Step 1: Key Exchange Init
Console.WriteLine("\n--- Step 1: Key Exchange Init ---");
var initReq = new InitRequest { IDa = ida, PA = paHex, Ra = raPubHex, KeyLen = keyLen };
Console.WriteLine($"Request: {JsonSerializer.Serialize(initReq)}");

InitResponse initResp;
try
{
    initResp = await PostJson<InitResponse>($"{serverUrl}/api/keyswap/init", initReq);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Failed to connect to server: {ex.Message}");
    Console.Error.WriteLine("Make sure the Java server is running on port 8080");
    return 1;
}

// Step 2: Calculate Sa and Ka
Console.WriteLine("\n--- Step 2: Calculate Sa and Ka ---");

var pB = SMX.ECPoint.FromHexEncoded(initResp.PB);
var rB = SMX.ECPoint.FromHexEncoded(initResp.RB);
var pA = SMX.ECPoint.FromHexEncoded(paHex);
var rA = SMX.ECPoint.FromHexEncoded(raPubHex);
var dA = BigInt256.FromHex(daHex);
var ra = BigInt256.FromHex(raHex);
var sbBytes = HexUtils.HexToBytes(initResp.Sb);

var result = SM2.GetSa(keyLen, pB, rB, pA, dA, rA, ra, ida, initResp.IDb, sbBytes);
if (!result.Success)
{
    Console.Error.WriteLine($"getSa failed: {result.Message}");
    return 1;
}

Console.WriteLine($"Sa: {result.Sa}");
Console.WriteLine($"Ka (negotiated key): {result.Ka}");

// Step 3: Key Exchange Confirm
Console.WriteLine("\n--- Step 3: Key Exchange Confirm ---");
var confirmReq = new ConfirmRequest { SessionId = initResp.SessionId, Sa = result.Sa };
Console.WriteLine($"Request: {JsonSerializer.Serialize(confirmReq)}");

var confirmResp = await PostJson<ConfirmResponse>($"{serverUrl}/api/keyswap/confirm", confirmReq);

if (!confirmResp.Success)
{
    Console.Error.WriteLine("Key exchange confirmation failed");
    return 1;
}

Console.WriteLine("\nKey exchange completed successfully!");
Console.WriteLine($"Negotiated key (Ka): {result.Ka}");

// Step 4: Bidirectional Crypto Test
Console.WriteLine("\n--- Step 4: Bidirectional Crypto Test ---");

var kaBytes = HexUtils.HexToBytes(result.Ka);
var ivBytes = new byte[16]; // all zeros
var sm4 = new SM4();
sm4.SetKey(kaBytes, ivBytes);

string clientPlaintext = "Hello from C# Client!";
string clientCiphertext = sm4.Encrypt(clientPlaintext);
Console.WriteLine($"Client plaintext: {clientPlaintext}");
Console.WriteLine($"Client ciphertext: {clientCiphertext}");

var cryptoReq = new CryptoTestRequest
{
    SessionId = initResp.SessionId,
    ClientCiphertext = clientCiphertext,
    ClientPlaintext = clientPlaintext
};
Console.WriteLine($"\nRequest: {JsonSerializer.Serialize(cryptoReq)}");

var cryptoResp = await PostJson<CryptoTestResponse>($"{serverUrl}/api/crypto/test", cryptoReq);

// Verify server correctly decrypted client's message
bool serverDecryptOk = cryptoResp.ClientDecryptMatch;
Console.WriteLine(serverDecryptOk
    ? "\n[Server decrypted client message]: PASS"
    : "\n[Server decrypted client message]: FAIL");

// Client decrypts server's message
string serverDecrypted = sm4.Decrypt(cryptoResp.ServerCiphertext);
bool clientDecryptOk = serverDecrypted == cryptoResp.ServerPlaintext;
Console.WriteLine(clientDecryptOk
    ? "[Client decrypted server message]: PASS"
    : "[Client decrypted server message]: FAIL");
Console.WriteLine($"  Server plaintext: {cryptoResp.ServerPlaintext}");
Console.WriteLine($"  Client decrypted: {serverDecrypted}");

if (serverDecryptOk && clientDecryptOk)
{
    Console.WriteLine("\nBidirectional Crypto test PASSED!");
}
else
{
    Console.Error.WriteLine("\nBidirectional Crypto test FAILED!");
    return 1;
}

Console.WriteLine("\n=== Demo Complete ===");
return 0;

// --- DTO classes with explicit JSON property names ---

class InitRequest
{
    [JsonPropertyName("IDa")] public string IDa { get; set; } = "";
    [JsonPropertyName("pA")] public string PA { get; set; } = "";
    [JsonPropertyName("Ra")] public string Ra { get; set; } = "";
    [JsonPropertyName("keyLen")] public int KeyLen { get; set; }
}

class InitResponse
{
    [JsonPropertyName("sessionId")] public string SessionId { get; set; } = "";
    [JsonPropertyName("IDb")] public string IDb { get; set; } = "";
    [JsonPropertyName("pB")] public string PB { get; set; } = "";
    [JsonPropertyName("Rb")] public string RB { get; set; } = "";
    [JsonPropertyName("Sb")] public string Sb { get; set; } = "";
}

class ConfirmRequest
{
    [JsonPropertyName("sessionId")] public string SessionId { get; set; } = "";
    [JsonPropertyName("Sa")] public string Sa { get; set; } = "";
}

class ConfirmResponse
{
    [JsonPropertyName("success")] public bool Success { get; set; }
}

class CryptoTestRequest
{
    [JsonPropertyName("sessionId")] public string SessionId { get; set; } = "";
    [JsonPropertyName("clientCiphertext")] public string ClientCiphertext { get; set; } = "";
    [JsonPropertyName("clientPlaintext")] public string ClientPlaintext { get; set; } = "";
}

class CryptoTestResponse
{
    [JsonPropertyName("clientDecrypted")] public string ClientDecrypted { get; set; } = "";
    [JsonPropertyName("clientDecryptMatch")] public bool ClientDecryptMatch { get; set; }
    [JsonPropertyName("serverPlaintext")] public string ServerPlaintext { get; set; } = "";
    [JsonPropertyName("serverCiphertext")] public string ServerCiphertext { get; set; } = "";
}
