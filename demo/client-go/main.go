// Command client-go demonstrates SM2 key exchange and SM4 encryption against the demo
// server.
//
// DEMO ONLY: it talks plain HTTP, uses a fixed all-zero IV as the protocol defines, and
// SM4-CBC gives no integrity. A real deployment needs TLS, a fresh random IV per message
// and authenticated ciphertexts.
//
// The server's public key arrives in the same unauthenticated response as everything
// else, so by default an impostor can complete the exchange and read the traffic. Set
// SM2_DEMO_SERVER_PUBKEY to the server's public key hex to pin it: any other key is then a
// hard failure. Without it the client warns that the server is UNAUTHENTICATED.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"smx"
	"strings"
	"time"
	"unicode"
)

const (
	serverURL = "http://localhost:8080"
	ida       = "go-client@demo.aicc"

	// maxResponseBytes bounds what a misbehaving server can make the client read.
	maxResponseBytes = 1 << 20

	// overallDeadline bounds the whole run, including servers that send one byte at a time.
	overallDeadline = 60 * time.Second

	// pinnedKeyEnv names the variable holding the expected server public key.
	pinnedKeyEnv = "SM2_DEMO_SERVER_PUBKEY"
)

type initRequest struct {
	IDa    string `json:"IDa"`
	PA     string `json:"pA"`
	RA     string `json:"Ra"`
	KeyLen int    `json:"keyLen"`
}

type initResponse struct {
	SessionID string `json:"sessionId"`
	IDb       string `json:"IDb"`
	PB        string `json:"pB"`
	RB        string `json:"Rb"`
	Sb        string `json:"Sb"`
}

type confirmRequest struct {
	SessionID string `json:"sessionId"`
	Sa        string `json:"Sa"`
}

type confirmResponse struct {
	Success bool `json:"success"`
}

type cryptoTestRequest struct {
	SessionID        string `json:"sessionId"`
	ClientCiphertext string `json:"clientCiphertext"`
	ClientPlaintext  string `json:"clientPlaintext"`
}

type cryptoTestResponse struct {
	ClientDecrypted    string `json:"clientDecrypted"`
	ClientDecryptMatch bool   `json:"clientDecryptMatch"`
	ServerPlaintext    string `json:"serverPlaintext"`
	ServerCiphertext   string `json:"serverCiphertext"`
}

func postJSON(ctx context.Context, url string, req any, resp any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", httpResp.StatusCode)
	}
	// One byte over the limit tells a truncated body from a complete one.
	data, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return errors.New("response too large")
	}
	if err := json.Unmarshal(data, resp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// sanitize removes what could drive a terminal from text that came from the server:
// control and format characters, including escape sequences and direction overrides, and
// invalid UTF-8. Line breaks in our own messages are added after this.
func sanitize(text string) string {
	return strings.Map(func(r rune) rune {
		if r == unicode.ReplacementChar || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(text, ""))
}

// loadPinnedKey reads the optional pinned server key. It returns nil if none is set, and
// an error if the value is not a valid public key.
func loadPinnedKey(value string) (*smx.ECPoint, error) {
	if value == "" {
		return nil, nil
	}
	pinned, err := smx.SM2ParsePublicKey(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid public key: %w", pinnedKeyEnv, err)
	}
	return &pinned, nil
}

// checkServerKey fails if a key is pinned and the server presented a different one.
func checkServerKey(pinned *smx.ECPoint, presented smx.ECPoint) error {
	if pinned != nil && !pinned.Equal(presented) {
		return errors.New("server public key does not match " + pinnedKeyEnv + ": refusing to continue")
	}
	return nil
}

// fail prints a message that must not contain secrets and exits.
func fail(format string, args ...any) {
	fmt.Fprintln(os.Stderr, sanitize(fmt.Sprintf(format, args...)))
	os.Exit(1)
}

func main() {
	fmt.Println("=== SM2 Key Exchange Demo (Go Client) ===")
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), overallDeadline)
	defer cancel()

	pinned, err := loadPinnedKey(os.Getenv(pinnedKeyEnv))
	if err != nil {
		fail("%v", err)
	}
	if pinned == nil {
		fmt.Printf("WARNING: server is UNAUTHENTICATED: %s is not set, so an impostor could complete this exchange.\n\n", pinnedKeyEnv)
	}

	// Generate A-side certificate keypair
	daHex, paHex, err := smx.SM2GenerateKeyPair()
	if err != nil {
		fail("Failed to generate keypair: %v", err)
	}
	fmt.Println("Generated A certificate keypair:")
	fmt.Printf("  Public key (pA): %s\n", paHex)

	// Generate A-side random keypair
	raHex, raPubHex, err := smx.SM2GenerateKeyPair()
	if err != nil {
		fail("Failed to generate keypair: %v", err)
	}
	fmt.Println("\nGenerated A random keypair:")
	fmt.Printf("  Public key (Ra): %s\n", raPubHex)

	keyLen := 16

	// Step 1: Key Exchange Init
	fmt.Println("\n--- Step 1: Key Exchange Init ---")
	initReq := initRequest{
		IDa:    ida,
		PA:     paHex,
		RA:     raPubHex,
		KeyLen: keyLen,
	}
	reqJSON, _ := json.Marshal(initReq)
	fmt.Printf("Request: %s\n", reqJSON)

	var initResp initResponse
	if err := postJSON(ctx, serverURL+"/api/keyswap/init", initReq, &initResp); err != nil {
		fail("Failed to connect to server: %v\nMake sure the Java server is running on port 8080", err)
	}
	respJSON, _ := json.Marshal(initResp)
	fmt.Printf("Response: %s\n", sanitize(string(respJSON)))

	// Step 2: Calculate Sa and Ka
	fmt.Println("\n--- Step 2: Calculate Sa and Ka ---")

	pB, err := smx.SM2ParsePublicKey(initResp.PB)
	if err != nil {
		fail("Server sent an invalid pB: %v", err)
	}
	if err := checkServerKey(pinned, pB); err != nil {
		fail("%v", err)
	}
	rB, err := smx.SM2ParsePublicKey(initResp.RB)
	if err != nil {
		fail("Server sent an invalid Rb: %v", err)
	}
	pA := smx.SM2DecodePoint(paHex)
	rA := smx.SM2DecodePoint(raPubHex)
	dA := smx.BigInt256FromHex(daHex)
	ra := smx.BigInt256FromHex(raHex)
	sbBytes, err := hex.DecodeString(initResp.Sb)
	if err != nil {
		fail("Server sent an invalid Sb")
	}

	result := smx.SM2GetSa(keyLen, pB, rB, pA, &dA, rA, &ra, ida, initResp.IDb, sbBytes)
	if !result.Success {
		fail("getSa failed: %s", result.Message)
	}

	fmt.Printf("Sa: %s\n", result.Sa)
	fmt.Println("Ka negotiated (not printed: it is a secret)")

	// Step 3: Key Exchange Confirm
	fmt.Println("\n--- Step 3: Key Exchange Confirm ---")
	confirmReq := confirmRequest{
		SessionID: initResp.SessionID,
		Sa:        result.Sa,
	}
	cReqJSON, _ := json.Marshal(confirmReq)
	fmt.Printf("Request: %s\n", cReqJSON)

	var confirmResp confirmResponse
	if err := postJSON(ctx, serverURL+"/api/keyswap/confirm", confirmReq, &confirmResp); err != nil {
		fail("Failed to send confirm request: %v", err)
	}
	cRespJSON, _ := json.Marshal(confirmResp)
	fmt.Printf("Response: %s\n", sanitize(string(cRespJSON)))

	if !confirmResp.Success {
		fail("Key exchange confirmation failed")
	}

	if pinned != nil {
		fmt.Println("\nKey exchange completed with the pinned server key.")
	} else {
		fmt.Println("\nKey exchange completed, but the server is UNAUTHENTICATED.")
	}

	// Step 4: Bidirectional Crypto Test
	fmt.Println("\n--- Step 4: Bidirectional Crypto Test ---")

	// Initialize SM4 with negotiated key and zero IV
	kaBytes, err := hex.DecodeString(result.Ka)
	if err != nil {
		fail("Invalid negotiated key")
	}
	ivBytes := make([]byte, 16) // all zeros: acceptable only because the demo's key is per-session
	sm4 := smx.NewSM4()
	if err := sm4.TrySetKey(kaBytes, ivBytes); err != nil {
		fail("Failed to set key: %v", err)
	}

	// Client encrypts a message
	clientPlaintext := "Hello from Go Client!"
	clientCiphertext, err := sm4.Encrypt(clientPlaintext)
	if err != nil {
		fail("Failed to encrypt: %v", err)
	}
	fmt.Printf("Client plaintext: %s\n", clientPlaintext)
	fmt.Printf("Client ciphertext: %s\n", clientCiphertext)

	// Send to server
	cryptoReq := cryptoTestRequest{
		SessionID:        initResp.SessionID,
		ClientCiphertext: clientCiphertext,
		ClientPlaintext:  clientPlaintext,
	}
	crReqJSON, _ := json.Marshal(cryptoReq)
	fmt.Printf("\nRequest: %s\n", crReqJSON)

	var cryptoResp cryptoTestResponse
	if err := postJSON(ctx, serverURL+"/api/crypto/test", cryptoReq, &cryptoResp); err != nil {
		fail("Failed to send crypto request: %v", err)
	}
	crRespJSON, _ := json.Marshal(cryptoResp)
	fmt.Printf("Response: %s\n", sanitize(string(crRespJSON)))

	// Verify server correctly decrypted client's message
	serverDecryptOk := cryptoResp.ClientDecryptMatch
	if serverDecryptOk {
		fmt.Println("\n[Server decrypted client message]: PASS")
	} else {
		fmt.Println("\n[Server decrypted client message]: FAIL")
	}

	// Client decrypts server's message
	serverDecrypted, err := sm4.Decrypt(cryptoResp.ServerCiphertext)
	if err != nil {
		fail("Failed to decrypt: %v", err)
	}
	clientDecryptOk := serverDecrypted == cryptoResp.ServerPlaintext
	if clientDecryptOk {
		fmt.Println("[Client decrypted server message]: PASS")
	} else {
		fmt.Println("[Client decrypted server message]: FAIL")
	}
	fmt.Printf("  Server plaintext: %s\n", sanitize(cryptoResp.ServerPlaintext))
	fmt.Printf("  Client decrypted: %s\n", sanitize(serverDecrypted))

	if serverDecryptOk && clientDecryptOk {
		fmt.Println("\nBidirectional Crypto test PASSED!")
	} else {
		fail("\nBidirectional Crypto test FAILED!")
	}

	fmt.Println("\n=== Demo Complete ===")
}
