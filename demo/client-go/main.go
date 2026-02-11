package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"smx"
)

const serverURL = "http://localhost:8080"
const ida = "go-client@demo.aicc"

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
	SessionID       string `json:"sessionId"`
	ClientCiphertext string `json:"clientCiphertext"`
	ClientPlaintext  string `json:"clientPlaintext"`
}

type cryptoTestResponse struct {
	ClientDecrypted    string `json:"clientDecrypted"`
	ClientDecryptMatch bool   `json:"clientDecryptMatch"`
	ServerPlaintext    string `json:"serverPlaintext"`
	ServerCiphertext   string `json:"serverCiphertext"`
}

func postJSON(url string, req any, resp any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpResp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	data, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, resp)
}

func hexToBytes(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			switch {
			case c >= '0' && c <= '9':
				v = v*16 + (c - '0')
			case c >= 'a' && c <= 'f':
				v = v*16 + (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				v = v*16 + (c - 'A' + 10)
			}
		}
		b[i/2] = v
	}
	return b
}

func main() {
	fmt.Println("=== SM2 Key Exchange Demo (Go Client) ===")
	fmt.Println()

	// Generate A-side certificate keypair
	daHex, paHex := smx.SM2GenKeyPair()
	fmt.Println("Generated A certificate keypair:")
	fmt.Printf("  Private key (dA): %s\n", daHex)
	fmt.Printf("  Public key (pA): %s\n", paHex)

	// Generate A-side random keypair
	raHex, raPubHex := smx.SM2GenKeyPair()
	fmt.Println("\nGenerated A random keypair:")
	fmt.Printf("  Private key (ra): %s\n", raHex)
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
	if err := postJSON(serverURL+"/api/keyswap/init", initReq, &initResp); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to server: %v\n", err)
		fmt.Fprintln(os.Stderr, "Make sure the Java server is running on port 8080")
		os.Exit(1)
	}
	respJSON, _ := json.Marshal(initResp)
	fmt.Printf("Response: %s\n", respJSON)

	// Step 2: Calculate Sa and Ka
	fmt.Println("\n--- Step 2: Calculate Sa and Ka ---")

	pB := smx.SM2DecodePoint(initResp.PB)
	rB := smx.SM2DecodePoint(initResp.RB)
	pA := smx.SM2DecodePoint(paHex)
	rA := smx.SM2DecodePoint(raPubHex)
	dA := smx.BigInt256FromHex(daHex)
	ra := smx.BigInt256FromHex(raHex)
	sbBytes := hexToBytes(initResp.Sb)

	result := smx.SM2GetSa(keyLen, pB, rB, pA, &dA, rA, &ra, ida, initResp.IDb, sbBytes)
	if !result.Success {
		fmt.Fprintf(os.Stderr, "getSa failed: %s\n", result.Message)
		os.Exit(1)
	}

	fmt.Printf("Sa: %s\n", result.Sa)
	fmt.Printf("Ka (negotiated key): %s\n", result.Ka)

	// Step 3: Key Exchange Confirm
	fmt.Println("\n--- Step 3: Key Exchange Confirm ---")
	confirmReq := confirmRequest{
		SessionID: initResp.SessionID,
		Sa:        result.Sa,
	}
	cReqJSON, _ := json.Marshal(confirmReq)
	fmt.Printf("Request: %s\n", cReqJSON)

	var confirmResp confirmResponse
	if err := postJSON(serverURL+"/api/keyswap/confirm", confirmReq, &confirmResp); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send confirm request: %v\n", err)
		os.Exit(1)
	}
	cRespJSON, _ := json.Marshal(confirmResp)
	fmt.Printf("Response: %s\n", cRespJSON)

	if !confirmResp.Success {
		fmt.Fprintln(os.Stderr, "Key exchange confirmation failed")
		os.Exit(1)
	}

	fmt.Println("\nKey exchange completed successfully!")
	fmt.Printf("Negotiated key (Ka): %s\n", result.Ka)

	// Step 4: Bidirectional Crypto Test
	fmt.Println("\n--- Step 4: Bidirectional Crypto Test ---")

	// Initialize SM4 with negotiated key and zero IV
	kaBytes := hexToBytes(result.Ka)
	ivBytes := make([]byte, 16) // all zeros
	sm4 := smx.NewSM4()
	sm4.SetKey(kaBytes, ivBytes)

	// Client encrypts a message
	clientPlaintext := "Hello from Go Client!"
	clientCiphertext, err := sm4.Encrypt(clientPlaintext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encrypt: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Client plaintext: %s\n", clientPlaintext)
	fmt.Printf("Client ciphertext: %s\n", clientCiphertext)

	// Send to server
	cryptoReq := cryptoTestRequest{
		SessionID:       initResp.SessionID,
		ClientCiphertext: clientCiphertext,
		ClientPlaintext:  clientPlaintext,
	}
	crReqJSON, _ := json.Marshal(cryptoReq)
	fmt.Printf("\nRequest: %s\n", crReqJSON)

	var cryptoResp cryptoTestResponse
	if err := postJSON(serverURL+"/api/crypto/test", cryptoReq, &cryptoResp); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to send crypto request: %v\n", err)
		os.Exit(1)
	}
	crRespJSON, _ := json.Marshal(cryptoResp)
	fmt.Printf("Response: %s\n", crRespJSON)

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
		fmt.Fprintf(os.Stderr, "Failed to decrypt: %v\n", err)
		os.Exit(1)
	}
	clientDecryptOk := serverDecrypted == cryptoResp.ServerPlaintext
	if clientDecryptOk {
		fmt.Println("[Client decrypted server message]: PASS")
	} else {
		fmt.Println("[Client decrypted server message]: FAIL")
	}
	fmt.Printf("  Server plaintext: %s\n", cryptoResp.ServerPlaintext)
	fmt.Printf("  Client decrypted: %s\n", serverDecrypted)

	if serverDecryptOk && clientDecryptOk {
		fmt.Println("\nBidirectional Crypto test PASSED!")
	} else {
		fmt.Fprintln(os.Stderr, "\nBidirectional Crypto test FAILED!")
		os.Exit(1)
	}

	fmt.Println("\n=== Demo Complete ===")
}
