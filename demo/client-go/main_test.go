package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"smx"
	"strings"
	"testing"
	"time"
)

func serve(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestServerKeyPinning(t *testing.T) {
	_, pubA, err := smx.SM2GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, pubB, err := smx.SM2GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	a, b := smx.SM2DecodePoint(pubA), smx.SM2DecodePoint(pubB)

	pinned, err := loadPinnedKey(pubA)
	if err != nil || pinned == nil {
		t.Fatalf("valid pin: %v", err)
	}
	if err := checkServerKey(pinned, a); err != nil {
		t.Errorf("matching key rejected: %v", err)
	}
	if err := checkServerKey(pinned, b); err == nil {
		t.Error("different key accepted")
	}
	if err := checkServerKey(pinned, smx.ECPointInfinity()); err == nil {
		t.Error("infinity accepted")
	}
	// Unset means no pin; invalid values never silently mean no pin.
	if p, err := loadPinnedKey(""); p != nil || err != nil {
		t.Errorf("unset: %v, %v", p, err)
	}
	if err := checkServerKey(nil, b); err != nil {
		t.Errorf("no pin: %v", err)
	}
	for _, bad := range []string{"zz", "04", pubA + "00", pubA[:128], " " + pubA} {
		if p, err := loadPinnedKey(bad); err == nil || p != nil {
			t.Errorf("invalid pin %q accepted", bad)
		}
	}
}

func TestOnlyRealBooleanCountsAsSuccess(t *testing.T) {
	for body, want := range map[string]bool{
		`{"success":true}`:    true,
		`{"success":false}`:   false,
		`{}`:                  false,
		`{"success":null}`:    false,
		`{"success":"true"}`:  false,
		`{"success":"false"}`: false,
		`{"success":1}`:       false,
		`[]`:                  false,
		`true`:                false,
		`not json`:            false,
	} {
		body := body
		url := serve(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
		var resp confirmResponse
		err := postJSON(context.Background(), url, confirmRequest{}, &resp)
		if got := err == nil && resp.Success; got != want {
			t.Errorf("%s: success = %v, err = %v", body, got, err)
		}
	}
}

func TestPostJSONRejectsBadResponses(t *testing.T) {
	var out initResponse
	over := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"sessionId":"` + strings.Repeat("x", maxResponseBytes) + `"}`))
	})
	if err := postJSON(context.Background(), over, initRequest{}, &out); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("oversized response: %v", err)
	}
	status := serve(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	if err := postJSON(context.Background(), status, initRequest{}, &out); err == nil {
		t.Error("error status accepted")
	}
	deep := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("[", 200000)))
	})
	if err := postJSON(context.Background(), deep, initRequest{}, &out); err == nil {
		t.Error("deep JSON accepted")
	}
}

// A server sending one byte at a time must not outlast the overall deadline.
func TestDeadlineStopsDripFeed(t *testing.T) {
	url := serve(t, func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		for {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
				_, _ = w.Write([]byte(" "))
				flusher.Flush()
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	var out initResponse
	err := postJSON(ctx, url, initRequest{}, &out)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v", elapsed)
	}
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":             "plain text",
		"\u4e2d\u6587 ok":        "\u4e2d\u6587 ok",
		"\x1b[31mred\x1b[0m":     "[31mred[0m",
		"a\rb\nc\td\x00e\x7f":    "abcde",
		"\u009b31m":              "31m",
		"bidi\u202eoverride":     "bidioverride",
		"bad\xff\xfeutf8":        "badutf8",
		"zero\u200bwidth\ufeffx": "zerowidthx",
		"\ufffdreplacement":      "replacement",
	} {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
