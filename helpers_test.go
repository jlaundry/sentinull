package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	validRuleID = "dcr-accepted"
	validStream = "Custom-MyTable"
	validPath   = "/dataCollectionRules/" + validRuleID + "/streams/" + validStream + "?api-version=2023-01-01"
)

var validBody = `[{"TimeGenerated":"2023-11-14 15:10:02","Column01":"val"}]`

// makeJWT builds an unsigned JWT with the given claims, sufficient for emulator tests.
func makeJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	return "Bearer " + header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".fake"
}

// postUpload creates a POST request to the upload endpoint and returns the recorder.
func postUpload(t *testing.T, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	return postUploadWithConfig(t, path, body, headers, defaultConfig())
}

// postUploadWithConfig is like postUpload but uses a custom server config.
func postUploadWithConfig(t *testing.T, path, body string, headers map[string]string, cfg config) *httptest.ResponseRecorder {
	t.Helper()

	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(http.MethodPost, path, nil)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rr := httptest.NewRecorder()
	newMux(cfg).ServeHTTP(rr, req)
	return rr
}

// postUploadBytes sends a raw byte slice body, used for pre-compressed payloads.
func postUploadBytes(t *testing.T, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	newMux(defaultConfig()).ServeHTTP(rr, req)
	return rr
}

// gzipBytes compresses b using gzip and returns the compressed bytes.
func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// validHeaders returns the minimum set of headers for a well-formed request.
func validHeaders() map[string]string {
	return map[string]string{
		"Authorization": makeJWT(map[string]any{
			"aud": "https://monitor.azure.com/.default",
			"exp": 9999999999,
			"nbf": 0,
		}),
		"Content-Type": "application/json",
	}
}

// assertStatus checks the HTTP status code.
func assertStatus(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Fatalf("status: got %d, want %d\nbody: %s", rr.Code, want, rr.Body.String())
	}
}

// assertErrorResponse checks the full SDK-compatible error envelope:
// status code, x-ms-error-code header, and JSON body error.code.
func assertErrorResponse(t *testing.T, rr *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()

	assertStatus(t, rr, wantStatus)

	gotHeader := rr.Header().Get("x-ms-error-code")
	if gotHeader != wantCode {
		t.Fatalf("x-ms-error-code: got %q, want %q", gotHeader, wantCode)
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("error body is not valid JSON: %v\nbody: %s", err, rr.Body.String())
	}

	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error object in body: %s", rr.Body.String())
	}

	gotCode, ok := errObj["code"].(string)
	if !ok || gotCode != wantCode {
		t.Fatalf("error.code: got %q, want %q", gotCode, wantCode)
	}

	if _, ok := errObj["message"].(string); !ok {
		t.Fatal("error.message missing or not a string")
	}
}
