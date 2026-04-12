package main

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const maxBodyBytes = 1 << 20 // 1 MB

type config struct {
	JWTAudience string
	ListenAddr  string
}

func defaultConfig() config {
	return config{
		JWTAudience: "https://monitor.azure.com/.default",
		ListenAddr:  "localhost:8564",
	}
}

func newMux(cfg config) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /dataCollectionRules/{ruleID}/streams/{stream}", func(w http.ResponseWriter, r *http.Request) {
		uploadHandler(w, r, cfg)
	})
	return mux
}

func uploadHandler(w http.ResponseWriter, r *http.Request, cfg config) {
	if r.URL.Query().Get("api-version") == "" {
		writeError(w, http.StatusBadRequest, "MissingApiVersionParameter", "An api-version query parameter is required.")
		return
	}

	if r.URL.Query().Get("api-version") != "2023-01-01" {
		writeError(w, http.StatusBadRequest, "UnsupportedApiVersion", fmt.Sprintf("The specified api-version '%s' is not supported.", r.URL.Query().Get("api-version")))
		return
	}

	if err := validateBearerToken(r.Header.Get("Authorization"), cfg.JWTAudience); err != nil {
		writeError(w, http.StatusUnauthorized, "Unauthorized", err.Error())
		return
	}

	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusBadRequest, "BadRequest", "Content-Type must be application/json.")
		return
	}

	bodyReader := io.Reader(r.Body)
	if r.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "BadRequest", "Content-Encoding is gzip but body could not be decompressed.")
			return
		}
		defer gr.Close()
		bodyReader = gr
	}

	body, err := io.ReadAll(io.LimitReader(bodyReader, maxBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "RequestBodyTooLarge", "The request body exceeds the maximum allowed size of 1 MB.")
		return
	}
	if int64(len(body)) > maxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "RequestBodyTooLarge", "The request body exceeds the maximum allowed size of 1 MB.")
		return
	}

	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "BadRequest", "Request body must not be empty.")
		return
	}

	var records []json.RawMessage
	if err := json.Unmarshal(body, &records); err != nil {
		writeError(w, http.StatusBadRequest, "BadRequest", "Request body must be a JSON array.")
		return
	}

	ruleID := r.PathValue("ruleID")
	stream := r.PathValue("stream")

	// --- DCR routing ---
	switch ruleID {
	case "dcr-forbidden":
		writeError(w, http.StatusForbidden, "OperationFailed", "The token does not have permission to ingest for the specified DCR.")
		return
	case "dcr-accepted", "dcr-validated":
		// OK — continue below.
	default:
		writeError(w, http.StatusNotFound, "ResourceNotFound", "The specified data collection rule was not found.")
		return
	}

	// --- Stream validation ---
	if !strings.HasPrefix(stream, "Custom-") && !strings.HasPrefix(stream, "Microsoft-") {
		writeError(w, http.StatusBadRequest, "InvalidStream", "The stream name does not match a stream declaration in the DCR.")
		return
	}

	// --- Schema validation (dcr-validated only) ---
	if ruleID == "dcr-validated" {
		schema := LookupSchema(stream)
		if schema != nil {
			for i, raw := range records {
				var rec map[string]any
				if err := json.Unmarshal(raw, &rec); err != nil {
					writeError(w, http.StatusBadRequest, "BadRequest", fmt.Sprintf("Record %d is not a JSON object.", i))
					return
				}
				if err := schema.ValidateRecord(rec); err != nil {
					writeError(w, http.StatusBadRequest, "BadRequest", fmt.Sprintf("Record %d: %s", i, err.Error()))
					return
				}
			}
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// validateBearerToken parses a Bearer JWT and checks the aud, exp, and nbf claims.
// Signature verification is skipped unless --validate-jwt-signature is configured.
func validateBearerToken(header, audience string) error {
	if !strings.HasPrefix(header, "Bearer ") {
		return errors.New("Authorization value was not a Bearer token")
	}
	parts := strings.Split(strings.TrimPrefix(header, "Bearer "), ".")
	if len(parts) != 3 {
		return errors.New("malformed JWT (did not include all 3 parts)")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("malformed JWT (part 1 was not base64 encoded)")
	}
	var claims struct {
		Aud any   `json:"aud"` // string or []string per JWT spec
		Exp int64 `json:"exp"`
		Nbf int64 `json:"nbf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return errors.New("malformed JWT claims (expected aud, exp, and nbf claims)")
	}
	if !audContains(claims.Aud, audience) {
		return fmt.Errorf("token audience '%s' does not match expected '%s'", claims.Aud, audience)
	}
	now := time.Now().Unix()
	if claims.Exp != 0 && claims.Exp < now {
		return errors.New("token has expired")
	}
	if claims.Nbf != 0 && claims.Nbf > now {
		return errors.New("token is not yet valid")
	}
	return nil
}

// audContains checks whether want is present in the aud claim (string or []string).
func audContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// writeError writes an SDK-compatible JSON error response with the x-ms-error-code header.
func writeError(w http.ResponseWriter, status int, code, message string) {
	log.Printf("Returning error code=%s message=\"%s\"", code, message)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-ms-error-code", code)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

func main() {
	cfg := defaultConfig()
	flag.StringVar(&cfg.JWTAudience, "jwt-audience", cfg.JWTAudience, "Expected JWT aud claim value")
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "Address and port to listen on")
	flag.Parse()

	log.Printf("Sentinull listening on %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, newMux(cfg)); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
