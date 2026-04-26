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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBodyBytes = 1 << 20 // 1 MB

type config struct {
	JWTAudience string
	ListenAddr  string
}

type streamMetrics struct {
	Total     int `json:"total_events"`
	Validated int `json:"validated_events"`
}

type server struct {
	cfg       config
	mu        sync.Mutex
	uploadCnt int
	streams   map[string]*streamMetrics
	lastJWT   map[string]any
}

func defaultConfig() config {
	return config{
		JWTAudience: "https://monitor.azure.com",
		ListenAddr:  "localhost:8564",
	}
}

func newServer(cfg config) *server {
	return &server{
		cfg:     cfg,
		streams: make(map[string]*streamMetrics),
		lastJWT: make(map[string]any),
	}
}

func newMux(cfg config) *http.ServeMux {
	return newServer(cfg).mux()
}

func (s *server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /dataCollectionRules/{ruleID}/streams/{stream}", s.uploadHandler)
	mux.HandleFunc("GET /internal/event_count", s.internalEventCountHandler)
	mux.HandleFunc("GET /internal/last_jwt", s.internalLastJWTHandler)
	mux.HandleFunc("GET /internal/stream/{stream}/event_count", s.internalStreamHandler)
	return mux
}

func (s *server) uploadHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.uploadCnt++
	s.mu.Unlock()

	ruleID := r.PathValue("ruleID")
	stream := r.PathValue("stream")

	if r.URL.Query().Get("api-version") == "" {
		writeError(w, http.StatusBadRequest, "MissingApiVersionParameter", "An api-version query parameter is required.")
		return
	}

	if r.URL.Query().Get("api-version") != "2023-01-01" {
		writeError(w, http.StatusBadRequest, "UnsupportedApiVersion", fmt.Sprintf("The specified api-version '%s' is not supported.", r.URL.Query().Get("api-version")))
		return
	}

	claims, err := validateBearerToken(r.Header.Get("Authorization"), s.cfg.JWTAudience)
	if claims != nil {
		s.setLastJWT(claims)
	}
	if err != nil {
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

	if len(records) > 0 {
		s.recordStreamTotal(stream, len(records))
	}

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
		s.recordStreamValidated(stream, len(records))
	}

	if ruleID == "dcr-accepted" {
		s.recordStreamValidated(stream, len(records))
	}

	w.WriteHeader(http.StatusNoContent)
}

// validateBearerToken parses a Bearer JWT and checks the aud, exp, and nbf claims.
// Signature verification is skipped unless --validate-jwt-signature is configured.
func validateBearerToken(header, audience string) (map[string]any, error) {
	if !strings.HasPrefix(header, "Bearer ") {
		return nil, errors.New("Authorization value was not a Bearer token")
	}
	parts := strings.Split(strings.TrimPrefix(header, "Bearer "), ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT (did not include all 3 parts)")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed JWT (part 1 was not base64 encoded)")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("malformed JWT claims (expected aud, exp, and nbf claims)")
	}
	var validated struct {
		Aud any   `json:"aud"` // string or []string per JWT spec
		Exp int64 `json:"exp"`
		Nbf int64 `json:"nbf"`
	}
	if err := json.Unmarshal(payload, &validated); err != nil {
		return nil, errors.New("malformed JWT claims (expected aud, exp, and nbf claims)")
	}
	if !audContains(validated.Aud, audience) {
		return claims, fmt.Errorf("token audience '%s' does not match expected '%s'", validated.Aud, audience)
	}
	now := time.Now().Unix()
	if validated.Exp != 0 && validated.Exp < now {
		return claims, errors.New("token has expired")
	}
	if validated.Nbf != 0 && validated.Nbf > now {
		return claims, errors.New("token is not yet valid")
	}
	return claims, nil
}

func (s *server) setLastJWT(claims map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastJWT = claims
}

func (s *server) recordStreamTotal(stream string, count int) {
	if count == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := s.streams[stream]
	if stats == nil {
		stats = &streamMetrics{}
		s.streams[stream] = stats
	}
	stats.Total += count
}

func (s *server) recordStreamValidated(stream string, count int) {
	if count == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := s.streams[stream]
	if stats == nil {
		stats = &streamMetrics{}
		s.streams[stream] = stats
	}
	stats.Validated += count
}

func (s *server) internalEventCountHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	count := s.uploadCnt
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"count": count})
}

func (s *server) internalLastJWTHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	claims := s.lastJWT
	s.mu.Unlock()
	if claims == nil {
		claims = map[string]any{}
	}
	writeJSON(w, http.StatusOK, claims)
}

func (s *server) internalStreamHandler(w http.ResponseWriter, r *http.Request) {
	stream := r.PathValue("stream")
	s.mu.Lock()
	stats := s.streams[stream]
	s.mu.Unlock()
	if stats == nil {
		stats = &streamMetrics{}
	}
	writeJSON(w, http.StatusOK, stats)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
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
	log.Printf("Returning error code=%s message=%s", code, strconv.Quote(message))
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

func parseConfig(args []string) (config, error) {
	cfg := defaultConfig()
	fs := flag.NewFlagSet("sentinull", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.JWTAudience, "jwt-audience", cfg.JWTAudience, "Expected JWT aud claim value")
	fs.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "Address and port to listen on")
	if err := fs.Parse(normalizeArgs(args)); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func normalizeArgs(args []string) []string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return args
	}
	if filepath.Base(args[0]) == "sentinull" {
		return args[1:]
	}
	return args
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		log.Fatalf("invalid flags: %v", err)
	}

	log.Printf("Sentinull listening on %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, newMux(cfg)); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
