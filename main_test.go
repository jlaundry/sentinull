package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- Success ---

func TestUpload_Success(t *testing.T) {
	rr := postUpload(t, validPath, validBody, validHeaders())
	assertStatus(t, rr, http.StatusNoContent)
}

// --- Routing ---

func TestUpload_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, validPath, nil)
	rr := httptest.NewRecorder()
	newMux(defaultConfig()).ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestUpload_MissingAPIVersion(t *testing.T) {
	path := "/dataCollectionRules/" + validRuleID + "/streams/" + validStream
	rr := postUpload(t, path, validBody, validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "MissingApiVersionParameter")
}

// --- Authentication ---

func TestUpload_MissingAuthorizationHeader(t *testing.T) {
	headers := validHeaders()
	delete(headers, "Authorization")
	rr := postUpload(t, validPath, validBody, headers)
	assertErrorResponse(t, rr, http.StatusUnauthorized, "Unauthorized")
}

func TestUpload_MalformedAuthorizationHeader(t *testing.T) {
	headers := validHeaders()
	headers["Authorization"] = "not-a-bearer-token"
	rr := postUpload(t, validPath, validBody, headers)
	assertErrorResponse(t, rr, http.StatusUnauthorized, "Unauthorized")
}

func TestUpload_ExpiredToken(t *testing.T) {
	// exp in the past (epoch 1000)
	headers := validHeaders()
	headers["Authorization"] = makeJWT(map[string]any{
		"aud": "https://monitor.azure.com",
		"exp": 1000,
		"nbf": 0,
	})
	rr := postUpload(t, validPath, validBody, headers)
	assertErrorResponse(t, rr, http.StatusUnauthorized, "Unauthorized")
}

// --- Audience ---

func TestUpload_WrongAudience(t *testing.T) {
	headers := validHeaders()
	headers["Authorization"] = makeJWT(map[string]any{
		"aud": "https://monitor.azure.cn",
		"exp": 9999999999,
		"nbf": 0,
	})
	rr := postUpload(t, validPath, validBody, headers)
	assertErrorResponse(t, rr, http.StatusUnauthorized, "Unauthorized")
}

func TestUpload_CustomAudience(t *testing.T) {
	cfg := defaultConfig()
	cfg.JWTAudience = "https://monitor.azure.cn"
	headers := validHeaders()
	headers["Authorization"] = makeJWT(map[string]any{
		"aud": "https://monitor.azure.cn",
		"exp": 9999999999,
		"nbf": 0,
	})
	rr := postUploadWithConfig(t, validPath, validBody, headers, cfg)
	assertStatus(t, rr, http.StatusNoContent)
}

// --- Content-Type ---

func TestUpload_MissingContentType(t *testing.T) {
	headers := validHeaders()
	delete(headers, "Content-Type")
	rr := postUpload(t, validPath, validBody, headers)
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

func TestUpload_WrongContentType(t *testing.T) {
	headers := validHeaders()
	headers["Content-Type"] = "text/plain"
	rr := postUpload(t, validPath, validBody, headers)
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

// --- Request body ---

func TestUpload_EmptyBody(t *testing.T) {
	rr := postUpload(t, validPath, "", validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

func TestUpload_InvalidJSON(t *testing.T) {
	rr := postUpload(t, validPath, "{not json", validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

func TestUpload_BodyNotArray(t *testing.T) {
	rr := postUpload(t, validPath, `{"TimeGenerated":"2023-11-14 15:10:02"}`, validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

func TestUpload_PayloadTooLarge(t *testing.T) {
	// 1 MB limit; send just over
	big := "[" + strings.Repeat(`{"TimeGenerated":"2023-11-14 15:10:02","Data":"`+strings.Repeat("x", 1024)+`"},`, 1024) + `{"TimeGenerated":"2023-11-14 15:10:02"}]`
	rr := postUpload(t, validPath, big, validHeaders())
	assertErrorResponse(t, rr, http.StatusRequestEntityTooLarge, "RequestBodyTooLarge")
}

// --- Content-Encoding: gzip ---

func TestUpload_GzipSuccess(t *testing.T) {
	headers := validHeaders()
	headers["Content-Encoding"] = "gzip"
	compressed := gzipBytes(t, []byte(validBody))
	rr := postUploadBytes(t, validPath, compressed, headers)
	assertStatus(t, rr, http.StatusNoContent)
}

func TestUpload_GzipInvalidEncoding(t *testing.T) {
	// Content-Encoding: gzip but body is plain JSON (not actually compressed).
	headers := validHeaders()
	headers["Content-Encoding"] = "gzip"
	rr := postUploadBytes(t, validPath, []byte(validBody), headers)
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

func TestUpload_GzipPayloadTooLargeAfterDecompression(t *testing.T) {
	// Compressed payload decompresses to >1 MB.
	big := bytes.Repeat([]byte(`{"TimeGenerated":"2023-11-14 15:10:02","Data":"`+strings.Repeat("x", 1024)+`"}`), 1025)
	bigJSON := append([]byte("["), append(bytes.Join(bytes.Split(big, []byte{}[:0]), []byte(",")), ']')...)
	// Build a JSON array that exceeds 1 MB uncompressed.
	row := `{"TimeGenerated":"2023-11-14 15:10:02","Data":"` + strings.Repeat("x", 1024) + `"}`
	rows := make([]string, 1025)
	for i := range rows {
		rows[i] = row
	}
	bigJSON = []byte("[" + strings.Join(rows, ",") + "]")
	headers := validHeaders()
	headers["Content-Encoding"] = "gzip"
	compressed := gzipBytes(t, bigJSON)
	rr := postUploadBytes(t, validPath, compressed, headers)
	assertErrorResponse(t, rr, http.StatusRequestEntityTooLarge, "RequestBodyTooLarge")
}

// --- Stream / DCR validation ---

func TestUpload_InvalidStream(t *testing.T) {
	path := "/dataCollectionRules/dcr-accepted/streams/Nonexistent-Stream?api-version=2023-01-01"
	rr := postUpload(t, path, validBody, validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "InvalidStream")
}

func TestUpload_UnknownRuleID(t *testing.T) {
	path := "/dataCollectionRules/dcr-unknown/streams/Custom-MyTable?api-version=2023-01-01"
	rr := postUpload(t, path, validBody, validHeaders())
	assertErrorResponse(t, rr, http.StatusNotFound, "ResourceNotFound")
}

func TestUpload_ForbiddenRuleID(t *testing.T) {
	path := "/dataCollectionRules/dcr-forbidden/streams/Custom-MyTable?api-version=2023-01-01"
	rr := postUpload(t, path, validBody, validHeaders())
	assertErrorResponse(t, rr, http.StatusForbidden, "OperationFailed")
}

// --- dcr-accepted (no schema check) ---

func TestUpload_AcceptedRuleAnyJSON(t *testing.T) {
	path := "/dataCollectionRules/dcr-accepted/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"arbitrary":"data","foo":123}]`
	rr := postUpload(t, path, body, validHeaders())
	assertStatus(t, rr, http.StatusNoContent)
}

// --- dcr-validated schema checks ---

func TestUpload_ValidatedSyslogSuccess(t *testing.T) {
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"TimeGenerated":"2023-11-14 15:10:02","SyslogMessage":"hello","Facility":"auth","SeverityLevel":"info","ProcessID":42}]`
	rr := postUpload(t, path, body, validHeaders())
	assertStatus(t, rr, http.StatusNoContent)
}

func TestUpload_ValidatedSyslogSubsetOfColumns(t *testing.T) {
	// All columns are optional — a record with just one valid column should pass.
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"SyslogMessage":"hello"}]`
	rr := postUpload(t, path, body, validHeaders())
	assertStatus(t, rr, http.StatusNoContent)
}

func TestUpload_ValidatedSyslogEmptyRecord(t *testing.T) {
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{}]`
	rr := postUpload(t, path, body, validHeaders())
	assertStatus(t, rr, http.StatusNoContent)
}

func TestUpload_ValidatedSyslogUnknownColumn(t *testing.T) {
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"TimeGenerated":"2023-11-14 15:10:02","NonExistentColumn":"value"}]`
	rr := postUpload(t, path, body, validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

func TestUpload_ValidatedSyslogWrongType(t *testing.T) {
	// ProcessID is int; send a non-numeric string.
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"ProcessID":"not-a-number"}]`
	rr := postUpload(t, path, body, validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

func TestUpload_ValidatedSyslogDatetimeWrongType(t *testing.T) {
	// TimeGenerated is datetime; send something unparseable.
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"TimeGenerated":"not-a-date"}]`
	rr := postUpload(t, path, body, validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

func TestUpload_ValidatedSyslogRealCoercion(t *testing.T) {
	// _BilledSize is real; an integer JSON number should be accepted.
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"_BilledSize":42}]`
	rr := postUpload(t, path, body, validHeaders())
	assertStatus(t, rr, http.StatusNoContent)
}

func TestUpload_ValidatedSyslogNullValue(t *testing.T) {
	// Null values should be accepted for any column.
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"ProcessID":null,"SyslogMessage":null}]`
	rr := postUpload(t, path, body, validHeaders())
	assertStatus(t, rr, http.StatusNoContent)
}

func TestUpload_ValidatedCustomStreamSkipsSchema(t *testing.T) {
	// Custom-* streams are never schema-validated, even with dcr-validated.
	path := "/dataCollectionRules/dcr-validated/streams/Custom-MyTable?api-version=2023-01-01"
	body := `[{"anything":"goes"}]`
	rr := postUpload(t, path, body, validHeaders())
	assertStatus(t, rr, http.StatusNoContent)
}

func TestUpload_ValidatedSyslogMultipleRecordsMixed(t *testing.T) {
	// First record is fine, second has an unknown column.
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"SyslogMessage":"ok"},{"SyslogMessage":"ok","BadColumn":"fail"}]`
	rr := postUpload(t, path, body, validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

func TestUpload_ValidatedSyslogIntCoercionFromFloat(t *testing.T) {
	// ProcessID is int; a JSON float like 42.5 should be rejected.
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"ProcessID":42.5}]`
	rr := postUpload(t, path, body, validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

// --- Reserved columns ---

func TestUpload_ValidatedSyslogReservedColumn_ResourceId(t *testing.T) {
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"_ResourceId":"some-id"}]`
	rr := postUpload(t, path, body, validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

func TestUpload_ValidatedSyslogReservedColumn_Type(t *testing.T) {
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"Type":"Syslog"}]`
	rr := postUpload(t, path, body, validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

func TestUpload_ValidatedSyslogReservedColumn_SubscriptionId(t *testing.T) {
	path := "/dataCollectionRules/dcr-validated/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"_SubscriptionId":"00000000-0000-0000-0000-000000000000"}]`
	rr := postUpload(t, path, body, validHeaders())
	assertErrorResponse(t, rr, http.StatusBadRequest, "BadRequest")
}

func TestUpload_ValidatedSyslogReservedColumnIgnoredByAccepted(t *testing.T) {
	// dcr-accepted skips validation entirely, so reserved columns pass through.
	path := "/dataCollectionRules/dcr-accepted/streams/Microsoft-Syslog?api-version=2023-01-01"
	body := `[{"_ResourceId":"some-id","Type":"Syslog"}]`
	rr := postUpload(t, path, body, validHeaders())
	assertStatus(t, rr, http.StatusNoContent)
}

// --- Rate limiting ---

func TestUpload_RateLimited(t *testing.T) {
	// The real API has a 12k req/min limit... we probably want something configurable
	t.Skip("TODO: implement rate limit")

	// When implemented, assert:
	// assertErrorResponse(t, rr, http.StatusTooManyRequests, "TooManyRequests")
	// if rr.Header().Get("Retry-After") == "" {
	//     t.Fatal("expected Retry-After header")
	// }
}

func TestInternal_EventCountTracksUploadRequests(t *testing.T) {
	srv := newServer(defaultConfig())
	h := srv.mux()

	rr := postUploadToHandler(t, h, validPath, validBody, validHeaders())
	assertStatus(t, rr, http.StatusNoContent)

	rr = postUploadToHandler(t, h, validPath, validBody, validHeaders())
	assertStatus(t, rr, http.StatusNoContent)

	rr = getInternal(t, h, "/internal/event_count")
	assertStatus(t, rr, http.StatusOK)

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got, want := int(payload["count"].(float64)), 2; got != want {
		t.Fatalf("count: got %d, want %d", got, want)
	}
}

func TestInternal_StreamEventCountTracksTotalAndValidated(t *testing.T) {
	srv := newServer(defaultConfig())
	h := srv.mux()

	path := "/dataCollectionRules/dcr-accepted/streams/Custom-MyTable?api-version=2023-01-01"
	assertStatus(t, postUploadToHandler(t, h, path, validBody, validHeaders()), http.StatusNoContent)
	assertStatus(t, postUploadToHandler(t, h, path, validBody, validHeaders()), http.StatusNoContent)
	assertStatus(t, postUploadToHandler(t, h, path, validBody, validHeaders()), http.StatusNoContent)
	assertStatus(t, postUploadToHandler(t, h, path, validBody, validHeaders()), http.StatusNoContent)

	rr := getInternal(t, h, "/internal/stream/Custom-MyTable/event_count")
	assertStatus(t, rr, http.StatusOK)

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got, want := int(payload["total_events"].(float64)), 4; got != want {
		t.Fatalf("total_events: got %d, want %d", got, want)
	}
	if got, want := int(payload["validated_events"].(float64)), 4; got != want {
		t.Fatalf("validated_events: got %d, want %d", got, want)
	}

	path = "/dataCollectionRules/dcr-accepted/streams/Nonexistent-Stream?api-version=2023-01-01"
	assertStatus(t, postUploadToHandler(t, h, path, validBody, validHeaders()), http.StatusBadRequest)

	rr = getInternal(t, h, "/internal/stream/Nonexistent-Stream/event_count")
	assertStatus(t, rr, http.StatusOK)

	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got, want := int(payload["total_events"].(float64)), 1; got != want {
		t.Fatalf("total_events: got %d, want %d", got, want)
	}
	if got, want := int(payload["validated_events"].(float64)), 0; got != want {
		t.Fatalf("validated_events: got %d, want %d", got, want)
	}

	rr = getInternal(t, h, "/internal/event_count")
	assertStatus(t, rr, http.StatusOK)

	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got, want := int(payload["count"].(float64)), 5; got != want {
		t.Fatalf("count: got %d, want %d", got, want)
	}

}

func TestInternal_LastJWTReturnsDecodedClaims(t *testing.T) {
	srv := newServer(defaultConfig())
	h := srv.mux()

	headers := validHeaders()
	headers["Authorization"] = makeJWT(map[string]any{
		"aud": "https://monitor.azure.com",
		"exp": 9999999999,
		"nbf": 0,
		"sub": "test-subject",
	})
	assertStatus(t, postUploadToHandler(t, h, validPath, validBody, headers), http.StatusNoContent)

	rr := getInternal(t, h, "/internal/last_jwt")
	assertStatus(t, rr, http.StatusOK)

	var claims map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &claims); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got, ok := claims["sub"].(string); !ok || got != "test-subject" {
		t.Fatalf("expected sub claim to be %q, got %v", "test-subject", claims["sub"])
	}
}
