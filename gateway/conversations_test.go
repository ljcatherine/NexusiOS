package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testConversationID = "550e8400-e29b-41d4-a716-446655440000"
	testConnectionID   = "550e8400-e29b-41d4-a716-446655440001"
)

func conversationJSON(id, title, content string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"id":%q,"connectionID":%q,"title":%q,"messages":[{"id":%q,"role":"user","content":%q}],"updatedAt":1730000000}`,
		id, testConnectionID, title, testConnectionID, content))
}

func TestEncryptedConversationStoreScopesEncryptsAndUsesRevisions(t *testing.T) {
	root := filepath.Join(t.TempDir(), "records")
	key := bytes.Repeat([]byte{0x5a}, 32)
	store := NewEncryptedConversationStore(root, key)
	secretText := "private conversation text that must not appear on disk"
	meta, err := store.Put("owner-subject", testConversationID, 0,
		conversationJSON(testConversationID, "Private chat", secretText))
	if err != nil || meta.Revision != 1 {
		t.Fatalf("create failed: meta=%+v err=%v", meta, err)
	}
	path := filepath.Join(root, subjectDirectoryName("owner-subject"), testConversationID+".json")
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(disk), secretText) || strings.Contains(string(disk), "Private chat") {
		t.Fatal("conversation plaintext was written to disk")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("record permissions are not owner-only: mode=%v err=%v", info.Mode().Perm(), err)
	}
	loaded, err := store.Get("owner-subject", testConversationID)
	if err != nil || string(loaded.Conversation) != string(conversationJSON(testConversationID, "Private chat", secretText)) {
		t.Fatalf("conversation did not round-trip: result=%+v err=%v", loaded, err)
	}
	metadata, err := store.List("owner-subject")
	if err != nil || len(metadata) != 1 || metadata[0].Revision != 1 {
		t.Fatalf("owner list failed: metadata=%+v err=%v", metadata, err)
	}
	other, err := store.List("another-subject")
	if err != nil || len(other) != 0 {
		t.Fatalf("subject isolation failed: list=%+v err=%v", other, err)
	}
	if _, err := store.Put("owner-subject", testConversationID, 0,
		conversationJSON(testConversationID, "Stale write", "overwrite")); err != errConversationConflict {
		t.Fatalf("stale update was not rejected: %v", err)
	}
	updated, err := store.Put("owner-subject", testConversationID, 1,
		conversationJSON(testConversationID, "Private chat", "latest text"))
	if err != nil || updated.Revision != 2 {
		t.Fatalf("revision update failed: metadata=%+v err=%v", updated, err)
	}
	storeAfterRestart := NewEncryptedConversationStore(root, key)
	loadedAfterRestart, err := storeAfterRestart.Get("owner-subject", testConversationID)
	if err != nil || loadedAfterRestart.Revision != 2 || !bytes.Contains(loadedAfterRestart.Conversation, []byte("latest text")) {
		t.Fatalf("encrypted record did not survive restart: result=%+v err=%v", loadedAfterRestart, err)
	}
	if err := storeAfterRestart.Delete("owner-subject", testConversationID, 1); err != errConversationConflict {
		t.Fatalf("stale delete was not rejected: %v", err)
	}
	if err := storeAfterRestart.Delete("owner-subject", testConversationID, 2); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
}

func subjectDirectoryName(subject string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(subject)))
}

func TestEncryptedConversationStoreRejectsMismatchedIDsAndPrivateDirectories(t *testing.T) {
	store := NewEncryptedConversationStore(filepath.Join(t.TempDir(), "records"), bytes.Repeat([]byte{1}, 32))
	if _, err := store.Put("owner", testConversationID, 0,
		conversationJSON(testConnectionID, "wrong id", "body")); err != errInvalidConversation {
		t.Fatalf("mismatched conversation ID accepted: %v", err)
	}
	if err := os.MkdirAll(store.root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List("owner"); err == nil {
		t.Fatal("group-accessible conversation root was accepted")
	}
}

func TestEncryptedConversationStoreRejectsTamperingWrongKeyAndNonAES256Keys(t *testing.T) {
	root := filepath.Join(t.TempDir(), "records")
	key := bytes.Repeat([]byte{0x2a}, 32)
	store := NewEncryptedConversationStore(root, key)
	if store == nil {
		t.Fatal("AES-256 key was rejected")
	}
	if _, err := store.Put("owner", testConversationID, 0,
		conversationJSON(testConversationID, "Private chat", "secret")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, subjectDirectoryName("owner"), testConversationID+".json")
	record, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope encryptedConversationRecord
	if err := json.Unmarshal(record, &envelope); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) == 0 {
		t.Fatalf("invalid test ciphertext: %v", err)
	}
	ciphertext[0] ^= 1
	envelope.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("owner", testConversationID); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	if err := os.WriteFile(path, record, 0o600); err != nil {
		t.Fatal(err)
	}
	envelope.Revision++
	changedMetadata, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, changedMetadata, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("owner", testConversationID); err == nil {
		t.Fatal("tampered revision metadata was accepted")
	}
	if _, err := NewEncryptedConversationStore(root, bytes.Repeat([]byte{0x2b}, 32)).Get("owner", testConversationID); err == nil {
		t.Fatal("record encrypted with another key was accepted")
	}
	if NewEncryptedConversationStore(root, bytes.Repeat([]byte{1}, 16)) != nil {
		t.Fatal("AES-128 key was accepted for AES-256 conversation storage")
	}
}

func TestConversationAPIRequiresPermissionAndScopesReads(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	permissions := map[string]map[string]bool{
		"owner-subject": {permissionHistory: true},
		"other-subject": {permissionHistory: true},
		"no-history":    {permissionChat: true},
	}
	gateway := testGateway(upstream, permissions)
	gateway.cfg.RequestsPerMinute = 100
	gateway.verifier = fakeVerifier{subjects: map[string]string{
		"valid-token": "owner-subject", "other-token": "other-subject", "limited-token": "no-history",
	}}
	gateway.conversationStore = NewEncryptedConversationStore(filepath.Join(t.TempDir(), "records"), bytes.Repeat([]byte{7}, 32))

	request := func(method, path, token string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		gateway.Handler().ServeHTTP(response, req)
		return response
	}
	limited := request(http.MethodPut, "/v1/conversations/"+testConversationID, "limited-token",
		[]byte(`{"expected_revision":0,"conversation":{}}`))
	if limited.Code != http.StatusForbidden {
		t.Fatalf("subject without history permission got %d", limited.Code)
	}
	missingRevision := request(http.MethodPut, "/v1/conversations/"+testConversationID, "valid-token",
		[]byte(`{"conversation":{}}`))
	if missingRevision.Code != http.StatusBadRequest {
		t.Fatalf("missing expected_revision was accepted: %d", missingRevision.Code)
	}
	extraField := request(http.MethodPut, "/v1/conversations/"+testConversationID, "valid-token",
		[]byte(`{"expected_revision":0,"conversation":{},"unexpected":true}`))
	if extraField.Code != http.StatusBadRequest {
		t.Fatalf("unknown sync request field was accepted: %d", extraField.Code)
	}
	putBody, _ := json.Marshal(map[string]any{"expected_revision": 0,
		"conversation": conversationJSON(testConversationID, "Shared chat", "owner text")})
	created := request(http.MethodPut, "/v1/conversations/"+testConversationID, "valid-token", putBody)
	if created.Code != http.StatusOK || created.Header().Get("ETag") != `"1"` {
		t.Fatalf("authorized create failed: status=%d body=%q", created.Code, created.Body.String())
	}
	other := request(http.MethodGet, "/v1/conversations/"+testConversationID, "other-token", nil)
	if other.Code != http.StatusNotFound || strings.Contains(other.Body.String(), "owner text") {
		t.Fatalf("another subject read owner's conversation: %d %q", other.Code, other.Body.String())
	}
	loaded := request(http.MethodGet, "/v1/conversations/"+testConversationID, "valid-token", nil)
	if loaded.Code != http.StatusOK || !strings.Contains(loaded.Body.String(), "owner text") {
		t.Fatalf("owner could not read conversation: %d %q", loaded.Code, loaded.Body.String())
	}
	stale := request(http.MethodDelete, "/v1/conversations/"+testConversationID, "valid-token", nil)
	if stale.Code != http.StatusPreconditionRequired {
		t.Fatalf("unconditional delete was accepted: %d", stale.Code)
	}
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/conversations/"+testConversationID, nil)
	deleteRequest.Header.Set("Authorization", "Bearer valid-token")
	deleteRequest.Header.Set("If-Match", `"1"`)
	deleted := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(deleted, deleteRequest)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("revision-guarded delete failed: %d %q", deleted.Code, deleted.Body.String())
	}
}

func TestConversationAPIFailsClosedWhenEncryptionIsUnconfigured(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	gateway := testGateway(upstream, map[string]map[string]bool{"owner-subject": {permissionHistory: true}})
	gateway.verifier = fakeVerifier{subjects: map[string]string{"valid-token": "owner-subject"}}
	request := httptest.NewRequest(http.MethodGet, "/v1/conversations", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "not configured") {
		t.Fatalf("unconfigured conversation storage did not fail closed: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestGatewayConfigurationAllowsOptInEncryptedHistoryOnlyWithValidKey(t *testing.T) {
	t.Setenv("NEXUS_OIDC_ISSUER", "https://identity.example.test/")
	t.Setenv("NEXUS_OIDC_AUDIENCE", "https://gateway.example.test")
	t.Setenv("NEXUS_GATEWAY_LISTEN", "127.0.0.1:8787")
	t.Setenv("NEXUS_SUBJECT_PERMISSIONS_JSON", `{"owner-subject":["ai.models","ai.chat","ai.history"]}`)
	t.Setenv("NEXUS_AI_UPSTREAM_URL", "http://192.168.1.50:8081/v1")
	t.Setenv("NEXUS_AI_UPSTREAM_TOKEN", "")
	t.Setenv("NEXUS_AI_ALLOWED_MODELS", "fixture-model")
	t.Setenv("NEXUS_AI_REQUEST_TIMEOUT", "15m")
	t.Setenv("NEXUS_AI_REQUESTS_PER_MINUTE", "30")
	t.Setenv("NEXUS_AI_MAX_CONCURRENT", "2")
	t.Setenv("NEXUS_SEARCH_PROVIDER", "")
	t.Setenv("NEXUS_SEARCH_TIMEOUT", "15s")
	t.Setenv("NEXUS_SEARCH_MAX_RESULTS", "5")
	t.Setenv("NEXUS_SEARCH_FETCH_PAGES", "")
	t.Setenv("NEXUS_CONVERSATIONS_DIR", filepath.Join(t.TempDir(), "conversations"))
	key := bytes.Repeat([]byte{0x42}, 32)
	t.Setenv("NEXUS_CONVERSATION_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(key))
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("valid encrypted history configuration rejected: %v", err)
	}
	if !cfg.SubjectPermissions["owner-subject"][permissionHistory] || !bytes.Equal(cfg.ConversationEncryptionKey, key) {
		t.Fatal("history permission or encryption key was not loaded")
	}
	t.Setenv("NEXUS_CONVERSATION_ENCRYPTION_KEY", "not-a-valid-key")
	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "32-byte key") {
		t.Fatalf("malformed conversation encryption key accepted or misreported: %v", err)
	}
}
