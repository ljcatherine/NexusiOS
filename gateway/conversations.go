package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxConversationBytes = 4 << 20
	maxConversations     = 100
	maxConversationStore = 64 << 20
	maxStoredMessages    = 500
)

var (
	errConversationNotFound = errors.New("conversation not found")
	errConversationConflict = errors.New("conversation revision conflict")
	errConversationQuota    = errors.New("conversation storage limit reached")
	errInvalidConversation  = errors.New("invalid conversation")
)

type EncryptedConversationStore struct {
	root string
	aead cipher.AEAD
	mu   sync.Mutex
}

type encryptedConversationRecord struct {
	Version    int       `json:"version"`
	ID         string    `json:"id"`
	Revision   uint64    `json:"revision"`
	UpdatedAt  time.Time `json:"updated_at"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
}

type conversationMetadata struct {
	ID        string    `json:"id"`
	Revision  uint64    `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
}

type conversationPutRequest struct {
	ExpectedRevision *uint64         `json:"expected_revision"`
	Conversation     json.RawMessage `json:"conversation"`
}

type conversationResponse struct {
	ID           string          `json:"id"`
	Revision     uint64          `json:"revision"`
	UpdatedAt    time.Time       `json:"updated_at"`
	Conversation json.RawMessage `json:"conversation"`
}

func NewEncryptedConversationStore(root string, key []byte) *EncryptedConversationStore {
	if len(key) != 32 {
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	return &EncryptedConversationStore{root: root, aead: aead}
}

func (s *EncryptedConversationStore) userDirectory(subject string) (string, error) {
	if strings.TrimSpace(subject) == "" || s == nil || s.aead == nil {
		return "", errInvalidConversation
	}
	if err := ensurePrivateDirectory(s.root); err != nil {
		return "", err
	}
	identity := sha256.Sum256([]byte(subject))
	directory := filepath.Join(s.root, hex.EncodeToString(identity[:]))
	if err := ensurePrivateDirectory(directory); err != nil {
		return "", err
	}
	return directory, nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("conversation directory must be a private, non-symlink directory")
	}
	return nil
}

func canonicalConversationID(raw string) (string, bool) {
	if len(raw) != 36 || raw[8] != '-' || raw[13] != '-' || raw[18] != '-' || raw[23] != '-' {
		return "", false
	}
	compact := strings.ReplaceAll(raw, "-", "")
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return "", false
	}
	return strings.ToLower(raw), true
}

func validateConversationJSON(data []byte, expectedID string) error {
	if len(data) == 0 || len(data) > maxConversationBytes || !json.Valid(data) {
		return errInvalidConversation
	}
	var value struct {
		ID           string            `json:"id"`
		ConnectionID string            `json:"connectionID"`
		Title        string            `json:"title"`
		Messages     []json.RawMessage `json:"messages"`
		UpdatedAt    json.RawMessage   `json:"updatedAt"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return errInvalidConversation
	}
	id, ok := canonicalConversationID(value.ID)
	if !ok || id != expectedID {
		return errInvalidConversation
	}
	if _, ok := canonicalConversationID(value.ConnectionID); !ok || strings.TrimSpace(value.Title) == "" || len(value.Title) > 240 || len(value.Messages) > maxStoredMessages {
		return errInvalidConversation
	}
	var updatedAt float64
	if len(value.UpdatedAt) == 0 || json.Unmarshal(value.UpdatedAt, &updatedAt) != nil || updatedAt <= 0 {
		return errInvalidConversation
	}
	return nil
}

func (s *EncryptedConversationStore) recordPath(directory, id string) string {
	return filepath.Join(directory, id+".json")
}

func (s *EncryptedConversationStore) read(subject, id string) (encryptedConversationRecord, json.RawMessage, error) {
	directory, err := s.userDirectory(subject)
	if err != nil {
		return encryptedConversationRecord{}, nil, err
	}
	path := s.recordPath(directory, id)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return encryptedConversationRecord{}, nil, errConversationNotFound
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxConversationBytes*2 {
		return encryptedConversationRecord{}, nil, errors.New("invalid conversation record")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return encryptedConversationRecord{}, nil, err
	}
	var record encryptedConversationRecord
	if err := json.Unmarshal(data, &record); err != nil || record.Version != 2 || record.ID != id || record.Revision == 0 || record.UpdatedAt.IsZero() {
		return encryptedConversationRecord{}, nil, errors.New("invalid conversation record")
	}
	nonce, err := base64.StdEncoding.DecodeString(record.Nonce)
	if err != nil || len(nonce) != s.aead.NonceSize() {
		return encryptedConversationRecord{}, nil, errors.New("invalid conversation record")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(record.Ciphertext)
	if err != nil || len(ciphertext) > maxConversationBytes+s.aead.Overhead() {
		return encryptedConversationRecord{}, nil, errors.New("invalid conversation record")
	}
	plain, err := s.aead.Open(nil, nonce, ciphertext, conversationAAD(subject, id, record.Revision, record.UpdatedAt))
	if err != nil || validateConversationJSON(plain, id) != nil {
		return encryptedConversationRecord{}, nil, errors.New("invalid conversation record")
	}
	return record, plain, nil
}

func conversationAAD(subject, id string, revision uint64, updatedAt time.Time) []byte {
	return []byte("nexus-conversation-v2\x00" + subject + "\x00" + id + "\x00" + strconv.FormatUint(revision, 10) + "\x00" + updatedAt.UTC().Format(time.RFC3339Nano))
}

func (s *EncryptedConversationStore) List(subject string) ([]conversationMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	directory, err := s.userDirectory(subject)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	result := make([]conversationMetadata, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			return nil, errors.New("invalid conversation directory entry")
		}
		id, ok := canonicalConversationID(strings.TrimSuffix(entry.Name(), ".json"))
		if !ok {
			return nil, errors.New("invalid conversation directory entry")
		}
		record, _, err := s.read(subject, id)
		if err != nil {
			return nil, err
		}
		result = append(result, conversationMetadata{ID: id, Revision: record.Revision, UpdatedAt: record.UpdatedAt})
	}
	if len(result) > maxConversations {
		return nil, errConversationQuota
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UpdatedAt.After(result[j].UpdatedAt) })
	return result, nil
}

func (s *EncryptedConversationStore) Get(subject, id string) (conversationResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, conversation, err := s.read(subject, id)
	if err != nil {
		return conversationResponse{}, err
	}
	return conversationResponse{ID: record.ID, Revision: record.Revision, UpdatedAt: record.UpdatedAt, Conversation: conversation}, nil
}

func (s *EncryptedConversationStore) Put(subject, id string, expected uint64, conversation json.RawMessage) (conversationMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateConversationJSON(conversation, id); err != nil {
		return conversationMetadata{}, err
	}
	directory, err := s.userDirectory(subject)
	if err != nil {
		return conversationMetadata{}, err
	}
	path := s.recordPath(directory, id)
	currentRevision := uint64(0)
	oldSize := int64(0)
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return conversationMetadata{}, errors.New("invalid conversation record")
		}
		oldSize = info.Size()
		current, _, readErr := s.read(subject, id)
		if readErr != nil {
			return conversationMetadata{}, readErr
		}
		currentRevision = current.Revision
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return conversationMetadata{}, statErr
	}
	if currentRevision != expected {
		return conversationMetadata{}, errConversationConflict
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return conversationMetadata{}, err
	}
	if currentRevision == 0 {
		count := 0
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".json") {
				count++
			}
		}
		if count >= maxConversations {
			return conversationMetadata{}, errConversationQuota
		}
	}
	var totalBytes int64
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			info, statErr := entry.Info()
			if statErr != nil || !info.Mode().IsRegular() {
				return conversationMetadata{}, errors.New("invalid conversation directory entry")
			}
			totalBytes += info.Size()
		}
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return conversationMetadata{}, err
	}
	revision := currentRevision + 1
	updatedAt := time.Now().UTC()
	ciphertext := s.aead.Seal(nil, nonce, conversation, conversationAAD(subject, id, revision, updatedAt))
	record := encryptedConversationRecord{Version: 2, ID: id, Revision: revision, UpdatedAt: updatedAt,
		Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(ciphertext)}
	encoded, err := json.Marshal(record)
	if err != nil {
		return conversationMetadata{}, err
	}
	if totalBytes-oldSize+int64(len(encoded)) > maxConversationStore {
		return conversationMetadata{}, errConversationQuota
	}
	temp, err := os.CreateTemp(directory, ".tmp-")
	if err != nil {
		return conversationMetadata{}, err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return conversationMetadata{}, err
	}
	if _, err := temp.Write(encoded); err != nil {
		temp.Close()
		return conversationMetadata{}, err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return conversationMetadata{}, err
	}
	if err := temp.Close(); err != nil {
		return conversationMetadata{}, err
	}
	if err := os.Rename(tempName, path); err != nil {
		return conversationMetadata{}, err
	}
	if dir, err := os.Open(directory); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return conversationMetadata{ID: id, Revision: revision, UpdatedAt: updatedAt}, nil
}

func (s *EncryptedConversationStore) Delete(subject, id string, expected uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, _, err := s.read(subject, id)
	if err != nil {
		return err
	}
	if current.Revision != expected {
		return errConversationConflict
	}
	directory, err := s.userDirectory(subject)
	if err != nil {
		return err
	}
	return os.Remove(s.recordPath(directory, id))
}

func (g *Gateway) conversationStoreOrError(w http.ResponseWriter) *EncryptedConversationStore {
	if g.conversationStore == nil {
		writeError(w, http.StatusServiceUnavailable, "encrypted conversation sync is not configured")
		return nil
	}
	return g.conversationStore
}

func (g *Gateway) listConversations(w http.ResponseWriter, r *http.Request) {
	store := g.conversationStoreOrError(w)
	if store == nil {
		return
	}
	items, err := store.List(r.Context().Value(principalKey{}).(string))
	if err != nil {
		writeConversationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"conversations": items})
}

func (g *Gateway) getConversation(w http.ResponseWriter, r *http.Request) {
	store := g.conversationStoreOrError(w)
	if store == nil {
		return
	}
	id, ok := canonicalConversationID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}
	result, err := store.Get(r.Context().Value(principalKey{}).(string), id)
	if err != nil {
		writeConversationError(w, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", result.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (g *Gateway) putConversation(w http.ResponseWriter, r *http.Request) {
	store := g.conversationStoreOrError(w)
	if store == nil {
		return
	}
	id, ok := canonicalConversationID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxConversationBytes+64*1024)
	defer r.Body.Close()
	var request conversationPutRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeConversationDecodeError(w, err)
		return
	}
	if request.ExpectedRevision == nil || len(request.Conversation) == 0 {
		writeError(w, http.StatusBadRequest, "invalid conversation sync request")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			writeError(w, http.StatusBadRequest, "invalid conversation sync request")
		} else {
			writeConversationDecodeError(w, err)
		}
		return
	}
	meta, err := store.Put(r.Context().Value(principalKey{}).(string), id, *request.ExpectedRevision, request.Conversation)
	if err != nil {
		writeConversationError(w, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", meta.Revision))
	writeJSON(w, http.StatusOK, meta)
}

func writeConversationDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "conversation sync request exceeds the size limit")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid conversation sync request")
}

func (g *Gateway) deleteConversation(w http.ResponseWriter, r *http.Request) {
	store := g.conversationStoreOrError(w)
	if store == nil {
		return
	}
	if store == nil {
		return
	}
	id, ok := canonicalConversationID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}
	match := strings.Trim(r.Header.Get("If-Match"), "\" ")
	expected, err := strconv.ParseUint(match, 10, 64)
	if err != nil || expected == 0 {
		writeError(w, http.StatusPreconditionRequired, "conversation revision is required")
		return
	}
	if err := store.Delete(r.Context().Value(principalKey{}).(string), id, expected); err != nil {
		writeConversationError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeConversationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errConversationNotFound):
		writeError(w, http.StatusNotFound, "conversation not found")
	case errors.Is(err, errConversationConflict):
		writeError(w, http.StatusConflict, "conversation changed; refresh before retrying")
	case errors.Is(err, errConversationQuota):
		writeError(w, http.StatusInsufficientStorage, "conversation storage limit reached")
	case errors.Is(err, errInvalidConversation):
		writeError(w, http.StatusBadRequest, "invalid conversation")
	default:
		writeError(w, http.StatusInternalServerError, "conversation storage operation failed")
	}
}
