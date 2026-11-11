package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var errPatchBinding = errors.New("invalid patch binding")
var errPatchConflict = errors.New("patch request conflicts with consumed identifier")
var errPatchUncertain = errors.New("patch outcome uncertain; root blocked")

// Internal trusted-orchestrator contract, not a review API or model tool.
// The signer must check current owner/permission, exact approved digest and
// atomic consumption of approval before dispatch. HMAC is not proof of a human
// decision independent of that trusted signer.
type patchRequest struct {
	Host              string `json:"host"`
	Generation        string `json:"workspace_generation,omitempty"`
	WorkspaceID       string `json:"workspace_id"`
	Owner             string `json:"owner"`
	ApprovalID        string `json:"approval_id"`
	Digest            string `json:"digest"`
	OperationID       string `json:"operation_id"`
	Path              string `json:"path"`
	BaseSHA256        string `json:"base_sha256"`
	Replacement       string `json:"replacement"`
	ReplacementSHA256 string `json:"replacement_sha256"`
	ExpiresAt         int64  `json:"expires_at"`
	Proof             string `json:"proof"`
}

type patchReceipt struct {
	Host        string `json:"host"`
	WorkspaceID string `json:"workspace_id"`
	ApprovalID  string `json:"approval_id"`
	Digest      string `json:"digest"`
	OperationID string `json:"operation_id"`
	Status      string `json:"status"`
	SHA256      string `json:"sha256,omitempty"`
}

func validExecutorToken(token string) bool {
	return len(token) >= 32 && len(token) <= 256 && !strings.ContainsAny(token, " \t\r\n")
}

// Versioned, length-prefixed UTF-8 fields remove JSON serialization ambiguity.
// Prefix lengths count bytes (uint32 big endian). Expiry is decimal Unix seconds.
func (p patchRequest) binding() []byte {
	out := []byte("nexus.workspace.patch.v2\x00")
	for _, value := range []string{p.Host, p.WorkspaceID, p.Owner, p.ApprovalID, p.Digest, p.OperationID, p.Path, p.BaseSHA256, p.Replacement, p.ReplacementSHA256, strconv.FormatInt(p.ExpiresAt, 10), p.Generation} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(value)))
		out = append(out, n[:]...)
		out = append(out, value...)
	}
	return out
}
func hashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
func (p patchRequest) requestDigest() string { return hashText(string(p.binding())) }
func (p patchRequest) sign(token string) string {
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(p.binding())
	return hex.EncodeToString(mac.Sum(nil))
}
func (p patchRequest) validate() error {
	if !identifier.MatchString(p.Host) || !identifier.MatchString(p.WorkspaceID) || !hex64.MatchString(p.Owner) || !hex32.MatchString(p.ApprovalID) || !hex32.MatchString(p.OperationID) || !hex64.MatchString(p.Digest) || !hex64.MatchString(p.BaseSHA256) || !hex64.MatchString(p.ReplacementSHA256) || p.ExpiresAt <= 0 {
		return errPatchBinding
	}
	if p.Generation != "" && !hex64.MatchString(p.Generation) {
		return errPatchBinding
	}
	if !validPatchPath(p.Path) || len(p.Replacement) > maxReadBytes || !utf8.ValidString(p.Replacement) || strings.ContainsRune(p.Replacement, 0) || hashText(p.Replacement) != p.ReplacementSHA256 {
		return errPatchBinding
	}
	return nil
}
func (p patchRequest) verifySignature(token string) error {
	if !validExecutorToken(token) || p.validate() != nil || !hex64.MatchString(p.Proof) || !hmac.Equal([]byte(p.Proof), []byte(p.sign(token))) {
		return errPatchBinding
	}
	return nil
}
func (p patchRequest) verify(token string, now time.Time) error {
	if p.verifySignature(token) != nil || p.ExpiresAt <= now.Unix() || p.ExpiresAt > now.Unix()+3600 {
		return errPatchBinding
	}
	return nil
}
func (p patchRequest) receipt(status string) patchReceipt {
	return patchReceipt{Host: p.Host, WorkspaceID: p.WorkspaceID, ApprovalID: p.ApprovalID, Digest: p.Digest, OperationID: p.OperationID, Status: status}
}

func (s *server) authorizeExecutor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Authorization")
		if s.executorToken == "" || len(values) != 1 {
			sendError(w, 401, "executor_authentication_required")
			return
		}
		parts := strings.Fields(values[0])
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 256 {
			sendError(w, 401, "executor_authentication_required")
			return
		}
		a, b := sha256.Sum256([]byte(parts[1])), sha256.Sum256([]byte(s.executorToken))
		if !hmac.Equal(a[:], b[:]) {
			sendError(w, 401, "executor_authentication_required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Only generation-bound requests to explicitly managed roots can mutate.
func (s *server) applyPatch(w http.ResponseWriter, r *http.Request) {
	var p patchRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil || dec.Decode(new(any)) != io.EOF || p.verify(s.executorToken, time.Now()) != nil {
		sendError(w, 400, "invalid_patch_binding")
		return
	}
	if !s.requireHost(w, p.Host) {
		return
	}
	if p.WorkspaceID != r.PathValue("id") {
		sendError(w, 400, "workspace_mismatch")
		return
	}
	root := s.root(w, p.WorkspaceID)
	if root == nil {
		return
	}
	if !root.config.ManagedWrite || s.executor == nil || s.patchJournal == nil {
		sendError(w, 503, "managed_write_unavailable")
		return
	}
	if !hex64.MatchString(p.Generation) || p.Generation != root.generation {
		sendError(w, 409, "workspace_generation_changed")
		return
	}
	receipt, err := s.executor.execute(r.Context(), root, p, s.patchJournal, func() bool {
		return p.verify(s.executorToken, time.Now()) == nil && p.Generation == root.generation
	})
	s.sendMutationReceipt(w, receipt, err)
}

// GET reconciliation accepts the ORIGINAL signed request as its bounded JSON
// body. Only expiry enforcement is omitted. It never reserves or executes.
func (s *server) patchReceiptLookup(w http.ResponseWriter, r *http.Request) {
	var p patchRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil || dec.Decode(new(any)) != io.EOF || p.verifySignature(s.executorToken) != nil {
		sendError(w, 400, "invalid_patch_binding")
		return
	}
	if !s.requireHost(w, p.Host) {
		return
	}
	if p.WorkspaceID != r.PathValue("id") || p.OperationID != r.PathValue("operation_id") {
		sendError(w, 400, "workspace_or_operation_mismatch")
		return
	}
	if s.root(w, p.WorkspaceID) == nil {
		return
	}
	if s.patchJournal == nil {
		sendError(w, 503, "patch_receipts_unavailable")
		return
	}
	receipt, err := s.patchJournal.lookup(p)
	switch {
	case errors.Is(err, errMissing):
		sendError(w, 404, "receipt_not_found")
	case errors.Is(err, errPatchConflict):
		sendError(w, 409, "patch_binding_conflict")
	case err != nil:
		sendError(w, 503, "patch_receipts_unavailable")
	default:
		sendJSON(w, 200, receipt)
	}
}

// Reconciliation can sync a known rename or clean this operation's known stage.
// It is POST and uses the original signed binding, even after its write expiry.
func (s *server) reconcilePatch(w http.ResponseWriter, r *http.Request) {
	var p patchRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil || dec.Decode(new(any)) != io.EOF || p.verifySignature(s.executorToken) != nil {
		sendError(w, 400, "invalid_patch_binding")
		return
	}
	if !s.requireHost(w, p.Host) {
		return
	}
	root := s.root(w, r.PathValue("id"))
	if root == nil {
		return
	}
	if p.WorkspaceID != root.config.ID || p.OperationID != r.PathValue("operation_id") {
		sendError(w, 400, "workspace_or_operation_mismatch")
		return
	}
	if !root.config.ManagedWrite || s.executor == nil || s.patchJournal == nil {
		sendError(w, 503, "managed_write_unavailable")
		return
	}
	if !hex64.MatchString(p.Generation) || p.Generation != root.generation {
		sendError(w, 409, "workspace_generation_changed")
		return
	}
	receipt, err := s.executor.recover(r.Context(), root, p, s.patchJournal)
	s.sendMutationReceipt(w, receipt, err)
}

func (s *server) sendMutationReceipt(w http.ResponseWriter, receipt patchReceipt, err error) {
	switch {
	case errors.Is(err, errPatchUncertain):
		sendError(w, 409, "patch_outcome_uncertain")
	case errors.Is(err, errPatchConflict):
		sendError(w, 409, "patch_binding_conflict")
	case err != nil:
		sendError(w, 503, "patch_executor_unavailable")
	default:
		sendJSON(w, 200, receipt)
	}
}
