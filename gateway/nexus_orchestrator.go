package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// The orchestrator is a separate owner-only loopback service. Never use the
// client's requested host, the PS5 address, or the ordinary AI upstream here.
const nexusOrchestratorOrigin = "http://127.0.0.1:8897"
const maxOrchestratorRequestBytes = 2 << 20
const maxOrchestratorResponseBytes = 3 << 20

var orchestratorModelID = regexp.MustCompile(`^[0-9a-f]{16}$`)
var orchestratorRunPath = regexp.MustCompile(`^/v1/nexus/agent-runs/[0-9a-f]{32}$`)
var orchestratorCancelRunPath = regexp.MustCompile(`^/v1/nexus/agent-runs/[0-9a-f]{32}/cancel$`)
var orchestratorCancelSubagentPath = regexp.MustCompile(`^/v1/nexus/agent-runs/[0-9a-f]{32}/subagents/[0-9a-f]{32}/cancel$`)
var orchestratorWorkspaceListPath = regexp.MustCompile(`^/v1/nexus/workspaces/(debian|nixos)$`)
var orchestratorWorkspaceFilesPath = regexp.MustCompile(`^/v1/nexus/workspaces/(debian|nixos)/[a-z][a-z0-9_-]{0,31}/files$`)
var orchestratorWorkspaceContextPath = regexp.MustCompile(`^/v1/nexus/workspaces/(debian|nixos)/[a-z][a-z0-9_-]{0,31}/context$`)
var orchestratorWorkspaceTasksPath = regexp.MustCompile(`^/v1/nexus/workspaces/(debian|nixos)/[a-z][a-z0-9_-]{0,31}/tasks$`)
var orchestratorPatchPath = regexp.MustCompile(`^/v1/nexus/workspaces/(debian|nixos)/([a-z][a-z0-9_-]{0,31})/patches(?:/([0-9a-f]{32})(?:/(decision|apply|reconcile))?)?$`)
var orchestratorCommandPath = regexp.MustCompile(`^/v1/nexus/workspaces/(debian|nixos)/([a-z][a-z0-9_-]{0,31})/commands(?:/([0-9a-f]{32})(?:/(decision|execute|reconcile|cancel))?)?$`)
var orchestratorCommandProfilesPath = regexp.MustCompile(`^/v1/nexus/workspaces/(debian|nixos)/([a-z][a-z0-9_-]{0,31})/commands/profiles$`)
var orchestratorCommandProfileID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
var orchestratorApprovalID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var workspaceGrantID = regexp.MustCompile(`^(debian|nixos):[a-z][a-z0-9_-]{0,31}$`)
var principalDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// The orchestrator already holds this dedicated private bearer. This endpoint
// discloses only a decision and never trusts a caller-supplied OIDC subject.
func (g *Gateway) authorizeInternalRun(w http.ResponseWriter, r *http.Request) {
	g.authorizeInternalPolicy(w, r, false)
}

func (g *Gateway) authorizeInternalWorkspaceOperation(w http.ResponseWriter, r *http.Request) {
	g.authorizeInternalPolicy(w, r, true)
}

func (g *Gateway) authorizeInternalPolicy(w http.ResponseWriter, r *http.Request, operationCheck bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	auth := r.Header.Values("Authorization")
	if err != nil || ip == nil || !ip.IsLoopback() || !validOrchestratorToken(g.cfg.OrchestratorBearerToken) || len(auth) != 1 ||
		subtle.ConstantTimeCompare([]byte(auth[0]), []byte("Bearer "+g.cfg.OrchestratorBearerToken)) != 1 {
		writeError(w, http.StatusForbidden, "permission denied")
		return
	}
	if r.URL.RawQuery != "" || r.ContentLength > 2048 {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 2049))
	object, valid := uniqueOrchestratorObject(body)
	expectedFields := 2
	if operationCheck {
		expectedFields = 3
	}
	if err != nil || len(body) > 2048 || !valid || len(object) != expectedFields {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	var digest string
	if json.Unmarshal(object["principal"], &digest) != nil || !principalDigest.MatchString(digest) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	workspace, present := object["workspace"]
	if !present {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	var workspaceHost, workspaceID string
	if !bytes.Equal(bytes.TrimSpace(workspace), []byte("null")) {
		var ok bool
		workspaceHost, workspaceID, ok = workspaceIdentity(workspace, "id")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
	}
	var operation string
	if operationCheck {
		if workspaceHost == "" || json.Unmarshal(object["operation"], &operation) != nil ||
			(operation != "propose" && operation != "apply" && operation != "execute") {
			writeError(w, http.StatusBadRequest, "invalid workspace operation")
			return
		}
	}
	for subject, permissions := range g.cfg.SubjectPermissions {
		hash := sha256.Sum256([]byte(subject))
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash[:])), []byte(digest)) != 1 {
			continue
		}
		operationAllowed := !operationCheck ||
			(operation == "propose" && permissions[permissionNexusPatchPropose]) ||
			(operation == "apply" && permissions[permissionNexusWorkspaceWrite] &&
				g.cfg.WorkspaceWriteGrants[subject][workspaceHost+":"+workspaceID]) ||
			(operation == "execute" && permissions[permissionNexusWorkspaceExecute] &&
				g.cfg.WorkspaceExecuteGrants[subject][workspaceHost+":"+workspaceID])
		if permissions[permissionOrchestrate] && permissions[permissionChat] && operationAllowed &&
			(workspaceHost == "" || (permissions[permissionNexusWorkspaceRead] && g.cfg.WorkspaceGrants[subject][workspaceHost+":"+workspaceID])) {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		break
	}
	writeError(w, http.StatusForbidden, "permission denied")
}

// Missing and empty policies grant no workspace roots.
func parseWorkspaceGrants(raw string) (map[string]map[string]bool, error) {
	object, ok := uniqueOrchestratorObject([]byte(raw))
	if !ok || len(raw) > 64<<10 || len(object) > 256 {
		return nil, errors.New("invalid NEXUS_WORKSPACE_GRANTS_JSON")
	}
	result := make(map[string]map[string]bool, len(object))
	for subject, encoded := range object {
		if subject == "" || strings.TrimSpace(subject) != subject {
			return nil, errors.New("invalid workspace grant subject")
		}
		var grants []string
		if json.Unmarshal(encoded, &grants) != nil || grants == nil || len(grants) > 32 {
			return nil, errors.New("invalid workspace grants")
		}
		set := make(map[string]bool, len(grants))
		for _, grant := range grants {
			if !workspaceGrantID.MatchString(grant) || set[grant] {
				return nil, errors.New("invalid or duplicate workspace grant")
			}
			set[grant] = true
		}
		result[subject] = set
	}
	return result, nil
}

func (g *Gateway) workspaceAllowed(r *http.Request, host, id string) bool {
	if !workspaceGrantID.MatchString(host + ":" + id) {
		return false
	}
	principal, ok := r.Context().Value(principalKey{}).(string)
	return ok && g.cfg.WorkspaceGrants[principal][host+":"+id]
}

func (g *Gateway) workspaceWriteAllowed(r *http.Request, host, id string) bool {
	if !workspaceGrantID.MatchString(host + ":" + id) {
		return false
	}
	principal, ok := r.Context().Value(principalKey{}).(string)
	return ok && g.cfg.WorkspaceWriteGrants[principal][host+":"+id]
}

func (g *Gateway) workspaceExecuteAllowed(r *http.Request, host, id string) bool {
	if !workspaceGrantID.MatchString(host + ":" + id) {
		return false
	}
	principal, ok := r.Context().Value(principalKey{}).(string)
	return ok && g.cfg.WorkspaceExecuteGrants[principal][host+":"+id]
}

func workspaceIdentity(raw json.RawMessage, idKey string) (string, string, bool) {
	object, ok := uniqueOrchestratorObject(raw)
	if !ok {
		return "", "", false
	}
	var host, id string
	if json.Unmarshal(object["host"], &host) != nil || json.Unmarshal(object[idKey], &id) != nil || !workspaceGrantID.MatchString(host+":"+id) {
		return "", "", false
	}
	return host, id, true
}

type nexusOrchestratorProxy struct {
	endpoint    string
	token       string
	reviewToken string
	client      *http.Client
}

// All gateway-managed inference and model switches share this gate. The
// pending state remains closed after a switch until status confirms its target.
// It does not coordinate direct callers that bypass the gateway.
func (g *Gateway) beginInference(w http.ResponseWriter) bool {
	if !g.aiLifecycle.TryLock() {
		writeError(w, http.StatusServiceUnavailable, "AI inference or model management is busy")
		return false
	}
	g.reconcilePendingModelSwitch()
	g.modelState.Lock()
	pending := g.modelPending != ""
	stateErr := g.modelStateErr
	g.modelState.Unlock()
	if pending || stateErr != nil {
		g.aiLifecycle.Unlock()
		writeError(w, http.StatusServiceUnavailable, "model state is unavailable or a switch is awaiting confirmation")
		return false
	}
	if g.orchestrator != nil {
		active, err := g.activeOrchestratorRuns()
		if err != nil {
			g.aiLifecycle.Unlock()
			writeError(w, http.StatusServiceUnavailable, "orchestrator task state is unavailable")
			return false
		}
		if active > 0 {
			g.aiLifecycle.Unlock()
			writeError(w, http.StatusServiceUnavailable, "an orchestrator task is using PS5 inference")
			return false
		}
	}
	return true
}

func (g *Gateway) activeOrchestratorRuns() (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	endpoint, err := url.Parse(g.orchestrator.endpoint + "/v1/nexus/agent-runs/active")
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Authorization", "Bearer "+g.orchestrator.token)
	request.Header.Set("Accept", "application/json")
	response, err := g.orchestrator.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, errOrchestratorState
	}
	var result struct {
		Active *int `json:"active"`
	}
	if decodeBoundedJSONResponse(response, 4096, &result) != nil || result.Active == nil || *result.Active < 0 || *result.Active > 8 {
		return 0, errOrchestratorState
	}
	return *result.Active, nil
}

var errOrchestratorState = &orchestratorStateError{}

type orchestratorStateError struct{}

func (*orchestratorStateError) Error() string { return "invalid orchestrator task state" }

func (g *Gateway) requireOrchestratorPermission(w http.ResponseWriter, r *http.Request, permission string) bool {
	principal, ok := r.Context().Value(principalKey{}).(string)
	if !ok || principal == "" || !g.cfg.SubjectPermissions[principal][permission] {
		logAuthorizationEvent(requestIDFromContext(r.Context()), permission, r.URL.Path,
			"deny", "permission_denied", auditSubjectID(principal))
		writeError(w, http.StatusForbidden, "permission denied")
		return false
	}
	return true
}

// Authorization depends on the top-level workspace field. Reject duplicate
// keys before making that decision, including keys written with JSON escapes.
func uniqueOrchestratorObject(body []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return nil, false
		}
		if _, duplicate := object[name]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		object[name] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, false
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, false
	}
	return object, true
}

// Caller holds aiLifecycle. A lost phone poll must not strand a completed
// switch forever. This only reads the trusted controller and never replays a
// model action or clears an unknown/corrupt journal.
func (g *Gateway) reconcilePendingModelSwitch() {
	g.modelState.Lock()
	check := g.modelPending != "" && g.modelStateErr == nil && !g.modelSwitchActive
	g.modelState.Unlock()
	if !check || g.orchestrator == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		g.orchestrator.endpoint+"/v1/nexus/status", nil)
	if err != nil {
		return
	}
	request.Header.Set("Authorization", "Bearer "+g.orchestrator.token)
	request.Header.Set("Accept", "application/json")
	response, err := g.orchestrator.client.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
	if err != nil || len(body) > 16*1024 {
		return
	}
	g.confirmModelStatus(body)
}

func (g *Gateway) confirmModelStatus(body []byte) {
	if _, valid := uniqueOrchestratorObject(body); !valid {
		return
	}
	var status struct {
		State   string `json:"state"`
		ModelID string `json:"model_id"`
		Ready   *bool  `json:"ready"`
	}
	if json.Unmarshal(body, &status) != nil || status.Ready == nil {
		return
	}
	g.modelState.Lock()
	defer g.modelState.Unlock()
	if g.modelSwitchActive || g.modelPending == "" {
		return
	}
	if (g.modelPending == "unload" && status.State == "no_model" && !*status.Ready) ||
		(g.modelPending != "unload" && status.ModelID == g.modelPending && *status.Ready &&
			(status.State == "ready" || status.State == "generating")) {
		if err := clearPendingModelSwitch(g.cfg.ModelStatePath); err != nil {
			g.modelStateErr = err
			return
		}
		g.modelPending, g.modelStateErr = "", nil
	}
}

func validOrchestratorToken(token string) bool {
	if len(token) < 32 || len(token) > 256 {
		return false
	}
	for _, char := range token {
		if char <= ' ' || char > '~' {
			return false
		}
	}
	return true
}

func newNexusOrchestratorProxy(token string) *nexusOrchestratorProxy {
	transport := &http.Transport{
		Proxy:                 nil, // never consult HTTP_PROXY for the private loopback service
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: 140 * time.Second,
	}
	return &nexusOrchestratorProxy{
		endpoint: nexusOrchestratorOrigin,
		token:    token,
		client: &http.Client{
			Transport: transport,
			Timeout:   145 * time.Second, // upper bound for orchestrator operations; job polling is normally brief
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func nexusOrchestratorUpstreamPath(method, path string) (string, bool) {
	if orchestratorCommandProfilesPath.MatchString(path) {
		return path, method == http.MethodGet
	}
	if command := orchestratorCommandPath.FindStringSubmatch(path); command != nil {
		if (method == http.MethodGet && command[4] == "") ||
			(method == http.MethodPost && (command[3] == "" || command[4] != "")) {
			return path, true
		}
		return "", false
	}
	if patch := orchestratorPatchPath.FindStringSubmatch(path); patch != nil {
		if (method == http.MethodGet && patch[4] == "") ||
			(method == http.MethodPost && (patch[3] == "" || patch[4] != "")) {
			return path, true
		}
		return "", false
	}
	switch {
	case method == http.MethodGet && path == "/v1/nexus/workspaces":
		return path, true
	case method == http.MethodGet && orchestratorWorkspaceListPath.MatchString(path):
		return path, true
	case method == http.MethodGet && (orchestratorWorkspaceFilesPath.MatchString(path) ||
		orchestratorWorkspaceContextPath.MatchString(path)):
		return path, true
	case method == http.MethodPost && orchestratorWorkspaceTasksPath.MatchString(path):
		return path, true
	case method == http.MethodPost && path == "/v1/nexus/agent-runs":
		return path, true
	case method == http.MethodGet && path == "/v1/nexus/agent-runs":
		return path, true
	case method == http.MethodGet && path == "/v1/nexus/agent-runs/active":
		return path, true
	case method == http.MethodGet && orchestratorRunPath.MatchString(path):
		return path, true
	case method == http.MethodPost && orchestratorCancelRunPath.MatchString(path):
		return path, true
	case method == http.MethodPost && orchestratorCancelSubagentPath.MatchString(path):
		return path, true
	case method == http.MethodGet && (path == "/v1/nexus/models" || path == "/v1/nexus/status"):
		return path, true
	case method == http.MethodGet && path == "/v1/nexus/models/status":
		return "/v1/nexus/status", true
	case method == http.MethodPost && path == "/v1/nexus/models/unload":
		return path, true
	case method == http.MethodPost &&
		strings.HasPrefix(path, "/v1/nexus/models/") && strings.HasSuffix(path, "/load"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/nexus/models/"), "/load")
		if orchestratorModelID.MatchString(id) {
			return "/v1/nexus/models/" + id + "/load", true
		}
	}
	return "", false
}

func (g *Gateway) serveNexusOrchestrator(w http.ResponseWriter, r *http.Request) {
	if g.orchestrator == nil || !validOrchestratorToken(g.orchestrator.token) {
		writeError(w, http.StatusServiceUnavailable, "orchestrator unavailable")
		return
	}
	upstreamPath, ok := nexusOrchestratorUpstreamPath(r.Method, r.URL.Path)
	if !ok || r.URL.RawPath != "" || r.URL.ForceQuery || r.URL.Fragment != "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	patch := orchestratorPatchPath.FindStringSubmatch(upstreamPath)
	patchRequest := patch != nil
	command := orchestratorCommandPath.FindStringSubmatch(upstreamPath)
	commandProfiles := orchestratorCommandProfilesPath.FindStringSubmatch(upstreamPath)
	commandRequest := command != nil || commandProfiles != nil
	commandExecution := commandRequest && r.Method == http.MethodPost && (command[4] == "execute" || command[4] == "reconcile" || command[4] == "cancel")
	if commandRequest {
		commandHost, commandRoot := "", ""
		if command != nil {
			commandHost, commandRoot = command[1], command[2]
		} else {
			commandHost, commandRoot = commandProfiles[1], commandProfiles[2]
		}
		// A separate explicit owner execute scope AND per-root grant is required
		// even to discover reviewable command profiles. Read/patch permissions
		// never imply executable authority; the Python host rechecks uncached.
		if !g.requireOrchestratorPermission(w, r, permissionOrchestrate) ||
			!g.requireOrchestratorPermission(w, r, permissionChat) ||
			!g.requireOrchestratorPermission(w, r, permissionNexusApprovalReview) ||
			!g.requireOrchestratorPermission(w, r, permissionNexusWorkspaceExecute) {
			return
		}
		if !g.workspaceAllowed(r, commandHost, commandRoot) ||
			!g.workspaceExecuteAllowed(r, commandHost, commandRoot) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		if !validOrchestratorToken(g.orchestrator.reviewToken) || g.orchestrator.reviewToken == g.orchestrator.token {
			writeError(w, http.StatusServiceUnavailable, "command review unavailable")
			return
		}
	}
	patchReview := patchRequest && !(r.Method == http.MethodPost && patch[3] == "")
	patchExecution := patchRequest && r.Method == http.MethodPost && (patch[4] == "apply" || patch[4] == "reconcile")
	if patchRequest {
		permission := permissionNexusPatchPropose
		if patchReview {
			permission = permissionNexusApprovalReview
		}
		if !g.requireOrchestratorPermission(w, r, permission) {
			return
		}
		if !g.workspaceAllowed(r, patch[1], patch[2]) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		if patchExecution {
			if !g.requireOrchestratorPermission(w, r, permissionNexusWorkspaceWrite) {
				return
			}
			if !g.workspaceWriteAllowed(r, patch[1], patch[2]) {
				writeError(w, http.StatusForbidden, "permission denied")
				return
			}
		}
		if !validOrchestratorToken(g.orchestrator.reviewToken) || g.orchestrator.reviewToken == g.orchestrator.token {
			writeError(w, http.StatusServiceUnavailable, "approval review unavailable")
			return
		}
	}
	if orchestratorWorkspaceFilesPath.MatchString(upstreamPath) || orchestratorWorkspaceContextPath.MatchString(upstreamPath) || orchestratorWorkspaceTasksPath.MatchString(upstreamPath) {
		parts := strings.Split(strings.TrimPrefix(upstreamPath, "/"), "/")
		if !g.workspaceAllowed(r, parts[3], parts[4]) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
	}
	runLookup := r.Method == http.MethodGet && orchestratorRunPath.MatchString(upstreamPath)
	if runLookup && !g.requireOrchestratorPermission(w, r, permissionChat) {
		return
	}
	query := ""
	if orchestratorWorkspaceFilesPath.MatchString(upstreamPath) || orchestratorWorkspaceContextPath.MatchString(upstreamPath) {
		if len(r.URL.RawQuery) > 2048 {
			writeError(w, http.StatusBadRequest, "invalid workspace path")
			return
		}
		values, err := url.ParseQuery(r.URL.RawQuery)
		pathValues := values["path"]
		workspacePath := ""
		if err != nil || len(values) > 1 || (len(values) == 1 && len(pathValues) != 1) {
			writeError(w, http.StatusBadRequest, "invalid workspace path")
			return
		}
		if len(pathValues) == 1 {
			workspacePath = pathValues[0]
		}
		if len(workspacePath) > 512 || !utf8.ValidString(workspacePath) || strings.HasPrefix(workspacePath, "/") ||
			strings.ContainsAny(workspacePath, "\\\x00") ||
			(orchestratorWorkspaceContextPath.MatchString(upstreamPath) && workspacePath == "") {
			writeError(w, http.StatusBadRequest, "invalid workspace path")
			return
		}
		for _, part := range strings.Split(workspacePath, "/") {
			if part == "." || part == ".." || (part == "" && workspacePath != "") {
				writeError(w, http.StatusBadRequest, "invalid workspace path")
				return
			}
		}
		if len(pathValues) == 1 {
			query = "?" + url.Values{"path": []string{workspacePath}}.Encode()
		}
	} else if r.URL.RawQuery != "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	workspaceTask := orchestratorWorkspaceTasksPath.MatchString(upstreamPath)
	var body []byte
	if r.Method == http.MethodPost {
		contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if upstreamPath == "/v1/nexus/agent-runs" || workspaceTask || patchRequest || commandRequest {
			if err != nil || contentType != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, "application/json required")
				return
			}
			maxBodyBytes := int64(maxOrchestratorRequestBytes)
			if workspaceTask {
				maxBodyBytes = 4096
			}
			if patchRequest {
				maxBodyBytes = 512 << 10
			}
			if commandRequest {
				maxBodyBytes = 4096
			}
			if r.ContentLength > maxBodyBytes {
				writeError(w, http.StatusRequestEntityTooLarge, "request too large")
				return
			}
			body, err = io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
			if err != nil || int64(len(body)) > maxBodyBytes {
				writeError(w, http.StatusRequestEntityTooLarge, "request too large")
				return
			}
			object, valid := uniqueOrchestratorObject(body)
			if !valid {
				writeError(w, http.StatusBadRequest, "invalid request")
				return
			}
			if upstreamPath == "/v1/nexus/agent-runs" {
				if !g.requireOrchestratorPermission(w, r, permissionChat) {
					return
				}
				if value, present := object["allow_proposals"]; present {
					var enabled bool
					if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &enabled) != nil {
						writeError(w, http.StatusBadRequest, "invalid proposal flag")
						return
					}
					if enabled {
						if !g.requireOrchestratorPermission(w, r, permissionNexusPatchPropose) {
							return
						}
						workspace, present := object["workspace"]
						if !present || bytes.Equal(bytes.TrimSpace(workspace), []byte("null")) {
							writeError(w, http.StatusBadRequest, "proposals require a selected workspace")
							return
						}
					}
				}
				if workspace, present := object["workspace"]; present && !bytes.Equal(bytes.TrimSpace(workspace), []byte("null")) &&
					!g.requireOrchestratorPermission(w, r, permissionNexusWorkspaceRead) {
					return
				}
				if workspace, present := object["workspace"]; present && !bytes.Equal(bytes.TrimSpace(workspace), []byte("null")) {
					host, id, valid := workspaceIdentity(workspace, "workspace_id")
					if !valid || !g.workspaceAllowed(r, host, id) {
						writeError(w, http.StatusForbidden, "permission denied")
						return
					}
				}
			}
		} else if r.ContentLength > 0 {
			writeError(w, http.StatusBadRequest, "request body not permitted")
			return
		} else {
			// Fail closed even for an undeclared chunked body.
			body, err = io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(body) != 0 {
				writeError(w, http.StatusBadRequest, "request body not permitted")
				return
			}
		}
	} else {
		// GET cannot be used to smuggle a request body or a query upstream.
		if r.ContentLength > 0 {
			writeError(w, http.StatusBadRequest, "request body not permitted")
			return
		}
		if r.Body != nil {
			first, err := io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(first) != 0 {
				writeError(w, http.StatusBadRequest, "request body not permitted")
				return
			}
		}
	}

	modelAction := r.Method == http.MethodPost && strings.HasPrefix(upstreamPath, "/v1/nexus/models/")
	if modelAction || upstreamPath == "/v1/nexus/agent-runs" {
		if !g.beginInference(w) {
			return
		}
		defer g.aiLifecycle.Unlock()
	}
	if modelAction {
		target := "unload"
		if upstreamPath != "/v1/nexus/models/unload" {
			target = strings.TrimSuffix(strings.TrimPrefix(upstreamPath, "/v1/nexus/models/"), "/load")
		}
		g.modelState.Lock()
		if g.modelStateErr != nil || g.cfg.ModelStatePath == "" {
			g.modelState.Unlock()
			writeError(w, http.StatusServiceUnavailable, "model state is unavailable")
			return
		}
		if err := writePendingModelSwitch(g.cfg.ModelStatePath, target); err != nil {
			g.modelStateErr = err
			g.modelState.Unlock()
			writeError(w, http.StatusServiceUnavailable, "could not safely record model switch")
			return
		}
		g.modelPending, g.modelSwitchActive = target, true
		g.modelState.Unlock()
		defer func() {
			g.modelState.Lock()
			g.modelSwitchActive = false
			g.modelState.Unlock()
		}()
	}

	// The upstream URL is a trusted constant. URL construction never considers
	// the client-supplied Host, query, Origin, forwarding headers or bearer.
	upstream, err := url.Parse(g.orchestrator.endpoint + upstreamPath + query)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "orchestrator unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 145*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, r.Method, upstream.String(), bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "orchestrator unavailable")
		return
	}
	upstreamToken := g.orchestrator.token
	if patchReview || commandRequest {
		upstreamToken = g.orchestrator.reviewToken
	}
	request.Header.Set("Authorization", "Bearer "+upstreamToken)
	request.Header.Set("Accept", "application/json")
	if patchRequest || commandRequest || upstreamPath == "/v1/nexus/agent-runs" ||
		(strings.HasPrefix(upstreamPath, "/v1/nexus/agent-runs/") && upstreamPath != "/v1/nexus/agent-runs/active") {
		principal, ok := r.Context().Value(principalKey{}).(string)
		if !ok || principal == "" {
			writeError(w, http.StatusForbidden, "verified principal required")
			return
		}
		digest := sha256.Sum256([]byte(principal))
		request.Header.Set("X-Nexus-Principal", hex.EncodeToString(digest[:]))
	}
	if r.Method == http.MethodPost && (upstreamPath == "/v1/nexus/agent-runs" || workspaceTask || patchRequest || commandRequest) {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := g.orchestrator.client.Do(request)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "orchestrator unavailable")
		return
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		writeError(w, http.StatusBadGateway, "orchestrator redirect rejected")
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// The orchestrator explicitly rejects these requests before initiating
		// a switch. Transport errors and 502 remain ambiguous and fail closed.
		if modelAction && (response.StatusCode == 400 || response.StatusCode == 409 ||
			response.StatusCode == 413 || response.StatusCode == 429 || response.StatusCode == 503) {
			g.modelState.Lock()
			if err := clearPendingModelSwitch(g.cfg.ModelStatePath); err != nil {
				g.modelStateErr = err
			} else {
				g.modelPending, g.modelStateErr = "", nil
			}
			g.modelState.Unlock()
		}
		// Preserve 503 when native PS5 control is disabled. Do not forward
		// untrusted upstream error text, cookies or infrastructure details.
		status := response.StatusCode
		switch status {
		case 400, 409, 413, 429, 503:
		case 403:
			if !patchExecution && !commandRequest {
				status = http.StatusBadGateway
			}
		case 404:
			if !patchRequest && !commandRequest && (r.Method != http.MethodGet || !orchestratorRunPath.MatchString(upstreamPath)) {
				status = http.StatusBadGateway
			}
		case 410:
			if r.Method != http.MethodPost || upstreamPath != "/v1/nexus/agent-runs" {
				status = http.StatusBadGateway
			}
		default:
			status = http.StatusBadGateway
		}
		writeError(w, status, "orchestrator unavailable or request rejected")
		return
	}
	if response.ContentLength > maxOrchestratorResponseBytes {
		writeError(w, http.StatusBadGateway, "orchestrator response too large")
		return
	}
	result, err := io.ReadAll(io.LimitReader(response.Body, maxOrchestratorResponseBytes+1))
	if err != nil || len(result) > maxOrchestratorResponseBytes || !json.Valid(result) {
		writeError(w, http.StatusBadGateway, "invalid orchestrator response")
		return
	}
	if patchRequest {
		object, valid := uniqueOrchestratorObject(result)
		var host, root string
		var executionEnabled *bool
		if !valid || json.Unmarshal(object["host"], &host) != nil || host != patch[1] ||
			json.Unmarshal(object["workspace_id"], &root) != nil || root != patch[2] ||
			json.Unmarshal(object["execution_enabled"], &executionEnabled) != nil || executionEnabled == nil || *executionEnabled != patchExecution {
			writeError(w, http.StatusBadGateway, "invalid approval response")
			return
		}
		if r.Method == http.MethodGet && patch[3] == "" {
			var items []json.RawMessage
			if json.Unmarshal(object["patches"], &items) != nil || items == nil || len(items) > 100 {
				writeError(w, http.StatusBadGateway, "invalid approval list")
				return
			}
		} else {
			record, ok := uniqueOrchestratorObject(object["patch"])
			proposalHost, proposalRoot, valid := workspaceIdentity(record["proposal"], "workspace_id")
			if !ok || !valid || proposalHost != patch[1] || proposalRoot != patch[2] {
				writeError(w, http.StatusBadGateway, "invalid approval scope")
				return
			}
		}
	}
	if commandRequest {
		object, valid := uniqueOrchestratorObject(result)
		var host, root string
		var enabled *bool
		expectedHost, expectedRoot := "", ""
		if command != nil {
			expectedHost, expectedRoot = command[1], command[2]
		} else {
			expectedHost, expectedRoot = commandProfiles[1], commandProfiles[2]
		}
		if !valid || json.Unmarshal(object["host"], &host) != nil || host != expectedHost ||
			json.Unmarshal(object["workspace_id"], &root) != nil || root != expectedRoot ||
			json.Unmarshal(object["execution_enabled"], &enabled) != nil || enabled == nil || *enabled != commandExecution {
			writeError(w, http.StatusBadGateway, "invalid command review response")
			return
		}
		if commandProfiles != nil {
			var generation string
			if json.Unmarshal(object["workspace_generation"], &generation) != nil || !principalDigest.MatchString(generation) {
				writeError(w, http.StatusBadGateway, "invalid fixed-profile root generation")
				return
			}
			var profiles []json.RawMessage
			if json.Unmarshal(object["profiles"], &profiles) != nil || profiles == nil || len(profiles) > 32 {
				writeError(w, http.StatusBadGateway, "invalid fixed-profile inventory")
				return
			}
			seen := make(map[string]bool)
			for _, value := range profiles {
				profile, valid := uniqueOrchestratorObject(value)
				var id, version string
				if !valid || len(profile) != 3 || json.Unmarshal(profile["id"], &id) != nil ||
					json.Unmarshal(profile["version"], &version) != nil ||
					!orchestratorCommandProfileID.MatchString(id) || !principalDigest.MatchString(version) ||
					seen[id] || len(profile["invocation"]) == 0 {
					writeError(w, http.StatusBadGateway, "invalid fixed-profile entry")
					return
				}
				seen[id] = true
			}
		} else if r.Method == http.MethodGet && command[3] == "" {
			var items []json.RawMessage
			if json.Unmarshal(object["commands"], &items) != nil || items == nil || len(items) > 100 {
				writeError(w, http.StatusBadGateway, "invalid command review list")
				return
			}
		} else {
			record, ok := uniqueOrchestratorObject(object["command"])
			proposalHost, proposalRoot, valid := workspaceIdentity(record["proposal"], "workspace_id")
			if !ok || !valid || proposalHost != expectedHost || proposalRoot != expectedRoot {
				writeError(w, http.StatusBadGateway, "invalid command review scope")
				return
			}
		}
	}
	if runLookup {
		object, valid := uniqueOrchestratorObject(result)
		var workspaceRequired bool
		field, present := object["workspace_required"]
		if !valid || !present || bytes.Equal(bytes.TrimSpace(field), []byte("null")) || json.Unmarshal(field, &workspaceRequired) != nil {
			writeError(w, http.StatusBadGateway, "invalid orchestrator response")
			return
		}
		if workspaceRequired && !g.requireOrchestratorPermission(w, r, permissionNexusWorkspaceRead) {
			return
		}
		if workspaceRequired {
			host, id, valid := workspaceIdentity(object["workspace_identity"], "id")
			if !valid || !g.workspaceAllowed(r, host, id) {
				writeError(w, http.StatusForbidden, "permission denied")
				return
			}
		}
		// Typed checkpoints are navigation metadata, never execute authority.
		// Unknown kinds, unbound IDs and non-waiting approvals fail closed.
		// Old upstreams may omit the kind; the native client then shows no
		// privileged review link rather than guessing from a phase string.
		if raw, present := object["approval_kind"]; present &&
			!bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			var kind, approvalID, status string
			if json.Unmarshal(raw, &kind) != nil || (kind != "patch" && kind != "command") ||
				json.Unmarshal(object["approval_id"], &approvalID) != nil ||
				!orchestratorApprovalID.MatchString(approvalID) ||
				json.Unmarshal(object["status"], &status) != nil ||
				status != "waiting_for_approval" || !workspaceRequired {
				writeError(w, http.StatusBadGateway, "invalid agent approval metadata")
				return
			}
		}
	}
	if upstreamPath == "/v1/nexus/workspaces" || orchestratorWorkspaceListPath.MatchString(upstreamPath) {
		object, valid := uniqueOrchestratorObject(result)
		var entries []json.RawMessage
		if !valid || json.Unmarshal(object["workspaces"], &entries) != nil || entries == nil || len(entries) > 32 {
			writeError(w, http.StatusBadGateway, "invalid orchestrator response")
			return
		}
		host := ""
		if orchestratorWorkspaceListPath.MatchString(upstreamPath) {
			host = strings.TrimPrefix(upstreamPath, "/v1/nexus/workspaces/")
			var responseHost string
			if json.Unmarshal(object["host"], &responseHost) != nil || responseHost != host {
				writeError(w, http.StatusBadGateway, "invalid orchestrator response")
				return
			}
		}
		filtered := make([]json.RawMessage, 0, len(entries))
		for _, entry := range entries {
			entryObject, valid := uniqueOrchestratorObject(entry)
			var id, entryHost string
			if !valid || json.Unmarshal(entryObject["id"], &id) != nil {
				writeError(w, http.StatusBadGateway, "invalid orchestrator response")
				return
			}
			entryHost = host
			if host == "" && json.Unmarshal(entryObject["host"], &entryHost) != nil {
				writeError(w, http.StatusBadGateway, "invalid orchestrator response")
				return
			}
			if !workspaceGrantID.MatchString(entryHost + ":" + id) {
				writeError(w, http.StatusBadGateway, "invalid orchestrator response")
				return
			}
			if g.workspaceAllowed(r, entryHost, id) {
				filtered = append(filtered, entry)
			}
		}
		object["workspaces"], err = json.Marshal(filtered)
		if err == nil {
			result, err = json.Marshal(object)
		}
		if err != nil {
			writeError(w, http.StatusBadGateway, "invalid orchestrator response")
			return
		}
	}
	if r.Method == http.MethodPost && (orchestratorCancelRunPath.MatchString(upstreamPath) || orchestratorCancelSubagentPath.MatchString(upstreamPath)) {
		// Cancellation must not expose a result after inference or workspace access is revoked.
		object, valid := uniqueOrchestratorObject(result)
		if !valid {
			writeError(w, http.StatusBadGateway, "invalid orchestrator response")
			return
		}
		allowed := map[string]bool{"id": true, "status": true, "created_at": true, "updated_at": true,
			"phase": true, "error": true, "cancel_requested": true, "subagents": true, "events": true,
			"workspace_required": true}
		for key := range object {
			if !allowed[key] {
				delete(object, key)
			}
		}
		result, err = json.Marshal(object)
		if err != nil {
			writeError(w, http.StatusBadGateway, "invalid orchestrator response")
			return
		}
	}
	if upstreamPath == "/v1/nexus/status" {
		g.confirmModelStatus(result)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(result)
}
