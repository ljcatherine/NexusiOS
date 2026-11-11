package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	permissionModels                = "ai.models"
	permissionChat                  = "ai.chat"
	permissionSearch                = "ai.search"
	permissionHistory               = "ai.history"
	permissionSSHConnect            = "ssh.connect"
	permissionMinecraftPanel        = "minecraft.panel"
	permissionOrchestrate           = "nexus.orchestrate"
	permissionNexusModelRead        = "nexus.model.read"
	permissionNexusModelControl     = "nexus.model.control"
	permissionNexusWorkspaceRead    = "nexus.workspace.read"
	permissionNexusWorkspaceWrite   = "nexus.workspace.write"
	permissionNexusWorkspaceExecute = "nexus.workspace.execute"
	permissionNexusPatchPropose     = "nexus.workspace.propose"
	permissionNexusApprovalReview   = "nexus.approvals.review"
	maxRequestBytes                 = 8 << 20
	maxMessages                     = 100
	maxMessageBytes                 = 128 << 10
	maxImagesPerMessage             = 3
	maxImageBytes                   = 512 << 10
	maxCombinedImageBytes           = 1 << 20
	maxOutputTokens                 = 16384
	maxStreamResponseBytes          = 4 << 20
)

type Config struct {
	IssuerURL                  string
	OIDCAudience               string
	OIDCJWKSURL                string
	OIDCPrincipalClaim         string
	SubjectPermissions         map[string]map[string]bool
	WorkspaceGrants            map[string]map[string]bool
	WorkspaceWriteGrants       map[string]map[string]bool
	WorkspaceExecuteGrants     map[string]map[string]bool
	Upstream                   *url.URL
	UpstreamBearerToken        string
	AllowedModels              map[string]bool
	AllowUpstreamModels        bool
	ListenAddress              string
	RequestTimeout             time.Duration
	RequestsPerMinute          int
	MetadataRequestsPerMinute  int
	MaximumConcurrentAI        int
	SearchProvider             string
	SearchURL                  *url.URL
	SearchAPIKey               string
	SearchTimeout              time.Duration
	SearchMaxResults           int
	SearchFetchPages           bool
	ConversationDirectory      string
	ModelStatePath             string
	ConversationEncryptionKey  []byte
	SSHPrivateKeyPath          string
	SSHHostKeyPath             string
	SSHKnownHostsPath          string
	SSHTargets                 map[string]SSHTarget
	MinecraftPanelOrigin       *url.URL
	MinecraftPanelPublicOrigin *url.URL
	OrchestratorBearerToken    string
	ApprovalReviewBearerToken  string
}

// SSHTarget is an operator-defined destination. The public API accepts only its
// short alias; clients cannot supply arbitrary hosts, ports, or usernames.
type SSHTarget struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
}

func loadConfig() (Config, error) {
	var cfg Config
	var err error
	cfg.IssuerURL = strings.TrimSpace(os.Getenv("NEXUS_OIDC_ISSUER"))
	cfg.OIDCAudience = strings.TrimSpace(os.Getenv("NEXUS_OIDC_AUDIENCE"))
	cfg.OIDCJWKSURL = strings.TrimSpace(os.Getenv("NEXUS_OIDC_JWKS_URL"))
	cfg.OIDCPrincipalClaim = strings.TrimSpace(os.Getenv("NEXUS_OIDC_PRINCIPAL_CLAIM"))
	if cfg.OIDCPrincipalClaim == "" {
		cfg.OIDCPrincipalClaim = "sub"
	}
	if cfg.OIDCPrincipalClaim != "sub" && cfg.OIDCPrincipalClaim != "email" {
		return cfg, errors.New("NEXUS_OIDC_PRINCIPAL_CLAIM must be sub or email")
	}
	cfg.ListenAddress = strings.TrimSpace(os.Getenv("NEXUS_GATEWAY_LISTEN"))
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "127.0.0.1:8787"
	}
	if !loopbackListenAddress(cfg.ListenAddress) {
		return cfg, errors.New("gateway listener must be bound to loopback")
	}
	panelOriginRaw := strings.TrimSpace(os.Getenv("NEXUS_MINECRAFT_PANEL_ORIGIN"))
	publicOriginRaw := strings.TrimSpace(os.Getenv("NEXUS_MINECRAFT_PUBLIC_ORIGIN"))
	if (panelOriginRaw == "") != (publicOriginRaw == "") {
		return cfg, errors.New("NEXUS_MINECRAFT_PANEL_ORIGIN and NEXUS_MINECRAFT_PUBLIC_ORIGIN must be configured together")
	}
	if panelOriginRaw != "" {
		cfg.MinecraftPanelOrigin, err = parseHTTPSOrigin(panelOriginRaw)
		if err != nil {
			return cfg, errors.New("NEXUS_MINECRAFT_PANEL_ORIGIN must be a clean HTTPS origin")
		}
		cfg.MinecraftPanelPublicOrigin, err = parseHTTPSOrigin(publicOriginRaw)
		if err != nil || !strings.HasSuffix(strings.ToLower(cfg.MinecraftPanelPublicOrigin.Hostname()), ".workers.dev") {
			return cfg, errors.New("NEXUS_MINECRAFT_PUBLIC_ORIGIN must be a clean HTTPS workers.dev origin")
		}
	}
	cfg.SSHPrivateKeyPath = strings.TrimSpace(os.Getenv("NEXUS_SSH_UPSTREAM_KEY"))
	cfg.SSHHostKeyPath = strings.TrimSpace(os.Getenv("NEXUS_SSH_RELAY_HOST_KEY"))
	cfg.SSHKnownHostsPath = strings.TrimSpace(os.Getenv("NEXUS_SSH_KNOWN_HOSTS"))
	if raw := strings.TrimSpace(os.Getenv("NEXUS_SSH_TARGETS_JSON")); raw != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&cfg.SSHTargets); err != nil || cfg.SSHTargets == nil || decoder.Decode(new(any)) != io.EOF {
			return cfg, errors.New("NEXUS_SSH_TARGETS_JSON is invalid")
		}
		if len(cfg.SSHTargets) > 16 {
			return cfg, errors.New("NEXUS_SSH_TARGETS_JSON has too many targets")
		}
		for alias, target := range cfg.SSHTargets {
			if !validSSHAlias(alias) || !validSSHHost(target.Host) || target.Port < 1 || target.Port > 65535 ||
				target.Username == "" || len(target.Username) > 64 || strings.ContainsAny(target.Username, "\r\n\x00") {
				return cfg, errors.New("NEXUS_SSH_TARGETS_JSON contains an invalid target")
			}
		}
	}
	if cfg.IssuerURL == "" || cfg.OIDCAudience == "" {
		return cfg, errors.New("NEXUS_OIDC_ISSUER and NEXUS_OIDC_AUDIENCE are required")
	}
	if !validOIDCAudience(cfg.OIDCAudience) {
		return cfg, errors.New("NEXUS_OIDC_AUDIENCE must be a clean HTTPS URI or a valid Cloudflare Access audience tag")
	}
	issuer, err := url.Parse(cfg.IssuerURL)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return cfg, errors.New("NEXUS_OIDC_ISSUER must be a clean HTTPS issuer URL")
	}
	if cfg.OIDCJWKSURL != "" {
		jwks, parseErr := url.Parse(cfg.OIDCJWKSURL)
		if parseErr != nil || jwks.Scheme != "https" || jwks.Host != issuer.Host || jwks.User != nil ||
			jwks.RawQuery != "" || jwks.ForceQuery || jwks.Fragment != "" {
			return cfg, errors.New("NEXUS_OIDC_JWKS_URL must be a clean HTTPS URL on the configured issuer host")
		}
	}

	permissionsRaw := strings.TrimSpace(os.Getenv("NEXUS_SUBJECT_PERMISSIONS_JSON"))
	if permissionsRaw == "" {
		return cfg, errors.New("NEXUS_SUBJECT_PERMISSIONS_JSON is required; an empty policy denies all users")
	}
	if len(permissionsRaw) > 64<<10 {
		return cfg, errors.New("NEXUS_SUBJECT_PERMISSIONS_JSON exceeds 64 KiB")
	}
	cfg.SubjectPermissions, err = parseSubjectPermissions(permissionsRaw)
	if err != nil {
		return cfg, err
	}
	cfg.WorkspaceGrants = make(map[string]map[string]bool)
	workspaceGrants := strings.TrimSpace(os.Getenv("NEXUS_WORKSPACE_GRANTS_JSON"))
	if workspaceGrants != "" {
		cfg.WorkspaceGrants, err = parseWorkspaceGrants(workspaceGrants)
		if err != nil {
			return cfg, err
		}
	}
	cfg.WorkspaceWriteGrants = make(map[string]map[string]bool)
	if raw := os.Getenv("NEXUS_WORKSPACE_WRITE_GRANTS_JSON"); strings.TrimSpace(raw) != "" {
		cfg.WorkspaceWriteGrants, err = parseWorkspaceGrants(raw)
		if err != nil {
			return Config{}, fmt.Errorf("write grants: %w", err)
		}
	}

	cfg.WorkspaceExecuteGrants = make(map[string]map[string]bool)
	if raw := os.Getenv("NEXUS_WORKSPACE_EXECUTE_GRANTS_JSON"); strings.TrimSpace(raw) != "" {
		cfg.WorkspaceExecuteGrants, err = parseWorkspaceGrants(raw)
		if err != nil {
			return Config{}, fmt.Errorf("execute grants: %w", err)
		}
	}

	upstreamRaw := strings.TrimSpace(os.Getenv("NEXUS_AI_UPSTREAM_URL"))
	upstream, err := url.Parse(upstreamRaw)
	if err != nil || !validUpstreamURL(upstream) {
		return cfg, errors.New("NEXUS_AI_UPSTREAM_URL must be HTTPS or HTTP on a private IPv4 address, with no credentials, query, or fragment")
	}
	cfg.Upstream = upstream
	cfg.UpstreamBearerToken = os.Getenv("NEXUS_AI_UPSTREAM_TOKEN")
	cfg.OrchestratorBearerToken = os.Getenv("NEXUS_ORCHESTRATOR_TOKEN")
	if cfg.OrchestratorBearerToken != "" && !validOrchestratorToken(cfg.OrchestratorBearerToken) {
		return cfg, errors.New("NEXUS_ORCHESTRATOR_TOKEN must have 32–256 non-whitespace characters")
	}
	cfg.ApprovalReviewBearerToken = os.Getenv("NEXUS_APPROVAL_REVIEW_TOKEN")
	if cfg.ApprovalReviewBearerToken != "" && (!validOrchestratorToken(cfg.ApprovalReviewBearerToken) ||
		cfg.OrchestratorBearerToken == "" || cfg.ApprovalReviewBearerToken == cfg.OrchestratorBearerToken ||
		cfg.ApprovalReviewBearerToken == cfg.UpstreamBearerToken) {
		return cfg, errors.New("approval review requires a distinct private token and configured orchestrator")
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NEXUS_AI_ALLOW_UPSTREAM_MODELS"))) {
	case "", "false":
	case "true":
		cfg.AllowUpstreamModels = true
	default:
		return cfg, errors.New("NEXUS_AI_ALLOW_UPSTREAM_MODELS must be true or false")
	}
	cfg.AllowedModels = map[string]bool{}
	for _, model := range strings.Split(os.Getenv("NEXUS_AI_ALLOWED_MODELS"), ",") {
		model = strings.TrimSpace(model)
		if model != "" {
			cfg.AllowedModels[model] = true
		}
	}
	if len(cfg.AllowedModels) == 0 && !cfg.AllowUpstreamModels {
		return cfg, errors.New("NEXUS_AI_ALLOWED_MODELS must list at least one approved model identifier")
	}
	cfg.SearchProvider = strings.ToLower(strings.TrimSpace(os.Getenv("NEXUS_SEARCH_PROVIDER")))
	switch cfg.SearchProvider {
	case "": // Web research stays disabled unless an operator configures it.
	case "brave":
		cfg.SearchAPIKey = strings.TrimSpace(os.Getenv("NEXUS_BRAVE_API_KEY"))
		if cfg.SearchAPIKey == "" || len(cfg.SearchAPIKey) > 4096 {
			return cfg, errors.New("NEXUS_BRAVE_API_KEY is required for the Brave search provider")
		}
	case "searxng":
		searchRaw := strings.TrimSpace(os.Getenv("NEXUS_SEARXNG_URL"))
		searchURL, parseErr := url.Parse(searchRaw)
		if parseErr != nil || !validSearchURL(searchURL) {
			return cfg, errors.New("NEXUS_SEARXNG_URL must be HTTPS or HTTP on a private IPv4 address, without credentials, query, or fragment")
		}
		cfg.SearchURL = searchURL
	default:
		return cfg, errors.New("NEXUS_SEARCH_PROVIDER must be brave, searxng, or empty")
	}
	cfg.SearchTimeout = envDuration("NEXUS_SEARCH_TIMEOUT", 15*time.Second)
	if cfg.SearchTimeout < 2*time.Second || cfg.SearchTimeout > time.Minute {
		return cfg, errors.New("NEXUS_SEARCH_TIMEOUT must be between 2 seconds and 1 minute")
	}
	cfg.SearchMaxResults = envInt("NEXUS_SEARCH_MAX_RESULTS", 5)
	if cfg.SearchMaxResults < 1 || cfg.SearchMaxResults > maxSearchResults {
		return cfg, errors.New("NEXUS_SEARCH_MAX_RESULTS must be between 1 and 10")
	}
	cfg.SearchFetchPages = cfg.SearchProvider != ""
	if raw := strings.TrimSpace(os.Getenv("NEXUS_SEARCH_FETCH_PAGES")); raw != "" {
		fetchPages, err := strconv.ParseBool(raw)
		if err != nil {
			return cfg, errors.New("NEXUS_SEARCH_FETCH_PAGES must be true or false")
		}
		cfg.SearchFetchPages = fetchPages
	}
	cfg.RequestTimeout = envDuration("NEXUS_AI_REQUEST_TIMEOUT", 15*time.Minute)
	if cfg.RequestTimeout < 10*time.Second || cfg.RequestTimeout > 30*time.Minute {
		return cfg, errors.New("NEXUS_AI_REQUEST_TIMEOUT must be between 10 seconds and 30 minutes")
	}
	cfg.RequestsPerMinute = envInt("NEXUS_AI_REQUESTS_PER_MINUTE", 30)
	if cfg.RequestsPerMinute < 1 || cfg.RequestsPerMinute > 600 {
		return cfg, errors.New("NEXUS_AI_REQUESTS_PER_MINUTE must be between 1 and 600")
	}
	cfg.MetadataRequestsPerMinute = envInt("NEXUS_AI_METADATA_REQUESTS_PER_MINUTE", 120)
	if cfg.MetadataRequestsPerMinute < 1 || cfg.MetadataRequestsPerMinute > 1200 {
		return cfg, errors.New("NEXUS_AI_METADATA_REQUESTS_PER_MINUTE must be between 1 and 1200")
	}
	cfg.MaximumConcurrentAI = envInt("NEXUS_AI_MAX_CONCURRENT", 2)
	if cfg.MaximumConcurrentAI < 1 || cfg.MaximumConcurrentAI > 16 {
		return cfg, errors.New("NEXUS_AI_MAX_CONCURRENT must be between 1 and 16")
	}
	cfg.ConversationDirectory = strings.TrimSpace(os.Getenv("NEXUS_CONVERSATIONS_DIR"))
	if cfg.ConversationDirectory == "" {
		cfg.ConversationDirectory = "/var/lib/nexus-gateway/conversations"
	}
	if !filepath.IsAbs(cfg.ConversationDirectory) || filepath.Clean(cfg.ConversationDirectory) != cfg.ConversationDirectory {
		return cfg, errors.New("NEXUS_CONVERSATIONS_DIR must be an absolute normalized path")
	}
	cfg.ModelStatePath = strings.TrimSpace(os.Getenv("NEXUS_MODEL_STATE_PATH"))
	if cfg.ModelStatePath == "" {
		cfg.ModelStatePath = "/var/lib/nexus-gateway/model-state/pending-switch.json"
	}
	if !filepath.IsAbs(cfg.ModelStatePath) || filepath.Clean(cfg.ModelStatePath) != cfg.ModelStatePath {
		return cfg, errors.New("NEXUS_MODEL_STATE_PATH must be an absolute normalized path")
	}
	key, err := parseConversationEncryptionKey(os.Getenv("NEXUS_CONVERSATION_ENCRYPTION_KEY"))
	if err != nil {
		return cfg, err
	}
	cfg.ConversationEncryptionKey = key
	return cfg, nil
}

func parseHTTPSOrigin(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, errors.New("invalid HTTPS origin")
	}
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid origin port")
		}
	}
	parsed.Path = ""
	return parsed, nil
}

func parseSubjectPermissions(raw string) (map[string]map[string]bool, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	root, err := decoder.Token()
	if err != nil || root != json.Delim('{') {
		return nil, errors.New("NEXUS_SUBJECT_PERMISSIONS_JSON must be a JSON object mapping OIDC subjects to permissions")
	}
	permissions := make(map[string]map[string]bool)
	seen := make(map[string]struct{})
	for decoder.More() {
		key, err := decoder.Token()
		subject, ok := key.(string)
		if err != nil || !ok || strings.TrimSpace(subject) == "" {
			return nil, errors.New("OIDC subject policy contains an empty or invalid subject")
		}
		subject = strings.TrimSpace(subject)
		if _, duplicate := seen[subject]; duplicate {
			return nil, errors.New("OIDC subject policy contains duplicate subjects after whitespace normalization")
		}
		seen[subject] = struct{}{}
		if len(seen) > 256 {
			return nil, errors.New("OIDC subject policy may contain at most 256 subjects")
		}
		var scopes []string
		if err := decoder.Decode(&scopes); err != nil || scopes == nil || len(scopes) > 16 {
			return nil, errors.New("OIDC subject permissions must be a JSON array of at most 16 entries")
		}
		set := make(map[string]bool, len(scopes))
		for _, scope := range scopes {
			if scope != permissionModels && scope != permissionChat && scope != permissionSearch && scope != permissionHistory && scope != permissionSSHConnect && scope != permissionMinecraftPanel && scope != permissionOrchestrate && scope != permissionNexusModelRead && scope != permissionNexusModelControl && scope != permissionNexusWorkspaceRead && scope != permissionNexusPatchPropose && scope != permissionNexusApprovalReview && scope != permissionNexusWorkspaceWrite && scope != permissionNexusWorkspaceExecute {
				return nil, fmt.Errorf("unsupported permission %q", scope)
			}
			if set[scope] {
				return nil, fmt.Errorf("duplicate permission %q", scope)
			}
			set[scope] = true
		}
		permissions[subject] = set
	}
	if _, err := decoder.Token(); err != nil {
		return nil, errors.New("NEXUS_SUBJECT_PERMISSIONS_JSON has an incomplete object")
	}
	if len(permissions) == 0 {
		return nil, errors.New("NEXUS_SUBJECT_PERMISSIONS_JSON must not be empty")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("NEXUS_SUBJECT_PERMISSIONS_JSON has trailing data")
	}
	return permissions, nil
}

func parseConversationEncryptionKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, errors.New("NEXUS_CONVERSATION_ENCRYPTION_KEY must be a base64-encoded 32-byte key")
	}
	return key, nil
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil {
		return fallback
	}
	return value
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0
	}
	return duration
}

func validUpstreamURL(value *url.URL) bool {
	if value == nil || value.Host == "" || value.User != nil || value.RawQuery != "" || value.Fragment != "" {
		return false
	}
	if value.Scheme == "https" {
		return true
	}
	if value.Scheme != "http" {
		return false
	}
	ip := net.ParseIP(value.Hostname())
	return ip != nil && isPrivateIPv4(ip)
}

func validSearchURL(value *url.URL) bool {
	if value == nil || value.Host == "" || value.User != nil || value.RawQuery != "" || value.ForceQuery || value.Fragment != "" {
		return false
	}
	if value.Scheme == "https" {
		return true
	}
	if value.Scheme != "http" {
		return false
	}
	ip := net.ParseIP(value.Hostname())
	return ip != nil && isPrivateIPv4(ip)
}

func validOIDCAudience(value string) bool {
	audience, err := url.Parse(value)
	if err == nil && audience.Scheme == "https" && audience.Host != "" && audience.User == nil &&
		audience.RawQuery == "" && !audience.ForceQuery && audience.Fragment == "" {
		return true
	}
	if len(value) < 16 || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func isPrivateIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 10 || v4[0] == 127 ||
		(v4[0] == 192 && v4[1] == 168) ||
		(v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31) ||
		(v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127) ||
		(v4[0] == 169 && v4[1] == 254)
}

func loopbackListenAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type TokenVerifier interface {
	Subject(context.Context, string) (string, error)
}

type OIDCAccessTokenVerifier struct {
	verifier       *oidc.IDTokenVerifier
	principalClaim string
}

func NewOIDCAccessTokenVerifier(ctx context.Context, issuer, audience string) (*OIDCAccessTokenVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, errors.New("cannot load configured OIDC provider metadata")
	}
	return &OIDCAccessTokenVerifier{verifier: provider.Verifier(&oidc.Config{ClientID: audience}), principalClaim: "sub"}, nil
}

func NewOIDCAccessTokenVerifierWithJWKS(ctx context.Context, issuer, audience, jwksURL, principalClaim string) (*OIDCAccessTokenVerifier, error) {
	if principalClaim != "sub" && principalClaim != "email" {
		return nil, errors.New("unsupported OIDC principal claim")
	}
	keySet := oidc.NewRemoteKeySet(ctx, jwksURL)
	return &OIDCAccessTokenVerifier{
		verifier:       oidc.NewVerifier(issuer, keySet, &oidc.Config{ClientID: audience}),
		principalClaim: principalClaim,
	}, nil
}

func (v *OIDCAccessTokenVerifier) Subject(ctx context.Context, raw string) (string, error) {
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return "", errors.New("invalid bearer token")
	}
	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	if err := token.Claims(&claims); err != nil {
		return "", errors.New("missing subject claim")
	}
	if v.principalClaim == "email" {
		if strings.TrimSpace(claims.Email) == "" {
			return "", errors.New("missing email claim")
		}
		return strings.ToLower(strings.TrimSpace(claims.Email)), nil
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return "", errors.New("missing subject claim")
	}
	return claims.Subject, nil
}

type principalKey struct{}

type apiMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	ToolCalls  []apiToolCall   `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
}

type apiToolCall struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Function apiToolFunction `json:"function"`
}

type apiToolFunction struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type apiToolDefinition struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type completionContentPart struct {
	Type     string              `json:"type"`
	Text     string              `json:"text,omitempty"`
	ImageURL *completionImageURL `json:"image_url,omitempty"`
}

type completionImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

type completionRequest struct {
	Model             string              `json:"model"`
	Messages          []apiMessage        `json:"messages"`
	Stream            bool                `json:"stream"`
	MaxTokens         *int                `json:"max_tokens,omitempty"`
	Temperature       *float64            `json:"temperature,omitempty"`
	TopP              *float64            `json:"top_p,omitempty"`
	Tools             []apiToolDefinition `json:"tools,omitempty"`
	ToolChoice        string              `json:"tool_choice,omitempty"`
	ParallelToolCalls *bool               `json:"parallel_tool_calls,omitempty"`
}

type modelEnvelope struct {
	Data []modelEntry `json:"data"`
}

type modelEntry struct {
	ID     string `json:"id"`
	Object string `json:"object"`
}

type requestCounter struct {
	window time.Time
	count  int
}

type Gateway struct {
	cfg               Config
	verifier          TokenVerifier
	searcher          Searcher
	client            *http.Client
	semaphore         chan struct{}
	mu                sync.Mutex
	counters          map[string]requestCounter
	metadataCounters  map[string]requestCounter
	pageFetcher       PageFetcher
	conversationStore *EncryptedConversationStore
	sshSessions       chan struct{}
	minecraftPanel    *httputil.ReverseProxy
	orchestrator      *nexusOrchestratorProxy
	aiLifecycle       sync.Mutex
	modelState        sync.Mutex
	modelPending      string
	modelSwitchActive bool
	modelStateErr     error
}

func NewGateway(cfg Config, verifier TokenVerifier) *Gateway {
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        32,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		// Local models can take several minutes to produce the first token.
		// The request context remains the authoritative upper bound.
		ResponseHeaderTimeout: cfg.RequestTimeout,
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	gateway := &Gateway{cfg: cfg, verifier: verifier, searcher: newSearcher(cfg), client: client,
		semaphore: make(chan struct{}, cfg.MaximumConcurrentAI), counters: make(map[string]requestCounter)}
	gateway.sshSessions = make(chan struct{}, 4)
	if cfg.SearchFetchPages {
		gateway.pageFetcher = NewSafePageFetcher()
	}
	if len(cfg.ConversationEncryptionKey) == 32 {
		gateway.conversationStore = NewEncryptedConversationStore(cfg.ConversationDirectory, cfg.ConversationEncryptionKey)
	}
	if cfg.MinecraftPanelOrigin != nil && cfg.MinecraftPanelPublicOrigin != nil {
		gateway.minecraftPanel = newMinecraftPanelProxy(cfg)
	}
	if cfg.OrchestratorBearerToken != "" {
		gateway.orchestrator = newNexusOrchestratorProxy(cfg.OrchestratorBearerToken)
		gateway.orchestrator.reviewToken = cfg.ApprovalReviewBearerToken
	}
	if cfg.ModelStatePath != "" {
		pending, err := readPendingModelSwitch(cfg.ModelStatePath)
		gateway.modelPending, gateway.modelStateErr = pending, err
	}
	// A restart must retain unknown switches, but may confirm an exact target
	// already proven ready by the private controller. No inference is replayed.
	gateway.aiLifecycle.Lock()
	gateway.reconcilePendingModelSwitch()
	gateway.aiLifecycle.Unlock()
	return gateway
}

func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /internal/nexus/authorize-run", g.authorizeInternalRun)
	mux.HandleFunc("POST /internal/nexus/authorize-workspace-operation", g.authorizeInternalWorkspaceOperation)
	mux.Handle("GET /v1/models", g.authorize(permissionModels, http.HandlerFunc(g.models)))
	mux.Handle("GET /v1/context", g.authorize(permissionModels, http.HandlerFunc(g.contextWindow)))
	mux.Handle("POST /v1/chat/completions", g.authorize(permissionChat, http.HandlerFunc(g.completions)))
	mux.Handle("POST /v1/chat/completions/input_tokens", g.authorize(permissionChat, http.HandlerFunc(g.inputTokens)))
	mux.Handle("POST /v1/search", g.authorize(permissionSearch, http.HandlerFunc(g.search)))
	mux.Handle("POST /v1/research", g.authorize(permissionChat, http.HandlerFunc(g.research)))
	mux.Handle("GET /v1/conversations", g.authorize(permissionHistory, http.HandlerFunc(g.listConversations)))
	mux.Handle("GET /v1/conversations/{id}", g.authorize(permissionHistory, http.HandlerFunc(g.getConversation)))
	mux.Handle("PUT /v1/conversations/{id}", g.authorize(permissionHistory, http.HandlerFunc(g.putConversation)))
	mux.Handle("DELETE /v1/conversations/{id}", g.authorize(permissionHistory, http.HandlerFunc(g.deleteConversation)))
	mux.Handle("GET /v1/ssh/{target}", g.authorize(permissionSSHConnect, http.HandlerFunc(g.sshRelay)))
	mux.Handle("GET /v1/nexus/workspaces", g.authorize(permissionNexusWorkspaceRead, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("GET /v1/nexus/workspaces/{host}", g.authorize(permissionNexusWorkspaceRead, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("GET /v1/nexus/workspaces/{host}/{id}/files", g.authorize(permissionNexusWorkspaceRead, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("GET /v1/nexus/workspaces/{host}/{id}/context", g.authorize(permissionNexusWorkspaceRead, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("POST /v1/nexus/workspaces/{host}/{id}/tasks", g.authorize(permissionNexusWorkspaceRead, http.HandlerFunc(g.serveNexusOrchestrator)))
	for _, route := range []string{
		"GET /v1/nexus/workspaces/{host}/{id}/patches", "POST /v1/nexus/workspaces/{host}/{id}/patches",
		"GET /v1/nexus/workspaces/{host}/{id}/patches/{patchID}", "POST /v1/nexus/workspaces/{host}/{id}/patches/{patchID}/decision",
		"POST /v1/nexus/workspaces/{host}/{id}/patches/{patchID}/apply", "POST /v1/nexus/workspaces/{host}/{id}/patches/{patchID}/reconcile",
	} {
		mux.Handle(route, g.authorize(permissionNexusWorkspaceRead, http.HandlerFunc(g.serveNexusOrchestrator)))
	}
	for _, route := range []string{
		"GET /v1/nexus/workspaces/{host}/{id}/commands", "POST /v1/nexus/workspaces/{host}/{id}/commands",
		"GET /v1/nexus/workspaces/{host}/{id}/commands/profiles",
		"GET /v1/nexus/workspaces/{host}/{id}/commands/{commandID}",
		"POST /v1/nexus/workspaces/{host}/{id}/commands/{commandID}/decision",
		"POST /v1/nexus/workspaces/{host}/{id}/commands/{commandID}/execute",
		"POST /v1/nexus/workspaces/{host}/{id}/commands/{commandID}/reconcile",
		"POST /v1/nexus/workspaces/{host}/{id}/commands/{commandID}/cancel",
	} {
		mux.Handle(route, g.authorize(permissionNexusWorkspaceRead, http.HandlerFunc(g.serveNexusOrchestrator)))
	}
	mux.Handle("POST /v1/nexus/agent-runs", g.authorize(permissionOrchestrate, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("GET /v1/nexus/agent-runs", g.authorize(permissionOrchestrate, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("GET /v1/nexus/agent-runs/active", g.authorize(permissionOrchestrate, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("GET /v1/nexus/agent-runs/{runID}", g.authorize(permissionOrchestrate, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("POST /v1/nexus/agent-runs/{runID}/cancel", g.authorize(permissionOrchestrate, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("POST /v1/nexus/agent-runs/{runID}/subagents/{childID}/cancel", g.authorize(permissionOrchestrate, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("GET /v1/nexus/models", g.authorize(permissionNexusModelRead, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("GET /v1/nexus/status", g.authorize(permissionNexusModelRead, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("GET /v1/nexus/models/status", g.authorize(permissionNexusModelRead, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("POST /v1/nexus/models/unload", g.authorize(permissionNexusModelControl, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("POST /v1/nexus/models/{id}/load", g.authorize(permissionNexusModelControl, http.HandlerFunc(g.serveNexusOrchestrator)))
	mux.Handle("/v1/minecraft/panel", g.authorize(permissionMinecraftPanel, http.HandlerFunc(g.serveMinecraftPanel)))
	mux.Handle("/v1/minecraft/panel/", g.authorize(permissionMinecraftPanel, http.HandlerFunc(g.serveMinecraftPanel)))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { writeError(w, http.StatusNotFound, "not found") })
	return g.logRequests(mux)
}

const minecraftPanelGatewayPrefix = "/v1/minecraft/panel"
const maxMinecraftPanelRequestBytes = 64 << 20

func newMinecraftPanelProxy(cfg Config) *httputil.ReverseProxy {
	target := &url.URL{Scheme: "http", Host: "127.0.0.1:8080"}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			panelPath := strings.TrimPrefix(request.In.URL.Path, minecraftPanelGatewayPrefix)
			if panelPath == "" {
				panelPath = "/"
			}
			request.SetURL(target)
			request.Out.URL.Path = panelPath
			request.Out.URL.RawPath = ""
			request.Out.URL.RawQuery = request.In.URL.RawQuery
			request.Out.Host = cfg.MinecraftPanelOrigin.Host
			request.Out.Header.Del("Authorization")
			request.Out.Header.Del("Cf-Access-Jwt-Assertion")
			request.Out.Header.Del("Accept-Encoding")
			request.Out.Header.Set("X-Forwarded-Proto", "https")
			request.Out.Header.Set("X-Forwarded-Host", cfg.MinecraftPanelOrigin.Host)
			request.Out.Header.Set("X-Forwarded-Port", "443")
			request.Out.Header.Del("X-Real-IP")
			for key := range request.Out.Header {
				if strings.HasPrefix(strings.ToLower(key), "x-forwarded-") &&
					key != "X-Forwarded-Proto" && key != "X-Forwarded-Host" && key != "X-Forwarded-Port" {
					request.Out.Header.Del(key)
				}
			}
			if request.Out.Header.Get("Origin") != "" {
				request.Out.Header.Set("Origin", cfg.MinecraftPanelOrigin.String())
			}
			if referer := request.Out.Header.Get("Referer"); referer != "" {
				if parsed, err := url.Parse(referer); err == nil && sameHTTPSOrigin(parsed, cfg.MinecraftPanelPublicOrigin) {
					parsed.Scheme = "https"
					parsed.Host = cfg.MinecraftPanelOrigin.Host
					request.Out.Header.Set("Referer", parsed.String())
				}
			}
		},
		ModifyResponse: func(response *http.Response) error {
			if location := response.Header.Get("Location"); location != "" {
				if parsed, err := url.Parse(location); err == nil && sameHTTPSOrigin(parsed, cfg.MinecraftPanelOrigin) {
					parsed.Scheme = "https"
					parsed.Host = cfg.MinecraftPanelPublicOrigin.Host
					response.Header.Set("Location", parsed.String())
				}
			}
			if len(response.Cookies()) > 0 {
				cookies := response.Cookies()
				response.Header.Del("Set-Cookie")
				for _, cookie := range cookies {
					cookie.Domain = ""
					response.Header.Add("Set-Cookie", cookie.String())
				}
			}
			contentType := strings.ToLower(response.Header.Get("Content-Type"))
			if response.Body != nil && response.Header.Get("Content-Encoding") == "" &&
				(strings.Contains(contentType, "text/") || strings.Contains(contentType, "json") ||
					strings.Contains(contentType, "javascript")) {
				const maxRewriteBytes = 4 << 20
				originalBody := response.Body
				body, err := io.ReadAll(io.LimitReader(originalBody, maxRewriteBytes+1))
				if err != nil {
					return err
				}
				if len(body) <= maxRewriteBytes {
					_ = originalBody.Close()
					body = bytes.ReplaceAll(body, []byte(cfg.MinecraftPanelOrigin.String()),
						[]byte(cfg.MinecraftPanelPublicOrigin.String()))
					response.Body = io.NopCloser(bytes.NewReader(body))
					response.ContentLength = int64(len(body))
					response.Header.Set("Content-Length", strconv.Itoa(len(body)))
				} else {
					response.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), originalBody))
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeError(w, http.StatusBadGateway, "Minecraft panel unavailable")
		},
	}
	return proxy
}

func sameHTTPSOrigin(left, right *url.URL) bool {
	if left == nil || right == nil || !strings.EqualFold(left.Scheme, "https") || !strings.EqualFold(right.Scheme, "https") ||
		!strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	leftPort, rightPort := left.Port(), right.Port()
	if leftPort == "" {
		leftPort = "443"
	}
	if rightPort == "" {
		rightPort = "443"
	}
	return leftPort == rightPort
}

func (g *Gateway) serveMinecraftPanel(w http.ResponseWriter, r *http.Request) {
	if g.minecraftPanel == nil {
		writeError(w, http.StatusServiceUnavailable, "Minecraft panel relay is not configured")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost &&
		r.Method != http.MethodPut && r.Method != http.MethodPatch && r.Method != http.MethodDelete &&
		r.Method != http.MethodOptions {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	origin := r.Header.Get("Origin")
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && origin == "" {
		writeError(w, http.StatusForbidden, "origin required")
		return
	}
	if origin != "" {
		parsed, err := parseHTTPSOrigin(origin)
		if err != nil || !sameHTTPSOrigin(parsed, g.cfg.MinecraftPanelPublicOrigin) {
			writeError(w, http.StatusForbidden, "origin rejected")
			return
		}
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxMinecraftPanelRequestBytes)
	}
	g.minecraftPanel.ServeHTTP(w, r)
}

func (g *Gateway) authorize(required string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		parts := strings.Fields(authorization)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			logAuthorizationEvent(requestIDFromContext(r.Context()), required, r.URL.Path, "deny", "bearer_missing_or_malformed", "")
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		subject, err := g.verifier.Subject(r.Context(), parts[1])
		if err != nil {
			logAuthorizationEvent(requestIDFromContext(r.Context()), required, r.URL.Path, "deny", "token_invalid", "")
			writeError(w, http.StatusUnauthorized, "invalid authentication")
			return
		}
		subjectID := auditSubjectID(subject)
		permissions, ok := g.cfg.SubjectPermissions[subject]
		if !ok || !permissions[required] {
			logAuthorizationEvent(requestIDFromContext(r.Context()), required, r.URL.Path, "deny", "permission_denied", subjectID)
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}
		limited := required == permissionModels || required == permissionChat || required == permissionSearch || required == permissionHistory || required == permissionOrchestrate || required == permissionNexusModelRead || required == permissionNexusModelControl || required == permissionNexusWorkspaceRead
		metadata := r.Method == http.MethodGet && (required == permissionModels || required == permissionNexusModelRead)
		if limited && !g.allowRequestBudget(subject, metadata) {
			logAuthorizationEvent(requestIDFromContext(r.Context()), required, r.URL.Path, "deny", "rate_limited", subjectID)
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "request limit reached")
			return
		}
		logAuthorizationEvent(requestIDFromContext(r.Context()), required, r.URL.Path, "allow", "", subjectID)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, subject)))
	})
}

type requestIDKey struct{}

func requestIDFromContext(ctx context.Context) string {
	requestID, _ := ctx.Value(requestIDKey{}).(string)
	return requestID
}

func auditSubjectID(subject string) string {
	digest := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(digest[:8])
}

func logAuthorizationEvent(requestID, permission, path, outcome, reason, subjectID string) {
	fields := "request_id=" + requestID + " route=" + routeName(path) + " permission=" + permission + " outcome=" + outcome
	if reason != "" {
		fields += " reason=" + reason
	}
	if subjectID != "" {
		fields += " subject_hash=" + subjectID
	}
	log.Printf("auth_event %s", fields)
}

func (g *Gateway) allowRequest(subject string) bool {
	return g.allowRequestBudget(subject, false)
}

// Read-only model/status polling cannot consume the inference/control budget.
// Both buckets remain bounded and keyed by the verified principal.
func (g *Gateway) allowRequestBudget(subject string, metadata bool) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	counters, limit := g.counters, g.cfg.RequestsPerMinute
	if metadata {
		if g.metadataCounters == nil {
			g.metadataCounters = make(map[string]requestCounter)
		}
		counters = g.metadataCounters
		if g.cfg.MetadataRequestsPerMinute > 0 {
			limit = g.cfg.MetadataRequestsPerMinute
		}
	}
	for known, state := range counters {
		if now.Sub(state.window) > time.Minute {
			delete(counters, known)
		}
	}
	state, exists := counters[subject]
	if !exists || now.Sub(state.window) >= time.Minute {
		counters[subject] = requestCounter{window: now, count: 1}
		return true
	}
	if state.count >= limit {
		return false
	}
	state.count++
	counters[subject] = state
	return true
}

// advertisedModels reads only the fixed configured inference upstream, never a
// caller-selected URL. Dynamic policy is refreshed per request and fails closed.
func (g *Gateway) advertisedModels(ctx context.Context) (modelEnvelope, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, g.upstreamURL("models").String(), nil)
	if err != nil {
		return modelEnvelope{}, err
	}
	request.Header.Set("Accept", "application/json")
	g.setUpstreamAuthorization(request)
	response, err := g.client.Do(request)
	if err != nil {
		return modelEnvelope{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return modelEnvelope{}, errors.New("model discovery failed")
	}
	var upstream modelEnvelope
	if err := decodeBoundedJSONResponse(response, 1<<20, &upstream); err != nil {
		return modelEnvelope{}, err
	}
	for _, model := range upstream.Data {
		if strings.TrimSpace(model.ID) == "" || len(model.ID) > 4096 || strings.ContainsAny(model.ID, "\x00\r\n") {
			return modelEnvelope{}, errors.New("invalid upstream model identifier")
		}
	}
	return upstream, nil
}

func (g *Gateway) requestModels(w http.ResponseWriter, r *http.Request) (map[string]bool, bool) {
	if !g.cfg.AllowUpstreamModels {
		return g.cfg.AllowedModels, true
	}
	upstream, err := g.advertisedModels(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI model discovery unavailable")
		return nil, false
	}
	allowed := make(map[string]bool, len(upstream.Data))
	for _, model := range upstream.Data {
		allowed[model.ID] = true
	}
	return allowed, true
}

func (g *Gateway) models(w http.ResponseWriter, r *http.Request) {
	if g.aiLifecycle.TryLock() {
		g.reconcilePendingModelSwitch()
		g.aiLifecycle.Unlock()
	}
	g.modelState.Lock()
	pending := g.modelPending != "" && g.modelStateErr == nil
	g.modelState.Unlock()
	if pending {
		// No chat model is available until the accepted transition is
		// confirmed. Refresh during startup is not an upstream failure.
		writeJSON(w, http.StatusOK, modelEnvelope{Data: []modelEntry{}})
		return
	}
	upstream, err := g.advertisedModels(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI model service unavailable")
		return
	}
	filtered := modelEnvelope{Data: make([]modelEntry, 0, len(upstream.Data))}
	for _, model := range upstream.Data {
		if g.cfg.AllowUpstreamModels || g.cfg.AllowedModels[model.ID] {
			filtered.Data = append(filtered.Data, modelEntry{ID: model.ID, Object: "model"})
		}
	}
	writeJSON(w, http.StatusOK, filtered)
}

// contextWindow exposes only the active server context size; raw /props data
// can include unrelated runtime details and is deliberately not relayed.
func (g *Gateway) contextWindow(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	upstreamURL := *g.cfg.Upstream
	upstreamURL.Path = "/props"
	upstreamURL.RawPath = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL.String(), nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI context service unavailable")
		return
	}
	request.Header.Set("Accept", "application/json")
	g.setUpstreamAuthorization(request)
	response, err := g.client.Do(request)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI context service unavailable")
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		writeError(w, http.StatusBadGateway, "AI context service request failed")
		return
	}
	var props struct {
		DefaultGenerationSettings struct {
			Context int `json:"n_ctx"`
		} `json:"default_generation_settings"`
	}
	if err := decodeBoundedJSONResponse(response, 128<<10, &props); err != nil ||
		props.DefaultGenerationSettings.Context < 1024 || props.DefaultGenerationSettings.Context > 1_000_000 {
		writeError(w, http.StatusBadGateway, "AI context service returned an invalid context window")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"context_window_tokens": props.DefaultGenerationSettings.Context})
}

func (g *Gateway) completions(w http.ResponseWriter, r *http.Request) {
	if !g.beginInference(w) {
		return
	}
	defer g.aiLifecycle.Unlock()
	if err := g.acquire(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "AI capacity is currently full")
		return
	}
	defer func() { <-g.semaphore }()

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input completionRequest
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid chat request")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid chat request")
		return
	}
	allowed, ok := g.requestModels(w, r)
	if !ok {
		return
	}
	if err := validateCompletion(input, allowed); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	body, err := json.Marshal(input)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid chat request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), g.cfg.RequestTimeout)
	defer cancel()
	upstreamURL := g.upstreamURL("chat/completions")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL.String(), strings.NewReader(string(body)))
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI inference service unavailable")
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "text/event-stream, application/json")
	g.setUpstreamAuthorization(request)
	response, err := g.client.Do(request)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI inference service unavailable")
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		writeError(w, http.StatusBadGateway, "AI inference request failed")
		return
	}
	contentType := response.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(response.StatusCode)
	flusher, _ := w.(http.Flusher)
	buffer := make([]byte, 16<<10)
	var forwarded int64
	for {
		count, readErr := response.Body.Read(buffer)
		if count > 0 {
			remaining := int64(maxStreamResponseBytes) - forwarded
			writeCount := min(int64(count), remaining)
			if writeCount > 0 {
				if _, err := w.Write(buffer[:writeCount]); err != nil {
					return
				}
				forwarded += writeCount
				if flusher != nil {
					flusher.Flush()
				}
			}
			if forwarded >= int64(maxStreamResponseBytes) {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

// inputTokens asks the pinned llama.cpp backend to apply the active model's
// chat template and tokenizer. This is an authenticated, read-only preflight;
// it shares the lifecycle gate so a model cannot change during tokenization.
func (g *Gateway) inputTokens(w http.ResponseWriter, r *http.Request) {
	if !g.beginInference(w) {
		return
	}
	defer g.aiLifecycle.Unlock()
	if err := g.acquire(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "AI capacity is currently full")
		return
	}
	defer func() { <-g.semaphore }()
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input completionRequest
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid token-count request")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid token-count request")
		return
	}
	allowed, ok := g.requestModels(w, r)
	if !ok {
		return
	}
	if err := validateCompletion(input, allowed); err != nil {
		writeError(w, http.StatusBadRequest, "invalid token-count request")
		return
	}
	body, err := json.Marshal(input)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token-count request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	upstreamURL := g.upstreamURL("chat/completions/input_tokens")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL.String(), bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI token-count service unavailable")
		return
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	g.setUpstreamAuthorization(request)
	response, err := g.client.Do(request)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI token-count service unavailable")
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		writeError(w, http.StatusBadGateway, "AI token-count request failed")
		return
	}
	var result struct {
		InputTokens int `json:"input_tokens"`
	}
	if err := decodeBoundedJSONResponse(response, 16<<10, &result); err != nil ||
		result.InputTokens < 0 || result.InputTokens > 1_000_000 {
		writeError(w, http.StatusBadGateway, "AI token-count service returned an invalid response")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func supportedReadOnlyTool(name string) bool {
	switch name {
	case "nexus_get_saved_host_snapshot", "nexus_get_saved_service_inventory":
		return true
	default:
		return false
	}
}

func validateCompletion(input completionRequest, allowed map[string]bool) error {
	if !allowed[input.Model] {
		return errors.New("model is not allowed")
	}
	if len(input.Messages) == 0 || len(input.Messages) > maxMessages {
		return errors.New("message count is outside the allowed range")
	}
	allowedToolDevices := map[string]map[string]bool{}
	if len(input.Tools) > 2 {
		return errors.New("too many read-only tools")
	}
	if input.ParallelToolCalls != nil && *input.ParallelToolCalls {
		return errors.New("parallel tool calls are not supported")
	}
	for _, tool := range input.Tools {
		if tool.Type != "function" || !supportedReadOnlyTool(tool.Function.Name) ||
			len(tool.Function.Description) > 512 || input.ToolChoice != "auto" {
			return errors.New("unsupported read-only tool definition")
		}
		if _, duplicate := allowedToolDevices[tool.Function.Name]; duplicate {
			return errors.New("duplicate read-only tool definition")
		}
		var schema struct {
			Type                 string   `json:"type"`
			Required             []string `json:"required"`
			AdditionalProperties *bool    `json:"additionalProperties"`
			Properties           map[string]struct {
				Type string   `json:"type"`
				Enum []string `json:"enum"`
			} `json:"properties"`
		}
		decoder := json.NewDecoder(bytes.NewReader(tool.Function.Parameters))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&schema); err != nil || schema.Type != "object" ||
			len(schema.Required) != 1 || schema.Required[0] != "device_id" ||
			schema.AdditionalProperties == nil || *schema.AdditionalProperties || len(schema.Properties) != 1 {
			return errors.New("invalid read-only tool schema")
		}
		property, ok := schema.Properties["device_id"]
		if !ok || property.Type != "string" || len(property.Enum) == 0 || len(property.Enum) > 20 {
			return errors.New("invalid read-only tool devices")
		}
		deviceIDs := map[string]bool{}
		for _, id := range property.Enum {
			if id == "" || len(id) > 64 || deviceIDs[id] {
				return errors.New("invalid read-only tool device ID")
			}
			deviceIDs[id] = true
		}
		allowedToolDevices[tool.Function.Name] = deviceIDs
	}
	if len(input.Tools) == 0 && input.ToolChoice != "" {
		return errors.New("tool choice requires a supported tool")
	}
	pendingToolID := ""
	seenToolIDs := map[string]bool{}
	for _, message := range input.Messages {
		if message.Role != "system" && message.Role != "user" && message.Role != "assistant" && message.Role != "tool" {
			return errors.New("unsupported message role")
		}
		if pendingToolID != "" {
			if message.Role != "tool" || message.ToolCallID != pendingToolID || len(message.ToolCalls) != 0 {
				return errors.New("tool result does not match the pending tool request")
			}
			pendingToolID = ""
		} else if message.Role == "tool" || message.ToolCallID != "" {
			return errors.New("tool result has no matching request")
		}
		if len(message.ToolCalls) > 1 || (len(message.ToolCalls) > 0 && message.Role != "assistant") {
			return errors.New("unsupported tool call count or role")
		}
		if len(message.ToolCalls) == 1 {
			call := message.ToolCalls[0]
			if call.Type != "function" || !supportedReadOnlyTool(call.Function.Name) ||
				call.ID == "" || len(call.ID) > 128 || seenToolIDs[call.ID] || len(message.ToolCalls) != 1 {
				return errors.New("unsupported tool call")
			}
			var args struct {
				DeviceID string `json:"device_id"`
			}
			var object map[string]json.RawMessage
			if json.Unmarshal(call.Function.Arguments, &args) != nil || json.Unmarshal(call.Function.Arguments, &object) != nil ||
				len(object) != 1 || args.DeviceID == "" || len(args.DeviceID) > 64 ||
				(len(input.Tools) > 0 && !allowedToolDevices[call.Function.Name][args.DeviceID]) {
				return errors.New("invalid read-only tool arguments")
			}
			seenToolIDs[call.ID] = true
			pendingToolID = call.ID
		}
		if err := validateMessageContent(message.Role, message.Content); err != nil {
			return err
		}
	}
	if pendingToolID != "" {
		return errors.New("tool request has no result")
	}
	if input.MaxTokens != nil && (*input.MaxTokens < 1 || *input.MaxTokens > maxOutputTokens) {
		return fmt.Errorf("max_tokens must be between 1 and %d", maxOutputTokens)
	}
	if input.Temperature != nil && (*input.Temperature < 0 || *input.Temperature > 2) {
		return errors.New("temperature must be between 0 and 2")
	}
	if input.TopP != nil && (*input.TopP <= 0 || *input.TopP > 1) {
		return errors.New("top_p must be greater than 0 and no greater than 1")
	}
	return nil
}

func validateMessageContent(role string, content json.RawMessage) error {
	if len(content) == 0 || bytes.Equal(content, []byte("null")) {
		return errors.New("message content is invalid")
	}
	var text string
	if err := json.Unmarshal(content, &text); err == nil {
		if len(text) > maxMessageBytes {
			return errors.New("message is too large")
		}
		return nil
	}
	if role != "user" {
		return errors.New("images are only allowed on user messages")
	}
	var parts []completionContentPart
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parts); err != nil || len(parts) < 2 || len(parts) > maxImagesPerMessage+1 ||
		parts[0].Type != "text" || len(parts[0].Text) > maxMessageBytes {
		return errors.New("message content is invalid")
	}
	if parts[0].ImageURL != nil {
		return errors.New("message content is invalid")
	}
	const prefix = "data:image/jpeg;base64,"
	totalImageBytes := 0
	for _, part := range parts[1:] {
		if part.Type != "image_url" || part.ImageURL == nil || part.Text != "" ||
			!strings.HasPrefix(part.ImageURL.URL, prefix) || (part.ImageURL.Detail != "" && part.ImageURL.Detail != "auto" &&
			part.ImageURL.Detail != "low" && part.ImageURL.Detail != "high") {
			return errors.New("image attachment must be a bounded JPEG data URL")
		}
		encoded := strings.TrimPrefix(part.ImageURL.URL, prefix)
		if len(encoded) > 700*1_024 {
			return errors.New("image attachment is too large")
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(decoded) < 4 || len(decoded) > maxImageBytes ||
			!bytes.HasPrefix(decoded, []byte{0xFF, 0xD8, 0xFF}) || !bytes.HasSuffix(decoded, []byte{0xFF, 0xD9}) {
			return errors.New("image attachment is not a valid bounded JPEG")
		}
		totalImageBytes += len(decoded)
		if totalImageBytes > maxCombinedImageBytes {
			return errors.New("combined image attachments are too large")
		}
	}
	return nil
}

func (g *Gateway) acquire(ctx context.Context) error {
	select {
	case g.semaphore <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *Gateway) upstreamURL(path string) *url.URL {
	copy := *g.cfg.Upstream
	copy.Path = strings.TrimRight(copy.Path, "/") + "/" + path
	copy.RawPath = ""
	return &copy
}

func (g *Gateway) setUpstreamAuthorization(request *http.Request) {
	if g.cfg.UpstreamBearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+g.cfg.UpstreamBearerToken)
	}
}

func (g *Gateway) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idBytes := make([]byte, 12)
		if _, err := rand.Read(idBytes); err != nil {
			writeError(w, http.StatusInternalServerError, "request failed")
			return
		}
		id := hex.EncodeToString(idBytes)
		wrapped := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		wrapped.Header().Set("X-Request-ID", id)
		start := time.Now()
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
		next.ServeHTTP(wrapped, r)
		log.Printf("request_id=%s method=%s route=%s status=%d duration_ms=%d", id, r.Method, routeName(r.URL.Path), wrapped.status, time.Since(start).Milliseconds())
	})
}

func routeName(path string) string {
	switch path {
	case "/healthz", "/v1/models", "/v1/context", "/v1/chat/completions", "/v1/search", "/v1/research", "/v1/conversations", "/v1/nexus/workspaces", "/v1/nexus/agent-runs", "/v1/nexus/agent-runs/active", "/v1/nexus/models", "/v1/nexus/status", "/v1/nexus/models/status", "/v1/nexus/models/unload":
		return path
	default:
		if strings.HasPrefix(path, "/v1/nexus/agent-runs/") {
			return "/v1/nexus/agent-runs/{id}"
		}
		if strings.HasPrefix(path, "/v1/nexus/models/") {
			return "/v1/nexus/models/{id}/load"
		}
		if strings.HasPrefix(path, minecraftPanelGatewayPrefix) {
			return "/v1/minecraft/panel/{path}"
		}
		if strings.HasPrefix(path, "/v1/ssh/") {
			return "/v1/ssh/{target}"
		}
		if strings.HasPrefix(path, "/v1/conversations/") {
			return "/v1/conversations/{id}"
		}
		return "unmatched"
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("underlying response writer does not support WebSocket upgrades")
	}
	connection, buffered, err := hijacker.Hijack()
	if err == nil {
		w.status = http.StatusSwitchingProtocols
	}
	return connection, buffered, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"message": message}})
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("configuration invalid: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var verifier *OIDCAccessTokenVerifier
	if cfg.OIDCJWKSURL != "" {
		verifier, err = NewOIDCAccessTokenVerifierWithJWKS(ctx, cfg.IssuerURL, cfg.OIDCAudience,
			cfg.OIDCJWKSURL, cfg.OIDCPrincipalClaim)
	} else {
		verifier, err = NewOIDCAccessTokenVerifier(ctx, cfg.IssuerURL, cfg.OIDCAudience)
	}
	if err != nil {
		log.Fatalf("OIDC access-token verification setup failed: %v", err)
	}
	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           NewGateway(cfg, verifier).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	log.Printf("Nexus gateway listening on loopback; authenticated model and streaming routes are enabled for configured subjects")
	log.Printf("AI request limits per minute: operations=%d metadata=%d", cfg.RequestsPerMinute, cfg.MetadataRequestsPerMinute)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("gateway stopped: %v", err)
	}
}
