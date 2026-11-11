package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDynamicModelPolicyTracksUpstreamAndFailsClosed(t *testing.T) {
	current := "new-model"
	discoveryStatus := http.StatusOK
	generationCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer server-only-upstream-secret" {
			t.Error("upstream service credential missing")
		}
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(discoveryStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": current}}})
			return
		}
		generationCalls++
		if r.URL.Path == "/v1/chat/completions/input_tokens" {
			_, _ = w.Write([]byte(`{"input_tokens":12}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer upstream.Close()
	g := testGateway(upstream, map[string]map[string]bool{"owner-subject": {permissionModels: true, permissionChat: true}})
	g.cfg.AllowUpstreamModels = true
	g.cfg.RequestsPerMinute = 100
	request := func(method, path, model, token string) *httptest.ResponseRecorder {
		body := ""
		if model != "" {
			b, _ := json.Marshal(map[string]any{"model": model, "messages": []map[string]string{{"role": "user", "content": "hello"}}, "stream": false})
			body = string(b)
		}
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		g.Handler().ServeHTTP(w, r)
		return w
	}
	for _, model := range []string{"new-model", "replacement-model"} {
		current = model
		w := request("GET", "/v1/models", "", "valid-token")
		if w.Code != 200 || !strings.Contains(w.Body.String(), model) {
			t.Fatalf("discovery: %d %s", w.Code, w.Body.String())
		}
		for _, path := range []string{"/v1/chat/completions", "/v1/chat/completions/input_tokens"} {
			if w := request("POST", path, model, "valid-token"); w.Code != 200 {
				t.Fatalf("advertised %s: %d %s", path, w.Code, w.Body.String())
			}
			before := generationCalls
			if w := request("POST", path, "unadvertised-model", "valid-token"); w.Code != 400 || generationCalls != before {
				t.Fatalf("unadvertised model forwarded: %d", w.Code)
			}
		}
	}
	before := generationCalls
	discoveryStatus = 503
	if w := request("POST", "/v1/chat/completions", current, "valid-token"); w.Code != 502 || generationCalls != before {
		t.Fatalf("failed discovery allowed generation: %d", w.Code)
	}
	if w := request("GET", "/v1/models", "", ""); w.Code != 401 {
		t.Fatalf("anonymous access: %d", w.Code)
	}
	if w := request("GET", "/v1/models", "", "invalid-token"); w.Code != 401 {
		t.Fatalf("invalid token: %d", w.Code)
	}
}

func TestDynamicModelConfigurationIsExplicitOptIn(t *testing.T) {
	setBaseConfig(t)
	for _, tc := range []struct {
		flag, models   string
		valid, dynamic bool
	}{
		{"", "owner-model", true, false}, {"false", "", false, false}, {"true", "", true, true}, {"typo", "owner-model", false, false},
	} {
		t.Setenv("NEXUS_AI_ALLOW_UPSTREAM_MODELS", tc.flag)
		t.Setenv("NEXUS_AI_ALLOWED_MODELS", tc.models)
		cfg, err := loadConfig()
		if (err == nil) != tc.valid || err == nil && cfg.AllowUpstreamModels != tc.dynamic {
			t.Fatalf("flag=%q valid=%v dynamic=%v err=%v", tc.flag, tc.valid, cfg.AllowUpstreamModels, err)
		}
	}
}

func TestResearchUsesDynamicPolicyWithoutGrantingSearch(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path == "/v1/models" {
			_, _ = w.Write([]byte(`{"data":[{"id":"new-model"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"search\":false,\"queries\":[]}"}}]}`))
	}))
	defer upstream.Close()
	g := testGateway(upstream, map[string]map[string]bool{"owner-subject": {permissionChat: true, permissionSearch: true}})
	g.cfg.AllowUpstreamModels = true
	body := `{"model":"new-model","mode":"automatic","max_queries":1,"messages":[{"role":"user","content":"hello"}]}`
	run := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/v1/research", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()
		g.Handler().ServeHTTP(w, r)
		return w
	}
	if w := run(); w.Code != 200 || calls != 2 {
		t.Fatalf("research dynamic discovery: %d calls=%d", w.Code, calls)
	}
	g.cfg.SubjectPermissions["owner-subject"][permissionSearch] = false
	if w := run(); w.Code != 403 || calls != 2 {
		t.Fatalf("search permission bypassed: %d calls=%d", w.Code, calls)
	}
}
