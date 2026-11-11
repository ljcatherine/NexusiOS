package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestResearchPlansAndSearchesThroughOneAuthorizedRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected planner endpoint: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer server-only-upstream-secret" {
			t.Errorf("client bearer was forwarded or upstream bearer missing")
		}
		var request completionRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("invalid planner payload: %v", err)
		}
		if !strings.Contains(string(request.Messages[1].Content), "latest release") {
			t.Errorf("planner did not receive bounded conversation: %s", request.Messages[1].Content)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"search\":true,\"queries\":[\"latest release\",\"release notes\"]}"}}]}`))
	}))
	defer upstream.Close()
	gateway := testGateway(upstream, map[string]map[string]bool{
		"owner-subject": {permissionChat: true, permissionSearch: true},
	})
	gateway.cfg.SearchProvider = "fixture"
	calls := 0
	gateway.searcher = searcherFunc(func(_ context.Context, query string, _ int) ([]SearchSource, error) {
		calls++
		return []SearchSource{{Title: "Source", URL: "https://example.org/article", Snippet: query}}, nil
	})
	body := `{"model":"model-installed-by-owner","mode":"automatic","max_queries":2,"messages":[{"role":"user","content":"latest release"}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/research", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(response, request)
	var result researchResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || !result.PlannerAvailable || result.PlannerFallback ||
		!result.Decision.ShouldSearch || len(result.Decision.Queries) != 2 || calls != 2 ||
		result.Search == nil || len(result.Search.Sources) != 1 || result.FailedQueries != 0 {
		t.Fatalf("status=%d calls=%d result=%+v body=%s", response.Code, calls, result, response.Body.String())
	}
}

func TestResearchAutomaticNoSearchDoesNotRequireConfiguredProvider(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"search\":false,\"queries\":[]}"}}]}`))
	}))
	defer upstream.Close()
	gateway := testGateway(upstream, map[string]map[string]bool{
		"owner-subject": {permissionChat: true, permissionSearch: true},
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/research", strings.NewReader(
		`{"model":"model-installed-by-owner","mode":"automatic","max_queries":1,"messages":[{"role":"user","content":"What is 2 + 2?"}]}`))
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(response, request)
	var result researchResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || !result.PlannerAvailable || result.Decision.ShouldSearch || result.Search != nil {
		t.Fatalf("automatic no-search request failed without provider: status=%d result=%+v", response.Code, result)
	}
}

func TestResearchRequiresBothChatAndSearchGrantsAndValidContext(t *testing.T) {
	upstreamCalls, searchCalls := 0, 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"search\":false,\"queries\":[]}"}}]}`))
	}))
	defer upstream.Close()
	gateway := testGateway(upstream, map[string]map[string]bool{
		"owner-subject": {permissionChat: true},
	})
	gateway.searcher = searcherFunc(func(context.Context, string, int) ([]SearchSource, error) {
		searchCalls++
		return nil, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/research", strings.NewReader(
		`{"model":"model-installed-by-owner","mode":"automatic","max_queries":1,"messages":[{"role":"user","content":"question"}]}`))
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || upstreamCalls != 0 || searchCalls != 0 {
		t.Fatalf("missing search grant reached work: status=%d upstream=%d search=%d", response.Code, upstreamCalls, searchCalls)
	}
	gateway.cfg.SubjectPermissions["owner-subject"][permissionSearch] = true
	for _, body := range []string{
		`{"model":"not-allowed","mode":"automatic","max_queries":1,"messages":[{"role":"user","content":"question"}]}`,
		`{"model":"model-installed-by-owner","mode":"automatic","max_queries":1,"messages":[{"role":"system","content":"question"}]}`,
		`{"model":"model-installed-by-owner","mode":"automatic","max_queries":4,"messages":[{"role":"user","content":"question"}]}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/research", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer valid-token")
		response := httptest.NewRecorder()
		gateway.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("invalid request accepted with status %d: %s", response.Code, body)
		}
	}
}

func TestResearchAlwaysModeFallsBackToSafeBoundedQuestion(t *testing.T) {
	// Use an unreachable private upstream to exercise planner failure without
	// relying on provider behavior or external network access.
	parsed, _ := url.Parse("http://127.0.0.1:1/v1")
	gateway := NewGateway(Config{
		SubjectPermissions: map[string]map[string]bool{"owner-subject": {permissionChat: true, permissionSearch: true}},
		Upstream:           parsed, AllowedModels: map[string]bool{"model-installed-by-owner": true},
		RequestTimeout: 100 * time.Millisecond, RequestsPerMinute: 10, MaximumConcurrentAI: 1,
	}, fakeVerifier{subjects: map[string]string{"valid-token": "owner-subject"}})
	gateway.searcher = searcherFunc(func(_ context.Context, query string, _ int) ([]SearchSource, error) {
		if len(query) > 256 {
			t.Errorf("fallback query exceeds limit: %d", len(query))
		}
		return []SearchSource{{Title: "Source", URL: "https://example.org/", Snippet: query}}, nil
	})
	body, _ := json.Marshal(researchRequest{Model: "model-installed-by-owner", Mode: "always", MaxQueries: 1,
		Messages: []researchMessage{{Role: "user", Content: strings.Repeat("é", 300)}}})
	request := httptest.NewRequest(http.MethodPost, "/v1/research", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(response, request)
	var result researchResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || result.PlannerAvailable || !result.PlannerFallback ||
		!result.Decision.ShouldSearch || len(result.Decision.Queries) != 1 || len(result.Decision.Queries[0]) > 256 {
		t.Fatalf("fallback result invalid: status=%d result=%+v body=%s", response.Code, result, response.Body.String())
	}
}
