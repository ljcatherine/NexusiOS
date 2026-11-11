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

func TestBraveSearcherParsesAndFiltersSearchResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/res/v1/web/search" || r.URL.Query().Get("q") != "Nexus research" ||
			r.URL.Query().Get("count") != "3" || r.Header.Get("X-Subscription-Token") != "test-key" {
			t.Errorf("unexpected Brave request: path=%q query=%v", r.URL.Path, r.URL.Query())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"web":{"results":[
			{"title":"Public result","url":"https://example.org/news","description":"summary","page_age":"3 days ago"},
			{"title":"Private address","url":"http://192.168.1.9/admin","description":"skip"},
			{"title":"Credential URL","url":"https://user:secret@example.org/","description":"skip"},
			{"title":"Second result","url":"https://example.net/page","description":"second"}
		]}}`))
	}))
	defer server.Close()
	endpoint, _ := url.Parse(server.URL + "/res/v1/web/search")
	searcher := &BraveSearcher{client: server.Client(), apiKey: "test-key", endpoint: endpoint}
	sources, err := searcher.Search(context.Background(), "Nexus research", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || sources[0].Title != "Public result" || sources[0].Age != "3 days ago" ||
		sources[1].Title != "Second result" {
		t.Fatalf("unexpected filtered sources: %+v", sources)
	}
}

func TestSearXNGSearcherUsesJSONSearchAndBoundsSources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/searx/search" || r.URL.Query().Get("format") != "json" ||
			r.URL.Query().Get("categories") != "general" || r.URL.Query().Get("q") != "recent releases" {
			t.Errorf("unexpected SearXNG request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"results":[
			{"title":"A","url":"https://a.example/","content":"one","publishedDate":"today"},
			{"title":"B","url":"https://b.example/","content":"two"},
			{"title":"C","url":"https://c.example/","content":"three"}
		]}`))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL + "/searx")
	searcher := &SearXNGSearcher{client: server.Client(), base: base}
	sources, err := searcher.Search(context.Background(), "recent releases", 2)
	if err != nil || len(sources) != 2 || sources[0].PublishedAt != "today" {
		t.Fatalf("sources=%+v err=%v", sources, err)
	}
}

func TestSearchProvidersRejectOversizedJSONResponses(t *testing.T) {
	largeResponse := `{"web":{"results":[]}}` + strings.Repeat(" ", maxSearchBodyBytes)
	for _, provider := range []string{"brave", "searxng"} {
		t.Run(provider, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(largeResponse))
			}))
			defer server.Close()
			endpoint, _ := url.Parse(server.URL)
			client := server.Client()
			var searcher Searcher
			if provider == "brave" {
				searcher = &BraveSearcher{client: client, apiKey: "test", endpoint: endpoint}
			} else {
				searcher = &SearXNGSearcher{client: client, base: endpoint}
			}
			if _, err := searcher.Search(context.Background(), "bounded query", 1); err == nil {
				t.Fatal("oversized provider response was accepted")
			}
		})
	}
}

func TestSearchRouteRequiresPermissionAndValidBoundedInput(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	gateway := testGateway(upstream,
		map[string]map[string]bool{"owner-subject": {permissionSearch: true}})
	gateway.cfg.RequestsPerMinute = 10
	gateway.searcher = searcherFunc(func(_ context.Context, query string, count int) ([]SearchSource, error) {
		calls++
		return []SearchSource{{Title: "Fixture source", URL: "https://example.org/", Snippet: query}}, nil
	})
	gateway.pageFetcher = pageFetcherFunc(func(_ context.Context, address string) (string, error) {
		if address != "https://example.org/" {
			t.Errorf("unexpected page fetch URL: %s", address)
		}
		return "bounded extracted article", nil
	})
	for _, body := range []string{
		`{"query":""}`,
		`{"query":"ok","count":11}`,
		`{"query":"ok","extra":true}`,
		`{"query":"ok"} {"query":"trailing"}`,
		`{"query":"password=do-not-search"}`,
		`{"query":"-----BEGIN OPENSSH PRIVATE KEY-----"}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/search", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer valid-token")
		response := httptest.NewRecorder()
		gateway.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Errorf("body %q returned %d, wanted 400", body, response.Code)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid search requests reached provider %d times", calls)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/search", strings.NewReader(`{"query":"recent release"}`))
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(response, request)
	var result searchResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || calls != 1 || len(result.Sources) != 1 || result.Sources[0].URL != "https://example.org/" ||
		result.Sources[0].Content != "bounded extracted article" {
		t.Fatalf("status=%d calls=%d response=%+v", response.Code, calls, result)
	}
}

func TestSearchRouteDeniesUnauthorisedAndUnconfiguredSearch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer upstream.Close()
	gateway := testGateway(upstream,
		map[string]map[string]bool{"owner-subject": {permissionChat: true}})
	request := httptest.NewRequest(http.MethodPost, "/v1/search", strings.NewReader(`{"query":"test"}`))
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("search permission escalation: got %d", response.Code)
	}

	gateway.cfg.SubjectPermissions["owner-subject"][permissionSearch] = true
	response = httptest.NewRecorder()
	gateway.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "provider") {
		t.Fatalf("unconfigured search should fail closed: %d %q", response.Code, response.Body.String())
	}
}

func TestSearchConfigurationURLAndResultAddressValidation(t *testing.T) {
	for _, raw := range []string{"https://search.example.test", "http://192.168.1.20:8080"} {
		parsed, _ := url.Parse(raw)
		if !validSearchURL(parsed) {
			t.Errorf("expected configured search URL allowed: %s", raw)
		}
	}
	for _, raw := range []string{"http://search.example.test", "http://8.8.8.8", "https://u:p@search.example.test", "https://search.example.test/?token=x"} {
		parsed, _ := url.Parse(raw)
		if validSearchURL(parsed) {
			t.Errorf("expected configured search URL rejected: %s", raw)
		}
	}
	for _, raw := range []string{"https://public.example.org/result", "http://8.8.8.8/", "https://192.1.1.1/"} {
		parsed, _ := url.Parse(raw)
		if !validPublicResultURL(parsed) {
			t.Errorf("expected public source address allowed: %s", raw)
		}
	}
	for _, raw := range []string{"http://127.0.0.1/admin", "http://192.168.1.2/", "https://192.0.2.10/", "https://198.18.0.1/", "https://203.0.113.9/", "https://[2001:db8::1]/", "https://[2001:10::1]/", "https://user:pass@example.org/", "file:///etc/passwd"} {
		parsed, _ := url.Parse(raw)
		if validPublicResultURL(parsed) {
			t.Errorf("expected unsafe source address rejected: %s", raw)
		}
	}
}

func TestSearchProviderConfigurationIsOptionalAndBounded(t *testing.T) {
	setBaseConfig(t)
	cfg, err := loadConfig()
	if err != nil || cfg.SearchProvider != "" || cfg.SearchMaxResults != 5 || cfg.SearchTimeout != 15*time.Second || cfg.SearchFetchPages {
		t.Fatalf("unexpected disabled-search defaults: config=%+v err=%v", cfg, err)
	}

	t.Setenv("NEXUS_SEARCH_PROVIDER", "brave")
	if _, err := loadConfig(); err == nil {
		t.Fatal("Brave search started without an API key")
	}
	t.Setenv("NEXUS_BRAVE_API_KEY", "local-test-key")
	t.Setenv("NEXUS_SEARCH_MAX_RESULTS", "4")
	t.Setenv("NEXUS_SEARCH_TIMEOUT", "8s")
	cfg, err = loadConfig()
	if err != nil || cfg.SearchProvider != "brave" || cfg.SearchMaxResults != 4 || cfg.SearchTimeout != 8*time.Second || !cfg.SearchFetchPages {
		t.Fatalf("valid Brave settings rejected: config=%+v err=%v", cfg, err)
	}
	t.Setenv("NEXUS_SEARCH_FETCH_PAGES", "false")
	cfg, err = loadConfig()
	if err != nil || cfg.SearchFetchPages {
		t.Fatalf("explicitly disabled page fetching was ignored: config=%+v err=%v", cfg, err)
	}
	t.Setenv("NEXUS_SEARCH_FETCH_PAGES", "maybe")
	if _, err := loadConfig(); err == nil {
		t.Fatal("invalid page-fetch setting was accepted")
	}
	t.Setenv("NEXUS_SEARCH_FETCH_PAGES", "")

	t.Setenv("NEXUS_SEARCH_PROVIDER", "searxng")
	t.Setenv("NEXUS_SEARXNG_URL", "http://search.example.test")
	if _, err := loadConfig(); err == nil {
		t.Fatal("SearXNG cleartext public hostname was accepted")
	}
	t.Setenv("NEXUS_SEARXNG_URL", "http://192.168.1.20:8080/searx")
	if _, err := loadConfig(); err != nil {
		t.Fatalf("private SearXNG endpoint was rejected: %v", err)
	}
	t.Setenv("NEXUS_SEARCH_MAX_RESULTS", "11")
	if _, err := loadConfig(); err == nil {
		t.Fatal("search result maximum above hard limit was accepted")
	}
}

func setBaseConfig(t *testing.T) {
	t.Helper()
	t.Setenv("NEXUS_GATEWAY_LISTEN", "127.0.0.1:8787")
	t.Setenv("NEXUS_OIDC_ISSUER", "https://identity.example.test/")
	t.Setenv("NEXUS_OIDC_AUDIENCE", "https://gateway.example.test")
	t.Setenv("NEXUS_SUBJECT_PERMISSIONS_JSON", `{"owner-subject":["ai.models","ai.chat","ai.search"]}`)
	t.Setenv("NEXUS_AI_UPSTREAM_URL", "http://192.168.1.30:8081/v1")
	t.Setenv("NEXUS_AI_UPSTREAM_TOKEN", "")
	t.Setenv("NEXUS_AI_ALLOWED_MODELS", "owner-model")
	t.Setenv("NEXUS_AI_REQUEST_TIMEOUT", "15m")
	t.Setenv("NEXUS_AI_REQUESTS_PER_MINUTE", "30")
	t.Setenv("NEXUS_AI_MAX_CONCURRENT", "2")
	t.Setenv("NEXUS_SEARCH_PROVIDER", "")
	t.Setenv("NEXUS_SEARCH_FETCH_PAGES", "")
	t.Setenv("NEXUS_BRAVE_API_KEY", "")
	t.Setenv("NEXUS_SEARXNG_URL", "")
	t.Setenv("NEXUS_SEARCH_TIMEOUT", "")
	t.Setenv("NEXUS_SEARCH_MAX_RESULTS", "")
}

type searcherFunc func(context.Context, string, int) ([]SearchSource, error)

func (f searcherFunc) Search(ctx context.Context, query string, count int) ([]SearchSource, error) {
	return f(ctx, query, count)
}
