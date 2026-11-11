package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var sensitiveSearchQuery = regexp.MustCompile(`(?i)(?:api[_-]?key|password|passwd|secret|token|authorization|bearer|private[_ -]?key)\s*[:=]\s*\S+|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)

const (
	maxSearchQueryBytes = 512
	maxSearchResults    = 10
	maxSearchBodyBytes  = 1 << 20
)

type SearchSource struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	Snippet     string `json:"snippet"`
	Content     string `json:"content,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`
	Age         string `json:"age,omitempty"`
}

type Searcher interface {
	Search(context.Context, string, int) ([]SearchSource, error)
}

type searchRequest struct {
	Query string `json:"query"`
	Count int    `json:"count,omitempty"`
}

type searchResponse struct {
	Provider    string         `json:"provider"`
	RetrievedAt time.Time      `json:"retrieved_at"`
	Sources     []SearchSource `json:"sources"`
}

type BraveSearcher struct {
	client   *http.Client
	apiKey   string
	endpoint *url.URL
}

type SearXNGSearcher struct {
	client *http.Client
	base   *url.URL
}

type braveEnvelope struct {
	Web struct {
		Results []struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Description string `json:"description"`
			PageAge     string `json:"page_age"`
		} `json:"results"`
	} `json:"web"`
}

type searxEnvelope struct {
	Results []struct {
		Title         string `json:"title"`
		URL           string `json:"url"`
		Content       string `json:"content"`
		PublishedDate string `json:"publishedDate"`
	} `json:"results"`
}

func newSearcher(cfg Config) Searcher {
	timeout := cfg.SearchTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	switch cfg.SearchProvider {
	case "brave":
		return &BraveSearcher{client: client, apiKey: cfg.SearchAPIKey}
	case "searxng":
		return &SearXNGSearcher{client: client, base: cfg.SearchURL}
	default:
		return nil
	}
}

func (s *BraveSearcher) Search(ctx context.Context, query string, count int) ([]SearchSource, error) {
	u := url.URL{Scheme: "https", Host: "api.search.brave.com", Path: "/res/v1/web/search"}
	if s.endpoint != nil {
		u = *s.endpoint
	}
	values := u.Query()
	values.Set("q", query)
	values.Set("count", strconv.Itoa(count))
	u.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("search request could not be created")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Subscription-Token", s.apiKey)
	response, err := s.client.Do(request)
	if err != nil {
		return nil, errors.New("search provider unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("search provider rejected the request")
	}
	var payload braveEnvelope
	if err := decodeBoundedJSONResponse(response, maxSearchBodyBytes, &payload); err != nil {
		return nil, errors.New("search provider returned invalid data")
	}
	sources := make([]SearchSource, 0, min(count, len(payload.Web.Results)))
	for _, item := range payload.Web.Results {
		if len(sources) == count {
			break
		}
		if source, ok := makeSource(item.Title, item.URL, item.Description, "", item.PageAge); ok {
			sources = append(sources, source)
		}
	}
	return sources, nil
}

func (s *SearXNGSearcher) Search(ctx context.Context, query string, count int) ([]SearchSource, error) {
	u := *s.base
	u.Path = strings.TrimRight(u.Path, "/") + "/search"
	values := u.Query()
	values.Set("q", query)
	values.Set("format", "json")
	values.Set("categories", "general")
	u.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("search request could not be created")
	}
	request.Header.Set("Accept", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return nil, errors.New("search provider unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("search provider rejected the request")
	}
	var payload searxEnvelope
	if err := decodeBoundedJSONResponse(response, maxSearchBodyBytes, &payload); err != nil {
		return nil, errors.New("search provider returned invalid data")
	}
	sources := make([]SearchSource, 0, min(count, len(payload.Results)))
	for _, item := range payload.Results {
		if len(sources) == count {
			break
		}
		if source, ok := makeSource(item.Title, item.URL, item.Content, item.PublishedDate, ""); ok {
			sources = append(sources, source)
		}
	}
	return sources, nil
}

func makeSource(title, rawURL, snippet, published, age string) (SearchSource, bool) {
	title, rawURL, snippet = cleanSearchText(title, 512), strings.TrimSpace(rawURL), cleanSearchText(snippet, 2_048)
	if strings.Contains(rawURL, "\\") {
		return SearchSource{}, false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || title == "" || !validPublicResultURL(parsed) {
		return SearchSource{}, false
	}
	if len(rawURL) > 2_048 {
		return SearchSource{}, false
	}
	return SearchSource{Title: title, URL: parsed.String(), Snippet: snippet,
		PublishedAt: cleanSearchText(published, 128), Age: cleanSearchText(age, 128)}, true
}

func validPublicResultURL(value *url.URL) bool {
	if value == nil || (value.Scheme != "https" && value.Scheme != "http") || value.Hostname() == "" ||
		value.User != nil || value.Opaque != "" || value.Fragment != "" {
		return false
	}
	if ip := net.ParseIP(value.Hostname()); ip != nil {
		return isPublicRoutableIP(ip)
	}
	return true
}

func isReservedIPv6(ip net.IP) bool {
	for _, rawPrefix := range []string{"2001::/23", "2001:db8::/32", "2001:10::/28", "2001:20::/28", "2002::/16", "3fff::/20"} {
		_, prefix, err := net.ParseCIDR(rawPrefix)
		if err == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func isReservedIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 0 || (v4[0] == 192 && v4[1] == 0) ||
		(v4[0] == 192 && v4[1] == 88 && v4[2] == 99) ||
		(v4[0] == 198 && (v4[1] == 18 || v4[1] == 19 || v4[1] == 51 && v4[2] == 100)) ||
		(v4[0] == 203 && v4[1] == 0 && v4[2] == 113) || v4[0] >= 240
}

func cleanSearchText(value string, maxBytes int) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 0x20 && r != 0x7f {
			return r
		}
		return -1
	}, value)
	if len(value) > maxBytes {
		value = value[:maxBytes]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return strings.TrimSpace(value)
}

func (g *Gateway) search(w http.ResponseWriter, r *http.Request) {
	if g.searcher == nil {
		writeError(w, http.StatusServiceUnavailable, "web search is not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input searchRequest
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid search request")
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid search request")
		return
	}
	input.Query = strings.TrimSpace(input.Query)
	maxResults := g.cfg.SearchMaxResults
	if maxResults < 1 || maxResults > maxSearchResults {
		maxResults = 5
	}
	if input.Query == "" || len(input.Query) > maxSearchQueryBytes || !safeSearchQuery(input.Query) ||
		input.Count < 0 || input.Count > maxResults {
		writeError(w, http.StatusBadRequest, "search query or result count is outside the allowed limits")
		return
	}
	count := input.Count
	if count == 0 {
		count = min(5, maxResults)
	}
	timeout := g.cfg.SearchTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	sources, err := g.searcher.Search(ctx, input.Query, count)
	if err != nil {
		writeError(w, http.StatusBadGateway, "web search provider unavailable")
		return
	}
	fetchSourcePages(r.Context(), sources, g.pageFetcher)
	provider := g.cfg.SearchProvider
	if provider == "" {
		provider = "configured"
	}
	writeJSON(w, http.StatusOK, searchResponse{Provider: provider, RetrievedAt: time.Now().UTC(), Sources: sources})
}

func safeSearchQuery(query string) bool {
	return strings.IndexFunc(query, unicode.IsControl) == -1 && !sensitiveSearchQuery.MatchString(query)
}
