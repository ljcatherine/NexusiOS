package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type fixedIPResolver []net.IPAddr

func (r fixedIPResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r, nil
}

type pageFetcherFunc func(context.Context, string) (string, error)

func (f pageFetcherFunc) Fetch(ctx context.Context, address string) (string, error) {
	return f(ctx, address)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestExtractHTMLTextExcludesExecutableAndNavigationContent(t *testing.T) {
	page := []byte(`<html><head><title>ignored title</title><script>send secrets</script></head><body>
	<nav>navigation</nav><main><h1>Research heading</h1><p>Useful article <b>text</b>.</p>
	<form>password input</form><footer>footer boilerplate</footer><div aria-hidden="true">hidden text</div></main></body></html>`)
	text := extractHTMLText(page)
	if !strings.Contains(text, "Research heading") || !strings.Contains(text, "Useful article text") ||
		strings.Contains(text, "send secrets") || strings.Contains(text, "navigation") ||
		strings.Contains(text, "password input") || strings.Contains(text, "footer boilerplate") || strings.Contains(text, "hidden text") {
		t.Fatalf("unexpected extracted page text: %q", text)
	}
}

func TestSafePageFetcherRejectsUnsafeURLAndPinsPublicDNSAddress(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1/admin", "http://localhost/", "https://server.local/", "https://host.internal/",
		"https://public.example.org:444/page",
	} {
		parsed, _ := url.Parse(raw)
		if validPageFetchURL(parsed) {
			t.Errorf("unsafe page URL was accepted: %s", raw)
		}
	}
	publicURL, _ := url.Parse("https://public.example.org/")
	if !validPageFetchURL(publicURL) {
		t.Fatal("ordinary public HTTPS page URL was rejected")
	}

	private := &safePageFetcher{resolver: fixedIPResolver{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("10.0.0.8")}}}
	dialCalled := false
	private.dial = func(context.Context, string, string) (net.Conn, error) {
		dialCalled = true
		return nil, errors.New("test dial")
	}
	if _, err := private.dialValidated(context.Background(), "tcp", "public.example:443"); err == nil || dialCalled {
		t.Fatal("mixed public/private DNS results were not rejected before dialing")
	}

	var dialAddress string
	public := &safePageFetcher{resolver: fixedIPResolver{{IP: net.ParseIP("93.184.216.34")}}}
	public.dial = func(_ context.Context, _, address string) (net.Conn, error) {
		dialAddress = address
		return nil, errors.New("expected fixture dial stop")
	}
	if _, err := public.dialValidated(context.Background(), "tcp", "public.example:443"); err == nil || dialAddress != "93.184.216.34:443" {
		t.Fatalf("DNS result was not pinned to its vetted address: target=%q err=%v", dialAddress, err)
	}
}

func TestPageTextExtractionIsBounded(t *testing.T) {
	content := extractHTMLText([]byte("<html><body><p>" + strings.Repeat("x", maxExtractedBytes+100) + "</p></body></html>"))
	if len(content) > maxExtractedBytes {
		t.Fatalf("extracted %d bytes, limit is %d", len(content), maxExtractedBytes)
	}
}

func TestPublicRoutableIPFiltersReservedRanges(t *testing.T) {
	for _, raw := range []string{"8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"} {
		if !isPublicRoutableIP(net.ParseIP(raw)) {
			t.Errorf("public address %s was rejected", raw)
		}
	}
	for _, raw := range []string{
		"10.0.0.1", "100.64.0.1", "192.0.0.9", "192.0.2.1", "198.19.0.1", "203.0.113.1", "240.0.0.1",
		"::1", "fe80::1", "2001:db8::1", "2001:10::1", "2002::1", "3fff::1", "64:ff9b::808:808",
	} {
		if isPublicRoutableIP(net.ParseIP(raw)) {
			t.Errorf("non-public or special address %s was accepted", raw)
		}
	}
}

func TestSafePageFetcherEnforcesResponseTypeStatusAndByteLimits(t *testing.T) {
	validHTML := `<html><body><article><p>bounded page excerpt</p></article></body></html>`
	for name, response := range map[string]*http.Response{
		"valid HTML": {StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/html; charset=utf-8"}},
			Body: io.NopCloser(strings.NewReader(validHTML)), ContentLength: -1},
		"redirect": {StatusCode: http.StatusFound, Header: http.Header{"Location": {"https://elsewhere.example/"}},
			Body: io.NopCloser(strings.NewReader("redirect")), ContentLength: -1},
		"unsupported content": {StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"private":"data"}`)), ContentLength: -1},
		"oversized body": {StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}},
			Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxFetchedPageBytes+1))), ContentLength: -1},
	} {
		fetcher := &safePageFetcher{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			copy := *response
			copy.Header = response.Header.Clone()
			copy.Body = io.NopCloser(response.Body)
			return &copy, nil
		})}, slots: make(chan struct{}, 1)}
		content, err := fetcher.Fetch(context.Background(), "https://example.org/article")
		if name == "valid HTML" {
			if err != nil || content != "bounded page excerpt" {
				t.Fatalf("valid page result=%q err=%v", content, err)
			}
		} else if err == nil {
			t.Errorf("%s response was accepted", name)
		}
	}
}
