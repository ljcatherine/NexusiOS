package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html"
)

const (
	maxFetchedPageBytes = 2 << 20
	maxExtractedBytes   = 8 << 10
	pageFetchTimeout    = 4 * time.Second
)

type PageFetcher interface {
	Fetch(context.Context, string) (string, error)
}

type ipAddressResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type safePageFetcher struct {
	client   *http.Client
	resolver ipAddressResolver
	dial     func(context.Context, string, string) (net.Conn, error)
	slots    chan struct{}
}

func NewSafePageFetcher() PageFetcher {
	fetcher := &safePageFetcher{resolver: net.DefaultResolver, slots: make(chan struct{}, 8)}
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 20 * time.Second}
	fetcher.dial = dialer.DialContext
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            fetcher.dialValidated,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        20 * time.Second,
		TLSHandshakeTimeout:    2 * time.Second,
		ResponseHeaderTimeout:  3 * time.Second,
		MaxResponseHeaderBytes: 32 << 10,
	}
	fetcher.client = &http.Client{Transport: transport, Timeout: pageFetchTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return fetcher
}

func (f *safePageFetcher) Fetch(parent context.Context, rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || !validPageFetchURL(parsed) {
		return "", errors.New("page address is not eligible for retrieval")
	}
	ctx, cancel := context.WithTimeout(parent, pageFetchTimeout)
	defer cancel()
	select {
	case f.slots <- struct{}{}:
		defer func() { <-f.slots }()
	case <-ctx.Done():
		return "", errors.New("page retrieval capacity is currently full")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", errors.New("page request could not be created")
	}
	request.Header.Set("Accept", "text/html,application/xhtml+xml,text/plain;q=0.9")
	request.Header.Set("User-Agent", "NexusResearch/1.0 (+https://github.com/ljcatherine/NexusiOS)")
	response, err := f.client.Do(request)
	if err != nil {
		return "", errors.New("page host unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", errors.New("page host returned an unsuccessful status")
	}
	if response.ContentLength > maxFetchedPageBytes {
		return "", errors.New("page response is too large")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (mediaType != "text/html" && mediaType != "application/xhtml+xml" && mediaType != "text/plain") {
		return "", errors.New("page content type is not supported")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxFetchedPageBytes+1))
	if err != nil || len(data) > maxFetchedPageBytes || !utf8.Valid(data) {
		return "", errors.New("page response is invalid or too large")
	}
	if mediaType == "text/plain" {
		return cleanSearchText(string(data), maxExtractedBytes), nil
	}
	return extractHTMLText(data), nil
}

func validPageFetchURL(value *url.URL) bool {
	if !validPublicResultURL(value) {
		return false
	}
	port := value.Port()
	if port != "" && !((value.Scheme == "https" && port == "443") || (value.Scheme == "http" && port == "80")) {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(value.Hostname(), "."))
	for _, suffix := range []string{".localhost", ".local", ".internal", ".home.arpa", ".test", ".example", ".invalid", ".onion"} {
		if host == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(host, suffix) {
			return false
		}
	}
	return true
}

func (f *safePageFetcher) dialValidated(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return nil, errors.New("page host address is invalid")
	}
	var addresses []net.IPAddr
	if literal := net.ParseIP(host); literal != nil {
		addresses = []net.IPAddr{{IP: literal}}
	} else {
		resolver := f.resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		addresses, err = resolver.LookupIPAddr(ctx, host)
		if err != nil || len(addresses) == 0 || len(addresses) > 32 {
			return nil, errors.New("page host DNS lookup failed")
		}
	}
	for _, address := range addresses {
		if !isPublicRoutableIP(address.IP) {
			return nil, errors.New("page host resolves to a non-public address")
		}
	}
	if f.dial == nil {
		return nil, errors.New("page network dialer is unavailable")
	}
	return f.dial(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
}

func isPublicRoutableIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		return v4.IsGlobalUnicast() && !v4.IsPrivate() && !isPrivateIPv4(v4) && !v4.IsLoopback() && !v4.IsLinkLocalUnicast() &&
			!v4.IsUnspecified() && !v4.IsMulticast() && !isReservedIPv4(v4)
	}
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() || ip.IsMulticast() || isReservedIPv6(ip) {
		return false
	}
	_, globalUnicast, err := net.ParseCIDR("2000::/3")
	return err == nil && globalUnicast.Contains(ip)
}

func extractHTMLText(data []byte) string {
	document, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return ""
	}
	var builder strings.Builder
	var walk func(*html.Node, bool)
	walk = func(node *html.Node, excluded bool) {
		if builder.Len() >= maxExtractedBytes {
			return
		}
		if node.Type == html.ElementNode {
			switch strings.ToLower(node.Data) {
			case "head", "title", "script", "style", "noscript", "svg", "nav", "footer", "header", "aside", "form", "iframe", "canvas":
				excluded = true
			}
			for _, attr := range node.Attr {
				if strings.EqualFold(attr.Key, "aria-hidden") && strings.EqualFold(attr.Val, "true") ||
					strings.EqualFold(attr.Key, "hidden") {
					excluded = true
				}
			}
			if !excluded && (node.Data == "p" || node.Data == "br" || node.Data == "li" || node.Data == "h1" ||
				node.Data == "h2" || node.Data == "h3" || node.Data == "article" || node.Data == "section") {
				builder.WriteByte('\n')
			}
		}
		if node.Type == html.TextNode && !excluded {
			builder.WriteString(node.Data)
			builder.WriteByte(' ')
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child, excluded)
		}
	}
	walk(document, false)
	return cleanSearchText(strings.Join(strings.Fields(builder.String()), " "), maxExtractedBytes)
}

func fetchSourcePages(parent context.Context, sources []SearchSource, fetcher PageFetcher) {
	if fetcher == nil || len(sources) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	semaphore := make(chan struct{}, 3)
	done := make(chan struct{}, len(sources))
	for index := range sources {
		go func(index int) {
			defer func() { done <- struct{}{} }()
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-semaphore }()
			content, err := fetcher.Fetch(ctx, sources[index].URL)
			if err == nil {
				sources[index].Content = cleanSearchText(content, maxExtractedBytes)
			}
		}(index)
	}
	for range sources {
		<-done
	}
}
