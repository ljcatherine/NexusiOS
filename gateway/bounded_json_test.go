package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDecodeBoundedJSONResponseEnforcesCompleteBoundedDocument(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		contentLength int64
		limit         int64
		wantErr       bool
	}{
		{name: "valid exact limit", body: `{"ok":true}`, contentLength: 11, limit: 11},
		{name: "rejects body beyond limit", body: `{"ok":true} `, contentLength: -1, limit: 11, wantErr: true},
		{name: "rejects multiple JSON values", body: `{"ok":true}{"ignored":true}`, contentLength: -1, limit: 64, wantErr: true},
		{name: "rejects oversized content length before reading", body: `{"ok":true}`, contentLength: 12, limit: 11, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{
				Body:          io.NopCloser(strings.NewReader(test.body)),
				ContentLength: test.contentLength,
			}
			var decoded struct {
				OK bool `json:"ok"`
			}
			err := decodeBoundedJSONResponse(response, test.limit, &decoded)
			if (err != nil) != test.wantErr {
				t.Fatalf("decode error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && !decoded.OK {
				t.Fatal("valid bounded JSON response was not decoded")
			}
		})
	}
}
