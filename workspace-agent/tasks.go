package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// This is a deliberately restricted orchestration interface, not an LLM
// execution environment. No prompts, remote shell, commands, or write APIs.
type taskRequest struct {
	Host        string `json:"host"`
	WorkspaceID string `json:"workspace_id"`
	Operation   string `json:"operation"`
	Path        string `json:"path"`
	Query       string `json:"query,omitempty"`
}

type textHit struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

func (s *server) runTask(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	var request taskRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		sendError(w, 400, "invalid_task")
		return
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		sendError(w, 400, "invalid_task")
		return
	}
	if !s.requireHost(w, request.Host) {
		return
	}
	root := s.root(w, request.WorkspaceID)
	if root == nil {
		return
	}
	if _, err := segments(request.Path, true); err != nil {
		respondFSError(w, err)
		return
	}
	gitOperation := request.Operation == "git_status" || request.Operation == "git_diff" || request.Operation == "git_diff_staged"
	if request.Operation != "inventory" && request.Operation != "find_text" && !gitOperation {
		sendError(w, 400, "unsupported_operation")
		return
	}
	if request.Operation != "find_text" && request.Query != "" {
		sendError(w, 400, "invalid_task")
		return
	}
	if gitOperation && (!root.config.GitRead || s.git == nil) {
		sendError(w, 403, "git_inspection_disabled")
		return
	}
	if request.Operation == "find_text" && (len(request.Query) < 2 || len(request.Query) > 80 || !utf8.ValidString(request.Query) || strings.ContainsAny(request.Query, "\r\n\x00")) {
		sendError(w, 400, "invalid_query")
		return
	}
	select {
	case s.tasks <- struct{}{}:
		defer func() { <-s.tasks }()
	default:
		sendError(w, 429, "task_capacity_reached")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	result := taskResult{Host: s.host, WorkspaceID: request.WorkspaceID, Operation: request.Operation, Status: "completed", Entries: []fileEntry{}, Hits: []textHit{}}
	var err error
	switch request.Operation {
	case "inventory":
		err = inventory(ctx, root, request.Path, &result)
	case "find_text":
		err = findText(ctx, root, request.Path, request.Query, &result)
	case "git_status", "git_diff", "git_diff_staged":
		result.Git, err = s.git.inspect(ctx, root, request.Operation, request.Path)
	}
	if err != nil {
		if errors.Is(err, errGitUnavailable) {
			sendError(w, 503, "git_inspection_unavailable")
			return
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			sendError(w, 408, "task_time_limit")
			return
		}
		respondFSError(w, err)
		return
	}
	sendJSON(w, 200, result)
}

type taskResult struct {
	Host        string      `json:"host"`
	WorkspaceID string      `json:"workspace_id"`
	Operation   string      `json:"operation"`
	Status      string      `json:"status"`
	Entries     []fileEntry `json:"entries"`
	Hits        []textHit   `json:"hits"`
	Scanned     int         `json:"scanned_files"`
	Truncated   bool        `json:"truncated"`
	Git         *gitResult  `json:"git,omitempty"`
}

func inventory(ctx context.Context, root *workspace, relative string, result *taskResult) error {
	// Three directory levels (root/children/grandchildren), 128 total entries.
	type node struct {
		path  string
		depth int
	}
	queue := []node{{relative, 0}}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := queue[0]
		queue = queue[1:]
		remaining := maxEntries - len(result.Entries)
		if remaining <= 0 {
			result.Truncated = true
			break
		}
		entries, clipped, err := root.list(current.path, remaining)
		if err != nil {
			return err
		}
		result.Entries = append(result.Entries, entries...)
		if clipped {
			result.Truncated = true
		}
		for _, entry := range entries {
			if entry.Kind == "directory" {
				if current.depth < 2 {
					queue = append(queue, node{entry.Path, current.depth + 1})
				} else {
					result.Truncated = true
				}
			}
		}
		if clipped {
			break
		}
	}
	if len(queue) > 0 {
		result.Truncated = true
	}
	return nil
}

func findText(ctx context.Context, root *workspace, relative, query string, result *taskResult) error {
	// Search only the immediate directory, scanning at most 24 eligible files;
	// each file is capped at 64 KiB, and at most 20 matching lines are emitted.
	entries, clipped, err := root.list(relative, maxEntries)
	if err != nil {
		return err
	}
	result.Truncated = clipped
	needle := strings.ToLower(query)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Kind != "file" {
			continue
		}
		if result.Scanned >= 24 {
			result.Truncated = true
			break
		}
		result.Scanned++
		content, err := root.readText(entry.Path)
		if err != nil {
			continue
		} // Files too large, binary, or changed during scan are skipped.
		for number, line := range strings.Split(content, "\n") {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !strings.Contains(strings.ToLower(line), needle) {
				continue
			}
			if len(result.Hits) == 20 {
				result.Truncated = true
				return nil
			}
			if len(line) > 240 {
				prefix := []rune(line)
				if len(prefix) > 120 {
					prefix = prefix[:120]
				}
				for len(prefix) > 0 && len(string(prefix)) > 240 {
					prefix = prefix[:len(prefix)-1]
				}
				line = string(prefix)
			}
			result.Hits = append(result.Hits, textHit{Path: entry.Path, Line: number + 1, Text: line})
		}
	}
	return nil
}
