package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mcpRoundTrip feeds newline-delimited JSON-RPC requests to serveMCP and
// returns the decoded responses in order.
func mcpRoundTrip(t *testing.T, requests []string) []map[string]any {
	t.Helper()
	in := strings.NewReader(strings.Join(requests, "\n") + "\n")
	var out strings.Builder
	if err := serveMCP(in, &out); err != nil {
		t.Fatalf("serveMCP: %v", err)
	}
	var responses []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	sc.Buffer(make([]byte, 64*1024), 32*1024*1024)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad response line %q: %v", sc.Text(), err)
		}
		responses = append(responses, m)
	}
	return responses
}

func TestMCPHandshakeAndToolsList(t *testing.T) {
	resp := mcpRoundTrip(t, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":4,"method":"nope/nope"}`,
	})
	if len(resp) != 4 {
		t.Fatalf("want 4 responses (notification is silent), got %d", len(resp))
	}

	init := resp[0]["result"].(map[string]any)
	if got := init["protocolVersion"]; got != "2025-03-26" {
		t.Errorf("protocolVersion: want echo of client's 2025-03-26, got %v", got)
	}
	if name := init["serverInfo"].(map[string]any)["name"]; name != "lockvet" {
		t.Errorf("serverInfo.name = %v", name)
	}

	tools := resp[1]["result"].(map[string]any)["tools"].([]any)
	var names []string
	for _, tl := range tools {
		names = append(names, tl.(map[string]any)["name"].(string))
	}
	if got := strings.Join(names, ","); got != "vet_url,vet_git,vet_files,queue" {
		t.Errorf("tools = %s", got)
	}
	for _, tl := range tools {
		m := tl.(map[string]any)
		if m["description"] == "" || m["inputSchema"] == nil {
			t.Errorf("tool %v missing description or schema", m["name"])
		}
	}

	if _, ok := resp[2]["result"]; !ok {
		t.Errorf("ping: want empty result, got %v", resp[2])
	}
	if e, ok := resp[3]["error"].(map[string]any); !ok || e["code"].(float64) != -32601 {
		t.Errorf("unknown method: want -32601, got %v", resp[3])
	}
}

func TestMCPVetFilesOffline(t *testing.T) {
	dir := t.TempDir()
	oldReq := filepath.Join(dir, "requirements.txt.old")
	newReq := filepath.Join(dir, "requirements.txt")
	os.WriteFile(oldReq, []byte("flask==2.0.0\nrequests==2.25.0\n"), 0o644)
	os.WriteFile(newReq, []byte("flask==3.0.0\nrequests==2.25.0\nnumpy==1.26.0\n"), 0o644)

	call := func(id int, format string) string {
		args := map[string]any{"old_path": oldReq, "new_path": newReq, "offline": true}
		if format != "" {
			args["format"] = format
		}
		b, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": id, "method": "tools/call",
			"params": map[string]any{"name": "vet_files", "arguments": args},
		})
		return string(b)
	}
	resp := mcpRoundTrip(t, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		call(2, ""),
		call(3, "json"),
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bogus","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"vet_files","arguments":{"old_path":"` + filepath.ToSlash(oldReq) + `"}}}`,
	})
	if len(resp) != 5 {
		t.Fatalf("want 5 responses, got %d", len(resp))
	}

	text := func(r map[string]any) string {
		res := r["result"].(map[string]any)
		if res["isError"].(bool) {
			t.Fatalf("tool call failed: %v", res)
		}
		return res["content"].([]any)[0].(map[string]any)["text"].(string)
	}

	md := text(resp[1])
	for _, want := range []string{"flask", "2.0.0", "3.0.0", "major", "numpy", "added"} {
		if !strings.Contains(strings.ToLower(md), want) {
			t.Errorf("markdown report missing %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "requests") {
		t.Errorf("unchanged package should not appear:\n%s", md)
	}

	var parsed struct {
		Summary struct {
			Major int `json:"major"`
			Added int `json:"added"`
		} `json:"summary"`
		VulnsChecked bool `json:"vulns_checked"`
	}
	if err := json.Unmarshal([]byte(text(resp[2])), &parsed); err != nil {
		t.Fatalf("json output: %v", err)
	}
	if parsed.Summary.Major != 1 || parsed.Summary.Added != 1 || parsed.VulnsChecked {
		t.Errorf("json summary wrong: %+v", parsed)
	}

	if e, ok := resp[3]["error"].(map[string]any); !ok || !strings.Contains(e["message"].(string), "unknown tool") {
		t.Errorf("bogus tool: want error, got %v", resp[3])
	}
	if e, ok := resp[4]["error"].(map[string]any); !ok || !strings.Contains(e["message"].(string), "old_path and new_path") {
		t.Errorf("missing args: want error, got %v", resp[4])
	}
}

func TestMCPVetGitNoRepo(t *testing.T) {
	dir := t.TempDir() // not a git repo → tool error result, not a crash
	req, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "vet_git", "arguments": map[string]any{"dir": dir, "offline": true}},
	})
	resp := mcpRoundTrip(t, []string{string(req)})
	res := resp[0]["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatalf("want isError=true outside a git repo, got %v", res)
	}
}
