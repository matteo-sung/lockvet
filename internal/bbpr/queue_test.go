package bbpr

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func queueSrv(t *testing.T, h http.HandlerFunc) *client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &client{
		http: srv.Client(),
		api:  srv.URL + "/",
	}
}

const prTemplate = `{"id":%d,"title":"%s","updated_on":"%s",
 "author":{"nickname":"%s","display_name":"%s","uuid":"%s"},
 "destination":{"repository":{"full_name":"%s"}},
 "links":{"html":{"href":"https://bitbucket.org/%s/pull-requests/%d"}}}`

func prJSON(id int, title, updated, nick, disp, uuid, fullName string) string {
	return fmt.Sprintf(prTemplate, id, title, updated, nick, disp, uuid, fullName, fullName, id)
}

func TestQueueRepoFiltersClientSide(t *testing.T) {
	c := queueSrv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repositories/acme/widget/pullrequests" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		for k, want := range map[string]string{"state": "OPEN", "sort": "-updated_on"} {
			if got := r.URL.Query().Get(k); got != want {
				t.Errorf("query %s = %q, want %q", k, got, want)
			}
		}
		fmt.Fprintf(w, `{"values":[%s,%s,%s]}`,
			prJSON(7, "human PR", "2026-07-24T12:00:00Z", "alice", "Alice", "{a1}", "acme/widget"),
			// App user: no nickname, display name only.
			prJSON(8, "Update dep a", "2026-07-24T11:00:00Z", "", "acme-renovate-bot", "{b2}", "acme/widget"),
			prJSON(9, "Update dep b", "2026-07-24T10:00:00Z", "Dependabot", "Dependabot", "{c3}", "acme/widget"))
	})
	items, err := c.queueRepo("acme", "widget", []string{"renovate-bot", "dependabot"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2 (loose author filter): %+v", len(items), items)
	}
	if items[0].Ref.ID != 8 || items[0].Author != "acme-renovate-bot" {
		t.Errorf("item 0 = %+v, want app-user renovate PR #8", items[0])
	}
	if items[1].Ref.ID != 9 || items[1].Author != "Dependabot" {
		t.Errorf("item 1 = %+v, want dependabot PR #9", items[1])
	}
	if items[0].Ref.Workspace != "acme" || items[0].Ref.Repo != "widget" {
		t.Errorf("ref = %+v", items[0].Ref)
	}
}

func TestQueueByAuthorWorkspaceWide(t *testing.T) {
	c := queueSrv(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/workspaces/acme/pullrequests/renovate-bot":
			fmt.Fprintf(w, `{"values":[%s,%s]}`,
				prJSON(3, "Update x", "2026-07-24T09:00:00Z", "renovate-bot", "Renovate", "{r1}", "acme/api"),
				prJSON(5, "Update y", "2026-07-24T11:00:00Z", "renovate-bot", "Renovate", "{r1}", "acme/web"))
		case r.URL.Path == "/workspaces/acme/pullrequests/dependabot":
			http.NotFound(w, r) // unknown username
		case r.URL.Path == "/workspaces/acme":
			fmt.Fprint(w, `{"slug":"acme"}`) // workspace exists
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	items, err := c.queueByAuthor("acme", []string{"renovate-bot", "dependabot"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2: %+v", len(items), items)
	}
	// Sorted most-recently-updated first, across repos.
	if items[0].Ref.Repo != "web" || items[1].Ref.Repo != "api" {
		t.Errorf("order = %s, %s; want web, api", items[0].Ref.Repo, items[1].Ref.Repo)
	}
	if !items[0].Updated.Equal(time.Date(2026, 7, 24, 11, 0, 0, 0, time.UTC)) {
		t.Errorf("updated = %v", items[0].Updated)
	}
}

func TestQueueByAuthorUnknownWorkspace(t *testing.T) {
	c := queueSrv(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	_, err := c.queueByAuthor("nope", []string{"renovate-bot"}, 30)
	if err == nil || !strings.Contains(err.Error(), "check the workspace name") {
		t.Fatalf("err = %v, want workspace hint", err)
	}
}

func TestQueueScanWorkspacePartialOnRateLimit(t *testing.T) {
	c := queueSrv(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repositories/acme":
			fmt.Fprint(w, `{"values":[{"slug":"one"},{"slug":"two"},{"slug":"three"}]}`)
		case "/repositories/acme/one/pullrequests":
			fmt.Fprintf(w, `{"values":[%s]}`,
				prJSON(1, "Update z", "2026-07-24T08:00:00Z", "", "acme-renovate-bot", "{b2}", "acme/one"))
		default:
			w.WriteHeader(http.StatusTooManyRequests)
		}
	})
	items, note, err := c.queueScanWorkspace("acme", []string{"renovate-bot"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Ref.Repo != "one" {
		t.Fatalf("items = %+v, want the PR gathered before the rate limit", items)
	}
	if !strings.Contains(note, "rate limited after scanning 1 of 3") {
		t.Errorf("note = %q", note)
	}
}

func TestMatchAuthor(t *testing.T) {
	pr := func(nick, disp, uuid string) queuePR {
		var p queuePR
		p.Author.Nickname, p.Author.DisplayName, p.Author.UUID = nick, disp, uuid
		return p
	}
	cases := []struct {
		pr   queuePR
		want []string
		ok   bool
	}{
		{pr("alice", "Alice", "{a}"), nil, true},                                  // no filter
		{pr("alice", "Alice", "{a}"), []string{"ALICE"}, true},                    // nickname, case-insensitive
		{pr("", "atlassian-renovate-bot", "{b}"), []string{"renovate-bot"}, true}, // display substring
		{pr("", "Renovate Bot", "{b}"), []string{"renovate"}, true},
		{pr("", "Some Bot", "{b}"), []string{"{B}"}, true}, // uuid
		{pr("alice", "Alice", "{a}"), []string{"renovate-bot", "dependabot"}, false},
	}
	for i, tc := range cases {
		if got := matchAuthor(tc.pr, tc.want); got != tc.ok {
			t.Errorf("case %d: matchAuthor(%+v, %v) = %v, want %v", i, tc.pr.Author, tc.want, got, tc.ok)
		}
	}
}
