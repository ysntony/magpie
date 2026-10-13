package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yetone/magpie/internal/provider"
)

// magpie accounts add kimi-code signs in with Kimi's device flow: the code
// is printed for Kimi's page, and the account is listed when the page is
// done with it. kimi-code-cn is the China site's own sign-in.
func TestAccountsAddKimiCode(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/oauth/device_authorization":
			json.NewEncoder(w).Encode(map[string]any{"device_code": "dc-1", "user_code": "KIMI-42",
				"verification_uri_complete": "https://www.kimi.ai/code/device?user_code=KIMI-42", "interval": 0})
		case "/api/oauth/token":
			_ = r.ParseForm()
			if polls.Add(1) == 1 {
				json.NewEncoder(w).Encode(map[string]any{"error": "authorization_pending"})
				return
			}
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
				t.Errorf("grant_type %q", r.Form.Get("grant_type"))
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "h.eyJzdWIiOiJ1c2VyLTQyIn0.sig", "refresh_token": "rt-1", "expires_in": 900})
		case "/coding/v1/usages":
			json.NewEncoder(w).Encode(map[string]any{
				"usage": map[string]any{"limit": "100", "used": "12"},
				"user":  map[string]any{"membership": map[string]any{"level": "LEVEL_ADVANCED"}},
			})
		default:
			t.Errorf("kimi: unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	defer provider.KimiCodeRegionForTest(provider.KimiCodePlanID, srv.URL, srv.URL+"/coding/v1")()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	noBrowser(t)

	out, err := said(t, func() error { return accountsCmd([]string{"accounts", "add", "kimi-code"}) })
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(out, "KIMI-42") || !strings.Contains(out, "https://www.kimi.ai/code/device?user_code=KIMI-42") {
		t.Fatalf("the code and page weren't said: %s", out)
	}
	ls := provider.Logins(provider.KimiCodePlanID)
	if len(ls) != 1 || ls[0].User != "user-42" || ls[0].Plan != "Allegro" {
		t.Fatalf("logins %+v", ls)
	}
	// the keyed presets are untouched: the account is the subscription's own
	p, err := provider.Find(provider.KimiCodePlanID)
	if err != nil || p.Account == nil {
		t.Fatalf("provider %+v %v", p, err)
	}
	if _, err := provider.Find("kimi-code"); err == nil {
		t.Fatal("a kimi-code key provider appeared from the sign-in")
	}
}
