package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/appdir"
	"github.com/yetone/magpie/internal/catalog"
)

// kimiFake is Kimi's OAuth host and API for tests: the device flow, the
// token endpoint (the device grant and refreshes), and the usage read.
// token answers the token endpoint by the form it was posted and the count
// of the call; usage answers /usages, with the membership's level.
type kimiFake struct {
	t          *testing.T
	url        string
	polls      atomic.Int32
	refreshes  atomic.Int32
	usageReads atomic.Int32
	mu         sync.Mutex
	pollAt     []time.Time
	// token answers a poll or a refresh: the form and the call's number
	// (polls and refreshes counted apart).
	token func(form url.Values, poll, refresh int) (int, any)
	// level is the membership level /usages tells, "LEVEL_ADVANCED" (Allegro)
	level string
	// refuseRefresh: a refresh token is good exactly once, as Kimi rotates it
	once sync.Map // refresh token → still good
}

func (f *kimiFake) serve(w http.ResponseWriter, r *http.Request) {
	t := f.t
	if err := r.ParseForm(); err != nil {
		t.Errorf("%s: %v", r.URL.Path, err)
	}
	switch r.URL.Path {
	case "/api/oauth/device_authorization", "/api/oauth/token":
		if r.Method != http.MethodPost {
			t.Errorf("%s %s, want POST", r.Method, r.URL.Path)
		}
		if r.Form.Get("client_id") != kimiCodeClientID {
			t.Errorf("%s client_id %q, want the CLI's public client", r.URL.Path, r.Form.Get("client_id"))
		}
	}
	// magpie's own identity, never the CLI's (kimi_code_cli): every OAuth
	// call and the usage read carry it, with a stable device id
	if ua := r.Header.Get("User-Agent"); ua != "magpie/"+Version {
		t.Errorf("%s User-Agent %q, want magpie/%s", r.URL.Path, ua, Version)
	}
	if r.Header.Get("X-Msh-Platform") != "magpie" || r.Header.Get("X-Msh-Version") != Version ||
		r.Header.Get("X-Msh-Device-Name") != "magpie" || r.Header.Get("X-Msh-Device-Model") != "magpie" ||
		r.Header.Get("X-Msh-Os-Version") == "" {
		t.Errorf("%s X-Msh headers %v", r.URL.Path, r.Header)
	}
	if id := r.Header.Get("X-Msh-Device-Id"); !kimiUUIDRe.MatchString(id) {
		t.Errorf("%s X-Msh-Device-Id %q, want a UUID", r.URL.Path, id)
	}
	switch r.URL.Path {
	case "/api/oauth/device_authorization":
		json.NewEncoder(w).Encode(map[string]any{"device_code": "dc-1", "user_code": "KIMI-42",
			"verification_uri_complete": "https://www.kimi.ai/code/device?user_code=KIMI-42", "interval": 0})
	case "/api/oauth/token":
		grant := r.Form.Get("grant_type")
		var status int
		var body any
		switch grant {
		case "urn:ietf:params:oauth:grant-type:device_code":
			f.mu.Lock()
			f.pollAt = append(f.pollAt, time.Now())
			f.mu.Unlock()
			status, body = f.token(r.Form, int(f.polls.Add(1)), 0)
		case "refresh_token":
			tok := r.Form.Get("refresh_token")
			if v, ok := f.once.Load(tok); ok && v.(bool) {
				f.once.Store(tok, false)
			} else {
				// Kimi's refresh tokens rotate: an old one works exactly once
				status, body = 400, map[string]any{"error": "invalid_grant", "error_description": "refresh token already used"}
				break
			}
			status, body = f.token(r.Form, 0, int(f.refreshes.Add(1)))
		default:
			t.Errorf("grant_type %q", grant)
			w.WriteHeader(400)
			return
		}
		if status != 200 {
			w.WriteHeader(status)
		}
		json.NewEncoder(w).Encode(body)
	case "/coding/v1/usages":
		f.usageReads.Add(1)
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("/usages without a Bearer: %v", r.Header)
		}
		level := f.level
		if level == "" {
			level = "LEVEL_ADVANCED"
		}
		json.NewEncoder(w).Encode(map[string]any{
			"usage": map[string]any{"limit": "100", "used": "12", "resetTime": time.Now().Add(3 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)},
			"limits": []any{map[string]any{
				"window": map[string]any{"duration": 300, "timeUnit": "TIME_UNIT_MINUTE"},
				"detail": map[string]any{"limit": "100", "remaining": "88", "resetTime": time.Now().Add(5 * time.Hour).UTC().Format(time.RFC3339Nano)},
			}},
			"user": map[string]any{"membership": map[string]any{"level": level}},
		})
	default:
		t.Errorf("kimi: unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(404)
	}
}

var kimiUUIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// kimiTokens are a token answer with a fresh access token of user and a
// refresh token that is good once (as Kimi's are).
func (f *kimiFake) tokens(user, refresh string, expiresIn int) (int, any) {
	f.once.Store(refresh, true)
	return 200, map[string]any{"access_token": fakeJWT(map[string]any{"sub": user, "exp": time.Now().Add(time.Hour).Unix()}),
		"refresh_token": refresh, "expires_in": expiresIn}
}

// kimiAt points one site's region at the fake and hands the fake back.
func kimiAt(t *testing.T, agent string) *kimiFake {
	t.Helper()
	f := &kimiFake{t: t, token: func(url.Values, int, int) (int, any) {
		return 200, map[string]any{"error": "authorization_pending"}
	}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	region := kimiCodeRegionOf(agent)
	old := *region
	t.Cleanup(func() { kimiCodeRegions[agent] = &old })
	kimiCodeRegions[agent] = &kimiCodeRegion{
		id: old.id, name: old.name, site: old.site, catalog: old.catalog,
		auth: srv.URL, api: srv.URL + "/coding/v1", anth: srv.URL + "/coding",
	}
	return f
}

// kimiSignIn runs a sign-in of agent to its end, failing the test when it
// is still waiting after d.
func kimiSignIn(t *testing.T, agent string, d time.Duration) SignInState {
	t.Helper()
	st, err := StartSignIn(agent)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	end, err := WaitSignIn(ctx, st.ID)
	if err != nil {
		CancelSignIn(st.ID)
		t.Fatalf("the sign-in never ended: %+v %v", end, err)
	}
	return end
}

// TestKimiCodeRegions are the two sites' hosts as Kimi has them: the
// global one and the China one, whose accounts exist only there.
func TestKimiCodeRegions(t *testing.T) {
	global, cn := kimiCodeRegionOf(KimiCodePlanID), kimiCodeRegionOf(KimiCodePlanCNID)
	if global.auth != "https://auth.kimi.ai" || global.api != "https://api.kimi.ai/coding/v1" || global.anth != "https://api.kimi.ai/coding" || global.site != "https://www.kimi.ai" || global.catalog != "kimi-code-plan-global" {
		t.Errorf("global region %+v", global)
	}
	if cn.auth != "https://auth.kimi.com" || cn.api != "https://api.kimi.com/coding/v1" || cn.anth != "https://api.kimi.com/coding" || cn.site != "https://www.kimi.com" || cn.catalog != "kimi-code-plan-cn" {
		t.Errorf("cn region %+v", cn)
	}
}

// A Kimi Code membership signed in with Kimi's device flow: the code shown,
// the account kept in logins.json beside a keyed preset's, models from the
// membership's catalog, requests signed with the access token, and the
// Usage page's reading of /usages with the membership's plan.
func TestKimiCodeSignIn(t *testing.T) {
	signIn(t)
	useKimiCodeCatalog(t)
	f := kimiAt(t, KimiCodePlanID)
	f.token = func(_ url.Values, poll, _ int) (int, any) {
		if poll == 1 {
			return 200, map[string]any{"error": "authorization_pending"}
		}
		return f.tokens("user-42", "rt-1", 900)
	}

	st, err := StartSignIn(KimiCodePlanID)
	if err != nil {
		t.Fatal(err)
	}
	if st.URL != "https://www.kimi.ai/code/device?user_code=KIMI-42" || st.Code != "KIMI-42" {
		t.Fatalf("sign-in shows %+v", st)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done, err := WaitSignIn(ctx, st.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.State != "done" || done.User != "user-42" || done.Plan != "Allegro" || !done.Using {
		t.Fatalf("sign-in ended %+v", done)
	}

	// the device id is magpie's own, kept in its own config
	id, err := kimiCodeDeviceID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(appdir.Config(), "kimi-code-device"))
	if err != nil || strings.TrimSpace(string(b)) != id {
		t.Fatalf("kimi-code-device: %q %v", b, err)
	}

	// the account as logins.json keeps it
	ls := Logins(KimiCodePlanID)
	if len(ls) != 1 || ls[0].User != "user-42" || ls[0].Plan != "Allegro" || !ls[0].Active || !ls[0].On {
		t.Fatalf("logins %+v", ls)
	}
	var saved *savedLogin
	for _, l := range readLogins() {
		if l.Agent == KimiCodePlanID {
			l := l
			saved = &l
		}
	}
	if saved == nil {
		t.Fatal("no saved kimi-code-plan login")
	}
	a, ok := kimiCodeSaved(*saved)
	if !ok || a.Refresh != "rt-1" || time.Until(time.Unix(a.Expires, 0)) < 10*time.Minute {
		t.Fatalf("saved %+v", a)
	}

	// the provider, beside the keyed preset's: the region's bases, models
	// from the membership's catalog
	p, found := find(All(), KimiCodePlanID)
	if !found || p.Account == nil || p.Account.User != "user-42" || p.Chat != f.url+"/coding/v1" || p.Anthropic != f.url+"/coding" {
		t.Fatalf("provider %+v", p)
	}
	models := p.Account.models()
	if !slices.ContainsFunc(models, func(m catalog.Model) bool { return m.ID == "k3" }) {
		t.Fatalf("models %v", models)
	}
	if pr, ok := p.ListPrice("k3"); !ok || pr.Input != 3 || pr.Output != 15 {
		t.Fatalf("k3 priced %+v %v, want the Kimi API's kimi-k3", pr, ok)
	}

	// requests signed with the access token, magpie's identity with them
	req := httptest.NewRequest(http.MethodPost, p.Chat+"/chat/completions", nil)
	if err := p.Sign(context.Background(), req, Chat, nil); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "Bearer "+a.Access || req.Header.Get("X-Msh-Platform") != "magpie" || req.Header.Get("X-Msh-Device-Id") != id {
		t.Fatalf("signed %v", req.Header)
	}

	// the Usage page's reading: the membership's windows and plan
	q := LoginUsage(context.Background(), KimiCodePlanID)["user-42"]
	if q.Error != "" || q.Plan != "Allegro" || len(q.Windows) != 2 {
		t.Fatalf("quota %+v", q)
	}
	if q.Windows[1].Name != "7 days" || q.Windows[1].Used != 12 {
		t.Fatalf("week %+v", q.Windows)
	}
	// the card as the Usage page draws it: the site's name and Kimi's logo
	if face := accountCard(KimiCodePlanID); face.name != "Kimi Code" || face.icon != "kimi" {
		t.Errorf("the account's card %+v", face)
	}
	if f.usageReads.Load() < 2 {
		t.Errorf("/usages read %d times, want at least the sign-in's and the card's", f.usageReads.Load())
	}
}

// slow_down is a rate hint, not a failure: the sign-in goes on, polling
// less often — the interval the answer names when it does.
func TestKimiCodeSignInSlowDown(t *testing.T) {
	signIn(t)
	f := kimiAt(t, KimiCodePlanID)
	f.token = func(_ url.Values, poll, _ int) (int, any) {
		switch poll {
		case 1:
			return 200, map[string]any{"error": "slow_down", "interval": 2}
		case 2:
			return 200, map[string]any{"error": "authorization_pending"}
		default:
			return f.tokens("user-42", "rt-1", 900)
		}
	}
	done := kimiSignIn(t, KimiCodePlanID, 20*time.Second)
	if done.State != "done" || done.User != "user-42" {
		t.Fatalf("sign-in ended %+v", done)
	}
	f.mu.Lock()
	at := slices.Clone(f.pollAt)
	f.mu.Unlock()
	if len(at) < 3 {
		t.Fatalf("polled %d times", len(at))
	}
	if d := at[1].Sub(at[0]); d < 1800*time.Millisecond {
		t.Errorf("after slow_down the next poll came %v later, want the 2s it asked", d)
	}
}

// A code Kimi says is expired fails the sign-in to be started again.
func TestKimiCodeSignInExpired(t *testing.T) {
	signIn(t)
	f := kimiAt(t, KimiCodePlanID)
	f.token = func(_ url.Values, poll, _ int) (int, any) {
		if poll == 1 {
			return 200, map[string]any{"error": "authorization_pending"}
		}
		return 400, map[string]any{"error": "expired_token"}
	}
	done := kimiSignIn(t, KimiCodePlanID, 15*time.Second)
	if done.State != "failed" || !strings.Contains(done.Error, "expired") {
		t.Fatalf("sign-in ended %+v", done)
	}
}

// A sign-in the user declines at Kimi's page says so.
func TestKimiCodeSignInDeclined(t *testing.T) {
	signIn(t)
	f := kimiAt(t, KimiCodePlanID)
	f.token = func(_ url.Values, poll, _ int) (int, any) {
		if poll == 1 {
			return 200, map[string]any{"error": "authorization_pending"}
		}
		return 400, map[string]any{"error": "access_denied"}
	}
	done := kimiSignIn(t, KimiCodePlanID, 15*time.Second)
	if done.State != "failed" || !strings.Contains(done.Error, "declined") {
		t.Fatalf("sign-in ended %+v", done)
	}
}

// A token endpoint that keeps failing fails the sign-in with what Kimi
// answered, instead of waiting out the sign-in's ten minutes.
func TestKimiCodeSignInPollKeepsFailing(t *testing.T) {
	signIn(t)
	f := kimiAt(t, KimiCodePlanID)
	f.token = func(_ url.Values, _, _ int) (int, any) {
		return 502, []byte("upstream connect error")
	}
	old := kimiCodePollMisses
	kimiCodePollMisses = 2
	defer func() { kimiCodePollMisses = old }()
	done := kimiSignIn(t, KimiCodePlanID, 15*time.Second)
	if done.State != "failed" || !strings.Contains(done.Error, "couldn't get the token") {
		t.Fatalf("sign-in ended %+v", done)
	}
	if n := f.polls.Load(); n != 2 {
		t.Errorf("polled %d times, want the %d misses", n, kimiCodePollMisses)
	}
}

// A sign-in to the China site goes to its OAuth host and its API base,
// never the global one's.
func TestKimiCodeSignInCN(t *testing.T) {
	signIn(t)
	f := kimiAt(t, KimiCodePlanCNID)
	f.token = func(_ url.Values, poll, _ int) (int, any) {
		if poll == 1 {
			return 200, map[string]any{"error": "authorization_pending"}
		}
		return f.tokens("user-43", "rt-cn", 900)
	}
	done := kimiSignIn(t, KimiCodePlanCNID, 15*time.Second)
	if done.State != "done" || done.User != "user-43" {
		t.Fatalf("sign-in ended %+v", done)
	}
	p, found := find(All(), KimiCodePlanCNID)
	if !found || p.Chat != f.url+"/coding/v1" || p.Anthropic != f.url+"/coding" {
		t.Fatalf("cn provider %+v", p)
	}
	if _, found := find(All(), KimiCodePlanID); found {
		t.Fatal("a global account appeared with the China sign-in")
	}
}

// An access token near its end is refreshed before the request is signed;
// the rotated bundle is kept — the old refresh token is spent, the new one
// is what the next refresh spends.
func TestKimiCodeRefreshRotates(t *testing.T) {
	signIn(t)
	f := kimiAt(t, KimiCodePlanID)
	f.token = func(_ url.Values, poll, _ int) (int, any) {
		if poll == 1 {
			return 200, map[string]any{"error": "authorization_pending"}
		}
		return f.tokens("user-42", "rt-1", 900)
	}
	if done := kimiSignIn(t, KimiCodePlanID, 15*time.Second); done.State != "done" {
		t.Fatalf("sign-in ended %+v", done)
	}
	// out of date: the next sign refreshes
	if err := editSideLogin(KimiCodePlanID, "user-42", func(ls []savedLogin, i int) ([]savedLogin, error) {
		a, _ := kimiCodeSaved(ls[i])
		a.Expires = time.Now().Add(-time.Minute).Unix()
		ls[i].Auth, _ = json.Marshal(a)
		return ls, nil
	}); err != nil {
		t.Fatal(err)
	}
	f.token = func(_ url.Values, _, refresh int) (int, any) {
		if refresh != 1 {
			t.Errorf("refresh %d, want the first", refresh)
		}
		return f.tokens("user-42", "rt-2", 900)
	}

	p, _ := find(All(), KimiCodePlanID)
	req := httptest.NewRequest(http.MethodPost, p.Chat+"/chat/completions", nil)
	if err := p.Sign(context.Background(), req, Chat, nil); err != nil {
		t.Fatal(err)
	}
	bearer := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	if bearer == "" || claimString(jwtClaims(bearer), "sub") != "user-42" {
		t.Fatalf("signed %v", req.Header)
	}
	var saved *savedLogin
	for _, l := range readLogins() {
		if l.Agent == KimiCodePlanID {
			l := l
			saved = &l
		}
	}
	a, _ := kimiCodeSaved(*saved)
	if a.Refresh != "rt-2" || time.Until(time.Unix(a.Expires, 0)) < 10*time.Minute {
		t.Fatalf("the rotated bundle wasn't kept: %+v", a)
	}
	if saved.Lapsed != "" || saved.Renewed.IsZero() {
		t.Fatalf("renewal not marked: %+v", saved)
	}

	// fresh now: another request refreshes nothing
	req2 := httptest.NewRequest(http.MethodPost, p.Chat+"/chat/completions", nil)
	if err := p.Sign(context.Background(), req2, Chat, nil); err != nil {
		t.Fatal(err)
	}
	if n := f.refreshes.Load(); n != 1 {
		t.Errorf("refreshed %d times, want once", n)
	}
}

// Two requests signed at once share one refresh: the second never spends
// the refresh token the first just rotated (Kimi's work exactly once).
func TestKimiCodeRefreshSerialized(t *testing.T) {
	signIn(t)
	f := kimiAt(t, KimiCodePlanID)
	f.token = func(_ url.Values, poll, _ int) (int, any) {
		if poll == 1 {
			return 200, map[string]any{"error": "authorization_pending"}
		}
		return f.tokens("user-42", "rt-1", 900)
	}
	if done := kimiSignIn(t, KimiCodePlanID, 15*time.Second); done.State != "done" {
		t.Fatalf("sign-in ended %+v", done)
	}
	if err := editSideLogin(KimiCodePlanID, "user-42", func(ls []savedLogin, i int) ([]savedLogin, error) {
		a, _ := kimiCodeSaved(ls[i])
		a.Expires = time.Now().Add(-time.Minute).Unix()
		ls[i].Auth, _ = json.Marshal(a)
		return ls, nil
	}); err != nil {
		t.Fatal(err)
	}
	f.token = func(_ url.Values, _, refresh int) (int, any) {
		return f.tokens("user-42", fmt.Sprintf("rt-%d", refresh+1), 900)
	}

	p, _ := find(All(), KimiCodePlanID)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, p.Chat+"/chat/completions", nil)
			if err := p.Sign(context.Background(), req, Chat, nil); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := f.refreshes.Load(); n != 1 {
		t.Errorf("8 signs refreshed %d times, want one", n)
	}
}

// A refresh Kimi refuses marks the account to be signed in again, as a
// lapsed sign-in's; one that only hiccups marks nothing.
func TestKimiCodeRefreshRefusedLapses(t *testing.T) {
	signIn(t)
	f := kimiAt(t, KimiCodePlanID)
	f.token = func(_ url.Values, poll, _ int) (int, any) {
		if poll == 1 {
			return 200, map[string]any{"error": "authorization_pending"}
		}
		return f.tokens("user-42", "rt-1", 900)
	}
	if done := kimiSignIn(t, KimiCodePlanID, 15*time.Second); done.State != "done" {
		t.Fatalf("sign-in ended %+v", done)
	}
	if err := editSideLogin(KimiCodePlanID, "user-42", func(ls []savedLogin, i int) ([]savedLogin, error) {
		a, _ := kimiCodeSaved(ls[i])
		a.Expires = time.Now().Add(-time.Minute).Unix()
		ls[i].Auth, _ = json.Marshal(a)
		return ls, nil
	}); err != nil {
		t.Fatal(err)
	}
	// the token is spent elsewhere: Kimi refuses it now
	f.once.Store("rt-1", false)

	p, _ := find(All(), KimiCodePlanID)
	req := httptest.NewRequest(http.MethodPost, p.Chat+"/chat/completions", nil)
	err := p.Sign(context.Background(), req, Chat, nil)
	if err == nil || !strings.Contains(err.Error(), "sign in again") {
		t.Fatalf("sign with a refused refresh: %v", err)
	}
	if l := Logins(KimiCodePlanID)[0]; !strings.Contains(l.Lapsed, "sign in again") {
		t.Fatalf("not marked lapsed: %+v", l)
	}
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		f.once.Store("rt-1", true)
		f.token = func(_ url.Values, _, _ int) (int, any) { return status, map[string]any{"error": "invalid_client"} }
		if _, err := kimiCodeToken(context.Background(), KimiCodePlanID, "user-42"); err == nil || !strings.Contains(err.Error(), "sign in again") {
			t.Fatalf("refresh refused with %d: %v", status, err)
		}
	}
}

func TestKimiCodeReloginClearsLapsed(t *testing.T) {
	for _, agent := range kimiCodeAgents {
		t.Run(agent, func(t *testing.T) {
			signIn(t)
			f := kimiAt(t, agent)
			f.token = func(_ url.Values, poll, _ int) (int, any) {
				if poll == 1 {
					return 200, map[string]any{"error": "authorization_pending"}
				}
				return f.tokens("user-42", "rt-1", 900)
			}
			if done := kimiSignIn(t, agent, 15*time.Second); done.State != "done" {
				t.Fatal(done)
			}
			if err := editSideLogin(agent, "user-42", func(ls []savedLogin, i int) ([]savedLogin, error) {
				ls[i].Lapsed = "the old sign-in expired"
				return ls, nil
			}); err != nil {
				t.Fatal(err)
			}

			// A new token bundle replaces the refused sign-in, so the account
			// can be used at once rather than after a later refresh.
			if done := kimiSignIn(t, agent, 15*time.Second); done.State != "done" {
				t.Fatal(done)
			}
			ls := Logins(agent)
			if len(ls) != 1 || ls[0].Lapsed != "" {
				t.Fatalf("the new sign-in kept the old lapse: %+v", ls)
			}
			p, found := find(All(), agent)
			if !found {
				t.Fatal("the account is not back among the providers")
			}
			req := httptest.NewRequest(http.MethodPost, p.Chat+"/chat/completions", nil)
			if err := p.Sign(context.Background(), req, Chat, nil); err != nil {
				t.Fatalf("the new sign-in can't sign a request: %v", err)
			}
		})
	}
}

func TestKimiCodeRefreshOtherFailureKeepsSignIn(t *testing.T) {
	signIn(t)
	f := kimiAt(t, KimiCodePlanID)
	f.token = func(_ url.Values, poll, _ int) (int, any) {
		if poll == 1 {
			return 200, map[string]any{"error": "authorization_pending"}
		}
		return f.tokens("user-42", "rt-1", 900)
	}
	if done := kimiSignIn(t, KimiCodePlanID, 15*time.Second); done.State != "done" {
		t.Fatal(done)
	}
	if err := editSideLogin(KimiCodePlanID, "user-42", func(ls []savedLogin, i int) ([]savedLogin, error) {
		a, _ := kimiCodeSaved(ls[i])
		a.Expires = time.Now().Add(-time.Minute).Unix()
		ls[i].Auth, _ = json.Marshal(a)
		return ls, nil
	}); err != nil {
		t.Fatal(err)
	}
	// Keep the refresh token valid so the fake reaches the failure under
	// test instead of falling back to its default invalid_grant answer.
	f.once.Store("rt-1", true)
	for _, tc := range []struct {
		name   string
		status int
		body   any
	}{
		{"HTML 400", 400, []byte("upstream bad request")},
		{"transient OAuth error", 400, map[string]any{"error": "server_error", "error_description": "try again later"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The fake consumes a valid refresh token once; each case needs its own.
			f.once.Store("rt-1", true)
			f.token = func(_ url.Values, _, _ int) (int, any) { return tc.status, tc.body }
			_, err := kimiCodeToken(context.Background(), KimiCodePlanID, "user-42")
			if err == nil {
				t.Fatal("the failed refresh returned no error")
			}
			if strings.Contains(err.Error(), "sign in again") {
				t.Fatalf("a refresh error without a credential refusal was taken as a lapse: %v", err)
			}
			if got := Logins(KimiCodePlanID)[0].Lapsed; got != "" {
				t.Fatalf("a refresh error without a credential refusal marked a lapse: %q", got)
			}
		})
	}
}
