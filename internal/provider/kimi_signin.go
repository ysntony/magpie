package provider

// Signing in to a Kimi Code membership from magpie: Kimi's OAuth device
// flow (RFC 8628) with the public OAuth client the Kimi Code CLI ships —
// there is no third-party registration, every integration signs in with
// that one. magpie shows the code, the user confirms it at Kimi's page,
// and the tokens are kept for magpie alone in logins.json, beside the
// keyed presets (kimi-code, kimi-code-cn), which are untouched. The access
// token signs requests to the region's API base as a Bearer; it lives
// about 15 minutes and is refreshed with the refresh token, which rotates
// on every refresh — an old one works exactly once — so the refresh is
// serialized (savedTokenMu) and the rotated bundle goes back with
// logins.json's atomic write.
//
// Kimi has two sites, a subscription of its own each: the global one
// (kimi.ai) and the China one (kimi.com), whose accounts exist only there.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/appdir"
	"github.com/yetone/magpie/internal/catalog"
	"github.com/yetone/magpie/internal/netproxy"
)

// KimiCodePlanID is the Kimi Code subscription's id on the global site,
// and KimiCodePlanCNID the China site's, as providers and in logins.json.
const (
	KimiCodePlanID   = "kimi-code-plan"
	KimiCodePlanCNID = "kimi-code-plan-cn"
)

// kimiCodeClientID is the public OAuth client the Kimi Code CLI ships.
const kimiCodeClientID = "17e5f671-d194-4dfb-9706-5516cb48c098"

// kimiCodePollMisses is how many polls of Kimi's token endpoint in a row
// may fail (no answer, an error status, a body that isn't JSON) before the
// sign-in fails with the last one's error, rather than wait out
// signInTimeout saying nothing (as copilotPollMisses is for GitHub's).
var kimiCodePollMisses = 5

// kimiCodeFinishWait bounds the plan read that follows Kimi's token: the
// account is known from the token itself, so a plan that never comes fails
// nothing, but a held answer (a proxy before Kimi) isn't waited on either.
var kimiCodeFinishWait = time.Minute

// Version is magpie's, set by cli.Main as gateway.Version is: Kimi's
// identity headers carry it.
var Version = "dev"

// kimiCodeRegions are Kimi's two sites. Vars so tests can point them
// elsewhere (KimiCodeRegionForTest), under kimiCodeRegionsMu: the
// package's tests run beside one another.
var (
	kimiCodeRegionsMu sync.RWMutex
	kimiCodeRegions   = map[string]*kimiCodeRegion{
		KimiCodePlanID: {
			id: KimiCodePlanID, name: "Kimi Code",
			auth: "https://auth.kimi.ai", api: "https://api.kimi.ai/coding/v1", anth: "https://api.kimi.ai/coding",
			site: "https://www.kimi.ai", catalog: "kimi-code-plan-global",
		},
		KimiCodePlanCNID: {
			id: KimiCodePlanCNID, name: "Kimi Code CN",
			auth: "https://auth.kimi.com", api: "https://api.kimi.com/coding/v1", anth: "https://api.kimi.com/coding",
			site: "https://www.kimi.com", catalog: "kimi-code-plan-cn",
		},
	}
)

// kimiCodeRegion is one of Kimi's two sites.
type kimiCodeRegion struct {
	id      string // the subscription's agent and provider id
	name    string
	auth    string // the OAuth host
	api     string // the OpenAI base, /coding/v1
	anth    string // the Anthropic base, /coding
	site    string
	catalog string // the membership's models.dev catalog
}

var kimiCodeAgents = []string{KimiCodePlanID, KimiCodePlanCNID}

func kimiCodeRegionOf(agent string) *kimiCodeRegion {
	kimiCodeRegionsMu.RLock()
	defer kimiCodeRegionsMu.RUnlock()
	return kimiCodeRegions[agent]
}

// KimiCodeRegionForTest points a site's OAuth host and API base at a test
// server, for the CLI's tests; the func it returns puts them back.
func KimiCodeRegionForTest(agent, auth, api string) func() {
	kimiCodeRegionsMu.Lock()
	old := kimiCodeRegions[agent]
	kimiCodeRegions[agent] = &kimiCodeRegion{id: old.id, name: old.name, site: old.site, catalog: old.catalog,
		auth: auth, api: api, anth: strings.TrimSuffix(api, "/v1")}
	kimiCodeRegionsMu.Unlock()
	return func() {
		kimiCodeRegionsMu.Lock()
		defer kimiCodeRegionsMu.Unlock()
		kimiCodeRegions[agent] = old
	}
}

// kimiIdentityHeaders are magpie's own identity, set on every call to
// Kimi's OAuth and usage endpoints and on requests an account's token
// signs: never the CLI's (kimi_code_cli), which these endpoints know.
func kimiIdentityHeaders(req *http.Request, deviceID string) {
	req.Header.Set("User-Agent", "magpie/"+Version)
	req.Header.Set("X-Msh-Platform", "magpie")
	req.Header.Set("X-Msh-Version", Version)
	req.Header.Set("X-Msh-Device-Name", "magpie")
	req.Header.Set("X-Msh-Device-Model", "magpie")
	req.Header.Set("X-Msh-Os-Version", "any")
	req.Header.Set("X-Msh-Device-Id", deviceID)
}

// kimiCodeDeviceID is this machine's id for Kimi, made once and kept in
// magpie's own config: the OAuth calls and the requests they sign carry
// it, and the tokens are issued to it.
func kimiCodeDeviceID() (string, error) {
	kimiDevice.Lock()
	defer kimiDevice.Unlock()
	dir := appdir.Config()
	if kimiDevice.id != "" && kimiDevice.dir == dir {
		return kimiDevice.id, nil
	}
	path := filepath.Join(dir, "kimi-code-device")
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			kimiDevice.dir, kimiDevice.id = dir, id
			return id, nil
		}
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80 // a version 4 UUID
	h := hex.EncodeToString(b)
	id := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	kimiDevice.dir, kimiDevice.id = dir, id
	return id, nil
}

var kimiDevice struct {
	sync.Mutex
	dir, id string
}

// kimiCodeClient is the client every call to Kimi's OAuth and usage
// endpoints goes through, on a transport of its own — whatever the process
// has done to http.DefaultClient — so they honor the proxy the caller's
// context names (netproxy.With): a sign-in's own (signInFlow.via, #1663),
// an account's, else the global one, as every side login's client is
// (zcodeStartClient).
var kimiCodeClient = &http.Client{Transport: netproxy.Dispatch(kimiCodeTransport)}

// kimiCodeTransport is kimiCodeClient's base: the proxy in force for the
// request (netproxy), and a bound on waiting for the answer's head, as the
// sign-in's plan read has (kimiCodeFinishWait).
var kimiCodeTransport = &http.Transport{
	Proxy:                 netproxy.Func,
	ResponseHeaderTimeout: time.Minute,
	MaxIdleConnsPerHost:   8,
	IdleConnTimeout:       90 * time.Second,
	ForceAttemptHTTP2:     true,
}

// kimiForm posts a form to one of Kimi's OAuth endpoints and reads the
// answer. OAuth's error answers are JSON too (RFC 8628's 400s), so v is
// filled from the body whenever it parses; a non-200 is handed back with
// the error so the caller can tell a refused grant from a hiccup.
func kimiForm(ctx context.Context, u string, form url.Values, v any) (int, error) {
	id, err := kimiCodeDeviceID()
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	kimiIdentityHeaders(req, id)
	res, err := kimiCodeClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	_ = json.Unmarshal(b, v)
	if res.StatusCode != 200 {
		return res.StatusCode, errors.New("Kimi: " + APIError(b, res.Status))
	}
	return res.StatusCode, nil
}

// kimiCodeTokenReply is what Kimi's token endpoint answers, the device
// grant's and a refresh's alike.
type kimiCodeTokenReply struct {
	Access   string `json:"access_token"`
	Refresh  string `json:"refresh_token"`
	Expires  int    `json:"expires_in"`
	Interval int    `json:"interval"`
	Error    string `json:"error"`
	Desc     string `json:"error_description"`
}

// startKimiCodeSignIn signs in on the region's site: Kimi's device
// authorization, the code shown for the user to confirm at the page, then
// the token polled for.
func startKimiCodeSignIn(s *signInFlow, region *kimiCodeRegion) error {
	ctx, cancel := context.WithCancel(s.via(context.Background()))
	var dc struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		URI        string `json:"verification_uri_complete"`
		Interval   int    `json:"interval"`
	}
	if _, err := kimiForm(ctx, region.auth+"/api/oauth/device_authorization", url.Values{"client_id": {kimiCodeClientID}}, &dc); err != nil {
		cancel()
		return err
	}
	if dc.DeviceCode == "" || dc.UserCode == "" || dc.URI == "" {
		cancel()
		return errors.New("Kimi gave no device code")
	}
	s.st.URL, s.st.Code = dc.URI, dc.UserCode
	s.stop = cancel
	interval := time.Duration(max(dc.Interval, 1)) * time.Second
	go func() {
		fail := func(msg string) {
			log.Printf("%s sign-in failed: %s", region.name, msg)
			s.finish(SignInState{State: "failed", Error: msg})
		}
		misses := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
			}
			var tok kimiCodeTokenReply
			_, err := kimiForm(ctx, region.auth+"/api/oauth/token", url.Values{"client_id": {kimiCodeClientID}, "device_code": {dc.DeviceCode},
				"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}}, &tok)
			switch {
			case ctx.Err() != nil:
				return
			case err != nil && tok.Error == "":
				// a hiccup: ask again, unless it keeps failing
				misses++
				log.Printf("%s sign-in: asking Kimi for the token failed (%d in a row): %v", region.name, misses, err)
				if misses >= kimiCodePollMisses {
					fail("couldn't get the token from Kimi: " + err.Error())
					return
				}
				continue
			}
			misses = 0
			switch tok.Error {
			case "":
			case "authorization_pending":
				continue
			case "slow_down":
				// a rate hint, not a failure: poll less often
				if tok.Interval > 0 {
					interval = time.Duration(tok.Interval) * time.Second
				} else {
					interval += 5 * time.Second
				}
				continue
			case "expired_token":
				fail("the code expired; start again")
				return
			case "access_denied":
				fail("the sign-in was declined on Kimi's page")
				return
			default:
				fail("Kimi: " + strings.TrimSpace(firstNonEmpty(tok.Desc, tok.Error)))
				return
			}
			if tok.Access == "" || tok.Refresh == "" || tok.Expires <= 0 {
				fail("Kimi sent back no token")
				return
			}
			user := kimiCodeUser(tok.Access)
			if user == "" {
				fail("Kimi didn't say which account signed in")
				return
			}
			auth, err := json.Marshal(kimiCodeAuth{Access: tok.Access, Refresh: tok.Refresh,
				Expires: time.Now().Add(time.Duration(tok.Expires) * time.Second).Unix(), ExpiresIn: tok.Expires})
			if err != nil {
				fail(err.Error())
				return
			}
			// the plan the membership is on, as the usage read names it;
			// best effort, the Usage page asks it again anyway
			fctx, fcancel := context.WithTimeout(ctx, kimiCodeFinishWait)
			plan := kimiCodePlan(fctx, region, tok.Access)
			fcancel()
			if ctx.Err() != nil {
				return
			}
			if err := addKimiCodeLogin(region, user, plan, auth); err != nil {
				fail(err.Error())
				return
			}
			using := strings.EqualFold(activeOf(kimiCodeLoginsOf(region.id)), user)
			s.finish(SignInState{State: "done", User: user, Plan: plan, Using: using})
			return
		}
	}()
	return nil
}

// kimiCodeUser names an account by the subject its access token carries:
// the token is a JWT, and its sub is the account's id.
func kimiCodeUser(access string) string {
	return claimString(jwtClaims(access), "sub")
}

// ---- the accounts -------------------------------------------------------------

// kimiCodeAuth is a Kimi Code account's sign-in as logins.json keeps it:
// the token bundle the device flow made, rotated on every refresh.
type kimiCodeAuth struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
	// Expires is when the access token stops working (Unix seconds): it
	// lives about 15 minutes.
	Expires int64 `json:"expires"`
	// ExpiresIn is the life it was issued with, in seconds: the refresh
	// threshold is half of it with a five-minute floor
	// (kimiCodeRefreshMargin). A bundle saved before it was kept reads as
	// 0 — the floor alone, as then.
	ExpiresIn int `json:"expires_in,omitempty"`
}

func kimiCodeSaved(l savedLogin) (kimiCodeAuth, bool) {
	var a kimiCodeAuth
	if json.Unmarshal(l.Auth, &a) != nil || a.Access == "" || a.Refresh == "" {
		return kimiCodeAuth{}, false
	}
	return a, true
}

// kimiCodeLoginsOf is every Kimi Code account of one site, the first in
// use first.
func kimiCodeLoginsOf(agent string) []sideLogin {
	ls := sideLogins(agent, "", func(l savedLogin) bool { _, ok := kimiCodeSaved(l); return ok })
	for i := range ls {
		ls[i].Lapsed = ls[i].saved.Lapsed // a refused refresh shows on the account
	}
	return ls
}

func kimiCodeLoginList(agent string) []Login { return loginsOf(kimiCodeLoginsOf(agent)) }

func switchKimiCodeLogin(agent, user string) error {
	return switchSideLogin(agent, user, kimiCodeLoginsOf(agent))
}

func setKimiCodeLoginOn(agent, user string, on bool) error {
	return setSideLoginOn(agent, user, on, kimiCodeLoginsOf(agent))
}

func forgetKimiCodeLogin(agent, user string) error {
	return forgetSideLogin(agent, user, kimiCodeLoginsOf(agent), nil)
}

// addKimiCodeLogin keeps an account magpie just signed in, in use beside
// the others.
func addKimiCodeLogin(region *kimiCodeRegion, user, plan string, auth json.RawMessage) error {
	return addSideLogin(savedLogin{Agent: region.id, User: user, Plan: plan, Auth: auth}, "", func(savedLogin) {})
}

// errKimiCodeReplaced is the account's bundle having been replaced while a
// refresh of it was in the air (a sign-in anew): the refresh is let go,
// never written back over the newer one.
var errKimiCodeReplaced = errors.New("the sign-in changed while it was refreshed")

// kimiCodeRefreshAttempts is how many times a refresh is asked of Kimi
// before its hiccup is told as an error: a 429, a 5xx or an unanswered ask
// is retried (the CLI retries those three times), where one failed try
// ended the account's request at once. A refusal — invalid_grant, 401,
// 403 — or a structured OAuth error is answered at once, never retried.
var kimiCodeRefreshAttempts = 3

// kimiCodeRefreshBackoff is the wait between one failed try and the next;
// a var so tests run without it.
var kimiCodeRefreshBackoff = time.Second

// kimiCodeRefreshMargin is how long before its end an access token is
// refreshed: max(300s, expires_in×50%), the CLI's threshold — a 15-minute
// token at half its life, a shorter-lived one five minutes out.
func kimiCodeRefreshMargin(expiresIn int) time.Duration {
	return time.Duration(max(300, expiresIn/2)) * time.Second
}

// kimiCodeToken is the account's access token, fresh: refreshed once it
// has less than kimiCodeRefreshMargin of its life left. The refresh token
// rotates on every refresh, so the refresh is serialized with every saved
// account's (savedTokenMu), and the rotated bundle is written back before
// it is used.
func kimiCodeToken(ctx context.Context, agent, user string) (string, error) {
	region := kimiCodeRegionOf(agent)
	savedTokenMu.Lock()
	defer savedTokenMu.Unlock()
	loginsMu.Lock()
	var l *savedLogin
	for _, x := range readLogins() {
		if x.Agent == agent && strings.EqualFold(x.User, user) {
			x := x
			l = &x
		}
	}
	loginsMu.Unlock()
	if l == nil {
		return "", fmt.Errorf("no saved %s account %q", region.name, user)
	}
	a, ok := kimiCodeSaved(*l)
	if !ok {
		return "", fmt.Errorf("%s: the saved sign-in of %s is unreadable", region.name, user)
	}
	if time.Until(time.Unix(a.Expires, 0)) > kimiCodeRefreshMargin(a.ExpiresIn) {
		return a.Access, nil
	}
	var tok kimiCodeTokenReply
	var status int
	var err error
	for attempt := 1; ; attempt++ {
		tok = kimiCodeTokenReply{}
		status, err = kimiForm(ctx, region.auth+"/api/oauth/token", url.Values{"client_id": {kimiCodeClientID},
			"refresh_token": {a.Refresh}, "grant_type": {"refresh_token"}}, &tok)
		if err != nil && ctx.Err() != nil {
			return "", fmt.Errorf("Kimi token refresh: %w", err)
		}
		// Kimi rejects a spent refresh with invalid_grant or an auth status:
		// the account is signed in again, never retried. A structured OAuth
		// error about another part of the request isn't either; it and a
		// proxy's HTML 400 leave the saved sign-in alone for a later retry.
		if tok.Error == "invalid_grant" || status == http.StatusUnauthorized || status == http.StatusForbidden {
			return "", kimiCodeLapsed(agent, user)
		}
		if tok.Error != "" {
			return "", fmt.Errorf("Kimi token refresh: %s", strings.TrimSpace(firstNonEmpty(tok.Desc, tok.Error)))
		}
		// 429, 5xx and a request that never got an answer are hiccups Kimi or
		// the path to it recovers from: asked again, up to the attempts.
		transient := status == 0 || status == http.StatusTooManyRequests || (status >= 500 && status < 600)
		if !transient || attempt >= kimiCodeRefreshAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("Kimi token refresh: %w", ctx.Err())
		case <-time.After(kimiCodeRefreshBackoff):
		}
	}
	if err != nil {
		return "", fmt.Errorf("Kimi token refresh: %w", err)
	}
	if tok.Access == "" || tok.Refresh == "" || tok.Expires <= 0 {
		return "", errors.New("Kimi sent back no token on the refresh")
	}
	fresh, err := json.Marshal(kimiCodeAuth{Access: tok.Access, Refresh: tok.Refresh,
		Expires: time.Now().Add(time.Duration(tok.Expires) * time.Second).Unix(), ExpiresIn: tok.Expires})
	if err != nil {
		return "", err
	}
	if err := editSideLogin(agent, user, func(ls []savedLogin, i int) ([]savedLogin, error) {
		if !sameAuth(ls[i].Auth, l.Auth) {
			return nil, errKimiCodeReplaced
		}
		ls[i].Auth, ls[i].Renewed, ls[i].Lapsed = fresh, time.Now().UTC(), ""
		return ls, nil
	}); err != nil {
		return "", err
	}
	return tok.Access, nil
}

// kimiCodeLapsed marks the account's sign-in gone: Kimi refused its
// refresh token, so it is signed in again.
func kimiCodeLapsed(agent, user string) error {
	msg := user + "'s " + kimiCodeRegionOf(agent).name + " sign-in has expired — sign in again"
	_ = editSideLogin(agent, user, func(ls []savedLogin, i int) ([]savedLogin, error) {
		ls[i].Lapsed = msg
		return ls, nil
	})
	return errors.New(msg)
}

// kimiCodeUsage asks the region's /usages with an OAuth access token: the
// same reading a plan's key gets (planquota.go), with the membership's
// level beside the allowance windows.
func kimiCodeUsage(ctx context.Context, region *kimiCodeRegion, access string) (plan string, ws []QuotaWindow, err error) {
	id, err := kimiCodeDeviceID()
	if err != nil {
		return "", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(region.api, "/")+"/usages", nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Accept", "application/json")
	kimiIdentityHeaders(req, id)
	res, err := kimiCodeClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != 200 {
		return "", nil, fmt.Errorf("%s", vendorSaid(b, res.Status))
	}
	if _, ws, err = readKimiCode(b); err != nil {
		return "", nil, err
	}
	return kimiCodePlanOf(b), ws, nil
}

// kimiCodePlan is the membership the token is on, as the usage read names
// it; "" when it can't be read, which fails nothing.
func kimiCodePlan(ctx context.Context, region *kimiCodeRegion, access string) string {
	plan, _, err := kimiCodeUsage(ctx, region, access)
	if err != nil {
		return ""
	}
	return plan
}

// kimiCodePlanOf is the membership level a /usages reply carries, named as
// Kimi's goods catalog names the plan.
func kimiCodePlanOf(b []byte) string {
	var r struct {
		User struct {
			Membership struct {
				Level string `json:"level"`
			} `json:"membership"`
		} `json:"user"`
	}
	if json.Unmarshal(b, &r) != nil {
		return ""
	}
	return kimiCodePlanName(r.User.Membership.Level)
}

// kimiCodePlanNames are Kimi's membership levels as its goods catalog
// names the plans; one it doesn't know is kept as it came.
var kimiCodePlanNames = map[string]string{
	"LEVEL_FREE": "Adagio", "LEVEL_TRIAL": "Andante", "LEVEL_BASIC": "Moderato",
	"LEVEL_INTERMEDIATE": "Allegretto", "LEVEL_ADVANCED": "Allegro", "LEVEL_STANDARD": "Vivace",
}

func kimiCodePlanName(level string) string {
	switch level = strings.TrimSpace(level); {
	case level == "", level == "LEVEL_UNSPECIFIED":
		return ""
	}
	if name, ok := kimiCodePlanNames[level]; ok {
		return name
	}
	return level
}

// kimiCodeLoginQuota is the account's Usage card: its windows as the
// region's /usages tells them to the access token.
func kimiCodeLoginQuota(ctx context.Context, l Login) SubscriptionQuota {
	region := kimiCodeRegionOf(l.Agent)
	q := SubscriptionQuota{Provider: l.Agent, Name: region.name, Icon: "kimi", Plan: l.Plan, User: l.User, Windows: []QuotaWindow{}}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tok, err := kimiCodeToken(ctx, l.Agent, l.User)
	if err != nil {
		q.Error = err.Error()
		return q
	}
	plan, ws, err := kimiCodeUsage(ctx, region, tok)
	if err != nil {
		q.Error = err.Error()
		return q
	}
	if plan != "" {
		q.Plan = plan
		if plan != l.Plan {
			_ = editSideLogin(l.Agent, l.User, func(ls []savedLogin, i int) ([]savedLogin, error) {
				ls[i].Plan = plan
				return ls, nil
			})
		}
	}
	q.Windows = ws
	return q
}

// kimiCodeProvider is a Kimi Code membership as one account serves it: the
// region's OpenAI and Anthropic bases, models as the membership's catalog
// lists them, requests signed with the account's access token.
func kimiCodeProvider(region *kimiCodeRegion, l sideLogin) Provider {
	user := l.User
	a := &Account{Agent: region.id, User: user, Plan: l.Plan}
	a.sign = func(ctx context.Context, req *http.Request, _ []byte) error {
		tok, err := kimiCodeToken(ctx, region.id, user)
		if err != nil {
			return err
		}
		id, err := kimiCodeDeviceID()
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		kimiIdentityHeaders(req, id)
		return nil
	}
	a.models = func() []catalog.Model { return catalog.Provider(region.catalog) }
	return Provider{ID: region.id, Name: region.name, Icon: "kimi", Chat: region.api, Anthropic: region.anth,
		Catalog: region.catalog, Website: region.site, Account: a}
}

func kimiCodeAccountOf(agent string) (Provider, bool) {
	ls := kimiCodeLoginsOf(agent)
	if len(ls) == 0 {
		return Provider{}, false
	}
	return kimiCodeProvider(kimiCodeRegionOf(agent), ls[0]), true
}

// kimiCodeAlsoOn is the accounts in use behind the first.
func kimiCodeAlsoOn(agent string) []Provider {
	var out []Provider
	for _, l := range kimiCodeLoginsOf(agent) {
		if !l.Active && l.On {
			out = append(out, kimiCodeProvider(kimiCodeRegionOf(agent), l))
		}
	}
	return out
}
