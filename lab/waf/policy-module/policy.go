// Package policy implements an intentionally small, local-only Caddy handler
// used to buffer requests before Coraza and apply local behavior rules.
package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/mileusna/useragent"
	"github.com/oschwald/geoip2-golang"
	"golang.org/x/time/rate"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("lab_policy", parseCaddyfile)
}

// Handler is the pre-Coraza policy stage. Runtime policy JSON is reread for
// each request so portal changes take effect without editing source config.
type Handler struct {
	PolicyFile  string `json:"policy_file,omitempty"`
	mu          sync.Mutex
	counters    map[string]counter
	lastDoc     map[string]int
	botWindows  map[string]botWindow
	botLimiters map[string]botLimiter
	geoDB       *geoip2.Reader
}

type counter struct {
	started time.Time
	count   int
}

type botWindow struct {
	started time.Time
	paths   map[string]struct{}
}

type botLimiter struct {
	limiter       *rate.Limiter
	lastSeen      time.Time
	requests      int
	windowSeconds int
}

type policy struct {
	Enabled     bool   `json:"enabled"`
	Mode        string `json:"mode"`
	BlockingPL  int    `json:"blocking_pl"`
	DetectionPL int    `json:"detection_pl"`
	CVERules    struct {
		CVE64642 bool `json:"CVE-2026-64642"`
		CVE64645 bool `json:"CVE-2026-64645"`
	} `json:"cve_rules"`
	CRSExclusions struct {
		SQLiSearch bool `json:"sqli_search"`
	} `json:"crs_exclusions"`
	RateLimit struct {
		Enabled            bool `json:"enabled"`
		Requests           int  `json:"requests"`
		WindowSeconds      int  `json:"window_seconds"`
		RangeRequests      int  `json:"range_requests"`
		RangeWindowSeconds int  `json:"range_window_seconds"`
		PrefixV4           int  `json:"prefix_v4"`
		PrefixV6           int  `json:"prefix_v6"`
		RangePrefixV4      int  `json:"range_prefix_v4"`
		RangePrefixV6      int  `json:"range_prefix_v6"`
	} `json:"rate_limit"`
	Geo struct {
		Enabled  bool              `json:"enabled"`
		Deny     []string          `json:"deny"`
		Allow    []string          `json:"allow"`
		Fixtures map[string]string `json:"fixtures"`
	} `json:"geo"`
	BotDetection struct {
		Enabled           bool   `json:"enabled"`
		UniquePaths       int    `json:"unique_paths"`
		WindowSeconds     int    `json:"window_seconds"`
		Action            string `json:"action"`
		SpamRequests      int    `json:"spam_requests"`
		SpamWindowSeconds int    `json:"spam_window_seconds"`
	} `json:"bot_detection"`
	Behavior struct {
		LoginFailures  behaviorRule `json:"login_failures"`
		NotFoundBurst  behaviorRule `json:"not_found_burst"`
		SequentialDocs behaviorRule `json:"sequential_documents"`
	} `json:"behavior"`
}

type behaviorRule struct {
	Enabled       bool   `json:"enabled"`
	Limit         int    `json:"limit"`
	WindowSeconds int    `json:"window_seconds"`
	Action        string `json:"action"`
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.lab_policy", New: func() caddy.Module { return new(Handler) }}
}

func (h *Handler) Provision(caddy.Context) error {
	if h.PolicyFile == "" {
		return fmt.Errorf("lab_policy requires a policy file")
	}
	h.counters = make(map[string]counter)
	h.lastDoc = make(map[string]int)
	h.botWindows = make(map[string]botWindow)
	h.botLimiters = make(map[string]botLimiter)
	geoDBPath := os.Getenv("GEOIP_DB_PATH")
	if geoDBPath != "" {
		if _, err := os.Stat(geoDBPath); err == nil {
			db, err := geoip2.Open(geoDBPath)
			if err != nil {
				return fmt.Errorf("open GeoIP database: %w", err)
			}
			h.geoDB = db
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat GeoIP database: %w", err)
		}
	}
	return nil
}

func (h *Handler) Cleanup() error {
	if h.geoDB != nil {
		return h.geoDB.Close()
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	requestID := r.Header.Get("X-Request-ID")
	remoteIP := firstIP(r.RemoteAddr)
	clientIP := remoteIP
	// Only the fixed HAProxy address on the lab frontend is allowed to provide
	// the forwarded client address. Direct callers cannot spoof country/rate IPs.
	if remoteIP == "172.30.0.2" {
		if forwarded := firstIP(r.Header.Get("X-Forwarded-For")); forwarded != "" {
			clientIP = forwarded
		}
	}
	var p policy
	if raw, err := os.ReadFile(h.PolicyFile); err == nil {
		_ = json.Unmarshal(raw, &p)
	}
	mode := "On"
	// Control headers are reserved for this handler. A client-provided exclusion
	// must never reach Coraza when the corresponding portal switch is disabled.
	for _, header := range []string{
		"X-Lab-Mode", "X-Lab-Blocking-PL", "X-Lab-Detection-PL",
		"X-Lab-CVE-64642", "X-Lab-CVE-64645", "X-Lab-Exclude-SQLi-942100",
		"X-Lab-Client-IP", "X-Lab-Country", "X-Lab-Geo-Source",
	} {
		r.Header.Del(header)
	}
	// Coraza's IP rules consume this value. Never accept one supplied by a client.
	r.Header.Set("X-Lab-Client-IP", clientIP)
	country, geoSource := h.country(clientIP, p.Geo.Fixtures)
	r.Header.Set("X-Lab-Country", country)
	r.Header.Set("X-Lab-Geo-Source", geoSource)
	if strings.EqualFold(p.Mode, "DetectionOnly") || strings.EqualFold(p.Mode, "detect") || strings.EqualFold(p.Mode, "observe") {
		mode = "DetectionOnly"
	}
	r.Header.Set("X-Lab-Mode", mode)
	blockingPL := p.BlockingPL
	if blockingPL < 1 || blockingPL > 4 {
		blockingPL = 1
	}
	detectionPL := p.DetectionPL
	if detectionPL < 1 || detectionPL > 4 {
		detectionPL = 2
	}
	r.Header.Set("X-Lab-Blocking-PL", fmt.Sprint(blockingPL))
	r.Header.Set("X-Lab-Detection-PL", fmt.Sprint(detectionPL))
	if p.Enabled {
		if p.CVERules.CVE64642 {
			r.Header.Set("X-Lab-CVE-64642", "on")
		}
		if p.CVERules.CVE64645 {
			r.Header.Set("X-Lab-CVE-64645", "on")
		}
		if p.CRSExclusions.SQLiSearch && r.URL.Path == "/api/lab/search" {
			r.Header.Set("X-Lab-Exclude-SQLi-942100", "on")
		}
	}
	if r.Body != nil && r.Body != http.NoBody {
		body, err := io.ReadAll(io.LimitReader(r.Body, (10<<20)+1))
		if err != nil {
			return err
		}
		if len(body) > 10<<20 {
			http.Error(w, "request body exceeds lab limit", http.StatusRequestEntityTooLarge)
			return nil
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	if !p.Enabled {
		return next.ServeHTTP(w, r)
	}
	if p.Geo.Enabled {
		blocked := contains(p.Geo.Deny, country) || (len(p.Geo.Allow) > 0 && !contains(p.Geo.Allow, country))
		if blocked {
			return h.decide(w, r, next, mode, http.StatusForbidden, requestID, clientIP, "geo_policy", "country denied: "+country+" ("+geoSource+")")
		}
	}
	if p.BotDetection.Enabled && p.BotDetection.UniquePaths >= 3 {
		limit := min(p.BotDetection.UniquePaths, 100)
		window := time.Duration(max(1, min(p.BotDetection.WindowSeconds, 3600))) * time.Second
		ua := useragent.Parse(r.UserAgent())
		if ua.Bot && p.BotDetection.SpamRequests > 0 {
			requests := min(p.BotDetection.SpamRequests, 10000)
			seconds := max(1, min(p.BotDetection.SpamWindowSeconds, 3600))
			allowed, tokens := h.allowBotRequest(clientIP, requests, seconds)
			if !allowed {
				return h.decideWithEvidence(w, r, next, actionMode(mode, p.BotDetection.Action), http.StatusTooManyRequests, requestID, clientIP, "bot_request_rate", fmt.Sprintf("declared bot=%q; token bucket=%d requests/%ds", ua.Name, requests, seconds), map[string]any{
					"counter_type": "token_bucket", "bucket_capacity": requests, "window_seconds": seconds, "tokens_remaining": tokens, "threshold_reached": true, "configured_action": p.BotDetection.Action,
				})
			}
		}
		if paths := h.botPaths(clientIP, r.URL.Path, window); paths >= limit {
			// A UA is a self-declared signal, never proof of crawler identity.
			// Block only when both the OSS classifier and path fanout agree.
			if ua.Bot {
				return h.decideWithEvidence(w, r, next, actionMode(mode, p.BotDetection.Action), http.StatusForbidden, requestID, clientIP, "bot_declared_fanout", fmt.Sprintf("declared bot=%q; distinct paths=%d within %s", ua.Name, paths, window), map[string]any{
					"counter_type": "distinct_paths", "count": paths, "limit": limit, "window_seconds": int(window.Seconds()), "threshold_reached": true, "configured_action": p.BotDetection.Action,
				})
			}
			if paths == limit {
				h.eventWithEvidence("behavior", requestID, clientIP, "bot_path_fanout", "observe", fmt.Sprintf("distinct paths=%d within %s; UA not classified as bot", paths, window), requestEvidence(r, mode, "observe", 0, map[string]any{
					"counter_type": "distinct_paths", "count": paths, "limit": limit, "window_seconds": int(window.Seconds()), "threshold_reached": true, "configured_action": "observe",
				}))
			}
		}
	}

	if p.RateLimit.Enabled && p.RateLimit.Requests > 0 {
		window := time.Duration(max(p.RateLimit.WindowSeconds, 1)) * time.Second
		prefix := p.RateLimit.PrefixV4
		if strings.Contains(clientIP, ":") {
			prefix = p.RateLimit.PrefixV6
		}
		key := "rate:" + networkKey(clientIP, prefix)
		count := h.bump(key, window)
		if count > p.RateLimit.Requests {
			return h.decideWithEvidence(w, r, next, mode, http.StatusTooManyRequests, requestID, clientIP, "rate_limit", "per-IP request count exceeded configured window", map[string]any{
				"counter_type": "requests_per_ip", "count": count, "limit": p.RateLimit.Requests, "window_seconds": int(window.Seconds()), "threshold_reached": true, "configured_action": "block",
			})
		}
		if p.RateLimit.RangeRequests > 0 {
			rangeWindow := time.Duration(max(p.RateLimit.RangeWindowSeconds, 1)) * time.Second
			rangePrefix := p.RateLimit.RangePrefixV4
			if strings.Contains(clientIP, ":") {
				rangePrefix = p.RateLimit.RangePrefixV6
			}
			rangeCount := h.bump("range:"+networkKey(clientIP, rangePrefix), rangeWindow)
			if rangeCount > p.RateLimit.RangeRequests {
				return h.decideWithEvidence(w, r, next, mode, http.StatusTooManyRequests, requestID, clientIP, "cidr_rate_limit", "CIDR request count exceeded configured window", map[string]any{
					"counter_type": "requests_per_cidr", "count": rangeCount, "limit": p.RateLimit.RangeRequests, "window_seconds": int(rangeWindow.Seconds()), "prefix": rangePrefix, "threshold_reached": true, "configured_action": "block",
				})
			}
		}
	}
	if p.Behavior.LoginFailures.Enabled && h.count("login:"+clientIP, time.Duration(max(p.Behavior.LoginFailures.WindowSeconds, 1))*time.Second) >= p.Behavior.LoginFailures.Limit && strings.HasPrefix(r.URL.Path, "/api/lab/login") {
		return h.decideWithEvidence(w, r, next, actionMode(mode, p.Behavior.LoginFailures.Action), http.StatusTooManyRequests, requestID, clientIP, "login_failures", "failed-login behavior threshold reached", map[string]any{
			"counter_type": "failed_logins", "count": h.count("login:"+clientIP, time.Duration(max(p.Behavior.LoginFailures.WindowSeconds, 1))*time.Second), "limit": p.Behavior.LoginFailures.Limit, "window_seconds": p.Behavior.LoginFailures.WindowSeconds, "threshold_reached": true, "configured_action": p.Behavior.LoginFailures.Action,
		})
	}
	if p.Behavior.NotFoundBurst.Enabled && h.count("404:"+clientIP, time.Duration(max(p.Behavior.NotFoundBurst.WindowSeconds, 1))*time.Second) >= p.Behavior.NotFoundBurst.Limit {
		return h.decideWithEvidence(w, r, next, actionMode(mode, p.Behavior.NotFoundBurst.Action), http.StatusForbidden, requestID, clientIP, "not_found_burst", "scanner behavior threshold reached", map[string]any{
			"counter_type": "responses_404", "count": h.count("404:"+clientIP, time.Duration(max(p.Behavior.NotFoundBurst.WindowSeconds, 1))*time.Second), "limit": p.Behavior.NotFoundBurst.Limit, "window_seconds": p.Behavior.NotFoundBurst.WindowSeconds, "threshold_reached": true, "configured_action": p.Behavior.NotFoundBurst.Action,
		})
	}

	path := r.URL.Path
	if strings.HasPrefix(path, "/api/lab/login") && p.Behavior.LoginFailures.Enabled {
		observed := &statusWriter{ResponseWriter: w}
		if err := next.ServeHTTP(observed, r); err != nil {
			return err
		}
		if observed.status == http.StatusUnauthorized {
			count := h.bump("login:"+clientIP, time.Duration(max(p.Behavior.LoginFailures.WindowSeconds, 1))*time.Second)
			if count == p.Behavior.LoginFailures.Limit {
				h.eventWithEvidence("behavior", requestID, clientIP, "login_failures", p.Behavior.LoginFailures.Action, fmt.Sprintf("failed logins=%d", count), requestEvidence(r, mode, p.Behavior.LoginFailures.Action, observed.status, map[string]any{
					"counter_type": "failed_logins", "count": count, "limit": p.Behavior.LoginFailures.Limit, "window_seconds": p.Behavior.LoginFailures.WindowSeconds, "threshold_reached": true, "configured_action": p.Behavior.LoginFailures.Action,
				}))
			}
		}
		return nil
	}

	if docID, ok := documentID(path); ok && p.Behavior.SequentialDocs.Enabled {
		h.mu.Lock()
		previous := h.lastDoc[clientIP]
		h.lastDoc[clientIP] = docID
		h.mu.Unlock()
		if previous > 0 && docID == previous+1 {
			count := h.bump("docs:"+clientIP, time.Duration(max(p.Behavior.SequentialDocs.WindowSeconds, 1))*time.Second)
			if count >= p.Behavior.SequentialDocs.Limit {
				return h.decideWithEvidence(w, r, next, actionMode(mode, p.Behavior.SequentialDocs.Action), http.StatusForbidden, requestID, clientIP, "sequential_documents", "sequential document access pattern", map[string]any{
					"counter_type": "sequential_document_ids", "count": count, "limit": p.Behavior.SequentialDocs.Limit, "window_seconds": p.Behavior.SequentialDocs.WindowSeconds, "threshold_reached": count >= p.Behavior.SequentialDocs.Limit, "configured_action": p.Behavior.SequentialDocs.Action,
				})
			}
		}
	}

	observed := &statusWriter{ResponseWriter: w}
	if err := next.ServeHTTP(observed, r); err != nil {
		return err
	}
	if observed.status == http.StatusNotFound && p.Behavior.NotFoundBurst.Enabled {
		count := h.bump("404:"+clientIP, time.Duration(max(p.Behavior.NotFoundBurst.WindowSeconds, 1))*time.Second)
		if count == p.Behavior.NotFoundBurst.Limit {
			h.eventWithEvidence("behavior", requestID, clientIP, "not_found_burst", p.Behavior.NotFoundBurst.Action, fmt.Sprintf("404 responses=%d", count), requestEvidence(r, mode, p.Behavior.NotFoundBurst.Action, observed.status, map[string]any{
				"counter_type": "responses_404", "count": count, "limit": p.Behavior.NotFoundBurst.Limit, "window_seconds": p.Behavior.NotFoundBurst.WindowSeconds, "threshold_reached": true, "configured_action": p.Behavior.NotFoundBurst.Action,
			}))
		}
	}
	return nil
}

// allowBotRequest limits repeated requests to the same or different paths.
// Each client IP has one token bucket; stale buckets are evicted on admission.
func (h *Handler) allowBotRequest(ip string, requests, seconds int) (bool, float64) {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	state, ok := h.botLimiters[ip]
	if !ok || state.requests != requests || state.windowSeconds != seconds {
		if len(h.botLimiters) >= 4096 {
			for key, value := range h.botLimiters {
				if now.Sub(value.lastSeen) > time.Hour {
					delete(h.botLimiters, key)
				}
			}
			if len(h.botLimiters) >= 4096 {
				return false, 0
			}
		}
		state = botLimiter{limiter: rate.NewLimiter(rate.Limit(float64(requests)/float64(seconds)), requests), requests: requests, windowSeconds: seconds}
	}
	state.lastSeen = now
	h.botLimiters[ip] = state
	allowed := state.limiter.Allow()
	return allowed, state.limiter.Tokens()
}

func (h *Handler) decide(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, mode string, status int, id, ip, rule, reason string) error {
	return h.decideWithEvidence(w, r, next, mode, status, id, ip, rule, reason, nil)
}

func (h *Handler) decideWithEvidence(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, mode string, status int, id, ip, rule, reason string, evidence map[string]any) error {
	if strings.EqualFold(mode, "DetectionOnly") || strings.EqualFold(mode, "detect") || strings.EqualFold(mode, "observe") {
		h.eventWithEvidence("behavior", id, ip, rule, "observe", reason, requestEvidence(r, mode, "observe", 0, evidence))
		w.Header().Set("X-WAF-Lab-Rule", rule)
		w.Header().Set("X-WAF-Lab-Decision", "observe")
		return next.ServeHTTP(w, r)
	}
	h.eventWithEvidence("blocked", id, ip, rule, "block", reason, requestEvidence(r, mode, "block", status, evidence))
	w.Header().Set("X-WAF-Lab-Rule", rule)
	w.Header().Set("X-WAF-Lab-Decision", "block")
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "10")
	}
	http.Error(w, http.StatusText(status), status)
	return nil
}

func actionMode(mode, action string) string {
	if strings.EqualFold(mode, "DetectionOnly") || strings.EqualFold(action, "observe") {
		return "DetectionOnly"
	}
	return "On"
}

func requestEvidence(r *http.Request, mode, action string, status int, evidence map[string]any) map[string]any {
	policy := map[string]any{
		"action":     action,
		"mode":       mode,
		"path":       r.URL.Path,
		"method":     r.Method,
		"user_agent": r.UserAgent(),
	}
	if r.Host != "" {
		policy["host"] = r.Host
	}
	if status > 0 {
		policy["response_status"] = status
	}
	for key, value := range evidence {
		policy[key] = value
	}
	return policy
}

// botPaths counts distinct paths, not query strings. The state is bounded and
// local to this WAF process; it is a lab heuristic, not a bot identity system.
func (h *Handler) botPaths(ip, path string, window time.Duration) int {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.botWindows) >= 4096 {
		for key, state := range h.botWindows {
			if now.Sub(state.started) >= window {
				delete(h.botWindows, key)
			}
		}
		if len(h.botWindows) >= 4096 {
			delete(h.botWindows, ip)
			return 0
		}
	}
	state := h.botWindows[ip]
	if state.started.IsZero() || now.Sub(state.started) >= window {
		state = botWindow{started: now, paths: make(map[string]struct{})}
	}
	if len(state.paths) < 100 {
		state.paths[path] = struct{}{}
	}
	h.botWindows[ip] = state
	return len(state.paths)
}

func (h *Handler) bump(key string, window time.Duration) int {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.counters[key]
	if c.started.IsZero() || now.Sub(c.started) > window {
		c = counter{started: now}
	}
	c.count++
	h.counters[key] = c
	return c.count
}

func (h *Handler) count(key string, window time.Duration) int {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.counters[key]
	if c.started.IsZero() || now.Sub(c.started) > window {
		delete(h.counters, key)
		return 0
	}
	return c.count
}

func (h *Handler) event(kind, id, ip, rule, action, reason string) {
	h.eventWithEvidence(kind, id, ip, rule, action, reason, nil)
}

func (h *Handler) eventWithEvidence(kind, id, ip, rule, action, reason string, evidence map[string]any) {
	entry := map[string]any{"@timestamp": time.Now().UTC().Format(time.RFC3339Nano), "event": map[string]any{"kind": kind, "action": action, "dataset": "waf.behavior"}, "http": map[string]any{"request": map[string]any{"id": id}}, "source": map[string]any{"ip": ip}, "rule": map[string]any{"id": rule}, "message": reason}
	if evidence != nil {
		policyEvidence := make(map[string]any, len(evidence)+3)
		for key, value := range evidence {
			policyEvidence[key] = value
		}
		if _, exists := policyEvidence["configured_action"]; !exists {
			policyEvidence["configured_action"] = action
		}
		effectiveAction := "none"
		if kind == "blocked" {
			effectiveAction = "block"
		} else if action == "observe" {
			effectiveAction = "observe"
		}
		policyEvidence["effective_action"] = effectiveAction
		policyEvidence["actual_block"] = kind == "blocked"
		if kind == "blocked" {
			policyEvidence["decision_result"] = "blocked"
		} else if action == "observe" {
			policyEvidence["decision_result"] = "threshold_observed"
		} else {
			policyEvidence["decision_result"] = "threshold_reached"
		}
		entry["waf"] = map[string]any{"policy": policyEvidence}
		if status, ok := evidence["response_status"].(int); ok {
			entry["http"].(map[string]any)["response"] = map[string]any{"status_code": status}
		}
		if path, ok := evidence["path"].(string); ok {
			entry["url"] = map[string]any{"path": path}
		}
		if method, ok := evidence["method"].(string); ok {
			entry["http"].(map[string]any)["request"].(map[string]any)["method"] = method
		}
	}
	raw, _ := json.Marshal(entry)
	file, err := os.OpenFile("/var/log/lab/waf-policy.jsonl", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err == nil {
		_, _ = file.Write(append(raw, '\n'))
		_ = file.Close()
	}
}

func firstIP(s string) string {
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	if host, _, err := net.SplitHostPort(strings.TrimSpace(s)); err == nil {
		return host
	}
	return strings.TrimSpace(s)
}

func networkKey(ip string, prefix int) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip
	}
	bits := 32
	if parsed.To4() == nil {
		bits = 128
	}
	if prefix < 0 || prefix > bits {
		prefix = bits
	}
	mask := net.CIDRMask(prefix, bits)
	return (&net.IPNet{IP: parsed.Mask(mask), Mask: mask}).String()
}

func fixtureCountry(ip string, fixtures map[string]string) string {
	for fixture, country := range fixtures {
		if ip == fixture {
			return country
		}
		if _, block, err := net.ParseCIDR(fixture); err == nil && block.Contains(net.ParseIP(ip)) {
			return country
		}
	}
	return "ZZ"
}

func (h *Handler) country(ip string, fixtures map[string]string) (string, string) {
	if country := fixtureCountry(ip, fixtures); country != "ZZ" {
		country = strings.ToUpper(country)
		if len(country) == 2 && country[0] >= 'A' && country[0] <= 'Z' && country[1] >= 'A' && country[1] <= 'Z' {
			return country, "fixture"
		}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || h.geoDB == nil {
		return "ZZ", "unknown"
	}
	record, err := h.geoDB.Country(parsed)
	if err != nil || record == nil || record.Country.IsoCode == "" {
		return "ZZ", "unknown"
	}
	return record.Country.IsoCode, "mmdb"
}

func contains(values []string, item string) bool {
	for _, value := range values {
		if strings.EqualFold(value, item) {
			return true
		}
	}
	return false
}

func documentID(path string) (int, bool) {
	const prefix = "/api/lab/documents/"
	if !strings.HasPrefix(path, prefix) {
		return 0, false
	}
	var id int
	_, err := fmt.Sscanf(strings.TrimPrefix(path, prefix), "%d", &id)
	return id, err == nil
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }
func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Handler
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &m, nil
}

func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if !d.NextArg() {
		return d.ArgErr()
	}
	h.PolicyFile = d.Val()
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

var _ caddy.Provisioner = (*Handler)(nil)
var _ caddyhttp.MiddlewareHandler = (*Handler)(nil)
var _ caddyfile.Unmarshaler = (*Handler)(nil)
