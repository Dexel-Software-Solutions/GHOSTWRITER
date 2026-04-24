// Package fingerprint implements GHOSTWRITER's core behavioral fingerprinting engine.
//
// Engineer: Demiyan Dissanayake
// Organization: Dexel Software Solutions
// Contact: dexelsoftwaresolutions@gmail.com | https://github.com/Dexel-Software-Solutions
package fingerprint

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Dexel-Software-Solutions/ghostwriter/pkg/models"
)

// Engine is the core behavioral fingerprinting processor.
type Engine struct {
	mu       sync.RWMutex
	profiles map[string]*models.AttackerProfile
	config   Config
}

// Config holds fingerprinting engine configuration.
type Config struct {
	MinRequestThreshold  int
	CorrelationThreshold float64
	Weights              SignalWeights
	EnableTLSFingerprint bool
	EnableTCPFingerprint bool
	ProfileTTL           time.Duration
}

// SignalWeights defines contribution of each behavioral signal.
type SignalWeights struct {
	TLSFingerprint   float64
	TCPStack         float64
	HTTPHeaders      float64
	TimingPattern    float64
	ScanPattern      float64
	ToolSignature    float64
	PayloadSignature float64
}

// DefaultConfig returns production-ready default configuration.
func DefaultConfig() Config {
	return Config{
		MinRequestThreshold:  3,
		CorrelationThreshold: 0.72,
		EnableTLSFingerprint: true,
		EnableTCPFingerprint: true,
		ProfileTTL:           30 * 24 * time.Hour,
		Weights: SignalWeights{
			TLSFingerprint:   0.30,
			TCPStack:         0.20,
			HTTPHeaders:      0.20,
			TimingPattern:    0.10,
			ScanPattern:      0.10,
			ToolSignature:    0.05,
			PayloadSignature: 0.05,
		},
	}
}

// NewEngine creates a new fingerprinting engine.
func NewEngine(cfg Config) *Engine {
	return &Engine{
		profiles: make(map[string]*models.AttackerProfile),
		config:   cfg,
	}
}

// IngestSession processes a session and updates or creates an attacker profile.
func (e *Engine) IngestSession(session models.Session) (*models.AttackerProfile, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	vector, err := e.extractBehaviorVector(session)
	if err != nil {
		return nil, fmt.Errorf("behavior extraction failed: %w", err)
	}

	fpHash, err := e.computeFingerprintHash(vector)
	if err != nil {
		return nil, fmt.Errorf("fingerprint computation failed: %w", err)
	}

	if matched := e.findMatchingProfile(vector, fpHash); matched != nil {
		matched.LastSeen = session.StartTime
		matched.Sessions = append(matched.Sessions, session)
		matched.ThreatScore = e.computeThreatScore(matched)
		e.refineBehaviorVector(&matched.Behavior, vector)
		return matched, nil
	}

	// Create new profile with a deterministic ID from the fingerprint hash
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(fpHash+session.StartTime.String())))[:32]

	profile := &models.AttackerProfile{
		ID:                id,
		Fingerprint:       fpHash,
		FirstSeen:         session.StartTime,
		LastSeen:          session.StartTime,
		Confidence:        0.5,
		Tags:              e.detectTags(vector),
		Behavior:          vector,
		Sessions:          []models.Session{session},
		CorrelationMethod: "behavioral_fingerprint_v1",
	}
	profile.ThreatScore = e.computeThreatScore(profile)
	e.profiles[profile.ID] = profile
	return profile, nil
}

func (e *Engine) extractBehaviorVector(session models.Session) (models.BehaviorVector, error) {
	vector := models.BehaviorVector{}

	if len(session.Requests) >= 2 {
		timings := make([]float64, 0, len(session.Requests)-1)
		for i := 1; i < len(session.Requests); i++ {
			delta := session.Requests[i].Timestamp.Sub(session.Requests[i-1].Timestamp)
			timings = append(timings, float64(delta.Milliseconds()))
		}
		vector.RequestTiming = timings
	}

	if !session.EndTime.IsZero() {
		vector.SessionDuration = session.EndTime.Sub(session.StartTime).Seconds()
	}

	hour := session.StartTime.Hour()
	vector.TimeOfDayPattern[hour]++

	if len(session.Requests) > 0 {
		vector.HTTPFingerprint = e.extractHTTPFingerprint(session.Requests)
		vector.UserAgentRotation = e.extractUserAgents(session.Requests)
	}

	vector.ScanPatterns = e.detectScanPatterns(session)
	vector.ToolBehavior = e.detectToolSignature(vector)
	return vector, nil
}

func (e *Engine) extractHTTPFingerprint(requests []models.Request) models.HTTPStack {
	stack := models.HTTPStack{HeaderValues: make(map[string]string)}
	if len(requests) == 0 {
		return stack
	}
	first := requests[0]

	keys := make([]string, 0, len(first.Headers))
	for k := range first.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	stack.HeaderOrder = keys

	for _, h := range []string{"Accept", "Accept-Encoding", "Accept-Language", "Connection", "Cache-Control"} {
		if v, ok := first.Headers[h]; ok {
			stack.HeaderValues[h] = v
		}
	}
	stack.AcceptEncoding = first.Headers["Accept-Encoding"]
	stack.AcceptLanguage = first.Headers["Accept-Language"]
	stack.ConnectionType = first.Headers["Connection"]
	return stack
}

func (e *Engine) extractUserAgents(requests []models.Request) []string {
	seen := make(map[string]struct{})
	agents := []string{}
	for _, r := range requests {
		if ua, ok := r.Headers["User-Agent"]; ok {
			if _, exists := seen[ua]; !exists {
				seen[ua] = struct{}{}
				agents = append(agents, ua)
			}
		}
	}
	return agents
}

func (e *Engine) detectScanPatterns(session models.Session) []models.ScanSignature {
	if len(session.Requests) < 3 {
		return nil
	}
	sig := models.ScanSignature{}

	if !session.EndTime.IsZero() {
		d := session.EndTime.Sub(session.StartTime).Seconds()
		if d > 0 {
			sig.ScanRate = float64(len(session.Requests)) / d
		}
	}

	probeTypes := make(map[string]struct{})
	for _, r := range session.Requests {
		p := strings.ToLower(r.Path)
		if strings.Contains(p, "..") || strings.Contains(p, "%2e") {
			probeTypes["path_traversal"] = struct{}{}
		}
		if strings.Contains(p, "admin") || strings.Contains(p, "wp-admin") {
			probeTypes["admin_probe"] = struct{}{}
		}
		if strings.Contains(p, "union") || strings.Contains(p, "select") || strings.Contains(r.Path, "'") {
			probeTypes["sqli_probe"] = struct{}{}
		}
		if strings.Contains(p, ".env") || strings.Contains(p, ".git") || strings.Contains(p, "phpinfo") {
			probeTypes["info_disclosure"] = struct{}{}
		}
		if strings.Contains(p, ".php") || strings.Contains(p, ".asp") {
			probeTypes["web_enum"] = struct{}{}
		}
	}
	for k := range probeTypes {
		sig.ProbeTypes = append(sig.ProbeTypes, k)
	}
	return []models.ScanSignature{sig}
}

func (e *Engine) detectToolSignature(vector models.BehaviorVector) models.ToolSignature {
	sig := models.ToolSignature{}
	for _, ua := range vector.UserAgentRotation {
		u := strings.ToLower(ua)
		switch {
		case strings.Contains(u, "sqlmap"):
			sig.LikelyTool, sig.Confidence = "sqlmap", 0.95
		case strings.Contains(u, "nikto"):
			sig.LikelyTool, sig.Confidence = "nikto", 0.95
		case strings.Contains(u, "nmap"):
			sig.LikelyTool, sig.Confidence = "nmap", 0.90
		case strings.Contains(u, "masscan"):
			sig.LikelyTool, sig.Confidence = "masscan", 0.90
		case strings.Contains(u, "zgrab"):
			sig.LikelyTool, sig.Confidence = "zgrab", 0.90
		case strings.Contains(u, "python-requests"):
			sig.LikelyTool, sig.Confidence = "python-requests (custom)", 0.60
		case strings.Contains(u, "go-http-client"):
			sig.LikelyTool, sig.Confidence = "go http.Client (custom)", 0.55
		case strings.Contains(u, "curl"):
			sig.LikelyTool, sig.Confidence = "curl", 0.50
		}
	}
	return sig
}

func (e *Engine) computeFingerprintHash(vector models.BehaviorVector) (string, error) {
	stable := struct {
		TLS         string            `json:"tls"`
		HeaderOrder []string          `json:"ho"`
		AcceptEnc   string            `json:"ae"`
		AcceptLang  string            `json:"al"`
		Connection  string            `json:"conn"`
	}{
		TLS:         vector.TLSFingerprint,
		HeaderOrder: vector.HTTPFingerprint.HeaderOrder,
		AcceptEnc:   vector.HTTPFingerprint.AcceptEncoding,
		AcceptLang:  vector.HTTPFingerprint.AcceptLanguage,
		Connection:  vector.HTTPFingerprint.ConnectionType,
	}
	data, err := json.Marshal(stable)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash), nil
}

func (e *Engine) findMatchingProfile(vector models.BehaviorVector, fpHash string) *models.AttackerProfile {
	for _, profile := range e.profiles {
		if profile.Fingerprint == fpHash {
			return profile
		}
		if sim := e.computeSimilarity(profile.Behavior, vector); sim >= e.config.CorrelationThreshold {
			return profile
		}
	}
	return nil
}

func (e *Engine) computeSimilarity(a, b models.BehaviorVector) float64 {
	w := e.config.Weights
	total := 0.0

	// TLS
	if a.TLSFingerprint != "" && a.TLSFingerprint == b.TLSFingerprint {
		total += w.TLSFingerprint
	}

	// HTTP headers
	total += e.headerSimilarity(a.HTTPFingerprint, b.HTTPFingerprint) * w.HTTPHeaders

	// Timing
	total += cosineSimilarity(a.RequestTiming, b.RequestTiming) * w.TimingPattern

	// Scan patterns
	total += e.scanSimilarity(a.ScanPatterns, b.ScanPatterns) * w.ScanPattern

	// Tool
	if a.ToolBehavior.LikelyTool != "" && a.ToolBehavior.LikelyTool == b.ToolBehavior.LikelyTool {
		total += w.ToolSignature
	}

	return total
}

func (e *Engine) headerSimilarity(a, b models.HTTPStack) float64 {
	score, checks := 0.0, 0.0
	if len(a.HeaderOrder) > 0 && len(b.HeaderOrder) > 0 {
		score += jaccardStrings(a.HeaderOrder, b.HeaderOrder)
		checks++
	}
	if a.AcceptEncoding != "" || b.AcceptEncoding != "" {
		if a.AcceptEncoding == b.AcceptEncoding {
			score++
		}
		checks++
	}
	if checks == 0 {
		return 0
	}
	return score / checks
}

func (e *Engine) scanSimilarity(a, b []models.ScanSignature) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0.5
	}
	score, checks := 0.0, 2.0

	ra, rb := a[0].ScanRate, b[0].ScanRate
	if ra > 0 && rb > 0 {
		ratio := ra / rb
		if ratio > 1 {
			ratio = 1 / ratio
		}
		if ratio >= 0.8 {
			score++
		}
	}

	score += jaccardStrings(a[0].ProbeTypes, b[0].ProbeTypes)
	return score / checks
}

func (e *Engine) refineBehaviorVector(existing *models.BehaviorVector, newData models.BehaviorVector) {
	const alpha = 0.3
	existing.RequestTiming = append(existing.RequestTiming, newData.RequestTiming...)
	if len(existing.RequestTiming) > 100 {
		existing.RequestTiming = existing.RequestTiming[len(existing.RequestTiming)-100:]
	}
	for i := range existing.TimeOfDayPattern {
		existing.TimeOfDayPattern[i] = int(float64(existing.TimeOfDayPattern[i])*(1-alpha) + float64(newData.TimeOfDayPattern[i])*alpha)
	}
	seen := make(map[string]struct{})
	for _, ua := range existing.UserAgentRotation {
		seen[ua] = struct{}{}
	}
	for _, ua := range newData.UserAgentRotation {
		if _, ok := seen[ua]; !ok {
			existing.UserAgentRotation = append(existing.UserAgentRotation, ua)
		}
	}
	if newData.TLSFingerprint != "" {
		existing.TLSFingerprint = newData.TLSFingerprint
	}
}

func (e *Engine) computeThreatScore(profile *models.AttackerProfile) float64 {
	score := math.Min(float64(len(profile.Sessions))*5, 30)
	if profile.Behavior.ToolBehavior.LikelyTool != "" {
		score += profile.Behavior.ToolBehavior.Confidence * 20
	}
	for _, scan := range profile.Behavior.ScanPatterns {
		score += float64(len(scan.ProbeTypes)) * 5
		if scan.ScanRate > 100 {
			score += 10
		}
	}
	return math.Min(score, 100)
}

func (e *Engine) detectTags(vector models.BehaviorVector) []string {
	tags := []string{}
	if len(vector.ScanPatterns) > 0 {
		tags = append(tags, "scanner")
		for _, scan := range vector.ScanPatterns {
			if scan.ScanRate > 500 {
				tags = append(tags, "aggressive-scanner")
			}
			for _, probe := range scan.ProbeTypes {
				switch probe {
				case "sqli_probe":
					tags = append(tags, "sql-injection")
				case "path_traversal":
					tags = append(tags, "path-traversal")
				case "admin_probe":
					tags = append(tags, "privilege-escalation")
				case "info_disclosure":
					tags = append(tags, "info-disclosure")
				case "web_enum":
					tags = append(tags, "web-enumeration")
				}
			}
		}
	}
	if vector.ToolBehavior.LikelyTool != "" {
		tags = append(tags, "automated-tool")
	}
	if len(vector.UserAgentRotation) > 3 {
		tags = append(tags, "ua-rotation")
	}
	return tags
}

// LoadProfile seeds the engine with an existing profile (e.g. loaded from storage).
// This enables cross-session deduplication across process restarts.
func (e *Engine) LoadProfile(profile *models.AttackerProfile) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.profiles[profile.ID]; !exists {
		e.profiles[profile.ID] = profile
	}
}

// GetProfile retrieves a profile by ID.
func (e *Engine) GetProfile(id string) (*models.AttackerProfile, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.profiles[id]
	return p, ok
}

// GetAllProfiles returns all profiles sorted by threat score descending.
func (e *Engine) GetAllProfiles() []*models.AttackerProfile {
	e.mu.RLock()
	defer e.mu.RUnlock()
	profiles := make([]*models.AttackerProfile, 0, len(e.profiles))
	for _, p := range e.profiles {
		profiles = append(profiles, p)
	}
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].ThreatScore > profiles[j].ThreatScore
	})
	return profiles
}

// Stats returns engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	total := 0
	for _, p := range e.profiles {
		total += len(p.Sessions)
	}
	return map[string]interface{}{
		"total_profiles": len(e.profiles),
		"total_sessions": total,
		"engine_version": "1.0.0",
	}
}

// --- Pure helpers ---

func jaccardStrings(a, b []string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	set := make(map[string]struct{})
	for _, s := range a {
		set[s] = struct{}{}
	}
	inter := 0
	for _, s := range b {
		if _, ok := set[s]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func cosineSimilarity(a, b []float64) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	buckets := 10
	na := normalizeToBuckets(a, buckets)
	nb := normalizeToBuckets(b, buckets)
	dot, magA, magB := 0.0, 0.0, 0.0
	for i := 0; i < buckets; i++ {
		dot += na[i] * nb[i]
		magA += na[i] * na[i]
		magB += nb[i] * nb[i]
	}
	mag := math.Sqrt(magA) * math.Sqrt(magB)
	if mag == 0 {
		return 0
	}
	return dot / mag
}

func normalizeToBuckets(values []float64, buckets int) []float64 {
	result := make([]float64, buckets)
	if len(values) == 0 {
		return result
	}
	minV, maxV := values[0], values[0]
	for _, v := range values {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	r := maxV - minV
	if r == 0 {
		result[buckets/2]++
		return result
	}
	for _, v := range values {
		bucket := int((v - minV) / r * float64(buckets-1))
		result[bucket]++
	}
	return result
}
