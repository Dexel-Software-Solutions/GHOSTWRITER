// Package correlation implements GHOSTWRITER's cross-session attacker correlation engine.
//
// Engineer: Demiyan Dissanayake
// Organization: Dexel Software Solutions
// Contact: dexelsoftwaresolutions@gmail.com | https://github.com/Dexel-Software-Solutions
package correlation

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Dexel-Software-Solutions/ghostwriter/internal/fingerprint"
	"github.com/Dexel-Software-Solutions/ghostwriter/pkg/models"
)

// Correlator performs cross-session and cross-profile correlation analysis.
type Correlator struct {
	mu      sync.RWMutex
	engine  *fingerprint.Engine
	results []models.CorrelationResult
	config  Config
}

// Config holds correlator configuration.
type Config struct {
	MinSimilarity  float64
	MultiSignal    bool
	MaxResults     int
}

// DefaultConfig returns sensible correlator defaults.
func DefaultConfig() Config {
	return Config{
		MinSimilarity: 0.60,
		MultiSignal:   true,
		MaxResults:    10000,
	}
}

// NewCorrelator creates a new correlation engine.
func NewCorrelator(engine *fingerprint.Engine, cfg Config) *Correlator {
	return &Correlator{
		engine:  engine,
		results: make([]models.CorrelationResult, 0),
		config:  cfg,
	}
}

// AttackerCluster represents a group of profiles believed to be the same attacker.
type AttackerCluster struct {
	ClusterID  string
	Profiles   []*models.AttackerProfile
	Confidence float64
	Tags       []string
	Evidence   []string
}

// CorrelateAll runs full correlation across all known profiles.
func (c *Correlator) CorrelateAll() ([]AttackerCluster, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	profiles := c.engine.GetAllProfiles()
	if len(profiles) < 2 {
		return nil, nil
	}

	results := make([]models.CorrelationResult, 0)
	for i := 0; i < len(profiles); i++ {
		for j := i + 1; j < len(profiles); j++ {
			result := correlateProfiles(profiles[i], profiles[j])
			if result.Similarity >= c.config.MinSimilarity {
				results = append(results, result)
			}
		}
	}
	c.results = append(c.results, results...)
	return clusterProfiles(profiles, results), nil
}

// CorrelateNewProfile correlates a new profile against all existing ones.
func (c *Correlator) CorrelateNewProfile(newProfile *models.AttackerProfile) []models.CorrelationResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	profiles := c.engine.GetAllProfiles()
	matches := make([]models.CorrelationResult, 0)
	for _, existing := range profiles {
		if existing.ID == newProfile.ID {
			continue
		}
		result := correlateProfiles(newProfile, existing)
		if result.Similarity >= c.config.MinSimilarity {
			matches = append(matches, result)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Similarity > matches[j].Similarity
	})
	return matches
}

func correlateProfiles(a, b *models.AttackerProfile) models.CorrelationResult {
	type signal struct {
		name    string
		score   float64
		weight  float64
		matched bool
	}

	signals := []signal{}

	// TLS fingerprint
	if a.Behavior.TLSFingerprint != "" && b.Behavior.TLSFingerprint != "" {
		m := a.Behavior.TLSFingerprint == b.Behavior.TLSFingerprint
		s := 0.0
		if m {
			s = 1.0
		}
		signals = append(signals, signal{"TLS/JA3 Fingerprint", s, 0.30, m})
	}

	// HTTP header order
	headerSim := jaccardStrings(a.Behavior.HTTPFingerprint.HeaderOrder, b.Behavior.HTTPFingerprint.HeaderOrder)
	signals = append(signals, signal{"HTTP Header Order", headerSim, 0.20, headerSim > 0.7})

	// Accept-Language
	if a.Behavior.HTTPFingerprint.AcceptLanguage != "" && b.Behavior.HTTPFingerprint.AcceptLanguage != "" {
		m := a.Behavior.HTTPFingerprint.AcceptLanguage == b.Behavior.HTTPFingerprint.AcceptLanguage
		s := 0.0
		if m {
			s = 1.0
		}
		signals = append(signals, signal{"Accept-Language", s, 0.10, m})
	}

	// Tool signature
	if a.Behavior.ToolBehavior.LikelyTool != "" && b.Behavior.ToolBehavior.LikelyTool != "" {
		m := a.Behavior.ToolBehavior.LikelyTool == b.Behavior.ToolBehavior.LikelyTool
		s := 0.0
		if m {
			s = 1.0
		}
		signals = append(signals, signal{"Attack Tool", s, 0.20, m})
	}

	// Probe type overlap
	probesA := getAllProbeTypes(a)
	probesB := getAllProbeTypes(b)
	probeSim := jaccardStrings(probesA, probesB)
	signals = append(signals, signal{"Attack Probe Types", probeSim, 0.20, probeSim > 0.6})

	// Weighted sum
	totalSim, totalWeight := 0.0, 0.0
	matchedNames := []string{}
	for _, s := range signals {
		totalSim += s.score * s.weight
		totalWeight += s.weight
		if s.matched {
			matchedNames = append(matchedNames, s.name)
		}
	}

	sim := 0.0
	if totalWeight > 0 {
		sim = totalSim / totalWeight
	}

	reason := fmt.Sprintf("Low correlation (%.0f%%)", sim*100)
	if len(matchedNames) > 0 {
		reason = fmt.Sprintf("Matched: %s (%.0f%% confidence)", strings.Join(matchedNames, ", "), sim*100)
	}

	return models.CorrelationResult{
		ProfileA:    a.ID,
		ProfileB:    b.ID,
		Similarity:  sim,
		IsMatch:     sim >= 0.72,
		Confidence:  sim,
		MatchReason: reason,
	}
}

func clusterProfiles(profiles []*models.AttackerProfile, results []models.CorrelationResult) []AttackerCluster {
	parent := make(map[string]string)
	for _, p := range profiles {
		parent[p.ID] = p.ID
	}

	var find func(string) string
	find = func(x string) string {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}

	union := func(x, y string) {
		px, py := find(x), find(y)
		if px != py {
			parent[py] = px
		}
	}

	for _, r := range results {
		if r.IsMatch {
			union(r.ProfileA, r.ProfileB)
		}
	}

	clusterMap := make(map[string][]*models.AttackerProfile)
	for _, p := range profiles {
		root := find(p.ID)
		clusterMap[root] = append(clusterMap[root], p)
	}

	clusters := make([]AttackerCluster, 0)
	for root, cps := range clusterMap {
		if len(cps) < 2 {
			continue
		}

		conf, count := 0.0, 0
		for _, r := range results {
			for _, p := range cps {
				if r.ProfileA == p.ID || r.ProfileB == p.ID {
					conf += r.Similarity
					count++
				}
			}
		}
		if count > 0 {
			conf /= float64(count)
		}

		tagSet := make(map[string]struct{})
		for _, p := range cps {
			for _, t := range p.Tags {
				tagSet[t] = struct{}{}
			}
		}
		tags := make([]string, 0, len(tagSet))
		for t := range tagSet {
			tags = append(tags, t)
		}

		clusters = append(clusters, AttackerCluster{
			ClusterID:  root,
			Profiles:   cps,
			Confidence: conf,
			Tags:       tags,
		})
	}

	sort.Slice(clusters, func(i, j int) bool {
		return len(clusters[i].Profiles) > len(clusters[j].Profiles)
	})
	return clusters
}

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

func getAllProbeTypes(p *models.AttackerProfile) []string {
	types := []string{}
	for _, scan := range p.Behavior.ScanPatterns {
		types = append(types, scan.ProbeTypes...)
	}
	return types
}
