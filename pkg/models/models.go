// Package models defines the core data structures for GHOSTWRITER.
//
// Engineer: Demiyan Dissanayake
// Organization: Dexel Software Solutions
// Contact: dexelsoftwaresolutions@gmail.com | https://github.com/Dexel-Software-Solutions
package models

import "time"

type AttackerProfile struct {
	ID                string         `json:"id"`
	Fingerprint       string         `json:"fingerprint"`
	FirstSeen         time.Time      `json:"first_seen"`
	LastSeen          time.Time      `json:"last_seen"`
	ThreatScore       float64        `json:"threat_score"`
	Confidence        float64        `json:"confidence"`
	Tags              []string       `json:"tags"`
	Behavior          BehaviorVector `json:"behavior"`
	Sessions          []Session      `json:"sessions"`
	CorrelationMethod string         `json:"correlation_method"`
}

type BehaviorVector struct {
	RequestTiming     []float64      `json:"request_timing"`
	SessionDuration   float64        `json:"session_duration"`
	TimeOfDayPattern  [24]int        `json:"time_of_day_pattern"`
	TCPFingerprint    TCPStack       `json:"tcp_fingerprint"`
	TLSFingerprint    string         `json:"tls_fingerprint"`
	HTTPFingerprint   HTTPStack      `json:"http_fingerprint"`
	UserAgentRotation []string       `json:"user_agent_rotation"`
	ScanPatterns      []ScanSignature `json:"scan_patterns"`
	PayloadSignatures []string       `json:"payload_signatures"`
	ToolBehavior      ToolSignature  `json:"tool_behavior"`
}

type TCPStack struct {
	WindowSize    int    `json:"window_size"`
	TTL           int    `json:"ttl"`
	MSS           int    `json:"mss"`
	WindowScaling bool   `json:"window_scaling"`
	SACKSupport   bool   `json:"sack_support"`
	OSGuess       string `json:"os_guess"`
}

type HTTPStack struct {
	HeaderOrder    []string          `json:"header_order"`
	HeaderValues   map[string]string `json:"header_values"`
	AcceptEncoding string            `json:"accept_encoding"`
	AcceptLanguage string            `json:"accept_language"`
	ConnectionType string            `json:"connection_type"`
}

type ScanSignature struct {
	ScanRate     float64  `json:"scan_rate"`
	ProbeTypes   []string `json:"probe_types"`
	PausePattern []float64 `json:"pause_pattern"`
}

type ToolSignature struct {
	LikelyTool  string  `json:"likely_tool"`
	Confidence  float64 `json:"confidence"`
	ToolVersion string  `json:"tool_version"`
}

type Session struct {
	ID         string    `json:"id"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	SourceIP   string    `json:"source_ip"`
	SourcePort int       `json:"source_port"`
	Protocol   string    `json:"protocol"`
	Requests   []Request `json:"requests"`
}

type Request struct {
	Timestamp    time.Time         `json:"timestamp"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Headers      map[string]string `json:"headers"`
	PayloadHash  string            `json:"payload_hash"`
	ResponseCode int               `json:"response_code"`
	BytesSent    int               `json:"bytes_sent"`
	BytesRecv    int               `json:"bytes_recv"`
	Latency      float64           `json:"latency"`
}

type CorrelationResult struct {
	ProfileA    string  `json:"profile_a"`
	ProfileB    string  `json:"profile_b"`
	Similarity  float64 `json:"similarity"`
	IsMatch     bool    `json:"is_match"`
	MatchReason string  `json:"match_reason"`
	Confidence  float64 `json:"confidence"`
}

type Alert struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    Severity  `json:"severity"`
	ProfileID   string    `json:"profile_id"`
	SourceIP    string    `json:"source_ip"`
	Description string    `json:"description"`
	Evidence    []string  `json:"evidence"`
	Recommended string    `json:"recommended_action"`
}

type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)
