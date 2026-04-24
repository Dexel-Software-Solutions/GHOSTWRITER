// Package reporter generates GHOSTWRITER analysis reports in multiple formats.
//
// Engineer: Demiyan Dissanayake
// Organization: Dexel Software Solutions
// Contact: dexelsoftwaresolutions@gmail.com | https://github.com/Dexel-Software-Solutions
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Dexel-Software-Solutions/ghostwriter/internal/correlation"
	"github.com/Dexel-Software-Solutions/ghostwriter/pkg/models"
)

// Format defines the output format of a report.
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatJSON     Format = "json"
	FormatHTML     Format = "html"
)

// Reporter generates analysis reports from GHOSTWRITER data.
type Reporter struct {
	outputDir string
}

// New creates a new Reporter.
func New(outputDir string) *Reporter {
	return &Reporter{outputDir: outputDir}
}

// ReportData holds all data needed to generate a report.
type ReportData struct {
	GeneratedAt time.Time
	Profiles    []*models.AttackerProfile
	Clusters    []correlation.AttackerCluster
	Alerts      []*models.Alert
	Stats       map[string]interface{}
}

// Generate creates a report in the specified format.
func (r *Reporter) Generate(data ReportData, format Format) (string, error) {
	switch format {
	case FormatTerminal:
		return r.generateTerminal(data)
	case FormatJSON:
		return r.generateJSON(data)
	case FormatHTML:
		return r.generateHTML(data)
	default:
		return "", fmt.Errorf("unknown format %q — use: terminal, json, html", format)
	}
}

func (r *Reporter) generateTerminal(data ReportData) (string, error) {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("  ╔══════════════════════════════════════════════════════════╗\n")
	sb.WriteString("  ║         GHOSTWRITER — Behavioral Threat Report           ║\n")
	sb.WriteString("  ║    Engineer: Demiyan Dissanayake | Dexel Software        ║\n")
	sb.WriteString("  ╚══════════════════════════════════════════════════════════╝\n")
	sb.WriteString(fmt.Sprintf("  Generated : %s\n\n", data.GeneratedAt.Format("2006-01-02 15:04:05")))

	sb.WriteString(fmt.Sprintf("  Profiles  : %d\n", len(data.Profiles)))
	sb.WriteString(fmt.Sprintf("  Clusters  : %d\n", len(data.Clusters)))
	sb.WriteString(fmt.Sprintf("  Alerts    : %d\n\n", len(data.Alerts)))

	if len(data.Profiles) == 0 {
		sb.WriteString("  No profiles found. Run 'ghostwriter ingest --file sessions.json' to get started.\n\n")
	} else {
		sb.WriteString("  ┌──────────────────────────────────────────────────────────────────────────────────┐\n")
		sb.WriteString("  │  #   ID                  SCORE   SESSIONS  TOOL                    TAGS          │\n")
		sb.WriteString("  ├──────────────────────────────────────────────────────────────────────────────────┤\n")
		for i, p := range data.Profiles {
			tool := p.Behavior.ToolBehavior.LikelyTool
			if tool == "" {
				tool = "—"
			}
			tags := strings.Join(p.Tags, ",")
			if tags == "" {
				tags = "—"
			}
			indicator := threatIndicator(p.ThreatScore)
			sb.WriteString(fmt.Sprintf("  │  %-3d %-20s  %s%-5.0f  %-8d  %-22s  %-12s  │\n",
				i+1,
				truncate(p.ID, 20),
				indicator,
				p.ThreatScore,
				len(p.Sessions),
				truncate(tool, 22),
				truncate(tags, 12),
			))
		}
		sb.WriteString("  └──────────────────────────────────────────────────────────────────────────────────┘\n\n")
	}

	if len(data.Clusters) > 0 {
		sb.WriteString("  [!] ATTACKER CLUSTERS — same actor, multiple IPs:\n\n")
		for i, c := range data.Clusters {
			sb.WriteString(fmt.Sprintf("  Cluster #%d  confidence=%.0f%%  tags=%s\n",
				i+1, c.Confidence*100, strings.Join(c.Tags, ",")))
			for _, p := range c.Profiles {
				sb.WriteString(fmt.Sprintf("    -> %s  score=%.0f  sessions=%d\n",
					p.ID[:16]+"...", p.ThreatScore, len(p.Sessions)))
			}
			sb.WriteString("\n")
		}
	}

	if len(data.Alerts) > 0 {
		sb.WriteString("  [!] ALERTS:\n\n")
		for _, a := range data.Alerts {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", a.Severity, a.Description))
			sb.WriteString(fmt.Sprintf("       Profile : %s\n", truncate(a.ProfileID, 20)))
			if a.SourceIP != "" {
				sb.WriteString(fmt.Sprintf("       Source  : %s\n", a.SourceIP))
			}
			sb.WriteString(fmt.Sprintf("       Action  : %s\n\n", a.Recommended))
		}
	}

	sb.WriteString("  ─────────────────────────────────────────────────────────────\n")
	sb.WriteString("  GHOSTWRITER by Dexel Software Solutions\n")
	sb.WriteString("  https://github.com/Dexel-Software-Solutions\n\n")

	return sb.String(), nil
}

func (r *Reporter) generateJSON(data ReportData) (string, error) {
	output := map[string]interface{}{
		"meta": map[string]interface{}{
			"tool":         "GHOSTWRITER",
			"version":      "1.0.0",
			"generated_at": data.GeneratedAt.Format(time.RFC3339),
			"author":       "Demiyan Dissanayake",
			"organization": "Dexel Software Solutions",
			"contact":      "dexelsoftwaresolutions@gmail.com",
			"github":       "https://github.com/Dexel-Software-Solutions",
		},
		"summary": map[string]interface{}{
			"total_profiles": len(data.Profiles),
			"total_clusters": len(data.Clusters),
			"total_alerts":   len(data.Alerts),
		},
		"profiles": data.Profiles,
		"clusters": data.Clusters,
		"alerts":   data.Alerts,
	}
	if data.Stats != nil {
		output["engine_stats"] = data.Stats
	}

	b, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return "", err
	}

	if r.outputDir != "" {
		if err := os.MkdirAll(r.outputDir, 0755); err != nil {
			return "", err
		}
		filename := fmt.Sprintf("ghostwriter_%s.json", data.GeneratedAt.Format("20060102_150405"))
		path := filepath.Join(r.outputDir, filename)
		if err := os.WriteFile(path, b, 0644); err != nil {
			return "", err
		}
		return fmt.Sprintf("\n  ✓  JSON report saved: %s\n\n", path), nil
	}

	return string(b) + "\n", nil
}

func (r *Reporter) generateHTML(data ReportData) (string, error) {
	var profileRows strings.Builder
	for i, p := range data.Profiles {
		tool := p.Behavior.ToolBehavior.LikelyTool
		if tool == "" {
			tool = "—"
		}
		tags := strings.Join(p.Tags, ", ")
		if tags == "" {
			tags = "—"
		}
		lastSeen := p.LastSeen.Format("2006-01-02 15:04")
		profileRows.WriteString(fmt.Sprintf(
			"<tr><td style=\"font-family:monospace;font-size:0.78rem\">%s</td>"+
				"<td><span class=\"badge %s\">%.0f</span></td>"+
				"<td style=\"text-align:center\">%d</td>"+
				"<td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			htmlEscape(truncate(p.ID, 16))+"...",
			threatBadgeClass(p.ThreatScore),
			p.ThreatScore,
			i+1,
			len(p.Sessions),
			htmlEscape(tool),
			htmlEscape(tags),
			lastSeen,
		))
	}

	var clusterRows strings.Builder
	if len(data.Clusters) == 0 {
		clusterRows.WriteString("<tr><td colspan=\"4\" style=\"text-align:center;color:var(--muted)\">No clusters detected</td></tr>\n")
	}
	for i, c := range data.Clusters {
		clusterRows.WriteString(fmt.Sprintf(
			"<tr><td>#%d</td><td style=\"text-align:center\">%d</td><td>%.0f%%</td><td>%s</td></tr>\n",
			i+1, len(c.Profiles), c.Confidence*100, htmlEscape(strings.Join(c.Tags, ", "))))
	}

	var alertRows strings.Builder
	if len(data.Alerts) == 0 {
		alertRows.WriteString("<tr><td colspan=\"4\" style=\"text-align:center;color:var(--muted)\">No active alerts</td></tr>\n")
	}
	for _, a := range data.Alerts {
		alertRows.WriteString(fmt.Sprintf(
			"<tr><td><span class=\"badge %s\">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			alertBadgeClass(a.Severity), a.Severity,
			a.Timestamp.Format("2006-01-02 15:04:05"),
			htmlEscape(a.Description),
			htmlEscape(a.Recommended),
		))
	}

	html := htmlTemplate
	html = strings.ReplaceAll(html, "{{GENERATED_AT}}", data.GeneratedAt.Format("2006-01-02 15:04:05"))
	html = strings.ReplaceAll(html, "{{PROFILE_COUNT}}", fmt.Sprintf("%d", len(data.Profiles)))
	html = strings.ReplaceAll(html, "{{CLUSTER_COUNT}}", fmt.Sprintf("%d", len(data.Clusters)))
	html = strings.ReplaceAll(html, "{{ALERT_COUNT}}", fmt.Sprintf("%d", len(data.Alerts)))
	html = strings.ReplaceAll(html, "{{PROFILE_ROWS}}", profileRows.String())
	html = strings.ReplaceAll(html, "{{CLUSTER_ROWS}}", clusterRows.String())
	html = strings.ReplaceAll(html, "{{ALERT_ROWS}}", alertRows.String())

	if r.outputDir != "" {
		if err := os.MkdirAll(r.outputDir, 0755); err != nil {
			return "", err
		}
		filename := fmt.Sprintf("ghostwriter_%s.html", data.GeneratedAt.Format("20060102_150405"))
		path := filepath.Join(r.outputDir, filename)
		if err := os.WriteFile(path, []byte(html), 0644); err != nil {
			return "", err
		}
		return fmt.Sprintf("\n  ✓  HTML report saved: %s\n\n", path), nil
	}
	return html, nil
}

// --- helpers ---

func threatIndicator(score float64) string {
	switch {
	case score >= 80:
		return "[CRIT] "
	case score >= 60:
		return "[HIGH] "
	case score >= 40:
		return "[MED]  "
	default:
		return "[LOW]  "
	}
}

func threatBadgeClass(score float64) string {
	switch {
	case score >= 80:
		return "badge-critical"
	case score >= 60:
		return "badge-high"
	case score >= 40:
		return "badge-medium"
	default:
		return "badge-low"
	}
}

func alertBadgeClass(severity models.Severity) string {
	switch severity {
	case models.SeverityCritical:
		return "badge-critical"
	case models.SeverityHigh:
		return "badge-high"
	case models.SeverityMedium:
		return "badge-medium"
	default:
		return "badge-low"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>GHOSTWRITER — Behavioral Threat Report</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2333;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;--accent:#58a6ff;--danger:#f85149;--warn:#d29922;--success:#3fb950;--purple:#bc8cff}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;font-size:14px}
.header{background:linear-gradient(135deg,#0d1117 0%,#1c2333 50%,#0d1117 100%);border-bottom:1px solid var(--border);padding:2.5rem 2rem;text-align:center}
.header h1{font-size:2.4rem;color:var(--accent);letter-spacing:.4em;text-shadow:0 0 20px rgba(88,166,255,.3)}
.header .tagline{color:var(--muted);margin-top:.6rem;font-style:italic}
.header .meta{color:var(--muted);margin-top:.5rem;font-size:.8rem}
.container{max-width:1200px;margin:0 auto;padding:2rem}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:1.2rem;margin:2rem 0}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.8rem;text-align:center;transition:border-color .2s}
.stat:hover{border-color:var(--accent)}
.stat .val{font-size:2.8rem;font-weight:700;color:var(--accent)}
.stat .lbl{color:var(--muted);font-size:.82rem;margin-top:.5rem;letter-spacing:.05em;text-transform:uppercase}
.section-title{font-size:1rem;color:var(--accent);margin:2.5rem 0 .8rem;padding-bottom:.5rem;border-bottom:1px solid var(--border);letter-spacing:.05em;text-transform:uppercase}
table{width:100%;border-collapse:collapse;margin:.5rem 0 1.5rem}
th{background:var(--surface2);border:1px solid var(--border);padding:.7rem .9rem;text-align:left;color:var(--accent);font-size:.78rem;letter-spacing:.05em;text-transform:uppercase}
td{border:1px solid var(--border);padding:.65rem .9rem;font-size:.82rem;vertical-align:middle}
tr:hover td{background:rgba(88,166,255,.04)}
.badge{display:inline-block;padding:.2rem .55rem;border-radius:4px;font-size:.72rem;font-weight:700;letter-spacing:.05em}
.badge-critical{background:rgba(248,81,73,.15);color:var(--danger);border:1px solid rgba(248,81,73,.3)}
.badge-high{background:rgba(210,153,34,.15);color:var(--warn);border:1px solid rgba(210,153,34,.3)}
.badge-medium{background:rgba(63,185,80,.15);color:var(--success);border:1px solid rgba(63,185,80,.3)}
.badge-low{background:rgba(139,148,158,.12);color:var(--muted);border:1px solid rgba(139,148,158,.2)}
.footer{text-align:center;padding:2.5rem 2rem;color:var(--muted);border-top:1px solid var(--border);margin-top:3rem;font-size:.82rem}
.footer a{color:var(--accent);text-decoration:none}
.footer a:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="header">
  <h1>👻 GHOSTWRITER</h1>
  <div class="tagline">"Same attacker. Different IP. Still caught."</div>
  <div class="meta">Behavioral Attacker Intelligence Report &nbsp;|&nbsp; Generated: {{GENERATED_AT}}</div>
  <div class="meta">Engineer: Demiyan Dissanayake &nbsp;|&nbsp; Dexel Software Solutions</div>
</div>
<div class="container">
  <div class="stats">
    <div class="stat"><div class="val">{{PROFILE_COUNT}}</div><div class="lbl">Attacker Profiles</div></div>
    <div class="stat"><div class="val">{{CLUSTER_COUNT}}</div><div class="lbl">Attacker Clusters</div></div>
    <div class="stat"><div class="val">{{ALERT_COUNT}}</div><div class="lbl">Active Alerts</div></div>
  </div>

  <div class="section-title">⚔ Attacker Profiles</div>
  <table>
    <thead><tr><th>Profile ID</th><th>Threat</th><th>#</th><th>Sessions</th><th>Tool</th><th>Tags</th><th>Last Seen</th></tr></thead>
    <tbody>{{PROFILE_ROWS}}</tbody>
  </table>

  <div class="section-title">🔗 Attacker Clusters</div>
  <table>
    <thead><tr><th>Cluster</th><th>Profiles</th><th>Confidence</th><th>Tags</th></tr></thead>
    <tbody>{{CLUSTER_ROWS}}</tbody>
  </table>

  <div class="section-title">🚨 Active Alerts</div>
  <table>
    <thead><tr><th>Severity</th><th>Timestamp</th><th>Description</th><th>Recommended Action</th></tr></thead>
    <tbody>{{ALERT_ROWS}}</tbody>
  </table>
</div>
<div class="footer">
  <p><strong>GHOSTWRITER</strong> — Behavioral Attacker Intelligence</p>
  <p style="margin-top:.4rem">by <strong>Demiyan Dissanayake</strong> @ Dexel Software Solutions</p>
  <p style="margin-top:.4rem">
    <a href="https://github.com/Dexel-Software-Solutions">github.com/Dexel-Software-Solutions</a>
    &nbsp;|&nbsp;
    <a href="mailto:dexelsoftwaresolutions@gmail.com">dexelsoftwaresolutions@gmail.com</a>
  </p>
</div>
</body>
</html>`
