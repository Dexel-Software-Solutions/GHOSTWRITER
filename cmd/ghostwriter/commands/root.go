// Package commands implements the GHOSTWRITER CLI.
//
// Engineer: Demiyan Dissanayake
// Organization: Dexel Software Solutions
// Contact: dexelsoftwaresolutions@gmail.com | https://github.com/Dexel-Software-Solutions
package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Dexel-Software-Solutions/ghostwriter/internal/correlation"
	"github.com/Dexel-Software-Solutions/ghostwriter/internal/fingerprint"
	"github.com/Dexel-Software-Solutions/ghostwriter/internal/reporter"
	"github.com/Dexel-Software-Solutions/ghostwriter/internal/storage"
	"github.com/Dexel-Software-Solutions/ghostwriter/pkg/models"
)

const banner = `
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗    ██╗██████╗ ██╗████████╗███████╗██████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║    ██║██╔══██╗██║╚══██╔══╝██╔════╝██╔══██╗
 ██║  ███╗███████║██║   ██║███████╗   ██║   ██║ █╗ ██║██████╔╝██║   ██║   █████╗  ██████╔╝
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║███╗██║██╔══██╗██║   ██║   ██╔══╝  ██╔══██╗
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ╚███╔███╔╝██║  ██║██║   ██║   ███████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

  Behavioral Attacker Intelligence  |  v1.0.0
  "Same attacker. Different IP. Still caught."
  ─────────────────────────────────────────────────────────────────────────────
  Engineer : Demiyan Dissanayake
  Org      : Dexel Software Solutions
  GitHub   : https://github.com/Dexel-Software-Solutions
  Email    : dexelsoftwaresolutions@gmail.com
  ─────────────────────────────────────────────────────────────────────────────
`

const usage = `
Usage:
  ghostwriter <command> [flags]

Commands:
  ingest      Ingest a JSON session file for behavioral analysis
  profiles    List all attacker profiles
  profile     Show a specific profile by ID
  correlate   Run cross-IP attacker correlation
  report      Generate a report (terminal|json|html)
  alerts      List active alerts
  flush       Remove profiles older than a given duration
  version     Print version info
  help        Show this help message

Flags:
  --db        Path to GHOSTWRITER database  (default: ghostwriter.db)
  --output    Output directory for reports   (default: ./reports)

Examples:
  ghostwriter ingest --file sessions.json
  ghostwriter ingest --file sessions.json --db /var/lib/ghostwriter/data.db
  ghostwriter profiles
  ghostwriter profiles --limit 20
  ghostwriter profile --id <profile-id>
  ghostwriter correlate
  ghostwriter report --format html --output ./reports
  ghostwriter report --format json
  ghostwriter alerts
  ghostwriter alerts --severity HIGH
  ghostwriter flush --older-than 720h

Session JSON format (array or single object):
  [
    {
      "id":          "sess-001",
      "start_time":  "2024-01-15T10:00:00Z",
      "end_time":    "2024-01-15T10:00:05Z",
      "source_ip":   "192.168.1.100",
      "source_port": 54321,
      "protocol":    "HTTP/1.1",
      "requests": [
        {
          "timestamp":     "2024-01-15T10:00:00Z",
          "method":        "GET",
          "path":          "/login.php?id=1'",
          "headers":       { "User-Agent": "sqlmap/1.7.8", "Accept-Encoding": "gzip, deflate" },
          "response_code": 200,
          "bytes_sent":    1024,
          "bytes_recv":    512,
          "latency":       45.2
        }
      ]
    }
  ]
`

// Execute parses os.Args and dispatches to the appropriate subcommand.
func Execute() error {
	if len(os.Args) < 2 {
		fmt.Print(banner)
		fmt.Print(usage)
		return nil
	}

	dbPath := "ghostwriter.db"
	outputDir := "./reports"

	switch os.Args[1] {
	case "ingest":
		fs := flag.NewFlagSet("ingest", flag.ExitOnError)
		file := fs.String("file", "", "path to JSON session file (required)")
		fs.StringVar(&dbPath, "db", dbPath, "database path")
		_ = fs.Parse(os.Args[2:])
		return runIngest(dbPath, *file)
	case "profiles":
		fs := flag.NewFlagSet("profiles", flag.ExitOnError)
		fs.StringVar(&dbPath, "db", dbPath, "database path")
		limit := fs.Int("limit", 50, "maximum profiles to display")
		_ = fs.Parse(os.Args[2:])
		return runProfiles(dbPath, *limit)
	case "profile":
		fs := flag.NewFlagSet("profile", flag.ExitOnError)
		id := fs.String("id", "", "profile ID (required)")
		fs.StringVar(&dbPath, "db", dbPath, "database path")
		_ = fs.Parse(os.Args[2:])
		return runProfile(dbPath, *id)
	case "correlate":
		fs := flag.NewFlagSet("correlate", flag.ExitOnError)
		fs.StringVar(&dbPath, "db", dbPath, "database path")
		_ = fs.Parse(os.Args[2:])
		return runCorrelate(dbPath)
	case "report":
		fs := flag.NewFlagSet("report", flag.ExitOnError)
		format := fs.String("format", "terminal", "output format: terminal|json|html")
		fs.StringVar(&dbPath, "db", dbPath, "database path")
		fs.StringVar(&outputDir, "output", outputDir, "output directory")
		_ = fs.Parse(os.Args[2:])
		return runReport(dbPath, outputDir, *format)
	case "alerts":
		fs := flag.NewFlagSet("alerts", flag.ExitOnError)
		fs.StringVar(&dbPath, "db", dbPath, "database path")
		severity := fs.String("severity", "", "filter by severity: LOW|MEDIUM|HIGH|CRITICAL")
		_ = fs.Parse(os.Args[2:])
		return runAlerts(dbPath, *severity)
	case "flush":
		fs := flag.NewFlagSet("flush", flag.ExitOnError)
		fs.StringVar(&dbPath, "db", dbPath, "database path")
		olderThan := fs.String("older-than", "720h", "remove profiles older than this duration (e.g. 720h)")
		_ = fs.Parse(os.Args[2:])
		return runFlush(dbPath, *olderThan)
	case "version":
		fmt.Printf("\n  GHOSTWRITER v1.0.0\n")
		fmt.Printf("  Engineer : Demiyan Dissanayake\n")
		fmt.Printf("  Org      : Dexel Software Solutions\n")
		fmt.Printf("  GitHub   : https://github.com/Dexel-Software-Solutions\n")
		fmt.Printf("  Email    : dexelsoftwaresolutions@gmail.com\n\n")
		return nil
	case "help", "--help", "-h":
		fmt.Print(banner)
		fmt.Print(usage)
		return nil
	default:
		fmt.Printf("\n  Unknown command: %s\n", os.Args[1])
		fmt.Print(usage)
		return nil
	}
}

// ─── ingest ───────────────────────────────────────────────────────────────────

func runIngest(dbPath, file string) error {
	if file == "" {
		return fmt.Errorf("--file is required. Example: ghostwriter ingest --file sessions.json")
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var sessions []models.Session
	if err := json.Unmarshal(data, &sessions); err != nil {
		var single models.Session
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return fmt.Errorf("parse sessions JSON: %w", err)
		}
		sessions = []models.Session{single}
	}

	if len(sessions) == 0 {
		return fmt.Errorf("no sessions found in %s", file)
	}

	store, err := storage.Open(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	engine := fingerprint.NewEngine(fingerprint.DefaultConfig())

	// Seed engine with existing profiles for cross-session matching
	existing, _ := store.GetAllProfiles()
	existingIDs := make(map[string]struct{}, len(existing))
	for _, p := range existing {
		engine.LoadProfile(p)
		existingIDs[p.ID] = struct{}{}
	}

	fmt.Printf("\n  Loaded %d existing profile(s).\n", len(existing))
	fmt.Printf("  Processing %d session(s) from %s...\n\n", len(sessions), file)

	newP, updated, skipped := 0, 0, 0
	seenInBatch := make(map[string]struct{})
	for _, session := range sessions {
		if session.ID == "" || len(session.Requests) == 0 {
			fmt.Printf("  [!] Session skipped: missing ID or requests\n")
			skipped++
			continue
		}

		profile, err := engine.IngestSession(session)
		if err != nil {
			fmt.Printf("  [!] Session %s skipped: %v\n", session.ID, err)
			skipped++
			continue
		}

		if err := store.SaveProfile(profile); err != nil {
			return fmt.Errorf("save profile: %w", err)
		}

		// Generate and persist alerts
		for _, alert := range generateAlerts(profile) {
			_ = store.SaveAlert(alert)
		}

		_, wasPreExisting := existingIDs[profile.ID]
		_, seenThisBatch := seenInBatch[profile.ID]
		if !wasPreExisting && !seenThisBatch {
			newP++
			seenInBatch[profile.ID] = struct{}{}
			fmt.Printf("  [+] NEW  %s  %s%.0f  tool=%-20s  tags=%s\n",
				profile.ID[:16]+"...",
				threatLabel(profile.ThreatScore), profile.ThreatScore,
				toolOrDash(profile.Behavior.ToolBehavior.LikelyTool),
				strings.Join(profile.Tags, ","),
			)
		} else {
			updated++
			fmt.Printf("  [~] UPD  %s  score=%.0f  sessions=%d\n",
				profile.ID[:16]+"...", profile.ThreatScore, len(profile.Sessions))
		}
	}

	fmt.Printf("\n  ✓  Ingestion complete.\n")
	fmt.Printf("     New profiles     : %d\n", newP)
	fmt.Printf("     Updated profiles : %d\n", updated)
	if skipped > 0 {
		fmt.Printf("     Skipped          : %d\n", skipped)
	}
	fmt.Printf("\n  Tip: Run 'ghostwriter correlate' to detect same-actor clusters.\n\n")
	return nil
}

// ─── profiles ────────────────────────────────────────────────────────────────

func runProfiles(dbPath string, limit int) error {
	store, err := storage.Open(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	profiles, err := store.GetAllProfiles()
	if err != nil {
		return err
	}
	alerts, _ := store.GetAllAlerts()
	sortProfilesByScore(profiles)

	r := reporter.New("")
	out, err := r.Generate(reporter.ReportData{
		GeneratedAt: time.Now(),
		Profiles:    limitProfiles(profiles, limit),
		Alerts:      alerts,
	}, reporter.FormatTerminal)
	if err != nil {
		return err
	}
	fmt.Print(out)
	return nil
}

// ─── profile ─────────────────────────────────────────────────────────────────

func runProfile(dbPath, id string) error {
	if id == "" {
		return fmt.Errorf("--id is required. Example: ghostwriter profile --id <profile-id>")
	}
	store, err := storage.Open(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	p, err := store.GetProfile(id)
	if err != nil {
		return fmt.Errorf("profile not found: %s\n  Use 'ghostwriter profiles' to list all IDs", id)
	}

	fmt.Printf("\n  👻 Attacker Profile\n")
	fmt.Printf("  ─────────────────────────────────────────────\n")
	fmt.Printf("  ID            : %s\n", p.ID)
	fmt.Printf("  Fingerprint   : %s...\n", p.Fingerprint[:32])
	fmt.Printf("  Threat Score  : %s%.0f / 100\n", threatLabel(p.ThreatScore), p.ThreatScore)
	fmt.Printf("  Confidence    : %.0f%%\n", p.Confidence*100)
	fmt.Printf("  First Seen    : %s\n", p.FirstSeen.Format(time.RFC1123))
	fmt.Printf("  Last Seen     : %s\n", p.LastSeen.Format(time.RFC1123))
	fmt.Printf("  Sessions      : %d\n", len(p.Sessions))
	if len(p.Tags) > 0 {
		fmt.Printf("  Tags          : %s\n", strings.Join(p.Tags, ", "))
	}

	fmt.Printf("\n  BEHAVIORAL FINGERPRINT:\n")
	fmt.Printf("  ─────────────────────────────────────────────\n")
	if p.Behavior.TLSFingerprint != "" {
		fmt.Printf("  TLS (JA3)     : %s\n", p.Behavior.TLSFingerprint)
	}
	if len(p.Behavior.HTTPFingerprint.HeaderOrder) > 0 {
		fmt.Printf("  HTTP Headers  : %v\n", p.Behavior.HTTPFingerprint.HeaderOrder)
	}
	if p.Behavior.HTTPFingerprint.AcceptEncoding != "" {
		fmt.Printf("  Accept-Enc    : %s\n", p.Behavior.HTTPFingerprint.AcceptEncoding)
	}
	if p.Behavior.HTTPFingerprint.AcceptLanguage != "" {
		fmt.Printf("  Accept-Lang   : %s\n", p.Behavior.HTTPFingerprint.AcceptLanguage)
	}
	fmt.Printf("  Session Dur   : %.1fs avg\n", p.Behavior.SessionDuration)
	if p.Behavior.ToolBehavior.LikelyTool != "" {
		fmt.Printf("  Tool          : %s (confidence=%.0f%%)\n",
			p.Behavior.ToolBehavior.LikelyTool, p.Behavior.ToolBehavior.Confidence*100)
	}

	if len(p.Sessions) > 0 {
		fmt.Printf("\n  SOURCE IPs OBSERVED:\n")
		seen := make(map[string]struct{})
		for _, s := range p.Sessions {
			if _, ok := seen[s.SourceIP]; !ok {
				seen[s.SourceIP] = struct{}{}
				fmt.Printf("    • %s  (%s)\n", s.SourceIP, s.StartTime.Format("2006-01-02 15:04"))
			}
		}
	}

	if len(p.Behavior.ScanPatterns) > 0 {
		fmt.Printf("\n  ATTACK PROBES:\n")
		probeSet := make(map[string]struct{})
		for _, scan := range p.Behavior.ScanPatterns {
			for _, probe := range scan.ProbeTypes {
				probeSet[probe] = struct{}{}
			}
			if scan.ScanRate > 0 {
				fmt.Printf("    Rate : %.1f req/s\n", scan.ScanRate)
			}
		}
		for probe := range probeSet {
			fmt.Printf("    • %s\n", probe)
		}
	}
	fmt.Println()
	return nil
}

// ─── correlate ───────────────────────────────────────────────────────────────

func runCorrelate(dbPath string) error {
	store, err := storage.Open(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	profiles, err := store.GetAllProfiles()
	if err != nil {
		return err
	}

	if len(profiles) == 0 {
		fmt.Print("\n  No profiles found. Run 'ghostwriter ingest' first.\n\n")
		return nil
	}

	engine := fingerprint.NewEngine(fingerprint.DefaultConfig())
	for _, p := range profiles {
		engine.LoadProfile(p)
	}

	fmt.Printf("\n  Correlating %d profile(s)...\n\n", len(profiles))

	correlator := correlation.NewCorrelator(engine, correlation.DefaultConfig())
	clusters, err := correlator.CorrelateAll()
	if err != nil {
		return err
	}

	if len(clusters) == 0 {
		fmt.Print("  No attacker clusters detected. All profiles appear to be unique actors.\n")
		fmt.Print("  (Tip: Ingest more sessions to improve correlation accuracy)\n\n")
		return nil
	}

	fmt.Printf("  [!] %d Attacker Cluster(s) Detected!\n\n", len(clusters))
	for i, c := range clusters {
		fmt.Printf("  Cluster #%d  confidence=%.0f%%  tags=%s\n",
			i+1, c.Confidence*100, strings.Join(c.Tags, ","))

		allIPs := make(map[string]struct{})
		for _, p := range c.Profiles {
			for _, s := range p.Sessions {
				allIPs[s.SourceIP] = struct{}{}
			}
		}
		for _, p := range c.Profiles {
			fmt.Printf("    -> %s  score=%.0f  sessions=%d\n",
				p.ID[:16]+"...", p.ThreatScore, len(p.Sessions))
		}
		ipList := make([]string, 0, len(allIPs))
		for ip := range allIPs {
			ipList = append(ipList, ip)
		}
		fmt.Printf("     Unique IPs: %s\n\n", strings.Join(ipList, ", "))
	}

	fmt.Print("  Tip: Run 'ghostwriter report --format html' for a full visual report.\n\n")
	return nil
}

// ─── report ───────────────────────────────────────────────────────────────────

func runReport(dbPath, outputDir, format string) error {
	store, err := storage.Open(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	profiles, err := store.GetAllProfiles()
	if err != nil {
		return err
	}
	alerts, _ := store.GetAllAlerts()
	sortProfilesByScore(profiles)

	engine := fingerprint.NewEngine(fingerprint.DefaultConfig())
	for _, p := range profiles {
		engine.LoadProfile(p)
	}
	correlator := correlation.NewCorrelator(engine, correlation.DefaultConfig())
	clusters, _ := correlator.CorrelateAll()

	r := reporter.New(outputDir)
	result, err := r.Generate(reporter.ReportData{
		GeneratedAt: time.Now(),
		Profiles:    profiles,
		Clusters:    clusters,
		Alerts:      alerts,
		Stats:       engine.Stats(),
	}, reporter.Format(format))
	if err != nil {
		return err
	}

	fmt.Print(result)
	return nil
}

// ─── alerts ───────────────────────────────────────────────────────────────────

func runAlerts(dbPath, severityFilter string) error {
	store, err := storage.Open(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	alerts, err := store.GetAllAlerts()
	if err != nil {
		return err
	}

	if severityFilter != "" {
		sf := models.Severity(strings.ToUpper(severityFilter))
		filtered := alerts[:0]
		for _, a := range alerts {
			if a.Severity == sf {
				filtered = append(filtered, a)
			}
		}
		alerts = filtered
	}

	if len(alerts) == 0 {
		if severityFilter != "" {
			fmt.Printf("\n  No alerts with severity %s.\n\n", strings.ToUpper(severityFilter))
		} else {
			fmt.Print("\n  No active alerts. Run 'ghostwriter ingest' to analyze sessions.\n\n")
		}
		return nil
	}

	sortAlerts(alerts)

	fmt.Printf("\n  Active Alerts (%d)\n\n", len(alerts))
	for _, a := range alerts {
		fmt.Printf("  [%s] %s — %s\n", a.Severity, a.Timestamp.Format("2006-01-02 15:04:05"), a.Description)
		fmt.Printf("         Profile : %s...\n", a.ProfileID[:16])
		if a.SourceIP != "" {
			fmt.Printf("         Source  : %s\n", a.SourceIP)
		}
		fmt.Printf("         Action  : %s\n\n", a.Recommended)
	}
	return nil
}

// ─── flush ───────────────────────────────────────────────────────────────────

func runFlush(dbPath, olderThan string) error {
	dur, err := time.ParseDuration(olderThan)
	if err != nil {
		return fmt.Errorf("invalid duration %q (example: 720h, 168h): %w", olderThan, err)
	}

	store, err := storage.Open(dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	profiles, err := store.GetAllProfiles()
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-dur)
	removed := 0
	for _, p := range profiles {
		if p.LastSeen.Before(cutoff) {
			if err := store.DeleteProfile(p.ID); err != nil {
				fmt.Printf("  [!] Could not delete %s: %v\n", p.ID[:16], err)
				continue
			}
			removed++
		}
	}

	fmt.Printf("\n  Flush complete.\n")
	fmt.Printf("  Cutoff    : %s\n", cutoff.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Removed   : %d profile(s)\n", removed)
	fmt.Printf("  Remaining : %d profile(s)\n\n", len(profiles)-removed)
	return nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func generateAlerts(profile *models.AttackerProfile) []*models.Alert {
	if profile.ThreatScore < 40 {
		return nil
	}

	severity := models.SeverityMedium
	desc := ""
	action := ""

	switch {
	case profile.ThreatScore >= 80:
		severity = models.SeverityCritical
		desc = fmt.Sprintf("Critical threat actor detected (score=%.0f)", profile.ThreatScore)
		action = "Block source IPs immediately and escalate to SOC. Preserve logs for forensics."
	case profile.ThreatScore >= 60:
		severity = models.SeverityHigh
		desc = fmt.Sprintf("High-threat actor detected (score=%.0f)", profile.ThreatScore)
		action = "Review traffic, apply rate-limiting, and monitor for escalation."
	default:
		desc = fmt.Sprintf("Suspicious behavioral pattern detected (score=%.0f)", profile.ThreatScore)
		action = "Monitor closely. Consider adding to watchlist."
	}

	if profile.Behavior.ToolBehavior.LikelyTool != "" {
		desc += fmt.Sprintf(" — tool: %s", profile.Behavior.ToolBehavior.LikelyTool)
	}

	sourceIP := ""
	if len(profile.Sessions) > 0 {
		sourceIP = profile.Sessions[len(profile.Sessions)-1].SourceIP
	}

	return []*models.Alert{{
		ID:          fmt.Sprintf("alert-%s-%d", profile.ID[:8], time.Now().UnixNano()),
		Timestamp:   time.Now(),
		Severity:    severity,
		ProfileID:   profile.ID,
		SourceIP:    sourceIP,
		Description: desc,
		Evidence:    profile.Tags,
		Recommended: action,
	}}
}

func threatLabel(score float64) string {
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

func toolOrDash(tool string) string {
	if tool == "" {
		return "—"
	}
	return tool
}

func sortProfilesByScore(profiles []*models.AttackerProfile) {
	for i := 1; i < len(profiles); i++ {
		for j := i; j > 0 && profiles[j].ThreatScore > profiles[j-1].ThreatScore; j-- {
			profiles[j], profiles[j-1] = profiles[j-1], profiles[j]
		}
	}
}

func sortAlerts(alerts []*models.Alert) {
	rank := func(s models.Severity) int {
		switch s {
		case models.SeverityCritical:
			return 4
		case models.SeverityHigh:
			return 3
		case models.SeverityMedium:
			return 2
		default:
			return 1
		}
	}
	for i := 1; i < len(alerts); i++ {
		for j := i; j > 0; j-- {
			ri, rj := rank(alerts[j].Severity), rank(alerts[j-1].Severity)
			if ri > rj || (ri == rj && alerts[j].Timestamp.After(alerts[j-1].Timestamp)) {
				alerts[j], alerts[j-1] = alerts[j-1], alerts[j]
			} else {
				break
			}
		}
	}
}

func limitProfiles(profiles []*models.AttackerProfile, limit int) []*models.AttackerProfile {
	if limit <= 0 || limit >= len(profiles) {
		return profiles
	}
	return profiles[:limit]
}
