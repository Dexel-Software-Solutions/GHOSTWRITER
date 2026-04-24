<div align="center">

<!-- Animated Title -->
<h2> GHOSTWRITER >_ <h2>

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=500&size=18&duration=2500&pause=800&color=3FB950&center=true&vCenter=true&width=800&lines=Behavioral+Attacker+Intelligence+Framework;Same+attacker.+Different+IP.+Still+caught.;IP+rotated%3F+Doesn't+matter.;VPN+switched%3F+We+see+through+it.;Tor+exit+changed%3F+The+ghost+has+a+face." alt="Tagline" />

<br/>

<!-- Badges -->
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-3FB950?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-58A6FF?style=for-the-badge&logo=linux&logoColor=white)]()
[![Category](https://img.shields.io/badge/Category-Threat_Intelligence-F85149?style=for-the-badge&logo=shield&logoColor=white)]()
[![Status](https://img.shields.io/badge/Status-Active-3FB950?style=for-the-badge)]()

<br/>

> **GHOSTWRITER** tracks *how* attackers behave — not *where* they connect from.  
> While adversaries rotate VPNs, Tor exits, and proxies, their **behavioral DNA** stays constant.  
> GHOSTWRITER reads it.

<br/>

</div>

---

## 🧬 The Core Idea

Traditional security tools block IPs. Attackers rotate IPs. Game over — for traditional tools.

GHOSTWRITER fingerprints the **attacker's behavior itself**: the cryptographic handshake, the HTTP header order, the timing rhythm, the tool signature. These don't change when the IP changes.

```
Traditional Tools:          GHOSTWRITER:
──────────────────────      ─────────────────────────────────────────
Block 185.220.101.45   →   TLS JA3:        a0e9f5d64c3...    ┐
Block 91.108.4.12      →   HTTP Headers:   [Accept, UA, Enc]  ├─ SAME ATTACKER
Block 45.141.84.83     →   Timing pattern: 0.5s burst rhythm  ┘
                            Tool:           sqlmap/1.7.8
                            → Threat Score: 87/100  [CRITICAL]
```

---

## ✨ Features

<table>
<tr>
<td width="50%" valign="top">

### 🔬 Behavioral Fingerprinting
- **TLS / JA3** fingerprinting — cryptographic handshake patterns
- **HTTP stack analysis** — header order, Accept-* values, Connection type
- **TCP fingerprinting** — OS-level window size, TTL, MSS
- **Tool detection** — sqlmap, nmap, nikto, masscan, zgrab, curl + custom
- **Timing rhythm** — inter-request delay cosine similarity
- **Payload hashing** — attack pattern tracking across sessions

</td>
<td width="50%" valign="top">

### 🔗 Cross-IP Correlation
- **Weighted 7-signal similarity scoring**
- **Attacker clustering** via Union-Find algorithm
- **Confidence scoring** per correlation match
- **Profile merging** — fingerprints refine over time
- **Temporal pattern analysis** — time-of-day activity
- **Probe type overlap** — attack target consistency

</td>
</tr>
<tr>
<td valign="top">

### 🎯 Threat Intelligence
- **0–100 threat scoring** — risk-based prioritization
- **Automatic tagging** — `scanner`, `sql-injection`, `path-traversal`, etc.
- **Severity alerts** — AUTO → LOW / MEDIUM / HIGH / CRITICAL
- **Profile timeline** — first seen, last seen, session count
- **Source IP history** — all observed IPs per behavioral identity
- **Complete session audit trail**

</td>
<td valign="top">

### 📊 Reporting & Output
- **Rich terminal tables** — ANSI threat indicators
- **HTML reports** — dark-theme standalone intelligence dashboards
- **JSON export** — machine-readable, SIEM-ready
- **`flush`** — TTL-based profile expiry
- **`correlate`** — on-demand cross-profile cluster analysis
- **Zero external dependencies** — pure Go standard library

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

- **Go 1.22+** → [go.dev/dl](https://go.dev/dl)
- Linux / macOS / Windows

### Build & Run

```bash
# 1. Clone
git clone https://github.com/Dexel-Software-Solutions/ghostwriter.git
cd ghostwriter

# 2. Build
go build -o ghostwriter ./cmd/ghostwriter

# 3. Ingest sessions
./ghostwriter ingest --file examples/sessions.json

# 4. Correlate — find same actor across different IPs
./ghostwriter correlate

# 5. Generate HTML report
./ghostwriter report --format html
```

Or use the Makefile:

```bash
make build          # compile binary
make run-example    # ingest + correlate + HTML report in one shot
make test           # run all unit tests
```

---

## 🛠️ Commands

```
ghostwriter <command> [flags]

Commands:
  ingest      Ingest a JSON session file for behavioral analysis
  profiles    List all attacker profiles
  profile     Show a specific profile by ID
  correlate   Run cross-IP attacker correlation
  report      Generate a report  (terminal | json | html)
  alerts      List active alerts
  flush       Remove profiles older than a given duration
  version     Print version info
  help        Show help
```

### Examples

```bash
# Ingest sessions from a custom database path
./ghostwriter ingest --file /var/log/sessions.json --db /opt/ghostwriter/data.db

# List top 20 profiles by threat score
./ghostwriter profiles --limit 20

# Deep-dive on a specific attacker
./ghostwriter profile --id 506ae28b7b44da19...

# Filter alerts by severity
./ghostwriter alerts --severity CRITICAL

# Export JSON report (SIEM-ready)
./ghostwriter report --format json --output ./exports

# Purge profiles inactive for 30 days
./ghostwriter flush --older-than 720h
```

---

## 📋 Session JSON Format

GHOSTWRITER ingests sessions in a simple JSON schema. Point it at your parsed log data:

```json
[
  {
    "id":          "sess-001",
    "start_time":  "2024-01-15T10:00:00Z",
    "end_time":    "2024-01-15T10:00:05Z",
    "source_ip":   "185.220.101.45",
    "source_port": 54321,
    "protocol":    "HTTP/1.1",
    "requests": [
      {
        "timestamp":     "2024-01-15T10:00:00Z",
        "method":        "GET",
        "path":          "/login.php?id=1'",
        "headers": {
          "User-Agent":      "sqlmap/1.7.8",
          "Accept-Encoding": "gzip, deflate",
          "Accept-Language": "en-US,en;q=0.5",
          "Connection":      "keep-alive"
        },
        "response_code": 500,
        "bytes_sent":    512,
        "bytes_recv":    256,
        "latency":       120.0
      }
    ]
  }
]
```

A ready-to-use example with 3 sessions (SQLMap × 2 IPs + Nikto) is at [`examples/sessions.json`](examples/sessions.json).

---

## 🏗️ Architecture

```
ghostwriter/
├── cmd/ghostwriter/
│   ├── main.go                    # Binary entry point
│   └── commands/
│       └── root.go                # CLI — all subcommands
│
├── internal/
│   ├── fingerprint/
│   │   ├── engine.go              # 🧬 Behavioral fingerprinting engine
│   │   └── engine_test.go         # Unit tests (11 tests)
│   ├── correlation/
│   │   └── correlator.go          # 🔗 Cross-session attacker correlation
│   ├── reporter/
│   │   └── reporter.go            # 📊 Terminal / HTML / JSON report generation
│   └── storage/
│       └── store.go               # 💾 JSON persistent store
│
├── pkg/
│   └── models/
│       └── models.go              # 📐 Core data structures
│
├── examples/
│   └── sessions.json              # Sample sessions for testing
│
└── configs/
    └── ghostwriter.yaml           # Default configuration
```

### Signal Pipeline

```
Raw HTTP Session
       │
       ▼
┌─────────────────────────────────────────────┐
│           fingerprint.Engine                │
│                                             │
│  TLS / JA3     ──┐                          │
│  HTTP Headers  ──┼──► BehaviorVector        │
│  TCP Stack     ──┤        │                 │
│  Timing        ──┤        ▼                 │
│  Tool Sig      ──┘   SHA-256 Hash           │
│  Probe Types         + Similarity Search    │
│                           │                 │
│                    Match? ─┬─ No  → New Profile
│                            └─ Yes → Update Profile
└─────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────┐
│          correlation.Correlator             │
│                                             │
│  Profile A ─┐                               │
│             ├──► Weighted Similarity Score  │
│  Profile B ─┘        (7 signals)            │
│                           │                 │
│                     ≥ 0.72 threshold?       │
│                      → Cluster (Union-Find) │
└─────────────────────────────────────────────┘
```

### Behavioral Signal Weights

| Signal | Weight | Description |
|--------|-------:|-------------|
| TLS / JA3 Fingerprint | **30%** | Cryptographic handshake — most stable cross-IP signal |
| HTTP Header Order | **20%** | Header sequence is tool/client-specific |
| TCP Stack | **20%** | OS-level: window size, TTL, MSS |
| Attack Tool | **15%** | sqlmap, nikto, nmap, masscan fingerprint |
| Probe Type Overlap | **10%** | SQLi, path traversal, admin probes |
| Timing Pattern | **5%** | Inter-request cosine similarity |

Correlation threshold: **≥ 72%** weighted similarity → same attacker.

---

## 🔌 API Usage (Go)

Embed GHOSTWRITER's engine directly in your own tooling:

```go
import (
    "github.com/Dexel-Software-Solutions/ghostwriter/internal/fingerprint"
    "github.com/Dexel-Software-Solutions/ghostwriter/internal/correlation"
    "github.com/Dexel-Software-Solutions/ghostwriter/pkg/models"
)

// Initialize engine
engine := fingerprint.NewEngine(fingerprint.DefaultConfig())

// Ingest a session
profile, err := engine.IngestSession(models.Session{
    ID:       "sess-001",
    SourceIP: "185.220.101.45",
    Requests: []models.Request{
        {
            Method: "GET",
            Path:   "/login.php?id=1'",
            Headers: map[string]string{
                "User-Agent":      "sqlmap/1.7.8",
                "Accept-Encoding": "gzip, deflate",
            },
        },
    },
})

fmt.Printf("Profile ID:    %s\n", profile.ID)
fmt.Printf("Threat Score:  %.0f / 100\n", profile.ThreatScore)
fmt.Printf("Tags:          %v\n", profile.Tags)
fmt.Printf("Detected Tool: %s\n", profile.Behavior.ToolBehavior.LikelyTool)

// Run correlation across all profiles
correlator := correlation.NewCorrelator(engine, correlation.DefaultConfig())
clusters, _ := correlator.CorrelateAll()
fmt.Printf("Clusters found: %d\n", len(clusters))
```

### SIEM Integration

```bash
# Stream high-threat profiles to SIEM / jq pipeline
./ghostwriter report --format json | \
  jq '.profiles[] | select(.threat_score >= 70) | {id, threat_score, tags}'
```

---

## 🗺️ Roadmap

- [x] **v1.0** — Behavioral fingerprinting engine (TLS, HTTP, TCP, Timing, Tool)
- [x] **v1.0** — Cross-IP attacker correlation & clustering
- [x] **v1.0** — Multi-format reporting (Terminal, HTML, JSON)
- [x] **v1.0** — Persistent JSON storage, alert generation, profile TTL flush
- [ ] **v1.1** — NGINX / Apache / HAProxy log parsers
- [ ] **v1.1** — Live JA3 / JA3S TLS fingerprinting (gopacket)
- [ ] **v1.2** — HTTP/2 HPACK header fingerprinting
- [ ] **v1.2** — REST API server mode
- [ ] **v1.3** — Prometheus metrics endpoint
- [ ] **v1.4** — Web dashboard (React / Svelte)
- [ ] **v2.0** — ML-based behavioral clustering (DBSCAN)
- [ ] **v2.0** — Threat feed integration (GreyNoise, AlienVault OTX, Shodan)
- [ ] **v2.1** — Distributed sensor mode — multi-node correlation

---

## ⚠️ Legal & Ethics

GHOSTWRITER is a **defensive security** tool — built to protect infrastructure you own or are authorized to monitor.

| ✅ Permitted | ❌ Not Permitted |
|---|---|
| Analyzing traffic to your own servers | Monitoring third-party traffic without authorization |
| Incident response and threat hunting | Offensive use against systems you don't own |
| Security research in controlled lab environments | Any use that violates applicable law |
| SOC integration and alerting | — |

Always ensure your use complies with applicable laws and organizational policies.

---

## 🤝 Contributing

Contributions are welcome — especially:
- New fingerprinting signals (HTTP/2, QUIC, WebSocket)
- Log format parsers (NGINX, Apache, AWS ALB, Cloudflare)
- Correlation algorithm improvements
- New export formats

```bash
git clone https://github.com/Dexel-Software-Solutions/ghostwriter.git
cd ghostwriter
go test ./...           # run all tests
go vet ./...            # lint
```

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting pull requests.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

<br/>

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=13&duration=4000&pause=1000&color=8B949E&center=true&vCenter=true&width=700&lines=Built+by+Demiyan+Dissanayake+%7C+Dexel+Software+Solutions;dexelsoftwaresolutions%40gmail.com;%22The+ghost+leaves+no+footprints+%E2%80%94+but+we+see+the+ghost.%22" alt="Footer" />

<br/>

[![GitHub](https://img.shields.io/badge/GitHub-Dexel--Software--Solutions-181717?style=for-the-badge&logo=github)](https://github.com/Dexel-Software-Solutions)
[![Email](https://img.shields.io/badge/Email-Contact-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:dexelsoftwaresolutions@gmail.com)

</div>
