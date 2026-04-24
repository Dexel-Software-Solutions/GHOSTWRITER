# Contributing to GHOSTWRITER

Thank you for contributing to GHOSTWRITER!

## Getting Started

```bash
git clone https://github.com/Dexel-Software-Solutions/ghostwriter.git
cd ghostwriter
go mod tidy
go build ./...
go test ./...
```

## Areas Where Contributions Are Especially Valuable

### New Fingerprinting Signals
The `internal/fingerprint/engine.go` is the heart of GHOSTWRITER. New signals:
- **HTTP/2 HPACK fingerprinting** — frame weight patterns
- **Mouse/keyboard timing** (for web app contexts)
- **DNS resolution patterns**
- **Certificate pinning behavior**

### Log Format Parsers
`parseLogFile()` in `commands/root.go` needs real implementations for:
- NGINX combined log format
- Apache Combined Log Format
- HAProxy logs
- Cloudflare JSON logs
- AWS ALB access logs

### Correlation Improvements
`internal/correlation/correlator.go` can be improved with:
- ML-based clustering (k-means, DBSCAN on behavioral vectors)
- Temporal correlation (attack campaign detection)
- ASN-aware correlation

## Code Style

- All exported functions must have godoc comments
- Include engineer attribution in new package files
- Follow standard Go conventions (`gofmt`, `go vet`)
- Write tests for new fingerprinting signals

## Contact

- **Engineer:** Demiyan Dissanayake
- **Email:** dexelsoftwaresolutions@gmail.com
- **GitHub:** https://github.com/Dexel-Software-Solutions
