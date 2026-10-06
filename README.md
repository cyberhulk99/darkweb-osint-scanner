# WODS — Dark Web OSINT Monitor

Continuously monitors the dark web for mentions of your organisation — leaked credentials, breach data, ransomware victim listings, paste dumps, and more.

---

## How it works

```
org_profile.toml  ← your org's domains, email pattern, infra keywords
      │
      ▼
scanner.py        ← Tor-proxied HTTP queries to:
                     • Ahmia (.onion + clearnet)   ← indexes .onion sites
                     • Torch (.onion)              ← dark web search engine
                     • Haystak (.onion)            ← dark web search engine
                     • Paste sites (.onion)        ← raw credential dumps
                     • Ransomware blogs (.onion)   ← victim announcement pages
      │
      ▼
analyzer.py       ← context-aware pattern matching
                     finds org keyword → scans ±300 char window
                     scores severity by what's found nearby:
                       CRITICAL  email:password combos, private keys, AWS/API tokens
                       HIGH      db dumps, source code, HR data, infra keywords
                       MEDIUM    org near breach/sale/leaked/confidential terms
                       LOW       general dark web mentions
      │
      ▼
result_store.py   ← SQLite deduplication (same finding never re-alerts)
      │
      ▼
alert.py          ← colour-coded console  +  data/alerts.log  +  optional Slack
```

---

## Setup

### 1. Install Tor
```bash
# Ubuntu / Debian
sudo apt install tor
sudo service tor start

# Kali Linux
sudo apt install tor
sudo systemctl enable --now tor
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure your organisation
Edit `config/org_profile.toml`:
```toml
[organization]
name         = "Acme Corp"
domains      = ["acmecorp.com", "acme.io"]
email_domain = "acmecorp.com"
subsidiaries = ["Acme Labs"]
executives   = []            # optional: adds name-based search keywords
keywords_extra = []          # any extra terms

[infrastructure]
internal_names = ["jira", "confluence", "vpn.acme", "okta.acme"]
ip_ranges      = []          # public IP ranges you own
cloud_buckets  = []          # S3/GCS bucket names

[monitoring]
interval_hours        = 6
min_severity          = "medium"   # low / medium / high / critical
max_results_per_query = 10
```

### 4. (Optional) Add ransomware blog addresses
Populate `config/ransomware_blogs.txt` from:
- https://www.ransomlook.io/      ← community-maintained tracker
- https://ransomwatch.telemetry.ltd ← open-source tracker

These groups publicly post victim names — monitoring them is standard threat intel practice.

### 5. (Optional) Slack alerts
```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

---

## Usage

```bash
cd scripts/

# One-shot scan
python3 darkwebosint.py

# Continuous monitoring (interval from profile, default 6h)
python3 darkwebosint.py --continuous

# Override org name
python3 darkwebosint.py -org "Acme Corp" --continuous

# Custom interval (every 2 hours)
python3 darkwebosint.py --continuous --interval 2

# Custom profile file
python3 darkwebosint.py --profile /path/to/profile.toml --continuous
```

---

## Output

| Location | Contents |
|---|---|
| `data/alerts.log` | Persistent log of every new finding with severity, source, URL, context |
| `data/findings.db` | SQLite deduplication store — prevents re-alerting on seen content |
| `logs/session_*.log` | Per-session debug log |

---

## What gets detected

| Severity | Examples |
|---|---|
| CRITICAL | `user@acme.com:password123` combo lists, SSH/RSA private keys, AWS AKIA keys, GitHub/Slack tokens |
| HIGH | Database dumps mentioning org, source code leaks, VPN/AD/LDAP infra references, HR/payroll data |
| MEDIUM | Org name near "breach", "for sale", "confidential", "internal" on dark web pages |
| LOW | General org name mentions on .onion forums |

---

## Notes

- All HTTP requests route through Tor (SOCKS5 `127.0.0.1:9050`)
- Findings are deduplicated in SQLite — the same content never fires a second alert
- Set `min_severity = "high"` in the profile to reduce noise on your first run
- The old multi-tool runner (`runner.py`) still works as a standalone; the main pipeline now goes through `scanner.py` + `analyzer.py`
