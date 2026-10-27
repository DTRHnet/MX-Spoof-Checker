# MX Spoof Checker

> **Email security spoofability scanner** — checks SPF, DKIM, DMARC, MX for domains to identify configurations vulnerable to email spoofing.

## What It Does

Scans domains for email authentication misconfigurations and tells you **whether a spoofed message would actually be delivered** (not just bounced).

```
🟢 dtrh.net        Score:   0  Tier: LOW       🛡️ Deliverable: False  Risk: LOW
🔴 github.com      Score:  70  Tier: CRITICAL  🚨 Deliverable: True   Risk: HIGH
🟠 google.com      Score:  40  Tier: HIGH      🚨 Deliverable: True   Risk: MEDIUM
🟠 test.org        Score:  60  Tier: HIGH      🚨 Deliverable: True   Risk: HIGH
```

## Features

- **SPF** — Checks record existence, `all` mechanism (`-all`, `~all`, `+all`, `none`), includes
- **DKIM** — Queries 7 common selectors (`default`, `selector1`, `selector2`, `mail`, `k1`, `k2`, `dkim`)
- **DMARC** — Checks policy (`p=none/quarantine/reject`), subdomain policy, reporting addresses
- **MX** — Verifies mail exchangers exist
- **Delivery Spoofability Assessment** — Determines if a spoofed message using the domain as envelope sender would be *delivered* (based on the blog post incident where spam was accepted and only failed due to recipient quota)
- **Scoring** — 0-100 spoofability score with tiers: CRITICAL/HIGH/MEDIUM/LOW
- **Exports** — JSON + CSV with timestamps

## Installation

```bash
# Requires Python 3.8+
pip install dnspython tldextract
# Optional: for pretty output
pip install rich
```

## Usage

```bash
# Use default domain_list.txt (contains dtrh.net)
python dtrh_mail_poc.py

# Custom input file (one domain per line, # comments ignored)
python dtrh_mail_poc.py -i domains.txt

# Direct domains (space-separated)
python dtrh_mail_poc.py dtrh.net github.com google.com

# Verbose per-domain detail
python dtrh_mail_poc.py -v

# JSON output only (for scripting)
python dtrh_mail_poc.py --json
```

## Example Output

```
[STEP 1] Reading domains...
         Source: command line arguments
         Loaded: 3 raw entries

[STEP 2] Sanitizing domains...
         3 → 3 unique domains after deduplication

[STEP 3] Checking domains (10 workers)...
  [1/3] 🟢 dtrh.net        Score:   0  Tier: LOW       🛡️ Deliverable: False  Risk: LOW
  [2/3] 🔴 github.com      Score:  70  Tier: CRITICAL  🚨 Deliverable: True   Risk: HIGH
  [3/3] 🟠 google.com      Score:  40  Tier: HIGH      🚨 Deliverable: True   Risk: MEDIUM

[STEP 4] Summary
  CRITICAL: 1
  HIGH:     1
  MEDIUM:   0
  LOW:      1

  Detailed results saved to:
    JSON: results/results_20261027_161910.json
    CSV:  results/results_20261027_161910.csv
```

## Scoring Logic

| Factor | Points |
|--------|--------|
| No SPF / `+all` / missing `all` | +30 |
| SPF `~all` (softfail) | +15 |
| SPF `?all` (neutral) | +20 |
| SPF `-all` (hardfail) | +0 |
| No DMARC | +30 |
| DMARC `p=none` | +20 |
| DMARC `p=quarantine` | +10 |
| DMARC `p=reject` | +0 |
| No valid DKIM keys | +15 |
| No MX records | +5 |
| Cloud provider in SPF includes (Gmail, Outlook, SES, SendGrid, etc.) | +10 each |

**Tiers:** CRITICAL (≥70) • HIGH (40-69) • MEDIUM (20-39) • LOW (0-19)

## Delivery Spoofability

The key insight from [the blog post](https://dtrh.net/blog/your-domain-is-sending-spam): **a spoofed message is *delivered* if the receiving server accepts it**. The scanner assesses:

- `DMARC p=reject` + `SPF -all` → **NOT deliverable** 🛡️
- `DMARC p=quarantine` / `p=none` / missing → **Deliverable** 🚨
- `SPF ~all` without DMARC reject → **Deliverable** 🚨

## Requirements

- Python 3.8+
- `dnspython` (DNS queries)
- `tldextract` (domain sanitization)
- Optional: `rich` (colored output)

Stdlib fallbacks included — runs with zero deps if needed.

## License

MIT