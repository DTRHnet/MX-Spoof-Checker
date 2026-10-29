# Your Domain Is Sending Spam (Spoiler: It's Not You)

> **How a bounce exposed my SPF/DMARC gap — and how I fixed it in 3 Cloudflare commands**

---

**Published:** 2026-10-27  
**Author:** kbs <admin@dtrh.net>  
**Domain:** dtrh.net  
**Tools:** [MX-Spoof-Checker](https://github.com/DTRHnet/MX-Spoof-Checker) — `dtrh_mail_poc.py` (scanner) + `dtrh_mail_send.py` (demo spoofer)

---

## 🔧 Tools & Repository

All code from this investigation is available at:

**GitHub: [DTRHnet/MX-Spoof-Checker](https://github.com/DTRHnet/MX-Spoof-Checker)**

| Tool | Purpose |
|------|---------|
| `dtrh_mail_poc.py` | **Scanner** — Checks SPF, DKIM, DMARC, MX; calculates spoofability score and delivery risk |
| `dtrh_mail_send.py` | **Spoofer (Demo)** — Sends test emails with custom MAIL FROM / From: header |

```bash
git clone https://github.com/DTRHnet/MX-Spoof-Checker.git
cd MX-Spoof-Checker
pip install dnspython tldextract rich

# Scan domains
python dtrh_mail_poc.py dtrh.net github.com google.com -v

# Test spoofing (configure SMTP first)
cp dtrh_mail_send.conf.example dtrh_mail_send.conf
# Edit with your SMTP credentials
python dtrh_mail_send.py "spoofed@yourdomain.com" "Test" "This is a spoof test"
```

> ⚠️ **`dtrh_mail_send.py` is for educational/testing purposes only.** Only use against domains you own or have explicit permission to test.

---

## The Backstory

I've owned `dtrh.net` for about four years. Started with hosting.com as a mail host (before A2 Hosting acquired them). Ran WordPress, then Hexo, then custom Node.js. Now it's a Next.js app on Vercel — free, fast, no server maintenance.

**The catch:** Vercel doesn't do email. I needed `admin@dtrh.net` → Gmail without running a mail server. Found ImprovMX. Setup: `email → admin@dtrh.net → ImprovMX forward → Gmail`. Simple, free, works.

One day I checked spam and found a bounce claiming to be *from* `ikmfgvivz@dtrh.net` — an address that doesn't exist in my ImprovMX config. The spam advertised counterfeit accessories, addressed to `18@bar18.jp`. The bounce came from `MAILER-DAEMON@www478.sakura.ne.jp` (Sakura Internet, Japan).

**Immediate questions:** Was my Gmail compromised? My ImprovMX account? Is my domain wide open for spoofing?

---

## The Bounce

```
Returned mail: see transcript for details
Mail Delivery Subsystem <MAILER-DAEMON@www478.sakura.ne.jp>
from localhost [127.0.0.1]
Final-Recipient: RFC822; 18@bar18.jp
X-Actual-Recipient: RFC822; 18@www478.sakura.ne.jp
Action: failed
Status: 5.3.0

maildrop: maildir over quota.
550 5.0.0 ... Insufficient permission
```

**Translation:** A spam message claiming `From: ikmfgvivz@dtrh.net` tried to reach `18@bar18.jp`. Sakura accepted it, handed it off locally (`localhost [127.0.0.1]`), then failed delivery because the *recipient's* mailbox was over quota. The bounce went to the envelope sender — `ikmfgvivz@dtrh.net`.

---

## My Infrastructure (Live DNS, 2026-10-27)

| Record | Value |
|--------|-------|
| **MX** | `10 mx1.improvmx.com`, `20 mx2.improvmx.com` |
| **SPF** | `v=spf1 include:spf.improvmx.com ~all` (softfail) |
| **DKIM** | `default._domainkey` — 2048-bit RSA valid; 6 empty selectors |
| **DMARC** | **MISSING** — no `_dmarc.dtrh.net` record |
| **Website** | Next.js on Vercel (A: 64.29.17.65, 216.198.79.65) |

**The problem:** No DMARC policy. SPF softfail (`~all`) means "accept but mark suspicious." Receiving servers had no instruction to reject failures.

---

## The ImprovMX Logs: Confirming the Bounce Path

```
Returned mail: see transcript for details
Sender: mailer-daemon@www478.sakura.ne.jp
Recipient: ikmfgvivz@dtrh.net
Forward To: dtrhnet@gmail.com
ENTERED QUEUE: 27/10/2026 01:25:25 am GMT-4 (2026-10-27T05:25:25Z)
From: www478.sakura.ne.jp → mx1.improvmx.com → 2.0.0 Queued
DELIVERED: +4.0s → mail2.mxpn1.infra.improvmx.com → gmail-smtp-in.l.google.com → 2.0.0 OK
```

**Why this matters:** In SMTP, a bounce (DSN) goes to the **envelope sender** (`MAIL FROM`), not the `From:` header. Sakura sent the bounce to `ikmfgvivz@dtrh.net` — so the original spam used that as its envelope sender. Classic **backscatter**: spammer forged `dtrh.net` → delivery failed → Sakura bounced to forged address → ImprovMX forwarded to my Gmail.

---

## What This Does NOT Mean

- ❌ My Gmail was compromised
- ❌ ImprovMX sent the spam
- ❌ The spammer controls/authenticates `dtrh.net`
- ❌ Sakura's server was compromised
- ❌ The `localhost` handoff was malicious
- ❌ The bounce was forged (ImprovMX logs confirm genuine delivery)

What I *have*: A bounce addressed to a forged envelope sender at my domain, forwarded through my legitimate setup. Classic backscatter.

---

## The Mail Flow (Visualized)

### Original Spam Message Path

<div align="center">

[![Figure 1: The spam path — forged envelope sender accepted by Sakura, fails local delivery due to quota](1.png)](1.png)

*Figure 1: The spam path — forged envelope sender accepted by Sakura, fails local delivery due to quota*

</div>

### Bounce Delivery Path

<div align="center">

[![Figure 2: The bounce path — DSN routed back through ImprovMX forwarding to Gmail](2.png)](2.png)

*Figure 2: The bounce path — DSN routed back through ImprovMX forwarding to Gmail*

</div>

---

## Why No DMARC Is the Real Problem

| Mechanism | What It Checks | What It Doesn't Do |
|-----------|----------------|-------------------|
| **SPF** | Connecting IP authorized for envelope sender domain? | Doesn't check `From:` header. Doesn't survive forwarding without SRS. |
| **DKIM** | Signing domain cryptographically signed the message? | Doesn't mean message is safe. Signing domain ≠ `From:` domain. |
| **DMARC** | Authenticated domain (SPF/DKIM) aligns with `From:` header? | **Publishes policy** (`p=none/quarantine/reject`) telling receivers what to do on failure. |

**Without DMARC:** Receivers get SPF/DKIM results but *no policy* from me. Most deliver anyway — maybe to spam, maybe to inbox.

**With DMARC `p=reject`:** Receivers that enforce DMARC reject messages where neither SPF nor DKIM aligns with `From:`. This kills most spoofing.

---

## My Situation & Recommendation

**Inventory:** Zero outbound senders (no website email, no "Send mail as", no ImprovMX SMTP).

**My fix (if you also send nothing):**
```
Add DMARC: v=DMARC1; p=reject; rua=mailto:dmarc@dtrh.net
Fix SPF:   v=spf1 include:spf.improvmx.com -all
```

**If you *do* send mail:** Inventory every sender → DKIM each → update SPF → start `p=none` + `rua` → monitor 2 weeks → `p=quarantine` → `p=reject`.

---

## The Fix (3 Cloudflare Commands)

### 1. Add DMARC (Reject Policy)
```bash
cf dns records create -z dtrh.net \
  --body '{"type":"TXT","name":"_dmarc","content":"v=DMARC1; p=reject; rua=mailto:dmarc@dtrh.net","ttl":3600}'
```

### 2. Upgrade SPF to Hardfail
```bash
cf dns records edit <record-id> -z dtrh.net \
  --body '{"type":"TXT","name":"dtrh.net","content":"v=spf1 include:spf.improvmx.com -all","ttl":3600}'
```

### 3. Clean Duplicate DKIM
```bash
cf dns records delete <old-record-id> -z dtrh.net --force
```

### Verification
```bash
$ dig dtrh.net TXT +short | grep spf1
"v=spf1 include:spf.improvmx.com -all"

$ dig _dmarc.dtrh.net TXT +short
"v=DMARC1; p=reject; rua=mailto:dmarc@dtrh.net"
```

### Results: Before vs After

| Metric | Before | After |
|--------|--------|-------|
| **Score** | 45 | **0** |
| **Tier** | HIGH 🟠 | **LOW 🟢** |
| **Spoofable** | YES 🚨 | **NO 🛡️** |
| **Risk** | HIGH | **LOW** |
| **SPF** | `~all` | **`-all`** |
| **DMARC** | Missing | **`p=reject`** |

---

## The Tooling

### 1. `dtrh_mail_poc.py` — The Scanner
```bash
python dtrh_mail_poc.py dtrh.net github.com google.com -v
```
Output:
```
🟢 dtrh.net        Score:   0  Tier: LOW       🛡️ Deliverable: False  Risk: LOW
🔴 github.com      Score:  70  Tier: CRITICAL  🚨 Deliverable: True   Risk: HIGH
🟠 google.com      Score:  40  Tier: HIGH      🚨 Deliverable: True   Risk: MEDIUM
```
**Key feature:** "Delivery Spoofability" — tells you if a spoofed message would actually *reach the inbox*.

### 2. `dtrh_mail_send.py` — The Demo Spoofer
```bash
cp dtrh_mail_send.conf.example dtrh_mail_send.conf
# Edit with SMTP credentials
python dtrh_mail_send.py "ceo@company.com" "Urgent" "Wire $50k now"
```
> ⚠️ Educational use only. Only test domains you own.

---

## The Bigger Question: Can This Be Automated?

**Yes.** The scanner is already a complete domain analyzer. Here's how it scales:

<div align="center">

[![Figure 3: Automated reconnaissance pipeline for domain spoofability assessment](3.png)](3.png)

*Figure 3: Automated reconnaissance pipeline for domain spoofability assessment*

</div>

### The Pipeline at Scale

**1. Input Acquisition**
- Tranco/Cisco Umbrella top 1M
- Certificate Transparency logs
- Zone file downloads (.com, .net, .org)
- Passive DNS (Farsight, SecurityTrails, VirusTotal)
- Subdomain enumeration (crt.sh, subfinder, amass)

**2. Mass DNS Resolution** (async, 500+ concurrent)
```python
import asyncio, dns.asyncresolver

async def bulk_check(domains, concurrency=500):
    sem = asyncio.Semaphore(concurrency)
    async def check_one(d):
        async with sem: return await analyze_domain(d)
    return await asyncio.gather(*[check_one(d) for d in domains])
```

**3. SPF Parsing & Expansion** — Recursively expand includes, flag `+all`, `~all`, missing `all`, excessive includes. Cross-reference cloud provider netblocks.

**4. DKIM Enumeration** — Common selectors (`default`, `selector1`, `selector2`, `mail`, `k1`, `k2`, `dkim`, `google`, `amazonses`). Validate key size (>1024-bit), algorithm (rsa-sha256 preferred).

**5. Scoring**
```python
def score_domain(result):
    score = 0
    if not result.spf.exists or result.spf.all in ('+all', 'none'): score += 30
    elif result.spf.all == '~all': score += 15
    if not result.dmarc.exists: score += 30
    elif result.dmarc.policy == 'none': score += 20
    elif result.dmarc.policy == 'quarantine': score += 10
    if result.dkim.valid_keys == 0: score += 15
    for inc in result.spf.includes:
        if any(p in inc for p in CLOUD_PROVIDERS): score += 10
    return min(score, 100)
```

**6. Output** — Ranked JSON with evidence, tier, remediation.

### Operational Challenges (Attacker's View)

| Challenge | Solution |
|-----------|----------|
| Rate limiting | Distribute across residential proxies, rotate resolvers |
| False positives | Validate with test sends (low volume, controlled) |
| Subdomain delegation | Recurse into `_dmarc.sub.domain`, check `redirect=` |
| Parked/expired domains | Filter via HTTP status, WHOIS, NS records |
| Volume | 1M domains ≈ 4-6 hours on modest hardware (500 concurrent) |

---

## Forwarding-Only vs. Hosted Email

| Aspect | Forwarding-Only (ImprovMX → Gmail) |
|--------|-------------------------------------|
| **Control** | No mail server tuning, no custom filters. Trust forwarder (ImprivMX does SRS/ARC). |
| **Sending** | Can't send unless you add SMTP service (ImprovMX SMTP, SendGrid, SES, etc.). |
| **Bounces** | Hit forwarder first → forwarded to inbox. *Better visibility* than traditional. |
| **SPF** | Simple: `include:spf.forwarder.com -all`. Update before adding senders. |
| **DMARC** | Works identically. `p=reject` is the equalizer. Costs nothing. |

**Checklist (shorter, not optional):**

| Area | Action |
|------|--------|
| **Inventory** | List every sender. Zero → `p=reject` is safe. |
| **SPF** | One record: `include:spf.forwarder.com -all`. Update before adding senders. |
| **DKIM** | Forwarder handles inbound. Outbound = each sender needs selector. |
| **DMARC** | Zero senders → `p=reject`. Else `p=none` → monitor → `p=quarantine` → `p=reject`. |
| **Accounts** | MFA on registrar, forwarder, Gmail. Unique passwords. |
| **Hygiene** | Prune aliases. Reconsider catch-all (attracts spam). |
| **Monitor** | DMARC reports are free intel. Check monthly. |

---

## The Fix, In Order (Step-by-Step)

1. **Audit** (15 min): `python dtrh_mail_poc.py yourdomain.com -v` — note score, tier, deliverable.
2. **Inventory** (10 min): List every sender. Zero → `p=reject` is safe.
3. **Fix SPF** (5 min): `v=spf1 include:spf.forwarder.com -all` (add senders before `-all` if needed).
4. **Add DMARC** (5 min): Zero senders → `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com`. Else `p=none` → monitor 2 weeks → `p=quarantine` → `p=reject`.
5. **Verify DKIM** (5 min): Check `default._domainkey` exists, valid key. Remove empty selectors.
6. **Re-scan** (2 min): Confirm **Score 0, Tier LOW, Deliverable: False, Risk LOW**.
7. **Enable Reporting**: Parse `rua=` XML daily/weekly. Watch for legit senders failing + unknown senders.

---

## Closing Thoughts

This started with a single bounce in spam. Counterfeit accessories, Japanese recipient, quota error — my domain in the `MAIL FROM`.

Three Cloudflare commands. Thirty minutes. The answer to "can someone spoof my domain and have it delivered?" flipped from **yes** to **no**.

**Email authentication isn't about perfection — it's about raising the cost of abuse.** A domain with `p=reject` + `-all` SPF forces the attacker to compromise a legitimate sender or find a non-enforcing receiver. Most won't bother.

If you run a domain — especially forwarding-only — run the scanner. Takes 30 seconds. Might save you from being the return address for someone else's spam.

---

*Published: 2026-10-27 | Domain: dtrh.net | Author: kbs <admin@dtrh.net>*

**Tools:** [MX-Spoof-Checker](https://github.com/DTRHnet/MX-Spoof-Checker) — `dtrh_mail_poc.py` (scanner) + `dtrh_mail_send.py` (demo spoofer)