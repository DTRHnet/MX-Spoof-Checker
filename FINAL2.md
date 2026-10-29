# Your Domain Is Sending Spam (Spoiler: It's Not You)

> **How a bounce exposed my SPF/DMARC gap — and how I fixed it in 3 Cloudflare commands**

---

**Published:** 2026-10-27  
**Author:** kbs <admin@dtrh.net>  
**Domain:** dtrh.net  
**Tools:** [MX-Spoof-Checker](https://github.com/DTRHnet/MX-Spoof-Checker)  
**Summary:** A suspicious bounce revealed my forwarding-only domain had no DMARC and softfail SPF — making it trivially spoofable. Three Cloudflare commands later (DMARC `p=reject`, SPF `-all`, DKIM cleanup), the domain went from "spoofable" to "reject at SMTP time." Includes a scanner (`dtrh_mail_poc.py`) and a demo spoofer (`dtrh_mail_send.py`), plus a breakdown of how to automate domain recon at scale.

---

## The Moment

You know that feeling when you open your spam folder and see a bounce — *from your own domain* — and your stomach drops? Not a "maybe I clicked something" moment. A deeper, colder one. The kind where your brain quietly goes: *"I didn't send that."*

It said `ikmfgvivz@dtrh.net`. An address I've never created. Advertised counterfeit branded accessories. Addressed to `18@bar18.jp` — a Japanese domain I have zero connection to. The bounce came from `MAILER-DAEMON@www478.sakura.ne.jp` — a Japanese hosting provider I don't use.

**My first thought: "I've been hacked."**

My second thought: "Or... my domain is being used as a cover."

The truth, it turned out, was both simpler and more uncomfortable than either of those. Let me walk you through exactly what I found — and what I did about it.

---

## The Setup

I've owned `dtrh.net` for about four years. My email history looks like a tech résumé:

- **hosting.com** (before A2 Hosting bought them) — full mail hosting
- **WordPress** — cPanel, PHP, the whole stack
- **Hexo** — static site generation, way simpler
- **Node.js** — custom build pipeline, because why not
- **Vercel** — free Next.js hosting, zero server maintenance

Somewhere along the way, I noticed I was paying for mail hosting I barely used. But Vercel doesn't do email. So I needed a bridge between my domain and my actual inbox.

Enter **ImprovMX**: a free service that accepts mail for `dtrh.net` and forwards it to my Gmail. Setup is one DNS change. No server, no mailboxes, no maintenance.

```
email → admin@dtrh.net → ImprovMX → Gmail (dtrhnet@gmail.com)
```

Simple. Free. Works perfectly — for *receiving* mail.

What I didn't think about: what happens when someone *else* uses my domain to send mail.

---

## What Actually Arrived

Here's the raw bounce message, redacted but otherwise untouched:

```text
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

Let me translate this into something that makes sense.

Someone — not me — sent a spam email `FROM` `ikmfgvivz@dtrh.net` `TO` `18@bar18.jp`. The receiving server (Sakura Internet) accepted it. Tried to deliver it. Failed — because the recipient's mailbox was full or misconfigured. Then bounced the failure notification back to... me. Because the email claimed I was the sender.

**Here's the thing that made my hair stand up:** that bounce didn't come from any account I own. It came from the *forged* return address the spammer invented. And because my domain was forwarding everything through ImprovMX, that bounce landed in my actual Gmail inbox.

I was receiving notifications about spam I didn't send, for an address I didn't own, from a server I'd never touched.

**No compromise. Just impersonation.**

---

## The Thinking Process (Because This Part Matters)

I want to be honest about what went through my mind, because I think most domain owners would go through the same steps — and most would stop at the wrong conclusion.

**Step 1: "Is my Gmail compromised?"**

This is the natural first guess. Someone's sending spam *from* my address? Maybe they can log in. I checked my Gmail login activity and 2FA settings. Clean. No unrecognized logins.

**Step 2: "Is ImprovMX compromised?"**

Less likely, but plausible. A forwarding service holds a lot of trust. I checked my ImprovMX account — no changes, no suspicious aliases, no unauthorized forwarders.

**Step 3: "Wait. The bounce didn't come from my mail server."**

This was the key realization. The `MAILER-DAEMON@www478.sakura.ne.jp` address belongs to a Japanese hosting company — not my provider. The bounce was generated there because the *destination* failed, and bounced back to the address that was forged as the sender.

**Step 4: "So someone just... wrote my domain in their From: header?"**

Yes. That's exactly what happened. And here's the uncomfortable truth: **anyone can do that.** SMTP — the protocol that carries email around the internet — was designed in 1982, before spam existed as we know it. It has no built-in authentication. You can put any address you want in the `From:` field, and the server has no way to verify you actually own it.

That's not a bug in my setup. That's the *default* state of email.

**Step 5: "So why should I care if I'm not sending it?"**

Because *my* domain's reputation gets dragged through the mud. And because — as I discovered — I was about to become the unwitting return address for a whole bunch of spam. I was about to start getting bounces, complaints, and spam-filter penalties for messages I never sent.

That's **backscatter**. It's like someone forging your return address on a bunch of letters, and when they can't be delivered, every undeliverable envelope gets sent back to you.

---

## The Mail Flow (Visualized)

<div align="center">

[![Figure 1: The spam path — forged envelope sender accepted by Sakura, fails local delivery due to quota](1.png)](1.png)

*Figure 1: The spam path — forged envelope sender accepted by Sakura, fails local delivery due to quota*

</div>

<div align="center">

[![Figure 2: The bounce path — DSN routed back through ImprovMX forwarding to Gmail](2.png)](2.png)

*Figure 2: The bounce path — DSN routed back through ImprovMX forwarding to Gmail*

</div>

---

## Why This Kept Happening (And Why It Was My Fault)

Here's where it gets uncomfortable. The spammer wasn't doing anything sophisticated. They weren't exploiting a bug. They weren't cracking a password. They just wrote my domain into an email and hit send.

The reason it *worked* was because of what I *hadn't* done:

**I had no DMARC record.** DMARC is a DNS record that tells receiving mail servers: "Hey, here's how to handle mail that claims to be from me." Without it, receiving servers default to... nothing. They look at the SPF and DKIM results, shrug, and often deliver the message anyway.

**My SPF record said `~all` (softfail).** In English: "If the sender's IP isn't on my list, accept the message but maybe mark it as suspicious." Not "reject it." Not "drop it." Just "meh, deliver it, maybe to spam."

**I had DKIM but wasn't leveraging it.** DKIM adds a cryptographic signature to outgoing mail. But if no one checks it, or if the receivers don't enforce DMARC, a missing DKIM signature doesn't block spoofed mail.

Put together, my configuration was the email equivalent of a house with a screen door and a sign that says "Please use the front door."

---

## Three Simple Concepts, Explained Like You're Not a Mail Admin

**SPF (Sender Policy Framework):** A list, published in DNS, of which servers are allowed to send email on behalf of your domain. Think of it like a guest list at a party. If you're not on the list, you should be turned away.

**DKIM (DomainKeys Identified Mail):** A cryptographic signature attached to outgoing email, proving it really came from your domain and wasn't altered in transit. Think of it like a wax seal on an envelope — hard to fake, easy to verify.

**DMARC (Domain-based Message Authentication, Reporting, and Conformance):** The policy that ties SPF and DKIM together. It tells receiving servers: "If the message fails SPF, or fails DKIM, or fails both — here's what to do with it." Think of it like a bouncer with instructions. Without DMARC, the bouncer just guesses.

**The critical insight:** SPF and DKIM are *checks*. DMARC is the *policy*. You can have all the checks in the world, but if you don't publish a policy telling servers what to do when a check fails, most of them will shrug and deliver the message anyway.

That's what was happening. My domain was being spoofed because I hadn't published a single DNS record.

---

## The Fix (Three Commands, Thirty Minutes)

Once I understood the problem, the solution was embarrassingly small.

I use Cloudflare for DNS, which has a CLI tool called `cf`. Three commands.

### 1. Add a DMARC record with the strictest policy

```bash
cf dns records create -z dtrh.net \
  --body '{"type":"TXT","name":"_dmarc","content":"v=DMARC1; p=reject; rua=mailto:dmarc@dtrh.net","ttl":3600}'
```

**What this does:** Tells every receiving mail server: "If a message claiming to be from `dtrh.net` fails authentication, **reject it outright**." Not "quarantine." Not "mark as spam." Reject.

The `rua=` part is a reporting address. Receiving servers send me daily/weekly reports about which messages are being sent as my domain, and whether they pass authentication. This is free threat intelligence.

### 2. Upgrade my SPF record from "softfail" to "hardfail"

My SPF record said `v=spf1 include:spf.improvmx.com ~all`. The `~all` means "softfail" — accept but mark suspicious. I changed it to `-all` — hardfail. Reject.

```bash
cf dns records edit <record-id> -z dtrh.net \
  --body '{"type":"TXT","name":"dtrh.net","content":"v=spf1 include:spf.improvmx.com -all","ttl":3600}'
```

**What this does:** Tells the internet: "If a message claims to be from `dtrh.net` and doesn't come from ImprovMX's servers, reject it." Full stop.

### 3. Clean up a duplicate DKIM record

I had two `default._domainkey` records — one with a valid key, one with an empty value. Removed the empty one.

```bash
cf dns records delete <old-record-id> -z dtrh.net --force
```

### The Decision Behind `p=reject`

Here's the part worth understanding: I set `p=reject` because **I don't send email from `dtrh.net`.**

If you *do* send email — website contact forms, password reset emails, "Send mail as" in Gmail, a newsletter platform — then `p=reject` is dangerous. You'll start rejecting your own legitimate email. The right approach in that case is:

1. Identify every service that sends as your domain
2. Give each one its own DKIM signature
3. Make sure their IPs are in your SPF
4. Start at `p=none` (monitor only)
5. Watch the reports for a couple weeks
6. Move to `p=quarantine` when you're confident
7. Move to `p=reject` only when you're sure

But for a forwarding-only domain like mine? `p=reject` is safe from day one. If I'm never sending, I should be rejecting everything that pretends to.

---

## The Before/After

I built a scanner to check domains like this, and it said this before and after my changes:

| Metric | Before | After |
|--------|--------|-------|
| Score | 45 | **0** |
| Tier | HIGH 🟠 | **LOW 🟢** |
| Spoofable | YES 🚨 | **NO 🛡️** |
| SPF | `~all` | **`-all`** |
| DMARC | Missing | **`p=reject`** |

Before: my domain was a rubber stamp for a spammer. After: any message claiming to be from `dtrh.net` that doesn't come from ImprovMX gets rejected at the receiving server. Not by my server — by *everyone else's* servers.

That's the part that still kind of amazes me. I didn't change my forwarding setup. I didn't add a mail server. I didn't pay for anything. I just published a DNS record, and the entire internet's mail infrastructure started enforcing it on my behalf.

---

## The Tools

I turned this investigation into two tools. Both are on GitHub: **[DTRHnet/MX-Spoof-Checker](https://github.com/DTRHnet/MX-Spoof-Checker)**

### `dtrh_mail_poc.py` — The Scanner

```bash
python dtrh_mail_poc.py dtrh.net github.com google.com -v
```

Output:

```text
🟢 dtrh.net     Score:   0  Tier: LOW       🛡️ Deliverable: False  Risk: LOW
🔴 github.com   Score:  70  Tier: CRITICAL  🚨 Deliverable: True   Risk: HIGH
🟠 google.com   Score:  40  Tier: HIGH      🚨 Deliverable: True   Risk: MEDIUM
```

The key feature is **Delivery Spoofability** — it doesn't just check if you *have* SPF/DKIM/DMARC. It checks whether a spoofed message using your domain would actually make it into someone's inbox. That's the metric that matters.

### `dtrh_mail_send.py` — The Demo Spoofer

A simple script that sends an email with any `From:` and `MAIL FROM` you specify. I included it because I wanted to *see* the vulnerability in action, not just read about it.

```bash
python dtrh_mail_send.py "ceo@company.com" "Urgent" "Wire funds immediately"
```

**Educational use only.** Only test domains you own or have explicit permission to test.

---

## The Bigger Question: Can This Be Automated?

This is what kept me up at night after I fixed my own domain.

If I could write a script in an afternoon that checks any domain for email spoofability — and I could — then anyone could. And if the tool scales, so does the problem.

<div align="center">

[![Figure 3: Automated reconnaissance pipeline for domain spoofability assessment](3.png)](3.png)

*Figure 3: Automated reconnaissance pipeline for domain spoofability assessment*

</div>

### The Pipeline

Here's how a motivated attacker (or security researcher) would find weak domains at scale:

**1. Get a massive domain list.** Tranco top 1M. Certificate Transparency logs (every new certificate issued = a new domain). `.com` zone file downloads. Passive DNS. Subdomain enumeration.

**2. Mass DNS resolution.** Query MX, SPF, DMARC, and DKIM records for millions of domains in parallel. With async Python or tools like `massdns`, you can do 500+ concurrent queries.

**3. Parse and score.** For each domain, compute a spoofability score:
- No SPF record, or permissive (`+all`): **30 points**
- SPF softfail (`~all`): **15 points**
- No DMARC record: **30 points**
- DMARC `p=none`: **20 points**
- NMDMARC `p=quarantine`: **10 points**
- No valid DKIM keys: **15 points**
- Cloud provider in SPF includes (Gmail, Outlook, SendGrid): **+10 each**
- No MX records: **+5 points** (can't receive bounces, but can still spoof)

**4. Filter for high-value targets.** A 70+ score means "spoofed messages almost certainly get delivered." Those are the domains an attacker would prioritize for phishing campaigns, invoice fraud, or executive impersonation.

**5. Output a ranked list.** With evidence. With remediation advice. With the confidence to act on it.

### The Attacker's View

| Challenge | Workaround |
|-----------|------------|
| Rate limiting | Distributed proxies, rotating resolvers |
| False positives | Test sends (low volume, targeting your own inbox) |
| Subdomain delegation | Recurse into `_dmarc.sub.domain`, check `redirect=` |
| Parked/expired domains | Filter by HTTP status, WHOIS, NS records |
| Volume | 1M domains ≈ 4-6 hours on a laptop with 500 concurrent queries |

**This isn't hypothetical.** Security researchers do variants of this for good reasons (vulnerability disclosure, responsible notification). But the same techniques work for the other side too.

**The optimistic framing:** every domain with `p=reject` + `-all` SPF is one fewer domain a spammer can hide behind. The internet gets incrementally safer when people fix their records.

---

## Forwarding-Only vs. Hosted Email: What's Different

Running a forwarding-only setup (like ImprovMX → Gmail) is a different animal than running a hosted mailbox. Here's what matters:

| Aspect | What to Know |
|--------|-------------|
| **Control** | No mail server to tune, no custom filters to write, no TLS to enforce. You trust the forwarder — and good forwarders like ImprovMX handle SRS and ARC to preserve authentication through forwarding. |
| **Sending** | You *can't* send from the domain unless you add a separate SMTP service. Forwarding ≠ sending. If you need to send as `@yourdomain`, use ImprovMX SMTP, SendGrid, AWS SES, or similar — and each one needs its own SPF and DKIM setup. |
| **Bounces** | They hit the forwarder first, then get forwarded to your real inbox. This is actually *better* visibility than a traditional setup — you see the full forwarding path in the logs. |
| **SPF** | Simpler. One record: `include:spf.forwarder.com -all`. But if you add a sender later, update SPF *before* you send — or those messages will fail authentication. |
| **DMARC** | Works exactly the same. `p=reject` costs nothing, takes 5 minutes, and is the single most effective control. |

### The Practical Checklist

| Area | Action |
|------|--------|
| **Inventory** | List every service that sends as your domain. Contact forms, password reset emails, Gmail "Send mail as," SMTP services, mailing lists, carts, support tools. If zero → `p=reject` is safe. |
| **SPF** | One record. `include:spf.forwarder.com -all`. Update before adding senders. |
| **DKIM** | Forwarders usually handle inbound. For outbound, each sender needs its own selector. |
| **DMARC** | Start `p=none` + `rua` if unsure. Move to `p=reject` once your inventory is clean. |
| **Accounts** | MFA on registrar, forwarder, Gmail. Unique passwords. |
| **Hygiene** | Prune unused aliases. Reconsider catch-all — it attracts spam to random addresses. |
| **Monitoring** | DMARC reports are free threat intel. Check them monthly. |

---

## The Step-by-Step Fix (Do It In This Order)

If you're where I was — forwarding-only, no DMARC, softfail SPF — here's the sequence that makes sense:

**1. Audit first (15 min).** Run the scanner against your domain:
```bash
python dtrh_mail_poc.py yourdomain.com -v
```
Note the score, the tier, and whether "Deliverable: True" shows up. That's your baseline.

**2. Inventory your senders (10 min).** List everything that sends as `@yourdomain`. Website forms? Password resets? Gmail "Send mail as"? A marketing platform? Nothing at all?

If it's zero — great. You can go straight to `p=reject`. If it's not zero — note each one. You'll need to authenticate each before tightening the policy.

**3. Fix SPF (5 min).**
- **Zero senders:** `v=spf1 include:spf.yourforwarder.com -all`
- **Some senders:** Add each sender's `include:` or `ip4:` block before the `-all`. Test with the scanner after each change.

**4. Add DMARC (5 min).**
- **Zero senders:** `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com`
- **Some senders:** Start with `p=none` + `rua`. Watch reports for 2 weeks to see who's actually sending as you. Then move to `p=quarantine`, then `p=reject`.

**5. Verify DKIM (5 min).** Check that `default._domainkey.yourdomain.com` exists and has a valid key. Remove any empty selectors (`selector1`, `mail`, etc.) — they just add noise.

**6. Re-scan (2 min).**
```bash
python dtrh_mail_poc.py yourdomain.com -v
```
You should see: **Score 0, Tier LOW, Deliverable: False, Risk LOW**.

**7. Enable reporting (ongoing).** The `rua=` address receives XML reports daily or weekly. Watch for:
- Legitimate senders failing alignment → fix them before they break
- Unknown senders → someone is spoofing you, and now you have evidence

---

## Closing Thoughts

This whole thing started with a single bounce in my spam folder. A counterfeit accessories spam, a Japanese recipient, a quota error — and my domain in the `MAIL FROM`.

Three Cloudflare commands. Thirty minutes. The answer to *"can someone spoof my domain and have it delivered?"* flipped from **yes** to **no**.

**Email authentication isn't about perfection — it's about raising the cost of abuse.** A domain with `p=reject` + `-all` SPF forces the attacker to either compromise a legitimate sender or find a receiver that doesn't enforce DMARC. Most won't bother. Most will move on to an easier target.

That's the thing that makes this worth writing about. Not the fix itself — that took half an hour. The thing that matters is that **the fix is half an hour**. There's no excuse. If you own a domain and you care about it, check your SPF, DKIM, and DMARC records. Run the scanner. It takes 30 seconds.

You might save yourself from becoming the return address for someone else's spam.

---

*Published: 2026-10-27 | Domain: dtrh.net | Author: kbs <admin@dtrh.net>*

**Tools:** [MX-Spoof-Checker](https://github.com/DTRHnet/MX-Spoof-Checker) — `dtrh_mail_poc.py` (scanner) + `dtrh_mail_send.py` (demo spoofer)