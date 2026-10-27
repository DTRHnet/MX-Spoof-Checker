#!/usr/bin/env python3
"""
dtrh_mail_poc - Email Security Spoofability Scanner
A simple tool to check domains for email security misconfigurations (SPF, DKIM, DMARC, MX)
and identify domains vulnerable to spoofing.

Usage:
    python dtrh_mail_poc.py                    # uses domain_list.txt
    python dtrh_mail_poc.py -i domains.txt     # custom input file
    python dtrh_mail_poc.py dtrh.net example.com  # direct domains
    python dtrh_mail_poc.py -v                 # verbose per-domain detail
    python dtrh_mail_poc.py --json             # machine-readable JSON output

Author: Domain Owner (dtrh.net)
"""

import sys
import os
import re
import json
import csv
import argparse
import socket
import subprocess
import platform
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# ============================================================================
# OPTIONAL DEPENDENCIES - Graceful fallbacks
# ============================================================================
try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import tldextract
    # Use cache_dir=None to avoid filesystem warnings in restricted environments
    _tld_extract = tldextract.TLDExtract(cache_dir=None)
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.box import ROUNDED
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False
    console = None

# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================
SCRIPT_DIR = Path(__file__).parent.absolute()
DEFAULT_LIST_FILE = SCRIPT_DIR / "domain_list.txt"
DKIM_SELECTORS = ["default", "selector1", "selector2", "mail", "k1", "k2", "dkim"]
CLOUD_PROVIDERS = [
    "gmail.com", "google.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "office365.com",
    "amazonses.com", "ses.amazonaws.com",
    "sendgrid.net", "sendgrid.com",
    "mailgun.org", "mailgun.com",
    "mandrillapp.com", "mailchimp.com",
    "postmarkapp.com", "sparkpostmail.com",
]

DNS_TIMEOUT = 5.0
MAX_WORKERS = 10
# Use reliable public DNS to avoid negative caching issues
PUBLIC_DNS_SERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
def log_info(msg: str, verbose: bool = True):
    if verbose:
        print(f"  {msg}")

def log_warn(msg: str):
    print(f"  ⚠ {msg}", file=sys.stderr)

def log_error(msg: str):
    print(f"  ✗ {msg}", file=sys.stderr)

def print_step(step: int, title: str, details: str = ""):
    print(f"\n[STEP {step}] {title}")
    if details:
        for line in details.strip().split("\n"):
            print(f"         {line}")

def print_header(title: str):
    width = 70
    print("\n" + "═" * width)
    print(f"  {title}")
    print("═" * width)

def sanitize_domain(raw: str) -> Optional[str]:
    """
    Sanitize a domain input to registered domain (e.g., example.com).
    Handles: protocols, paths, email addresses, subdomains.
    Returns None if input cannot be parsed as a domain.
    """
    if not raw or not raw.strip():
        return None
    
    domain = raw.strip().lower()
    
    # Strip common protocols
    for proto in ["http://", "https://", "mailto:", "ftp://"]:
        if domain.startswith(proto):
            domain = domain[len(proto):]
    
    # Strip paths, query, fragment
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    
    # Handle email addresses - extract domain part
    if "@" in domain:
        domain = domain.split("@")[-1]
    
    # Strip port
    domain = domain.split(":")[0]
    
    # Use tldextract if available for proper registered domain extraction
    if HAS_TLDEXTRACT:
        extracted = _tld_extract(domain)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
    
    # Fallback: simple heuristic - take last two parts for common TLDs
    # This is imperfect but works for most common cases
    parts = domain.split(".")
    if len(parts) >= 2:
        # Handle known multi-part TLDs
        known_multi = {"co.uk", "co.jp", "co.kr", "co.nz", "co.za", "com.au", "com.br", 
                       "com.cn", "com.mx", "com.tr", "org.uk", "ac.uk", "gov.uk",
                       "edu.au", "gov.au", "ne.jp", "or.jp", "ac.jp", "go.jp"}
        if len(parts) >= 3 and ".".join(parts[-3:]) in known_multi:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    
    return domain if "." in domain else None


def load_domains_from_file(filepath: Path) -> List[str]:
    """Load domains from file, skipping comments and empty lines."""
    domains = []
    errors = 0
    comments = 0
    
    try:
        with open(filepath, "r", encoding="utf-8", newline="") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    comments += 1
                    continue
                domains.append(line)
    except FileNotFoundError:
        log_error(f"File not found: {filepath}")
        return []
    except Exception as e:
        log_error(f"Error reading {filepath}: {e}")
        return []
    
    return domains, comments, errors


def run_dig(domain: str, record_type: str, name: str = "") -> List[str]:
    """Fallback DNS query using system dig/nslookup."""
    results = []
    target = f"{name}.{domain}" if name else domain
    
    try:
        if platform.system() == "Windows":
            # Windows nslookup
            cmd = ["nslookup", "-type=" + record_type, target]
        else:
            # Linux/macOS dig
            cmd = ["dig", "+short", record_type, target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=DNS_TIMEOUT)
        output = result.stdout.strip()
        
        if output:
            for line in output.split("\n"):
                line = line.strip().rstrip(".")
                if line and not line.startswith(";"):
                    results.append(line)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    
    return results


# ============================================================================
# DNS CHECKS
# ============================================================================
def _get_resolver():
    """Create a resolver with public DNS servers to avoid caching issues."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    resolver.nameservers = PUBLIC_DNS_SERVERS
    return resolver


def check_mx(domain: str) -> Dict[str, Any]:
    """Check MX records for domain."""
    result = {"has_mx": False, "records": [], "error": None}
    
    if HAS_DNSPYTHON:
        try:
            resolver = _get_resolver()
            answers = resolver.resolve(domain, "MX")
            for rdata in answers:
                result["records"].append({
                    "priority": rdata.preference,
                    "exchange": str(rdata.exchange).rstrip(".")
                })
            result["has_mx"] = len(result["records"]) > 0
        except dns.resolver.NXDOMAIN:
            result["error"] = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            result["error"] = "No MX record"
        except dns.exception.Timeout:
            result["error"] = "Timeout"
        except Exception as e:
            result["error"] = str(e)
    else:
        # Fallback to dig
        mx_records = run_dig(domain, "MX")
        for line in mx_records:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    priority = int(parts[0])
                    exchange = parts[1].rstrip(".")
                    result["records"].append({"priority": priority, "exchange": exchange})
                except ValueError:
                    pass
        result["has_mx"] = len(result["records"]) > 0
    
    # Sort by priority
    result["records"].sort(key=lambda x: x["priority"])
    return result


def check_spf(domain: str) -> Dict[str, Any]:
    """Check SPF record for domain."""
    result = {"has_spf": False, "record": "", "all_mechanism": "none", "includes": [], "error": None}
    
    if HAS_DNSPYTHON:
        try:
            resolver = _get_resolver()
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                for string in rdata.strings:
                    txt = string.decode() if isinstance(string, bytes) else string
                    if txt.startswith("v=spf1"):
                        result["has_spf"] = True
                        result["record"] = txt
                        # Extract all mechanism
                        all_match = re.search(r'([+\-~?])all\b', txt)
                        if all_match:
                            result["all_mechanism"] = all_match.group(1) + "all"
                        # Extract includes
                        includes = re.findall(r'include:([^\s]+)', txt)
                        result["includes"] = includes
                        break
        except Exception as e:
            result["error"] = str(e)
    else:
        txt_records = run_dig(domain, "TXT")
        for txt in txt_records:
            txt = txt.strip('"')
            if txt.startswith("v=spf1"):
                result["has_spf"] = True
                result["record"] = txt
                all_match = re.search(r'([+\-~?])all\b', txt)
                if all_match:
                    result["all_mechanism"] = all_match.group(1) + "all"
                includes = re.findall(r'include:([^\s]+)', txt)
                result["includes"] = includes
                break
    
    return result


def check_dmarc(domain: str) -> Dict[str, Any]:
    """Check DMARC record for domain."""
    result = {"has_dmarc": False, "record": "", "policy": "none", "subdomain_policy": None, "rua": [], "error": None}
    dmarc_domain = f"_dmarc.{domain}"
    
    if HAS_DNSPYTHON:
        try:
            resolver = _get_resolver()
            answers = resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                for string in rdata.strings:
                    txt = string.decode() if isinstance(string, bytes) else string
                    if txt.startswith("v=DMARC1"):
                        result["has_dmarc"] = True
                        result["record"] = txt
                        # Extract policy
                        p_match = re.search(r'p=([^;\s]+)', txt)
                        if p_match:
                            result["policy"] = p_match.group(1)
                        # Extract subdomain policy
                        sp_match = re.search(r'sp=([^;\s]+)', txt)
                        if sp_match:
                            result["subdomain_policy"] = sp_match.group(1)
                        # Extract rua
                        rua_matches = re.findall(r'rua=([^;\s]+)', txt)
                        result["rua"] = rua_matches
                        break
        except dns.resolver.NXDOMAIN:
            result["error"] = "NXDOMAIN"
        except dns.resolver.NoAnswer:
            result["error"] = "No DMARC record"
        except Exception as e:
            result["error"] = str(e)
    else:
        txt_records = run_dig(dmarc_domain, "TXT")
        for txt in txt_records:
            txt = txt.strip('"')
            if txt.startswith("v=DMARC1"):
                result["has_dmarc"] = True
                result["record"] = txt
                p_match = re.search(r'p=([^;\s]+)', txt)
                if p_match:
                    result["policy"] = p_match.group(1)
                sp_match = re.search(r'sp=([^;\s]+)', txt)
                if sp_match:
                    result["subdomain_policy"] = sp_match.group(1)
                rua_matches = re.findall(r'rua=([^;\s]+)', txt)
                result["rua"] = rua_matches
                break
    
    return result


def check_dkim(domain: str) -> Dict[str, Any]:
    """Check DKIM selectors for domain."""
    result = {"has_dkim": False, "selectors": {}, "valid_keys": 0, "error": None}
    
    for selector in DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        selector_result = {"found": False, "record": "", "key_type": "", "key_size": 0, "empty": False}
        
        if HAS_DNSPYTHON:
            try:
                resolver = _get_resolver()
                answers = resolver.resolve(dkim_domain, "TXT")
                for rdata in answers:
                    for string in rdata.strings:
                        txt = string.decode() if isinstance(string, bytes) else string
                        if txt.startswith("v=DKIM1"):
                            selector_result["found"] = True
                            selector_result["record"] = txt
                            # Extract key type
                            k_match = re.search(r'k=([^;\s]+)', txt)
                            if k_match:
                                selector_result["key_type"] = k_match.group(1)
                            # Extract public key and estimate size
                            p_match = re.search(r'p=([^;\s]*)', txt)
                            if p_match:
                                p_value = p_match.group(1)
                                if not p_value or p_value == "":
                                    selector_result["empty"] = True
                                    selector_result["key_size"] = 0
                                else:
                                    # Rough key size estimation from base64 length
                                    # base64 encodes 6 bits per char, RSA modulus is ~key_size bits
                                    selector_result["key_size"] = (len(p_value) * 6 * 8) // 8  # simplified: len * 6 ≈ bits for base64
                                    # More accurate: base64 length * 6 ≈ bit length
                                    selector_result["key_size"] = len(p_value) * 6
                            break
            except Exception:
                pass
        else:
            txt_records = run_dig(dkim_domain, "TXT")
            for txt in txt_records:
                txt = txt.strip('"')
                if txt.startswith("v=DKIM1"):
                    selector_result["found"] = True
                    selector_result["record"] = txt
                    k_match = re.search(r'k=([^;\s]+)', txt)
                    if k_match:
                        selector_result["key_type"] = k_match.group(1)
                    p_match = re.search(r'p=([^;\s]*)', txt)
                    if p_match:
                        p_value = p_match.group(1)
                        if not p_value or p_value == "":
                            selector_result["empty"] = True
                            selector_result["key_size"] = 0
                        else:
                            # Rough key size estimation from base64 length
                            selector_result["key_size"] = len(p_value) * 6
                    break
        
        result["selectors"][selector] = selector_result
        if selector_result["found"] and not selector_result["empty"]:
            result["has_dkim"] = True
            result["valid_keys"] += 1
    
    return result


# ============================================================================
# SCORING & ANALYSIS
# ============================================================================
def calculate_score(mx: Dict, spf: Dict, dmarc: Dict, dkim: Dict) -> Tuple[int, str, List[str]]:
    """Calculate spoofability score and return (score, tier, reasons)."""
    score = 0
    reasons = []
    
    # SPF scoring
    all_mech = spf.get("all_mechanism", "none")
    if not spf.get("has_spf") or all_mech in ("+all", "none"):
        score += 30
        reasons.append("No SPF record or permissive (+all/none) → anyone can send as this domain")
    elif all_mech == "~all":
        score += 15
        reasons.append("SPF softfail (~all) → unauthorized senders accepted but marked")
    elif all_mech == "?all":
        score += 20
        reasons.append("SPF neutral (?all) → no policy enforcement")
    elif all_mech == "-all":
        score += 0
    else:
        score += 10
        reasons.append("SPF redirect/include only, no explicit all mechanism")
    
    # DMARC scoring
    if not dmarc.get("has_dmarc"):
        score += 30
        reasons.append("No DMARC record → receivers have no policy guidance")
    else:
        policy = dmarc.get("policy", "none")
        if policy == "none":
            score += 20
            reasons.append("DMARC p=none → monitoring only, no enforcement")
        elif policy == "quarantine":
            score += 10
            reasons.append("DMARC p=quarantine → suspicious mail quarantined")
        elif policy == "reject":
            score += 0
    
    # DKIM scoring
    if dkim.get("valid_keys", 0) == 0:
        score += 15
        reasons.append("No valid DKIM keys → no cryptographic message signing")
    else:
        score += 0
        # Check for empty selectors (noise)
        empty_selectors = [s for s, v in dkim.get("selectors", {}).items() if v.get("found") and v.get("empty")]
        if empty_selectors:
            reasons.append(f"Empty DKIM selectors ({', '.join(empty_selectors)}) create confusion")
    
    # MX scoring
    if not mx.get("has_mx"):
        score += 5
        reasons.append("No MX records → can't receive bounces but From: still forgeable")
    
    # Cloud provider bonus (avoid duplicates)
    spf_includes = spf.get("includes", [])
    seen_providers = set()
    for inc in spf_includes:
        for provider in CLOUD_PROVIDERS:
            if provider in inc and provider not in seen_providers:
                seen_providers.add(provider)
                score += 10
                reasons.append(f"SPF includes {provider} → commonly abused cloud sender")
                break
    
    # Cap score
    score = min(score, 100)
    
    # Determine tier
    if score >= 70:
        tier = "CRITICAL"
    elif score >= 40:
        tier = "HIGH"
    elif score >= 20:
        tier = "MEDIUM"
    else:
        tier = "LOW"
    
    return score, tier, reasons


def assess_delivery_spoofability(mx: Dict, spf: Dict, dmarc: Dict, dkim: Dict) -> Dict[str, Any]:
    """
    Assess whether a spoofed message using this domain as envelope sender
    would likely be DELIVERED (not just bounced).
    
    Based on the blog post incident: the spam was ACCEPTED by Sakura and
    only failed due to recipient quota. For delivery to succeed:
    1. Receiving server must not reject at SMTP time
    2. DMARC must not be p=reject (or receiver doesn't enforce)
    3. SPF must not be -all (hardfail) - or receiver ignores SPF fail
    4. Attacker doesn't need valid DKIM (can send unsigned)
    
    Returns: {"deliverable": bool, "risk_level": str, "conditions": list, "explanation": str}
    """
    conditions = []
    deliverable = False
    risk_factors = 0
    
    # Condition 1: DMARC policy
    dmarc_policy = dmarc.get("policy", "none") if dmarc.get("has_dmarc") else "none"
    if dmarc_policy == "reject":
        conditions.append("✗ DMARC p=reject → Receiving servers SHOULD reject on alignment failure")
        # But: not all receivers enforce DMARC strictly
        risk_factors += 1  # Still some risk if receiver doesn't enforce
    elif dmarc_policy == "quarantine":
        conditions.append("⚠ DMARC p=quarantine → May go to spam folder, but often delivered")
        deliverable = True
        risk_factors += 2
    elif dmarc_policy == "none":
        conditions.append("⚠ DMARC p=none → No enforcement, delivery likely")
        deliverable = True
        risk_factors += 3
    else:  # no DMARC
        conditions.append("✗ NO DMARC record → No policy, delivery very likely")
        deliverable = True
        risk_factors += 4
    
    # Condition 2: SPF mechanism
    spf_all = spf.get("all_mechanism", "none") if spf.get("has_spf") else "none"
    if spf_all == "-all":
        conditions.append("✓ SPF -all (hardfail) → SPF check fails for unauthorized senders")
        # With DMARC reject, this would block. Without DMARC reject, many receivers still deliver.
        if dmarc_policy != "reject":
            conditions.append("  But: Without DMARC reject, many receivers ignore SPF fail and deliver anyway")
            deliverable = True
            risk_factors += 1
    elif spf_all == "~all":
        conditions.append("⚠ SPF ~all (softfail) → Unauthorized senders accepted but marked")
        deliverable = True
        risk_factors += 3
    elif spf_all in ("+all", "none"):
        conditions.append("✗ SPF +all/none/missing → SPF check passes for anyone")
        deliverable = True
        risk_factors += 4
    else:
        conditions.append("? SPF redirect/include only → Depends on included domains")
        deliverable = True
        risk_factors += 2
    
    # Condition 3: DKIM - attacker can't sign, but that's OK if SPF passes or DMARC not enforced
    if dkim.get("valid_keys", 0) > 0:
        conditions.append("✓ Domain has DKIM keys → Legitimate mail can sign (attacker cannot)")
    else:
        conditions.append("⚠ No DKIM keys → No signing possible for anyone (legitimate or attacker)")
    
    # Condition 4: MX - needed for bounces to route back, not for delivery
    if mx.get("has_mx"):
        conditions.append("✓ MX records exist → Bounces route back (enables backscatter)")
    else:
        conditions.append("○ No MX → No bounce path, but delivery still possible")
    
    # Determine risk level
    if risk_factors >= 7:
        risk_level = "CRITICAL - Spoofed mail almost certainly delivered"
    elif risk_factors >= 5:
        risk_level = "HIGH - Spoofed mail likely delivered"
    elif risk_factors >= 3:
        risk_level = "MEDIUM - Spoofed mail may be delivered (spam folder or inbox)"
    elif risk_factors >= 1:
        risk_level = "LOW - Some risk if receiver doesn't enforce DMARC"
    else:
        risk_level = "MINIMAL - Strong protections (DMARC reject + SPF hardfail)"
    
    # Summary explanation
    if deliverable:
        explanation = (
            "A spoofed message using this domain as envelope sender (MAIL FROM) "
            "would likely be ACCEPTED and DELIVERED by many receiving servers, "
            "just like the spam in the blog post that reached Sakura and only failed "
            "due to recipient quota. The recipient would see the forged From: address."
        )
    else:
        explanation = (
            "Strong protections (DMARC p=reject + SPF -all) mean most compliant "
            "receivers will REJECT spoofed messages at SMTP time. However, "
            "non-compliant receivers may still deliver."
        )
    
    return {
        "deliverable": deliverable,
        "risk_level": risk_level,
        "risk_score": risk_factors,
        "conditions": conditions,
        "explanation": explanation
    }


def check_domain(domain: str) -> Dict[str, Any]:
    """Run all checks for a single domain."""
    mx = check_mx(domain)
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim = check_dkim(domain)
    score, tier, reasons = calculate_score(mx, spf, dmarc, dkim)
    delivery_assessment = assess_delivery_spoofability(mx, spf, dmarc, dkim)
    
    return {
        "domain": domain,
        "score": score,
        "tier": tier,
        "reasons": reasons,
        "delivery_spoofability": delivery_assessment,
        "mx": mx,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    }


# ============================================================================
# OUTPUT FORMATTING
# ============================================================================
def format_domain_summary(result: Dict[str, Any]) -> str:
    """Format one-line domain summary."""
    domain = result["domain"]
    score = result["score"]
    tier = result["tier"]
    mx = "✓" if result["mx"]["has_mx"] else "✗"
    spf_mech = result["spf"].get("all_mechanism", "none")
    dmarc_pol = result["dmarc"].get("policy", "none") if result["dmarc"]["has_dmarc"] else "✗"
    dkim_status = "✓" if result["dkim"]["valid_keys"] > 0 else "✗"
    
    # Delivery spoofability indicator
    delivery = result.get("delivery_spoofability", {})
    deliverable = delivery.get("deliverable", False)
    risk = delivery.get("risk_level", "").split(" - ")[0] if delivery.get("risk_level") else "?"
    deliver_icon = "🚨" if deliverable else "🛡️"
    
    tier_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    icon = tier_colors.get(tier, "⚪")
    
    return f"{icon} {domain:<30} Score: {score:3d}  Tier: {tier:<8}  {deliver_icon} Deliverable: {str(deliverable):<5}  Risk: {risk:<8}  MX:{mx}  SPF:{spf_mech:<5}  DMARC:{dmarc_pol:<8}  DKIM:{dkim_status}"


def format_domain_detail(result: Dict[str, Any]) -> str:
    """Format detailed per-domain output."""
    domain = result["domain"]
    score = result["score"]
    tier = result["tier"]
    mx = result["mx"]
    spf = result["spf"]
    dmarc = result["dmarc"]
    dkim = result["dkim"]
    delivery = result.get("delivery_spoofability", {})
    
    lines = []
    lines.append(f"┌─ {domain} " + "─" * (60 - len(domain)))
    lines.append(f"│ Score: {score:3d}  │  Tier: {tier}")
    lines.append("├" + "─" * 62 + "┤")
    
    # Delivery Spoofability Assessment (KEY SECTION)
    lines.append(f"│ 🎯 DELIVERY SPOOFABILITY: {delivery.get('risk_level', 'UNKNOWN')}")
    lines.append(f"│    Spoofed mail deliverable: {'YES 🚨' if delivery.get('deliverable') else 'NO 🛡️'}")
    lines.append(f"│    {delivery.get('explanation', '')[:80]}")
    if len(delivery.get('explanation', '')) > 80:
        lines.append(f"│    {delivery.get('explanation', '')[80:160]}")
    lines.append("├" + "─" * 62 + "┤")
    
    # Conditions
    for cond in delivery.get("conditions", []):
        lines.append(f"│    {cond}")
    
    lines.append("├" + "─" * 62 + "┤")
    
    # MX
    if mx["has_mx"]:
        mx_str = ", ".join([f"{r['exchange']} ({r['priority']})" for r in mx["records"][:3]])
        if len(mx["records"]) > 3:
            mx_str += f" ... (+{len(mx['records'])-3} more)"
    else:
        mx_str = "NO MX RECORDS"
    lines.append(f"│ MX:        {mx_str}")
    
    # SPF
    if spf["has_spf"]:
        spf_str = spf["record"][:80] + ("..." if len(spf["record"]) > 80 else "")
        lines.append(f"│ SPF:       {spf_str}")
        all_mech = spf.get("all_mechanism", "none")
        if all_mech == "~all":
            lines.append(f"│            → Softfail: unauthorized senders accepted but marked")
        elif all_mech == "-all":
            lines.append(f"│            → Hardfail: unauthorized senders rejected")
        elif all_mech == "+all":
            lines.append(f"│            → PASS ALL: anyone can send (DANGEROUS)")
    else:
        lines.append(f"│ SPF:       NO SPF RECORD → anyone can send")
    
    # DMARC
    if dmarc["has_dmarc"]:
        lines.append(f"│ DMARC:     {dmarc['record'][:80]}")
        policy = dmarc.get("policy", "none")
        if policy == "none":
            lines.append(f"│            → Monitoring only (p=none), no enforcement")
        elif policy == "reject":
            lines.append(f"│            → Reject policy (p=reject) - GOOD")
    else:
        lines.append(f"│ DMARC:     NO RECORD → no policy published")
    
    # DKIM
    valid_selectors = [s for s, v in dkim["selectors"].items() if v["found"] and not v["empty"]]
    empty_selectors = [s for s, v in dkim["selectors"].items() if v["found"] and v["empty"]]
    if valid_selectors:
        for sel in valid_selectors:
            info = dkim["selectors"][sel]
            lines.append(f"│ DKIM:      {sel}._domainkey: {info['key_type']} {info['key_size']}-bit ✓")
    else:
        lines.append(f"│ DKIM:      NO VALID KEYS")
    if empty_selectors:
        lines.append(f"│            Empty selectors: {', '.join(empty_selectors)}")
    
    # Why vulnerable
    if result["reasons"]:
        lines.append("│ WHY VULNERABLE (General):")
        for reason in result["reasons"]:
            lines.append(f"│   • {reason}")
    
    lines.append("└" + "─" * 62 + "┘")
    return "\n".join(lines)


def print_results_table(results: List[Dict], verbose: bool):
    """Print summary table and optional verbose details."""
    # Summary counts
    tiers = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        tiers[r["tier"]] += 1
    
    print_step(4, "Summary")
    print(f"  CRITICAL: {tiers['CRITICAL']}")
    print(f"  HIGH:     {tiers['HIGH']}")
    print(f"  MEDIUM:   {tiers['MEDIUM']}")
    print(f"  LOW:      {tiers['LOW']}")
    
    if verbose:
        print("\n  Per-domain details:")
        for r in results:
            print(f"\n{format_domain_detail(r)}")


def export_results(results: List[Dict], output_dir: Path) -> Tuple[Path, Path]:
    """Export results to JSON and CSV."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    json_file = output_dir / f"results_{timestamp}.json"
    csv_file = output_dir / f"results_{timestamp}.csv"
    
    # JSON export
    with open(json_file, "w") as f:
        json.dump(results, f, indent=2)
    
    # CSV export
    fieldnames = [
        "domain", "score", "tier", 
        "delivery_deliverable", "delivery_risk_level", "delivery_risk_score", "delivery_explanation",
        "has_mx", "mx_records",
        "has_spf", "spf_record", "spf_all_mechanism", "spf_includes",
        "has_dmarc", "dmarc_record", "dmarc_policy", "dmarc_subdomain_policy", "dmarc_rua",
        "has_dkim", "dkim_valid_keys", "dkim_selectors"
    ]
    
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            delivery = r.get("delivery_spoofability", {})
            writer.writerow({
                "domain": r["domain"],
                "score": r["score"],
                "tier": r["tier"],
                "delivery_deliverable": delivery.get("deliverable", False),
                "delivery_risk_level": delivery.get("risk_level", ""),
                "delivery_risk_score": delivery.get("risk_score", 0),
                "delivery_explanation": delivery.get("explanation", ""),
                "has_mx": r["mx"]["has_mx"],
                "mx_records": "; ".join([f"{x['exchange']}({x['priority']})" for x in r["mx"]["records"]]),
                "has_spf": r["spf"]["has_spf"],
                "spf_record": r["spf"]["record"],
                "spf_all_mechanism": r["spf"].get("all_mechanism", "none"),
                "spf_includes": ", ".join(r["spf"].get("includes", [])),
                "has_dmarc": r["dmarc"]["has_dmarc"],
                "dmarc_record": r["dmarc"]["record"],
                "dmarc_policy": r["dmarc"].get("policy", "none"),
                "dmarc_subdomain_policy": r["dmarc"].get("subdomain_policy", ""),
                "dmarc_rua": ", ".join(r["dmarc"].get("rua", [])),
                "has_dkim": r["dkim"]["has_dkim"],
                "dkim_valid_keys": r["dkim"]["valid_keys"],
                "dkim_selectors": json.dumps(r["dkim"]["selectors"])
            })
    
    return json_file, csv_file


def print_json_output(results: List[Dict]):
    """Print machine-readable JSON."""
    print(json.dumps(results, indent=2))


# ============================================================================
# MAIN
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="dtrh_mail_poc - Email Security Spoofability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dtrh_mail_poc.py
  python dtrh_mail_poc.py -i my_domains.txt
  python dtrh_mail_poc.py dtrh.net example.com test.org
  python dtrh_mail_poc.py -v --json
        """
    )
    parser.add_argument("-i", "--input", help="Input file with domains (one per line)")
    parser.add_argument("-o", "--output", default="./results", help="Output directory for JSON/CSV")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose per-domain detail")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="DNS timeout in seconds")
    parser.add_argument("-j", "--jobs", type=int, default=10, help="Parallel workers")
    parser.add_argument("--json", action="store_true", help="Output JSON only")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("domains", nargs="*", help="Domains to check (space-separated)")
    
    args = parser.parse_args()
    
    global DNS_TIMEOUT, MAX_WORKERS
    DNS_TIMEOUT = args.timeout
    MAX_WORKERS = args.jobs
    
    print_header("dtrh_mail_poc - Email Security Spoofability Scanner")
    
    # ---------------------------------------------------------------------
    # STEP 1: Read domains
    # ---------------------------------------------------------------------
    raw_domains = []
    source = ""
    
    if args.domains:
        # Positional arguments take priority
        raw_domains = args.domains
        source = "command line arguments"
    elif args.input:
        # Custom input file
        filepath = Path(args.input)
        loaded, comments, errors = load_domains_from_file(filepath)
        raw_domains = loaded
        source = f"{filepath} ({comments} comments skipped)"
    else:
        # Default file
        loaded, comments, errors = load_domains_from_file(DEFAULT_LIST_FILE)
        raw_domains = loaded
        source = f"{DEFAULT_LIST_FILE.name} ({comments} comments skipped)"
    
    print_step(1, "Reading domains...", f"Source: {source}\nLoaded: {len(raw_domains)} raw entries")
    
    # ---------------------------------------------------------------------
    # STEP 2: Sanitize domains
    # ---------------------------------------------------------------------
    sanitized = []
    seen = set()
    changes = []
    
    for raw in raw_domains:
        clean = sanitize_domain(raw)
        if clean and clean not in seen:
            seen.add(clean)
            sanitized.append(clean)
            if clean != raw.strip().lower():
                changes.append(f"{raw} → {clean}")
    
    details = [f"{len(raw_domains)} → {len(sanitized)} unique domains after deduplication"]
    if changes:
        details.append("Changes:")
        for c in changes[:10]:  # Show first 10
            details.append(f"  {c}")
        if len(changes) > 10:
            details.append(f"  ... and {len(changes) - 10} more")
    
    print_step(2, "Sanitizing domains...", "\n".join(details))
    
    if not sanitized:
        print("\n  No valid domains to check. Exiting.")
        return 1
    
    # ---------------------------------------------------------------------
    # STEP 3: Check domains
    # ---------------------------------------------------------------------
    print_step(3, f"Checking {len(sanitized)} domains ({MAX_WORKERS} workers)...")
    
    results = []
    completed = 0
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_domain = {executor.submit(check_domain, d): d for d in sanitized}
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            completed += 1
            try:
                result = future.result()
                results.append(result)
                
                # Print progress line
                summary = format_domain_summary(result)
                print(f"  [{completed}/{len(sanitized)}] {summary}")
            except Exception as e:
                log_error(f"{domain}: {e}")
                results.append({
                    "domain": domain,
                    "score": -1,
                    "tier": "ERROR",
                    "reasons": [f"Check failed: {e}"],
                    "mx": {"has_mx": False, "error": str(e)},
                    "spf": {"has_spf": False, "error": str(e)},
                    "dmarc": {"has_dmarc": False, "error": str(e)},
                    "dkim": {"has_dkim": False, "error": str(e)},
                    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                })
    
    # Sort by score descending (most vulnerable first)
    results.sort(key=lambda x: x["score"], reverse=True)
    
    # ---------------------------------------------------------------------
    # STEP 4: Summary & Export
    # ---------------------------------------------------------------------
    if not args.json:
        print_results_table(results, args.verbose)
        
        json_file, csv_file = export_results(results, Path(args.output))
        print(f"\n  Detailed results saved to:")
        print(f"    JSON: {json_file}")
        print(f"    CSV:  {csv_file}")
    else:
        print_json_output(results)
    
    print("\n" + "═" * 70)
    print("  Scan complete.")
    print("═" * 70)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())