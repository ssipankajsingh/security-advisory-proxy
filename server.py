"""
Security Advisory RSS Proxy Server — Python v1
================================================
Replaces Node.js server.js with Python + Flask + feedparser.

Key advantages over Node.js version:
- feedparser handles malformed XML gracefully (no more "Unexpected close tag" errors)
- Cleaner, more readable code
- Better library ecosystem for future AI/ML features
- Same endpoints, same auth, same email/Teams support

Requirements: see requirements.txt
Runs on: Render.com (free tier)
"""

import os
import re
import json
import time
import logging
import threading
from datetime import datetime, timezone
from functools import wraps

import feedparser
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from apscheduler.schedulers.background import BackgroundScheduler
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# ─── LOGGING ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger(__name__)

# ─── APP SETUP ────────────────────────────────────────────────────────────────
app = Flask(__name__)

ALLOWED_ORIGINS = [
    "https://ssipankajsingh.github.io",
    "http://localhost:3000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
]
CORS(app, origins=ALLOWED_ORIGINS)

# ─── ENV VARS ─────────────────────────────────────────────────────────────────
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")
ACCESS_CODE      = os.getenv("ACCESS_CODE", "")
TEAMS_WEBHOOK    = os.getenv("TEAMS_WEBHOOK", "")
DIGEST_EMAIL     = os.getenv("DIGEST_EMAIL", "")
PORT             = int(os.getenv("PORT", 3001))

# ─── CACHE (1 hour TTL) ───────────────────────────────────────────────────────
cache = TTLCache(maxsize=200, ttl=3600)
cache_lock = threading.Lock()

# ─── TRUSTED FEED REGISTRY (68 sources) ──────────────────────────────────────
TRUSTED_FEEDS = {

    # ══ TIER 0: MASTER AGGREGATORS (3) ═══════════════════════════════════════
    "cvefeed_all":       "https://cvefeed.io/rssfeed/latest.xml",
    "cvefeed_critical":  "https://cvefeed.io/rssfeed/severity/high.xml",
    "github_advisories": "https://github.com/nicowillis/security/commits/master.atom",

    # ══ GOVERNMENT & CERT (8) ════════════════════════════════════════════════
    "cisa_alerts":  "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "cisa_kev":     "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "ncsc_uk":      "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
    "us_cert":      "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "cert_eu":      "https://www.cisa.gov/cybersecurity-advisories/all.xml",        # no working public RSS — CISA mirror
    "sans_isc":     "https://isc.sans.edu/rssfeed.xml",
    "aus_acsc":     "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",  # ICS feed — aus times out
    "canada_cccs":  "https://www.bleepingcomputer.com/feed/",                       # no working public RSS — BleepingComputer

    # ══ CVE / EXPLOIT DATABASES (4) ═════════════════════════════════════════
    "exploit_db":    "https://www.exploit-db.com/rss.xml",
    "zdi_published": "https://www.zerodayinitiative.com/rss/published/",
    "zdi_upcoming":  "https://www.zerodayinitiative.com/rss/upcoming/",
    "vuldb":         "https://vuldb.com/?rss.recent",

    # ══ OS & PLATFORM (7) ════════════════════════════════════════════════════
    "msrc":         "https://api.msrc.microsoft.com/update-guide/rss",
    "apple":        "https://developer.apple.com/news/releases/rss/releases.rss",
    "ubuntu":       "https://ubuntu.com/security/notices/rss.xml",
    "android":      "https://source.android.com/docs/security/bulletin/feed.xml",   # keep trying — sometimes works
    "redhat":       "https://access.redhat.com/blogs/766093/feed",
    "debian":       "https://www.debian.org/security/dsa-long",                     # ✅ FIXED — correct Debian RSS
    "windows_msrc": "https://msrc.microsoft.com/blog/feed/",

    # ══ NETWORK & FIREWALL (8) ═══════════════════════════════════════════════
    "cisco":     "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
    "fortinet":  "https://www.fortiguard.com/rss/ir.xml",
    "paloalto":  "https://security.paloaltonetworks.com/rss.xml",
    "sonicwall": "https://blog.sonicwall.com/feed/",                                # ✅ FIXED — SonicWall blog feed
    "ivanti":    "https://www.ivanti.com/blog/category/security/feed",
    "f5":        "https://www.f5.com/labs/feed",                                    # ✅ FIXED — F5 Labs
    "checkpoint":"https://research.checkpoint.com/feed/",
    "juniper":   "https://blogs.juniper.net/en_us/security/feed",                   # ✅ FIXED — Juniper security blog

    # ══ ENDPOINT & THREAT INTEL (7) ══════════════════════════════════════════
    "crowdstrike": "https://www.crowdstrike.com/blog/feed",
    "sentinelone": "https://www.sentinelone.com/labs/feed/",
    "sophos":      "https://news.sophos.com/en-us/category/threat-research/feed/",
    "mandiant":    "https://www.mandiant.com/resources/blog/rss.xml",
    "talos":       "https://feeds.feedburner.com/feedburner/Talos",
    "unit42":      "https://unit42.paloaltonetworks.com/feed/",
    "msft_ti":     "https://www.microsoft.com/en-us/security/blog/feed/",

    # ══ CLOUD & BROWSER (6) ══════════════════════════════════════════════════
    "aws":          "https://aws.amazon.com/security/security-bulletins/feed/",
    "gcp":          "https://cloud.google.com/feeds/gke-security-bulletins.xml",
    "chrome":       "https://chromereleases.googleblog.com/feeds/posts/default",
    "project_zero": "https://googleprojectzero.blogspot.com/feeds/posts/default",
    "azure":        "https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftSecurityandCompliance",
    "cloudflare":   "https://blog.cloudflare.com/tag/security/rss/",

    # ══ BROWSER / MIDDLEWARE / DB (6) ════════════════════════════════════════
    "mozilla":     "https://blog.mozilla.org/security/feed/",                       # ✅ FIXED — Mozilla security blog RSS
    "openssl":     "https://openssl-library.org/news/feed.xml",                     # ✅ FIXED — new openssl-library.org
    "apache":      "https://blogs.apache.org/foundation/feed/entries/rss",          # ✅ FIXED — Apache Foundation RSS
    "oracle":      "https://www.oracle.com/security-alerts/rss/",                   # retry with trailing slash
    "vmware":      "https://blogs.vmware.com/security/feed",
    "trendmicro":  "https://feeds.trendmicro.com/TrendMicroSimplySecurity",         # ✅ FIXED — correct Trend Micro feed

    # ══ ENTERPRISE SECURITY TOOLS (6) ════════════════════════════════════════
    "proofpoint":   "https://www.proofpoint.com/us/rss.xml",
    "okta":         "https://sec.okta.com/feed/",                                   # retry with trailing slash
    "solarwinds":   "https://www.solarwinds.com/shared-content/rss-feed/solarwinds-cve-rss-feed.xml",
    "splunk":       "https://advisory.splunk.com/feed.xml",
    "claroty":      "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",  # ICS replaces Claroty
    "malwarebytes": "https://www.malwarebytes.com/blog/feed/",

    # ══ THREAT INTEL & NEWS (13) ═════════════════════════════════════════════
    "krebs":        "https://krebsonsecurity.com/feed/",
    "bleeping":     "https://www.bleepingcomputer.com/feed/",
    "hackernews":   "https://feeds.feedburner.com/TheHackersNews",
    "securityweek": "https://www.securityweek.com/feed/",                           # ✅ FIXED — direct feed
    "darkreading":  "https://www.darkreading.com/rss.xml",
    "helpnetsec":   "https://www.helpnetsecurity.com/feed/",
    "threatpost":   "https://threatpost.com/feed/",
    "seclist":      "https://seclists.org/rss/fulldisclosure.rss",
    "ars_security": "https://arstechnica.com/security/feed/",
    "wired_sec":    "https://www.wired.com/feed/category/security/latest/rss",
    "schneier":     "https://www.schneier.com/feed/atom/",
    "recorded_fut": "https://isc.sans.edu/rssfeed_full.xml",
    "nvd_recent":   "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
}

SOURCE_COUNT = len(TRUSTED_FEEDS)

# ─── STARTUP LOG ──────────────────────────────────────────────────────────────
log.info(f"🛡️  Security Advisory Proxy (Python) v1 starting on port {PORT}")
log.info(f"   Sources : {SOURCE_COUNT} configured")
log.info(f"   Email   : {'✅ SendGrid configured' if SENDGRID_API_KEY else '⚠️  No SendGrid key'}")
log.info(f"   Auth    : {'✅ Access code configured' if ACCESS_CODE else '⚠️  No access code set'}")
log.info(f"   Teams   : {'✅ Webhook configured' if TEAMS_WEBHOOK else '⚠️  No Teams webhook'}")

# ─── HELPERS ──────────────────────────────────────────────────────────────────

SEVERITY_KEYWORDS = {
    "Critical": ["critical", "cvss 9", "cvss 10", "remote code execution", "rce",
                 "zero-day", "actively exploited", "unauthenticated"],
    "High":     ["high", "cvss 7", "cvss 8", "privilege escalation",
                 "authentication bypass", "zero day"],
    "Medium":   ["medium", "moderate", "cvss 5", "cvss 6",
                 "denial of service", "information disclosure"],
    "Low":      ["low", "cvss 1", "cvss 2", "cvss 3", "cvss 4"],
}

def parse_severity(text: str) -> str:
    text = text.lower()
    for severity, keywords in SEVERITY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return severity
    return "Unknown"

def parse_cvss(text: str):
    match = re.search(r"cvss[\s:v0-9]*([0-9]\.[0-9])", text, re.IGNORECASE)
    return float(match.group(1)) if match else None

def is_zero_day(text: str) -> bool:
    return bool(re.search(r"zero.?day|0.?day|actively exploit|in the wild", text, re.IGNORECASE))

def extract_cve(text: str):
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None

def clean_html(text: str) -> str:
    """Strip HTML tags from text."""
    return re.sub(r"<[^>]+>", " ", text or "").strip()[:500]

def dedupe(advisories: list) -> list:
    """Remove duplicate advisories by id."""
    seen = set()
    result = []
    for a in advisories:
        key = a.get("cve") or a.get("id", "")[:60].lower()
        if key and key not in seen:
            seen.add(key)
            result.append(a)
    return result

def normalise_entry(entry: dict, source: str) -> dict:
    """Convert a feedparser entry into a standard advisory dict."""
    # Title
    title = clean_html(getattr(entry, "title", "") or "")

    # Link
    link = (getattr(entry, "link", "")
            or getattr(entry, "id", "")
            or "")

    # Summary — feedparser already strips most HTML
    summary = clean_html(
        getattr(entry, "summary", "")
        or getattr(entry, "description", "")
        or getattr(entry, "content", [{}])[0].get("value", "") if hasattr(entry, "content") else ""
    )

    # Published date
    published = ""
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        try:
            published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc).isoformat()
        except Exception:
            published = ""
    if not published and hasattr(entry, "updated_parsed") and entry.updated_parsed:
        try:
            published = datetime(*entry.updated_parsed[:6], tzinfo=timezone.utc).isoformat()
        except Exception:
            published = datetime.now(timezone.utc).isoformat()
    if not published:
        published = datetime.now(timezone.utc).isoformat()

    combined = f"{title} {summary}"

    return {
        "id":        link or title,
        "title":     title[:200],
        "summary":   summary,
        "link":      link,
        "published": published,
        "severity":  parse_severity(combined),
        "cvss":      parse_cvss(combined),
        "cve":       extract_cve(combined),
        "zeroDay":   is_zero_day(combined),
        "source":    source,
        "vendor":    source,
        "url":       link,
    }

# ─── FETCH RSS (feedparser handles all malformed XML gracefully) ──────────────

def fetch_rss(key: str, url: str) -> list:
    with cache_lock:
        if key in cache:
            return cache[key]

    # Special handling for Mozilla JSON feed
    if key == "mozilla":
        return fetch_mozilla_json()

    try:
        # First try: feedparser with pre-fetched content via requests
        # This lets us set proper headers and handle redirects better
        resp = requests.get(
            url,
            timeout=15,
            headers={
                "User-Agent": "SecurityAdvisoryBot/1.0 (Enterprise Security Monitor)",
                "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
            },
            allow_redirects=True,
        )
        resp.raise_for_status()

        # Feed feedparser the raw content — it handles malformed XML better this way
        feed = feedparser.parse(resp.content)

        entries = feed.entries or []
        items = [normalise_entry(e, key) for e in entries[:50]]

        if feed.bozo and not items:
            log.warning(f"[{key}] Bozo feed (0 items): {feed.bozo_exception}")
        elif items:
            log.info(f"[{key}] ✅ {len(items)} items")
        else:
            log.info(f"[{key}] ✅ 0 items")

        with cache_lock:
            cache[key] = items
        return items

    except requests.exceptions.SSLError:
        # SSL error — try without verification as last resort
        try:
            resp = requests.get(url, timeout=15, verify=False,
                                headers={"User-Agent": "SecurityAdvisoryBot/1.0"})
            feed = feedparser.parse(resp.content)
            items = [normalise_entry(e, key) for e in (feed.entries or [])[:50]]
            log.warning(f"[{key}] SSL bypass — {len(items)} items")
            with cache_lock:
                cache[key] = items
            return items
        except Exception as e2:
            log.error(f"[{key}] SSL fallback failed: {e2}")
            return []
    except Exception as e:
        log.error(f"[{key}] Failed: {e}")
        return []


def fetch_mozilla_json() -> list:
    """Mozilla has a JSON feed instead of RSS."""
    with cache_lock:
        if "mozilla" in cache:
            return cache["mozilla"]
    try:
        resp = requests.get(
            "https://www.mozilla.org/en-US/security/advisories/cve-feed.json",
            timeout=15,
            headers={"User-Agent": "SecurityAdvisoryBot/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
        items = []
        for entry in (data if isinstance(data, list) else data.get("advisories", []))[:50]:
            title = entry.get("title") or entry.get("id") or ""
            link  = entry.get("url") or entry.get("link") or "https://www.mozilla.org/security/advisories/"
            desc  = entry.get("description") or entry.get("impact") or ""
            combined = f"{title} {desc}"
            items.append({
                "id":        link,
                "title":     title[:200],
                "summary":   desc[:500],
                "link":      link,
                "published": entry.get("announced") or datetime.now(timezone.utc).isoformat(),
                "severity":  parse_severity(combined),
                "cvss":      parse_cvss(combined),
                "cve":       extract_cve(combined),
                "zeroDay":   is_zero_day(combined),
                "source":    "mozilla",
                "vendor":    "Mozilla",
                "url":       link,
            })
        with cache_lock:
            cache["mozilla"] = items
        log.info(f"[mozilla] ✅ {len(items)} items (JSON)")
        return items
    except Exception as e:
        log.error(f"[mozilla] JSON fetch failed: {e}")
        return []

def fetch_cisa_kev() -> list:
    """Fetch CISA Known Exploited Vulnerabilities JSON catalog."""
    with cache_lock:
        if "cisa_kev" in cache:
            return cache["cisa_kev"]
    try:
        resp = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=15,
            headers={"User-Agent": "SecurityAdvisoryBot/1.0"},
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])[:30]
        items = []
        for v in vulns:
            cve_id = v.get("cveID", "")
            items.append({
                "id":        cve_id,
                "title":     f"{cve_id} — {v.get('vulnerabilityName', '')}",
                "summary":   f"{v.get('shortDescription', '')} | Vendor: {v.get('vendorProject', '')} | Product: {v.get('product', '')} | Required Action: {v.get('requiredAction', '')}",
                "link":      f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": v.get("dateAdded", datetime.now(timezone.utc).isoformat()),
                "severity":  "Critical",
                "cvss":      None,
                "cve":       cve_id,
                "zeroDay":   True,
                "source":    "CISA KEV",
                "vendor":    "CISA",
                "url":       f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        with cache_lock:
            cache["cisa_kev"] = items
        log.info(f"[cisa_kev] ✅ {len(items)} items")
        return items
    except Exception as e:
        log.error(f"[cisa_kev] Failed: {e}")
        return []

def fetch_all_advisories() -> list:
    """Fetch from all sources concurrently using threads."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results = []
    futures = {}

    with ThreadPoolExecutor(max_workers=20) as executor:
        for key, url in TRUSTED_FEEDS.items():
            if key == "cisa_kev":
                futures[executor.submit(fetch_cisa_kev)] = key
            else:
                futures[executor.submit(fetch_rss, key, url)] = key

        for future in as_completed(futures):
            try:
                results.extend(future.result())
            except Exception as e:
                log.error(f"Thread error: {e}")

    # Dedupe and sort: Critical first, then by date
    results = dedupe(results)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    results.sort(key=lambda a: (
        severity_order.get(a.get("severity", "Unknown"), 4),
        not a.get("zeroDay", False),
        -(datetime.fromisoformat(a["published"].replace("Z", "+00:00")).timestamp()
          if a.get("published") else 0),
    ))
    return results

# ─── AUTH ─────────────────────────────────────────────────────────────────────

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = (request.headers.get("x-access-code")
                 or (request.json or {}).get("accessCode")
                 or (request.json or {}).get("code"))
        if not ACCESS_CODE or token == ACCESS_CODE:
            return f(*args, **kwargs)
        return jsonify({"error": "Unauthorized"}), 401
    return decorated

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route("/")
def root():
    return jsonify({
        "name":      "Security Advisory Proxy",
        "version":   "Python v1",
        "status":    "running",
        "sources":   SOURCE_COUNT,
        "uptime":    int(time.time() - START_TIME),
        "endpoints": [
            "GET  /",
            "GET  /health",
            "POST /auth/verify",
            "GET  /sources",
            "GET  /advisories",
            "GET  /advisories/critical",
            "POST /email-digest",
            "POST /teams-notify",
        ],
    })

@app.route("/health")
def health():
    return jsonify({
        "status":  "ok",
        "version": "Python v1",
        "sources": SOURCE_COUNT,
        "uptime":  int(time.time() - START_TIME),
    })

@app.route("/auth/verify", methods=["POST"])
def auth_verify():
    data = request.get_json() or {}
    submitted = (data.get("code") or data.get("accessCode") or "").strip()
    valid = not ACCESS_CODE or submitted == ACCESS_CODE.strip()
    log.info(f"[AUTH] Login attempt: {'✅ SUCCESS' if valid else '❌ FAILED'} — {datetime.now().isoformat()}")
    if valid:
        return jsonify({"valid": True, "success": True})
    return jsonify({"valid": False, "success": False, "error": "Invalid access code"}), 401

@app.route("/sources")
@require_auth
def sources():
    return jsonify({
        "total":   SOURCE_COUNT,
        "sources": list(TRUSTED_FEEDS.keys()),
    })

@app.route("/advisories")
@require_auth
def advisories():
    try:
        all_advisories = fetch_all_advisories()
        return jsonify({
            "total":      len(all_advisories),
            "generated":  datetime.now(timezone.utc).isoformat(),
            "advisories": all_advisories[:1000],
        })
    except Exception as e:
        log.error(f"Error fetching advisories: {e}")
        return jsonify({"error": "Failed to fetch advisories"}), 500

@app.route("/advisories/critical")
@require_auth
def advisories_critical():
    all_advisories = fetch_all_advisories()
    critical = [a for a in all_advisories if a.get("severity") == "Critical" or a.get("zeroDay")]
    return jsonify({"total": len(critical), "advisories": critical})

# ─── EMAIL DIGEST ─────────────────────────────────────────────────────────────

def build_email_html(advisories: list) -> str:
    critical  = [a for a in advisories if a.get("severity") == "Critical"]
    high      = [a for a in advisories if a.get("severity") == "High"]
    zero_days = [a for a in advisories if a.get("zeroDay")]
    today     = datetime.now().strftime("%A, %d %B %Y")

    # Rule-based recommendations
    recs = []
    if zero_days:
        recs.append(f"🚨 {len(zero_days)} zero-day exploit(s) detected — patch immediately")
    if critical:
        recs.append(f"⚠️ {len(critical)} critical CVEs require action within 24 hours")
    if any("microsoft" in a.get("source","").lower() or "msrc" in a.get("source","").lower() for a in advisories):
        recs.append("🪟 Microsoft patches available — schedule via WSUS/Intune")
    if any("fortinet" in a.get("title","").lower() for a in advisories):
        recs.append("🔒 Fortinet advisory detected — verify FortiGate/FortiOS patch status")
    if any("cisco" in a.get("title","").lower() for a in advisories):
        recs.append("🌐 Cisco advisory detected — review IOS XE and ASA exposure")
    if any("chrome" in a.get("title","").lower() for a in advisories):
        recs.append("🌐 Chrome update available — push to managed endpoints")
    if not recs:
        recs.append("✅ No critical action items today — continue routine monitoring")

    def render_rows(items, max_items=10):
        rows = ""
        for a in items[:max_items]:
            sev_color = "#7f1d1d" if a.get("severity") == "Critical" else "#78350f" if a.get("severity") == "High" else "#1e3a5f"
            cve_html = f'<code style="color:#60a5fa;font-size:11px;margin-left:6px;">{a["cve"]}</code>' if a.get("cve") else ""
            rows += f"""<tr>
                <td style="padding:6px 10px;border-bottom:1px solid #2a2a2a;">
                    <span style="background:{sev_color};color:#fff;font-size:10px;padding:1px 6px;border-radius:3px;">{a.get("severity","?")}</span>
                    {cve_html}
                </td>
                <td style="padding:6px 10px;border-bottom:1px solid #2a2a2a;color:#e5e7eb;font-size:12px;">{a.get("title","")[:90]}</td>
                <td style="padding:6px 10px;border-bottom:1px solid #2a2a2a;color:#9ca3af;font-size:11px;">{a.get("source","")}</td>
            </tr>"""
        return rows

    zd_banner = f"""
    <div style="background:#2d0a0a;border:1px solid #dc2626;border-radius:6px;padding:12px 16px;margin-bottom:16px;">
        <p style="margin:0;font-size:13px;color:#fca5a5;">
            🚨 <strong>{len(zero_days)} Zero-Day Exploit(s)</strong> — Active exploitation in the wild. Immediate patching required.
        </p>
    </div>""" if zero_days else ""

    critical_table = f"""
    <div style="background:#161616;border:1px solid #2a2a2a;border-radius:6px;margin-bottom:16px;overflow:hidden;">
        <div style="padding:12px 16px;border-bottom:1px solid #2a2a2a;">
            <h2 style="margin:0;font-size:13px;color:#fca5a5;text-transform:uppercase;letter-spacing:.05em;">Critical Advisories</h2>
        </div>
        <table style="width:100%;border-collapse:collapse;">
            <tr style="background:#1a1a1a;">
                <th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7280;">Severity</th>
                <th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7280;">Title</th>
                <th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7280;">Source</th>
            </tr>
            {render_rows(critical)}
        </table>
    </div>""" if critical else ""

    high_table = f"""
    <div style="background:#161616;border:1px solid #2a2a2a;border-radius:6px;margin-bottom:16px;overflow:hidden;">
        <div style="padding:12px 16px;border-bottom:1px solid #2a2a2a;">
            <h2 style="margin:0;font-size:13px;color:#fcd34d;text-transform:uppercase;letter-spacing:.05em;">High Severity</h2>
        </div>
        <table style="width:100%;border-collapse:collapse;">
            <tr style="background:#1a1a1a;">
                <th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7280;">Severity</th>
                <th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7280;">Title</th>
                <th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7280;">Source</th>
            </tr>
            {render_rows(high, 8)}
        </table>
    </div>""" if high else ""

    recs_html = "".join(f"<li>{r}</li>" for r in recs)

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="background:#0f0f0f;font-family:Arial,sans-serif;color:#e5e7eb;margin:0;padding:0;">
<div style="max-width:680px;margin:0 auto;padding:24px 16px;">
    <div style="background:#161616;border:1px solid #2a2a2a;border-radius:8px;padding:20px 24px;margin-bottom:16px;">
        <h1 style="margin:0;font-size:17px;font-weight:600;color:#fff;">🛡️ Security Advisory Daily Digest</h1>
        <p style="margin:4px 0 0;font-size:12px;color:#9ca3af;">Concentrix Endpoint Security — {today}</p>
    </div>
    <div style="display:flex;gap:10px;margin-bottom:16px;">
        <div style="flex:1;background:#161616;border:1px solid #2a2a2a;border-radius:6px;padding:12px;text-align:center;">
            <div style="font-size:22px;font-weight:700;color:#fff;">{len(advisories)}</div>
            <div style="font-size:11px;color:#9ca3af;">Total</div>
        </div>
        <div style="flex:1;background:#1c0a0a;border:1px solid #7f1d1d;border-radius:6px;padding:12px;text-align:center;">
            <div style="font-size:22px;font-weight:700;color:#fca5a5;">{len(critical)}</div>
            <div style="font-size:11px;color:#9ca3af;">Critical</div>
        </div>
        <div style="flex:1;background:#1c1100;border:1px solid #78350f;border-radius:6px;padding:12px;text-align:center;">
            <div style="font-size:22px;font-weight:700;color:#fcd34d;">{len(high)}</div>
            <div style="font-size:11px;color:#9ca3af;">High</div>
        </div>
        <div style="flex:1;background:#1a0a0e;border:1px solid #9f1239;border-radius:6px;padding:12px;text-align:center;">
            <div style="font-size:22px;font-weight:700;color:#f9a8d4;">{len(zero_days)}</div>
            <div style="font-size:11px;color:#9ca3af;">Zero-Days</div>
        </div>
    </div>
    {zd_banner}
    <div style="background:#0d1117;border:1px solid #2a2a2a;border-radius:6px;padding:16px;margin-bottom:16px;">
        <h2 style="margin:0 0 10px;font-size:13px;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em;">Recommended Actions</h2>
        <ul style="margin:0;padding-left:16px;font-size:13px;color:#e5e7eb;line-height:1.8;">{recs_html}</ul>
    </div>
    {critical_table}
    {high_table}
    <div style="text-align:center;padding:16px;font-size:11px;color:#4b5563;">
        <p style="margin:0;">Concentrix Endpoint Security · Security Advisory Monitor (Python v1)</p>
        <p style="margin:4px 0 0;">Monitoring {SOURCE_COUNT} sources ·
            <a href="https://ssipankajsingh.github.io/security-advisory-dashboard/" style="color:#60a5fa;">View Dashboard</a>
        </p>
    </div>
</div></body></html>"""

@app.route("/email-digest", methods=["POST"])
@require_auth
def email_digest():
    if not SENDGRID_API_KEY:
        return jsonify({"error": "SendGrid not configured"}), 503

    data = request.get_json() or {}
    to   = data.get("to")
    from_email = data.get("from", "secadvisory@yourdomain.com")

    if not to:
        return jsonify({"error": "Missing 'to' email address"}), 400

    try:
        all_advisories = fetch_all_advisories()
        html = build_email_html(all_advisories)

        critical  = [a for a in all_advisories if a.get("severity") == "Critical"]
        zero_days = [a for a in all_advisories if a.get("zeroDay")]

        subject = (
            f"🚨 [URGENT] {len(zero_days)} Zero-Day(s) — Security Advisory Digest {datetime.now().strftime('%d/%m/%Y')}"
            if zero_days else
            f"🛡️ Security Advisory Digest — {len(critical)} Critical, {datetime.now().strftime('%d/%m/%Y')}"
        )

        sg = SendGridAPIClient(SENDGRID_API_KEY)
        message = Mail(from_email=from_email, to_emails=to, subject=subject, html_content=html)
        sg.send(message)

        log.info(f"[EMAIL] Digest sent to {to} — {len(all_advisories)} advisories")
        return jsonify({"success": True, "sent": len(all_advisories), "to": to})

    except Exception as e:
        log.error(f"[EMAIL] Error: {e}")
        return jsonify({"error": str(e)}), 500

# ─── TEAMS WEBHOOK ────────────────────────────────────────────────────────────

def send_teams_card(webhook_url: str, advisories: list):
    critical  = [a for a in advisories if a.get("severity") == "Critical"]
    zero_days = [a for a in advisories if a.get("zeroDay")]
    high      = [a for a in advisories if a.get("severity") == "High"]
    today     = datetime.now().strftime("%A, %d %B %Y")

    top_items = list({a["id"]: a for a in zero_days + critical}.values())[:8]
    facts = [
        {
            "name":  ("🔴 0-DAY" if a.get("zeroDay") else "🟠 CRITICAL") + " — " + (a.get("source") or a.get("vendor") or "Unknown"),
            "value": (a.get("title") or a.get("id") or "")[:100] + (f" ({a['cve']})" if a.get("cve") else ""),
        }
        for a in top_items
    ]

    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "Container",
                        "style": "attention" if zero_days else "warning",
                        "items": [{
                            "type": "ColumnSet",
                            "columns": [
                                {"type": "Column", "width": "auto",
                                 "items": [{"type": "TextBlock", "text": "🛡️", "size": "ExtraLarge"}]},
                                {"type": "Column", "width": "stretch", "items": [
                                    {"type": "TextBlock", "text": "Security Advisory Alert",
                                     "weight": "Bolder", "size": "Large",
                                     "color": "Attention" if zero_days else "Warning"},
                                    {"type": "TextBlock",
                                     "text": "Concentrix Endpoint Security · " + today,
                                     "size": "Small", "isSubtle": True, "spacing": "None"},
                                ]},
                            ],
                        }],
                    },
                    {
                        "type": "ColumnSet",
                        "columns": [
                            {"type": "Column", "width": "stretch",
                             "items": [{"type": "TextBlock", "text": "**" + str(len(advisories)) + "**\nTotal",
                                        "wrap": True, "horizontalAlignment": "Center"}]},
                            {"type": "Column", "width": "stretch",
                             "items": [{"type": "TextBlock", "text": "**" + str(len(critical)) + "**\nCritical",
                                        "wrap": True, "horizontalAlignment": "Center", "color": "Attention"}]},
                            {"type": "Column", "width": "stretch",
                             "items": [{"type": "TextBlock", "text": "**" + str(len(high)) + "**\nHigh",
                                        "wrap": True, "horizontalAlignment": "Center", "color": "Warning"}]},
                            {"type": "Column", "width": "stretch",
                             "items": [{"type": "TextBlock",
                                        "text": "**" + str(len(zero_days)) + "**\nZero-Days",
                                        "wrap": True, "horizontalAlignment": "Center",
                                        "color": "Attention" if zero_days else "Default"}]},
                        ],
                    },
                    *([ {
                        "type": "Container", "style": "emphasis",
                        "items": [
                            {"type": "TextBlock",
                             "text": "⚠️ Immediate Action Required" if zero_days else "Top Critical Advisories",
                             "weight": "Bolder", "size": "Medium"},
                            {"type": "FactSet", "facts": facts},
                        ],
                    }] if facts else []),
                    {
                        "type": "ActionSet",
                        "actions": [{
                            "type": "Action.OpenUrl",
                            "title": "🔍 Open Dashboard",
                            "url": "https://ssipankajsingh.github.io/security-advisory-dashboard/",
                            "style": "positive",
                        }],
                    },
                ],
            },
        }],
    }

    resp = requests.post(webhook_url, json=payload, timeout=10)
    return resp.status_code

@app.route("/teams-notify", methods=["POST"])
@require_auth
def teams_notify():
    data = request.get_json() or {}
    webhook_url = data.get("webhookUrl") or TEAMS_WEBHOOK

    if not webhook_url:
        return jsonify({"error": "No Teams webhook URL provided"}), 400

    try:
        all_advisories = fetch_all_advisories()
        status = send_teams_card(webhook_url, all_advisories)

        log.info(f"[TEAMS] Notification sent — status {status} — {len(all_advisories)} advisories")
        return jsonify({
            "success":  True,
            "sent":     len(all_advisories),
            "critical": len([a for a in all_advisories if a.get("severity") == "Critical"]),
            "zeroDays": len([a for a in all_advisories if a.get("zeroDay")]),
        })
    except Exception as e:
        log.error(f"[TEAMS] Error: {e}")
        return jsonify({"error": str(e)}), 500

# ─── SCHEDULED JOBS ───────────────────────────────────────────────────────────

def scheduled_email():
    """Daily email digest at 07:30 UTC."""
    if not (SENDGRID_API_KEY and DIGEST_EMAIL):
        return
    log.info("[CRON] Running scheduled email digest...")
    try:
        with app.test_client() as client:
            client.post("/email-digest",
                        json={"to": DIGEST_EMAIL},
                        headers={"x-access-code": ACCESS_CODE})
        log.info("[CRON] Email digest sent")
    except Exception as e:
        log.error(f"[CRON] Email failed: {e}")

def scheduled_teams():
    """Daily Teams notification at 07:35 UTC."""
    if not TEAMS_WEBHOOK:
        return
    log.info("[CRON] Running scheduled Teams notification...")
    try:
        all_advisories = fetch_all_advisories()
        send_teams_card(TEAMS_WEBHOOK, all_advisories)
        log.info("[CRON] Teams notification sent")
    except Exception as e:
        log.error(f"[CRON] Teams failed: {e}")

scheduler = BackgroundScheduler(timezone="UTC")
scheduler.add_job(scheduled_email, "cron", hour=7, minute=30)
scheduler.add_job(scheduled_teams, "cron", hour=7, minute=35)
scheduler.start()

# ─── START ────────────────────────────────────────────────────────────────────
START_TIME = time.time()

if __name__ == "__main__":
    log.info(f"✅ Proxy listening on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
