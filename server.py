"""
Security Advisory RSS Proxy Server — Python v2
================================================
All pending fixes applied — April 2026
"""

import os, re, json, time, logging, threading
from datetime import datetime, timezone, timedelta
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed

import feedparser, requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from apscheduler.schedulers.background import BackgroundScheduler
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# ─── LOGGING ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger(__name__)

# ─── APP ──────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, origins=[
    "https://ssipankajsingh.github.io",
    "http://localhost:3000","http://localhost:5500","http://127.0.0.1:5500",
])

# ─── ENV ──────────────────────────────────────────────────────────────────────
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY","")
ACCESS_CODE      = os.getenv("ACCESS_CODE","")
TEAMS_WEBHOOK    = os.getenv("TEAMS_WEBHOOK","")
DIGEST_EMAIL     = os.getenv("DIGEST_EMAIL","")
PORT             = int(os.getenv("PORT",3001))
SUPABASE_URL     = os.getenv("SUPABASE_URL","").rstrip("/")
SUPABASE_KEY     = os.getenv("SUPABASE_KEY","")

# ─── CACHE ────────────────────────────────────────────────────────────────────
cache      = TTLCache(maxsize=200, ttl=3600)
cache_lock = threading.Lock()

# ─── SUPABASE ─────────────────────────────────────────────────────────────────
def supa_headers(prefer="return=representation"):
    return {"apikey":SUPABASE_KEY,"Authorization":f"Bearer {SUPABASE_KEY}",
            "Content-Type":"application/json","Prefer":prefer}

def supa_get_acks() -> dict:
    if not (SUPABASE_URL and SUPABASE_KEY): return {}
    try:
        r = requests.get(f"{SUPABASE_URL}/rest/v1/acknowledgments?select=*", headers=supa_headers(), timeout=8)
        if r.status_code == 200:
            return {row["id"]:{
                "by":          row["acknowledged_by"],
                "at":          row["acknowledged_at"],
                "note":        row.get("note",""),
                "status":      row.get("status","In Review"),
                "assigned_to": row.get("assigned_to",""),
                "ai_triage":   row.get("ai_triage",""),
            } for row in r.json()}
    except Exception as e: log.error(f"[SUPABASE] get_acks: {e}")
    return {}

def supa_set_ack(advisory_id:str, by:str, note:str="", status:str="In Review", assigned_to:str="", ai_triage:str="") -> bool:
    if not (SUPABASE_URL and SUPABASE_KEY): return False
    try:
        h = {**supa_headers(),"Prefer":"resolution=merge-duplicates,return=representation"}
        payload = {
            "id":              advisory_id,
            "acknowledged_by": by,
            "acknowledged_at": datetime.now(timezone.utc).isoformat(),
            "note":            note,
            "status":          status,
            "assigned_to":     assigned_to,
            "ai_triage":       ai_triage,
        }
        r = requests.post(f"{SUPABASE_URL}/rest/v1/acknowledgments", headers=h, json=payload, timeout=8)
        return r.status_code in (200,201)
    except Exception as e: log.error(f"[SUPABASE] set_ack: {e}"); return False

def supa_delete_ack(advisory_id:str, by:str) -> bool:
    """Only allow delete if acknowledged_by matches requester."""
    if not (SUPABASE_URL and SUPABASE_KEY): return False
    try:
        # Verify ownership first
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/acknowledgments?id=eq.{requests.utils.quote(advisory_id)}&select=acknowledged_by",
            headers=supa_headers(), timeout=8)
        if r.status_code == 200:
            rows = r.json()
            if rows and rows[0].get("acknowledged_by","") != by:
                log.warning(f"[SUPABASE] Undo blocked: {advisory_id} owned by {rows[0].get('acknowledged_by')} not {by}")
                return False
        r = requests.delete(
            f"{SUPABASE_URL}/rest/v1/acknowledgments?id=eq.{requests.utils.quote(advisory_id)}",
            headers=supa_headers(), timeout=8)
        return r.status_code in (200,204)
    except Exception as e: log.error(f"[SUPABASE] delete_ack: {e}"); return False

def supa_save_advisory_cache(advisories:list) -> bool:
    if not (SUPABASE_URL and SUPABASE_KEY): return False
    try:
        now = datetime.now(timezone.utc).isoformat()
        rows = [{"id":a["id"][:500],"data":{**a,"isNew":False},"fetched_at":now} for a in advisories[:2500] if a.get("id")]
        h = {**supa_headers(),"Prefer":"resolution=merge-duplicates"}
        saved = 0
        for i in range(0, len(rows), 100):
            r = requests.post(f"{SUPABASE_URL}/rest/v1/advisory_cache", headers=h, json=rows[i:i+100], timeout=20)
            if r.status_code not in (200,201): log.warning(f"[SUPABASE] Cache batch {i//100} failed: {r.status_code}")
            else: saved += len(rows[i:i+100])
        # Purge items older than 90 days
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        requests.delete(f"{SUPABASE_URL}/rest/v1/advisory_cache?fetched_at=lt.{cutoff}", headers=supa_headers(), timeout=10)
        log.info(f"[SUPABASE] Cache saved: {saved}/{len(rows)} items")
        return True
    except Exception as e: log.error(f"[SUPABASE] save_cache: {e}"); return False

def supa_load_advisory_cache() -> list:
    """Load all rows from advisory_cache in paginated 1000-row chunks (handles 2500+ rows)."""
    if not (SUPABASE_URL and SUPABASE_KEY): return []
    all_items = []
    offset = 0
    chunk = 1000
    while True:
        try:
            url = (f"{SUPABASE_URL}/rest/v1/advisory_cache"
                   f"?select=data&order=fetched_at.desc&limit={chunk}&offset={offset}")
            r = requests.get(url, headers=supa_headers(), timeout=15)
            if r.status_code != 200:
                log.warning(f"[SUPABASE] load_cache page offset={offset}: HTTP {r.status_code}")
                break
            rows = r.json()
            items = [row["data"] for row in rows if row.get("data")]
            all_items.extend(items)
            if len(rows) < chunk:
                break  # last page
            offset += chunk
        except Exception as e:
            log.error(f"[SUPABASE] load_cache page offset={offset}: {e}")
            break
    log.info(f"[SUPABASE] Cache loaded: {len(all_items)} items (paginated, {offset+chunk} rows scanned)")
    return all_items

def supa_get_source_config() -> dict:
    if not (SUPABASE_URL and SUPABASE_KEY): return {}
    try:
        r = requests.get(f"{SUPABASE_URL}/rest/v1/source_config?select=*", headers=supa_headers(), timeout=8)
        if r.status_code == 200: return {row["id"]:row["enabled"] for row in r.json()}
    except Exception as e: log.error(f"[SUPABASE] get_source_config: {e}")
    return {}

def supa_set_source_config(source_id:str, enabled:bool, updated_by:str) -> bool:
    if not (SUPABASE_URL and SUPABASE_KEY): return False
    try:
        h = {**supa_headers(),"Prefer":"resolution=merge-duplicates,return=representation"}
        r = requests.post(f"{SUPABASE_URL}/rest/v1/source_config", headers=h,
            json={"id":source_id,"enabled":enabled,"updated_by":updated_by,"updated_at":datetime.now(timezone.utc).isoformat()}, timeout=8)
        return r.status_code in (200,201)
    except Exception as e: log.error(f"[SUPABASE] set_source_config: {e}"); return False

# Purge acks older than 1 year
def supa_purge_old_acks():
    if not (SUPABASE_URL and SUPABASE_KEY): return
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        requests.delete(f"{SUPABASE_URL}/rest/v1/acknowledgments?acknowledged_at=lt.{cutoff}", headers=supa_headers(), timeout=10)
        log.info("[SUPABASE] Old acks purged")
    except Exception as e: log.error(f"[SUPABASE] purge_acks: {e}")

# ─── TRUSTED FEED REGISTRY (86 sources) ──────────────────────────────────────
TRUSTED_FEEDS = {

    # ══ TIER 0: MASTER AGGREGATORS ═══════════════════════════════════════════
    "cvefeed_all":           "https://cvefeed.io/rssfeed/",
    "cvefeed_high_critical": "https://cvefeed.io/rssfeed/high.xml",
    "github_advisories":     "https://github.com/advisories.atom",
    "cvedaily_all":          "https://cvedaily.com/feed.xml",
    "cvedaily_new":          "https://cvedaily.com/feed-new.xml",
    "cvedaily_critical":     "https://cvedaily.com/feed-critical.xml",

    # ══ GOVERNMENT & CERT ════════════════════════════════════════════════════
    "cisa_alerts":       "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "cisa_kev":          "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cisa_ics":          "https://www.cisa.gov/ics/advisories/rss.xml",
    "ncsc_uk":           "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
    "us_cert":           "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "cert_eu":           "https://cert.europa.eu/publications/security-advisories-rss",
    "certeu_threat_intel":"https://cert.europa.eu/publications/threat-intelligence-rss",
    "cert_in":           "https://www.cert-in.org.in/RSS/Vulnerability_Notes.xml",
    "sans_isc":          "https://isc.sans.edu/rssfeed.xml",

    # ══ CVE / EXPLOIT DATABASES ══════════════════════════════════════════════
    "exploit_db":    "https://www.exploit-db.com/rss.xml",
    "zdi_published": "https://www.zerodayinitiative.com/rss/published/",
    "zdi_upcoming":  "https://www.zerodayinitiative.com/rss/upcoming/",
    "vuldb":         "https://vuldb.com/?rss.recent",
    "packetstorm":   "https://rss.packetstormsecurity.com/files/",
    "nvd_recent":    "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",

    # ══ OS & PLATFORM ════════════════════════════════════════════════════════
    "msrc":         "https://api.msrc.microsoft.com/update-guide/rss",
    "msrc_blog":    "https://msrc.microsoft.com/blog/feed/",
    "ms_azure":     "https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftSecurityandCompliance",
    "apple":        "https://support.apple.com/en-in/rss/securityupdates.rss",
    "ubuntu":       "https://ubuntu.com/security/notices/rss.xml",
    "android":      "https://source.android.com/security/bulletin/rss.xml",
    "redhat":       "https://access.redhat.com/security/data/rss",
    "debian":       "https://www.debian.org/security/dsa-long",
    "docker":       "https://docs.docker.com/security/rss.xml",

    # ══ NETWORK & FIREWALL ═══════════════════════════════════════════════════
    "cisco":        "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
    "fortinet":     "https://www.fortiguard.com/rss/ir.xml",
    "paloalto":     "https://security.paloaltonetworks.com/rss.xml",
    "paloalto_psirt":"https://securityadvisories.paloaltonetworks.com/rss.xml",
    "sonicwall":    "https://blog.sonicwall.com/feed/",
    "ivanti":       "https://forums.ivanti.com/s/rss/security-advisories",
    "f5":           "https://support.f5.com/rss/security-advisories.xml",
    "checkpoint":   "https://research.checkpoint.com/feed/",
    "juniper":      "https://kb.juniper.net/JSA/rss",
    "citrix":       "https://www.citrix.com/blogs/security/rss.xml",
    "aruba":        "https://www.arubanetworks.com/security-advisories/feed",
    "netgear":      "https://kb.netgear.com/app/answers/detail/a_id/62001",
    "zyxel":        "https://www.zyxel.com/global/en/support/security-advisories.shtml",

    # ══ ENDPOINT SECURITY ════════════════════════════════════════════════════
    "crowdstrike":            "https://www.crowdstrike.com/security-advisories/feed/",
    "crowdstrike_blog":       "https://www.crowdstrike.com/blog/feed/",
    "sentinelone":            "https://www.sentinelone.com/labs/feed/",
    "sophos":                 "https://www.sophos.com/en-us/rss/security-advisories",
    "trendmicro":             "https://success.trendmicro.com/rss",
    "trellix":                "https://www.trellix.com/en-us/rss/security-advisories.xml",
    "malwarebytes":           "https://www.malwarebytes.com/blog/feed/",
    "eset":                   "https://www.welivesecurity.com/feed/",

    # ══ CLOUD & BROWSER ══════════════════════════════════════════════════════
    "aws":          "https://aws.amazon.com/security/security-bulletins/feed/",
    "gcp":          "https://cloud.google.com/feeds/gke-security-bulletins.xml",
    "chrome":       "https://chromereleases.googleblog.com/feeds/posts/default",
    "project_zero": "https://googleprojectzero.blogspot.com/feeds/posts/default",
    "cloudflare":   "https://blog.cloudflare.com/tag/security/rss/",
    "okta":         "https://sec.okta.com/feed/",

    # ══ MIDDLEWARE / DB ═══════════════════════════════════════════════════════
    "mozilla":      "https://blog.mozilla.org/security/feed/",
    "openssl":      "https://openssl-library.org/news/feed.xml",
    "apache":       "https://blogs.apache.org/foundation/feed/entries/rss",
    "oracle":       "https://www.oracle.com/security-alerts/rss/",
    "vmware":       "https://www.vmware.com/security/advisories.xml",
    "splunk":       "https://advisory.splunk.com/feed.xml",
    "veeam":        "https://www.veeam.com/rss/security-advisories.xml",
    "nginx":        "https://nginx.org/en/security_advisories.xml",

    # ══ YOUR STACK ═══════════════════════════════════════════════════════════
    "cortex_xdr":   "https://security.paloaltonetworks.com/rss.xml",
    "netskope":     "https://www.netskope.com/blog/feed",
    "proofpoint":   "https://www.proofpoint.com/us/rss.xml",
    "solarwinds":   "https://www.solarwinds.com/shared-content/rss-feed/solarwinds-cve-rss-feed.xml",
    "forescout":    "https://www.forescout.com/resources/feed/?type=advisory",

    # ══ THREAT INTEL ══════════════════════════════════════════════════════════
    "mandiant":     "https://www.mandiant.com/resources/blog/rss.xml",
    "talos":        "https://feeds.feedburner.com/feedburner/Talos",
    "unit42":       "https://unit42.paloaltonetworks.com/feed/",
    "msft_ti":      "https://www.microsoft.com/en-us/security/blog/feed/",
    "secureworks":  "https://www.secureworks.com/blog/rss",
    "recorded_fut": "https://www.recordedfuture.com/category/research/feed/",

    # ══ NEWS & COMMUNITY ══════════════════════════════════════════════════════
    "krebs":        "https://krebsonsecurity.com/feed/",
    "bleeping":     "https://www.bleepingcomputer.com/feed/",
    "hackernews":   "https://feeds.feedburner.com/TheHackersNews",
    "securityweek": "https://www.securityweek.com/feed/",
    "darkreading":  "https://www.darkreading.com/rss.xml",
    "helpnetsec":   "https://www.helpnetsecurity.com/feed/",
    "ars_security": "https://arstechnica.com/security/feed/",
    "wired_sec":    "https://www.wired.com/feed/category/security/latest/rss",
    "schneier":     "https://www.schneier.com/feed/atom/",
    "reddit_netsec":"https://www.reddit.com/r/netsec/.rss",
    "threatpost":   "https://threatpost.com/feed/",
}

SOURCE_COUNT = len(TRUSTED_FEEDS)

# OEM/Vendor Tier 1 — shown first in feed (direct vendor PSIRTs)
OEM_TIER1 = {
    "msrc","cisco","fortinet","paloalto","paloalto_psirt","juniper","f5","sonicwall",
    "ivanti","citrix","checkpoint","vmware","crowdstrike","sophos","apple","ubuntu",
    "redhat","android","oracle","splunk","veeam","cisa_kev","cisa_alerts","cisa_ics",
    "ncsc_uk","cert_eu","cert_in","zdi_published","mozilla","openssl","cortex_xdr",
    "netskope","forescout","aws","gcp","msrc_blog","trellix",
}

# ─── STARTUP LOG ──────────────────────────────────────────────────────────────
log.info(f"🛡️  Security Advisory Proxy v2 — port {PORT}")
log.info(f"   Sources   : {SOURCE_COUNT} configured")
log.info(f"   Email     : {'✅ SendGrid' if SENDGRID_API_KEY else '⚠️  No SendGrid'}")
log.info(f"   Auth      : {'✅ Access code set' if ACCESS_CODE else '⚠️  No access code'}")
log.info(f"   Teams     : {'✅ Webhook set' if TEAMS_WEBHOOK else '⚠️  No webhook'}")
log.info(f"   Supabase  : {'✅ Persistent storage' if SUPABASE_URL else '⚠️  Memory only'}")

# ─── HELPERS ──────────────────────────────────────────────────────────────────

# News/blog sources — these are articles, not structured advisories
NEWS_SOURCES = {
    "krebs","bleeping","hackernews","secweek","darkread","helpnet",
    "ars_security","reddit_netsec","threatpost","schneier","cybersecnews",
    "gbhackers","cyberinsider","qualys_blog","sans_isc","mandiant",
    "talos","unit42","msft_ti","secureworks","recorded_future",
}

SEVERITY_KEYWORDS = {
    "Critical":["critical","cvss 9","cvss 10","remote code execution","rce",
                "zero-day","actively exploited","unauthenticated","pre-auth",
                "authentication bypass","arbitrary code","arbitrary command"],
    "High":    ["high","cvss 7","cvss 8","privilege escalation","zero day",
                "sql injection","xxe","ssrf","path traversal","deserialization"],
    "Medium":  ["medium","moderate","cvss 5","cvss 6","denial of service",
                "dos","information disclosure","xss","csrf","open redirect"],
    "Low":     ["low","cvss 1","cvss 2","cvss 3","cvss 4","minor","low severity"],
}

def parse_severity(text:str) -> str:
    # First try CVSS score directly — most reliable
    score = extract_cvss_v3(text)
    if score is not None:
        if score >= 9.0: return "Critical"
        if score >= 7.0: return "High"
        if score >= 4.0: return "Medium"
        return "Low"
    # Fall back to keyword matching
    t = text.lower()
    for sev, kws in SEVERITY_KEYWORDS.items():
        if any(k in t for k in kws): return sev
    return "Unknown"

def extract_cvss_v3(text:str):
    # CVSSv3.x explicit
    m = re.search(r"CVSS\s*v?3[.\d]*\s*[:\-]?\s*([0-9](?:\.[0-9]+)?)", text, re.IGNORECASE)
    if m:
        try: return round(float(m.group(1)),1)
        except: pass
    # Base Score pattern (common in NVD/MSRC feeds)
    m = re.search(r"Base\s+Score[:\s]+([0-9](?:\.[0-9]+)?)", text, re.IGNORECASE)
    if m:
        try: return round(float(m.group(1)),1)
        except: pass
    # Generic CVSS score
    m = re.search(r"CVSS\s*[:\s=]+([0-9](?:\.[0-9]+)?)", text, re.IGNORECASE)
    if m:
        try:
            v = round(float(m.group(1)),1)
            if 0.0 <= v <= 10.0: return v
        except: pass
    return None

def parse_cvss(text:str): return extract_cvss_v3(text)

def is_zero_day(text:str) -> bool:
    return bool(re.search(
        r"zero.?day|0.?day|actively exploit|in the wild|exploited in|"
        r"wild exploit|known exploit|weaponized|exploited in attacks",
        text, re.IGNORECASE))

def extract_cve(text:str):
    m = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return m.group(0).upper() if m else None

def extract_all_cves(text:str) -> list:
    return list(dict.fromkeys(
        c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    ))

def clean_html(text:str) -> str:
    """Remove HTML tags and clean whitespace."""
    text = re.sub(r"<br\s*/?>", " | ", text or "", flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;",  "<", text)
    text = re.sub(r"&gt;",  ">", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&#\d+;", " ", text)
    return re.sub(r"\s+", " ", text).strip()

def extract_title_from_url(url:str) -> str:
    """Turn a URL path into a readable title as last resort."""
    try:
        path = re.sub(r"https?://[^/]+/", "", url)
        path = re.sub(r"\.\w{2,4}$", "", path)
        path = path.split("?")[0].split("#")[0]
        slug = path.split("/")[-1] or path.split("/")[-2]
        return slug.replace("-", " ").replace("_", " ").title()[:150]
    except:
        return url[:150]

def extract_products(entry) -> list:
    products = []
    # From RSS tags/categories
    for t in (getattr(entry,"tags",[]) or []):
        v = (t.get("term") or t.get("label") or "").strip()
        if v and 2 < len(v) < 60 and v.lower() not in ("security","advisory","update","patch") and v not in products:
            products.append(v)
    cat = (getattr(entry,"category","") or "").strip()
    if cat and cat not in products and 2 < len(cat) < 60:
        products.append(cat)
    return products[:8]

def extract_products_from_text(text:str) -> list:
    """Extract software/product names from advisory text using common patterns."""
    products = []
    # "affects X versions Y through Z"
    for m in re.finditer(
        r"(?:affects?|affected|impacts?|impacted|vulnerable|in)\s+"
        r"([A-Z][A-Za-z0-9\s\/\-]{2,40}?)"
        r"(?:\s+version|\s+v\d|[\s,\.;])",
        text, re.IGNORECASE):
        p = m.group(1).strip()
        if p and len(p) > 3 and p not in products:
            products.append(p[:50])
    # "Product X Y.Z through Y.Z"
    for m in re.finditer(
        r"([A-Z][A-Za-z0-9\s]{2,30}?)\s+(?:version|v)[\s]*([\d\.]+)",
        text, re.IGNORECASE):
        p = m.group(1).strip()
        if p and p not in products:
            products.append(p[:50])
    return products[:6]

def extract_patch_info(text:str) -> str:
    """Extract solution/patch/remediation sentence from advisory text."""
    patterns = [
        r"(?:solution|patch|fix|remediation|mitigation|workaround|required action|recommended action|apply|update to)[:\s]+([^\|]{20,400})",
        r"(?:users? (?:should|must|are advised to|are recommended to))\s+([^\|]{20,300})",
        r"(?:upgrade|update)\s+to\s+([^\|]{10,200})",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
        if m:
            result = re.sub(r'\s+', ' ', m.group(1)).strip()
            if len(result) > 15:
                return result[:300]
    return ""

def extract_affected_versions(text:str) -> list:
    """Extract version ranges from advisory text."""
    versions = []
    for m in re.finditer(
        r"(?:versions?|v)[\s]*([\d\.]+(?:\s*(?:through|to|and earlier|and below|before|prior to)\s*[\d\.]+)?)",
        text, re.IGNORECASE):
        v = m.group(0).strip()
        if v not in versions: versions.append(v[:40])
    return versions[:4]

def extract_bug_id(entry, source:str) -> str:
    """Extract advisory/bug number from entry ID, title, or link."""
    patterns = [
        r"(CVE-\d{4}-\d{4,7})",
        r"(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})",
        r"(FG-IR-\d{2}-\d+)",
        r"(cisco-sa-[a-zA-Z0-9\-]+)",
        r"(MSRC-[A-Z0-9\-]+)",
        r"(ADV\d{6})",
        r"(SA\d{4,8})",
        r"(VMSA-\d{4}-\d{4})",
        r"(JSA\d+)",
        r"(HPSB[A-Z0-9]+)",
        r"(VU#\d+)",
        r"(KB\d{6,8})",
    ]
    combined = f"{getattr(entry,'id','')} {getattr(entry,'title','')} {getattr(entry,'link','')}"
    for pat in patterns:
        m = re.search(pat, combined, re.IGNORECASE)
        if m: return m.group(1).upper()
    return ""

def extract_author(entry) -> str:
    a = (getattr(entry,"author","") or
         getattr(entry,"author_detail",{}).get("name","") or
         getattr(entry,"dc_creator","") or "")
    return a.strip()[:80]

def data_quality(advisory:dict) -> str:
    """Rate advisory data completeness: rich | partial | thin"""
    score = 0
    if advisory.get("cve") or advisory.get("cves"): score += 3
    if advisory.get("cvss"):                         score += 2
    if advisory.get("description","") and len(advisory.get("description","")) > 80: score += 2
    if advisory.get("products"):                     score += 1
    if advisory.get("severity","Unknown") != "Unknown": score += 1
    if advisory.get("patch_info"):                   score += 1
    if score >= 7: return "rich"
    if score >= 3: return "partial"
    return "thin"

def dedupe(advisories:list) -> list:
    """
    Deduplicate by CVE ID (preferred) or advisory ID.
    When the same CVE appears from multiple sources, the OEM/Tier-1 entry
    wins over aggregators/news — regardless of arrival order.
    """
    # First pass: bucket by key, collecting all entries per CVE
    buckets: dict = {}
    for a in advisories:
        key = (a.get("cve") or a.get("id","")[:60]).lower()
        if not key:
            continue
        if key not in buckets:
            buckets[key] = []
        buckets[key].append(a)

    result = []
    for key, entries in buckets.items():
        if len(entries) == 1:
            result.append(entries[0])
        else:
            # Prefer OEM direct source over aggregators/news
            oem_entries = [e for e in entries if e.get("isOEM")]
            chosen = oem_entries[0] if oem_entries else entries[0]
            # Enrich chosen entry with source count info for the badge
            chosen["source_count"] = len(entries)
            chosen["sources_list"] = list(dict.fromkeys(
                e.get("source") or e.get("vendor","") for e in entries
            ))[:8]
            result.append(chosen)
    return result

def fmt_ts(dt_str:str) -> str:
    """Return ISO timestamp string."""
    return dt_str or datetime.now(timezone.utc).isoformat()

def normalise_entry(entry, source:str) -> dict:
    # ── Raw field extraction ──────────────────────────────────────────────
    title_raw = clean_html(getattr(entry,"title","") or "")
    link      = getattr(entry,"link","") or getattr(entry,"id","") or ""

    raw_sum = (getattr(entry,"summary","") or getattr(entry,"description","") or
               (getattr(entry,"content",[{}])[0].get("value","") if hasattr(entry,"content") and entry.content else ""))
    summary = clean_html(raw_sum)[:800]
    full    = clean_html(
        getattr(entry,"content",[{}])[0].get("value","")
        if hasattr(entry,"content") and entry.content else ""
    )[:2000] or summary

    # ── Title cleaning: if title IS a URL, replace with readable slug ──
    is_url_title = bool(re.match(r"https?://", title_raw.strip()))
    if is_url_title and summary:
        # Use first sentence of summary as the title
        first_sent = re.split(r"[.!?]", summary)[0].strip()
        title = first_sent[:200] if len(first_sent) > 15 else extract_title_from_url(link)
    elif is_url_title:
        title = extract_title_from_url(link)
    else:
        title = title_raw[:200]

    # ── Published date ────────────────────────────────────────────────────
    published = ""
    for attr in ["published_parsed","updated_parsed"]:
        val = getattr(entry, attr, None)
        if val:
            try: published = datetime(*val[:6], tzinfo=timezone.utc).isoformat(); break
            except: pass
    if not published: published = datetime.now(timezone.utc).isoformat()

    # ── Updated/Review date ───────────────────────────────────────────────
    updated = ""
    val = getattr(entry, "updated_parsed", None)
    if val:
        try: updated = datetime(*val[:6], tzinfo=timezone.utc).isoformat()
        except: pass

    # ── Enriched extraction ───────────────────────────────────────────────
    combined  = f"{title} {summary} {full}"
    all_cves  = extract_all_cves(combined)

    # Products: RSS tags first, then text mining
    products = extract_products(entry)
    if not products:
        products = extract_products_from_text(combined)
    if not products:
        m = re.search(r"(?:product|affects?|affected)[:\s]+([^\n.]{3,80})", summary, re.IGNORECASE)
        if m: products = [m.group(1).strip()[:60]]

    # Patch/solution info extraction
    patch_info = extract_patch_info(combined)

    # Affected versions extraction
    affected_versions = extract_affected_versions(combined)

    # Bug/advisory ID extraction
    bug_id = extract_bug_id(entry, source)

    is_oem     = source in OEM_TIER1
    is_news    = source in NEWS_SOURCES
    cvss_score = extract_cvss_v3(combined)
    severity   = parse_severity(combined)

    advisory = {
        "id":               all_cves[0] if all_cves else (link or title_raw),
        "title":            title,
        "summary":          summary,
        "description":      full,
        "link":             link,
        "url":              link,
        "published":        published,
        "updated":          updated,
        "severity":         severity,
        "cvss":             cvss_score,
        "cve":              all_cves[0] if all_cves else None,
        "cves":             all_cves[:10],
        "zeroDay":          is_zero_day(combined),
        "source":           source,
        "vendor":           source,
        "products":         products,
        "affected_versions":affected_versions,
        "patch_info":       patch_info,
        "bug_id":           bug_id,
        "author":           extract_author(entry),
        "tags":             [t.get("term","") for t in (getattr(entry,"tags",[]) or []) if t.get("term")][:6],
        "isOEM":            is_oem,
        "isNews":           is_news,
    }
    advisory["data_quality"] = data_quality(advisory)
    advisory["fetched_at"]   = datetime.now(timezone.utc).isoformat()
    return advisory

# ─── FETCH ────────────────────────────────────────────────────────────────────
def fetch_rss(key:str, url:str) -> list:
    with cache_lock:
        if key in cache: return cache[key]
    if key == "mozilla": return fetch_mozilla_json()
    try:
        resp = requests.get(url, timeout=15, headers={
            "User-Agent":"SecurityAdvisoryBot/2.0 (Enterprise Security Monitor)",
            "Accept":"application/rss+xml,application/atom+xml,application/xml,text/xml,*/*",
        }, allow_redirects=True)
        resp.raise_for_status()
        feed  = feedparser.parse(resp.content)
        items = [normalise_entry(e, key) for e in (feed.entries or [])[:50]]
        if feed.bozo and not items: log.warning(f"[{key}] Bozo: {feed.bozo_exception}")
        elif items: log.info(f"[{key}] ✅ {len(items)} items")
        with cache_lock: cache[key] = items
        return items
    except requests.exceptions.SSLError:
        try:
            resp  = requests.get(url, timeout=15, verify=False, headers={"User-Agent":"SecurityAdvisoryBot/2.0"})
            feed  = feedparser.parse(resp.content)
            items = [normalise_entry(e, key) for e in (feed.entries or [])[:50]]
            log.warning(f"[{key}] SSL bypass — {len(items)} items")
            with cache_lock: cache[key] = items
            return items
        except Exception as e2: log.error(f"[{key}] SSL fallback: {e2}"); return []
    except Exception as e: log.error(f"[{key}] Failed: {e}"); return []

def fetch_mozilla_json() -> list:
    with cache_lock:
        if "mozilla" in cache: return cache["mozilla"]
    try:
        resp = requests.get("https://www.mozilla.org/en-US/security/advisories/cve-feed.json",
                            timeout=15, headers={"User-Agent":"SecurityAdvisoryBot/2.0"})
        resp.raise_for_status()
        data = resp.json()
        items = []
        for entry in (data if isinstance(data,list) else data.get("advisories",[]))[:50]:
            title = entry.get("title") or entry.get("id") or ""
            link  = entry.get("url") or entry.get("link") or "https://www.mozilla.org/security/advisories/"
            desc  = entry.get("description") or entry.get("impact") or ""
            combined = f"{title} {desc}"
            items.append({"id":link,"title":title[:200],"summary":desc[:600],"description":desc,"link":link,
                "published":entry.get("announced") or datetime.now(timezone.utc).isoformat(),
                "severity":parse_severity(combined),"cvss":extract_cvss_v3(combined),
                "cve":extract_cve(combined),"cves":extract_all_cves(combined),
                "zeroDay":is_zero_day(combined),"source":"mozilla","vendor":"Mozilla","url":link,
                "products":[],"author":"","tags":[],"isOEM":True,
                "fetched_at":datetime.now(timezone.utc).isoformat()})
        with cache_lock: cache["mozilla"] = items
        log.info(f"[mozilla] ✅ {len(items)} items (JSON)")
        return items
    except Exception as e: log.error(f"[mozilla] JSON failed: {e}"); return []

def fetch_cisa_kev() -> list:
    with cache_lock:
        if "cisa_kev" in cache: return cache["cisa_kev"]
    try:
        resp = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                            timeout=15, headers={"User-Agent":"SecurityAdvisoryBot/2.0"})
        resp.raise_for_status()
        items = []
        for v in resp.json().get("vulnerabilities",[])[:50]:
            cve_id = v.get("cveID","")
            title  = f"{cve_id} — {v.get('vulnerabilityName','')}"
            summary= (f"{v.get('shortDescription','')} | Vendor: {v.get('vendorProject','')} | "
                      f"Product: {v.get('product','')} | Required Action: {v.get('requiredAction','')}")
            items.append({"id":cve_id,"title":title,"summary":summary,"description":summary,
                "link":f"https://nvd.nist.gov/vuln/detail/{cve_id}","url":f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published":v.get("dateAdded",datetime.now(timezone.utc).isoformat()),
                "severity":"Critical","cvss":None,"cve":cve_id,"cves":[cve_id],"zeroDay":True,
                "source":"CISA KEV","vendor":"CISA","products":[v.get("product","")],"author":"","tags":["KEV"],"isOEM":True,
                "fetched_at":datetime.now(timezone.utc).isoformat()})
        with cache_lock: cache["cisa_kev"] = items
        log.info(f"[cisa_kev] ✅ {len(items)} items")
        return items
    except Exception as e: log.error(f"[cisa_kev] Failed: {e}"); return []

def fetch_all_advisories() -> list:
    results = []; futures = {}
    with ThreadPoolExecutor(max_workers=25) as executor:
        for key, url in TRUSTED_FEEDS.items():
            if key == "cisa_kev": futures[executor.submit(fetch_cisa_kev)] = key
            else: futures[executor.submit(fetch_rss, key, url)] = key
        for future in as_completed(futures):
            try: results.extend(future.result())
            except Exception as e: log.error(f"Thread error: {e}")

    # ── Sort BEFORE dedupe so OEM entries always win the dedup race ──
    sev_order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Unknown":4}
    results.sort(key=lambda a: (
        0 if a.get("isOEM") else 1,                            # OEM first
        sev_order.get(a.get("severity","Unknown"),4),
        not a.get("zeroDay",False),
        -(datetime.fromisoformat(a["published"].replace("Z","+00:00")).timestamp() if a.get("published") else 0),
    ))

    results = dedupe(results)   # dedupe after sort — OEM entry is always first in each bucket
    return results

# ─── AUTH ─────────────────────────────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = (request.headers.get("x-access-code")
                 or (request.json or {}).get("accessCode")
                 or (request.json or {}).get("code"))
        if not ACCESS_CODE or token == ACCESS_CODE: return f(*args, **kwargs)
        return jsonify({"error":"Unauthorized"}), 401
    return decorated

# ─── ROUTES ───────────────────────────────────────────────────────────────────
START_TIME = time.time()

@app.route("/")
def root():
    return jsonify({"name":"Security Advisory Proxy","version":"v2","status":"running",
        "sources":SOURCE_COUNT,"uptime":int(time.time()-START_TIME)})

@app.route("/health")
def health():
    return jsonify({"status":"ok","version":"v2","sources":SOURCE_COUNT,"uptime":int(time.time()-START_TIME)})

@app.route("/auth/verify", methods=["POST"])
def auth_verify():
    data = request.get_json() or {}
    submitted = (data.get("code") or data.get("accessCode") or "").strip()
    valid = not ACCESS_CODE or submitted == ACCESS_CODE.strip()
    log.info(f"[AUTH] {'✅ SUCCESS' if valid else '❌ FAILED'}")
    if valid: return jsonify({"valid":True,"success":True})
    return jsonify({"valid":False,"success":False,"error":"Invalid access code"}), 401

@app.route("/sources")
@require_auth
def sources():
    return jsonify({"total":SOURCE_COUNT,"sources":list(TRUSTED_FEEDS.keys()),"oem_tier1":list(OEM_TIER1)})

@app.route("/advisories")
@require_auth
def advisories():
    try:
        force = request.args.get("force","false").lower() == "true"
        # Only serve from cache on auto-refresh (not manual/first load)
        if not force and SUPABASE_URL:
            cached = supa_load_advisory_cache()
            if len(cached) > 50:
                log.info(f"[ADVISORIES] Cache hit: {len(cached)} items")
                return jsonify({"total":len(cached),"generated":datetime.now(timezone.utc).isoformat(),
                    "advisories":cached[:2500],"source":"cache"})
        # Live fetch
        all_adv = fetch_all_advisories()
        if SUPABASE_URL and all_adv:
            threading.Thread(target=supa_save_advisory_cache, args=(all_adv,), daemon=True).start()
        return jsonify({"total":len(all_adv),"generated":datetime.now(timezone.utc).isoformat(),
            "advisories":all_adv[:2500],"source":"live"})
    except Exception as e:
        log.error(f"[ADVISORIES] {e}")
        return jsonify({"error":"Failed to fetch advisories"}), 500

@app.route("/advisories/critical")
@require_auth
def advisories_critical():
    all_adv = fetch_all_advisories()
    crit = [a for a in all_adv if a.get("severity")=="Critical" or a.get("zeroDay")]
    return jsonify({"total":len(crit),"advisories":crit})

# ─── ACKNOWLEDGE ──────────────────────────────────────────────────────────────
@app.route("/ack", methods=["GET"])
@require_auth
def get_acks():
    acks = supa_get_acks()
    return jsonify({"acks":acks,"count":len(acks),"persistent":bool(SUPABASE_URL)})

@app.route("/ack", methods=["POST"])
@require_auth
def set_ack():
    data        = request.get_json() or {}
    advisory_id = data.get("id","").strip()
    by          = data.get("by","Team Member").strip()[:50]
    note        = data.get("note","").strip()[:300]
    status      = data.get("status","In Review").strip()[:50]
    assigned_to = data.get("assigned_to","").strip()[:80]
    ai_triage   = data.get("ai_triage","").strip()[:500]
    if not advisory_id: return jsonify({"error":"Missing advisory id"}), 400
    ok = supa_set_ack(advisory_id, by, note, status, assigned_to, ai_triage)
    at = datetime.now(timezone.utc).isoformat()
    log.info(f"[ACK] {advisory_id} by {by} → {status}" + (f" → {assigned_to}" if assigned_to else ""))
    return jsonify({"success":True,"id":advisory_id,"by":by,"at":at,"note":note,
                    "status":status,"assigned_to":assigned_to,"ai_triage":ai_triage,"persisted":ok})

@app.route("/ack/<path:advisory_id>", methods=["DELETE"])
@require_auth
def clear_ack(advisory_id):
    data = request.get_json() or {}
    by   = data.get("by","").strip()
    ok   = supa_delete_ack(advisory_id, by)
    if ok: return jsonify({"success":True})
    return jsonify({"error":"Delete failed or not authorised — only the person who acknowledged can undo"}), 403

# ─── CACHE MANAGEMENT ─────────────────────────────────────────────────────────
@app.route("/feed-check")
@require_auth
def feed_check():
    """
    Check if a single RSS feed URL is reachable and returns items.
    Used by the Feed Health Monitor on the frontend.
    Query params: url=<rss_feed_url>
    Returns: {ok, item_count, last_item_date, http_code, error}
    """
    url = request.args.get("url","").strip()
    if not url:
        return jsonify({"ok":False,"error":"No URL provided","item_count":0}), 400
    if not url.startswith("http"):
        return jsonify({"ok":False,"error":"Invalid URL","item_count":0}), 400

    try:
        resp = requests.get(url, timeout=12, headers={
            "User-Agent":"SecurityAdvisoryBot/2.0 (Feed Health Monitor)",
            "Accept":"application/rss+xml,application/atom+xml,application/xml,text/xml,*/*",
        }, allow_redirects=True)
        http_code = resp.status_code
        if resp.status_code >= 400:
            return jsonify({
                "ok":False,"item_count":0,"http_code":http_code,
                "error":f"HTTP {http_code} — feed URL may have changed or moved"
            })

        feed = feedparser.parse(resp.content)
        item_count = len(feed.entries or [])

        # Get date of most recent item
        last_item_date = None
        if feed.entries:
            entry = feed.entries[0]
            for attr in ["published_parsed","updated_parsed"]:
                val = getattr(entry, attr, None)
                if val:
                    try:
                        last_item_date = datetime(*val[:6], tzinfo=timezone.utc).isoformat()
                        break
                    except: pass

        # Bozo = feed parsed but had errors (malformed XML etc)
        bozo_warning = None
        if feed.bozo and item_count == 0:
            bozo_warning = "Feed returned malformed XML — may still be partially functional"

        return jsonify({
            "ok": item_count > 0,
            "item_count": item_count,
            "last_item_date": last_item_date,
            "http_code": http_code,
            "feed_title": feed.feed.get("title","") if hasattr(feed,"feed") else "",
            "error": bozo_warning if item_count == 0 else None,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        })

    except requests.exceptions.SSLError:
        return jsonify({"ok":False,"item_count":0,"http_code":None,
            "error":"SSL certificate error — feed may have changed domain"})
    except requests.exceptions.ConnectionError:
        return jsonify({"ok":False,"item_count":0,"http_code":None,
            "error":"Connection refused — feed URL may no longer exist"})
    except requests.exceptions.Timeout:
        return jsonify({"ok":False,"item_count":0,"http_code":None,
            "error":"Timeout after 12s — feed server not responding"})
    except Exception as e:
        return jsonify({"ok":False,"item_count":0,"http_code":None,
            "error":str(e)[:120]})


@app.route("/cache/clear", methods=["POST"])
@require_auth
def clear_advisory_cache():
    if not (SUPABASE_URL and SUPABASE_KEY): return jsonify({"error":"Supabase not configured"}), 503
    try:
        r = requests.delete(f"{SUPABASE_URL}/rest/v1/advisory_cache?fetched_at=gte.2000-01-01",
                            headers=supa_headers(), timeout=10)
        log.info(f"[CACHE] Cleared: {r.status_code}")
        return jsonify({"success":True})
    except Exception as e: return jsonify({"error":str(e)}), 500

@app.route("/source-config", methods=["GET"])
@require_auth
def get_source_config():
    return jsonify({"config":supa_get_source_config()})

@app.route("/source-config", methods=["POST"])
@require_auth
def set_source_config_route():
    data = request.get_json() or {}
    ok = supa_set_source_config(data.get("id",""), data.get("enabled",True), data.get("by","Team Member"))
    return jsonify({"success":ok})

@app.route("/source-config/clear", methods=["POST"])
@require_auth
def clear_source_config():
    if not (SUPABASE_URL and SUPABASE_KEY): return jsonify({"error":"Supabase not configured"}), 503
    try:
        r = requests.delete(f"{SUPABASE_URL}/rest/v1/source_config?updated_at=gte.2000-01-01",
                            headers=supa_headers(), timeout=10)
        return jsonify({"success":True})
    except Exception as e: return jsonify({"error":str(e)}), 500

# ─── EMAIL ────────────────────────────────────────────────────────────────────
def build_email_html(advisories:list) -> str:
    critical  = [a for a in advisories if a.get("severity")=="Critical"]
    high      = [a for a in advisories if a.get("severity")=="High"]
    zero_days = [a for a in advisories if a.get("zeroDay")]
    today     = datetime.now().strftime("%A, %d %B %Y")
    recs = []
    if zero_days: recs.append(f"🚨 {len(zero_days)} zero-day exploit(s) — patch immediately")
    if critical:  recs.append(f"⚠️ {len(critical)} critical CVEs require action within 24 hours")
    if any("microsoft" in a.get("source","").lower() for a in advisories): recs.append("🪟 Microsoft patches available — schedule via WSUS/Intune")
    if any("fortinet" in a.get("title","").lower() for a in advisories): recs.append("🔒 Fortinet advisory — verify FortiOS patch status")
    if any("cisco" in a.get("title","").lower() for a in advisories): recs.append("🌐 Cisco advisory — review IOS XE/ASA exposure")
    if not recs: recs.append("✅ No critical action items today")
    def rows(items, n=10):
        out=""
        for a in items[:n]:
            sc={"Critical":"#7f1d1d","High":"#78350f"}.get(a.get("severity",""),"#1e3a5f")
            cve=f'<code style="color:#60a5fa;font-size:11px;margin-left:6px;">{a["cve"]}</code>' if a.get("cve") else ""
            out+=f'<tr><td style="padding:6px 10px;border-bottom:1px solid #2a2a2a;"><span style="background:{sc};color:#fff;font-size:10px;padding:1px 6px;border-radius:3px;">{a.get("severity","?")}</span>{cve}</td><td style="padding:6px 10px;border-bottom:1px solid #2a2a2a;color:#e5e7eb;font-size:12px;">{a.get("title","")[:90]}</td><td style="padding:6px 10px;border-bottom:1px solid #2a2a2a;color:#9ca3af;font-size:11px;">{a.get("source","")}</td></tr>'
        return out
    zd = f'<div style="background:#2d0a0a;border:1px solid #dc2626;border-radius:6px;padding:12px 16px;margin-bottom:16px;"><p style="margin:0;font-size:13px;color:#fca5a5;">🚨 <strong>{len(zero_days)} Zero-Day(s)</strong> — Immediate patching required.</p></div>' if zero_days else ""
    ct = f'<div style="background:#161616;border:1px solid #2a2a2a;border-radius:6px;margin-bottom:16px;overflow:hidden;"><div style="padding:12px 16px;border-bottom:1px solid #2a2a2a;"><h2 style="margin:0;font-size:13px;color:#fca5a5;text-transform:uppercase;">Critical Advisories</h2></div><table style="width:100%;border-collapse:collapse;"><tr style="background:#1a1a1a;"><th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7280;">Severity</th><th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7280;">Title</th><th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7280;">Source</th></tr>{rows(critical)}</table></div>' if critical else ""
    ht = f'<div style="background:#161616;border:1px solid #2a2a2a;border-radius:6px;margin-bottom:16px;overflow:hidden;"><div style="padding:12px 16px;border-bottom:1px solid #2a2a2a;"><h2 style="margin:0;font-size:13px;color:#fcd34d;text-transform:uppercase;">High Severity</h2></div><table style="width:100%;border-collapse:collapse;"><tr style="background:#1a1a1a;"><th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7280;">Severity</th><th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7280;">Title</th><th style="padding:6px 10px;text-align:left;font-size:11px;color:#6b7280;">Source</th></tr>{rows(high,8)}</table></div>' if high else ""
    recs_html="".join(f"<li>{r}</li>" for r in recs)
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="background:#0f0f0f;font-family:Arial,sans-serif;color:#e5e7eb;margin:0;padding:0;">
<div style="max-width:680px;margin:0 auto;padding:24px 16px;">
<div style="background:#161616;border:1px solid #2a2a2a;border-radius:8px;padding:20px 24px;margin-bottom:16px;">
<h1 style="margin:0;font-size:17px;font-weight:600;color:#fff;">🛡️ Security Advisory Daily Digest</h1>
<p style="margin:4px 0 0;font-size:12px;color:#9ca3af;">Concentrix Endpoint Security — {today}</p></div>
<div style="display:flex;gap:10px;margin-bottom:16px;">
<div style="flex:1;background:#161616;border:1px solid #2a2a2a;border-radius:6px;padding:12px;text-align:center;"><div style="font-size:22px;font-weight:700;color:#fff;">{len(advisories)}</div><div style="font-size:11px;color:#9ca3af;">Total</div></div>
<div style="flex:1;background:#1c0a0a;border:1px solid #7f1d1d;border-radius:6px;padding:12px;text-align:center;"><div style="font-size:22px;font-weight:700;color:#fca5a5;">{len(critical)}</div><div style="font-size:11px;color:#9ca3af;">Critical</div></div>
<div style="flex:1;background:#1c1100;border:1px solid #78350f;border-radius:6px;padding:12px;text-align:center;"><div style="font-size:22px;font-weight:700;color:#fcd34d;">{len(high)}</div><div style="font-size:11px;color:#9ca3af;">High</div></div>
<div style="flex:1;background:#1a0a0e;border:1px solid #9f1239;border-radius:6px;padding:12px;text-align:center;"><div style="font-size:22px;font-weight:700;color:#f9a8d4;">{len(zero_days)}</div><div style="font-size:11px;color:#9ca3af;">Zero-Days</div></div>
</div>{zd}
<div style="background:#0d1117;border:1px solid #2a2a2a;border-radius:6px;padding:16px;margin-bottom:16px;">
<h2 style="margin:0 0 10px;font-size:13px;color:#9ca3af;text-transform:uppercase;">Recommended Actions</h2>
<ul style="margin:0;padding-left:16px;font-size:13px;color:#e5e7eb;line-height:1.8;">{recs_html}</ul></div>
{ct}{ht}
<div style="text-align:center;padding:16px;font-size:11px;color:#4b5563;">
<p style="margin:0;">Concentrix Endpoint Security · Security Advisory Monitor v2</p>
<p style="margin:4px 0 0;">Monitoring {SOURCE_COUNT} sources · <a href="https://ssipankajsingh.github.io/security-advisory-dashboard/" style="color:#60a5fa;">View Dashboard</a></p>
</div></div></body></html>"""

@app.route("/email-digest", methods=["POST"])
@require_auth
def email_digest():
    if not SENDGRID_API_KEY: return jsonify({"error":"SendGrid not configured"}), 503
    data = request.get_json() or {}
    to   = data.get("to")
    if not to: return jsonify({"error":"Missing 'to'"}), 400
    from_email = data.get("from","secadvisory@yourdomain.com")
    try:
        all_adv   = fetch_all_advisories()
        html      = build_email_html(all_adv)
        zero_days = [a for a in all_adv if a.get("zeroDay")]
        critical  = [a for a in all_adv if a.get("severity")=="Critical"]
        subject = (f"🚨 [URGENT] {len(zero_days)} Zero-Day(s) — Security Advisory Digest {datetime.now().strftime('%d/%m/%Y')}"
                   if zero_days else f"🛡️ Security Advisory Digest — {len(critical)} Critical, {datetime.now().strftime('%d/%m/%Y')}")
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(Mail(from_email=from_email, to_emails=to, subject=subject, html_content=html))
        log.info(f"[EMAIL] Sent to {to} — {len(all_adv)} advisories")
        return jsonify({"success":True,"sent":len(all_adv),"to":to})
    except Exception as e: log.error(f"[EMAIL] {e}"); return jsonify({"error":str(e)}), 500

# ─── TEAMS ────────────────────────────────────────────────────────────────────
def send_teams_card(webhook_url:str, advisories:list):
    critical  = [a for a in advisories if a.get("severity")=="Critical"]
    zero_days = [a for a in advisories if a.get("zeroDay")]
    high      = [a for a in advisories if a.get("severity")=="High"]
    today     = datetime.now().strftime("%A, %d %B %Y")
    top       = list({a["id"]:a for a in zero_days+critical}.values())[:8]
    facts     = [{"name":("🔴 0-DAY" if a.get("zeroDay") else "🟠 CRITICAL")+" — "+(a.get("source") or a.get("vendor") or ""),
                  "value":(a.get("title") or a.get("id") or "")[:100]+(f" ({a['cve']})" if a.get("cve") else "")} for a in top]
    payload = {"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{
        "$schema":"http://adaptivecards.io/schemas/adaptive-card.json","type":"AdaptiveCard","version":"1.4",
        "body":[
            {"type":"Container","style":"attention" if zero_days else "warning","items":[{"type":"ColumnSet","columns":[
                {"type":"Column","width":"auto","items":[{"type":"TextBlock","text":"🛡️","size":"ExtraLarge"}]},
                {"type":"Column","width":"stretch","items":[
                    {"type":"TextBlock","text":"Security Advisory Alert","weight":"Bolder","size":"Large","color":"Attention" if zero_days else "Warning"},
                    {"type":"TextBlock","text":"Concentrix Endpoint Security · "+today,"size":"Small","isSubtle":True,"spacing":"None"},
                ]},
            ]}]},
            {"type":"ColumnSet","columns":[
                {"type":"Column","width":"stretch","items":[{"type":"TextBlock","text":"**"+str(len(advisories))+"**\nTotal","wrap":True,"horizontalAlignment":"Center"}]},
                {"type":"Column","width":"stretch","items":[{"type":"TextBlock","text":"**"+str(len(critical))+"**\nCritical","wrap":True,"horizontalAlignment":"Center","color":"Attention"}]},
                {"type":"Column","width":"stretch","items":[{"type":"TextBlock","text":"**"+str(len(high))+"**\nHigh","wrap":True,"horizontalAlignment":"Center","color":"Warning"}]},
                {"type":"Column","width":"stretch","items":[{"type":"TextBlock","text":"**"+str(len(zero_days))+"**\nZero-Days","wrap":True,"horizontalAlignment":"Center","color":"Attention" if zero_days else "Default"}]},
            ]},
            *([ {"type":"Container","style":"emphasis","items":[
                {"type":"TextBlock","text":"⚠️ Immediate Action Required" if zero_days else "Top Critical Advisories","weight":"Bolder","size":"Medium"},
                {"type":"FactSet","facts":facts},
            ]}] if facts else []),
            {"type":"ActionSet","actions":[{"type":"Action.OpenUrl","title":"🔍 Open Dashboard",
                "url":"https://ssipankajsingh.github.io/security-advisory-dashboard/","style":"positive"}]},
        ],
    }}]}
    resp = requests.post(webhook_url, json=payload, timeout=10)
    return resp.status_code

@app.route("/teams-notify", methods=["POST"])
@require_auth
def teams_notify():
    data = request.get_json() or {}
    webhook_url = data.get("webhookUrl") or TEAMS_WEBHOOK
    if not webhook_url: return jsonify({"error":"No webhook URL"}), 400
    try:
        all_adv = fetch_all_advisories()
        status  = send_teams_card(webhook_url, all_adv)
        return jsonify({"success":True,"sent":len(all_adv),
            "critical":len([a for a in all_adv if a.get("severity")=="Critical"]),
            "zeroDays":len([a for a in all_adv if a.get("zeroDay")])})
    except Exception as e: log.error(f"[TEAMS] {e}"); return jsonify({"error":str(e)}), 500

# ─── SCHEDULED JOBS ───────────────────────────────────────────────────────────
def scheduled_email():
    if not (SENDGRID_API_KEY and DIGEST_EMAIL): return
    log.info("[CRON] Running email digest...")
    try:
        with app.test_client() as client:
            client.post("/email-digest", json={"to":DIGEST_EMAIL}, headers={"x-access-code":ACCESS_CODE})
        log.info("[CRON] Email sent")
    except Exception as e: log.error(f"[CRON] Email: {e}")

def scheduled_teams():
    if not TEAMS_WEBHOOK: return
    log.info("[CRON] Running Teams notification...")
    try: send_teams_card(TEAMS_WEBHOOK, fetch_all_advisories()); log.info("[CRON] Teams sent")
    except Exception as e: log.error(f"[CRON] Teams: {e}")

def is_patch_tuesday() -> bool:
    """True if today is the 2nd Tuesday of the month."""
    now = datetime.now()
    if now.weekday() != 1: return False  # Not Tuesday
    return 8 <= now.day <= 14

def scheduled_patch_tuesday():
    """Special Microsoft-only digest on Patch Tuesday."""
    if not is_patch_tuesday(): return
    if not (SENDGRID_API_KEY and DIGEST_EMAIL): return
    log.info("[CRON] Patch Tuesday digest running...")
    try:
        all_adv  = fetch_all_advisories()
        ms_adv   = [a for a in all_adv if "microsoft" in a.get("source","").lower() or "msrc" in a.get("source","").lower()]
        if not ms_adv: return
        html = build_email_html(ms_adv)
        subject = f"🪟 Patch Tuesday — {len(ms_adv)} Microsoft Advisories — {datetime.now().strftime('%d/%m/%Y')}"
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(Mail(from_email="secadvisory@yourdomain.com", to_emails=DIGEST_EMAIL, subject=subject, html_content=html))
        log.info(f"[CRON] Patch Tuesday digest sent — {len(ms_adv)} MS advisories")
    except Exception as e: log.error(f"[CRON] Patch Tuesday: {e}")

scheduler = BackgroundScheduler(timezone="UTC")
scheduler.add_job(scheduled_email,         "cron", hour=2,  minute=30)   # 8:00 AM IST
scheduler.add_job(scheduled_teams,         "cron", hour=2,  minute=35)   # 8:05 AM IST
scheduler.add_job(scheduled_patch_tuesday, "cron", hour=3,  minute=0)    # 8:30 AM IST on Patch Tuesdays
scheduler.add_job(supa_purge_old_acks,     "cron", hour=0,  minute=0)    # Midnight UTC — purge old acks
scheduler.start()

if __name__ == "__main__":
    log.info(f"✅ Proxy listening on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
