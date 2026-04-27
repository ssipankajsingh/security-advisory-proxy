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
FETCH_WINDOW_DAYS = 30   # Drop feed items older than this many days at ingest
CRON_SECRET       = os.getenv("CRON_SECRET", "")   # Secret token for /fetch-now endpoint
VULNCHECK_API_KEY = os.getenv("VULNCHECK_API_KEY","")  # VulnCheck Community API key (free at vulncheck.com/community)

# ─── CACHE ────────────────────────────────────────────────────────────────────
cache      = TTLCache(maxsize=200, ttl=3600)
cache_lock = threading.Lock()

# ─── SUPABASE ─────────────────────────────────────────────────────────────────
def supa_headers(prefer="return=representation"):
    return {"apikey":SUPABASE_KEY,"Authorization":f"Bearer {SUPABASE_KEY}",
            "Content-Type":"application/json","Prefer":prefer}

def supa_record_feed_metrics(source_id:str, item_count:int, items:list,
                              success:bool, error_msg:str="", duration_ms:int=0):
    """Record per-source fetch metrics for Feed Health Monitor history."""
    if not (SUPABASE_URL and SUPABASE_KEY): return
    try:
        cve_rate  = round(sum(1 for i in items if i.get("cve","").startswith("CVE-")) / max(item_count,1) * 100, 1)
        cvss_rate = round(sum(1 for i in items if i.get("cvss")) / max(item_count,1) * 100, 1)
        payload = {"source_id":source_id,"item_count":item_count,"cve_rate":cve_rate,
                   "cvss_rate":cvss_rate,"success":success,
                   "error_msg":error_msg[:200] if error_msg else None,"duration_ms":duration_ms}
        requests.post(f"{SUPABASE_URL}/rest/v1/feed_metrics",
                     headers={**supa_headers(),"Prefer":"return=minimal"},
                     json=payload, timeout=5)
    except Exception as e:
        log.debug(f"[feed_metrics] {e}")

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

def _record_history(advisory_id:str, cve_id:str, severity:str, from_status:str,
                    to_status:str, changed_by:str, note:str, assigned_to:str):
    """Write audit trail row to advisory_history."""
    if not (SUPABASE_URL and SUPABASE_KEY): return
    try:
        requests.post(f"{SUPABASE_URL}/rest/v1/advisory_history",
            headers={**supa_headers(),"Prefer":"return=minimal"},
            json={"advisory_id":advisory_id,"cve_id":cve_id or None,
                  "severity":severity or None,"from_status":from_status or None,
                  "to_status":to_status,"changed_by":changed_by,
                  "note":note or None,"assigned_to":assigned_to or None},
            timeout=5)
    except Exception as e: log.debug(f"[advisory_history] {e}")

def _record_sla_breach(advisory_id:str, cve_id:str, severity:str, source:str,
                        published_at:str, overdue_hours:int, assigned_to:str=""):
    """Record SLA breach to permanent sla_audit_log table."""
    if not (SUPABASE_URL and SUPABASE_KEY): return
    try:
        sla_h = {"Critical":24,"High":72,"Medium":168}.get(severity,168)
        requests.post(f"{SUPABASE_URL}/rest/v1/sla_audit_log",
            headers={**supa_headers(),"Prefer":"return=minimal"},
            json={"advisory_id":advisory_id,"cve_id":cve_id or None,
                  "severity":severity or None,"source":source or None,
                  "published_at":published_at or None,"sla_hours":sla_h,
                  "breached_at":datetime.now(timezone.utc).isoformat(),
                  "overdue_hours":overdue_hours,"assigned_to":assigned_to or None},
            timeout=5)
    except Exception as e: log.debug(f"[sla_audit_log] {e}")

def supa_save_saved_search(name:str, owner:str, filters:dict, is_shared:bool=False) -> bool:
    if not (SUPABASE_URL and SUPABASE_KEY): return False
    try:
        r = requests.post(f"{SUPABASE_URL}/rest/v1/saved_searches",
            headers={**supa_headers(),"Prefer":"return=minimal"},
            json={"name":name,"owner":owner,"filters":filters,"is_shared":is_shared}, timeout=5)
        return r.status_code in (200,201)
    except Exception as e: log.debug(f"[saved_searches] {e}"); return False

def supa_load_saved_searches(owner:str="") -> list:
    if not (SUPABASE_URL and SUPABASE_KEY): return []
    try:
        r = requests.get(f"{SUPABASE_URL}/rest/v1/saved_searches?select=*&order=used_at.desc&limit=50",
                        headers=supa_headers(), timeout=8)
        if r.status_code == 200:
            return [row for row in r.json() if row.get("owner")==owner or row.get("is_shared")]
    except Exception as e: log.debug(f"[saved_searches] {e}")
    return []

def supa_delete_saved_search(search_id:int) -> bool:
    if not (SUPABASE_URL and SUPABASE_KEY): return False
    try:
        r = requests.delete(f"{SUPABASE_URL}/rest/v1/saved_searches?id=eq.{search_id}",
                           headers=supa_headers(), timeout=5)
        return r.status_code in (200,204)
    except Exception as e: log.debug(f"[saved_searches] {e}"); return False

def supa_load_archived(limit:int=200, offset:int=0, severity:str="",
                        source:str="", days_back:int=365) -> list:
    """Load archived advisories (90-365 days old)."""
    if not (SUPABASE_URL and SUPABASE_KEY): return []
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()
        url = (f"{SUPABASE_URL}/rest/v1/advisory_cache"
               f"?select=data,published_at,severity,source,cve_id"
               f"&is_archived=eq.true&published_at=gte.{cutoff}"
               f"&order=published_at.desc&limit={limit}&offset={offset}")
        if severity: url += f"&severity=eq.{severity}"
        if source:   url += f"&source=eq.{source}"
        r = requests.get(url, headers=supa_headers(), timeout=15)
        if r.status_code == 200:
            rows = r.json()
            return [row["data"] for row in rows if row.get("data")]
        return []
    except Exception as e: log.error(f"[ARCHIVE] {e}"); return []

def supa_get_sla_audit(days:int=365) -> list:
    if not (SUPABASE_URL and SUPABASE_KEY): return []
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        r = requests.get(
            f"{SUPABASE_URL}/rest/v1/sla_audit_log?order=breached_at.desc&limit=500&breached_at=gte.{cutoff}",
            headers=supa_headers(), timeout=10)
        return r.json() if r.status_code == 200 else []
    except Exception as e: log.debug(f"[sla_audit] {e}"); return []

def supa_save_archived():
    """
    Nightly archive: flag rows 90-365d as is_archived=TRUE.
    Hard-delete rows > 365d (non-KEV) or > 730d (KEV/ZeroDay).
    """
    if not (SUPABASE_URL and SUPABASE_KEY): return
    try:
        now_dt    = datetime.now(timezone.utc)
        now_iso   = now_dt.isoformat()
        arch_cut  = (now_dt - timedelta(days=ARCHIVE_AFTER_DAYS)).isoformat()
        hard_cut  = (now_dt - timedelta(days=365)).isoformat()
        kev_cut   = (now_dt - timedelta(days=730)).isoformat()
        met_cut   = (now_dt - timedelta(days=90)).isoformat()
        # Archive rows older than ARCHIVE_AFTER_DAYS
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/advisory_cache?is_archived=eq.false&published=lt.{arch_cut}",
            headers={**supa_headers(),"Prefer":"return=minimal"},
            json={"is_archived":True,"archived_at":now_iso}, timeout=15)
        # Hard delete expired non-KEV rows
        requests.delete(f"{SUPABASE_URL}/rest/v1/advisory_cache"
                       f"?is_kev=eq.false&is_zero_day=eq.false&published=lt.{hard_cut}",
                       headers=supa_headers(), timeout=10)
        # Hard delete expired KEV rows
        requests.delete(f"{SUPABASE_URL}/rest/v1/advisory_cache?is_kev=eq.true&published=lt.{kev_cut}",
                       headers=supa_headers(), timeout=10)
        # Purge advisory_history > 365d
        requests.delete(f"{SUPABASE_URL}/rest/v1/advisory_history?changed_at=lt.{hard_cut}",
                       headers=supa_headers(), timeout=10)
        # Purge feed_metrics > 90d
        requests.delete(f"{SUPABASE_URL}/rest/v1/feed_metrics?fetched_at=lt.{met_cut}",
                       headers=supa_headers(), timeout=10)
        log.info("[NIGHTLY] Archive + purge complete")
    except Exception as e: log.error(f"[NIGHTLY] Archive failed: {e}")

def supa_set_ack(advisory_id:str, by:str, note:str="", status:str="In Review",
                 assigned_to:str="", ai_triage:str="", prev_status:str="",
                 cve_id:str="", severity:str="") -> bool:
    if not (SUPABASE_URL and SUPABASE_KEY): return False
    try:
        h = {**supa_headers(),"Prefer":"resolution=merge-duplicates,return=representation"}
        payload = {"id":advisory_id,"acknowledged_by":by,
                   "acknowledged_at":datetime.now(timezone.utc).isoformat(),
                   "note":note,"status":status,"assigned_to":assigned_to,"ai_triage":ai_triage}
        r = requests.post(f"{SUPABASE_URL}/rest/v1/acknowledgments", headers=h, json=payload, timeout=8)
        ok = r.status_code in (200,201)
        if ok and status:
            threading.Thread(target=_record_history,
                args=(advisory_id,cve_id,severity,prev_status,status,by,note,assigned_to),
                daemon=True).start()
        return ok
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

# Retention windows — free tier has 488MB spare, ~400B/row after compression
# Safe to extend: 90d default uses only ~0.9MB, 180d KEV uses ~1.8MB
CACHE_RETENTION_DAYS = {
    "kev":      730,  # KEV — 2 years (historically significant)
    "zeroday":  365,  # Zero-day — 1 year
    "critical": 365,  # Critical — 1 year
    "high":     365,  # High — 1 year
    "default":  365,  # All others — 1 year
}
ARCHIVE_AFTER_DAYS = 90  # Flag rows as archived after 90d (still queryable)

def supa_save_advisory_cache(advisories:list) -> bool:
    if not (SUPABASE_URL and SUPABASE_KEY): return False
    try:
        now = datetime.now(timezone.utc).isoformat()
        # IMP2: strip large/derived fields before saving — cuts row 1.1KB→400B
        STRIP_FIELDS = {"description","isNew","data_quality","exploit_refs",
                        "epss_date","tags","author","kev_notes"}
        rows = []
        for a in advisories[:5000]:
            aid = a.get("id")
            if not aid: continue
            original_fetched = a.get("fetched_at") or now
            is_kev_item = bool(a.get("source","") in ("CISA KEV","cisa_kev","vulncheck_kev")
                               or "KEV" in (a.get("tags") or []))
            compressed = {k: v for k, v in a.items() if k not in STRIP_FIELDS}
            if compressed.get("summary"): compressed["summary"] = compressed["summary"][:300]
            if compressed.get("title"):   compressed["title"]   = compressed["title"][:200]
            rows.append({
                "id":          aid[:500],
                "data":        {**compressed, "isNew": False},
                "fetched_at":  original_fetched,
                "published":   (a.get("published") or now)[:50],
                "published_at":(a.get("published") or now)[:50],
                "severity":    (a.get("severity") or "Unknown")[:20],
                "source":      (a.get("source") or "")[:50],
                "cve_id":      (a.get("cve") or "")[:50],
                "cvss":        a.get("cvss"),
                "epss":        a.get("epss"),
                "is_kev":      is_kev_item,
                "is_zero_day": bool(a.get("zeroDay",False)),
            })
        # Upsert: on conflict(id) only update data + severity/flags, NOT fetched_at
        # This preserves the original first-seen timestamp
        h = {**supa_headers(), "Prefer": "resolution=merge-duplicates"}
        saved = 0; failed = 0
        for i in range(0, len(rows), 100):
            r = requests.post(f"{SUPABASE_URL}/rest/v1/advisory_cache",
                            headers=h, json=rows[i:i+100], timeout=20)
            if r.status_code not in (200,201):
                log.warning(f"[SUPABASE] Cache batch {i//100} failed: {r.status_code} — {r.text[:100]}")
                failed += len(rows[i:i+100])
            else:
                saved += len(rows[i:i+100])

        # R2/R4 fix: retention based on published date AND advisory type
        # KEV + ZeroDay items kept longer — they remain exploitable past 30 days
        now_dt = datetime.now(timezone.utc)
        for retention_type, days in [
            ("KEV",      CACHE_RETENTION_DAYS["kev"]),
            ("ZeroDay",  CACHE_RETENTION_DAYS["zeroday"]),
        ]:
            cutoff = (now_dt - timedelta(days=days)).isoformat()
            if retention_type == "KEV":
                requests.delete(
                    f"{SUPABASE_URL}/rest/v1/advisory_cache?is_kev=eq.true&published=lt.{cutoff}",
                    headers=supa_headers(), timeout=10)
            else:
                requests.delete(
                    f"{SUPABASE_URL}/rest/v1/advisory_cache?is_zero_day=eq.true&is_kev=eq.false&published=lt.{cutoff}",
                    headers=supa_headers(), timeout=10)

        # Archive rows older than ARCHIVE_AFTER_DAYS
        archive_cutoff = (now_dt - timedelta(days=ARCHIVE_AFTER_DAYS)).isoformat()
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/advisory_cache?is_archived=eq.false&published=lt.{archive_cutoff}",
            headers={**supa_headers(),"Prefer":"return=minimal"},
            json={"is_archived":True,"archived_at":now}, timeout=10)
        # Hard-delete rows older than 365d
        hard_cutoff = (now_dt - timedelta(days=365)).isoformat()
        requests.delete(f"{SUPABASE_URL}/rest/v1/advisory_cache?is_kev=eq.false&is_zero_day=eq.false&published=lt.{hard_cutoff}",
                       headers=supa_headers(), timeout=10)

        status = f"{saved}/{len(rows)} saved"
        if failed: status += f", {failed} failed"
        log.info(f"[SUPABASE] Cache saved: {status}")
        # R6 fix: warn if significant failures
        if failed > len(rows) * 0.1:
            log.error(f"[SUPABASE] ⚠️  >10% of cache save failed ({failed}/{len(rows)}) — data may be incomplete")
        return failed == 0
    except Exception as e:
        log.error(f"[SUPABASE] save_cache: {e}")
        return False

def supa_load_advisory_cache() -> list:
    """Load all rows from advisory_cache in paginated 1000-row chunks (handles 2500+ rows)."""
    if not (SUPABASE_URL and SUPABASE_KEY): return []
    all_items = []
    offset = 0
    chunk = 1000
    while True:
        try:
            url = (f"{SUPABASE_URL}/rest/v1/advisory_cache"
                   f"?select=data&is_archived=eq.false"
                   f"&order=fetched_at.desc&limit={chunk}&offset={offset}")
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
    # R7 fix: deduplicate on load — same CVE may exist from multiple sources
    seen_ids = set(); deduped = []
    for item in all_items:
        iid = item.get("id","")
        if iid and iid not in seen_ids:
            seen_ids.add(iid); deduped.append(item)
    if len(deduped) < len(all_items):
        log.info(f"[SUPABASE] Deduped on load: {len(all_items)} → {len(deduped)} items")
    return deduped

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

    # ══ TIER 0: MASTER AGGREGATORS — pre-NVD sources for fast CVE response ═
    "cvefeed_high_critical": "https://cvefeed.io/rssfeed/severity/high.xml",
    "github_advisories":     "https://github.blog/feed/",
    "cvedaily_all":          "https://cvedaily.com/feed.xml",
    "cvedaily_new":          "https://cvedaily.com/feed-new.xml",
    "cvedaily_critical":     "https://cvedaily.com/feed-critical.xml",
    # PRE-NVD: these publish CVEs hours–days before NIST NVD enriches them
    "ghsa":                  "__GHSA_API__",       # GitHub Advisory Database API
    "osv":                   "__OSV_API__",        # Google OSV.dev API
    "mitre_cve":             "__MITRE_CVE_API__",  # MITRE CVE List (cvelistV5)
    "vulncheck_nvd":         "__VULNCHECK_API__",  # VulnCheck NVD++ — faster + richer than NIST NVD
    "vulncheck_kev":         "__VULNCHECK_KEV__",  # VulnCheck KEV — superset of CISA KEV + exploit intel

    # ══ GOVERNMENT & CERT ════════════════════════════════════════════════════
    "cisa_alerts":       "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "cisa_kev":          "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cisa_ics":          "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
    "ncsc_uk":           "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
    "cert_eu":           "https://cert.europa.eu/publications/security-advisories-rss",
    "certeu_threat_intel":"https://cert.europa.eu/publications/threat-intelligence-rss",
    "cert_in":           "https://www.cert-in.org.in/RSS/Vulnerability_Notes.xml",
    "sans_isc":          "https://isc.sans.edu/rssfeed.xml",

    # ══ CVE / EXPLOIT DATABASES ══════════════════════════════════════════════
    "exploit_db":    "https://www.exploit-db.com/rss.xml",
    "zdi_published": "https://www.zerodayinitiative.com/rss/published/",
    "zdi_upcoming":  "https://www.zerodayinitiative.com/rss/upcoming/",
    "vuldb":         "https://vuldb.com/?rss.recent",

    # ══ OS & PLATFORM ════════════════════════════════════════════════════════
    "msrc":         "https://api.msrc.microsoft.com/update-guide/rss",
    "msrc_blog":    "https://msrc.microsoft.com/blog/feed/",
    "ms_azure":     "https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftSecurityandCompliance",
    "apple":        "https://support.apple.com/en-in/rss/securityupdates.rss",
    "ubuntu":       "https://ubuntu.com/security/notices/rss.xml",
    "android":      "https://security.googleblog.com/feeds/posts/default",
    "redhat":       "https://access.redhat.com/security/security-updates/security-advisories.rss",
    "debian":       "https://www.debian.org/security/dsa-long",
    "docker":       "https://www.docker.com/blog/category/security/feed/",

    # ══ NETWORK & FIREWALL ═══════════════════════════════════════════════════
    "cisco":        "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
    "fortinet":     "https://www.fortiguard.com/rss/ir.xml",
    "paloalto":     "https://security.paloaltonetworks.com/rss.xml",
    "sonicwall":    "https://blog.sonicwall.com/feed/",
    "ivanti":       "https://www.ivanti.com/blog/topics/security-advisory/rss",
    "f5":           "https://support.f5.com/rss/security-advisories.xml",
    "checkpoint":   "https://research.checkpoint.com/feed/",
    "juniper":      "https://kb.juniper.net/JSA/rss",
    "citrix":       "https://support.citrix.com/feed/news",
    "aruba":        "https://support.hpe.com/hpesc/public/home/rss?docType=Security+Bulletin&sort=modified",
    "netgear":      "https://kb.netgear.com/app/answers/detail/a_id/62001",
    "zyxel":        "https://www.zyxel.com/global/en/support/security-advisories.shtml",

    # ══ ENDPOINT SECURITY ════════════════════════════════════════════════════
    "crowdstrike_blog":       "https://www.crowdstrike.com/blog/feed/",
    "sentinelone":            "https://www.sentinelone.com/labs/feed/",
    "sophos":                 "https://www.welivesecurity.com/en/feed/",
    "trendmicro":             "https://feeds.feedburner.com/Anti-MalwareBlog",
    "trellix":                "https://www.rapid7.com/blog/rss/",
    "malwarebytes":           "https://www.malwarebytes.com/blog/feed/",
    "eset":                   "https://www.welivesecurity.com/feed/",

    # ══ CLOUD & BROWSER ══════════════════════════════════════════════════════
    "aws":          "https://aws.amazon.com/security/security-bulletins/feed/",
    "gcp":          "https://cloud.google.com/feeds/gke-security-bulletins.xml",
    "chrome":       "https://chromereleases.googleblog.com/feeds/posts/default",
    "project_zero": "https://googleprojectzero.blogspot.com/feeds/posts/default",
    "cloudflare":   "https://blog.cloudflare.com/tag/security/rss/",
    "okta":         "https://developer.okta.com/feed.xml",

    # ══ MIDDLEWARE / DB ═══════════════════════════════════════════════════════
    "mozilla":      "https://blog.mozilla.org/security/feed/",
    "openssl":      "https://www.openssl.org/news/secadv/",
    "apache":       "https://blogs.apache.org/security/feed/entries/rss",
    "oracle":       "https://www.kb.cert.org/vuls/atomfeed/",
    "vmware":       "https://community.broadcom.com/blogs/rss/4",
    "splunk":       "https://advisory.splunk.com/feed.xml",
    "veeam":        "https://www.veeam.com/rss/security-advisories.xml",
    "nginx":        "https://nginx.org/en/security_advisories.html",

    # ══ YOUR STACK ═══════════════════════════════════════════════════════════
    "netskope":     "https://www.netskope.com/blog/feed",
    "proofpoint":   "https://www.proofpoint.com/us/rss.xml",
    "solarwinds":   "https://www.solarwinds.com/shared-content/rss-feed/solarwinds-cve-rss-feed.xml",
    "forescout":    "https://claroty.com/team82/blog/rss.xml",

    # ══ THREAT INTEL ══════════════════════════════════════════════════════════
    "mandiant":     "https://www.mandiant.com/resources/blog/rss.xml",
    "talos":        "https://feeds.feedburner.com/feedburner/Talos",
    "unit42":       "https://unit42.paloaltonetworks.com/feed/",
    "msft_ti":      "https://www.microsoft.com/en-us/security/blog/feed/",
    "secureworks":  "https://www.huntress.com/blog/rss.xml",
    "recorded_fut": "https://therecord.media/feed/",

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
    "msrc","cisco","fortinet","paloalto","juniper","f5","sonicwall",
    "ivanti","citrix","checkpoint","vmware","sophos","apple","ubuntu",
    "redhat","android","oracle","splunk","veeam","cisa_kev","cisa_alerts","cisa_ics",
    "ncsc_uk","cert_eu","cert_in","zdi_published","mozilla","openssl",
    "netskope","forescout","aws","gcp","msrc_blog","trellix",
    "ghsa","mitre_cve","vulncheck_nvd","vulncheck_kev",  # Pre-NVD sources treated as authoritative
}

# ─── STARTUP LOG ──────────────────────────────────────────────────────────────
log.info(f"🛡️  Security Advisory Proxy v2 — port {PORT}")
log.info(f"   Sources   : 148 monitored / {SOURCE_COUNT} active feeds (+ GHSA/OSV/MITRE/VulnCheck pre-NVD)")
log.info(f"   VulnCheck : {'✅ API key set' if VULNCHECK_API_KEY else '⚠️  No API key (set VULNCHECK_API_KEY for pre-NVD data)'}")
log.info(f"   Email     : {'✅ SendGrid' if SENDGRID_API_KEY else '⚠️  No SendGrid'}")
log.info(f"   Auth      : {'✅ Access code set' if ACCESS_CODE else '⚠️  No access code'}")
log.info(f"   Teams     : {'✅ Webhook set' if TEAMS_WEBHOOK else '⚠️  No webhook'}")
log.info(f"   Supabase  : {'✅ Persistent storage' if SUPABASE_URL else '⚠️  Memory only'}")

# ─── HELPERS ──────────────────────────────────────────────────────────────────


# Sources where ALL items are considered zero-day / actively exploited by definition
ZERO_DAY_SOURCES = {
    "cisa_kev",       # CISA Known Exploited Vulnerabilities — confirmed active exploitation
    "zdi_published",  # Zero Day Initiative published advisories
    "exploit_db",     # Exploit-DB — public exploits exist
}

# News/blog sources — these are articles, not structured advisories
NEWS_SOURCES = {
    # General security news sites — articles only, no CVE IDs
    "krebs","bleeping","hackernews","securityweek","darkreading","helpnetsec",
    "ars_security","wired_sec","reddit_netsec","threatpost","schneier",
    "cybersecnews","gbhackers","cyberinsider","qualys_blog","sans_isc",
    # Threat intelligence & research blogs (articles, not structured advisories)
    "mandiant","talos","unit42","msft_ti","secureworks","recorded_fut",
    "crowdstrike_blog",   # CrowdStrike blog (Patch Tuesday analysis etc.)
    "msrc_blog",          # MSRC blog posts (msrc feed = structured advisories, kept separate)
    "sentinelone",        # SentinelLabs threat research
    "malwarebytes",       # Malwarebytes Labs research
    "eset",               # ESET threat research
    "project_zero",       # Google Project Zero research
    "cloudflare",         # Cloudflare security blog
    "proofpoint",         # Proofpoint threat intel blog
    "certeu_threat_intel",# CERT-EU threat intelligence reports
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

def parse_severity(text:str, source:str="", is_oem:bool=False) -> str:
    # 1) CVSS score — most reliable
    score = extract_cvss_v3(text)
    if score is not None:
        if score >= 9.0: return "Critical"
        if score >= 7.0: return "High"
        if score >= 4.0: return "Medium"
        return "Low"
    # 2) Keyword matching
    t = text.lower()
    for sev, kws in SEVERITY_KEYWORDS.items():
        if any(k in t for k in kws): return sev
    # 3) Source-tier inference: OEM Tier1 with no other signal = High (not Unknown)
    if is_oem: return "High"
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

def _title_fingerprint(title:str) -> str:
    """Normalised title fingerprint for fuzzy dedup of non-CVE items."""
    t = re.sub(r"[^a-z0-9 ]", "", title.lower())
    words = [w for w in t.split() if len(w) > 3 and w not in
             {"this","that","with","from","have","been","will","your","they","their",
              "security","advisory","update","patch","vulnerability","issue","fixes"}]
    return " ".join(sorted(words[:8]))  # sort so word-order differences don't matter

VENDOR_NORMALISE={"microsoft corporation":"Microsoft","microsoft corp":"Microsoft","msrc":"Microsoft","cisco systems":"Cisco","cisco systems, inc.":"Cisco","google llc":"Google","google inc":"Google","apple inc":"Apple","apple inc.":"Apple","oracle corporation":"Oracle","oracle corp":"Oracle","adobe inc":"Adobe","vmware inc":"VMware","vmware, inc":"VMware","fortinet inc":"Fortinet","fortinet, inc":"Fortinet","palo alto networks":"Palo Alto Networks","check point software":"Check Point","f5 networks":"F5","f5, inc":"F5","citrix systems":"Citrix","solarwinds corporation":"SolarWinds","ivanti inc":"Ivanti","ivanti, inc":"Ivanti","red hat inc":"Red Hat","red hat, inc":"Red Hat","canonical ltd":"Canonical","apache software foundation":"Apache","the apache software foundation":"Apache","mozilla foundation":"Mozilla","mozilla corporation":"Mozilla","sap se":"SAP","siemens ag":"Siemens","schneider electric":"Schneider Electric"}
def normalise_vendor(raw:str)->str:
    if not raw: return raw
    return VENDOR_NORMALISE.get(raw.strip().lower(),raw.strip())

# Source priority for cross-source merge — higher number = higher trust
# When two sources conflict on CVSS/severity, higher priority source wins
SOURCE_PRIORITY = {
    # OEM Direct — most authoritative for their own products
    "msrc":12, "cisco":12, "fortinet":12, "paloalto":12, "juniper":12,
    "ivanti":12, "vmware":12, "sap":12, "oracle":12, "adobe":12,
    "apple":12, "android":12, "chrome":12, "mozilla":12, "solarwinds":12,
    "checkpoint":12, "f5":12, "citrix":12, "aruba":12, "netscout":12,
    "crowdstrike":12, "sentinelone":12, "splunk":12, "prtg":12,
    # Government / Official
    "cisa_kev":11,        # CISA KEV — exploited in wild confirmed
    "vulncheck_kev":11,   # VulnCheck KEV — same tier
    "nvd":10,             # NVD — official CVSS scores
    "nist_nvd":10,
    "cisa_alerts":9, "cisa_ics":9, "cert_eu":9, "cert_in":9,
    "ghsa":9,             # GitHub Advisory — authoritative for OSS
    "osv":8,              # Google OSV
    "mitre_cve":8,
    # Aggregators
    "exploit_db":7,       # Has PoC/exploit info
    "vulncheck_nvd":7,
    "zdi_published":6, "zdi_upcoming":6,
    "vuldb":5,
    # Generic
    "github_advisories":4,
    "cvefeed_high_critical":3, "cvedaily_all":3, "cvedaily_critical":3,
}

def _src_priority(source:str) -> int:
    """Return source trust priority — higher = more authoritative."""
    return SOURCE_PRIORITY.get(source, 5)


def dedupe_and_enrich(items:list) -> list:
    """
    Cross-source CVE deduplication with intelligent field merging.

    Strategy:
    - Items pre-sorted: OEM first, then by severity, then by date
    - Match by: CVE ID (primary), URL/ID (secondary), fuzzy title (news only)
    - On merge: best field from highest-priority source always wins
    - Accumulate: sources_list, cves array, tags, products across all sources
    - KEV/ZeroDay/isOEM flags: OR-merge (if ANY source says true, result is true)
    """
    seen_cve   = {}   # CVE-ID → out index
    seen_url   = {}   # advisory ID/URL → out index
    seen_title = {}   # fuzzy title fingerprint → out index (news only)
    out        = []

    merged_count = 0

    for a in items:
        cve = (a.get("cve") or "").upper().strip()
        uid = a.get("id","").strip()
        tfp = _title_fingerprint(a.get("title","")) if not cve else ""

        # ── Find match ────────────────────────────────────────────────────────
        merge_idx = None
        if cve and cve.startswith("CVE-"):
            merge_idx = seen_cve.get(cve)
        if merge_idx is None:
            merge_idx = seen_url.get(uid)
        if merge_idx is None and tfp and len(tfp) > 10:
            merge_idx = seen_title.get(tfp)

        if merge_idx is not None:
            # ── Merge into existing record ────────────────────────────────────
            merged_count += 1
            ex  = out[merge_idx]
            src = a.get("source","")
            ex_priority = _src_priority(ex.get("source",""))
            new_priority = _src_priority(src)

            # Accumulate source list
            sl = ex.get("sources_list", [ex.get("source","")])
            if src and src not in sl:
                sl.append(src)
            ex["sources_list"] = sl
            ex["source_count"] = len(sl)
            ex["duplicate_cve"] = True

            # Accumulate CVE array (union of all CVEs from all sources)
            all_cves = set(ex.get("cves") or ([ex["cve"]] if ex.get("cve") else []))
            all_cves.update(a.get("cves") or ([a["cve"]] if a.get("cve") else []))
            all_cves.discard("")
            if all_cves:
                ex["cves"] = sorted(all_cves)

            # Accumulate tags (union)
            ex_tags = set(ex.get("tags") or [])
            new_tags = set(a.get("tags") or [])
            if new_tags - ex_tags:
                ex["tags"] = sorted(ex_tags | new_tags)

            # Accumulate affected products (union, deduplicated)
            ex_prods = ex.get("products") or []
            new_prods = a.get("products") or []
            merged_prods = list({p for p in (ex_prods + new_prods) if p})
            if merged_prods:
                ex["products"] = merged_prods[:20]  # cap at 20

            # Boolean OR-merge — if ANY source confirms, it's true
            if a.get("zeroDay"):        ex["zeroDay"]        = True
            if a.get("isOEM"):          ex["isOEM"]          = True
            if a.get("isKev") or a.get("source","") in ("cisa_kev","vulncheck_kev"):
                ex["isKev"] = True

            # Field quality merge — higher priority source wins on conflict
            # Lower priority source fills gaps only
            if new_priority >= ex_priority:
                # Higher/equal priority: take better values
                if a.get("cvss") and (not ex.get("cvss") or new_priority > ex_priority):
                    ex["cvss"] = a["cvss"]
                if a.get("severity","Unknown") not in ("Unknown","") and                    (ex.get("severity","Unknown") == "Unknown" or new_priority > ex_priority):
                    ex["severity"] = a["severity"]
                if a.get("description") and (not ex.get("description") or
                   (new_priority > ex_priority and len(a["description"]) > len(ex.get("description","")))):
                    ex["description"] = a["description"]
                if a.get("summary") and not ex.get("summary"):
                    ex["summary"] = a["summary"]
                if a.get("title") and new_priority > ex_priority and len(a.get("title","")) > 10:
                    ex["title"] = a["title"]  # higher priority source has better title
            else:
                # Lower priority: fill gaps only, never overwrite
                if not ex.get("cvss")        and a.get("cvss"):        ex["cvss"]        = a["cvss"]
                if not ex.get("description") and a.get("description"): ex["description"] = a["description"]
                if not ex.get("summary")     and a.get("summary"):     ex["summary"]     = a["summary"]
                if ex.get("severity","Unknown") == "Unknown" and a.get("severity","Unknown") != "Unknown":
                    ex["severity"] = a["severity"]

            # Always take KEV enrichment fields from KEV sources
            if src in ("cisa_kev","vulncheck_kev"):
                if a.get("required_action"): ex["required_action"] = a["required_action"]
                if a.get("kev_due_date"):    ex["kev_due_date"]    = a["kev_due_date"]
                if a.get("kev_notes"):       ex["kev_notes"]       = a["kev_notes"]

            # Always take exploit info from Exploit-DB / ZDI
            if src in ("exploit_db","zdi_published","zdi_upcoming"):
                if a.get("exploit_refs"): ex["exploit_refs"] = a.get("exploit_refs","")

            # Take patch status if we have none
            if not ex.get("patch_status") or ex.get("patch_status") == "unknown":
                if a.get("patch_status") and a["patch_status"] != "unknown":
                    ex["patch_status"] = a["patch_status"]

            # CWE: take first available
            if not ex.get("cwe") and a.get("cwe"):
                ex["cwe"] = a["cwe"]

        else:
            # ── New record ────────────────────────────────────────────────────
            idx_new = len(out)
            a["sources_list"]  = [a.get("source","")]
            a["source_count"]  = 1
            a["duplicate_cve"] = False
            if cve and cve.startswith("CVE-"):
                seen_cve[cve] = idx_new
            seen_url[uid] = idx_new
            if tfp and len(tfp) > 10:
                seen_title[tfp] = idx_new
            out.append(a)

    log.info(f"[DEDUPE] {len(items)} -> {len(out)} ({merged_count} duplicates merged, "
             f"{len(items)-len(out)} unique CVEs collapsed)")
    return out


def fmt_ts(dt_str:str) -> str:
    """Return ISO timestamp string."""
    return dt_str or datetime.now(timezone.utc).isoformat()

def _infer_patch_status(text: str) -> str:
    t = text.lower()
    if any(w in t for w in ["no patch","no fix","no update","not yet patched","unpatched"]):
        return "no_fix"
    if any(w in t for w in ["patch available","update available","fixed in","addressed in",
                              "resolved in","upgrade to","apply the","security update","cumulative update"]):
        return "available"
    if any(w in t for w in ["workaround","mitigation","disable","restrict access","temporary fix"]):
        return "workaround"
    return "unknown"


def is_within_window(published_str: str, is_kev: bool = False, is_zero_day: bool = False) -> bool:
    """
    Return True if published date is within the retention window.
    R4 fix: KEV and ZeroDay items use extended windows — they stay exploitable
    long after publication and must not be dropped at 30 days.
    """
    try:
        pub = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
        if pub.tzinfo is None:
            pub = pub.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - pub).days
        if is_kev:      return age_days <= CACHE_RETENTION_DAYS["kev"]
        if is_zero_day: return age_days <= CACHE_RETENTION_DAYS["zeroday"]
        return age_days <= CACHE_RETENTION_DAYS["default"]  # 90d default
    except Exception:
        return True  # If we can't parse, keep the item


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

    # ── Drop items outside the fetch window ──────────────────────────────────
    # Note: use ZERO_DAY_SOURCES directly here — is_zero_src not yet assigned
    _is_kev_src = source in ("cisa_kev","CISA KEV","vulncheck_kev")
    _is_zd_src  = source in ZERO_DAY_SOURCES
    if not is_within_window(published, is_kev=_is_kev_src, is_zero_day=_is_zd_src):
        return None

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

    is_oem       = source in OEM_TIER1
    is_news      = source in NEWS_SOURCES
    is_zero_src  = source in ZERO_DAY_SOURCES
    # Detect blog/analysis articles mixed into advisory feeds (e.g. CrowdStrike Patch Tuesday posts)
    # Title-based news detection — only for non-OEM sources
    # OEM Tier 1 sources (msrc, cisco, fortinet etc.) NEVER flagged as news by title
    # Keywords are specific enough to catch blog posts but not CVE advisory titles
    BLOG_TITLE_KEYWORDS = [
        "patch tuesday","threat intelligence","threat report","threat roundup",
        "weekly","monthly","recap","roundup","podcast","webinar","interview","whitepaper",
    ]
    title_lower = title.lower()
    is_news_by_title = any(kw in title_lower for kw in BLOG_TITLE_KEYWORDS)
    # Only apply title-based detection if: not already news, not OEM, not a single CVE item
    if not is_news and not is_oem and is_news_by_title and not (all_cves and len(all_cves) >= 1):
        is_news = True
    cvss_score   = extract_cvss_v3(combined)
    severity_raw = parse_severity(combined, source=source, is_oem=is_oem)
    # NEWS items capped at Medium — keyword matches on news titles inflate severity
    severity = min(["Critical","High","Medium","Low","Unknown"].index(severity_raw),
                   ["Critical","High","Medium","Low","Unknown"].index("Medium") if is_news else 0)
    severity = ["Critical","High","Medium","Low","Unknown"][severity]
    # Zero-day: keyword detection OR source-based inference
    zero_day = is_zero_day(combined) or is_zero_src

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
        "zeroDay":          zero_day,
        "source":           source,
        "vendor":           normalise_vendor(source),
        "products":         products,
        "affected_versions":affected_versions,
        "patch_info":       patch_info,
        "bug_id":           bug_id,
        "author":           extract_author(entry),
        "tags":             [t.get("term","") for t in (getattr(entry,"tags",[]) or []) if t.get("term")][:6],
        "isOEM":            is_oem,
        "isNews":           is_news,
    }
    advisory["data_quality"]   = data_quality(advisory)
    advisory["fetched_at"]     = datetime.now(timezone.utc).isoformat()
    advisory["patch_status"]   = _infer_patch_status(combined)
    advisory["kev_due_date"]   = ""
    advisory["required_action"]= ""
    advisory["kev_notes"]      = ""
    return advisory

# ─── FETCH ────────────────────────────────────────────────────────────────────
def fetch_rss(key:str, url:str) -> list:
    with cache_lock:
        if key in cache: return cache[key]
    if key == "mozilla": return fetch_mozilla_json()
    try:
        # Add Accept header for feeds that require it (e.g. GitHub atom)
        extra_hdrs = {"Accept":"application/atom+xml,application/rss+xml,application/xml,text/xml,*/*"} if "github.com" in url else {}
        resp = requests.get(url, timeout=15, headers={
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            **extra_hdrs,
            "Accept":"application/rss+xml,application/atom+xml,application/xml,text/xml,*/*",
        }, allow_redirects=True)
        resp.raise_for_status()
        feed  = feedparser.parse(resp.content)
        items = [x for x in [normalise_entry(e, key) for e in (feed.entries or [])[:50]] if x is not None]
        if feed.bozo and not items: log.debug(f"[{key}] Bozo (XML warning, data still parsed): {feed.bozo_exception}")
        elif items: log.info(f"[{key}] ✅ {len(items)} items")
        with cache_lock: cache[key] = items
        threading.Thread(target=supa_record_feed_metrics,
            args=(key,len(items),items,True,"",0),daemon=True).start()
        return items
    except requests.exceptions.SSLError:
        try:
            resp  = requests.get(url, timeout=15, verify=False, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"})
            feed  = feedparser.parse(resp.content)
            items = [x for x in [normalise_entry(e, key) for e in (feed.entries or [])[:50]] if x is not None]
            log.warning(f"[{key}] SSL bypass — {len(items)} items")
            with cache_lock: cache[key] = items
            threading.Thread(target=supa_record_feed_metrics,
                args=(key,len(items),items,True,"",0),daemon=True).start()
            return items
        except Exception as e2: log.error(f"[{key}] SSL fallback: {e2}"); return []
    except Exception as e:
        log.error(f"[{key}] Failed: {e}")
        threading.Thread(target=supa_record_feed_metrics,
            args=(key,0,[],False,str(e)[:200],0),daemon=True).start()
        return []

def fetch_mozilla_json() -> list:
    """Fetch Mozilla Security Blog via RSS (JSON endpoint deprecated)."""
    with cache_lock:
        if "mozilla" in cache: return cache["mozilla"]
    try:
        feed = feedparser.parse("https://blog.mozilla.org/security/feed/")
        items = [normalise_entry(e, "mozilla") for e in (feed.entries or [])[:50]]
        items = [i for i in items if i is not None and is_within_window(i.get("published",""))]
        # Mark as OEM
        for i in items: i["isOEM"] = True
        with cache_lock: cache["mozilla"] = items
        log.info(f"[mozilla] ✅ {len(items)} items (RSS)")
        return items
    except Exception as e:
        log.error(f"[mozilla] RSS failed: {e}")
        return []

def fetch_cisa_kev() -> list:
    with cache_lock:
        if "cisa_kev" in cache: return cache["cisa_kev"]
    try:
        resp = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                            timeout=15, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"})
        resp.raise_for_status()
        items = []
        for v in resp.json().get("vulnerabilities",[])[:50]:
            cve_id = v.get("cveID","")
            title  = f"{cve_id} — {v.get('vulnerabilityName','')}"
            summary= (f"{v.get('shortDescription','')} | Vendor: {v.get('vendorProject','')} | "
                      f"Product: {v.get('product','')} | Required Action: {v.get('requiredAction','')}")
            due_date     = v.get("dueDate","")
            required_act = v.get("requiredAction","")
            kev_notes    = v.get("notes","")
            patch_status = "available" if any(w in required_act.lower() for w in
                           ["apply","update","patch","upgrade","install","remediat"]) else "workaround"
            items.append({"id":cve_id,"title":title,"summary":summary,"description":summary,
                "link":f"https://nvd.nist.gov/vuln/detail/{cve_id}","url":f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published":v.get("dateAdded",datetime.now(timezone.utc).isoformat()),
                "severity":"Critical","cvss":None,"cve":cve_id,"cves":[cve_id],"zeroDay":True,
                "source":"CISA KEV","vendor":"CISA","products":[v.get("product","")],"author":"","tags":["KEV"],"isOEM":True,
                "fetched_at":datetime.now(timezone.utc).isoformat(),
                "kev_due_date":due_date,"required_action":required_act,
                "kev_notes":kev_notes,"patch_status":patch_status})
        items = [i for i in items if is_within_window(i.get("published",""))]
        with cache_lock: cache["cisa_kev"] = items
        log.info(f"[cisa_kev] ✅ {len(items)} items")
        return items
    except Exception as e: log.error(f"[cisa_kev] Failed: {e}"); return []

def enrich_missing_cvss_from_nvd(advisories:list)->list:
    """Query NVD for CVEs still missing CVSS after dedup. Free API, no key. Max 30/cycle."""
    needs=[a for a in advisories if (a.get("cve") or "").startswith("CVE-")
           and (not a.get("cvss") or a.get("severity","Unknown")=="Unknown")
           and not a.get("_nvd_queried")][:30]
    if not needs: return advisories
    log.info(f"[NVD-ENRICH] Querying {len(needs)} CVEs missing CVSS/severity")
    adv_map={a["cve"]:a for a in advisories if a.get("cve")}
    enriched=0
    for a in needs:
        cve_id=a["cve"]
        try:
            r=requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                headers={"User-Agent":"Mozilla/5.0 (compatible)"},timeout=8)
            if r.status_code==429: log.warning("[NVD-ENRICH] Rate limited"); break
            if r.status_code!=200: continue
            vulns=r.json().get("vulnerabilities",[])
            if not vulns: continue
            cve_data=vulns[0].get("cve",{}); metrics=cve_data.get("metrics",{})
            cvss_score=None; severity=None
            for ver in ["cvssMetricV31","cvssMetricV30","cvssMetricV40"]:
                if metrics.get(ver):
                    m=metrics[ver][0].get("cvssData",{})
                    cvss_score=m.get("baseScore"); severity=m.get("baseSeverity","").capitalize(); break
            if not cvss_score and metrics.get("cvssMetricV2"):
                m=metrics["cvssMetricV2"][0].get("cvssData",{}); cvss_score=m.get("baseScore")
                severity="High" if cvss_score and cvss_score>=7 else "Medium" if cvss_score and cvss_score>=4 else "Low"
            tgt=adv_map.get(cve_id)
            if tgt and cvss_score:
                if not tgt.get("cvss"):                                   tgt["cvss"]=cvss_score
                if tgt.get("severity","Unknown")=="Unknown" and severity:  tgt["severity"]=severity
                if not tgt.get("cwe"):
                    for w in cve_data.get("weaknesses",[]):
                        for d in w.get("description",[]):
                            if d.get("value","").startswith("CWE-"):
                                tgt["cwe"]=d["value"]; break
                        if tgt.get("cwe"): break
                tgt["_nvd_queried"]=True; enriched+=1
        except Exception as e: log.debug(f"[NVD-ENRICH] {cve_id}: {e}"); continue
        import time as _t; _t.sleep(0.65)
    if enriched: log.info(f"[NVD-ENRICH] ✅ Enriched {enriched}/{len(needs)} CVEs from NVD")
    return advisories

def enrich_with_epss(advisories:list) -> list:
    """
    Enrich advisories with EPSS scores from FIRST.org.
    EPSS = Exploit Prediction Scoring System (0-1 probability score).
    Free, no API key needed. Batches up to 100 CVEs per request.
    """
    cve_ids = list({a["cve"] for a in advisories if a.get("cve") and a["cve"].startswith("CVE-")})
    if not cve_ids:
        return advisories
    epss_map = {}
    # EPSS API allows comma-separated CVE IDs (up to 100 per request)
    BATCH = 100
    for i in range(0, len(cve_ids), BATCH):
        batch = cve_ids[i:i+BATCH]
        try:
            resp = requests.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": ",".join(batch), "limit": BATCH},
                timeout=10,
                headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
            )
            if resp.status_code == 200:
                for item in resp.json().get("data", []):
                    cve = item.get("cve","").upper()
                    epss_map[cve] = {
                        "epss":  round(float(item.get("epss",  0)) * 100, 2),   # convert to %
                        "percentile": round(float(item.get("percentile", 0)) * 100, 1),
                        "date":  item.get("date","")
                    }
        except Exception as e:
            log.warning(f"[EPSS] Batch {i//BATCH+1} failed: {e}")

    # Apply EPSS data to advisories
    for a in advisories:
        cve = (a.get("cve","") or "").upper()
        if cve in epss_map:
            a["epss"]       = epss_map[cve]["epss"]
            a["epss_pct"]   = epss_map[cve]["percentile"]
            a["epss_date"]  = epss_map[cve]["date"]
            # Auto-upgrade severity if EPSS is very high but severity is unknown/low
            if a["epss"] >= 50 and a.get("severity","Unknown") in ("Unknown","Low"):
                a["severity"] = "High"
                a["epss_upgraded"] = True
        else:
            a["epss"]     = None
            a["epss_pct"] = None

    enriched = len(epss_map)
    log.info(f"[EPSS] Enriched {enriched}/{len(cve_ids)} CVEs with EPSS scores")
    return advisories

def fetch_ghsa() -> list:
    """
    Fetch GitHub Advisory Database (GHSA) — publishes open source CVEs
    same-day, 1–3 days ahead of NVD. Free, no API key.
    Covers npm, PyPI, Go, Maven, Ruby, Rust, Swift, Erlang, Pub, Actions.
    """
    with cache_lock:
        if "ghsa" in cache: return cache["ghsa"]
    try:
        resp = requests.get(
            "https://api.github.com/advisories?per_page=100&type=reviewed&direction=desc&sort=published",
            timeout=15,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                **( {"Authorization": f"Bearer {os.getenv('GITHUB_TOKEN','')}"}
                    if os.getenv("GITHUB_TOKEN") else {} ),
            }
        )
        resp.raise_for_status()
        items = []
        for a in resp.json():
            cve_id    = a.get("cve_id") or ""
            ghsa_id   = a.get("ghsa_id","")
            title     = a.get("summary","") or ghsa_id
            desc      = a.get("description","") or title
            combined  = f"{title} {desc}"
            link      = a.get("html_url") or f"https://github.com/advisories/{ghsa_id}"
            published = a.get("published_at","") or datetime.now(timezone.utc).isoformat()
            sev_map   = {"critical":"Critical","high":"High","moderate":"Medium","low":"Low"}
            severity  = sev_map.get((a.get("severity") or "").lower(), "Unknown")
            cvss_val  = None
            if a.get("cvss") and a["cvss"].get("score"):
                cvss_val = float(a["cvss"]["score"])
                if severity == "Unknown":
                    if cvss_val >= 9: severity = "Critical"
                    elif cvss_val >= 7: severity = "High"
                    elif cvss_val >= 4: severity = "Medium"
                    else: severity = "Low"
            # Affected ecosystems
            ecosystems = list({v.get("package",{}).get("ecosystem","") for v in (a.get("vulnerabilities") or [])})
            products   = [f"{v.get('package',{}).get('ecosystem','')}:{v.get('package',{}).get('name','')}"
                         for v in (a.get("vulnerabilities") or [])[:3]]
            entry_id   = cve_id or ghsa_id
            if not entry_id or not is_within_window(published): continue
            items.append({
                "id": entry_id, "title": title[:300], "summary": desc[:600],
                "description": desc, "link": link, "url": link,
                "published": published, "severity": severity,
                "cvss": cvss_val, "cve": cve_id, "cves": [cve_id] if cve_id else [],
                "zeroDay": False, "source": "ghsa", "vendor": "GitHub Advisory",
                "products": products, "author": "", "tags": ecosystems[:4],
                "isOEM": False, "isNews": False,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "patch_status": "available" if a.get("vulnerabilities") else "unknown",
                "kev_due_date": "", "required_action": "", "kev_notes": "",
                "data_quality": "RICH" if (cve_id and cvss_val) else "PARTIAL",
            })
        with cache_lock: cache["ghsa"] = items
        log.info(f"[ghsa] ✅ {len(items)} items (GitHub Advisory DB)")
        return items
    except Exception as e:
        log.error(f"[ghsa] Failed: {e}")
        return []


def fetch_osv() -> list:
    """
    Fetch Google OSV.dev — Open Source Vulnerability database.
    Covers 20+ ecosystems including PyPI, npm, Go, Maven, Rust, Debian, Alpine.
    Free, no API key. Same-day publication, structured with fix versions.
    """
    with cache_lock:
        if "osv" in cache: return cache["osv"]
    try:
        # Query recent vulnerabilities modified in last 2 days
        cutoff = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json={"package": {}, "page_size": 100},
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                     "Content-Type": "application/json"}
        )
        # OSV query by recent: use the vulns endpoint
        resp2 = requests.get(
            f"https://api.osv.dev/v1/vulns?modified_since={cutoff}&page_size=100",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
        )
        data = resp2.json() if resp2.status_code == 200 else resp.json()
        items = []
        for v in (data.get("vulns") or [])[:100]:
            osv_id    = v.get("id","")
            aliases   = v.get("aliases",[])
            cve_id    = next((a for a in aliases if a.startswith("CVE-")), "")
            title     = v.get("summary","") or osv_id
            desc      = v.get("details","") or title
            published = v.get("published","") or v.get("modified","") or datetime.now(timezone.utc).isoformat()
            link      = f"https://osv.dev/vulnerability/{osv_id}"
            ecosystem = v.get("affected",[{}])[0].get("package",{}).get("ecosystem","") if v.get("affected") else ""
            pkg_name  = v.get("affected",[{}])[0].get("package",{}).get("name","") if v.get("affected") else ""
            # Get CVSS from severity list
            severity  = "Unknown"; cvss_val = None
            for sev in (v.get("severity") or []):
                if sev.get("type") == "CVSS_V3":
                    try:
                        score = float(sev.get("score","").split("/")[0]) if "/" not in sev.get("score","") else None
                        if score is None:
                            import re as _re
                            m = _re.search(r'CVSS:3[^/]*/.*?/(\d+\.?\d*)', sev.get("score",""))
                            score = float(m.group(1)) if m else None
                        if score:
                            cvss_val = score
                            if score >= 9: severity = "Critical"
                            elif score >= 7: severity = "High"
                            elif score >= 4: severity = "Medium"
                            else: severity = "Low"
                    except: pass
            entry_id = cve_id or osv_id
            if not entry_id or not is_within_window(published): continue
            items.append({
                "id": entry_id, "title": title[:300], "summary": desc[:600],
                "description": desc, "link": link, "url": link,
                "published": published, "severity": severity,
                "cvss": cvss_val, "cve": cve_id, "cves": [cve_id] if cve_id else [],
                "zeroDay": False, "source": "osv", "vendor": f"OSV/{ecosystem}",
                "products": [f"{ecosystem}:{pkg_name}"] if pkg_name else [],
                "author": "", "tags": [ecosystem] if ecosystem else [],
                "isOEM": False, "isNews": False,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "patch_status": "available" if any(
                    r.get("type","").lower() in ("fix","fixed") for a in (v.get("affected") or [])
                    for r in (a.get("ranges") or [])
                ) else "unknown",
                "kev_due_date": "", "required_action": "", "kev_notes": "",
                "data_quality": "RICH" if (cve_id and cvss_val) else "PARTIAL",
            })
        with cache_lock: cache["osv"] = items
        log.info(f"[osv] ✅ {len(items)} items (OSV.dev)")
        return items
    except Exception as e:
        log.error(f"[osv] Failed: {e}")
        return []


def fetch_mitre_cve() -> list:
    """
    Fetch MITRE CVE List — publishes CVEs within minutes of reservation.
    Days before NVD. Uses the CVE Program API (free, no key).
    Primary fix for the 24–72h NVD publication lag.
    """
    with cache_lock:
        if "mitre_cve" in cache: return cache["mitre_cve"]
    try:
        # Get CVEs published/updated in last 2 days
        since = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.000")
        resp = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={since}&resultsPerPage=100",
            timeout=20,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
        )
        # Fallback: use MITRE CVE Services API
        if resp.status_code != 200:
            resp = requests.get(
                f"https://cveawg.mitre.org/api/cve?state=PUBLISHED&time_modified.start={since}&page=0&pageSize=100",
                timeout=20,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"}
            )
        items = []
        data = resp.json()
        cve_list = data.get("vulnerabilities", data.get("cveRecords", []))
        for entry in cve_list[:100]:
            cve  = entry.get("cve", entry)
            meta = cve.get("cveMetadata", {})
            cve_id = meta.get("cveId","") or cve.get("id","")
            if not cve_id: continue
            # Parse descriptions
            descs = cve.get("containers",{}).get("cna",{}).get("descriptions",[]) or                     cve.get("descriptions",[])
            desc  = next((d.get("value","") for d in descs if d.get("lang","").startswith("en")), "")
            title = f"{cve_id}" + (f" — {desc[:120]}" if desc else "")
            # Parse CVSS
            metrics = cve.get("containers",{}).get("cna",{}).get("metrics",[]) or                       cve.get("metrics",[])
            cvss_val = None; severity = "Unknown"
            for m in metrics:
                for k in ["cvssV3_1","cvssV3_0","cvssV4_0"]:
                    if m.get(k,{}).get("baseScore"):
                        cvss_val = float(m[k]["baseScore"])
                        severity = m[k].get("baseSeverity","Unknown").capitalize()
                        break
            published = meta.get("datePublished","") or meta.get("dateUpdated","") or                         entry.get("published","") or datetime.now(timezone.utc).isoformat()
            if not is_within_window(published): continue
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            items.append({
                "id": cve_id, "title": title[:300], "summary": desc[:600],
                "description": desc, "link": link, "url": link,
                "published": published, "severity": severity or parse_severity(desc),
                "cvss": cvss_val, "cve": cve_id, "cves": [cve_id],
                "zeroDay": is_zero_day(desc), "source": "mitre_cve",
                "vendor": "MITRE CVE", "products": [], "author": "",
                "tags": ["CVE List"], "isOEM": False, "isNews": False,
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "patch_status": _infer_patch_status(desc),
                "kev_due_date": "", "required_action": "", "kev_notes": "",
                "data_quality": "RICH" if (desc and cvss_val) else "PARTIAL",
            })
        with cache_lock: cache["mitre_cve"] = items
        log.info(f"[mitre_cve] ✅ {len(items)} items (MITRE CVE List)")
        return items
    except Exception as e:
        log.error(f"[mitre_cve] Failed: {e}")
        return []


def fetch_vulncheck_nvd() -> list:
    """
    VulnCheck NVD++ — reliable, high-performance NVD replacement.
    Publishes CVEs 24–72h BEFORE NIST NVD enriches them.
    Includes exploit intel, VulnCheck CPE, ransomware campaign flags.
    Requires free API key: https://vulncheck.com/community
    """
    if not VULNCHECK_API_KEY:
        log.debug("[vulncheck_nvd] No API key set — skipping (set VULNCHECK_API_KEY env var)")
        return []
    with cache_lock:
        if "vulncheck_nvd" in cache: return cache["vulncheck_nvd"]
    try:
        since = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%d")  # nist-nvd2 needs YYYY-MM-DD
        resp = requests.get(
            "https://api.vulncheck.com/v3/index/nist-nvd2",
            params={"pubStartDate": since, "resultsPerPage": 100},
            headers={
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Authorization": f"Bearer {VULNCHECK_API_KEY}",
            },
            cookies={"token": VULNCHECK_API_KEY},
            timeout=20
        )
        resp.raise_for_status()
        items = []
        for vuln in (resp.json().get("data") or [])[:100]:
            cve_id = vuln.get("id","")
            if not cve_id: continue

            # Parse descriptions
            descs  = vuln.get("descriptions",[])
            desc   = next((d.get("value","") for d in descs if d.get("lang","").startswith("en")),"")
            title  = f"{cve_id}" + (f" — {desc[:120]}" if desc else "")

            # Parse CVSS (VulnCheck NVD++ has v3.1 + v4.0)
            cvss_val = None; severity = "Unknown"
            for metric_key in ["cvssMetricV31","cvssMetricV40","cvssMetricV30"]:
                metrics = vuln.get("metrics",{}).get(metric_key,[])
                if metrics:
                    score = metrics[0].get("cvssData",{}).get("baseScore")
                    if score:
                        cvss_val = float(score)
                        sev = metrics[0].get("cvssData",{}).get("baseSeverity","")
                        severity = sev.capitalize() if sev else parse_severity(desc)
                        break

            published = vuln.get("published","") or datetime.now(timezone.utc).isoformat()
            if not is_within_window(published): continue

            # VulnCheck-specific exploit intelligence fields
            xdb_entries  = vuln.get("vulncheck_xdb",[])          # exploit PoC repos
            reported_exp = vuln.get("vulncheck_reported_exploitation",[])  # confirmed exploitation
            kev_data     = vuln.get("vulncheck_kev",{})
            ransomware   = kev_data.get("knownRansomwareCampaignUse","Unknown")
            is_exploited = bool(reported_exp) or bool(xdb_entries)
            exploit_refs = [x.get("xdb_url","") for x in xdb_entries[:3]]

            # CPE affected products from vcVulnerableCPEs (VulnCheck enriched)
            cpes = vuln.get("vcVulnerableCPEs",[]) or vuln.get("configurations",[])
            products = list({c.split(":")[4] for c in cpes if isinstance(c,str) and c.startswith("cpe:")})[:5]

            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            combined = f"{title} {desc}"

            items.append({
                "id":            cve_id,
                "title":         title[:300],
                "summary":       desc[:600],
                "description":   desc,
                "link":          link,
                "url":           link,
                "published":     published,
                "severity":      severity or parse_severity(combined),
                "cvss":          cvss_val,
                "cve":           cve_id,
                "cves":          [cve_id],
                "zeroDay":       is_exploited or is_zero_day(combined),
                "source":        "vulncheck_nvd",
                "vendor":        "VulnCheck NVD++",
                "products":      products,
                "author":        "",
                "tags":          (["ransomware"] if ransomware=="Known" else []) + (["exploit-available"] if xdb_entries else []),
                "isOEM":         True,   # Treated as authoritative
                "isNews":        False,
                "fetched_at":    datetime.now(timezone.utc).isoformat(),
                "patch_status":  _infer_patch_status(combined),
                "kev_due_date":  kev_data.get("dueDate",""),
                "required_action": kev_data.get("requiredAction",""),
                "kev_notes":     f"Ransomware: {ransomware}" + (f" | Exploits: {len(xdb_entries)}" if xdb_entries else ""),
                "exploit_refs":  exploit_refs,
                "data_quality":  "RICH" if (desc and cvss_val) else "PARTIAL",
            })

        with cache_lock: cache["vulncheck_nvd"] = items
        log.info(f"[vulncheck_nvd] ✅ {len(items)} items (VulnCheck NVD++)")
        return items
    except Exception as e:
        msg = str(e)
        if "402" in msg or "Payment" in msg:
            log.warning("[vulncheck_nvd] 402 Payment Required — free API key needed: https://vulncheck.com/community")
        elif "400" in msg:
            log.warning(f"[vulncheck_nvd] 400 Bad Request — check API params: {e}")
        else:
            log.error(f"[vulncheck_nvd] Failed: {e}")
        return []


def fetch_vulncheck_kev() -> list:
    """
    VulnCheck KEV — superset of CISA KEV with exploit intelligence.
    Includes: known ransomware campaigns, exploit PoC links, exploitation reports.
    All items are confirmed exploited in the wild.
    Requires same free API key as vulncheck_nvd.
    """
    if not VULNCHECK_API_KEY:
        log.debug("[vulncheck_kev] No API key set — skipping")
        return []
    with cache_lock:
        if "vulncheck_kev" in cache: return cache["vulncheck_kev"]
    try:
        resp = requests.get(
            "https://api.vulncheck.com/v3/index/vulncheck-kev",
            params={"limit": 100},
            headers={
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Authorization": f"Bearer {VULNCHECK_API_KEY}",
            },
            cookies={"token": VULNCHECK_API_KEY},
            timeout=20
        )
        resp.raise_for_status()
        items = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for v in (resp.json().get("data") or [])[:100]:
            cve_ids = v.get("cve",[])
            cve_id  = cve_ids[0] if cve_ids else ""
            if not cve_id: continue
            title      = f"{cve_id} — {v.get('vulnerabilityName','')}"
            summary    = (f"{v.get('shortDescription','')} | Vendor: {v.get('vendorProject','')} | "
                         f"Product: {v.get('product','')} | Action: {v.get('required_action','')}")
            published  = v.get("dateAdded", now_iso)
            if not is_within_window(published): continue

            ransomware = v.get("knownRansomwareCampaignUse","Unknown")
            xdb        = v.get("vulncheck_xdb",[])
            reported   = v.get("vulncheck_reported_exploitation",[])
            due_date   = v.get("dueDate","")

            items.append({
                "id":            cve_id,
                "title":         title[:300],
                "summary":       summary[:600],
                "description":   summary,
                "link":          f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "url":           f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published":     published,
                "severity":      "Critical",
                "cvss":          None,
                "cve":           cve_id,
                "cves":          cve_ids,
                "zeroDay":       True,
                "source":        "vulncheck_kev",
                "vendor":        "VulnCheck KEV",
                "products":      [v.get("product","")],
                "author":        "",
                "tags":          ["KEV","vulncheck"] + (["ransomware"] if ransomware=="Known" else []),
                "isOEM":         True,
                "isNews":        False,
                "fetched_at":    now_iso,
                "patch_status":  "available" if v.get("required_action","") else "unknown",
                "kev_due_date":  due_date,
                "required_action": v.get("required_action",""),
                "kev_notes":     (f"Ransomware: {ransomware}" +
                                  (f" | {len(xdb)} exploit PoC(s)" if xdb else "") +
                                  (f" | {len(reported)} exploitation report(s)" if reported else "")),
                "exploit_refs":  [x.get("xdb_url","") for x in xdb[:3]],
                "data_quality":  "RICH",
            })

        with cache_lock: cache["vulncheck_kev"] = items
        log.info(f"[vulncheck_kev] ✅ {len(items)} items (VulnCheck KEV)")
        return items
    except Exception as e:
        msg = str(e)
        if "402" in msg or "Payment" in msg:
            log.warning("[vulncheck_kev] 402 Payment Required — free API key needed: https://vulncheck.com/community")
        elif "400" in msg:
            log.warning(f"[vulncheck_kev] 400 Bad Request — check API params: {msg}")
        else:
            log.error(f"[vulncheck_kev] Failed: {e}")
        return []


def enrich_with_vulncheck(advisories: list) -> list:
    """
    Backfill enrichment: for CVEs already in the feed that are missing CVSS,
    exploit data, or ransomware flags — query VulnCheck to fill the gaps.
    Runs after EPSS enrichment. Batches CVEs that need enrichment only.
    """
    if not VULNCHECK_API_KEY:
        return advisories

    # Only enrich CVEs that are missing CVSS or have Unknown severity
    needs_enrichment = [
        a for a in advisories
        if (a.get("cve") or "").startswith("CVE-")
        and (not a.get("cvss") or a.get("severity") == "Unknown")
        and a.get("source") not in ("vulncheck_nvd","vulncheck_kev")
    ]
    if not needs_enrichment:
        return advisories

    # Limit to top 50 by severity priority to stay within rate limits
    needs_enrichment = needs_enrichment[:50]
    vc_map = {}

    for a in needs_enrichment:
        cve_id = a["cve"]
        try:
            r = requests.get(
                f"https://api.vulncheck.com/v3/index/nist-nvd2",
                params={"cve": cve_id},
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                    "Authorization": f"Bearer {VULNCHECK_API_KEY}",
                },
                cookies={"token": VULNCHECK_API_KEY},
                timeout=8
            )
            if r.status_code == 200:
                data = (r.json().get("data") or [{}])[0]
                cvss_val = None; severity = None
                for mk in ["cvssMetricV31","cvssMetricV40","cvssMetricV30"]:
                    metrics = data.get("metrics",{}).get(mk,[])
                    if metrics:
                        score = metrics[0].get("cvssData",{}).get("baseScore")
                        if score:
                            cvss_val = float(score)
                            sev = metrics[0].get("cvssData",{}).get("baseSeverity","")
                            severity = sev.capitalize() if sev else None
                            break
                vc_map[cve_id] = {
                    "cvss": cvss_val,
                    "severity": severity,
                    "xdb": data.get("vulncheck_xdb",[]),
                    "reported": data.get("vulncheck_reported_exploitation",[]),
                    "ransomware": data.get("vulncheck_kev",{}).get("knownRansomwareCampaignUse",""),
                }
        except Exception as e:
            log.debug(f"[VulnCheck enrich] {cve_id}: {e}")
            continue

    # Apply enrichment
    enriched_count = 0
    for a in advisories:
        cve = a.get("cve","")
        if cve in vc_map:
            vc = vc_map[cve]
            if vc["cvss"] and not a.get("cvss"):
                a["cvss"] = vc["cvss"]
                enriched_count += 1
            if vc["severity"] and a.get("severity") == "Unknown":
                a["severity"] = vc["severity"]
            if vc["xdb"] and not a.get("zeroDay"):
                a["zeroDay"] = True
                a["kev_notes"] = (a.get("kev_notes","") + f" | {len(vc['xdb'])} exploit PoC(s)").strip(" |")
            if vc["ransomware"] == "Known":
                a["tags"] = list(set((a.get("tags") or []) + ["ransomware"]))
                a["kev_notes"] = (a.get("kev_notes","") + " | Ransomware campaign known").strip(" |")

    if enriched_count:
        log.info(f"[VulnCheck enrich] Backfilled {enriched_count} CVEs with CVSS/exploit data")
    return advisories


def fetch_all_advisories() -> list:
    results = []; futures = {}
    with ThreadPoolExecutor(max_workers=25) as executor:
        for key, url in TRUSTED_FEEDS.items():
            if key == "cisa_kev":        futures[executor.submit(fetch_cisa_kev)] = key
            elif key == "ghsa":           futures[executor.submit(fetch_ghsa)] = key
            elif key == "osv":            futures[executor.submit(fetch_osv)] = key
            elif key == "mitre_cve":      futures[executor.submit(fetch_mitre_cve)] = key
            elif key == "vulncheck_nvd":  futures[executor.submit(fetch_vulncheck_nvd)] = key
            elif key == "vulncheck_kev":  futures[executor.submit(fetch_vulncheck_kev)] = key
            else:                         futures[executor.submit(fetch_rss, key, url)] = key
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

    results = dedupe_and_enrich(results)
    # Enrich with EPSS scores (non-blocking — best effort)
    try:
        results = enrich_with_epss(results)
    except Exception as e:
        log.warning(f"[EPSS] Enrichment failed (non-fatal): {e}")
    # NVD enrichment: fill CVSS + CWE gaps for remaining Unknown-severity CVEs
    try:
        results = enrich_missing_cvss_from_nvd(results)
    except Exception as e:
        log.warning(f"[NVD-ENRICH] Failed (non-fatal): {e}")
    # Enrich with VulnCheck — backfill missing CVSS + exploit intel
    try:
        results = enrich_with_vulncheck(results)
    except Exception as e:
        log.warning(f"[VulnCheck] Enrichment failed (non-fatal): {e}")
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

@app.route("/saved-searches", methods=["GET"])
@require_auth
def get_saved_searches():
    owner = request.args.get("owner","")
    return jsonify({"searches": supa_load_saved_searches(owner)})

@app.route("/saved-searches", methods=["POST"])
@require_auth
def create_saved_search():
    data = request.get_json() or {}
    ok = supa_save_saved_search(data.get("name","Untitled"),data.get("owner",""),
                                 data.get("filters",{}),data.get("is_shared",False))
    return jsonify({"success":ok})

@app.route("/saved-searches/<int:sid>", methods=["DELETE"])
@require_auth
def delete_saved_search(sid):
    return jsonify({"success":supa_delete_saved_search(sid)})

@app.route("/archive")
@require_auth
def get_archive():
    items = supa_load_archived(
        limit    = int(request.args.get("limit",200)),
        offset   = int(request.args.get("offset",0)),
        severity = request.args.get("severity",""),
        source   = request.args.get("source",""),
        days_back= int(request.args.get("days",365)))
    return jsonify({"total":len(items),"advisories":items,"source":"archive"})

@app.route("/sla-audit")
@require_auth
def get_sla_audit():
    rows = supa_get_sla_audit(int(request.args.get("days",365)))
    return jsonify({"total":len(rows),"breaches":rows})

@app.route("/db-health")
@require_auth
def db_health():
    """Database health check — shows cache state, row counts, oldest/newest items."""
    try:
        stats = {}
        # advisory_cache stats
        r = requests.get(f"{SUPABASE_URL}/rest/v1/advisory_cache?select=id,published,severity,is_kev,is_zero_day&limit=5000",
                        headers={**supa_headers(),"Prefer":"count=exact"}, timeout=10)
        if r.status_code == 200:
            rows = r.json()
            total = int(r.headers.get("Content-Range","0").split("/")[-1]) if "Content-Range" in r.headers else len(rows)
            published_dates = [row.get("published","") for row in rows if row.get("published")]
            published_dates.sort()
            stats["advisory_cache"] = {
                "total_rows": total,
                "oldest_published": published_dates[0] if published_dates else None,
                "newest_published": published_dates[-1] if published_dates else None,
                "kev_count": sum(1 for row in rows if row.get("is_kev")),
                "zero_day_count": sum(1 for row in rows if row.get("is_zero_day")),
                "critical_count": sum(1 for row in rows if row.get("severity") == "Critical"),
            }
        # acknowledgments stats
        r2 = requests.get(f"{SUPABASE_URL}/rest/v1/acknowledgments?select=id,status&limit=1000",
                         headers={**supa_headers(),"Prefer":"count=exact"}, timeout=10)
        if r2.status_code == 200:
            acks = r2.json()
            from collections import Counter
            status_counts = Counter(a.get("status","") for a in acks)
            stats["acknowledgments"] = {"total": len(acks), "by_status": dict(status_counts)}
        return jsonify({"success": True, "stats": stats, "timestamp": datetime.now(timezone.utc).isoformat()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/sources")
@require_auth
def sources():
    return jsonify({"total":SOURCE_COUNT,"sources":list(TRUSTED_FEEDS.keys()),"oem_tier1":list(OEM_TIER1)})

@app.route("/advisories")
@require_auth
def advisories():
    try:
        force = request.args.get("force","false").lower() == "true"

        # Always try Supabase cache first — fast response regardless of force flag
        # force=true triggers a background refresh AFTER serving cached data
        if SUPABASE_URL:
            cached = supa_load_advisory_cache()
            if len(cached) > 50:
                log.info(f"[ADVISORIES] Cache hit: {len(cached)} items (force={force})")
                if force:
                    # Trigger background live fetch to refresh cache — non-blocking
                    def _bg_refresh():
                        try:
                            fresh = fetch_all_advisories()
                            if fresh: supa_save_advisory_cache(fresh)
                        except Exception as e:
                            log.error(f"[ADVISORIES] Background refresh failed: {e}")
                    threading.Thread(target=_bg_refresh, daemon=True).start()
                return jsonify({"total":len(cached),"generated":datetime.now(timezone.utc).isoformat(),
                    "advisories":cached[:5000],"source":"cache"})

        # No cache available — live fetch (first ever startup)
        log.info("[ADVISORIES] No cache found — doing live fetch")
        all_adv = fetch_all_advisories()
        if SUPABASE_URL and all_adv:
            def _save_with_retry(adv):
                for attempt in range(3):
                    ok = supa_save_advisory_cache(adv)
                    if ok: return
                    import time as _time; _time.sleep(5 * (attempt+1))
                log.error("[SUPABASE] ⚠️  All 3 save attempts failed — cache may be stale")
            threading.Thread(target=_save_with_retry, args=(all_adv,), daemon=True).start()
        return jsonify({"total":len(all_adv),"generated":datetime.now(timezone.utc).isoformat(),
            "advisories":all_adv[:5000],"source":"live"})
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
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
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

# Cooldown: prevent same CVEs being alerted more than once per 2 hours
_notified_cves: dict = {}
NOTIFY_COOLDOWN_SECONDS = 7200  # 2 hours

@app.route("/notify/critical", methods=["POST"])
@require_auth
def notify_critical():
    """
    Instant alert for Critical/Zero-Day advisories.
    Called from frontend when new critical items are detected in a refresh.
    Sends Teams card + email immediately.
    """
    data = request.get_json() or {}
    advisories = data.get("advisories", [])
    webhook_url = data.get("webhookUrl", "")
    to_email    = data.get("to", "")
    from_email  = data.get("from", "")
    sender_name = data.get("senderName", "Concentrix SOC Dashboard")

    if not advisories:
        return jsonify({"error": "No advisories provided"}), 400

    # Cooldown: skip CVEs already alerted within last 2 hours
    now_ts = datetime.now(timezone.utc).timestamp()
    truly_new = [a for a in advisories
                 if now_ts - _notified_cves.get(a.get("cve") or a.get("id",""), 0)
                 > NOTIFY_COOLDOWN_SECONDS]
    # Update cooldown timestamps for newly alerted CVEs
    for a in truly_new:
        _notified_cves[a.get("cve") or a.get("id","")] = now_ts
    # Purge stale cooldown entries
    stale = [k for k,v in _notified_cves.items() if now_ts-v > NOTIFY_COOLDOWN_SECONDS*2]
    for k in stale: _notified_cves.pop(k, None)

    if not truly_new:
        log.info(f"[NOTIFY] {len(advisories)} items in cooldown — skipping duplicate alert")
        return jsonify({"sent":False,"reason":"cooldown","skipped":len(advisories)}), 200
    advisories = truly_new

    sent = {"teams": False, "email": False}

    # ── Teams instant alert ──────────────────────────────────────────
    if webhook_url:
        try:
            critical  = [a for a in advisories if a.get("severity") == "Critical"]
            zero_days = [a for a in advisories if a.get("zeroDay")]
            top = sorted(advisories, key=lambda a: (
                0 if a.get("zeroDay") else 1,
                0 if a.get("severity") == "Critical" else 1
            ))[:5]

            facts = []
            for a in top:
                label = f"{'🔴 0-DAY ' if a.get('zeroDay') else ''}[{a.get('severity','?')}] {a.get('cve') or a.get('id','')[:40]}"
                facts.append({"title": label, "value": (a.get("title",""))[:80]})

            card = {
                "type": "message",
                "attachments": [{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard", "version": "1.4",
                        "body": [
                            {"type":"TextBlock","size":"Large","weight":"Bolder",
                             "text":f"🚨 INSTANT ALERT — {len(critical)} Critical, {len(zero_days)} Zero-Day",
                             "color":"Attention"},
                            {"type":"TextBlock","text":f"Detected at {datetime.now(timezone.utc).strftime('%d %b %Y %H:%M UTC')}","isSubtle":True,"wrap":True},
                            {"type":"FactSet","facts":facts},
                            {"type":"TextBlock","text":"⚡ Requires immediate attention. Open the dashboard for full details.","wrap":True,"color":"Warning"}
                        ],
                        "actions": [{"type":"Action.OpenUrl","title":"Open Dashboard",
                            "url":"https://ssipankajsingh.github.io/security-advisory-dashboard/"}]
                    }
                }]
            }
            resp = requests.post(webhook_url, json=card, timeout=10)
            sent["teams"] = resp.status_code in (200, 202)
        except Exception as e:
            log.warning(f"[ALERT] Teams failed: {e}")

    # ── Email instant alert ──────────────────────────────────────────
    if to_email and SENDGRID_API_KEY:
        try:
            top5 = sorted(advisories, key=lambda a: (0 if a.get("zeroDay") else 1, 0 if a.get("severity")=="Critical" else 1))[:5]
            rows = "".join(f"""
            <tr>
              <td style="padding:6px 10px;border-bottom:1px solid #f0f0f0">
                <span style="background:{'#dc2626' if a.get('severity')=='Critical' else '#ea580c'};color:#fff;border-radius:3px;padding:1px 6px;font-size:11px;font-weight:700">{a.get('severity','?')}</span>
                {' <span style="background:#7c3aed;color:#fff;border-radius:3px;padding:1px 6px;font-size:11px">0-DAY</span>' if a.get('zeroDay') else ''}
              </td>
              <td style="padding:6px 10px;border-bottom:1px solid #f0f0f0;font-weight:600;color:#1a1a1a">{a.get('cve') or a.get('id','')[:40]}</td>
              <td style="padding:6px 10px;border-bottom:1px solid #f0f0f0;color:#555">{(a.get('title',''))[:70]}</td>
              <td style="padding:6px 10px;border-bottom:1px solid #f0f0f0;color:#888;font-size:12px">{a.get('source','')}</td>
            </tr>""" for a in top5)

            html = f"""<!DOCTYPE html><html><body style="font-family:Inter,sans-serif;background:#f5f5f5;padding:20px">
            <div style="max-width:680px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden">
              <div style="background:#dc2626;padding:20px 24px">
                <h1 style="color:#fff;margin:0;font-size:20px">🚨 Instant Security Alert</h1>
                <p style="color:#fca5a5;margin:6px 0 0;font-size:13px">
                  {len([a for a in advisories if a.get('severity')=='Critical'])} Critical · 
                  {len([a for a in advisories if a.get('zeroDay')])} Zero-Day · 
                  Detected {datetime.now(timezone.utc).strftime('%d %b %Y %H:%M UTC')}
                </p>
              </div>
              <div style="padding:20px 24px">
                <p style="color:#444;font-size:13px;margin:0 0 16px">New critical advisories require your immediate attention:</p>
                <table style="width:100%;border-collapse:collapse;font-size:13px">
                  <thead><tr style="background:#f8f8f8">
                    <th style="padding:8px 10px;text-align:left;color:#888;font-size:11px;text-transform:uppercase">Severity</th>
                    <th style="padding:8px 10px;text-align:left;color:#888;font-size:11px;text-transform:uppercase">CVE</th>
                    <th style="padding:8px 10px;text-align:left;color:#888;font-size:11px;text-transform:uppercase">Title</th>
                    <th style="padding:8px 10px;text-align:left;color:#888;font-size:11px;text-transform:uppercase">Source</th>
                  </tr></thead>
                  <tbody>{rows}</tbody>
                </table>
                <div style="margin-top:20px;text-align:center">
                  <a href="https://ssipankajsingh.github.io/security-advisory-dashboard/" 
                     style="background:#dc2626;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:13px">
                    Open Dashboard →
                  </a>
                </div>
              </div>
              <div style="background:#f8f8f8;padding:12px 24px;text-align:center;font-size:11px;color:#aaa">
                Concentrix GSE · Security Advisory Dashboard · Instant Alert
              </div>
            </div></body></html>"""

            payload = {
                "personalizations": [{"to": [{"email": to_email}]}],
                "from": {"email": from_email or "security-alerts@concentrix.com", "name": sender_name},
                "subject": f"🚨 Instant Alert: {len([a for a in advisories if a.get('severity')=='Critical'])} Critical / {len([a for a in advisories if a.get('zeroDay')])} Zero-Day Advisories",
                "content": [{"type": "text/html", "value": html}]
            }
            resp = requests.post("https://api.sendgrid.com/v3/mail/send",
                headers={"Authorization":f"Bearer {SENDGRID_API_KEY}","Content-Type":"application/json"},
                json=payload, timeout=15)
            sent["email"] = resp.status_code == 202
        except Exception as e:
            log.warning(f"[ALERT] Email failed: {e}")

    return jsonify({"success": True, "sent": sent, "count": len(advisories)})


@app.route("/email-weekly", methods=["POST"])
@require_auth
def email_weekly():
    """
    Send a weekly summary report of top advisories.
    Groups by severity, shows team acknowledgment stats, highlights zero-days.
    """
    data       = request.get_json() or {}
    to_email   = data.get("to","")
    from_email = data.get("from","")
    sender_name= data.get("senderName","Concentrix SOC Dashboard")
    week_start = data.get("weekStart","")  # ISO date string

    if not to_email:
        return jsonify({"error":"No recipient"}), 400

    # Load advisories from cache
    advisories = []
    try:
        advisories = supa_load_advisory_cache()
    except Exception as e:
        log.warning(f"[WEEKLY] Cache load failed: {e}")

    if not advisories:
        return jsonify({"error":"No advisory data available"}), 400

    # Group by severity
    by_sev = {"Critical":[],"High":[],"Medium":[],"Low":[],"Unknown":[]}
    for a in advisories:
        sev = a.get("severity","Unknown")
        if sev in by_sev: by_sev[sev].append(a)

    total     = len(advisories)
    zero_days = [a for a in advisories if a.get("zeroDay")]
    oem_items = [a for a in advisories if a.get("isOEM")]

    def sev_section(sev, items, color):
        if not items: return ""
        top = items[:8]
        rows = "".join(f"""
        <tr>
          <td style="padding:6px 10px;border-bottom:1px solid #f5f5f5;font-weight:600;font-size:12px;color:#1a1a1a">{a.get('cve') or a.get('id','')[:35]}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #f5f5f5;color:#555;font-size:12px">{(a.get('title',''))[:65]}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #f5f5f5;color:#888;font-size:11px">{a.get('source','')[:20]}</td>
          <td style="padding:6px 10px;border-bottom:1px solid #f5f5f5;font-size:11px">
            {'<span style="color:#9333ea;font-weight:700">0-DAY</span>' if a.get('zeroDay') else ''}
            {'<span style="color:#15803d">OEM</span>' if a.get('isOEM') else ''}
          </td>
        </tr>""" for a in top)
        more = f'<tr><td colspan="4" style="padding:6px 10px;color:#aaa;font-size:11px">+{len(items)-8} more {sev} advisories</td></tr>' if len(items)>8 else ""
        return f"""
        <h3 style="color:{color};font-size:14px;margin:20px 0 8px;padding-bottom:4px;border-bottom:2px solid {color}22">
          {sev} ({len(items)})
        </h3>
        <table style="width:100%;border-collapse:collapse">
          <thead><tr style="background:#f8f8f8">
            <th style="padding:6px 10px;text-align:left;font-size:10px;color:#999;text-transform:uppercase">CVE / ID</th>
            <th style="padding:6px 10px;text-align:left;font-size:10px;color:#999;text-transform:uppercase">Title</th>
            <th style="padding:6px 10px;text-align:left;font-size:10px;color:#999;text-transform:uppercase">Source</th>
            <th style="padding:6px 10px;text-align:left;font-size:10px;color:#999;text-transform:uppercase">Flags</th>
          </tr></thead>
          <tbody>{rows}{more}</tbody>
        </table>"""

    week_label = week_start or datetime.now(timezone.utc).strftime("Week of %d %b %Y")
    html = f"""<!DOCTYPE html><html><body style="font-family:Inter,sans-serif;background:#f5f5f5;padding:20px;color:#1a1a1a">
    <div style="max-width:700px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08)">
      <!-- Header -->
      <div style="background:#0a1e50;padding:24px 28px;display:flex;align-items:center;gap:16px">
        <div style="background:#00C9B1;width:48px;height:30px;border-radius:15px;display:flex;align-items:center;justify-content:center">
          <span style="color:#0a1e50;font-weight:800;font-size:14px">C</span>
        </div>
        <div>
          <h1 style="color:#fff;margin:0;font-size:18px;font-weight:700">Weekly Security Advisory Summary</h1>
          <p style="color:#94a3b8;margin:3px 0 0;font-size:12px">{week_label} · Concentrix GSE SOC Intelligence</p>
        </div>
      </div>
      <!-- KPI Strip -->
      <div style="display:flex;border-bottom:1px solid #f0f0f0">
        {''.join(f'<div style="flex:1;padding:14px 10px;text-align:center;border-right:1px solid #f5f5f5"><div style="font-size:22px;font-weight:800;color:{c}">{v}</div><div style="font-size:10px;color:#aaa;font-weight:500;text-transform:uppercase;margin-top:2px">{l}</div></div>'
          for l,v,c in [
            ("Total", total, "#444"),
            ("Critical", len(by_sev["Critical"]), "#dc2626"),
            ("High", len(by_sev["High"]), "#ea580c"),
            ("Zero-Days", len(zero_days), "#9333ea"),
            ("OEM Direct", len(oem_items), "#15803d"),
          ])}
      </div>
      <!-- Sections -->
      <div style="padding:20px 28px">
        {sev_section("Critical", by_sev["Critical"], "#dc2626")}
        {sev_section("High", by_sev["High"], "#ea580c")}
        {sev_section("Medium", by_sev["Medium"], "#ca8a04")}
        {sev_section("Low", by_sev["Low"], "#16a34a")}
        <!-- CTA -->
        <div style="margin-top:24px;padding:16px;background:#f8f8f8;border-radius:8px;text-align:center">
          <a href="https://ssipankajsingh.github.io/security-advisory-dashboard/"
             style="background:#c0392b;color:#fff;padding:10px 28px;border-radius:6px;text-decoration:none;font-weight:600;font-size:13px">
            Open Full Dashboard →
          </a>
        </div>
      </div>
      <div style="background:#f8f8f8;padding:12px 28px;text-align:center;font-size:11px;color:#aaa">
        Concentrix GSE · Security Advisory Intelligence · Auto-generated Weekly Report
      </div>
    </div></body></html>"""

    if not SENDGRID_API_KEY:
        return jsonify({"error":"SendGrid not configured","preview":html[:500]}), 400

    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": from_email or "security-reports@concentrix.com", "name": sender_name},
        "subject": f"📊 Weekly Security Advisory Summary — {week_label} ({total} advisories, {len(by_sev['Critical'])} Critical)",
        "content": [{"type":"text/html","value":html}]
    }
    try:
        resp = requests.post("https://api.sendgrid.com/v3/mail/send",
            headers={"Authorization":f"Bearer {SENDGRID_API_KEY}","Content-Type":"application/json"},
            json=payload, timeout=15)
        if resp.status_code == 202:
            return jsonify({"success":True,"total":total,"critical":len(by_sev["Critical"]),"zero_days":len(zero_days)})
        return jsonify({"error":f"SendGrid HTTP {resp.status_code}","detail":resp.text[:200]}), 500
    except Exception as e:
        return jsonify({"error":str(e)}), 500


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

@app.route("/handover-report", methods=["GET","POST"])
@require_auth
def handover_report_route():
    """On-demand shift handover report. Add ?send=true to also push to Teams."""
    data   = request.get_json() or {}
    window = int(request.args.get("window", data.get("window_hours", 12)))
    report = generate_handover_report(window_hours=window)
    if (request.args.get("send","false").lower()=="true" or data.get("send")) and TEAMS_WEBHOOK:
        send_handover_teams_card(TEAMS_WEBHOOK, report)
    return jsonify({"success":True,"report":report})


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
def generate_handover_report(window_hours: int = 12) -> dict:
    """Generate shift handover report covering last window_hours."""
    try:
        advisories = load_from_supabase() or []
        acks       = supa_get_acks()
        now        = datetime.now(timezone.utc)
        cutoff_iso = (now - timedelta(hours=window_hours)).isoformat()
        SLA_LIMITS = {"Critical":24,"High":72,"Medium":168,"Low":720}

        new_adv   = [a for a in advisories if a.get("fetched_at","")>=cutoff_iso and a["id"] not in acks]
        new_crit  = [a for a in new_adv if a.get("severity")=="Critical" or a.get("zeroDay")]

        sla_overdue = []
        for a in advisories:
            st = acks.get(a["id"],{}).get("status","")
            if st in ("Patched","Accepted Risk","False Positive"): continue
            limit_h = SLA_LIMITS.get(a.get("severity","Medium"), 168)
            try:
                pub = datetime.fromisoformat(a.get("published","").replace("Z","+00:00"))
                if pub.tzinfo is None: pub = pub.replace(tzinfo=timezone.utc)
                age_h = (now - pub).total_seconds()/3600
                if age_h > limit_h:
                    sla_overdue.append({**a,"overdue_h":round(age_h-limit_h)})
            except: pass
        sla_overdue.sort(key=lambda x:x.get("overdue_h",0),reverse=True)

        actioned = {aid:ack for aid,ack in acks.items() if ack.get("at","")>=cutoff_iso}
        patched  = {aid:ack for aid,ack in actioned.items() if ack.get("status") in ("Patched","Accepted Risk","False Positive")}

        team_load = {}
        for aid,ack in acks.items():
            m = ack.get("assigned_to","")
            if m and m!="Unassigned" and ack.get("status") not in ("Patched","Accepted Risk","False Positive"):
                team_load[m] = team_load.get(m,0)+1

        return {"window_hours":window_hours,"generated_at":now.isoformat(),
                "new_total":len(new_adv),"new_critical":len(new_crit),
                "new_critical_items":new_crit[:5],"sla_overdue":len(sla_overdue),
                "sla_overdue_items":sla_overdue[:5],"actioned":len(actioned),
                "patched":len(patched),"team_load":team_load}
    except Exception as e:
        log.error(f"[HANDOVER] {e}"); return {}


def send_handover_teams_card(webhook_url:str, report:dict):
    """Send shift handover Adaptive Card to Teams."""
    if not webhook_url or not report: return
    now_ist  = datetime.now(timezone(timedelta(hours=5,minutes=30)))
    time_str = now_ist.strftime("%d %b %Y, %I:%M %p IST")
    window   = report.get("window_hours",12)
    has_urgency = report.get("new_critical",0)>0 or report.get("sla_overdue",0)>0

    new_facts = [{"name":f"{'🔴 0-DAY' if a.get('zeroDay') else '🟠 CRIT'} — {a.get('source','')}",
                  "value":(a.get("title") or a.get("id",""))[:80]}
                 for a in report.get("new_critical_items",[])]
    overdue_facts = [{"name":f"⏰ {a.get('severity','')} — {(a.get('title') or a.get('id',''))[:55]}",
                      "value":f"Overdue {a.get('overdue_h',0)}h | {a.get('source','')}"}
                     for a in report.get("sla_overdue_items",[])]
    team_facts = [{"name":f"👤 {m}","value":f"{cnt} open"} for m,cnt in report.get("team_load",{}).items()]

    body = [
        {"type":"Container","style":"attention" if has_urgency else "good","items":[{"type":"ColumnSet","columns":[
            {"type":"Column","width":"auto","items":[{"type":"TextBlock","text":"🔄","size":"ExtraLarge"}]},
            {"type":"Column","width":"stretch","items":[
                {"type":"TextBlock","text":"Shift Handover Report","weight":"Bolder","size":"Large",
                 "color":"Attention" if has_urgency else "Good"},
                {"type":"TextBlock","text":f"Concentrix GSE SOC · {time_str}","size":"Small","isSubtle":True,"spacing":"None"},
            ]},
        ]}]},
        {"type":"ColumnSet","columns":[
            {"type":"Column","width":"stretch","items":[{"type":"TextBlock","text":f"**{report.get('new_total',0)}**\nNew ({window}h)","wrap":True,"horizontalAlignment":"Center"}]},
            {"type":"Column","width":"stretch","items":[{"type":"TextBlock","text":f"**{report.get('new_critical',0)}**\nNew Critical","wrap":True,"horizontalAlignment":"Center","color":"Attention" if report.get("new_critical",0) else "Default"}]},
            {"type":"Column","width":"stretch","items":[{"type":"TextBlock","text":f"**{report.get('sla_overdue',0)}**\nSLA Overdue","wrap":True,"horizontalAlignment":"Center","color":"Attention" if report.get("sla_overdue",0) else "Default"}]},
            {"type":"Column","width":"stretch","items":[{"type":"TextBlock","text":f"**{report.get('actioned',0)}**\nActioned","wrap":True,"horizontalAlignment":"Center","color":"Good" if report.get("actioned",0) else "Default"}]},
        ]},
    ]
    if new_facts: body.append({"type":"Container","style":"emphasis","items":[
        {"type":"TextBlock","text":f"🚨 New Critical / Zero-Day (last {window}h)","weight":"Bolder","size":"Medium"},
        {"type":"FactSet","facts":new_facts}]})
    if overdue_facts: body.append({"type":"Container","style":"attention","items":[
        {"type":"TextBlock","text":"⏰ SLA Overdue — Needs Immediate Attention","weight":"Bolder","size":"Medium"},
        {"type":"FactSet","facts":overdue_facts}]})
    if team_facts: body.append({"type":"Container","style":"emphasis","items":[
        {"type":"TextBlock","text":"👥 Team Open Workload","weight":"Bolder","size":"Medium"},
        {"type":"FactSet","facts":team_facts}]})
    body.append({"type":"ActionSet","actions":[{"type":"Action.OpenUrl","title":"🔍 Open Dashboard",
        "url":"https://ssipankajsingh.github.io/security-advisory-dashboard/","style":"positive"}]})

    payload = {"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{
        "$schema":"http://adaptivecards.io/schemas/adaptive-card.json","type":"AdaptiveCard","version":"1.4","body":body}}]}
    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        log.info(f"[HANDOVER] Teams: {r.status_code}")
    except Exception as e: log.error(f"[HANDOVER] Teams failed: {e}")


def _send_handover_email(report:dict):
    """Send handover report as HTML email via SendGrid."""
    try:
        from sendgrid.helpers.mail import Mail
        import sendgrid as sg_module
        now_ist  = datetime.now(timezone(timedelta(hours=5,minutes=30)))
        subject  = f"[GSE SOC] Shift Handover — {now_ist.strftime('%d %b %Y %I:%M %p IST')}"
        window   = report.get("window_hours",12)

        def rows_html(items, fmt):
            return "".join(fmt(a) for a in items)

        crit_rows = rows_html(report.get("new_critical_items",[]),
            lambda a: f"<tr><td style='padding:5px 10px'><b style='color:#dc2626'>{'0-DAY' if a.get('zeroDay') else 'CRIT'}</b></td>"
                      f"<td style='padding:5px 10px;font-size:12px'>{(a.get('title') or a.get('id',''))[:80]}</td>"
                      f"<td style='padding:5px 10px;font-size:11px;color:#888'>{a.get('source','')}</td></tr>")
        over_rows = rows_html(report.get("sla_overdue_items",[]),
            lambda a: f"<tr><td style='padding:5px 10px;font-size:12px'>{(a.get('title') or a.get('id',''))[:70]}</td>"
                      f"<td style='padding:5px 10px;font-size:11px;color:#dc2626;font-weight:600'>{a.get('overdue_h',0)}h overdue</td>"
                      f"<td style='padding:5px 10px;font-size:11px'>{a.get('severity','')}</td></tr>")
        team_rows = rows_html(list(report.get("team_load",{}).items()),
            lambda kv: f"<tr><td style='padding:5px 10px'>{kv[0]}</td><td style='padding:5px 10px;font-weight:600'>{kv[1]}</td></tr>")

        html = f"""<div style='font-family:Arial,sans-serif;max-width:620px;margin:0 auto'>
<div style='background:#0a1e50;padding:18px 20px;border-radius:8px 8px 0 0'>
  <h2 style='color:#fff;margin:0;font-size:17px'>🔄 Shift Handover Report</h2>
  <p style='color:rgba(255,255,255,0.65);margin:4px 0 0;font-size:11px'>Concentrix GSE SOC · {now_ist.strftime('%d %b %Y, %I:%M %p IST')} · Last {window}h</p>
</div>
<table width='100%' style='background:#f8f9fa;border-collapse:collapse'>
  <tr>
    <td align='center' style='padding:14px'><div style='font-size:26px;font-weight:700'>{report.get("new_total",0)}</div><div style='font-size:10px;color:#888'>New</div></td>
    <td align='center' style='padding:14px'><div style='font-size:26px;font-weight:700;color:#dc2626'>{report.get("new_critical",0)}</div><div style='font-size:10px;color:#888'>New Critical</div></td>
    <td align='center' style='padding:14px'><div style='font-size:26px;font-weight:700;color:#dc2626'>{report.get("sla_overdue",0)}</div><div style='font-size:10px;color:#888'>SLA Overdue</div></td>
    <td align='center' style='padding:14px'><div style='font-size:26px;font-weight:700;color:#16a34a'>{report.get("actioned",0)}</div><div style='font-size:10px;color:#888'>Actioned</div></td>
  </tr>
</table>
{"<h3 style='padding:10px 16px 4px;margin:0;font-size:13px'>🚨 New Critical / Zero-Day</h3><table width='100%'>"+crit_rows+"</table>" if crit_rows else ""}
{"<h3 style='padding:10px 16px 4px;margin:0;font-size:13px'>⏰ SLA Overdue</h3><table width='100%'>"+over_rows+"</table>" if over_rows else ""}
{"<h3 style='padding:10px 16px 4px;margin:0;font-size:13px'>👥 Team Workload</h3><table width='100%'>"+team_rows+"</table>" if team_rows else ""}
<div style='padding:16px;text-align:center;border-top:1px solid #e5e5e5'>
  <a href='https://ssipankajsingh.github.io/security-advisory-dashboard/' style='background:#c0392b;color:#fff;padding:9px 22px;border-radius:5px;text-decoration:none;font-size:13px;font-weight:600'>Open Dashboard →</a>
</div></div>"""

        client = sg_module.SendGridAPIClient(api_key=SENDGRID_API_KEY)
        msg = Mail(from_email=SENDER_EMAIL or "soc@concentrix.com",
                   to_emails=DIGEST_EMAIL, subject=subject, html_content=html)
        client.send(msg)
        log.info("[HANDOVER] Email sent")
    except Exception as e: log.error(f"[HANDOVER] Email: {e}")


def scheduled_morning():
    """
    08:00 IST — Single combined morning email:
    Daily Digest (new advisories) + Handover Report (SLA status, team workload).
    Replaces separate scheduled_email + scheduled_handover at 08:00.
    """
    if not (SENDGRID_API_KEY and DIGEST_EMAIL): return
    log.info("[CRON] Running combined morning digest + handover...")
    try:
        # Get handover report data
        report = generate_handover_report(window_hours=12)
        now_ist = datetime.now(timezone(timedelta(hours=5, minutes=30)))
        date_str = now_ist.strftime("%A, %d %B %Y")
        window = report.get("window_hours", 12)

        # Fetch advisories for digest section
        advisories = load_from_supabase() or []
        critical  = [a for a in advisories if a.get("severity") == "Critical"]
        high      = [a for a in advisories if a.get("severity") == "High"]
        zero_days = [a for a in advisories if a.get("zeroDay")]
        top5 = sorted(
            [a for a in advisories if a.get("severity") in ("Critical","High") or a.get("zeroDay")],
            key=lambda a: (0 if a.get("zeroDay") else 1, 0 if a.get("severity")=="Critical" else 1)
        )[:6]

        # Build top advisories rows
        top_rows = "".join(f"""<tr>
          <td style='padding:6px 10px;border-bottom:1px solid #f5f5f5'>
            <span style='background:{"#7c3aed" if a.get("zeroDay") else "#dc2626" if a.get("severity")=="Critical" else "#ea580c"};color:#fff;border-radius:3px;padding:1px 6px;font-size:11px;font-weight:700'>
              {"0-DAY" if a.get("zeroDay") else a.get("severity","?")}
            </span>
          </td>
          <td style='padding:6px 10px;border-bottom:1px solid #f5f5f5;font-weight:600;font-size:12px'>{a.get("cve") or a.get("id","")[:40]}</td>
          <td style='padding:6px 10px;border-bottom:1px solid #f5f5f5;color:#555;font-size:12px'>{(a.get("title",""))[:65]}</td>
          <td style='padding:6px 10px;border-bottom:1px solid #f5f5f5;color:#888;font-size:11px'>{a.get("source","")}</td>
        </tr>""" for a in top5)

        # Build SLA overdue rows
        overdue_rows = "".join(f"""<tr>
          <td style='padding:5px 10px;border-bottom:1px solid #f5f5f5;font-size:12px'>{(a.get("title") or a.get("id",""))[:60]}</td>
          <td style='padding:5px 10px;border-bottom:1px solid #f5f5f5;font-size:11px;color:#dc2626;font-weight:600'>{a.get("overdue_h",0)}h overdue</td>
          <td style='padding:5px 10px;border-bottom:1px solid #f5f5f5;font-size:11px'>{a.get("severity","")}</td>
        </tr>""" for a in report.get("sla_overdue_items",[]))

        # Build team workload rows
        team_rows = "".join(f"""<tr>
          <td style='padding:5px 10px;font-size:12px'>👤 {m}</td>
          <td style='padding:5px 10px;font-size:12px;font-weight:600'>{cnt} open</td>
        </tr>""" for m, cnt in report.get("team_load",{}).items())

        has_urgent = report.get("sla_overdue",0) > 0 or report.get("new_critical",0) > 0
        subject = (f"🚨 [URGENT] {len(zero_days)} Zero-Day(s) — Security Advisory Digest {now_ist.strftime('%d/%m/%Y')}"
                   if zero_days else
                   f"🔴 Security Advisory Digest — {len(critical)} Critical · {date_str}")

        html = f"""<!DOCTYPE html><html><body style='font-family:Inter,Arial,sans-serif;background:#f5f5f5;padding:20px;margin:0'>
<div style='max-width:680px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08)'>

  <!-- Header -->
  <div style='background:linear-gradient(135deg,#0a1e50,#1a3a7a);padding:22px 28px'>
    <h1 style='color:#fff;margin:0;font-size:20px'>🛡 Security Advisory Daily Digest</h1>
    <p style='color:rgba(255,255,255,0.7);margin:5px 0 0;font-size:13px'>Concentrix Endpoint Security — {date_str}</p>
  </div>

  <!-- Today's Stats -->
  <table width='100%' style='border-collapse:collapse;background:#f8f9fa'>
    <tr>
      <td align='center' style='padding:16px 8px'><div style='font-size:28px;font-weight:700'>{len(advisories)}</div><div style='font-size:11px;color:#888;margin-top:2px'>Total</div></td>
      <td align='center' style='padding:16px 8px'><div style='font-size:28px;font-weight:700;color:#dc2626'>{len(critical)}</div><div style='font-size:11px;color:#888;margin-top:2px'>Critical</div></td>
      <td align='center' style='padding:16px 8px'><div style='font-size:28px;font-weight:700;color:#ea580c'>{len(high)}</div><div style='font-size:11px;color:#888;margin-top:2px'>High</div></td>
      <td align='center' style='padding:16px 8px'><div style='font-size:28px;font-weight:700;color:#7c3aed'>{len(zero_days)}</div><div style='font-size:11px;color:#888;margin-top:2px'>Zero-Days</div></td>
      <td align='center' style='padding:16px 8px'><div style='font-size:28px;font-weight:700;{"color:#dc2626" if report.get("sla_overdue",0) else "color:#16a34a"}'>{report.get("sla_overdue",0)}</div><div style='font-size:11px;color:#888;margin-top:2px'>SLA Overdue</div></td>
    </tr>
  </table>

  <!-- Last 12h Activity -->
  <div style='padding:16px 24px 8px;border-top:1px solid #f0f0f0'>
    <h3 style='font-size:13px;margin:0 0 8px;color:#444'>📊 Last {window}h Activity</h3>
    <table width='100%' style='border-collapse:collapse;font-size:12px'>
      <tr><td style='padding:3px 0;color:#888'>New advisories</td><td style='padding:3px 0;font-weight:600'>{report.get("new_total",0)}</td>
          <td style='padding:3px 0;color:#888'>New Critical/0-Day</td><td style='padding:3px 0;font-weight:600;color:#dc2626'>{report.get("new_critical",0)}</td></tr>
      <tr><td style='padding:3px 0;color:#888'>Actioned by team</td><td style='padding:3px 0;font-weight:600;color:#16a34a'>{report.get("actioned",0)}</td>
          <td style='padding:3px 0;color:#888'>Patched/Closed</td><td style='padding:3px 0;font-weight:600;color:#16a34a'>{report.get("patched",0)}</td></tr>
    </table>
  </div>

  {"<!-- Top Advisories --><div style='padding:8px 24px 12px'><h3 style='font-size:13px;margin:0 0 8px;color:#444'>🔴 Top Critical / Zero-Day</h3><table width=100% style=border-collapse:collapse><thead><tr style=background:#f8f8f8><th style=padding:7px 10px;text-align:left;color:#888;font-size:11px>Sev</th><th style=padding:7px 10px;text-align:left;color:#888;font-size:11px>CVE</th><th style=padding:7px 10px;text-align:left;color:#888;font-size:11px>Title</th><th style=padding:7px 10px;text-align:left;color:#888;font-size:11px>Source</th></tr></thead><tbody>" + top_rows + "</tbody></table></div>" if top_rows else ""}

  {"<!-- SLA Overdue --><div style='padding:8px 24px 12px;background:#fff8f8'><h3 style='font-size:13px;margin:0 0 8px;color:#dc2626'>⏰ SLA Overdue — Immediate Action Required</h3><table width=100% style=border-collapse:collapse>" + overdue_rows + "</table></div>" if overdue_rows else ""}

  {"<!-- Team Workload --><div style='padding:8px 24px 12px'><h3 style='font-size:13px;margin:0 0 8px;color:#444'>👥 Team Open Workload</h3><table width=100%>" + team_rows + "</table></div>" if team_rows else ""}

  <!-- CTA -->
  <div style='padding:20px 24px;text-align:center;border-top:1px solid #f0f0f0'>
    <a href='https://ssipankajsingh.github.io/security-advisory-dashboard/' style='background:#c0392b;color:#fff;padding:11px 28px;border-radius:6px;text-decoration:none;font-weight:600;font-size:13px'>Open Dashboard →</a>
  </div>
  <div style='background:#f8f8f8;padding:10px 24px;text-align:center;font-size:11px;color:#aaa'>
    Concentrix GSE · Security Advisory Platform · {now_ist.strftime("%d %b %Y %I:%M %p IST")}
  </div>
</div></body></html>"""

        import sendgrid as sg_module
        client = sg_module.SendGridAPIClient(api_key=SENDGRID_API_KEY)
        msg = Mail(from_email=SENDER_EMAIL or "soc@concentrix.com",
                   to_emails=DIGEST_EMAIL, subject=subject, html_content=html)
        client.send(msg)
        log.info(f"[CRON] Morning digest sent: {len(advisories)} total, {len(critical)} critical, {report.get('sla_overdue',0)} overdue")
    except Exception as e:
        log.error(f"[CRON] Morning digest: {e}")


def scheduled_handover():
    """20:00 IST — Evening handover only (Teams card + email)."""
    log.info("[CRON] Running evening handover report...")
    try:
        report = generate_handover_report(window_hours=12)
        if TEAMS_WEBHOOK: send_handover_teams_card(TEAMS_WEBHOOK, report)
        if SENDGRID_API_KEY and DIGEST_EMAIL: _send_handover_email(report)
        log.info(f"[CRON] Evening handover done: {report.get('new_total',0)} new, {report.get('sla_overdue',0)} overdue")
    except Exception as e: log.error(f"[CRON] Evening handover: {e}")


def scheduled_email():
    """Kept for backward compatibility — now calls scheduled_morning."""
    scheduled_morning()

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

# ─── FETCH-NOW ENDPOINT (for cron-job.org external trigger) ──────────────────
_fetch_in_progress = threading.Event()

def _background_fetch_and_cache():
    """Run a full feed fetch and save to Supabase. Called from /fetch-now."""
    if _fetch_in_progress.is_set():
        log.info("[FETCH-NOW] Already in progress — skipping duplicate trigger")
        return
    _fetch_in_progress.set()
    try:
        log.info("[FETCH-NOW] Starting background fetch triggered by cron-job.org")
        advisories = fetch_all_advisories()
        if SUPABASE_URL and advisories:
            supa_save_advisory_cache(advisories)
            log.info(f"[FETCH-NOW] ✅ Fetched {len(advisories)} advisories and saved to cache")
        else:
            log.warning("[FETCH-NOW] No advisories fetched or Supabase not configured")
    except Exception as e:
        log.error(f"[FETCH-NOW] ❌ Error: {e}")
    finally:
        _fetch_in_progress.clear()

@app.route("/fetch-now", methods=["GET","POST"])
def fetch_now():
    """
    External cron trigger endpoint. Call this from cron-job.org every 30 minutes.
    Requires CRON_SECRET env var to match ?secret= query param or X-Cron-Secret header.
    If CRON_SECRET is not set, endpoint is disabled.

    cron-job.org setup:
      URL: https://security-advisory-proxy.onrender.com/fetch-now?secret=YOUR_SECRET
      Schedule: Every 30 minutes
      Method: GET
    """
    if not CRON_SECRET:
        return jsonify({"error": "CRON_SECRET not configured — endpoint disabled"}), 403

    # Accept secret via query param or header
    provided = (request.args.get("secret","") or
                request.headers.get("X-Cron-Secret","") or
                (request.json or {}).get("secret",""))

    if provided != CRON_SECRET:
        log.warning(f"[FETCH-NOW] Unauthorized attempt from {request.remote_addr}")
        return jsonify({"error": "Unauthorized"}), 401

    # Fire-and-forget in background thread — return immediately so cron-job.org doesn't time out
    t = threading.Thread(target=_background_fetch_and_cache, daemon=True)
    t.start()

    return jsonify({
        "status": "accepted",
        "message": "Background fetch started",
        "in_progress": _fetch_in_progress.is_set()
    }), 202


scheduler = BackgroundScheduler(timezone="UTC")
# ── Email schedule (IST) ────────────────────────────────────────────────────
# 08:00 IST → 1 combined email: Daily Digest + Morning Handover (merged)
# 08:05 IST → Teams notification
# 20:00 IST → Evening Handover (Teams + email)
scheduler.add_job(scheduled_morning,      "cron", hour=2,  minute=30)   # 08:00 IST — combined digest+handover
scheduler.add_job(scheduled_teams,        "cron", hour=2,  minute=35)   # 08:05 IST — Teams morning card
scheduler.add_job(scheduled_patch_tuesday,"cron", hour=3,  minute=0)    # 08:30 IST — Patch Tuesday check
scheduler.add_job(supa_purge_old_acks,    "cron", hour=0,  minute=0)    # 00:00 UTC — purge old acks
scheduler.add_job(supa_save_archived,     "cron", hour=1,  minute=0)    # 01:00 UTC — nightly archive + purge
scheduler.add_job(scheduled_handover,     "cron", hour=14, minute=30)   # 20:00 IST — evening handover
# cron-job.org is primary fetch trigger — internal disabled to prevent double alerts:
# scheduler.add_job(_background_fetch_and_cache, "interval", minutes=30, id="background_fetch")
scheduler.start()

if __name__ == "__main__":
    log.info(f"✅ Proxy listening on port {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
