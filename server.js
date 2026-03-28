/**
 * Security Advisory RSS Proxy Server — v2 (Fixed URLs)
 * Fetches vendor RSS/Atom feeds server-side, bypassing browser CORS.
 * Includes per-feed caching, error resilience, and XML/Atom/JSON support.
 */

const express   = require("express");
const cors      = require("cors");
const axios     = require("axios");
const xml2js    = require("xml2js");
const NodeCache = require("node-cache");

const app   = express();
const cache = new NodeCache({ stdTTL: 3600 }); // 1-hour cache
const PORT  = process.env.PORT || 3001;

// ─── CORS ────────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  "https://ssipankajsingh.github.io",
  "http://localhost:3000",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
];
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.some(o => origin.startsWith(o))) cb(null, true);
    else cb(new Error("CORS blocked: " + origin));
  }
}));
app.use(express.json());

// ─── TRUSTED FEED REGISTRY (verified working URLs) ───────────────────────────
const TRUSTED_FEEDS = {

  // ── GOVERNMENT ──────────────────────────────────────────────────────────────
  cisa_alerts:    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
  ncsc_uk:        "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",

  // ── CVE DATABASES ───────────────────────────────────────────────────────────
  exploit_db:     "https://www.exploit-db.com/rss.xml",
  zdi_published:  "https://www.zerodayinitiative.com/rss/published/",
  zdi_upcoming:   "https://www.zerodayinitiative.com/rss/upcoming/",

  // ── OS & PLATFORM ───────────────────────────────────────────────────────────
  // MSRC — correct API endpoint (blog/feed was returning malformed XML)
  msrc:           "https://api.msrc.microsoft.com/update-guide/rss",
  msrc_blog:      "https://msrc.microsoft.com/blog/rss/",
  ubuntu:         "https://ubuntu.com/security/notices/rss.xml",
  redhat:         "https://access.redhat.com/hydra/rest/securitydata/cve.json?after=2024-01-01&severity=critical&limit=20",
  android:        "https://source.android.com/docs/security/bulletin/feed.xml",

  // ── NETWORK & FIREWALL ──────────────────────────────────────────────────────
  // Cisco — tools.cisco.com blocks external servers; using sec.cloudapps mirror
  cisco:          "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
  fortinet:       "https://www.fortiguard.com/rss/ir.xml",
  paloalto:       "https://security.paloaltonetworks.com/rss.xml",
  sonicwall:      "https://psirt.global.sonicwall.com/vuln-list/rss",
  ivanti:         "https://forums.ivanti.com/servlet/JiveServlet/download/8399-3-18160/IvantiSecurityAdvisories.rss",

  // ── ENDPOINT SECURITY ───────────────────────────────────────────────────────
  crowdstrike:    "https://www.crowdstrike.com/blog/feed/",
  sentinelone:    "https://www.sentinelone.com/labs/feed/",
  sophos:         "https://news.sophos.com/en-us/category/threat-research/feed/",
  malwarebytes:   "https://www.malwarebytes.com/blog/feed/",

  // ── CLOUD ───────────────────────────────────────────────────────────────────
  aws:            "https://aws.amazon.com/security/security-bulletins/feed/",
  gcp:            "https://cloud.google.com/feeds/cloud-security-bulletins.xml",
  chrome:         "https://chromereleases.googleblog.com/feeds/posts/default",
  project_zero:   "https://googleprojectzero.blogspot.com/feeds/posts/default",

  // ── BROWSER / MIDDLEWARE ────────────────────────────────────────────────────
  // Mozilla — no official RSS; using CVE JSON feed instead
  mozilla:        "https://www.mozilla.org/en-US/security/advisories/cve-feed.json",
  openssl:        "https://www.openssl.org/news/openssl-security.rss",
  apache:         "https://httpd.apache.org/security/vulnerabilities-httpd.xml",
  oracle:         "https://www.oracle.com/security-alerts/rss.xml",

  // ── THREAT INTELLIGENCE ─────────────────────────────────────────────────────
  mandiant:       "https://www.mandiant.com/resources/blog/rss.xml",
  talos:          "https://blog.talosintelligence.com/feeds/posts/default",
  unit42:         "https://unit42.paloaltonetworks.com/feed/",
  msft_ti:        "https://www.microsoft.com/en-us/security/blog/feed/",
  krebs:          "https://krebsonsecurity.com/feed/",
  bleeping:       "https://www.bleepingcomputer.com/feed/",
  hackernews:     "https://feeds.feedburner.com/TheHackersNews",
  secweek:        "https://feeds.feedburner.com/securityweek",
  darkread:       "https://www.darkreading.com/rss/vulnerabilities-threats.xml",
};

// ─── HELPERS ─────────────────────────────────────────────────────────────────
const parser = new xml2js.Parser({
  explicitArray: false,
  ignoreAttrs:   false,
  strict:        false,   // tolerate malformed XML
  trim:          true,
});

function parseSeverity(text = "") {
  const t = text.toLowerCase();
  if (t.match(/critical|cvss[:\s]+([89]\.|10)/i)) return "Critical";
  if (t.match(/\bhigh\b|cvss[:\s]+[78]\./i))       return "High";
  if (t.match(/medium|moderate|cvss[:\s]+[456]\./i)) return "Medium";
  if (t.match(/\blow\b|cvss[:\s]+[123]\./i))        return "Low";
  return "Unknown";
}

function parseCVSS(text = "") {
  const m = text.match(/cvss[v23 ]*[:\s]+([0-9]{1,2}\.[0-9])/i) ||
            text.match(/score[:\s]+([0-9]{1,2}\.[0-9])/i);
  return m ? parseFloat(m[1]) : null;
}

function isZeroDay(text = "") {
  return /zero.?day|0-day|actively exploit|in the wild|emergency patch|out.of.band/i.test(text);
}

function safeText(val) {
  if (!val) return "";
  if (typeof val === "string") return val.replace(/<[^>]+>/g, "").replace(/&[a-z]+;/gi, " ").trim();
  if (val._) return safeText(val._);
  return String(val).replace(/<[^>]+>/g, "").trim();
}

function safeLink(val) {
  if (!val) return "";
  if (typeof val === "string") return val.trim();
  if (val.$?.href) return val.$.href;
  if (val._) return val._.trim();
  if (Array.isArray(val)) return safeLink(val[0]);
  return "";
}

function parseDate(val) {
  if (!val) return new Date().toISOString().split("T")[0];
  const d = new Date(safeText(val));
  return isNaN(d.getTime()) ? new Date().toISOString().split("T")[0] : d.toISOString().split("T")[0];
}

function normalizeItems(sourceId, items = [], vendorName = "") {
  if (!Array.isArray(items)) items = [items];
  return items.slice(0, 25).map((item, i) => {
    const title   = safeText(item.title);
    const summary = safeText(item.description || item.summary || item["content:encoded"] || item.content || "");
    const link    = safeLink(item.link || item.url || "");
    const date    = parseDate(item.pubDate || item.updated || item.published || item.date);
    const combined = `${title} ${summary}`;

    return {
      id:       safeText(item.guid || item.id) || `${sourceId}-${Date.now()}-${i}`,
      vendor:   vendorName || sourceId,
      title:    title || "(No title)",
      summary:  summary.slice(0, 400),
      url:      link,
      date,
      severity: parseSeverity(combined),
      cvss:     parseCVSS(combined),
      zeroDay:  isZeroDay(combined),
      isNew:    false,
      source:   sourceId,
    };
  });
}

// Handle Mozilla's JSON advisory feed (no RSS available)
function parseMozillaJSON(data) {
  try {
    const advisories = data.advisories || [];
    return advisories.slice(0, 25).map((a, i) => ({
      id:       a.mfsa_id || `mozilla-${i}`,
      vendor:   "Mozilla",
      title:    a.title || "(No title)",
      summary:  (a.description || "").slice(0, 400),
      url:      `https://www.mozilla.org/en-US/security/advisories/mfsa${a.mfsa_id}/`,
      date:     a.announced ? new Date(a.announced).toISOString().split("T")[0] : new Date().toISOString().split("T")[0],
      severity: parseSeverity((a.impact || "") + " " + (a.description || "")),
      cvss:     null,
      zeroDay:  isZeroDay(a.description || ""),
      isNew:    false,
      source:   "mozilla",
    }));
  } catch { return []; }
}

// Handle Red Hat's JSON CVE feed
function parseRedHatJSON(data) {
  try {
    if (!Array.isArray(data)) return [];
    return data.slice(0, 25).map((cve, i) => ({
      id:       cve.CVE || `redhat-${i}`,
      vendor:   "Red Hat",
      title:    cve.bugzilla_description || cve.CVE || "(No title)",
      summary:  (cve.bugzilla_description || "").slice(0, 400),
      url:      `https://access.redhat.com/security/cve/${cve.CVE}`,
      date:     cve.public_date ? cve.public_date.split("T")[0] : new Date().toISOString().split("T")[0],
      severity: parseSeverity(cve.severity || ""),
      cvss:     cve.cvss3_score ? parseFloat(cve.cvss3_score) : (cve.cvss_score ? parseFloat(cve.cvss_score) : null),
      zeroDay:  false,
      isNew:    false,
      source:   "redhat",
    }));
  } catch { return []; }
}

const VENDOR_NAMES = {
  msrc: "Microsoft", msrc_blog: "Microsoft", ubuntu: "Ubuntu",
  redhat: "Red Hat", android: "Google", cisco: "Cisco",
  fortinet: "Fortinet", paloalto: "Palo Alto", sonicwall: "SonicWall",
  ivanti: "Ivanti", crowdstrike: "CrowdStrike", sentinelone: "SentinelOne",
  sophos: "Sophos", malwarebytes: "Malwarebytes", aws: "AWS", gcp: "Google Cloud",
  chrome: "Google", project_zero: "Google", mozilla: "Mozilla",
  openssl: "OpenSSL", apache: "Apache", oracle: "Oracle", mandiant: "Mandiant",
  talos: "Cisco Talos", unit42: "Palo Alto", msft_ti: "Microsoft",
  krebs: "KrebsOnSecurity", bleeping: "BleepingComputer",
  hackernews: "The Hacker News", secweek: "SecurityWeek",
  darkread: "Dark Reading", cisa_alerts: "CISA", ncsc_uk: "NCSC UK",
  exploit_db: "Exploit-DB", zdi_published: "ZDI", zdi_upcoming: "ZDI",
};

async function fetchFeed(sourceId, url) {
  const cached = cache.get(sourceId);
  if (cached) return cached;

  const res = await axios.get(url, {
    timeout: 15000,
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; SecurityAdvisoryBot/2.0; +https://ssipankajsingh.github.io/security-advisory-dashboard/)",
      "Accept": "application/rss+xml, application/atom+xml, application/xml, application/json, text/xml, */*",
      "Accept-Encoding": "gzip, deflate",
    },
    maxRedirects: 5,
  });

  const contentType = res.headers["content-type"] || "";
  let normalized = [];

  // JSON feeds (Mozilla, Red Hat)
  if (contentType.includes("json") || url.endsWith(".json")) {
    if (sourceId === "mozilla")      normalized = parseMozillaJSON(res.data);
    else if (sourceId === "redhat")  normalized = parseRedHatJSON(res.data);
  } else {
    // XML / RSS / Atom
    const raw = await parser.parseStringPromise(
      typeof res.data === "string" ? res.data : String(res.data)
    );

    let items = raw?.rss?.channel?.item       // RSS 2.0
             || raw?.feed?.entry              // Atom
             || raw?.["rdf:RDF"]?.item        // RSS 1.0
             || raw?.channel?.item;

    normalized = normalizeItems(sourceId, items || [], VENDOR_NAMES[sourceId] || sourceId);
  }

  cache.set(sourceId, normalized);
  return normalized;
}

// ─── ROUTES ──────────────────────────────────────────────────────────────────

app.get("/", (req, res) => res.json({
  name: "Security Advisory Proxy",
  version: "2.0",
  feeds: Object.keys(TRUSTED_FEEDS).length,
  endpoints: ["/health", "/sources", "/feed/:sourceId", "/feeds/all"],
}));

app.get("/health", (req, res) => res.json({
  status:  "ok",
  sources: Object.keys(TRUSTED_FEEDS).length,
  cached:  cache.keys().length,
  uptime:  Math.round(process.uptime()) + "s",
  time:    new Date().toISOString(),
}));

app.get("/sources", (req, res) => res.json(
  Object.keys(TRUSTED_FEEDS).map(id => ({
    id,
    vendor: VENDOR_NAMES[id] || id,
    url:    TRUSTED_FEEDS[id],
    cached: cache.has(id),
  }))
));

app.get("/feed/:sourceId", async (req, res) => {
  const { sourceId } = req.params;
  const url = TRUSTED_FEEDS[sourceId];
  if (!url) return res.status(404).json({ error: "Unknown source: " + sourceId });
  try {
    const items = await fetchFeed(sourceId, url);
    res.json({ sourceId, vendor: VENDOR_NAMES[sourceId] || sourceId, count: items.length, items });
  } catch (err) {
    console.error(`[${sourceId}] Error:`, err.message);
    res.status(502).json({ error: "Failed to fetch feed", detail: err.message, sourceId });
  }
});

app.post("/feeds/all", async (req, res) => {
  const { sources = Object.keys(TRUSTED_FEEDS) } = req.body;
  const enabled = sources.filter(id => TRUSTED_FEEDS[id]);
  const results = [];
  const errors  = [];

  await Promise.allSettled(
    enabled.map(async (id) => {
      try {
        const items = await fetchFeed(id, TRUSTED_FEEDS[id]);
        results.push(...items);
      } catch (err) {
        console.error(`[${id}] Failed:`, err.message);
        errors.push({ id, error: err.message });
      }
    })
  );

  // Deduplicate by title
  const seen = new Set();
  const deduped = results.filter(item => {
    const key = item.title.toLowerCase().slice(0, 80);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort: date desc, then severity
  const sevOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };
  deduped.sort((a, b) => {
    const dd = new Date(b.date) - new Date(a.date);
    return dd !== 0 ? dd : (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4);
  });

  res.json({
    fetched:   enabled.length,
    succeeded: enabled.length - errors.length,
    failed:    errors.length,
    errors,
    total:     deduped.length,
    timestamp: new Date().toISOString(),
    items:     deduped,
  });
});

app.post("/cache/clear", (req, res) => {
  cache.flushAll();
  res.json({ cleared: true, time: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`\n🛡️  Security Advisory Proxy v2 running on port ${PORT}`);
  console.log(`   Sources : ${Object.keys(TRUSTED_FEEDS).length} configured`);
  console.log(`   Health  : http://localhost:${PORT}/health\n`);
});
