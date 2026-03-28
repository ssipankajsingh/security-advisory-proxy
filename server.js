/**
 * Security Advisory RSS Proxy Server
 * Fetches vendor RSS/Atom feeds server-side and serves them to the dashboard.
 * Bypasses browser CORS restrictions. Includes in-memory caching.
 *
 * Deploy free on: Render.com | Railway.app | Fly.io | any Node.js host
 */

const express  = require("express");
const cors     = require("cors");
const axios    = require("axios");
const xml2js   = require("xml2js");
const NodeCache = require("node-cache");

const app   = express();
const cache = new NodeCache({ stdTTL: 3600 }); // 1-hour cache per feed
const PORT  = process.env.PORT || 3001;

// ─── CORS: allow your GitHub Pages dashboard ────────────────────────────────
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

// ─── TRUSTED SOURCE REGISTRY ────────────────────────────────────────────────
// Only feeds explicitly listed here will be proxied (security: no open proxy)
const TRUSTED_FEEDS = {
  // Government
  cisa_alerts:   "https://www.cisa.gov/cybersecurity-advisories/all.xml",
  ncsc_uk:       "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
  us_cert:       "https://www.cisa.gov/sites/default/files/feeds/bulletins.xml",

  // CVE Databases
  exploit_db:    "https://www.exploit-db.com/rss.xml",
  zdi_published: "https://www.zerodayinitiative.com/rss/published/",
  zdi_upcoming:  "https://www.zerodayinitiative.com/rss/upcoming/",

  // OS & Platform
  msrc:          "https://msrc.microsoft.com/blog/feed",
  apple:         "https://support.apple.com/en-us/security-updates/rss",
  ubuntu:        "https://ubuntu.com/security/notices/rss.xml",
  android:       "https://source.android.com/docs/security/bulletin/feed.xml",
  redhat:        "https://access.redhat.com/blogs/feed",

  // Network
  cisco:         "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
  fortinet:      "https://www.fortiguard.com/rss/ir.xml",
  paloalto:      "https://security.paloaltonetworks.com/rss.xml",

  // Endpoint / Threat Intel
  crowdstrike:   "https://www.crowdstrike.com/blog/feed",
  sentinelone:   "https://www.sentinelone.com/labs/feed/",
  sophos:        "https://news.sophos.com/en-us/feed/",
  mandiant:      "https://www.mandiant.com/resources/blog/rss.xml",
  talos:         "https://blog.talosintelligence.com/feeds/posts/default",
  unit42:        "https://unit42.paloaltonetworks.com/feed/",
  msft_ti:       "https://www.microsoft.com/en-us/security/blog/feed/",

  // Cloud
  aws:           "https://aws.amazon.com/security/security-bulletins/feed/",
  gcp:           "https://cloud.google.com/feeds/cloud-security-bulletins.xml",
  chrome:        "https://chromereleases.googleblog.com/feeds/posts/default",
  project_zero:  "https://googleprojectzero.blogspot.com/feeds/posts/default",

  // Browser/Middleware
  mozilla:       "https://www.mozilla.org/en-US/security/advisories/feed/",
  openssl:       "https://www.openssl.org/news/secadv/secadv.rss",
  apache:        "https://apache.org/security/advisories.rss",
  oracle:        "https://www.oracle.com/security-alerts/rss.xml",

  // News
  krebs:         "https://krebsonsecurity.com/feed/",
  bleeping:      "https://www.bleepingcomputer.com/feed/",
  hackernews:    "https://feeds.feedburner.com/TheHackersNews",
  proofpoint:    "https://www.proofpoint.com/us/rss.xml",
};

// ─── HELPERS ─────────────────────────────────────────────────────────────────

const parser = new xml2js.Parser({ explicitArray: false, ignoreAttrs: false });

function parseSeverity(text = "") {
  const t = text.toLowerCase();
  if (t.includes("critical"))                             return "Critical";
  if (t.includes("high"))                                 return "High";
  if (t.includes("medium") || t.includes("moderate"))    return "Medium";
  if (t.includes("low"))                                  return "Low";
  return "Unknown";
}

function parseCVSS(text = "") {
  const m = text.match(/cvss[:\s]+([0-9.]+)/i) || text.match(/([0-9]\.[0-9])/);
  return m ? parseFloat(m[1]) : null;
}

function isZeroDay(text = "") {
  return /zero.?day|0-day|actively exploit|in the wild|emergency patch/i.test(text);
}

function safeText(val) {
  if (!val) return "";
  if (typeof val === "string") return val.replace(/<[^>]+>/g, "").trim();
  if (val._) return val._.replace(/<[^>]+>/g, "").trim();
  return String(val).replace(/<[^>]+>/g, "").trim();
}

function parseDate(val) {
  if (!val) return new Date().toISOString().split("T")[0];
  const d = new Date(safeText(val));
  return isNaN(d) ? new Date().toISOString().split("T")[0] : d.toISOString().split("T")[0];
}

function normalizeItems(sourceId, items = []) {
  if (!Array.isArray(items)) items = [items];
  return items.slice(0, 20).map((item, i) => {
    const title   = safeText(item.title);
    const summary = safeText(item.description || item.summary || item["content:encoded"] || "");
    const link    = safeText(item.link || (item.link && item.link._) || "");
    const date    = parseDate(item.pubDate || item.updated || item.published);
    const combined = title + " " + summary;

    return {
      id:       item.guid ? safeText(item.guid) : `${sourceId}-${Date.now()}-${i}`,
      vendor:   sourceId,
      title,
      summary:  summary.slice(0, 300),
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

async function fetchFeed(sourceId, url) {
  const cached = cache.get(sourceId);
  if (cached) return cached;

  const res = await axios.get(url, {
    timeout: 10000,
    headers: {
      "User-Agent": "SecurityAdvisoryDashboard/1.0 (SOC RSS Aggregator)",
      "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml",
    },
  });

  const raw = await parser.parseStringPromise(res.data);

  // Handle RSS 2.0
  let items = raw?.rss?.channel?.item;
  // Handle Atom
  if (!items) items = raw?.feed?.entry;
  // Handle RDF
  if (!items) items = raw?.["rdf:RDF"]?.item;

  const normalized = normalizeItems(sourceId, items || []);
  cache.set(sourceId, normalized);
  return normalized;
}

// ─── ROUTES ──────────────────────────────────────────────────────────────────

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    sources: Object.keys(TRUSTED_FEEDS).length,
    cached:  cache.keys().length,
    uptime:  Math.round(process.uptime()) + "s",
    time:    new Date().toISOString(),
  });
});

// List available sources
app.get("/sources", (req, res) => {
  res.json(Object.keys(TRUSTED_FEEDS).map(id => ({
    id,
    url:    TRUSTED_FEEDS[id],
    cached: cache.has(id),
  })));
});

// Fetch a single source
app.get("/feed/:sourceId", async (req, res) => {
  const { sourceId } = req.params;
  const url = TRUSTED_FEEDS[sourceId];
  if (!url) return res.status(404).json({ error: "Unknown source: " + sourceId });
  try {
    const items = await fetchFeed(sourceId, url);
    res.json({ sourceId, count: items.length, items });
  } catch (err) {
    console.error(`[${sourceId}] Error:`, err.message);
    res.status(502).json({ error: "Failed to fetch feed", detail: err.message });
  }
});

// Fetch ALL enabled sources (called by dashboard on refresh)
app.post("/feeds/all", async (req, res) => {
  const { sources = Object.keys(TRUSTED_FEEDS) } = req.body;
  const enabled = sources.filter(id => TRUSTED_FEEDS[id]);
  const results = [];

  await Promise.allSettled(
    enabled.map(async (id) => {
      try {
        const items = await fetchFeed(id, TRUSTED_FEEDS[id]);
        results.push(...items);
      } catch (err) {
        console.error(`[${id}] Failed:`, err.message);
      }
    })
  );

  // Deduplicate by title similarity
  const seen = new Set();
  const deduped = results.filter(item => {
    const key = item.title.toLowerCase().slice(0, 60);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Sort by date descending, then severity
  const sevOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };
  deduped.sort((a, b) => {
    const dateDiff = new Date(b.date) - new Date(a.date);
    if (dateDiff !== 0) return dateDiff;
    return (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4);
  });

  res.json({
    fetched:   enabled.length,
    total:     deduped.length,
    timestamp: new Date().toISOString(),
    items:     deduped,
  });
});

// Force clear cache (useful after proxy restart or manual trigger)
app.post("/cache/clear", (req, res) => {
  cache.flushAll();
  res.json({ cleared: true });
});

// ─── START ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡️  Security Advisory Proxy running on port ${PORT}`);
  console.log(`   Sources: ${Object.keys(TRUSTED_FEEDS).length} configured`);
  console.log(`   Health:  http://localhost:${PORT}/health\n`);
});
