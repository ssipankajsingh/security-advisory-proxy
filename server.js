/**
 * Security Advisory RSS Proxy Server — v3
 * Added: Email Digest via SendGrid (scheduled + manual)
 */

const express    = require("express");
const cors       = require("cors");
const axios      = require("axios");
const xml2js     = require("xml2js");
const NodeCache  = require("node-cache");
const cron       = require("node-cron");
const sgMail     = require("@sendgrid/mail");

const app   = express();
const cache = new NodeCache({ stdTTL: 3600 });
const PORT  = process.env.PORT || 3001;

// ─── SENDGRID CONFIG (set these in Render environment variables) ─────────────
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || "";
if (SENDGRID_API_KEY) sgMail.setApiKey(SENDGRID_API_KEY);

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

// ─── TRUSTED FEED REGISTRY ───────────────────────────────────────────────────
const TRUSTED_FEEDS = {
  cisa_alerts:   "https://www.cisa.gov/cybersecurity-advisories/all.xml",
  ncsc_uk:       "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
  exploit_db:    "https://www.exploit-db.com/rss.xml",
  zdi_published: "https://www.zerodayinitiative.com/rss/published/",
  zdi_upcoming:  "https://www.zerodayinitiative.com/rss/upcoming/",
  msrc:          "https://api.msrc.microsoft.com/update-guide/rss",
  msrc_blog:     "https://msrc.microsoft.com/blog/rss/",
  ubuntu:        "https://ubuntu.com/security/notices/rss.xml",
  redhat:        "https://access.redhat.com/hydra/rest/securitydata/cve.json?after=2024-01-01&severity=critical&limit=20",
  android:       "https://source.android.com/docs/security/bulletin/feed.xml",
  cisco:         "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
  fortinet:      "https://www.fortiguard.com/rss/ir.xml",
  paloalto:      "https://security.paloaltonetworks.com/rss.xml",
  sonicwall:     "https://psirt.global.sonicwall.com/vuln-list/rss",
  ivanti:        "https://forums.ivanti.com/servlet/JiveServlet/download/8399-3-18160/IvantiSecurityAdvisories.rss",
  crowdstrike:   "https://www.crowdstrike.com/blog/feed/",
  sentinelone:   "https://www.sentinelone.com/labs/feed/",
  sophos:        "https://news.sophos.com/en-us/category/threat-research/feed/",
  malwarebytes:  "https://www.malwarebytes.com/blog/feed/",
  aws:           "https://aws.amazon.com/security/security-bulletins/feed/",
  gcp:           "https://cloud.google.com/feeds/cloud-security-bulletins.xml",
  chrome:        "https://chromereleases.googleblog.com/feeds/posts/default",
  project_zero:  "https://googleprojectzero.blogspot.com/feeds/posts/default",
  mozilla:       "https://www.mozilla.org/en-US/security/advisories/cve-feed.json",
  openssl:       "https://www.openssl.org/news/openssl-security.rss",
  apache:        "https://httpd.apache.org/security/vulnerabilities-httpd.xml",
  oracle:        "https://www.oracle.com/security-alerts/rss.xml",
  mandiant:      "https://www.mandiant.com/resources/blog/rss.xml",
  talos:         "https://blog.talosintelligence.com/feeds/posts/default",
  unit42:        "https://unit42.paloaltonetworks.com/feed/",
  msft_ti:       "https://www.microsoft.com/en-us/security/blog/feed/",
  krebs:         "https://krebsonsecurity.com/feed/",
  bleeping:      "https://www.bleepingcomputer.com/feed/",
  hackernews:    "https://feeds.feedburner.com/TheHackersNews",
  secweek:       "https://feeds.feedburner.com/securityweek",
  darkread:      "https://www.darkreading.com/rss/vulnerabilities-threats.xml",
};

const VENDOR_NAMES = {
  msrc:"Microsoft", msrc_blog:"Microsoft", ubuntu:"Ubuntu", redhat:"Red Hat",
  android:"Google", cisco:"Cisco", fortinet:"Fortinet", paloalto:"Palo Alto",
  sonicwall:"SonicWall", ivanti:"Ivanti", crowdstrike:"CrowdStrike",
  sentinelone:"SentinelOne", sophos:"Sophos", malwarebytes:"Malwarebytes",
  aws:"AWS", gcp:"Google Cloud", chrome:"Google", project_zero:"Google",
  mozilla:"Mozilla", openssl:"OpenSSL", apache:"Apache", oracle:"Oracle",
  mandiant:"Mandiant", talos:"Cisco Talos", unit42:"Palo Alto", msft_ti:"Microsoft",
  krebs:"KrebsOnSecurity", bleeping:"BleepingComputer", hackernews:"The Hacker News",
  secweek:"SecurityWeek", darkread:"Dark Reading", cisa_alerts:"CISA",
  ncsc_uk:"NCSC UK", exploit_db:"Exploit-DB", zdi_published:"ZDI", zdi_upcoming:"ZDI",
};

// ─── FEED PARSING HELPERS ────────────────────────────────────────────────────
const parser = new xml2js.Parser({ explicitArray:false, ignoreAttrs:false, strict:false, trim:true });

function parseSeverity(t=""){
  if(t.match(/critical|cvss[:\s]+([89]\.|10)/i)) return "Critical";
  if(t.match(/\bhigh\b|cvss[:\s]+[78]\./i))      return "High";
  if(t.match(/medium|moderate/i))                 return "Medium";
  if(t.match(/\blow\b/i))                         return "Low";
  return "Unknown";
}
function parseCVSS(t=""){const m=t.match(/cvss[v23 ]*[:\s]+([0-9]{1,2}\.[0-9])/i);return m?parseFloat(m[1]):null;}
function isZeroDay(t=""){return /zero.?day|0-day|actively exploit|in the wild|emergency patch/i.test(t);}
function safeText(v){if(!v)return "";if(typeof v==="string")return v.replace(/<[^>]+>/g,"").replace(/&[a-z]+;/gi," ").trim();if(v._)return safeText(v._);return String(v).replace(/<[^>]+>/g,"").trim();}
function safeLink(v){if(!v)return "";if(typeof v==="string")return v.trim();if(v.$?.href)return v.$.href;if(v._)return v._.trim();if(Array.isArray(v))return safeLink(v[0]);return "";}
function parseDate(v){if(!v)return new Date().toISOString().split("T")[0];const d=new Date(safeText(v));return isNaN(d.getTime())?new Date().toISOString().split("T")[0]:d.toISOString().split("T")[0];}

function normalizeItems(sourceId, items=[], vendorName=""){
  if(!Array.isArray(items)) items=[items];
  return items.slice(0,25).map((item,i)=>{
    const title=safeText(item.title);
    const summary=safeText(item.description||item.summary||item["content:encoded"]||item.content||"");
    const link=safeLink(item.link||item.url||"");
    const date=parseDate(item.pubDate||item.updated||item.published||item.date);
    const combined=`${title} ${summary}`;
    return {
      id:safeText(item.guid||item.id)||`${sourceId}-${Date.now()}-${i}`,
      vendor:vendorName||sourceId, title:title||"(No title)",
      summary:summary.slice(0,400), url:link, date,
      severity:parseSeverity(combined), cvss:parseCVSS(combined),
      zeroDay:isZeroDay(combined), isNew:false, source:sourceId,
    };
  });
}

function parseMozillaJSON(data){
  try{
    return(data.advisories||[]).slice(0,25).map((a,i)=>({
      id:a.mfsa_id||`mozilla-${i}`, vendor:"Mozilla", title:a.title||"(No title)",
      summary:(a.description||"").slice(0,400),
      url:`https://www.mozilla.org/en-US/security/advisories/mfsa${a.mfsa_id}/`,
      date:a.announced?new Date(a.announced).toISOString().split("T")[0]:new Date().toISOString().split("T")[0],
      severity:parseSeverity((a.impact||"")+" "+(a.description||"")),
      cvss:null, zeroDay:isZeroDay(a.description||""), isNew:false, source:"mozilla",
    }));
  }catch{return [];}
}

function parseRedHatJSON(data){
  try{
    if(!Array.isArray(data))return[];
    return data.slice(0,25).map((cve,i)=>({
      id:cve.CVE||`redhat-${i}`, vendor:"Red Hat",
      title:cve.bugzilla_description||cve.CVE||"(No title)",
      summary:(cve.bugzilla_description||"").slice(0,400),
      url:`https://access.redhat.com/security/cve/${cve.CVE}`,
      date:cve.public_date?cve.public_date.split("T")[0]:new Date().toISOString().split("T")[0],
      severity:parseSeverity(cve.severity||""),
      cvss:cve.cvss3_score?parseFloat(cve.cvss3_score):null,
      zeroDay:false, isNew:false, source:"redhat",
    }));
  }catch{return [];}
}

async function fetchFeed(sourceId, url){
  const cached=cache.get(sourceId);
  if(cached)return cached;
  const res=await axios.get(url,{
    timeout:15000,
    headers:{
      "User-Agent":"Mozilla/5.0 (compatible; SecurityAdvisoryBot/2.0)",
      "Accept":"application/rss+xml, application/atom+xml, application/xml, application/json, text/xml, */*",
    },
    maxRedirects:5,
  });
  const ct=res.headers["content-type"]||"";
  let normalized=[];
  if(ct.includes("json")||url.endsWith(".json")){
    if(sourceId==="mozilla")     normalized=parseMozillaJSON(res.data);
    else if(sourceId==="redhat") normalized=parseRedHatJSON(res.data);
  } else {
    const raw=await parser.parseStringPromise(typeof res.data==="string"?res.data:String(res.data));
    const items=raw?.rss?.channel?.item||raw?.feed?.entry||raw?.["rdf:RDF"]?.item||raw?.channel?.item;
    normalized=normalizeItems(sourceId, items||[], VENDOR_NAMES[sourceId]||sourceId);
  }
  cache.set(sourceId, normalized);
  return normalized;
}

async function fetchAllFeeds(){
  const results=[];
  await Promise.allSettled(
    Object.keys(TRUSTED_FEEDS).map(async id=>{
      try{const items=await fetchFeed(id,TRUSTED_FEEDS[id]);results.push(...items);}
      catch(err){console.error(`[${id}] Failed:`,err.message);}
    })
  );
  const seen=new Set();
  const deduped=results.filter(item=>{
    const key=item.title.toLowerCase().slice(0,80);
    if(seen.has(key))return false;
    seen.add(key);return true;
  });
  const sevOrder={Critical:0,High:1,Medium:2,Low:3,Unknown:4};
  deduped.sort((a,b)=>{
    const dd=new Date(b.date)-new Date(a.date);
    return dd!==0?dd:(sevOrder[a.severity]??4)-(sevOrder[b.severity]??4);
  });
  return deduped;
}

// ─── EMAIL HTML TEMPLATE (no AI required) ───────────────────────────────────
function buildEmailHTML(advisories, date){
  const critical  = advisories.filter(a=>a.severity==="Critical");
  const zeroDays  = advisories.filter(a=>a.zeroDay);
  const high      = advisories.filter(a=>a.severity==="High"&&!a.zeroDay);
  const medium    = advisories.filter(a=>a.severity==="Medium");
  const sevColor  = {Critical:"#dc2626",High:"#ea580c",Medium:"#ca8a04",Low:"#16a34a",Unknown:"#6b7280"};

  // Top critical + zero-day advisories table
  const topAdvisories = advisories
    .filter(a=>a.severity==="Critical"||a.zeroDay)
    .slice(0,20);

  const advisoryRows = topAdvisories.map(a=>`
    <tr style="border-bottom:1px solid #e5e7eb;">
      <td style="padding:10px 8px;white-space:nowrap;">
        ${a.zeroDay?`<span style="background:#7c3aed;color:#fff;border-radius:3px;padding:1px 6px;font-size:10px;font-weight:700;margin-right:4px;">0-DAY</span>`:""}
        <span style="background:${sevColor[a.severity]||"#6b7280"};color:#fff;border-radius:3px;padding:1px 6px;font-size:10px;font-weight:700;">${a.severity}</span>
      </td>
      <td style="padding:10px 8px;">
        <div style="font-weight:600;font-size:12px;color:#111827;">${a.id}</div>
        <div style="font-size:11px;color:#6b7280;">${a.vendor} · ${a.date}${a.cvss?` · CVSS ${a.cvss}`:""}</div>
      </td>
      <td style="padding:10px 8px;font-size:12px;color:#374151;">${a.title}</td>
      <td style="padding:10px 8px;font-size:12px;color:#6b7280;max-width:200px;">${a.summary.slice(0,120)}...</td>
      <td style="padding:10px 8px;text-align:center;white-space:nowrap;">
        ${a.url?`<a href="${a.url}" style="color:#2563eb;font-size:12px;text-decoration:none;font-weight:600;">View →</a>`:""}
      </td>
    </tr>`).join("");

  // High severity section
  const highRows = high.slice(0,10).map(a=>`
    <tr style="border-bottom:1px solid #e5e7eb;">
      <td style="padding:8px;">
        <span style="background:#ea580c;color:#fff;border-radius:3px;padding:1px 6px;font-size:10px;font-weight:700;">HIGH</span>
      </td>
      <td style="padding:8px;font-size:12px;font-weight:600;color:#111827;">${a.id}</td>
      <td style="padding:8px;font-size:12px;color:#374151;">${a.title}</td>
      <td style="padding:8px;font-size:11px;color:#6b7280;">${a.vendor} · ${a.date}</td>
      <td style="padding:8px;text-align:center;">${a.url?`<a href="${a.url}" style="color:#2563eb;font-size:12px;">View →</a>`:""}</td>
    </tr>`).join("");

  // Key recommendations based on top threats (rule-based, no AI)
  const recommendations = [];
  if(zeroDays.length>0) recommendations.push(`🚨 <strong>${zeroDays.length} zero-day vulnerability${zeroDays.length>1?"ies":""} detected</strong> — apply emergency patches immediately and check for signs of exploitation.`);
  if(critical.some(a=>a.vendor==="Microsoft")) recommendations.push(`🔵 <strong>Microsoft patches available</strong> — prioritise Windows/Azure/Entra ID updates via WSUS/Intune.`);
  if(critical.some(a=>a.vendor==="Cisco"||a.vendor==="Fortinet"||a.vendor==="Palo Alto")) recommendations.push(`🔴 <strong>Network infrastructure advisories</strong> — review firewall/VPN/router patches with network team before deployment.`);
  if(critical.some(a=>a.vendor==="CrowdStrike"||a.vendor==="SentinelOne")) recommendations.push(`🛡️ <strong>Endpoint security updates</strong> — verify EDR agents are on latest version across all endpoints.`);
  if(critical.some(a=>["AWS","Google Cloud","Azure","Okta"].includes(a.vendor))) recommendations.push(`☁️ <strong>Cloud/identity advisories</strong> — review cloud security settings and IAM configurations.`);
  if(recommendations.length===0) recommendations.push(`✅ No critical zero-day threats today — continue routine patch management cycle.`);

  return `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Security Advisory Digest — ${date}</title></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:24px 0;">
<tr><td align="center">
<table width="680" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.12);">

  <!-- HEADER -->
  <tr><td style="background:linear-gradient(135deg,#1e3a5f 0%,#1e40af 100%);padding:24px 32px;">
    <table width="100%"><tr>
      <td>
        <div style="font-size:22px;font-weight:700;color:#ffffff;">🛡️ Security Advisory Digest</div>
        <div style="font-size:13px;color:#93c5fd;margin-top:4px;">${date} · Concentrix Endpoint Security</div>
        <div style="font-size:11px;color:#60a5fa;margin-top:2px;">Auto-generated from ${Object.keys(TRUSTED_FEEDS).length} trusted sources</div>
      </td>
      <td align="right" style="vertical-align:top;">
        ${critical.length>0?`<div style="background:#dc2626;color:#fff;border-radius:6px;padding:6px 14px;font-size:13px;font-weight:700;display:inline-block;margin-bottom:4px;">${critical.length} Critical</div><br>`:""}
        ${zeroDays.length>0?`<div style="background:#7c3aed;color:#fff;border-radius:6px;padding:6px 14px;font-size:13px;font-weight:700;display:inline-block;">${zeroDays.length} Zero-Day</div>`:""}
      </td>
    </tr></table>
  </td></tr>

  <!-- STATS BAR -->
  <tr><td style="background:#1e3a5f;padding:14px 32px;">
    <table width="100%"><tr>
      ${[["Critical",critical.length,"#fca5a5"],["Zero-Days",zeroDays.length,"#c4b5fd"],["High",high.length,"#fdba74"],["Medium",medium.length,"#fde68a"],["Total",advisories.length,"#93c5fd"]].map(([l,v,c])=>`
      <td align="center" style="color:${c};">
        <div style="font-size:24px;font-weight:700;">${v}</div>
        <div style="font-size:11px;opacity:.8;margin-top:2px;">${l}</div>
      </td>`).join("")}
    </tr></table>
  </td></tr>

  <!-- RECOMMENDED ACTIONS -->
  <tr><td style="padding:24px 32px;border-bottom:1px solid #e5e7eb;">
    <div style="font-size:11px;font-weight:700;color:#6b7280;letter-spacing:1px;text-transform:uppercase;margin-bottom:12px;">✅ Recommended Actions</div>
    <div style="background:#f0fdf4;border-left:3px solid #16a34a;padding:14px 16px;border-radius:0 6px 6px 0;">
      ${recommendations.map(r=>`<div style="font-size:13px;color:#374151;line-height:1.7;margin-bottom:6px;">${r}</div>`).join("")}
    </div>
  </td></tr>

  <!-- CRITICAL & ZERO-DAY TABLE -->
  ${topAdvisories.length>0?`
  <tr><td style="padding:24px 32px;border-bottom:1px solid #e5e7eb;">
    <div style="font-size:11px;font-weight:700;color:#6b7280;letter-spacing:1px;text-transform:uppercase;margin-bottom:12px;">
      ⚠️ Critical & Zero-Day Advisories (${topAdvisories.length})
    </div>
    <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:6px;overflow:hidden;font-size:13px;">
      <thead><tr style="background:#fef2f2;">
        <th style="padding:8px;font-size:11px;color:#dc2626;text-align:left;font-weight:700;">SEVERITY</th>
        <th style="padding:8px;font-size:11px;color:#6b7280;text-align:left;font-weight:600;">ID</th>
        <th style="padding:8px;font-size:11px;color:#6b7280;text-align:left;font-weight:600;">TITLE</th>
        <th style="padding:8px;font-size:11px;color:#6b7280;text-align:left;font-weight:600;">SUMMARY</th>
        <th style="padding:8px;font-size:11px;color:#6b7280;text-align:center;font-weight:600;">LINK</th>
      </tr></thead>
      <tbody>${advisoryRows}</tbody>
    </table>
  </td></tr>`:""}

  <!-- HIGH SEVERITY TABLE -->
  ${high.length>0?`
  <tr><td style="padding:24px 32px;border-bottom:1px solid #e5e7eb;">
    <div style="font-size:11px;font-weight:700;color:#6b7280;letter-spacing:1px;text-transform:uppercase;margin-bottom:12px;">
      🔶 High Severity Advisories (${Math.min(high.length,10)} shown)
    </div>
    <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:6px;overflow:hidden;">
      <thead><tr style="background:#fff7ed;">
        <th style="padding:8px;font-size:11px;color:#ea580c;text-align:left;font-weight:700;">SEV</th>
        <th style="padding:8px;font-size:11px;color:#6b7280;text-align:left;font-weight:600;">ID</th>
        <th style="padding:8px;font-size:11px;color:#6b7280;text-align:left;font-weight:600;">TITLE</th>
        <th style="padding:8px;font-size:11px;color:#6b7280;text-align:left;font-weight:600;">VENDOR · DATE</th>
        <th style="padding:8px;font-size:11px;color:#6b7280;text-align:center;font-weight:600;">LINK</th>
      </tr></thead>
      <tbody>${highRows}</tbody>
    </table>
  </td></tr>`:""}

  <!-- FOOTER -->
  <tr><td style="background:#f9fafb;padding:16px 32px;border-top:1px solid #e5e7eb;">
    <table width="100%"><tr>
      <td style="font-size:11px;color:#9ca3af;line-height:1.6;">
        Concentrix Endpoint Security Team · Security Advisory Dashboard<br>
        <a href="https://ssipankajsingh.github.io/security-advisory-dashboard/" style="color:#2563eb;text-decoration:none;">
          🔗 View Full Dashboard & Filter by Severity/Vendor
        </a>
      </td>
      <td align="right" style="font-size:11px;color:#9ca3af;vertical-align:top;">
        ${advisories.length} advisories · ${Object.keys(TRUSTED_FEEDS).length} sources<br>
        ${new Date().toISOString().split("T")[0]}
      </td>
    </tr></table>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>`;
}

// ─── EMAIL SENDER (no AI required) ───────────────────────────────────────────
async function sendDigestEmail(config){
  const { recipients, senderEmail, senderName } = config;
  if(!SENDGRID_API_KEY) throw new Error("SENDGRID_API_KEY not configured in Render environment variables");
  if(!recipients?.length) throw new Error("No recipients configured");

  console.log("📧 Fetching advisories for digest...");
  const advisories = await fetchAllFeeds();
  const critCount  = advisories.filter(a=>a.severity==="Critical").length;
  const zdCount    = advisories.filter(a=>a.zeroDay).length;

  const dateStr = new Date().toLocaleDateString("en-GB",{weekday:"long",year:"numeric",month:"long",day:"numeric"});
  const html    = buildEmailHTML(advisories, dateStr);
  const subject = `🛡️ Security Advisory Digest — ${dateStr}${critCount>0?` | ${critCount} Critical`:""}${zdCount>0?` | ${zdCount} Zero-Day`:""}`;

  const msg = {
    to:      recipients,
    from:    { email: senderEmail||"security-digest@concentrix-soc.com", name: senderName||"Concentrix SOC Dashboard" },
    subject,
    html,
    text:    `Security Advisory Digest — ${dateStr}\n\nCritical: ${critCount} | Zero-Day: ${zdCount} | Total: ${advisories.length}\n\nView full dashboard: https://ssipankajsingh.github.io/security-advisory-dashboard/`,
    headers: { "X-Priority": critCount>0?"1":"3", "Importance": critCount>0?"high":"normal" },
  };

  await sgMail.sendMultiple(msg);
  console.log(`📧 Digest sent to ${recipients.length} recipients`);
  return { sent:true, recipients:recipients.length, criticalCount:critCount, zeroDayCount:zdCount };
}

// ─── SCHEDULED DIGEST (cron) ─────────────────────────────────────────────────
// Loaded from environment — DIGEST_SCHEDULE e.g. "0 8 * * *" = 8:00 AM UTC daily
// Default: 8:00 AM UTC. Override via DIGEST_SCHEDULE env var in Render.
let scheduledJob = null;

function startSchedule(cronExpr, config){
  if(scheduledJob){ scheduledJob.stop(); scheduledJob=null; }
  if(!cronExpr||cronExpr==="off") return;
  try{
    scheduledJob=cron.schedule(cronExpr,async()=>{
      console.log(`⏰ Scheduled digest triggered: ${new Date().toISOString()}`);
      try{ await sendDigestEmail(config); }
      catch(e){ console.error("Scheduled digest failed:", e.message); }
    },{ timezone:"UTC" });
    console.log(`⏰ Digest scheduled: ${cronExpr} UTC`);
  }catch(e){
    console.error("Invalid cron expression:", e.message);
  }
}

// ─── ACCESS CODE AUTH ────────────────────────────────────────────────────────
// Set ACCESS_CODE in Render environment variables — never hardcode here
// Example: ACCESS_CODE=ConcentrixSOC2026
const ACCESS_CODE = process.env.ACCESS_CODE || "";

app.post("/auth/verify", async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ valid: false, error: "No code provided" });
  if (!ACCESS_CODE) return res.status(503).json({ valid: false, error: "Access code not configured on server" });
  // Compare submitted code to server-side code (trim + case-insensitive)
  const valid = code.trim() === ACCESS_CODE.trim();
  // Log attempt (no sensitive data logged)
  console.log(`[AUTH] Login attempt: ${valid ? "✅ SUCCESS" : "❌ FAILED"} — ${new Date().toISOString()}`);
  res.json({ valid });
});



app.get("/", (req,res)=>res.json({
  name:"Security Advisory Proxy v3",
  feeds:Object.keys(TRUSTED_FEEDS).length,
  emailEnabled:!!SENDGRID_API_KEY,
  endpoints:["/health","/sources","/feed/:sourceId","/feeds/all","/digest/send","/digest/schedule"],
}));

app.get("/health",(req,res)=>res.json({
  status:"ok", sources:Object.keys(TRUSTED_FEEDS).length,
  cached:cache.keys().length, uptime:Math.round(process.uptime())+"s",
  time:new Date().toISOString(),
  emailEnabled:!!SENDGRID_API_KEY,
  scheduleActive:!!scheduledJob,
}));

app.get("/sources",(req,res)=>res.json(
  Object.keys(TRUSTED_FEEDS).map(id=>({ id, vendor:VENDOR_NAMES[id]||id, url:TRUSTED_FEEDS[id], cached:cache.has(id) }))
));

app.get("/feed/:sourceId",async(req,res)=>{
  const{sourceId}=req.params;
  const url=TRUSTED_FEEDS[sourceId];
  if(!url)return res.status(404).json({error:"Unknown source: "+sourceId});
  try{
    const items=await fetchFeed(sourceId,url);
    res.json({sourceId,vendor:VENDOR_NAMES[sourceId]||sourceId,count:items.length,items});
  }catch(err){
    console.error(`[${sourceId}] Error:`,err.message);
    res.status(502).json({error:"Failed to fetch feed",detail:err.message,sourceId});
  }
});

app.post("/feeds/all",async(req,res)=>{
  const{sources=Object.keys(TRUSTED_FEEDS)}=req.body;
  const enabled=sources.filter(id=>TRUSTED_FEEDS[id]);
  const results=[];const errors=[];
  await Promise.allSettled(enabled.map(async id=>{
    try{const items=await fetchFeed(id,TRUSTED_FEEDS[id]);results.push(...items);}
    catch(err){console.error(`[${id}] Failed:`,err.message);errors.push({id,error:err.message});}
  }));
  const seen=new Set();
  const deduped=results.filter(item=>{
    const key=item.title.toLowerCase().slice(0,80);
    if(seen.has(key))return false;seen.add(key);return true;
  });
  const sevOrder={Critical:0,High:1,Medium:2,Low:3,Unknown:4};
  deduped.sort((a,b)=>{
    const dd=new Date(b.date)-new Date(a.date);
    return dd!==0?dd:(sevOrder[a.severity]??4)-(sevOrder[b.severity]??4);
  });
  res.json({fetched:enabled.length,succeeded:enabled.length-errors.length,failed:errors.length,errors,total:deduped.length,timestamp:new Date().toISOString(),items:deduped});
});

// Manual digest send
app.post("/digest/send",async(req,res)=>{
  const{recipients,senderEmail,senderName}=req.body;
  if(!recipients?.length) return res.status(400).json({error:"recipients array required"});
  try{
    const result=await sendDigestEmail({recipients,senderEmail,senderName});
    res.json(result);
  }catch(err){
    console.error("Digest send error:",err.message);
    res.status(500).json({error:err.message});
  }
});

// Configure scheduled digest
app.post("/digest/schedule",async(req,res)=>{
  const{cronExpr,recipients,senderEmail,senderName,enabled}=req.body;
  if(enabled===false){ if(scheduledJob){scheduledJob.stop();scheduledJob=null;} return res.json({scheduled:false,message:"Schedule disabled"}); }
  if(!recipients?.length) return res.status(400).json({error:"recipients array required"});
  if(!cronExpr) return res.status(400).json({error:"cronExpr required (e.g. '0 8 * * *' for 8AM UTC)"});
  startSchedule(cronExpr,{recipients,senderEmail,senderName});
  res.json({scheduled:true,cronExpr,recipients,message:`Digest scheduled: ${cronExpr} UTC`});
});

app.get("/digest/status",(req,res)=>res.json({
  scheduleActive:!!scheduledJob,
  sendgridConfigured:!!SENDGRID_API_KEY,
}));

app.post("/cache/clear",(req,res)=>{cache.flushAll();res.json({cleared:true,time:new Date().toISOString()});});

app.listen(PORT,()=>{
  console.log(`\n🛡️  Security Advisory Proxy v3 running on port ${PORT}`);
  console.log(`   Sources : ${Object.keys(TRUSTED_FEEDS).length} configured`);
  console.log(`   Email   : ${SENDGRID_API_KEY?"✅ SendGrid configured":"⚠️  Set SENDGRID_API_KEY env var"}\n`);
});
