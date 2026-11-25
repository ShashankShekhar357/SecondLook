const express = require("express");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const fs = require("fs/promises");
const path = require("path");

const PORT = process.env.PORT || 3000;
const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_API_KEY || "";
const CACHE_HOURS = 24;
const LIST_REFRESH_HOURS = 6;
const MAX_CACHE_ENTRIES = 5000;

const FILTER_LISTS = [
  { name: "uBlock Badware risks", url: "https://ublockorigin.github.io/uAssets/filters/badware.txt", kind: "threat" },
  { name: "URLhaus", url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt", kind: "threat" },
  { name: "Phishing Army", url: "https://phishing.army/download/phishing_army_blocklist.txt", kind: "threat" },
  { name: "OISD big", url: "https://big.oisd.nl", kind: "other" },
  { name: "uBlock Privacy", url: "https://ublockorigin.github.io/uAssets/filters/privacy.txt", kind: "other" },
  { name: "My filters", file: "my-filters.txt", kind: "other" },
  { name: "Test threat list", file: "test-threat.txt", kind: "threat" },
];

const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "support",
]);

let blockedDomains = new Map();
let blockedUrls = new Map();
let blockedUrlCount = 0;
let listsLoaded = 0;
let listsUpdatedAt = null;
const resultCache = new Map();

function extractDomain(line) {
  let text = line.trim();
  if (!text) return null;
  if (text.startsWith("#") || text.startsWith("!") || text.startsWith("[")) return null;

  if (/#[@?$%]?#/.test(text)) return null;

  text = text.split(/\s#/)[0].trim();

  if (text.startsWith("||")) {
    text = text.slice(2).split("^")[0];
  } else {
    const parts = text.split(/\s+/);
    text = parts[parts.length - 1];
  }

  text = text.toLowerCase();

  if (text.startsWith("*.")) {
    const suffix = text.slice(2);
    const looksLikeSuffix = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(suffix);
    return looksLikeSuffix ? text : null;
  }

  const looksLikeDomain = /^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(text);
  if (!looksLikeDomain) return null;

  const isIpAddress = /^\d+\.\d+\.\d+\.\d+$/.test(text);
  if (isIpAddress) return null;

  return text;
}

function extractUrlRule(line) {
  let text = line.trim();
  if (!text.startsWith("||")) return null;
  if (/#[@?$%]?#/.test(text)) return null;

  text = text.slice(2).split("$")[0].toLowerCase();
  if (/[*|]/.test(text)) return null;
  if (text.slice(0, -1).includes("^")) return null;

  const slash = text.indexOf("/");
  if (slash === -1) return null;

  const domain = text.slice(0, slash);
  const looksLikeDomain = /^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(domain);
  if (!looksLikeDomain) return null;

  return { domain: domain, pattern: text };
}

async function readListText(list) {
  if (list.file) {
    return fs.readFile(path.join(__dirname, list.file), "utf8");
  }

  const response = await fetch(list.url, { signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error("HTTP " + response.status);

  return response.text();
}

async function downloadList(list) {
  const body = await readListText(list);
  const domains = [];
  const urlRules = [];

  for (const line of body.split("\n")) {
    const domain = extractDomain(line);
    if (domain) {
      domains.push(domain);
      continue;
    }

    const urlRule = extractUrlRule(line);
    if (urlRule) urlRules.push(urlRule);
  }

  return { domains: domains, urlRules: urlRules };
}

async function refreshLists() {
  const fresh = new Map();
  const freshUrls = new Map();
  let freshUrlCount = 0;
  let loadedCount = 0;

  for (const list of FILTER_LISTS) {
    try {
      const parsedList = await downloadList(list);

      for (const domain of parsedList.domains) {
        const names = fresh.get(domain) || [];
        names.push({ name: list.name, kind: list.kind });
        fresh.set(domain, names);
      }

      for (const rule of parsedList.urlRules) {
        const rules = freshUrls.get(rule.domain) || [];
        rules.push({ pattern: rule.pattern, name: list.name, kind: list.kind });
        freshUrls.set(rule.domain, rules);
        freshUrlCount += 1;
      }

      loadedCount += 1;
      console.log("Loaded " + parsedList.domains.length + " domains and " + parsedList.urlRules.length + " exact addresses from " + list.name);
    } catch (error) {
      console.error("Could not load " + list.name + ": " + error.message);
    }
  }

  if (fresh.size > 0) {
    blockedDomains = fresh;
    blockedUrls = freshUrls;
    blockedUrlCount = freshUrlCount;
    listsLoaded = loadedCount;
    listsUpdatedAt = new Date().toISOString();
  }
}

function findListHits(hostname) {
  const labels = hostname.split(".");
  const hits = [];

  function addHit(key) {
    const entries = blockedDomains.get(key);
    if (!entries) return;

    hits.push({
      domain: key,
      lists: entries.map((entry) => entry.name),
      isThreat: entries.some((entry) => entry.kind === "threat"),
    });
  }

  for (let start = 0; start < labels.length - 1; start++) {
    addHit(labels.slice(start).join("."));
  }

  for (let start = 1; start < labels.length; start++) {
    addHit("*." + labels.slice(start).join("."));
  }

  return hits;
}

function urlRuleMatches(target, pattern) {
  const wantsSeparator = pattern.endsWith("^");
  const prefix = wantsSeparator ? pattern.slice(0, -1) : pattern;

  if (!target.startsWith(prefix)) return false;
  if (!wantsSeparator) return true;

  const next = target.charAt(prefix.length);
  return next === "" || !/[a-z0-9_.%-]/i.test(next);
}

function findUrlHits(parsed) {
  const labels = parsed.hostname.split(".");
  const pathAndQuery = parsed.pathname + parsed.search;
  const hits = [];

  for (let start = 0; start < labels.length - 1; start++) {
    const domain = labels.slice(start).join(".");
    const rules = blockedUrls.get(domain);
    if (!rules) continue;

    const target = (domain + pathAndQuery).toLowerCase();

    for (const rule of rules) {
      if (!urlRuleMatches(target, rule.pattern)) continue;

      hits.push({
        domain: rule.pattern,
        lists: [rule.name],
        isThreat: rule.kind === "threat",
        exact: true,
      });
    }
  }

  return hits;
}

function normalizeUrl(input) {
  let text = String(input || "").trim();
  if (!text || text.length > 2000) return null;

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text);
  if (!hasScheme) text = "https://" + text;

  try {
    const parsed = new URL(text);
    const isWebLink = parsed.protocol === "http:" || parsed.protocol === "https:";
    return isWebLink ? parsed : null;
  } catch (error) {
    return null;
  }
}

function inspectPatterns(parsed) {
  const signals = [];
  const host = parsed.hostname;
  const labels = host.split(".");
  const tld = labels[labels.length - 1];

  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    signals.push("The link uses a raw IP address instead of a domain name.");
  }
  if (host.startsWith("xn--") || host.includes(".xn--")) {
    signals.push("The domain uses punycode, which can disguise lookalike characters.");
  }
  if (parsed.username || parsed.password) {
    signals.push("The link has a username or password before the domain, a trick used to mislead readers.");
  }
  if (labels.length > 4) {
    signals.push("The domain has an unusually long chain of subdomains.");
  }
  if (SUSPICIOUS_TLDS.has(tld)) {
    signals.push("The ." + tld + " ending is often used in scams.");
  }
  if (parsed.protocol === "http:") {
    signals.push("The page is not encrypted (http instead of https).");
  }
  if (parsed.href.length > 200) {
    signals.push("The address is very long, which can hide where it really goes.");
  }

  return signals;
}

function virusTotalId(href) {
  return Buffer.from(href).toString("base64url");
}

function virusTotalRequest(pathname, options) {
  const settings = options || {};
  return fetch("https://www.virustotal.com/api/v3" + pathname, {
    method: settings.method || "GET",
    headers: Object.assign({ "x-apikey": VIRUSTOTAL_KEY }, settings.headers || {}),
    body: settings.body,
    signal: AbortSignal.timeout(20000),
  });
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function submitAndWait(href) {
  const submission = await virusTotalRequest("/urls", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ url: href }).toString(),
  });

  if (submission.status === 429) return "rate-limited";
  if (!submission.ok) return null;

  const submissionBody = await submission.json();
  const analysisId = submissionBody.data.id;

  for (let attempt = 0; attempt < 3; attempt++) {
    await wait(7000);

    const poll = await virusTotalRequest("/analyses/" + analysisId);
    if (poll.status === 429) return "rate-limited";
    if (!poll.ok) return null;

    const pollBody = await poll.json();
    if (pollBody.data.attributes.status === "completed") {
      return pollBody.data.attributes.stats;
    }
  }

  return "pending";
}

function describeVirusTotal(stats, href) {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;

  return {
    status: "done",
    malicious: malicious,
    suspicious: suspicious,
    harmless: harmless,
    undetected: undetected,
    total: malicious + suspicious + harmless + undetected,
    reportUrl: "https://www.virustotal.com/gui/url/" + crypto.createHash("sha256").update(href).digest("hex"),
  };
}

async function checkVirusTotal(href) {
  if (!VIRUSTOTAL_KEY) {
    return { status: "skipped", message: "No VirusTotal API key is set on this server." };
  }

  try {
    const existing = await virusTotalRequest("/urls/" + virusTotalId(href));

    if (existing.status === 429) {
      return { status: "unavailable", message: "VirusTotal's rate limit was reached. Try again in a minute." };
    }

    if (existing.ok) {
      const body = await existing.json();
      return describeVirusTotal(body.data.attributes.last_analysis_stats, href);
    }

    if (existing.status !== 404) {
      return { status: "unavailable", message: "VirusTotal returned an error (" + existing.status + ")." };
    }

    const outcome = await submitAndWait(href);

    if (outcome === "rate-limited") {
      return { status: "unavailable", message: "VirusTotal's rate limit was reached. Try again in a minute." };
    }
    if (outcome === "pending") {
      return { status: "pending", message: "VirusTotal is still scanning this link. Check again in a minute." };
    }
    if (!outcome) {
      return { status: "unavailable", message: "VirusTotal could not scan this link." };
    }

    return describeVirusTotal(outcome, href);
  } catch (error) {
    return { status: "unavailable", message: "VirusTotal could not be reached." };
  }
}

function decideVerdict(listHits, virusTotal, signals) {
  const threatHits = listHits.filter((hit) => hit.isThreat);
  if (threatHits.length > 0) return "dangerous";

  if (virusTotal.status === "done") {
    if (virusTotal.malicious >= 3) return "dangerous";
    if (virusTotal.malicious > 0 || virusTotal.suspicious > 0) return "suspicious";
  }

  if (signals.length >= 2) return "suspicious";

  return "clear";
}

function summarize(verdict) {
  if (verdict === "dangerous") return "Do not open this link. It is flagged as malicious.";
  if (verdict === "suspicious") return "Be careful. Something about this link looks wrong.";
  return "No known threats found. That does not guarantee the link is safe.";
}

function rememberResult(href, result) {
  if (resultCache.size >= MAX_CACHE_ENTRIES) {
    const oldestKey = resultCache.keys().next().value;
    resultCache.delete(oldestKey);
  }
  resultCache.set(href, { result: result, expires: Date.now() + CACHE_HOURS * 3600 * 1000 });
}

const app = express();

app.set("trust proxy", 1);

app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

const checkLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many checks from your connection. Wait a minute and try again." },
});

app.get("/api/status", (req, res) => {
  res.json({
    domains: blockedDomains.size,
    urlRules: blockedUrlCount,
    lists: listsLoaded,
    updatedAt: listsUpdatedAt,
    virusTotal: Boolean(VIRUSTOTAL_KEY),
  });
});

app.post("/api/check", checkLimiter, async (req, res) => {
  const parsed = normalizeUrl(req.body && req.body.url);

  if (!parsed) {
    return res.status(400).json({ error: "Enter a full web address, like https://example.com/page." });
  }

  const href = parsed.href;
  const cached = resultCache.get(href);

  if (cached && cached.expires > Date.now()) {
    return res.json(Object.assign({}, cached.result, { cached: true }));
  }

  const listHits = findListHits(parsed.hostname).concat(findUrlHits(parsed));
  const signals = inspectPatterns(parsed);

  const hasThreatHit = listHits.some((hit) => hit.isThreat);

  let virusTotal;
  if (hasThreatHit) {
    virusTotal = { status: "skipped", message: "Not needed. A malware or phishing list already flagged this link." };
  } else {
    virusTotal = await checkVirusTotal(href);
  }

  const verdict = decideVerdict(listHits, virusTotal, signals);

  const result = {
    url: href,
    hostname: parsed.hostname,
    verdict: verdict,
    summary: summarize(verdict),
    filterLists: { hits: listHits, domains: blockedDomains.size, urlRules: blockedUrlCount, lists: listsLoaded },
    virusTotal: virusTotal,
    signals: signals,
    checkedAt: new Date().toISOString(),
  };

  const finished = virusTotal.status === "done" || virusTotal.status === "skipped";
  if (finished) rememberResult(href, result);

  res.json(result);
});

app.listen(PORT, () => {
  console.log("SecondLook is running at http://localhost:" + PORT);
  if (!VIRUSTOTAL_KEY) console.log("No VIRUSTOTAL_API_KEY set. Only filter lists and pattern checks will run.");
});

refreshLists();
setInterval(refreshLists, LIST_REFRESH_HOURS * 3600 * 1000);
