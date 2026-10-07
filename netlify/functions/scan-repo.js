// GeekMonster free-tier scanner.
// Reads source files from a public GitHub repo via the GitHub API (no cloning,
// no execution of any kind) and asks Claude to flag CANDIDATE vulnerabilities.
// This never proves anything: it's the lead-gen half. Verified, reproduced
// findings are the paid engagement, done by hand with new_engagement.py/report.py.

const SCANNABLE_EXT = [".ts", ".js", ".py", ".sol", ".go", ".java", ".php", ".rb"];
const SKIP_DIR_PARTS = ["node_modules", ".git", "dist", "build", "test", "tests", "__pycache__", "frontend", "vendor"];

// --- Cost / latency caps -------------------------------------------------
const MAX_FILES = 4;            // files per scan (was 8)
const MAX_FILE_CHARS = 8000;    // per-file truncation (was 20000)
const MAX_TOKENS = 1200;        // output cap per file (was 2000)
const MODEL = process.env.GM_MODEL || "claude-haiku-5-5";
// Total time we allow before returning whatever finished. Keep under Netlify's
// sync function limit (10s default on many plans). Override with SCAN_BUDGET_MS.
const BUDGET_MS = Number(process.env.SCAN_BUDGET_MS) || 8500;

// --- Abuse protection ----------------------------------------------------
// Best-effort, in-memory. It resets when a serverless instance is recycled and
// is not shared across instances, so treat it as a speed bump. The Anthropic
// spend cap is the real backstop.
const PER_IP_LIMIT = 3;                    // scans per IP per window
const PER_IP_WINDOW_MS = 60 * 60 * 1000;   // 1 hour
const DAILY_LIMIT = 100;                   // scans per instance per UTC day
const ipHits = new Map();
let daily = { day: "", count: 0 };

function clientIp(event) {
  const h = event.headers || {};
  return (
    h["x-nf-client-connection-ip"] ||
    (h["x-forwarded-for"] || "").split(",")[0].trim() ||
    "unknown"
  );
}

function checkRateLimit(ip) {
  const now = Date.now();
  const day = new Date().toISOString().slice(0, 10);
  if (daily.day !== day) daily = { day, count: 0 };
  if (daily.count >= DAILY_LIMIT) {
    return { ok: false, error: "The free scanner hit its daily limit. Try again tomorrow, or request a verified report." };
  }
  const recent = (ipHits.get(ip) || []).filter((t) => now - t < PER_IP_WINDOW_MS);
  if (recent.length >= PER_IP_LIMIT) {
    return { ok: false, error: `Free scan limit reached (${PER_IP_LIMIT} per hour). Try again later.` };
  }
  recent.push(now);
  ipHits.set(ip, recent);
  daily.count++;
  if (ipHits.size > 5000) {
    for (const [k, v] of ipHits) {
      if (!v.some((t) => now - t < PER_IP_WINDOW_MS)) ipHits.delete(k);
    }
  }
  return { ok: true };
}

// --- Helpers -------------------------------------------------------------
function cors(body, status = 200) {
  return {
    statusCode: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
    },
    body: JSON.stringify(body),
  };
}

// Strict: only github.com/<owner>/<repo> with safe characters.
function parseGithubUrl(input) {
  const m = String(input || "").trim().match(
    /^(?:https?:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?(?:[/?#].*)?$/i
  );
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

async function ghFetch(url, signal) {
  const headers = { "User-Agent": "geekmonster-scan", Accept: "application/vnd.github+json" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetch(url, { headers, signal });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GitHub API ${res.status}: ${text.slice(0, 300)}`);
  }
  return res.json();
}

// Higher score = more likely to hold interesting security-relevant code.
function fileScore(p) {
  let s = 0;
  if (/login|auth|session|token|password|passwd|jwt|oauth/i.test(p)) s += 4;
  if (/user|account|admin|payment|upload|search|query|db|sql/i.test(p)) s += 3;
  if (/route|controller|handler|api|endpoint/i.test(p)) s += 2;
  return s;
}

async function listCandidateFiles(owner, repo, signal) {
  const repoInfo = await ghFetch(`https://api.github.com/repos/${owner}/${repo}`, signal);
  const branch = repoInfo.default_branch || "main";
  const tree = await ghFetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`,
    signal
  );
  if (!tree.tree) return { files: [], branch, repoInfo };

  const files = tree.tree
    .filter((n) => n.type === "blob")
    .filter((n) => SCANNABLE_EXT.some((ext) => n.path.endsWith(ext)))
    .filter((n) => !SKIP_DIR_PARTS.some((part) => n.path.split("/").includes(part)))
    .filter((n) => !n.size || n.size < 200000)
    .sort((a, b) => fileScore(b.path) - fileScore(a.path))
    .slice(0, MAX_FILES);

  return { files, branch, repoInfo };
}

async function fetchFileContent(owner, repo, branch, path, signal) {
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
  const res = await fetch(url, { headers: { "User-Agent": "geekmonster-scan" }, signal });
  if (!res.ok) return null;
  const text = await res.text();
  return text.slice(0, MAX_FILE_CHARS);
}

function numbered(text) {
  return text.split("\n").map((l, i) => `${i + 1}: ${l}`).join("\n");
}

const PROMPT = (path, code) => `You are a security code reviewer. Analyze the source file below for potential vulnerabilities.

Rules:
- Do NOT claim anything is proven. Flag suspicious code that deserves human testing.
- Trace: input -> processing -> dangerous operation -> missing security control -> impact.
- Cite line numbers exactly as shown in the numbered listing.
- Report at most 3 findings, highest confidence first. Keep each "reason" under 40 words.
- If there is nothing worth testing, return [].

Return ONLY a JSON array (no prose, no markdown fences). Each element:
{"finding": str, "line": int, "confidence": number 0-1, "reason": str,
 "hypothesis": "If I send X to Y, I expect Z because there is no W check",
 "severity_guess": "Critical|High|Medium|Low|Info"}

FILE: ${path}

${numbered(code)}`;

function parseJsonArray(text) {
  const cleaned = text.trim().replace(/^```(?:json)?/, "").replace(/```$/, "").trim();
  try {
    const d = JSON.parse(cleaned);
    return Array.isArray(d) ? d : null;
  } catch {
    const m = cleaned.match(/\[[\s\S]*\]/);
    if (!m) return null;
    try {
      const d = JSON.parse(m[0]);
      return Array.isArray(d) ? d : null;
    } catch {
      return null;
    }
  }
}

async function scanFile(path, code, signal) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    signal,
    headers: {
      "Content-Type": "application/json",
      "x-api-key": process.env.ANTHROPIC_API_KEY.trim(),
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: MAX_TOKENS,
      messages: [{ role: "user", content: PROMPT(path, code) }],
    }),
  });
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`Anthropic API ${res.status}: ${t.slice(0, 300)}`);
  }
  const data = await res.json();
  const raw = (data.content || []).filter((b) => b.type === "text").map((b) => b.text).join("");
  const items = parseJsonArray(raw) || [];
  return items.map((it) => ({ ...it, file: path, source: "ai", human_verified: false }));
}

// --- Handler -------------------------------------------------------------
exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return cors({});
  if (event.httpMethod !== "POST") return cors({ error: "POST only" }, 405);
  if (!process.env.ANTHROPIC_API_KEY) return cors({ error: "Server misconfigured: ANTHROPIC_API_KEY not set" }, 500);

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return cors({ error: "Invalid JSON body" }, 400);
  }

  const parsed = parseGithubUrl(body.repoUrl);
  if (!parsed) return cors({ error: "Paste a valid public GitHub repo URL, e.g. https://github.com/owner/repo" }, 400);

  const rl = checkRateLimit(clientIp(event));
  if (!rl.ok) return cors({ error: rl.error }, 429);

  // One shared deadline: when it fires, in-flight requests abort and we return
  // clean JSON with whatever finished instead of letting Netlify send an HTML 504.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), BUDGET_MS);
  const signal = controller.signal;

  try {
    const { files, branch, repoInfo } = await listCandidateFiles(parsed.owner, parsed.repo, signal);
    if (repoInfo.private) return cors({ error: "Private repos aren't supported on the free scanner yet." }, 400);
    if (!files.length) {
      return cors({
        repo: `${parsed.owner}/${parsed.repo}`,
        branch,
        filesScanned: [],
        candidateCount: 0,
        candidates: [],
        note: "No scannable source files found in common extensions.",
        disclaimer: "Unverified AI candidates only. Not proof of exploitability. No code was executed.",
      });
    }

    // Fetch + scan all files in parallel.
    const settled = await Promise.allSettled(
      files.map(async (f) => {
        const code = await fetchFileContent(parsed.owner, parsed.repo, branch, f.path, signal);
        if (!code) return { path: f.path, found: [] };
        return { path: f.path, found: await scanFile(f.path, code, signal) };
      })
    );

    const candidates = [];
    const scanned = [];
    let timedOut = 0;
    let firstError = null;
    for (const r of settled) {
      if (r.status === "fulfilled") {
        scanned.push(r.value.path);
        candidates.push(...r.value.found);
      } else if (r.reason && r.reason.name === "AbortError") {
        timedOut++;
      } else if (!firstError) {
        firstError = r.reason;
      }
    }

    // Nothing worked and it wasn't just a timeout: surface the real error.
    if (!scanned.length && firstError) throw firstError;
    if (!scanned.length && timedOut) {
      return cors({ error: "Scan timed out. Try a smaller repo or try again." }, 504);
    }

    candidates.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
    candidates.forEach((c, i) => (c.id = `CAND-${String(i + 1).padStart(3, "0")}`));

    return cors({
      repo: `${parsed.owner}/${parsed.repo}`,
      branch,
      filesScanned: scanned,
      candidateCount: candidates.length,
      candidates,
      partial: timedOut > 0,
      note: timedOut ? `${timedOut} file(s) didn't finish in time and were skipped.` : undefined,
      disclaimer: "Unverified AI candidates only. Not proof of exploitability. No code was executed.",
    });
  } catch (err) {
    if (err && err.name === "AbortError") {
      return cors({ error: "Scan timed out. Try a smaller repo or try again." }, 504);
    }
    return cors({ error: err.message || "Scan failed" }, 502);
  } finally {
    clearTimeout(timer);
  }
};
