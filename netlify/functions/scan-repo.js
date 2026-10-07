// GeekMonster free-tier scanner.
// Reads source files from a public GitHub repo via the GitHub API (no cloning,
// no execution of any kind) and asks Claude to flag CANDIDATE vulnerabilities.
// This never proves anything — it's the lead-gen half. Verified, reproduced
// findings are the paid engagement, done by hand with new_engagement.py/report.py.

const SCANNABLE_EXT = [".ts", ".js", ".py", ".sol", ".go", ".java", ".php", ".rb"];
const SKIP_DIR_PARTS = ["node_modules", ".git", "dist", "build", "test", "tests", "__pycache__", "frontend", "vendor"];
const MAX_FILES = 8;             // hard cap per scan — keeps latency and API cost bounded
const MAX_FILE_CHARS = 20000;    // truncate very large files
const MODEL = process.env.GM_MODEL || "claude-sonnet-5-5";

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

function parseGithubUrl(input) {
  const m = String(input).trim().match(
    /github\.com[/:]([^/\s]+)\/([^/\s#?]+?)(?:\.git)?(?:[/?#].*)?$/i
  );
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

async function ghFetch(url) {
  const headers = { "User-Agent": "geekmonster-scan", Accept: "application/vnd.github+json" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetch(url, { headers });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GitHub API ${res.status}: ${text.slice(0, 300)}`);
  }
  return res.json();
}

async function listCandidateFiles(owner, repo) {
  const repoInfo = await ghFetch(`https://api.github.com/repos/${owner}/${repo}`);
  const branch = repoInfo.default_branch || "main";
  const tree = await ghFetch(
    `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`
  );
  if (!tree.tree) return { files: [], branch, repoInfo };

  const files = tree.tree
    .filter((n) => n.type === "blob")
    .filter((n) => SCANNABLE_EXT.some((ext) => n.path.endsWith(ext)))
    .filter((n) => !SKIP_DIR_PARTS.some((part) => n.path.split("/").includes(part)))
    .sort((a, b) => {
      const score = (p) => (/route|controller|api|auth|login|admin/i.test(p) ? 0 : 1);
      return score(a.path) - score(b.path);
    })
    .slice(0, MAX_FILES);

  return { files, branch, repoInfo };
}

async function fetchFileContent(owner, repo, branch, path) {
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
  const res = await fetch(url, { headers: { "User-Agent": "geekmonster-scan" } });
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
- If there is nothing worth testing, return [].

Return ONLY a JSON array (no prose, no markdown fences). Each element:
{"finding": str, "line": int, "confidence": number 0-1, "reason": str,
 "hypothesis": "If I send X to Y, I expect Z because there is no W check",
 "severity_guess": "Critical|High|Medium|Low|Info"}

FILE: ${path}

${numbered(code)}`;

function parseJsonArray(text) {
  let cleaned = text.trim().replace(/^```(?:json)?/, "").replace(/```$/, "").trim();
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

async function scanFile(path, code) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": process.env.ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 2000,
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

  const parsed = parseGithubUrl(body.repoUrl || "");
  if (!parsed) return cors({ error: "Paste a valid public GitHub repo URL, e.g. https://github.com/owner/repo" }, 400);

  try {
    const { files, branch, repoInfo } = await listCandidateFiles(parsed.owner, parsed.repo);
    if (repoInfo.private) return cors({ error: "Private repos aren't supported on the free scanner yet." }, 400);
    if (!files.length) {
      return cors({ repo: `${parsed.owner}/${parsed.repo}`, branch, filesScanned: 0, candidates: [], note: "No scannable source files found in common extensions." });
    }

    const candidates = [];
    for (const f of files) {
      const code = await fetchFileContent(parsed.owner, parsed.repo, branch, f.path);
      if (!code) continue;
      const found = await scanFile(f.path, code);
      candidates.push(...found);
    }
    candidates.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
    candidates.forEach((c, i) => (c.id = `CAND-${String(i + 1).padStart(3, "0")}`));

    return cors({
      repo: `${parsed.owner}/${parsed.repo}`,
      branch,
      filesScanned: files.map((f) => f.path),
      candidateCount: candidates.length,
      candidates,
      disclaimer: "Unverified AI candidates only. Not proof of exploitability. No code was executed.",
    });
  } catch (err) {
    return cors({ error: err.message || "Scan failed" }, 502);
  }
};
