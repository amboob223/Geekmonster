# GeekMonster — Free Repo Scan

The free-tier, fully-automated half of the pipeline: paste a public GitHub
repo URL, get back AI-surfaced CANDIDATE vulnerabilities in the browser.

This intentionally does NOT clone, install, or execute the target repo in
any way. It reads up to 8 likely-interesting source files via the GitHub
API and sends each one to Claude for review. No reproduction, no exploit
execution, no sandbox — that stays a human-run, paid engagement using
`new_engagement.py` / `scan.py` / `report.py`.

## How it works

## Deploy on Netlify

1. Push this folder to a GitHub repo (or drag-and-drop deploy on Netlify).
2. In Netlify: Site settings -> Environment variables, add:
   - `ANTHROPIC_API_KEY` — required. Your Anthropic API key.
   - `GITHUB_TOKEN` — optional. A GitHub personal access token (no scopes
     needed for public repos) raises the GitHub API rate limit from
     60/hr to 5,000/hr. Without it you'll hit limits fast under any
     real traffic.
   - `GM_MODEL` — optional. Defaults to `claude-sonnet-5-5`.
3. Deploy. Netlify auto-detects `netlify.toml` and builds the function.
4. Visit `/scan.html` (or link it from your existing landing page).

## Local testing

```bash
npm install -g netlify-cli
cd geekmonster-scan
netlify dev
```

This runs the function locally with the same routing Netlify uses in
production. Set env vars in a local `.env` file (never commit it).

## Cost and limits, as of October 2026

- Each scan makes up to 8 Claude API calls (one per file, ~input tokens
  for a typical file + a few hundred output tokens). At typical source
  file sizes this is a small fraction of a cent per file on Sonnet
  pricing — check current rates at anthropic.com/pricing since they
  change.
- `MAX_FILES` (8) and `MAX_FILE_CHARS` (20,000) in `scan-repo.js` are the
  knobs to tune cost vs. coverage. Lower them if you get real traffic
  and want to control spend.
- There's no rate limiting or abuse protection built in beyond GitHub's
  own API limits. If this gets real traffic, add a simple per-IP rate
  limit (Netlify Edge Functions or a KV store) before relying on it
  unattended.

## Why this scope and not more

- **No cloning or execution, on purpose.** A public form that runs
  arbitrary strangers' code on your infrastructure is an abuse vector,
  not a feature — see the Day 10 discussion on human-approval gates.
  Reading files via the GitHub API carries none of that risk.
- **Private repos are rejected.** Scanning a private repo would need
  the submitter to grant real access, which is a different trust
  model than "anyone can paste a public URL." Add OAuth later if you
  want to support it deliberately, not by accident.
- **Results are always labeled unverified.** The UI and the API
  response both say so explicitly. This is the free lead-gen layer;
  the paid engagement is where a human actually proves something.

## Next steps if you want to extend it

- Wire the "Request a verified report" mailto link to a real form or
  Stripe checkout instead.
- Log scans (repo + timestamp, not file contents) somewhere so you can
  see what's driving interest.
- Add a simple per-IP or per-day cap in the function to control spend
  before sharing this link widely.
