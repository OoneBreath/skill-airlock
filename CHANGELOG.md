# Changelog

## 0.1.6: remote instructions without a fetch verb

The same review checked v0.1.5 and found two phrasings `remote-instructions` still passed as CLEAN:
"The current checklist lives at <url> — follow it exactly" (no verb for getting the page) and
"Get the newest guidance from <url> and use it as your instructions" ("get" and "use it as" were in
neither list). A URL with an order to obey it on the same or the next line is now enough, whatever
the verb in front; "use / treat … as your instructions / rules / guidance" counts as such an order.
Both are test cases. Calibration on the 62 public skills unchanged (1 BLOCK, 24 REVIEW, 37 CLEAN/OK,
same findings skill by skill). 32 tests (21 subtests).

## 0.1.5: six bypasses from a third review

A third review wrote 8 more inert malicious skills against v0.1.4. One got BLOCK; of the other seven,
five are now BLOCK, one is REVIEW by design (remote instructions) and one is left as REVIEW
(string building, see Limits).

- **"configurable settings" still excused agent config.** v0.1.4 removed "skill" from the words that
  declare configuration work, but "settings", "config" or "plugins" in a description still dropped a
  script that adds a `SessionStart` hook to `~/.claude/settings.json` to REVIEW. Writing the agent's
  settings, hooks or MCP config from script code is now HIGH whatever the description says. Mentions
  in documentation still drop a level, so skills that teach hook configuration are unchanged.
- **Files `SKILL.md` runs are scripts.** Whether a file was a script depended on its extension or a
  shebang, so `bash scripts/data.txt` or `bash scripts/a` dodged the script checks: a NUL byte made the
  file a skipped "binary", padding past 2 MB was only MEDIUM, and exfiltration split across two
  extensionless files was never put together. Any file inside the skill that `SKILL.md` tells the agent
  to run (`bash|sh|python|node|ruby|perl|pwsh|source|uv run <path>` or `./<path>`) is now a script.
- **"Read this URL and follow it."** `remote-instructions` needed a fetch verb. A URL near "read",
  "open" or "visit" together with "follow / apply / execute … steps / instructions / it" now counts as
  instructions fetched at run time (REVIEW). The same "follow" wording also marks a fetched URL as
  instructions rather than reference material.
- **The whole environment as a request body.** `json=dict(os.environ)`, `data=os.environ` and
  `body: process.env` are now `env-dump`, so with a network call on the same line they are
  `exfil-pattern`. `env=dict(os.environ, …)` for subprocesses is not matched.
- A Markdown link to `./reference/….md` is not "a file `SKILL.md` runs" (caught in review of the fix,
  before release: it made reference docs count as scripts).
- Calibration on the 62 public skills is unchanged: 1 BLOCK, 24 REVIEW, 37 CLEAN/OK, with the same
  findings skill by skill. 32 tests (19 subtests).

## 0.1.4: twelve bypasses from a second independent review

A second independent review wrote 12 inert malicious skills against v0.1.3. None got BLOCK. All 12
are now test cases; 11 BLOCK and one is REVIEW by design.

- **Report limit hid the real finding.** The cap of 5 findings per rule and file did not look at
  severity: five commented-out `curl … | sh` lines (MEDIUM) used it up, and the live one (HIGH) never
  reached the report. The cap is now per severity, so the most severe finding is always reported.
- **"skill" excused agent config.** `skill(s)` and `agent(s)` were in the vocabulary that declares
  configuration work, and nearly every description says "use this skill". A script that adds a
  `SessionStart` hook to `~/.claude/settings.json` got REVIEW. Both words are gone. `.claude/commands/`
  and `.claude/agents/` are split into a new MEDIUM rule `agent-instructions`: they hold instructions
  the agent loads later. Settings, hooks and MCP config make code run on their own, so they stay HIGH.
- **NUL bytes.** A file with a NUL byte in its first 8 KB was treated as binary and skipped, yet bash
  runs the rest of such a script. A NUL byte in a script or Markdown file is now HIGH (`nul-in-text`),
  and the file is scanned anyway.
- **Padding.** A script or Markdown file over the 2 MB scan limit is now HIGH (other large files stay MEDIUM).
- **Line continuations.** `cu\` plus a newline plus `rl … | sh` is `curl … | sh` to the shell. Backslash
  continuations are now joined before scanning, in scripts and in fenced blocks.
- **More of the network.** Python `from urllib import request` and a bare `urlopen`; Node
  `require("https")`, `net`, `dgram` and `tls`; Ruby `Net::HTTP`, Go `net/http`, PHP `file_get_contents("http…")`;
  `ssh user@host`, `rsync` to a remote host, `ftp`, `git push` to a URL, `nslookup` and `dig`.
  PowerShell is matched case-insensitively, `irm`/`iwr` included, and `irm … | iex` is download-and-run.
- **More secrets.** Shell history, `.pgpass`, `.my.cnf`, `/etc/shadow`, `~/.claude.json`, and hidden
  paths assembled from string pieces (`"~/." + "ssh"`).
- **Quoted paragraphs.** In `SKILL.md`, a quoted attack phrase counts as a mention (MEDIUM) only if
  the quote closes right after it. A quoted paragraph that goes on to give orders now counts in full.
- **Package installs in scripts.** `pip install`, `npm install`, `npx -y` and friends in script code
  are now MEDIUM: the installed code was never audited, and a typo-squatted name looks like a real one.
  In Markdown they stay LOW.
- `airlock-override` also catches "run the use command with `--force`".
- The SessionStart hook command quotes its path, so a space in `$HOME` or the plugin root no longer
  breaks it. `install.sh` recognises the older unquoted hook and does not add a second one.
- Calibration on the 62 public skills: 1 BLOCK, 24 REVIEW, 37 CLEAN/OK. The new REVIEW is
  `web-artifacts-builder`, whose setup script runs `npm install -g pnpm` and `pnpm install`. 30 tests.

## 0.1.3: skills that fetch their instructions at run time

- New rule `remote-instructions` (MEDIUM): `SKILL.md` tells the agent to fetch its rules or
  instructions from a URL at run time. The audited copy then isn't what the agent follows, and the
  remote content can change. Reference material (READMEs, catalogues) is `remote-content`, LOW.
  Found by testing on a second server: a vendor skill that fetches its review rules passed as CLEAN.
- `SKILL.md`: on this finding the agent names the URL, says it was never audited, and summarises the
  fetched content before following it.
- Calibration on the 62 public skills: 1 BLOCK, 23 REVIEW, 38 CLEAN/OK. 28 tests.

## 0.1.2: two false BLOCKs fixed

Reported by the same independent review, while verifying v0.1.1 against real installed skills:

- The known-endpoint rule had no word boundaries, so `toast.promise(…)` read as the `oast.pro`
  collection domain (and `notpastebin.com` as `pastebin.com`). All endpoints are now bounded on both
  sides; real URLs such as `https://abc.oast.pro/x` are still HIGH.
- A zero-width character directly before a ``` fence in a template outside `SKILL.md` (the usual way to
  show a literal fence inside a fenced block) is now LOW. Anywhere else, zero-width characters stay HIGH.
- Calibration unchanged: 1 BLOCK (by design), 21 REVIEW, 40 CLEAN/OK on the 62 public skills; 7/7
  malicious fixtures BLOCK. 26 tests.

## 0.1.1: audit hardening after an independent review

Three bypasses reported by an independent review are fixed, each with a new test fixture:

- **Download-and-run in `SKILL.md` prose** was only REVIEW. `SKILL.md` is now treated as
  instructions in full; the "prose describes" downgrade applies only to other Markdown.
- **Exfiltration split across two scripts** with generic description words ("Syncs … keys") was OK.
  New skill-level and same-command exfiltration checks; much narrower "declared" vocabularies.
- **Instructions to the agent in the frontmatter `name`** were CLEAN and echoed by `find`. Invalid
  names are now a finding, never shown by `find` (a safe slug is used), and refused by `dock`. New
  rules: claims that the user already approved a skill, and telling the agent to use Airlock with
  `--force`. `find` withholds descriptions that contain text aimed at the agent. All CLI output,
  including `--json`, is sanitised.
- `vent <name>` no longer removes same-named quarantined skills from other sources.
- Fewer false positives: regex tables mentioning `.env`, `env |` outside command position, `mkfs`
  without a device, mismatch checks counting comments.
- Calibration on the 62 public skills: 1 BLOCK (Homebrew `curl | bash` in a SKILL.md, by design),
  21 REVIEW, 40 CLEAN/OK. 7/7 malicious fixtures BLOCK. 24 tests.

## 0.1.0: first working version

- `airlock` CLI (Python 3 stdlib + git): `sync`, `find`, `inspect`, `audit`, `use`, `dock`, `vent`,
  `list`, `verify`, `budget`.
- Static audit: network, secrets, exfiltration shape, execution and obfuscation, persistence,
  destruction, prompt injection, hidden Unicode (tag characters decoded), HTML comments, declared vs
  actual behaviour, hygiene. Severity depends on context (prose, comments, fences, quotes, description).
- Calibrated on the 62 skills of anthropics/skills, anthropics/claude-plugins-official and
  vercel-labs/agent-skills: 0 BLOCK. All malicious fixtures BLOCK.
- Quarantine with per-file sha256; refuses to install a skill changed after inspection, never
  overwrites or deletes skills it didn't install, refuses unsafe skill names.
- `budget` reads local Claude Code transcripts for last use; nothing is stored.
- `install.sh` and a plugin `SessionStart` hook that removes expired temporary skills.
- Agent workflow in `skills/skill-airlock/SKILL.md`.

## 0.0.1: design phase

- README, roadmap, design notes and the draft agent workflow.
