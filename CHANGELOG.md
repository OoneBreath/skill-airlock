# Changelog

## 0.1.1: the audit after independent reviews

Released 31 October 2026. Between 0.1.0 and this release the audit went through two independent
reviews and a test on a second server. The second review ran four rounds and wrote 31 inert malicious
skills and phrasings against the rules. The full record, probe by probe and skill by skill, is in
[docs/calibration.md](docs/calibration.md). Each bypass below is now a test case.

**Bypasses closed**

- Download-and-run in `SKILL.md` prose was only REVIEW. `SKILL.md` now counts in full as
  instructions; the "prose describes" downgrade applies only to other Markdown.
- Exfiltration split across two scripts behind generic description words ("Syncs … keys") was OK.
  New cross-script and same-command exfiltration checks; much narrower "declared" vocabularies.
- Instructions to the agent in the frontmatter `name` were CLEAN and echoed by `find`. Invalid names
  are a finding, never shown by `find`, and refused by `dock`. New rules for claims that the user
  already approved a skill and for telling the agent to use Airlock with `--force` (including "run the
  use command with `--force`").
- The cap of 5 findings per rule and file ignored severity, so five commented-out `curl … | sh` lines
  hid the live one. The cap is now per severity: the most severe finding is always reported.
- "skill", "agent", "settings" or "config" in a description excused a script that adds a hook to
  `~/.claude/settings.json`. Writing the agent's settings, hooks or MCP config from script code is now
  HIGH whatever the description says. `.claude/commands/` and `.claude/agents/` are a separate MEDIUM
  rule (`agent-instructions`): they hold instructions, not code that runs on its own.
- A NUL byte made a script or Markdown file a skipped "binary"; bash runs past it. Now HIGH, and the
  file is scanned anyway. Scripts and Markdown padded past the 2 MB scan limit are HIGH.
- Files `SKILL.md` tells the agent to run (`bash scripts/data.txt`, `./setup`) are scripts whatever
  their extension. A Markdown link to `./reference/….md` is a link, not a run.
- Backslash-newline continuations (`cu\` + newline + `rl … | sh`) are joined before scanning.
- More network: Python `urllib` imports and a bare `urlopen`, Node `https`/`net`/`dgram`/`tls`, Ruby,
  Go, PHP, `ssh user@host`, remote `rsync`, `ftp`, `git push` to a URL, `nslookup`/`dig`; PowerShell
  case-insensitive, and `irm … | iex` is download-and-run.
- More secrets: shell history, `.pgpass`, `.my.cnf`, `/etc/shadow`, `~/.claude.json`, hidden paths
  built from string pieces (`"~/." + "ssh"`), and the whole environment as a request body
  (`json=dict(os.environ)`).
- In `SKILL.md`, a quoted attack phrase counts as a mention only if the quote closes right after it;
  a quoted paragraph that goes on to give orders counts in full.
- Package installs in script code (`pip install`, `npx -y`, …) are MEDIUM: that code was never
  audited, and a typo-squatted name looks like a real one.
- New rule `remote-instructions` (MEDIUM): `SKILL.md` points the agent at raw text (Markdown, plain
  text, YAML, a `/raw/` path, a gist or a paste site), or tells it to fetch or follow a URL as its
  instructions. Flagged by the shape of the link, whatever the wording or language, because word
  lists kept missing phrasings. Every other URL is `remote-content` (LOW). On this finding the agent
  names the URL, says it was never audited, and summarises the content before following it.

**False positives fixed**

- `toast.promise(…)` read as the `oast.pro` collection domain: endpoints are now bounded on both sides.
- A zero-width character escaping a code fence in a template outside `SKILL.md` is LOW (still HIGH
  anywhere else).

**Other**

- `vent <name>` no longer removes same-named quarantined skills from other sources.
- `find` withholds descriptions that contain text aimed at the agent; all CLI output, `--json`
  included, is sanitised.
- The `SessionStart` hook command quotes its path, so a space in `$HOME` no longer breaks it.
- Calibration on the 62 public skills: 1 BLOCK (Homebrew `curl | bash` in a `SKILL.md`, by design),
  24 REVIEW, 37 CLEAN/OK. 7/7 malicious fixtures BLOCK. 33 tests.

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
