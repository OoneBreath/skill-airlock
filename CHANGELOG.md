# Changelog

## 0.3.0 (unreleased)

- **What the audit did not read is listed.** `not_scanned[]` in the JSON report holds each skipped file
  with its reason (`binary`, `too-large`, `symlink-out`, `unreadable`) and size; the text report gets a
  "Not scanned (N files)" line right after the verdict. A file SKILL.md tells the agent to run that the
  audit could not read is `unscanned-invoked` (HIGH).
- **Remote-package instructions in prose: `prose-remote-package`.** Covers `npx`, `bunx`, `uvx`,
  `pnpm dlx`, `yarn dlx`, `pipx run`, `pip install`, `npm i -g`, `uv tool install`, `deno run <url>`.
  - **Severity.** In SKILL.md: MEDIUM; HIGH with `-y`/`--yes` (no confirmation prompt); one level down
    when the version is pinned or the description names the package. LOW in reference Markdown.
  - **Left out on purpose.** A project's own `npm install` and negated mentions ("do not run
    `pip install`") are not flagged.
  - **Before.** 0.2.0 caught most of these only as LOW, and `pipx run`, `pnpm dlx` and `yarn dlx` not
    at all.
  - **Calibration.** 4 catalog skills went OK → REVIEW. The probes and the reasons, including why
    `@latest` alone isn't HIGH, are in [docs/calibration.md](docs/calibration.md).
- **Skills inside plugins.** A plugin's authority lives in its hooks and MCP servers, not in the skill's
  directory. The audit now reads them too.
  - **Detection and quarantine.** `sync` records `plugin_root` for a skill under a
    `.claude-plugin/plugin.json`, and `audit <dir>` finds it on its own. `inspect` copies the
    plugin's manifest, `hooks/`, `.mcp.json` and the scripts hooks run into the quarantine
    (`plugin/`), so they are audited, integrity-checked and can be pinned by `accept`.
  - **Hooks.** Each hook command is a `plugin-hook` (MEDIUM). Hook commands and hook scripts get the
    line rules at full severity: secrets plus network is `exfil-pattern` HIGH.
  - **MCP servers.** A remote server is `plugin-mcp-remote` (MEDIUM). A local one is
    `plugin-mcp-local` (LOW) and its command is audited. Env and header NAMES are listed; values
    are never read out.
  - **Skill text.** A SKILL.md that relies on `mcp__…` tools or "the hook will…" gets
    `plugin-dependency` (LOW).
  - **Output.** It says: "This skill ships inside plugin X. Docking the skill alone does not install
    the plugin's hooks or MCP servers; installing the plugin does." That is true: `dock` copies the
    skill directory only.
  - **Calibration.** 6 of 62 catalog verdicts changed, all in claude-plugins-official, listed in
    [docs/calibration.md](docs/calibration.md).
  - **Tests.** 4 plugin fixtures (`tests/plugin_fixtures/`) and 7 tests.
- **Semantic review by a fresh subagent.** airlock prepares the review and checks the answer; it
  never calls a model.
  - **`airlock review-pack <skill>`** writes `pack.md` and `questions.json` into the quarantine.
    `pack.md` opens with an untrusted-content header, then the metadata, the static findings, and every
    file with line numbers, in a fence longer than any fence in the file, invisible characters shown as
    `<U+XXXX>`. It is capped at ~60k tokens; SKILL.md and scripts are always included, the rest is listed
    under "Not included". `questions.json` holds 7 fixed questions.
  - **`airlock review-check <skill> <answer.json>`** validates the reviewer's JSON: exactly q1..q7;
    every cited file:line exists inside the quarantined skill; text capped at 600 characters; no
    secret-looking text; q6 ids are real findings. Otherwise `review_status: invalid` and the verdict is
    unchanged.
  - **It can only raise.** A q3/q4/q5/q7 item at a file:line no static finding covers, marked
    `expected: false`, adds a `llm-review` finding one level above the current verdict (OK→REVIEW,
    REVIEW→BLOCK). A claimed false positive (q6) is shown as input for `accept`. A review never lowers
    a verdict.
  - **Agent instructions.** SKILL.md has a new step 3b: a fresh subagent whose only tool is Read; the
    main agent never reads the pack. Rationale and residual risk: docs/design.md.
  - **Tests.** A fixture whose risk is only semantic (`tests/review_fixtures/pr-notes`: static CLEAN,
    raised to REVIEW by a canned answer) and 8 tests.
- **`airlock accept`: accept findings you have read, pinned to their content.** For tools that
  legitimately trip the audit (security tools), instead of `--force`. You run
  `airlock accept <skill> <id…> --reason "…"` on a quarantined skill with a current `audit.json`; it
  stores `~/.skill-airlock/accepted.json` and offers `--list`, `--revoke <id…>`, and `--rule R [--file F]`,
  which lists the ids and accepts nothing.
  - **Effect on the verdict.** An accepted finding stays in the report, marked `ACCEPTED`, and stops
    counting toward the verdict while its id and the sha256 of every file it depends on still match
    (all of `files_involved` for cross-file findings). A change brings it back, and the report says so.
    The verdict is computed over every finding, including the repeats the text report hides, so
    accepting the visible lines doesn't lower it over lines you never saw.
  - **Limits, enforced and tested.** Findings aimed at the agent are refused: instruction rules,
    `hidden-unicode`, `bidi-control`, `unicode-tags`, `html-comment`, `unsafe-name`. An acceptance is
    per source and skill. An accepted skill is never `CLEAN`, `OK` at best.
  - **Decision log and agent rule.** Every accept and revoke is appended to
    `~/.skill-airlock/decisions.jsonl` (the start of the roadmap's decision log). SKILL.md: the agent
    may propose exact ids after the user has read the findings, and runs `accept` only after the user
    agrees.
- **Machine-readable audit report.** `airlock inspect <skill> --json` and `airlock audit <dir…> --json`
  print one JSON document ([docs/audit-schema.json](docs/audit-schema.json); audit: `{"reports": [...]}`).
  The text output stays the default and exit codes are unchanged. Each finding has a stable `id`
  (sha256 of rule, file and the matched text with whitespace normalised, no line number, plus an
  occurrence number when the same text repeats in a file), `context` (`skill_md`, `reference_md`,
  `fenced`, `code`, `comment`), `declared`, `files_involved` (every file a cross-file finding such as
  `exfil-pattern` or `mismatch-*` depends on) and `repeat`. JSON lists every finding, including the
  repeats the text report hides past 5 per rule and file. Text from the skill is sanitised exactly as in
  the text output, and the report names those fields in `untrusted_fields`. `inspect` saves the last
  report as `quarantine/<qid>/audit.json`; `dock` records the verdict, the finding ids and `tree_sha256`
  in `lock.json` (never the excerpts). Verdicts are unchanged: re-running the three public catalogs (62
  skills, mirrors from 2026-10-28) gives 1 BLOCK, 24 REVIEW, 37 OK/CLEAN, as in 0.2.0.
- CI: Python 3.9 runs on `ubuntu-24.04`. setup-python has no 3.9 for `ubuntu-latest` (now Ubuntu 26.04),
  so the next run on the old matrix would have failed before any test ran.

## 0.2.0: the audit after independent reviews

Released 31 October 2026. The rule changes between 0.1.0 and 0.2.0 were committed as working
versions 0.1.1–0.1.7, one per review step, and briefly tagged and published as releases; those
releases were withdrawn and this entry folds them into one. [docs/calibration.md](docs/calibration.md)
keeps each round. Version numbers only go up: anyone who installed a working version gets 0.2.0 as an
update. Between 0.1.0 and this release the audit went through two independent reviews and a test on
a second server. The second review ran four rounds and wrote 31 inert malicious
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
