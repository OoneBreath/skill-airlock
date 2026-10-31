# Design

Working notes for v0.1–v0.4. Short on purpose; details are decided when the code is written.

## Principles

1. **Nothing leaves the machine except fetches you asked for.** No telemetry, no search API.
2. **Nothing runs or loads before you say yes.** Fetched skills sit in quarantine.
3. **Evidence, not verdicts.** The audit shows the exact lines it flagged and why.
4. **Zero runtime dependencies.** Bash plus Python 3 stdlib, like Project Brain. A tool that audits
   other people's code should be easy to audit itself.
5. **The agent is the search engine.** The local index does cheap keyword filtering; the agent reads
   the shortlisted descriptions and judges the fit. No embedding model needed.

## Layout

```
~/.skill-airlock/
  sources.json        # catalogs you trust (copied from sources.default.json on first run)
  mirrors/<source>/   # shallow git clones of github/git sources
  index.json          # one entry per skill: id, name, description, source, path, commit, token estimates
  quarantine/<id>/    # skill/ (the copy), meta.json (hashes, verdict), audit.txt; never inside an agent's skills dir
  lock.json           # every install: source, commit, sha256 per file, mode, expiry, agents, audit verdict
  ledger.md           # ratings and notes per skill (v0.4)
```

## Index and search

- `airlock sync` shallow-fetches each source at its default branch, finds every `SKILL.md`, and
  stores the frontmatter `name` and `description`, the path and the commit. Nothing else is stored.
- `airlock find` scores entries by keyword overlap with name and description and returns the top ~15.
- The agent shortlists 3–5 and presents them: what each does, source, last commit date, size in
  tokens, and whether it bundles scripts.
- Your query is never written to disk and never sent anywhere.

## Audit

Static rules run over every file in the skill, Markdown included. Each finding is
`severity · rule · file:line · excerpt`. The rule tables live in `skills/skill-airlock/_audit.py`;
the README has the [overview](../README.md#how-the-audit-works).

Severity is adjusted by context, because most real skills *document* risky things:

- `SKILL.md` is instructions: every line counts in full, prose included (v0.2.0; v0.1.0 treated its
  prose as documentation, which let `curl … | bash` in a sentence through as REVIEW).
- Other Markdown prose and script comments describe rather than run: code-like rules drop one level
  there. Fenced code blocks keep full severity.
- Instruction rules (injection, concealment, claimed user approval, `--force` overrides, …) drop to
  low when the phrase is quoted in reference docs or comments, and to medium when quoted in `SKILL.md`.
- Behaviour the description declares drops one level (network, credentials, agent config). The word
  lists are narrow: generic words ("sync", "keys", "server", "tokens" in the LLM sense) don't count.
- Exfiltration: secrets and network on one line (any file except reference prose), in one script, or
  split across scripts. Declared words never lower it.
- Declared-vs-actual checks (`mismatch-*`) and exfiltration only count real script code, not comments.
- Frontmatter `name` must be a valid skill name. Otherwise it is a finding, `find` shows a safe slug
  instead, and `dock` refuses it. `find` withholds descriptions that match instruction rules.

The auditor skips its own two code files when they are byte-identical to the running copy, so its
rule tables don't flag themselves. A different file can't borrow that exemption.

**Calibration.** Changes to rules are checked against the full public catalogs and the malicious
fixtures in `tests/fixtures/` (all must BLOCK). v0.1.0: 0 BLOCK, 16 REVIEW, 46 CLEAN/OK, 4 malicious fixtures (+1 clean).
v0.2.0: 1 BLOCK (Homebrew `curl | bash` in a SKILL.md, by design), 24 REVIEW, 37 CLEAN/OK, 7 fixtures plus
the probes of two independent reviews as test cases.
A rule change that blocks a well-known legitimate skill needs a reason. The full record, including
the 18 blocks of the first rule set and where each bypass came from, is in [calibration.md](calibration.md).

**The report is untrusted text.** Excerpts are truncated, and invisible or control characters are
shown as `<U+XXXX>`, so a skill can't use its own audit report to smuggle instructions to the agent
reading it. `SKILL.md` tells the agent the same.

Verdicts: any HIGH is **BLOCK** (the agent recommends against it; only the user can override with
`--force`), MEDIUM is **REVIEW**, LOW only is **OK**, nothing is **CLEAN**.

## Modes

- **once**: the skill stays in quarantine; the agent reads its `SKILL.md` and follows it for this
  task only. No future session sees it.
- **temp**: installed with `expires` in `lock.json`. `airlock vent --expired` removes expired ones; a SessionStart
  hook can run it automatically.
- **keep**: installed and pinned to a commit. `airlock update` shows the diff and re-audits before
  anything changes.
- **fork** (v0.4): for agents that support running a skill in a sub-agent (Claude Code: `context: fork`
  frontmatter, to be verified per agent). Only the result returns to the main conversation.

A skill loaded into a conversation stays in that conversation's context; no agent can unload it
mid-session. The modes control what future sessions load, and `fork` keeps the body out of the
main context in the first place.

## Integrity

`lock.json` stores sha256 for every installed file. `airlock verify` reports any file that changed
after install, whether from an upstream update or a local edit.

## Agents

Install targets come from a small table (agent → project dir, global dir). v0.1 ships Claude Code
(`~/.claude/skills/`) and the shared `~/.agents/skills/` (Codex and others). More agents follow in
v0.4; their paths are checked against each agent's own docs before being added.

## Context budget

`airlock budget` estimates tokens as characters / 4 over each installed skill's name and description
(what agents load every session) and over the body (what loads on use). It reports unused skills
from local Claude Code transcripts: `Skill` tool calls and `/slash` invocations, read in place,
only files modified within the window, nothing copied or stored.

## Project Brain integration (optional, v0.4)

If `.project-brain/` exists, `airlock rate` appends one line to the ledger and can mirror it into the
brain, so the agent can check "what worked last time for this kind of task" before searching.
There is no hard dependency in either direction.
