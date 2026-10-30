# Design

Working notes for v0.1–v0.3. Short on purpose; details are decided when the code is written.

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
~/.skill-scout/
  sources.json        # catalogs you trust (copied from sources.default.json on first run)
  index/              # mirrored catalogs: one JSON line per skill (name, description, source, path, commit)
  quarantine/<id>/    # fetched but not installed; never inside an agent's skills dir
  lock.json           # every install: source, commit, sha256 per file, mode, expiry, agents, audit result
  ledger.md           # ratings and notes per skill (v0.3)
  audit/<id>.txt      # last audit report per skill
```

## Index and search

- `scout sync` shallow-fetches each source at its default branch, finds every `SKILL.md`, and
  stores the frontmatter `name` and `description`, the path and the commit. Nothing else is stored.
- `scout find` scores entries by keyword overlap with name and description and returns the top ~15.
- The agent shortlists 3–5 and presents them: what each does, source, last commit date, size in
  tokens, and whether it bundles scripts.
- Your query is never written to disk and never sent anywhere.

## Audit

Static rules run over every file in the quarantined skill. Each finding is `severity · rule · file:line · excerpt`.

| Area | Examples of what is flagged |
|---|---|
| Network | `curl`, `wget`, `nc`, `/dev/tcp`, `fetch(`, `requests.`, `urllib`, `http.client`, raw IPs, webhook URLs |
| Secrets | reads of `.env`, `~/.ssh`, `~/.aws`, `~/.config/gh`, `*_TOKEN`/`*_KEY` env vars, keychains |
| Obfuscation | `base64 -d \| sh`, `eval`, `exec(`, long encoded blobs, minified scripts |
| Persistence | `crontab`, systemd units, shell rc files, writes into agent settings or hooks |
| Prompt injection | HTML comments carrying instructions, zero-width / bidi Unicode, "ignore previous instructions", instructions to skip confirmation, send data or disable safety |
| Mismatch | description says "formats tables" but scripts use the network or read secrets |
| Hygiene | oversized `SKILL.md`, missing or vague `description`, unpinned remote downloads |

Severity sets the default: **high** means the agent recommends not installing and requires an
explicit override; **medium** means review the evidence first; **low** is informational.

The audit is a filter, not a proof. A clean report means "nothing known was found".

## Modes

- **once**: the skill stays in quarantine; the agent reads its `SKILL.md` and follows it for this
  task only. No future session sees it.
- **temp**: installed with `expires` in `lock.json`. `scout gc` removes expired ones; a SessionStart
  hook can run it automatically.
- **keep**: installed and pinned to a commit. `scout update` shows the diff and re-audits before
  anything changes.
- **fork**: for agents that support running a skill in a sub-agent (Claude Code: `context: fork`
  frontmatter, to be verified per agent). Only the result returns to the main conversation.

A skill loaded into a conversation stays in that conversation's context; no agent can unload it
mid-session. The modes control what future sessions load, and `fork` keeps the body out of the
main context in the first place.

## Integrity

`lock.json` stores sha256 for every installed file. `scout verify` reports any file that changed
after install, whether from an upstream update or a local edit.

## Agents

Install targets come from a small table (agent → project dir, global dir). v0.1 ships Claude Code
(`~/.claude/skills/`) and the shared `~/.agents/skills/` (Codex and others). More agents follow in
v0.3; their paths are checked against each agent's own docs before being added.

## Context budget

`scout budget` estimates tokens as characters / 4 over each installed skill's name and description
(what agents load every session) and over the body (what loads on use). It reports unused skills
from `lock.json` usage timestamps and, from v0.2, from local transcripts.

## Project Brain integration (optional, v0.3)

If `.project-brain/` exists, `scout rate` appends one line to the ledger and can mirror it into the
brain, so the agent can check "what worked last time for this kind of task" before searching.
There is no hard dependency in either direction.
