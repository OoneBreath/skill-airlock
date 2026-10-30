# Skill Airlock — find, vet, use and unload agent skills

**Give your agent a task. It finds the right skills, checks them before they touch your machine,
uses them, and cleans up afterwards.**

[![Status](https://img.shields.io/badge/status-design%20phase-orange)](ROADMAP.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Runtime deps](https://img.shields.io/badge/runtime%20deps-zero-success)](docs/design.md)
[![Telemetry](https://img.shields.io/badge/telemetry-none-success)](#privacy)

> **Status: design phase.** This repo currently holds the design and the plan, not working code.
> See [ROADMAP.md](ROADMAP.md) for what ships in v0.1.

Skill Airlock is a skill for AI coding agents (Claude Code, Codex, Gemini CLI, Cursor, Copilot,
OpenCode, and anything else that reads `SKILL.md`). It manages *other* skills. You don't search a
marketplace yourself; you tell the agent what you want done:

```
> Build me a changelog from the last 40 commits. Pick suitable skills for this.
```

The agent searches a **local** index, shows you what fits and what each candidate does, audits the
one you pick in quarantine, asks before installing, and once the task is done the skill is gone
unless you chose to keep it.

---

## The problem

The skills ecosystem grew fast, and the tooling around it is built for "find it and install it
quickly". That leaves three problems:

- **Your task leaks.** Marketplace search and CLI telemetry send your query (which is usually your
  task) to a third party.
- **You install code from strangers.** A skill is instructions *and* scripts that your agent runs
  with your permissions, next to your `.env`, your SSH keys and your production config. A skill can
  also change after you installed it.
- **Context bloat.** Every installed skill puts its name and description into every session. Fifty
  skills mean thousands of tokens per session spent on tools you aren't using, and more
  near-duplicates competing to trigger.

## The approach

Think of a spacecraft airlock: nothing gets in without passing through the chamber first, and
what is no longer needed goes back out the same way.

```
task ─▶ find (offline) ─▶ quarantine ─▶ audit ─▶ you decide ─▶ use ─▶ unload
                                                     │
                                         once · temp · keep · fork
```

| Step | What happens |
|---|---|
| **Find** | `airlock sync` mirrors skill catalogs from sources you trust. Search runs locally, and the agent itself ranks candidates by reading their descriptions, so your query never leaves the machine. |
| **Quarantine** | A candidate is fetched into `~/.skill-airlock/quarantine/`, outside every agent's skills directory, so nothing can load it yet. |
| **Audit** | Static checks with evidence: network calls, secret paths, obfuscation, persistence, hidden or injected instructions in the Markdown, and a mismatch between what the skill *says* it does and what its scripts *actually* do. |
| **Decide** | You see the findings and choose a mode. Nothing installs without your yes. |
| **Use** | The skill runs in the mode you picked (below). |
| **Unload** | Temporary installs expire and are garbage-collected. Kept skills are pinned to an exact commit, and an update shows you the diff first. |

### Modes

| Mode | On disk | Loads into future sessions | When to use |
|---|---|---|---|
| `once` | quarantine only | no | One-off task. The agent reads the skill once and follows it. |
| `temp` | installed with an expiry | until it expires | A few days of related work. |
| `keep` | installed and pinned | yes | Skills you use all the time. |
| `fork` | installed, runs in a sub-agent | description only | Large skills: the main conversation gets only the result. |

### Context budget

```
$ airlock budget
30 skills installed · ~4,200 tokens per session in descriptions
18 not used in 30 days (~2,500 tokens) → airlock vent --unused 30d
2 overlap: "pdf-tools" ↔ "pdf-extract" (similar descriptions; may trigger unpredictably)
```

## Privacy

- No telemetry, ever. No accounts, no server.
- Search is local. The only network traffic is `airlock sync` / `inspect` talking to the git hosts of
  sources **you** listed.
- Usage history and ratings stay in `~/.skill-airlock/` on your machine.

## Works across agents

`SKILL.md` is a shared format. Skill Airlock installs into each agent's own directory
(`~/.claude/skills/`, `~/.agents/skills/`, `~/.gemini/skills/`, …) and can install the same
pinned skill into several agents at once.

## Pairs with Project Brain

Optional: with [Project Brain](https://github.com/OoneBreath/claude-code-project-brain) present,
Skill Airlock records which skill worked for which kind of task and which didn't. The next time a
similar task comes up, the agent already knows, without searching.

## What it is not

- **Not a security certificate.** The audit is static and heuristic. It surfaces evidence for
  you to review; it doesn't prove a skill is safe.
- **Not a marketplace.** It indexes the sources you choose.

## Author

Slawomir Luzny · [FixFlex](https://fixflex.co.uk) · also the author of
[Project Brain](https://github.com/OoneBreath/claude-code-project-brain).

## License

[MIT](LICENSE)
