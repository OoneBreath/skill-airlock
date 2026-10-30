# Roadmap

Ordered by what makes the tool useful soonest. Versions are targets, not promises.

## v0.1: find, vet, use (MVP)

The smallest version that does the whole loop safely.

- [ ] `scout sync`: mirror catalogs from `sources.json` (GitHub repos, shallow, pinned to a commit)
- [ ] `scout find <words>`: offline keyword search over the local index; the agent reranks
- [ ] `scout fetch <skill>`: copy into quarantine and record the source commit and file hashes
- [ ] `scout audit <skill>`: static rules with evidence lines (see [design](docs/design.md#audit))
- [ ] `scout use <skill>`: `once` mode; prints the path so the agent can read it, installs nothing
- [ ] `scout add <skill> --temp 7d | --keep`: install into the Claude Code and `.agents/` directories
- [ ] `scout gc`: remove expired `temp` installs (also runnable from a SessionStart hook)
- [ ] `scout budget`: description token cost of installed skills, plus unused ones
- [ ] `SKILL.md`: the agent workflow (task → find → present → audit → ask → use → unload)
- [ ] Tests for the audit rules (malicious fixtures included in `tests/fixtures/`)

## v0.2: keep it under control

- [ ] `scout update`: show the diff against the pinned commit, re-audit, ask before applying
- [ ] Trust list and blocklist (authors, repos, specific commits)
- [ ] Profiles: a named set of skills per project or kind of work, switched in one command
- [ ] Overlap detection: skills with similar descriptions that compete to trigger
- [ ] Usage stats from local agent transcripts (which skills actually fire)
- [ ] `fork` mode for agents that support running a skill in a sub-agent

## v0.3: learn from use

- [ ] Ratings ledger: "skill X for task type Y: good / poor, why", optionally mirrored into Project Brain
- [ ] Gap detection: spot a task you repeat that no skill covers, and offer to draft one
- [ ] Fork & adapt: a local copy tuned to you, tracking upstream so updates still show a diff
- [ ] Network-less dry run of bundled scripts in a sandbox, to catch "phone home" behaviour
- [ ] More agents: Gemini CLI, Cursor, Copilot, OpenCode, …, with one install linked into several

## Later / maybe

- Session distillation: turn a successful session into a new skill draft
- Skill chains: plan an ordered set of skills for a larger task
- Before/after mini-eval on your own sample task before installing
- Sync approved skills across your machines via a private git repo
