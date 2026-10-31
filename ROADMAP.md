# Roadmap

Ordered by what makes the tool useful soonest. Versions are targets, not promises.

## v0.1: find, vet, use, vent ✓

- [x] `airlock sync`: shallow mirrors of `github` / `git` sources, `path` sources indexed in place
- [x] `airlock find`: offline keyword search over the local index; the agent judges fit
- [x] `airlock inspect`: quarantine copy, sha256 per file, static audit with evidence
- [x] `airlock audit`: audit any directory in place, or `--installed` for everything you have
- [x] `airlock use`: `once` mode, nothing installed
- [x] `airlock dock --temp | --keep`: install into Claude Code and the shared `~/.agents/skills/`
- [x] `airlock vent`: remove what Airlock installed; `--expired` from a SessionStart hook
- [x] `airlock verify`: installed files against the lock
- [x] `airlock budget`: per-session token cost, unused skills (local transcripts), overlaps
- [x] Context-aware severity, calibrated on all 62 skills of three public catalogs
- [x] Tests, including malicious fixtures (exfiltration, hidden instructions, persistence, obfuscation)

## v0.2: keep it under control

- [ ] `airlock update`: show the diff against the pinned commit and **what the audit says now that it
      didn't before** (e.g. "new network access in scripts/sync.sh"); ask before applying
- [ ] Trust list and blocklist (authors, repos, specific commits). A skill with scripts from a source
      that isn't on the trust list is REVIEW at least, whatever the static rules find: they can be evaded
- [ ] Sandboxed runs of a skill's bundled scripts where the OS provides one (no network, read-only
      outside a work dir). Instructions the agent follows can't be sandboxed this way; scripts can.
- [ ] Decision log: who approved which skill, at which commit and audit verdict, for how long, and
      when and why it was vented (`lock.json` already records the install side)
- [ ] Profiles: a named set of skills per project or kind of work, switched in one command
- [ ] Plugin and built-in skills in `budget`
- [ ] Usage counts per skill in `budget` (not just last use)

## v0.3: learn from use

- [ ] Local ratings ledger: "worked 24×, failed 2×" per skill and task type, no central server;
      optionally mirrored into Project Brain so the agent knows what to rent next time
- [ ] Gap detection: a task you repeat that no skill covers, with an offer to draft one
- [ ] Fork & adapt: a local copy tuned to you, tracking upstream so updates still show a diff
- [ ] More agents: Gemini CLI, Cursor, Copilot, OpenCode, …, after checking each one's docs
- [ ] `fork` mode for agents that can run a skill in a sub-agent

## Later / maybe

- Local trust signals next to the audit (source tier, pinned commit, age, your own history).
  Deliberately no single "trust score": a number hides the evidence the audit is there to show.
- Session distillation: turn a successful session into a new skill draft
- Skill chains: an ordered set of skills for a larger task
- Sync approved skills across your machines via a private git repo
