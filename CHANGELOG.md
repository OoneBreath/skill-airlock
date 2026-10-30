# Changelog

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
