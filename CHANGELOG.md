# Changelog

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
