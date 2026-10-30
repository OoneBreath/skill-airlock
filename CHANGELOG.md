# Changelog

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
