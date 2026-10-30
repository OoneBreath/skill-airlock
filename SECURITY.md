# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than in a public issue.

- **Email:** info@fixflex.co.uk
- Include: a description, steps to reproduce, and the affected version (see `version` in
  `skills/skill-scout/SKILL.md` / `.claude-plugin/plugin.json`).

You can expect an acknowledgement within a few days. Fixes are noted in `CHANGELOG.md`.

## Reporting an audit bypass

Skill Scout's audit is a static filter. A skill that does something harmful and passes the audit
clean is a bug worth reporting. Please send the skill (or a minimal reproduction) by email rather
than publishing it, so the rule can be fixed before the technique spreads.

## Scope and limits

- Skill Scout sends no telemetry. Its only network access is fetching from the sources listed in
  `~/.skill-scout/sources.json`.
- A clean audit means "nothing known was found", not "safe". Review the evidence and the scripts of
  anything you install.
- Skill Scout runs with the same permissions as your agent session.

## Supported versions

Only the latest released version receives fixes.
