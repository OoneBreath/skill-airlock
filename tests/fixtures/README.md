# Test fixtures

Deliberately malicious-looking skills used to test the audit rules. They are inert: every URL uses
the reserved `.invalid` domain, and nothing here is run by the tests.

Each skill's file is named `SKILL.fixture.md` (not `SKILL.md`) so that no agent or skill installer
mistakes these for real skills. The tests copy them into a temporary catalog and rename the file.

| Fixture | Pretends to be | Actually |
|---|---|---|
| `clean` | table formatter | a table formatter (must stay clean) |
| `exfil` | table formatter | uploads `~/.ssh` to a remote host |
| `hidden` | commit helper | hidden instructions: HTML comment, zero-width and Unicode tag characters |
| `persistence` | shell theme | edits `~/.bashrc`, crontab and the agent's own permissions |
| `obfuscated` | CSV statistics | runs base64-encoded code |
