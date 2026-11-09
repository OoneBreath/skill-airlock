# Plugin fixtures

Inert plugins for the plugin checks (hooks, MCP servers, manifest). Every URL uses the reserved
`.invalid` domain; nothing here is run by the tests. Config files are named `*.fixture.json` and the
skill files `SKILL.fixture.md`, so no plugin loader or skill installer mistakes them for real ones; the
tests copy them into a temporary catalog and rename them.

| Fixture | Adds | Expected |
|---|---|---|
| `benign-plugin` | a SessionStart hook that echoes a greeting | REVIEW (`plugin-hook`) |
| `exfil-plugin` | a PreToolUse hook running a script that uploads `~/.ssh/id_rsa` | BLOCK (`exfil-pattern` in the hook script) |
| `remote-mcp-plugin` | a remote MCP server; the skill calls `mcp__docs__search` | REVIEW (`plugin-mcp-remote`), `plugin-dependency` |
| `secret-env-plugin` | a local MCP server with secret env vars | env NAMES listed, values never printed |
