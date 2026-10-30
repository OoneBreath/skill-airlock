# Contributing to Skill Airlock

The project is in its design phase, so the most useful contributions right now are:

- **Audit rules**: a technique a malicious skill could use that the [design](docs/design.md#audit)
  doesn't cover. If it is a live technique, report it privately (see [SECURITY.md](SECURITY.md)).
- **Agent paths**: where a given agent reads skills from, with a link to its docs.
- **Design feedback**: open an issue before a PR for anything that changes behaviour.

## Pull request guidelines

1. Branch from `main`; one logical change per PR.
2. No new runtime dependencies: Bash and Python 3 stdlib only.
3. New audit rules come with a test fixture that triggers them and one that must not.
4. Update `CHANGELOG.md` for user-visible changes.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
