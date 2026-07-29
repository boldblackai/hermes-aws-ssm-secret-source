# AGENTS.md — hermes-aws-ssm-secret-source

## What this is

A Hermes Agent secret-source plugin that resolves AWS SSM `SecureString`
parameters into env vars at startup. **Mapped shape** — only parameters
explicitly listed in `secrets.aws_ssm.env` are fetched. This is the security
boundary: an SSM writer cannot inject arbitrary env vars.

For install, configure, and IAM docs, see **README.md**. This file covers only
what an agent needs to edit the code safely.

## Toolchain (P003/P010)

- **Python >=3.13** (version pinned in `mise.toml` and `.python-version`).
- **mise** manages the Python runtime. Activate: `eval "$(mise activate bash)"`.
- **uv** is the dev tool. No `requirements.txt`; lock is `uv.lock`.
- Dev dependencies (optional `[dev]` extra): **pytest** (tests), **ruff**
  (linter), **ty** (type checker).
- There is no bare `python`/`pip` on PATH; the environment is PEP 668 (use `uv`).
  Run Python via `uv run python ...`.

## Layout

This is a **flat directory plugin** — `__init__.py` and `plugin.yaml` live at
the repo root. Hermes discovers it via `hermes plugins install <github-url>`,
which clones the repo into `~/.hermes/plugins/<name>/` and imports
`__init__.py` directly. Do not move to a `src/` layout — it would break
directory-plugin discovery.

## Lint, type-check, test

CI (`.github/workflows/ci.yml`) runs these on every push/PR — run them locally
before committing:

```
uv run ruff check .     # linter (config in [tool.ruff])
uv run ty check .       # type checker
uv run pytest           # tests
```

CI uses `jdx/mise-action` (P016) to install Python from `mise.toml` — there is
no separate `setup-python` step. The action is SHA-pinned per P002.

## CI tool versions

CI installs its tools with `jdx/mise-action`, which reads `mise.toml` and puts
every declared tool on PATH for the job. There are no per-tool `curl` or
`setup-*` steps for mise-managed tools.

- To change a tool version in CI, change it in `mise.toml` and push — there is
  no separate CI version to update.
- The action is SHA-pinned with a version comment, like every other action (P002).
- Do not add a hand-rolled install step for a tool that is already in `mise.toml`.

## Conventions

- **fetch() must never raise.** The SecretSource contract requires errors to go
  in `result.error` / `result.error_kind`, not exceptions. The orchestrator's
  `_fetch_with_timeout` catches them, but the contract is the contract.
- **fetch() must never prompt.** Startup runs in non-TTY contexts (gateway, cron).
- **You fetch; the orchestrator applies.** Never write `os.environ` directly.
- **SecureString only.** Plaintext `String`/`StringList` params are skipped with
  a warning. This is intentional — there is no reason not to encrypt.
- **No path normalization.** Env-var names come from the `env:` map keys,
  not derived from SSM paths.
