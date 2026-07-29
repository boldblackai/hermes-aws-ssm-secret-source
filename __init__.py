"""AWS SSM Parameter Store secret source — Hermes plugin.

Resolves individual SSM ``SecureString`` parameters into environment variables
at Hermes startup — after ``.env`` loads, before Hermes reads credentials. On
ECS the botocore credential chain resolves the **task role** via the container
credential endpoint, so no explicit AWS credentials need to live in ``.env``.

Shape is ``mapped``: the operator explicitly binds each environment-variable
name to a specific SSM parameter path in ``secrets.aws_ssm.env``. Only
parameters listed there are fetched — an SSM writer cannot inject arbitrary
env vars. Only ``SecureString`` parameters are accepted; ``String`` and
``StringList`` are skipped with a warning (use KMS-backed encryption).

Install::

    hermes plugins install boldblackai/hermes-aws-ssm-secret-source --enable

``register(ctx)`` calls ``ctx.register_secret_source(SsmSource())``.

REQUIRES Hermes with NousResearch/hermes-agent#64189 ("re-pull plugin secret
sources after discovery"). On older Hermes the plugin registers but is NOT
consulted by the first ``load_hermes_dotenv()`` (the bootstrap-timing gap,
#64177) — so secrets won't reach the gateway/interactive sessions. (Cron-
triggered sessions work even without #64189, since the scheduler re-pulls.)

Contract reference:
    https://hermes-agent.nousresearch.com/docs/developer-guide/secret-source-plugin
"""

from __future__ import annotations

import logging
from pathlib import Path

from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource

logger = logging.getLogger(__name__)

# AWS GetParameters accepts at most 10 names per call.
_BATCH_SIZE = 10


class SsmSource(SecretSource):
    name = "aws_ssm"
    label = "AWS SSM Parameter Store"
    shape = "mapped"
    # No URI ``scheme`` — SSM params are path-addressed, not URI-addressed.

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        """Resolve explicitly-mapped SSM parameters into a {ENV_VAR: value} dict.

        Never raises — errors go in ``result.error`` / ``result.error_kind``
        per the SecretSource contract.
        """
        result = FetchResult()

        if not isinstance(cfg, dict):
            cfg = {}

        # ── Validate the env→path map ───────────────────────────────────
        env_map = cfg.get("env")
        if not isinstance(env_map, dict) or not env_map:
            result.error = (
                "secrets.aws_ssm.env is required (a mapping of "
                "ENV_VAR_NAME -> /ssm/param/path)."
            )
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        valid: dict[str, str] = {}
        for env_name, ssm_path in env_map.items():
            if not isinstance(env_name, str) or not _is_valid_env_name(env_name):
                _note(result, f"env key {env_name!r} is not a valid env-var name; skipped.")
                continue
            if not isinstance(ssm_path, str) or not ssm_path.strip():
                _note(result, f"env[{env_name!r}] has no SSM path; skipped.")
                continue
            path = ssm_path.strip()
            if not path.startswith("/"):
                path = "/" + path
            valid[env_name] = path

        if not valid:
            result.error = "No valid env→SSM-path bindings in secrets.aws_ssm.env."
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        region = _str_or_empty(cfg.get("region"))

        # ── Create boto3 client ─────────────────────────────────────────
        try:
            import boto3
            from botocore.config import Config
            from botocore.exceptions import (
                BotoCoreError,
                ClientError,
                EndpointConnectionError,
                NoCredentialsError,
            )
        except ImportError:
            result.error = (
                "boto3 is not installed. The harness image ships it (Bedrock); "
                "outside that image, install it in the Hermes venv "
                "(pip install boto3)."
            )
            result.error_kind = ErrorKind.BINARY_MISSING
            return result

        try:
            client_kwargs: dict = {}
            if region:
                client_kwargs["region_name"] = region
            client_kwargs["config"] = Config(
                connect_timeout=5,
                read_timeout=15,
                retries={"max_attempts": 3, "mode": "standard"},
            )
            client = boto3.client("ssm", **client_kwargs)
        except Exception as exc:  # malformed region / config
            result.error = f"Failed to create SSM client: {exc}"
            result.error_kind = ErrorKind.INTERNAL
            return result

        # ── Fetch parameters in batches of 10 ───────────────────────────
        #
        # GetParameters resolves all names server-side in one call. A name
        # that doesn't exist is listed in InvalidParameters rather than
        # raising — we warn per-ref and continue with the rest.
        secrets: dict[str, str] = {}
        items = list(valid.items())

        try:
            for i in range(0, len(items), _BATCH_SIZE):
                batch = items[i : i + _BATCH_SIZE]
                batch_env_names = [e for e, _ in batch]
                batch_paths = [p for _, p in batch]

                resp = client.get_parameters(
                    Names=batch_paths,
                    WithDecryption=True,
                )

                params_by_name: dict[str, dict] = {}
                for param in resp.get("Parameters", []):
                    params_by_name[param["Name"]] = param

                invalid = set(resp.get("InvalidParameters", []))

                for j, ssm_path in enumerate(batch_paths):
                    env_name = batch_env_names[j]
                    param = params_by_name.get(ssm_path)

                    if param is None:
                        if ssm_path in invalid:
                            _note(result, f"SSM parameter '{ssm_path}' not found.")
                        else:
                            _note(result, f"SSM parameter '{ssm_path}' returned no result.")
                        continue

                    ptype = param.get("Type", "")
                    if ptype != "SecureString":
                        _note(
                            result,
                            f"SSM parameter '{ssm_path}' is type '{ptype}', "
                            "not SecureString; skipped.",
                        )
                        continue

                    value = param.get("Value", "")
                    if value == "":
                        _note(result, f"SSM parameter '{ssm_path}' is empty; skipped.")
                        continue
                    if "\x00" in value:
                        _note(result, f"SSM parameter '{ssm_path}' contains NUL byte; skipped.")
                        continue

                    secrets[env_name] = value

        except NoCredentialsError:
            result.error = (
                "No AWS credentials found. On ECS this resolves via the task "
                "role; elsewhere set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY "
                "or AWS_PROFILE."
            )
            result.error_kind = ErrorKind.AUTH_FAILED
            return result
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in (
                "AccessDeniedException",
                "UnrecognizedClientException",
                "ExpiredTokenException",
            ):
                result.error = f"SSM access denied ({code})."
                result.error_kind = ErrorKind.AUTH_FAILED
            elif code in ("ThrottlingException", "RequestLimitExceeded"):
                result.error = f"SSM throttled ({code})."
                result.error_kind = ErrorKind.NETWORK
            else:
                result.error = f"SSM error ({code})."
                result.error_kind = ErrorKind.NETWORK
            return result
        except (EndpointConnectionError, BotoCoreError) as exc:
            result.error = f"SSM connection failed: {exc}"
            result.error_kind = ErrorKind.NETWORK
            return result
        except Exception as exc:  # never raise out of fetch()
            result.error = f"Unexpected SSM fetch error: {exc}"
            result.error_kind = ErrorKind.INTERNAL
            return result

        if not secrets:
            _note(result, "No usable parameters resolved — check paths and types.")

        result.secrets = secrets
        return result

    def override_existing(self, cfg: dict) -> bool:
        """Override .env/shell values so centrally-rotated keys take effect."""
        return _bool(cfg.get("override_existing"), default=True)

    def config_schema(self) -> dict:
        return {
            "env": {
                "description": (
                    "Mapping of ENV_VAR_NAME → /ssm/param/path. Only "
                    "parameters listed here are fetched."
                ),
                "default": {},
            },
            "region": {
                "description": (
                    "AWS region (empty = botocore default chain: AWS_REGION / "
                    "profile / ECS task role)"
                ),
                "default": "",
            },
            "override_existing": {
                "description": (
                    "Overwrite .env/shell values (default true — rotate "
                    "centrally without .env edits)"
                ),
                "default": True,
            },
        }


def register(ctx):
    """Plugin entry point — Hermes calls this on discovery."""
    ctx.register_secret_source(SsmSource())


# ── helpers ──────────────────────────────────────────────────────────────


def _is_valid_env_name(name: str) -> bool:
    """True when ``name`` is a legal environment-variable name.

    POSIX: [A-Za-z_][A-Za-z0-9_]*  — must not be empty, must start with a
    letter or underscore, must contain only alphanumeric + underscore.
    """
    if not name:
        return False
    if not (name[0].isalpha() or name[0] == "_"):
        return False
    return all(ch.isalnum() or ch == "_" for ch in name)


def _str_or_empty(v) -> str:
    if isinstance(v, str):
        return v.strip()
    return ""


def _bool(v, default: bool = True) -> bool:
    """Lenient bool parse for YAML/string/bool config values."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes", "on")
    return default


def _note(result: FetchResult, msg: str) -> None:
    """Record a warning on the FetchResult if it carries a warnings list.

    ``FetchResult.warnings`` is not part of the documented public contract, so
    record defensively: append when present, otherwise fall back to the logger.
    A missing attribute must never raise out of ``fetch()``.
    """
    warnings = getattr(result, "warnings", None)
    if isinstance(warnings, list):
        warnings.append(msg)
    else:
        logger.warning("aws_ssm: %s", msg)
