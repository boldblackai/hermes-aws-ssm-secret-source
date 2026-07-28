"""AWS SSM Parameter Store secret source — publishable Hermes plugin.

Resolves SSM parameters (SecureString, String, StringList) under a configured
path prefix into environment variables at Hermes startup — after ``.env``
loads, before Hermes reads credentials. On ECS the botocore credential chain
resolves the **task role** via the container credential endpoint, so no
explicit AWS credentials need to live in ``.env``.

Shape is ``bulk``: every parameter under ``path`` is injected, and the source
yields to ``mapped`` sources (Bitwarden / 1Password) on contested vars.

This is the plugin form (``hermes plugins install boldblackai/hermes-aws-ssm-secret-source``);
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
import re
from pathlib import Path
from typing import Dict

from agent.secret_sources.base import ErrorKind, FetchResult, SecretSource

logger = logging.getLogger(__name__)

# Legal env-var name: uppercase [A-Z0-9_], must start with a letter or
# underscore. SSM param names that don't normalize to this shape are skipped.
_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


class SsmSource(SecretSource):
    name = "aws_ssm"
    label = "AWS SSM Parameter Store"
    shape = "bulk"
    # No URI ``scheme`` — SSM params are path-addressed, not URI-addressed.

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        """Resolve parameters under ``path`` into a {ENV_VAR: value} mapping.

        Never raises — errors go in ``result.error`` / ``result.error_kind``
        per the SecretSource contract.
        """
        result = FetchResult()

        path = _clean_path(cfg.get("path", ""))
        if not path:
            result.error = "secrets.aws_ssm.enabled is true but 'path' is not set."
            result.error_kind = ErrorKind.NOT_CONFIGURED
            return result

        region = str(cfg.get("region", "") or "").strip()  # "" → botocore default chain
        recursive = _bool(cfg.get("recursive"), default=True)

        # boto3 (in-process). The harness image ships it (Bedrock); the graceful
        # error path covers running the plugin outside that image.
        try:
            import boto3
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
            client_kwargs = {}
            if region:
                client_kwargs["region_name"] = region
            client = boto3.client("ssm", **client_kwargs)
        except Exception as exc:  # malformed region / config
            result.error = f"Failed to create SSM client: {exc}"
            result.error_kind = ErrorKind.INTERNAL
            return result

        # Paginated GetParametersByPath. KMS decryption is server-side: the
        # caller only needs kms:Decrypt on the key backing the params.
        secrets: Dict[str, str] = {}
        try:
            paginator = client.get_paginator("get_parameters_by_path")
            for page in paginator.paginate(Path=path, Recursive=recursive, WithDecryption=True):
                for param in page.get("Parameters", []):
                    full = param.get("Name", "")
                    name = _param_name_to_env_var(full, path)
                    if not name:
                        _note(result, f"SSM param '{full}' does not map to a valid env-var name; skipped.")
                        continue
                    value = param.get("Value", "")
                    if value == "":
                        # Never apply "" over a good credential (EMPTY_VALUE rule).
                        _note(result, f"SSM param '{full}' is empty; skipped.")
                        continue
                    secrets[name] = value
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
            if code in ("AccessDeniedException", "UnrecognizedClientException", "ExpiredTokenException"):
                result.error = f"SSM access denied ({code}): {exc}"
                result.error_kind = ErrorKind.AUTH_FAILED
            elif code in ("ThrottlingException", "RequestLimitExceeded"):
                result.error = f"SSM throttled ({code}): {exc}"
                result.error_kind = ErrorKind.NETWORK
            else:
                result.error = f"SSM error ({code}): {exc}"
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
            _note(result, f"No usable parameters found under '{path}' — empty namespace?")

        result.secrets = secrets
        return result

    # Bulk sources default to NOT overriding. For SSM as the claw's source of
    # truth we DO want to win over stale .env/shell values so a centrally-
    # rotated key takes effect without a .env edit. The orchestrator still
    # enforces "override never crosses sources" and bulk-yields-to-mapped.
    def override_existing(self, cfg: dict) -> bool:
        return _bool(cfg.get("override_existing"), default=True)

    def config_schema(self) -> dict:
        return {
            "path": {"description": "SSM parameter path prefix, e.g. /myclaw/", "default": ""},
            "region": {
                "description": "AWS region (empty = botocore default chain: AWS_REGION / profile / ECS task role)",
                "default": "",
            },
            "recursive": {"description": "Recurse into sub-paths under 'path'", "default": True},
            "override_existing": {
                "description": "Overwrite .env/shell values (default true — rotate centrally without .env edits)",
                "default": True,
            },
        }


def register(ctx):
    """Plugin entry point — Hermes calls this on discovery."""
    ctx.register_secret_source(SsmSource())


# ── helpers ──────────────────────────────────────────────────────────────


def _clean_path(p) -> str:
    """Normalize an SSM path: non-empty, starts and ends with '/'."""
    p = (p or "").strip()
    if not p:
        return ""
    if not p.startswith("/"):
        p = "/" + p
    if not p.endswith("/"):
        p = p + "/"
    return p


def _param_name_to_env_var(param_name: str, path_prefix: str) -> str:
    """Map an SSM parameter name to an env-var name.

    Examples (path_prefix = "/myclaw/"):
        /myclaw/OPENROUTER_API_KEY  -> OPENROUTER_API_KEY
        /myclaw/db/PASSWORD         -> DB_PASSWORD   (recursive subtree flattened)
        /myclaw/foo-bar             -> ""  (hyphen -> invalid env-var name, dropped)
    """
    name = param_name
    if path_prefix and name.startswith(path_prefix):
        name = name[len(path_prefix):]
    name = name.replace("/", "_").upper().lstrip("_")
    return name if _ENV_NAME_RE.match(name) else ""


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
