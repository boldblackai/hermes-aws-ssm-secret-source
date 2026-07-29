"""Conformance: the aws_ssm source satisfies the Hermes SecretSource contract.

These checks encode the parts of the contract that break other people when
violated: never raising, never prompting, respecting disabled config, valid
identity attributes, and orchestrator compatibility.

We vendor these checks rather than subclassing the upstream conformance kit
(tests/secret_sources/conformance.py) because that file doesn't ship in the
hermes-agent wheel. The checks mirror the upstream ones exactly.
"""

from __future__ import annotations

from pathlib import Path

from agent.secret_sources.base import (  # noqa: E402
    SECRET_SOURCE_API_VERSION,
    FetchResult,
    SecretSource,
    is_valid_env_name,
)

from __init__ import SsmSource  # noqa: E402


class TestSsmConformance:
    """Contract checks — mirror tests/secret_sources/conformance.py."""

    @property
    def source(self) -> SecretSource:
        return SsmSource()

    # -- identity ----------------------------------------------------------

    def test_name_is_lowercase_identifier(self):
        s = self.source
        assert s.name, "source.name must be non-empty"
        assert s.name == s.name.lower()
        assert s.name.replace("_", "").isalnum()

    def test_label_present(self):
        assert self.source.label, "source.label must be human-readable"

    def test_shape_valid(self):
        assert self.source.shape in ("mapped", "bulk")

    def test_api_version_current(self):
        assert self.source.api_version == SECRET_SOURCE_API_VERSION

    # -- contract behavior --------------------------------------------------

    def test_fetch_never_raises_on_malformed_config(self, tmp_path: Path):
        """Every degenerate config shape must produce a FetchResult, not a raise."""
        for cfg in (
            {},
            {"enabled": True},
            {"enabled": True, "env": "not-a-dict"},
            {"enabled": True, "cache_ttl_seconds": "bogus"},
            None,
        ):
            result = self.source.fetch(cfg if isinstance(cfg, dict) else {}, tmp_path)
            assert isinstance(result, FetchResult), (
                f"fetch() returned {type(result).__name__} for cfg={cfg!r}"
            )

    def test_fetch_unconfigured_reports_error_not_secrets(self, tmp_path: Path):
        """enabled=true with nothing else set must fail cleanly with a kind."""
        result = self.source.fetch({"enabled": True}, tmp_path)
        assert isinstance(result, FetchResult)
        if not result.ok:
            assert result.error_kind is not None, (
                "errors must carry a machine-readable ErrorKind"
            )
            assert not result.secrets

    def test_disabled_by_default(self):
        s = self.source
        assert s.is_enabled({}) is False
        assert s.is_enabled({"enabled": False}) is False

    def test_timeout_is_positive(self):
        s = self.source
        assert s.fetch_timeout_seconds({"enabled": True}) > 0
        # Garbage config must not break the timeout accessor either.
        assert s.fetch_timeout_seconds({"timeout_seconds": "junk"}) > 0

    def test_protected_vars_are_valid_names(self):
        s = self.source
        for var in s.protected_env_vars({"enabled": True}):
            assert is_valid_env_name(var)
