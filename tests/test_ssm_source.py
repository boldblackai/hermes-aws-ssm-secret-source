"""Unit tests for the aws_ssm secret source — mocked boto3, no AWS calls."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agent.secret_sources.base import FetchResult  # noqa: E402

from __init__ import SsmSource  # noqa: E402


def _make_param(name: str, value: str, ptype: str = "SecureString") -> dict:
    return {"Name": name, "Value": value, "Type": ptype}


def _mock_ssm_client(
    params: list[dict], invalid: list[str] | None = None
) -> MagicMock:
    """Build a mock boto3 SSM client whose get_parameters returns the given params."""
    client = MagicMock()
    client.get_parameters.return_value = {
        "Parameters": params,
        "InvalidParameters": invalid or [],
    }
    return client


def _run_fetch(
    source: SsmSource, cfg: dict, home_path: Path, mock_client: MagicMock
) -> FetchResult:
    """Run source.fetch() with a mocked boto3 client injected."""
    mock_boto3 = MagicMock()
    mock_boto3.client.return_value = mock_client

    botocore_mock = MagicMock()
    botocore_mock.exceptions.BotoCoreError = Exception
    botocore_mock.exceptions.ClientError = Exception
    botocore_mock.exceptions.EndpointConnectionError = Exception
    botocore_mock.exceptions.NoCredentialsError = Exception
    botocore_mock.config.Config = MagicMock()

    with (
        patch.dict(sys.modules, {"boto3": mock_boto3}),
        patch.dict(sys.modules, {"botocore": botocore_mock}),
        patch.dict(sys.modules, {"botocore.config": botocore_mock.config}),
        patch.dict(sys.modules, {"botocore.exceptions": botocore_mock.exceptions}),
    ):
        return source.fetch(cfg, home_path)


@pytest.fixture
def source():
    return SsmSource()


@pytest.fixture
def tmp_home(tmp_path):
    return tmp_path


# ── config validation ────────────────────────────────────────────────────


class TestConfigValidation:
    def test_missing_env_returns_not_configured(self, source, tmp_home):
        result = source.fetch({"enabled": True}, tmp_home)
        assert not result.ok
        assert result.error_kind is not None
        assert result.secrets == {}

    def test_env_not_a_dict_returns_not_configured(self, source, tmp_home):
        result = source.fetch({"enabled": True, "env": "not-a-dict"}, tmp_home)
        assert not result.ok
        assert result.secrets == {}

    def test_env_empty_dict_returns_not_configured(self, source, tmp_home):
        result = source.fetch({"enabled": True, "env": {}}, tmp_home)
        assert not result.ok
        assert result.secrets == {}

    def test_malformed_config_does_not_raise(self, source, tmp_home):
        """Every degenerate config must produce a FetchResult, never raise."""
        for cfg in (None, [], "string", 42, {"env": None}, {"env": []}):
            result = source.fetch(cfg if isinstance(cfg, dict) else {}, tmp_home)
            assert result is not None

    def test_invalid_ssm_path_skipped(self, source, tmp_home):
        cfg = {"env": {"VALID_KEY": ""}}
        result = source.fetch(cfg, tmp_home)
        assert not result.ok
        assert result.secrets == {}


# ── SecureString enforcement ─────────────────────────────────────────────


class TestSecureStringEnforcement:
    def test_securestring_accepted(self, source, tmp_home):
        mock_client = _mock_ssm_client([
            _make_param("/app/key1", "secret-value-1"),
        ])
        cfg = {"env": {"API_KEY": "/app/key1"}}
        result = _run_fetch(source, cfg, tmp_home, mock_client)
        assert result.ok
        assert result.secrets == {"API_KEY": "secret-value-1"}

    def test_plaintext_string_skipped(self, source, tmp_home):
        mock_client = _mock_ssm_client([
            _make_param("/app/key1", "secret-value-1", ptype="SecureString"),
            _make_param("/app/key2", "plaintext-value", ptype="String"),
        ])
        cfg = {"env": {"KEY1": "/app/key1", "KEY2": "/app/key2"}}
        result = _run_fetch(source, cfg, tmp_home, mock_client)
        assert result.ok
        assert "KEY1" in result.secrets
        assert "KEY2" not in result.secrets
        assert any("SecureString" in w for w in result.warnings)

    def test_stringlist_skipped(self, source, tmp_home):
        mock_client = _mock_ssm_client([
            _make_param("/app/key1", "a,b,c", ptype="StringList"),
        ])
        cfg = {"env": {"KEY1": "/app/key1"}}
        result = _run_fetch(source, cfg, tmp_home, mock_client)
        assert result.ok
        assert result.secrets == {}
        assert any("SecureString" in w for w in result.warnings)


# ── value validation ────────────────────────────────────────────────────


class TestValueValidation:
    def test_empty_value_skipped(self, source, tmp_home):
        mock_client = _mock_ssm_client([
            _make_param("/app/key1", ""),
        ])
        cfg = {"env": {"KEY1": "/app/key1"}}
        result = _run_fetch(source, cfg, tmp_home, mock_client)
        assert result.ok
        assert "KEY1" not in result.secrets
        assert any("empty" in w for w in result.warnings)

    def test_nul_byte_rejected(self, source, tmp_home):
        mock_client = _mock_ssm_client([
            _make_param("/app/key1", "bad\x00value"),
        ])
        cfg = {"env": {"KEY1": "/app/key1"}}
        result = _run_fetch(source, cfg, tmp_home, mock_client)
        assert result.ok
        assert "KEY1" not in result.secrets
        assert any("NUL" in w for w in result.warnings)


# ── batching ────────────────────────────────────────────────────────────


class TestBatching:
    def test_batch_over_10_params(self, source, tmp_home):
        """More than 10 params should trigger multiple GetParameters calls."""
        params: list[dict] = []
        env_map: dict[str, str] = {}
        for i in range(15):
            path = f"/app/key{i}"
            params.append(_make_param(path, f"value-{i}"))
            env_map[f"KEY_{i:02d}"] = path

        mock_client = MagicMock()
        mock_client.get_parameters.side_effect = [
            {"Parameters": params[:10], "InvalidParameters": []},
            {"Parameters": params[10:], "InvalidParameters": []},
        ]

        cfg = {"env": env_map}
        result = _run_fetch(source, cfg, tmp_home, mock_client)
        assert result.ok
        assert len(result.secrets) == 15
        assert mock_client.get_parameters.call_count == 2

    def test_invalid_parameter_skipped(self, source, tmp_home):
        mock_client = _mock_ssm_client(
            [_make_param("/app/exists", "value")],
            invalid=["/app/missing"],
        )
        cfg = {"env": {"EXISTS": "/app/exists", "MISSING": "/app/missing"}}
        result = _run_fetch(source, cfg, tmp_home, mock_client)
        assert result.ok
        assert result.secrets == {"EXISTS": "value"}
        assert any("not found" in w for w in result.warnings)


# ── error handling ──────────────────────────────────────────────────────


class TestErrorHandling:
    def test_boto3_missing(self, source, tmp_home, monkeypatch):
        """Missing boto3 returns BINARY_MISSING, not a crash."""
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "boto3":
                raise ImportError("boto3 not found")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        cfg = {"env": {"KEY": "/app/key"}}
        result = source.fetch(cfg, tmp_home)
        assert not result.ok
        assert "boto3" in result.error.lower()


# ── helper functions ────────────────────────────────────────────────────


class TestHelpers:
    def test_is_valid_env_name(self):
        from __init__ import _is_valid_env_name

        assert _is_valid_env_name("API_KEY")
        assert _is_valid_env_name("_PRIVATE")
        assert _is_valid_env_name("A")
        assert not _is_valid_env_name("")
        assert not _is_valid_env_name("1INVALID")
        assert not _is_valid_env_name("has-dash")
        assert not _is_valid_env_name("has space")

    def test_bool_parser(self):
        from __init__ import _bool

        assert _bool(True) is True
        assert _bool(False) is False
        assert _bool("true") is True
        assert _bool("yes") is True
        assert _bool("1") is True
        assert _bool("on") is True
        assert _bool("false") is False
        assert _bool("anything") is False
        assert _bool(None) is True  # default
        assert _bool(None, default=False) is False

    def test_str_or_empty(self):
        from __init__ import _str_or_empty

        assert _str_or_empty("  us-east-1  ") == "us-east-1"
        assert _str_or_empty("") == ""
        assert _str_or_empty(None) == ""
        assert _str_or_empty(42) == ""
        assert _str_or_empty([]) == ""


# ── config_schema / override_existing ───────────────────────────────────


class TestConfigInterface:
    def test_config_schema_has_env(self, source):
        schema = source.config_schema()
        assert "env" in schema
        assert "region" in schema
        assert "override_existing" in schema

    def test_override_existing_default_true(self, source):
        assert source.override_existing({}) is True

    def test_override_existing_explicit_false(self, source):
        assert source.override_existing({"override_existing": False}) is False
