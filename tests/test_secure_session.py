"""Unit tests for per-account storage in secure_session.

Paths are resolved from AMAZON_ORDERS_MCP_ACCOUNT at import time, so each
test reloads the module under a patched environment and home directory.
"""

import importlib
from pathlib import Path

import pytest

from amazon_orders_mcp import secure_session


@pytest.fixture
def reload_with(monkeypatch, tmp_path):
    """Reload secure_session with HOME=tmp_path and the given account env."""

    def _reload(account):
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        if account is None:
            monkeypatch.delenv(secure_session.ACCOUNT_ENV_VAR, raising=False)
        else:
            monkeypatch.setenv(secure_session.ACCOUNT_ENV_VAR, account)
        return importlib.reload(secure_session)

    yield _reload
    monkeypatch.undo()
    importlib.reload(secure_session)


class TestSingleAccountMode:
    def test_original_locations(self, reload_with, tmp_path):
        ss = reload_with(None)
        assert ss.ACCOUNT is None
        assert ss.COOKIE_JAR_PATH == tmp_path / ".amazon-orders-mcp" / "cookies.json"
        assert ss.KEYRING_SERVICE == "com.mcp.amazon-orders-mcp"
        assert ss.capture_command() == "uv run python cookie_capture.py"

    def test_blank_env_is_single_account(self, reload_with):
        assert reload_with("  ").ACCOUNT is None

    def test_ensure_data_dir_leaves_home_alone(self, reload_with, tmp_path):
        tmp_path.chmod(0o755)
        ss = reload_with(None)
        ss.ensure_data_dir()
        assert (tmp_path.stat().st_mode & 0o777) == 0o755
        assert (ss.DATA_DIR.stat().st_mode & 0o777) == 0o700


class TestNamedAccount:
    def test_isolated_locations(self, reload_with, tmp_path):
        ss = reload_with("Bob")
        assert ss.ACCOUNT == "bob"
        expected_dir = tmp_path / ".amazon-orders-mcp" / "accounts" / "bob"
        assert ss.DATA_DIR == expected_dir
        assert ss.COOKIE_JAR_PATH == expected_dir / "cookies.json"
        assert ss.OUTPUT_DIR == expected_dir / "output"
        assert ss.KEYRING_SERVICE == "com.mcp.amazon-orders-mcp.bob"
        assert ss.capture_command() == ("uv run python cookie_capture.py --account bob")

    def test_accounts_do_not_share_a_jar(self, reload_with):
        alice = reload_with("alice").COOKIE_JAR_PATH
        bob = reload_with("bob").COOKIE_JAR_PATH
        assert alice != bob

    def test_ensure_data_dir_permissions(self, reload_with, tmp_path):
        tmp_path.chmod(0o755)
        ss = reload_with("alice")
        ss.ensure_data_dir()
        for d in (ss.BASE_DIR, ss.BASE_DIR / "accounts", ss.DATA_DIR):
            assert (d.stat().st_mode & 0o777) == 0o700
        assert (tmp_path.stat().st_mode & 0o777) == 0o755

    @pytest.mark.parametrize("bad", ["../etc", "a/b", "-alice", "x" * 33, "alice bob"])
    def test_rejects_unsafe_names(self, reload_with, bad):
        with pytest.raises(ValueError, match="not a valid account name"):
            reload_with(bad)
