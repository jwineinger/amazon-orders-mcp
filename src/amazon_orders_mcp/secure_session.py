"""
Secure credential + cookie management for the Amazon Orders MCP server.

Credentials (email, password, optional TOTP secret) are stored in the system
keyring. Amazon session cookies are persisted by the amazon-orders library to
a data directory owned by this server (isolated from any other amazon-orders
usage on the host).

Several Amazon accounts can be used side by side: set
`AMAZON_ORDERS_MCP_ACCOUNT` (e.g. `alice`) and that account gets its own data
directory under `~/.amazon-orders-mcp/accounts/<name>/` and its own keyring
service. Run one MCP server per account. Without the variable, the original
single-account locations are used.
"""

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

ACCOUNT_ENV_VAR = "AMAZON_ORDERS_MCP_ACCOUNT"
_ACCOUNT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


def _account_from_env() -> Optional[str]:
    """Return the configured account name, or None for single-account mode."""
    raw = os.getenv(ACCOUNT_ENV_VAR, "").strip().lower()
    if not raw:
        return None
    if not _ACCOUNT_NAME_RE.match(raw):
        raise ValueError(
            f"{ACCOUNT_ENV_VAR}={raw!r} is not a valid account name. Use 1-32 "
            "lowercase letters, digits, '-' or '_', starting with a letter or digit."
        )
    return raw


# Which Amazon account this process serves (None = the original single account)
ACCOUNT: Optional[str] = _account_from_env()

# Keyring service identifier
KEYRING_SERVICE = "com.mcp.amazon-orders-mcp" + (f".{ACCOUNT}" if ACCOUNT else "")

# Keyring usernames — each credential component is stored under its own key
# so they can be updated independently.
KEY_EMAIL = "amazon-email"
KEY_PASSWORD = "amazon-password"
KEY_OTP_SECRET = "amazon-otp-secret"

# Data directory for cookies + library state
BASE_DIR = Path.home() / ".amazon-orders-mcp"
DATA_DIR = BASE_DIR / "accounts" / ACCOUNT if ACCOUNT else BASE_DIR
COOKIE_JAR_PATH = DATA_DIR / "cookies.json"
OUTPUT_DIR = DATA_DIR / "output"


@dataclass
class AmazonCredentials:
    """Credentials needed to log in to Amazon."""

    email: str
    password: str
    otp_secret_key: Optional[str] = None


def capture_command() -> str:
    """The cookie-capture command for this process's account."""
    suffix = f" --account {ACCOUNT}" if ACCOUNT else ""
    return f"uv run python cookie_capture.py{suffix}"


def ensure_data_dir() -> None:
    """Create the data directory (and its parents) with owner-only permissions."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    # Only directories this server owns — never DATA_DIR.parent, which is
    # the home directory in single-account mode.
    owned = [BASE_DIR, BASE_DIR / "accounts", DATA_DIR] if ACCOUNT else [BASE_DIR]
    for d in owned:
        try:
            d.chmod(0o700)
        except OSError:
            pass


def save_credentials(creds: AmazonCredentials) -> None:
    """Persist credentials to the system keyring."""
    import keyring

    keyring.set_password(KEYRING_SERVICE, KEY_EMAIL, creds.email)
    keyring.set_password(KEYRING_SERVICE, KEY_PASSWORD, creds.password)
    if creds.otp_secret_key:
        keyring.set_password(KEYRING_SERVICE, KEY_OTP_SECRET, creds.otp_secret_key)
    else:
        # Clear any stale OTP secret if not provided
        try:
            keyring.delete_password(KEYRING_SERVICE, KEY_OTP_SECRET)
        except keyring.errors.PasswordDeleteError:
            pass

    logger.info("✅ Amazon credentials saved to keyring")


def load_credentials() -> Optional[AmazonCredentials]:
    """Load credentials from the keyring, or env vars as a fallback."""
    try:
        import keyring

        email = keyring.get_password(KEYRING_SERVICE, KEY_EMAIL)
        password = keyring.get_password(KEYRING_SERVICE, KEY_PASSWORD)
        otp_secret = keyring.get_password(KEYRING_SERVICE, KEY_OTP_SECRET)
    except Exception as e:
        logger.warning(f"⚠️  Keyring load failed: {e}")
        email = password = otp_secret = None

    # Env vars win if keyring empty (and amazon-orders reads them too, but
    # we still want to surface them via load_credentials for consistency)
    email = email or os.getenv("AMAZON_USERNAME")
    password = password or os.getenv("AMAZON_PASSWORD")
    otp_secret = otp_secret or os.getenv("AMAZON_OTP_SECRET_KEY")

    if email and password:
        return AmazonCredentials(
            email=email, password=password, otp_secret_key=otp_secret
        )
    return None


def delete_credentials() -> None:
    """Remove stored credentials from the keyring."""
    import keyring

    for key in (KEY_EMAIL, KEY_PASSWORD, KEY_OTP_SECRET):
        try:
            keyring.delete_password(KEYRING_SERVICE, key)
        except keyring.errors.PasswordDeleteError:
            pass
    logger.info("🗑️  Amazon credentials deleted from keyring")


def cookie_jar_exists() -> bool:
    """Return True if a cookie jar file already exists from a prior login."""
    return COOKIE_JAR_PATH.is_file() and COOKIE_JAR_PATH.stat().st_size > 0
