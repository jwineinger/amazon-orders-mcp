#!/usr/bin/env python3
"""
Cookie capture flow for the Amazon Orders MCP server.

This script launches a real Chromium browser via Playwright, navigates to
Amazon's sign-in page, and waits for the user to authenticate interactively.
Once signed in, it extracts the full set of amazon.com cookies (including
httpOnly ones that JavaScript cannot see) and writes them to the cookie jar
at ~/.amazon-orders-mcp/cookies.json (or the --account's own jar) in the format expected by the
`amazon-orders` Python library.

Why this exists: amazon-orders uses a plain `requests.Session` to log in,
which Amazon's JavaScript-based WAF frequently blocks with a captcha that
requires a real browser to solve. By capturing cookies from a real browser
post-authentication, we sidestep the WAF entirely — amazon-orders sees a
valid session and skips the sign-in flow.

Run from the repo root:
    uv run python cookie_capture.py [--account NAME]

With --account, the cookies are stored for that account only (see
secure_session.py), so several Amazon accounts can each have a session.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

# Make the package importable when running as a script
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

# Pick the account before importing the package: secure_session resolves its
# paths from AMAZON_ORDERS_MCP_ACCOUNT at import time.
_parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
_parser.add_argument(
    "--account",
    help="Account name (e.g. alice). Stores this session separately; the MCP "
    "server for it must set AMAZON_ORDERS_MCP_ACCOUNT to the same name.",
)
_args = _parser.parse_args()
if _args.account:
    os.environ["AMAZON_ORDERS_MCP_ACCOUNT"] = _args.account

from playwright.sync_api import Error as PlaywrightError  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

from amazon_orders_mcp.secure_session import (  # noqa: E402
    ACCOUNT,
    COOKIE_JAR_PATH,
    ensure_data_dir,
)

# The cookie the amazon-orders library uses to detect an authenticated session
REQUIRED_COOKIE = "x-main"

# URL to land on after sign-in to confirm the session is active
SIGNED_IN_LANDING_URL = "https://www.amazon.com/gp/your-account/order-history"


def main() -> None:
    print("\n🛒 Amazon Orders MCP — Cookie Capture")
    print("=" * 45)
    print("This will open a Chromium browser window where you can sign in")
    print("to Amazon. Once signed in, cookies will be captured and saved")
    print("for the MCP server to use.\n")
    print("Press Ctrl+C to cancel at any time.\n")
    if ACCOUNT:
        print(f"👤 Account: {ACCOUNT} — sign in as this person.")
        print(f"   Cookies will be saved to {COOKIE_JAR_PATH}\n")

    ensure_data_dir()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()

        print("🌐 Opening Amazon sign-in page...")
        page.goto(
            "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=900&openid.return_to=https%3A%2F%2Fwww.amazon.com%2Fgp%2Fyour-account%2Forder-history&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
        )

        print("\n👉 Please sign in to Amazon in the browser window.")
        print("   (Enter your email, password, and any 2FA code.)")
        print("   The script will auto-detect when you're signed in.\n")

        # Wait for the x-main cookie to appear — that's the signal we're authenticated.
        # Poll every 2 seconds for up to 5 minutes.
        timeout_seconds = 300
        poll_interval = 2
        elapsed = 0
        captured = False

        while elapsed < timeout_seconds:
            try:
                cookies = context.cookies()
            except PlaywrightError:
                print("\n❌ Browser window was closed before sign-in completed.")
                print("   No cookies captured. Re-run the script to try again.")
                return
            has_auth = any(
                c["name"] == REQUIRED_COOKIE
                and c["domain"]
                and "amazon.com" in c["domain"]
                for c in cookies
            )
            if has_auth:
                captured = True
                break
            time.sleep(poll_interval)
            elapsed += poll_interval

        if not captured:
            print("\n❌ Timed out after 5 minutes waiting for sign-in.")
            print("   No cookies captured. Re-run the script to try again.")
            browser.close()
            return

        print("✅ Signed in — capturing cookies...")

        # Give the page a moment to finish setting any post-login cookies
        time.sleep(2)

        # Optionally navigate to the order history page to warm up the session
        # and pick up any additional cookies set by that page.
        try:
            page.goto(SIGNED_IN_LANDING_URL, timeout=15000)
            page.wait_for_load_state("networkidle", timeout=10000)
        except Exception as e:
            print(f"⚠️  Could not load order history page: {e}")
            print("   Proceeding with cookies captured so far.")

        # Grab the final cookie set
        all_cookies = context.cookies()
        amazon_cookies = [
            c for c in all_cookies if c["domain"] and "amazon.com" in c["domain"]
        ]

        # Convert to the flat {name: value} dict format amazon-orders expects
        flat_dict = {c["name"]: c["value"] for c in amazon_cookies}

        # Write to the cookie jar
        COOKIE_JAR_PATH.parent.mkdir(parents=True, exist_ok=True)
        COOKIE_JAR_PATH.write_text(json.dumps(flat_dict))
        COOKIE_JAR_PATH.chmod(0o600)

        print(f"✅ Wrote {len(flat_dict)} cookies to {COOKIE_JAR_PATH}")
        print(f"   Cookie names: {', '.join(sorted(flat_dict.keys()))}")

        browser.close()

    # Verify by doing a quick API call
    print("\n🧪 Testing cookies by fetching last 30 days of transactions...")
    try:
        from amazonorders.transactions import AmazonTransactions

        from amazon_orders_mcp.client import build_session, ensure_authenticated

        session = build_session()
        ensure_authenticated(session)
        txns = AmazonTransactions(session).get_transactions(days=30)
        print(f"✅ Retrieved {len(txns)} transactions from the last 30 days")
    except Exception as e:
        print(f"⚠️  Test fetch failed: {type(e).__name__}: {e}")
        print("   Cookies were saved but may not be valid.")
        return

    print("\n🎉 Cookie capture complete! The MCP server is ready to use.")
    print("\n💡 Cookies will last until Amazon expires them (typically several")
    print("   weeks). Re-run this script when the server starts reporting")
    print("   auth errors.")


if __name__ == "__main__":
    main()
