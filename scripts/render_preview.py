"""Render static HTML previews of Grant's core screens."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ.setdefault("GRANT_DB", str(Path(tempfile.gettempdir()) / "grant-preview.db"))
os.environ.setdefault("GRANT_PUBLIC_BASE_URL", "https://grant.yourdomain.com")
os.environ.setdefault("GRANT_RATE_LIMIT_PER_MIN", "0")

import main  # noqa: E402

OUT = ROOT / ".publish_assets"
OUT.mkdir(parents=True, exist_ok=True)

main.init_db()
result = main.create_request(
    main.RequestIn(
        agent="support-agent",
        action="refund_order",
        summary="Refund order ord_42 for $48.00",
        scope={"order_id": "ord_42", "amount": 48, "expires": "30 minutes"},
        requester="Support desk",
        workspace="support",
    )
)
row = main.get_request_by_token(result["token"])

workspace_code = "support"
workspace = main.get_workspace(workspace_code)
files = {
    "grant-home.html": main.home_page(),
    "grant-docs.html": main.docs_page(),
    "grant-pricing.html": main.pricing_page("ws_preview"),
    "grant-approval.html": main.approval_page(row),
    "grant-start.html": main.start_page(),
    "grant-console.html": main.console_index_page(),
    "grant-protected.html": main.protected_page(workspace_code, workspace, []),
}
for name, html in files.items():
    (OUT / name).write_text(html, encoding="utf-8")
    print(OUT / name)
