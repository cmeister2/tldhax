"""Report offline freshness or explicitly collect upstream review observations."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import refresh
from .report import freshness, write


def main() -> int:
    """Dispatch maintenance without writing approved manifests or policies."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument(
        "--as-of", required=True, help="explicit YYYY-MM-DD freshness boundary"
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--inventory-days", type=int, default=7)
    parser.add_argument("--policy-days", type=int, default=30)
    parser.add_argument(
        "--refresh-inventory", metavar="NEW_STAGING_DIRECTORY", type=Path
    )
    parser.add_argument("--check-policies", action="store_true")
    args = parser.parse_args()
    failed = False
    try:
        result = freshness(
            args.root,
            args.as_of,
            inventory_days=args.inventory_days,
            policy_days=args.policy_days,
        )
        if args.refresh_inventory:
            try:
                result["inventory_refresh"] = refresh.inventory(
                    args.root, args.refresh_inventory, args.as_of
                )
            except (ValueError, KeyError, OSError) as exc:
                result["inventory_refresh"] = {
                    "status": "check_failed",
                    "error_type": type(exc).__name__,
                    "approval_status": "review_required",
                }
                print("Inventory refresh failed: " + str(exc), file=sys.stderr)
                failed = True
        if args.check_policies:
            result["policy_observations"] = refresh.policies(args.root, args.as_of)
        write(result, args.report)
    except (ValueError, KeyError, OSError) as exc:
        print("Maintenance error: " + str(exc), file=sys.stderr)
        return 1
    print("Prepared review report " + str(args.report))
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
