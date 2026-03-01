"""Mandatory authorisation and legal disclaimer for Scorpio Pro."""

from __future__ import annotations

import sys
from datetime import datetime, timezone


_DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║              SCORPIO PRO — PENETRATION TESTING TOOL                        ║
║                     LEGAL DISCLAIMER & AUTHORISATION                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This tool is intended EXCLUSIVELY for use on systems and networks that     ║
║  you OWN or have EXPLICIT, WRITTEN AUTHORISATION to test.                   ║
║                                                                              ║
║  Unauthorised scanning or testing of systems is ILLEGAL and may result in   ║
║  criminal prosecution under the Computer Fraud and Abuse Act (18 U.S.C.    ║
║  § 1030), the Computer Misuse Act 1990 (UK), and equivalent laws worldwide. ║
║                                                                              ║
║  By proceeding you confirm that:                                             ║
║    1. You have written authorisation for all targets in scope.               ║
║    2. You will not exceed the agreed scope.                                  ║
║    3. You accept full legal responsibility for your actions.                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


def prompt_authorisation(
    engagement_name: str,
    authorised_by: str,
    scope_summary: str,
    non_interactive: bool = False,
) -> bool:
    """Display the legal disclaimer and request explicit user acceptance.

    Args:
        engagement_name: Name of the pen test engagement.
        authorised_by: Name of the authorising party.
        scope_summary: Brief textual description of the scope.
        non_interactive: Skip interactive prompt (for CI/testing only).

    Returns:
        ``True`` if the user accepted the disclaimer; ``False`` otherwise.
    """
    print(_DISCLAIMER)
    print(f"  Engagement : {engagement_name}")
    print(f"  Authorised by: {authorised_by}")
    print(f"  Scope summary: {scope_summary}")
    print(f"  Timestamp  : {datetime.now(tz=timezone.utc).isoformat()}")
    print()

    if non_interactive:
        print("[AUTH] Non-interactive mode: disclaimer auto-accepted.")
        return True

    try:
        answer = input(
            "Do you confirm you are authorised to perform this scan? "
            "Type 'YES I CONFIRM' to proceed: "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[AUTH] Scan aborted by user.")
        return False

    if answer == "YES I CONFIRM":
        print("[AUTH] Authorisation confirmed. Proceeding with scan.\n")
        return True

    print("[AUTH] Authorisation not confirmed. Scan aborted.")
    return False
