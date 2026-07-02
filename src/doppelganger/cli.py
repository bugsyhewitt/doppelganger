"""doppelganger command-line interface.

The argument surface below is the v0.1 CLI contract from V0.1-CRITERIA.md --
target, technique selection, safe-testing mode, connection-reuse control, scope
file, and output format. ``--version`` and ``--help`` work fully. A scan drives
:class:`doppelganger.engine.DesyncEngine` (two-stage timing detection ->
differential confirmation with pipelining discrimination) and emits findings in
the requested format.

[Worker decision: argparse, not Click -- mirrors ferryman/enshroud and keeps the
dependency surface tight.]

Exit codes:
    0  scan completed, no desync findings
    1  scan completed, one or more desync findings (candidate or confirmed)
    2  usage / argument error (argparse default)
    3  scope file / target could not be read, or a target was out of scope
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence
from urllib.parse import urlsplit

from scan_primitives import OutOfScopeError, load_scope

from doppelganger import __version__
from doppelganger.engine import DesyncEngine
from doppelganger.findings import TECHNIQUES, Finding
from doppelganger.reporting import to_h1md
from doppelganger.sarif import to_sarif
from doppelganger.techniques import all_techniques, technique_by_name

# Technique selection: the HTTP/1.1 desync family (criterion 1) plus "all".
_TECHNIQUE_CHOICES = (*TECHNIQUES, "all")

# Output formats doppelganger emits (criterion 6).
_FORMAT_CHOICES = ("json", "sarif", "h1md")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="doppelganger",
        description=(
            "Headless HTTP/1.1 request-smuggling / desync detector and "
            "differential-confirmation tool. Detects CL.TE, TE.CL, TE.TE, "
            "CL.0, and duplicate Content-Length desyncs with pipelining "
            "false-positive discrimination and safe-testing defaults. "
            "Authorized targets only."
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        metavar="URL",
        help="target URL to probe (e.g. https://example.com/)",
    )
    parser.add_argument(
        "--technique",
        choices=_TECHNIQUE_CHOICES,
        default="all",
        help=(
            "which desync technique to probe (default: all). One of: "
            + ", ".join(_TECHNIQUE_CHOICES)
        ),
    )
    parser.add_argument(
        "--scope-file",
        metavar="FILE",
        dest="scope_file",
        help=(
            "path to the authorization scope file (one host / CIDR per line). "
            "Every probe -- raw and well-formed -- is scope-checked before "
            "egress."
        ),
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help=(
            "safe / production mode: per-probe connection isolation, CL.TE "
            "before TE.CL, bounded+randomised timeouts, never leave a poisoned "
            "socket in a shared pool"
        ),
    )
    reuse = parser.add_mutually_exclusive_group()
    reuse.add_argument(
        "--reuse-connection",
        action="store_true",
        dest="reuse_connection",
        default=False,
        help=(
            "reuse one client connection across probes. Used to *discriminate* "
            "pipelining from a true server-side desync: an effect that "
            "reproduces only with connection reuse is probable client-side "
            "pipelining, not a desync"
        ),
    )
    reuse.add_argument(
        "--no-reuse-connection",
        action="store_false",
        dest="reuse_connection",
        help="force per-probe connection isolation (the default)",
    )
    parser.add_argument(
        "--format",
        choices=_FORMAT_CHOICES,
        default="json",
        dest="output_format",
        help="output format (default: json)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="per-request timeout in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"doppelganger {__version__}",
    )
    return parser


def _render(findings: list[Finding], output_format: str, suppressed: list[dict]) -> str:
    """Render findings in the requested output format."""
    if output_format == "sarif":
        return json.dumps(to_sarif(findings), indent=2)
    if output_format == "h1md":
        return to_h1md(findings)
    # json (default): doppelganger's own finding documents.
    return json.dumps(
        {
            "tool": "doppelganger",
            "finding_count": len(findings),
            "findings": [f.to_dict() for f in findings],
            "suppressed_pipelining": suppressed,
        },
        indent=2,
    )


def run(args: argparse.Namespace) -> int:
    """Execute a scan for the parsed args.

    Loads the scope (required -- scope enforcement precedes any probe), drives the
    two-stage desync engine over the selected technique(s), and prints findings in
    the requested format. Returns an exit code per the module docstring.
    """
    # Scope is mandatory: no probe -- raw or well-formed -- leaves the host
    # without a scope check first (criterion 4 / Safety).
    if not args.scope_file:
        print(
            "error: --scope-file is required; scope is enforced before any probe",
            file=sys.stderr,
        )
        return 3
    try:
        scope = load_scope(args.scope_file)
    except OSError as exc:
        print(f"error: could not read scope file: {exc}", file=sys.stderr)
        return 3

    if not urlsplit(args.target).hostname:
        print(f"error: could not parse target URL: {args.target!r}", file=sys.stderr)
        return 3

    if args.technique == "all":
        techniques = all_techniques()
    else:
        techniques = technique_by_name(args.technique)

    engine = DesyncEngine(
        args.target,
        scope=scope,
        timeout=args.timeout,
        safe=args.safe,
        reuse_connection=args.reuse_connection,
    )
    try:
        findings = engine.run(techniques)
    except OutOfScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except OSError as exc:
        print(f"error: could not reach target {args.target!r}: {exc}", file=sys.stderr)
        return 3

    print(_render(findings, args.output_format, engine.suppressed))
    return 1 if findings else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # argparse has already handled --version / --help (they exit 0). A run with
    # no target is a usage error.
    if not args.target:
        parser.error("a target URL is required (or use --version / --help)")

    return run(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
