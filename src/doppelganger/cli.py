"""doppelganger command-line interface.

Scaffold status: the argument surface below is the v0.1 CLI contract from
V0.1-CRITERIA.md -- target, technique selection, safe-testing mode,
connection-reuse control, scope file, and output format. ``--version`` and
``--help`` work fully. The scan path is **stubbed**: invoking a probe raises
``NotImplementedError`` because the desync engine and the raw-socket transport
are not built in this pass. See V0.1-CRITERIA.md.

[Worker decision: argparse, not Click -- mirrors ferryman/enshroud and keeps the
dependency surface tight.]

Exit codes (planned, once the engine lands):
    0  scan completed, no findings at/above --fail-on
    1  --fail-on threshold met
    2  usage / argument error (argparse default)
    3  scope file / target could not be read
"""

from __future__ import annotations

import argparse
from typing import Sequence

from doppelganger import __version__
from doppelganger.findings import TECHNIQUES

_NOT_BUILT = "v0.1 build -- see V0.1-CRITERIA.md"

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


def run(args: argparse.Namespace) -> int:
    """Execute a scan for the parsed args.

    STUB: the desync probe engine, timing detection, differential confirmation,
    pipelining discrimination, and the raw-socket transport are not built in
    this scaffold pass. Raises :class:`NotImplementedError`.
    """
    raise NotImplementedError(_NOT_BUILT)


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
