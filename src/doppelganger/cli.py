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

from scan_primitives import OutOfScopeError, Scope, load_scope

from doppelganger import __version__
from doppelganger.engine import DesyncEngine
from doppelganger.findings import TECHNIQUES, Finding
from doppelganger.h2c import H2C_TECHNIQUES
from doppelganger.h2techniques import H2_TECHNIQUES, h2_technique_by_name
from doppelganger.reporting import to_h1md
from doppelganger.sarif import to_sarif
from doppelganger.techniques import all_techniques, technique_by_name

# NOTE: the H2 engine + send layer (doppelganger.h2engine / .h2send) pull the
# hpack/h2 stack; they are imported LAZILY inside _scan_single() only when an
# H2 technique is selected, so H1-only usage (and installs without the h2
# extra) stay light.  h2techniques above is deliberately hpack-free at import.

# Technique selection: the HTTP/1.1 desync family (criterion 1), the v0.2
# HTTP/2-downgrade family (H2.CL / H2.TE), the v0.3 H2C cleartext-upgrade
# probe (H2C), plus "all" (HTTP/1.1 only -- H2/H2C probes are opt-in because
# they require specific server capabilities and are targeted, not sweeping).
_TECHNIQUE_CHOICES = (*TECHNIQUES, *H2_TECHNIQUES, *H2C_TECHNIQUES, "all")

# Output formats doppelganger emits (criterion 6).
_FORMAT_CHOICES = ("json", "sarif", "h1md")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="doppelganger",
        description=(
            "Headless HTTP request-smuggling / desync detector and "
            "differential-confirmation tool. Detects the HTTP/1.1 desync family "
            "(CL.TE, TE.CL, TE.TE, CL.0, duplicate Content-Length) and the "
            "HTTP/2-downgrade family (H2.CL, H2.TE) with pipelining "
            "false-positive discrimination and safe-testing defaults. "
            "Authorized targets only."
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        metavar="URL",
        help=(
            "target URL to probe (e.g. https://example.com/). "
            "Mutually exclusive with --target-file."
        ),
    )
    parser.add_argument(
        "--target-file",
        metavar="FILE",
        dest="target_file",
        help=(
            "path to a file containing target URLs to probe, one per line. "
            "Lines starting with '#' and blank lines are ignored. "
            "Scans all targets in sequence and aggregates findings. "
            "Mutually exclusive with the positional URL argument."
        ),
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
        "--retries",
        type=int,
        default=0,
        metavar="N",
        help=(
            "retry the timing probe up to N additional times when it times out "
            "(default: 0). A genuine back-end hang is stable and times out on "
            "every retry; a transient network timeout typically clears on the "
            "first retry and is not reported as a timing signal. Applies to the "
            "HTTP/1.1 engine (CL.TE / TE.CL / TE.TE / CL.0 / dup-CL / "
            "TE.chunk / Expect.CL.TE); H2 and H2C engines ignore this flag."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"doppelganger {__version__}",
    )
    return parser


def _load_target_file(path: str) -> list[str]:
    """Read a target-list file and return non-blank, non-comment lines.

    The file format mirrors the scope file: one entry per line, lines starting
    with ``#`` are treated as comments and ignored, blank lines are ignored.
    The caller is responsible for validating that the returned list is non-empty.

    Raises:
        OSError: if the file cannot be opened or read.
    """
    with open(path) as fh:
        lines = fh.readlines()
    targets: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            targets.append(stripped)
    return targets


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


def _scan_single(
    target: str,
    scope: Scope,
    args: argparse.Namespace,
) -> tuple[list[Finding], list[dict], int]:
    """Scan one target URL with the given scope and CLI args.

    Routes to the correct engine (H1, H2, H2C) based on ``args.technique``.
    Scope is enforced before any bytes leave the host.

    Returns:
        (findings, suppressed, exit_code) where exit_code is:
            0 -- scan completed, no findings
            1 -- scan completed, one or more findings
            3 -- scope / connectivity error for this target
    """
    if not urlsplit(target).hostname:
        print(f"error: could not parse target URL: {target!r}", file=sys.stderr)
        return [], [], 3

    if args.technique in H2C_TECHNIQUES:
        from doppelganger.h2c import H2CEngine

        engine = H2CEngine(
            target,
            scope=scope,
            timeout=args.timeout,
            safe=args.safe,
        )
        try:
            findings = engine.run()
        except OutOfScopeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return [], [], 3
        except OSError as exc:
            print(
                f"error: could not reach target {target!r}: {exc}",
                file=sys.stderr,
            )
            return [], [], 3

    elif args.technique in H2_TECHNIQUES:
        from doppelganger.h2engine import H2DesyncEngine
        from doppelganger.h2send import H2NotSupportedError

        engine = H2DesyncEngine(
            target,
            scope=scope,
            timeout=args.timeout,
            safe=args.safe,
            reuse_connection=args.reuse_connection,
        )
        try:
            findings = engine.run(h2_technique_by_name(args.technique))
        except OutOfScopeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return [], [], 3
        except H2NotSupportedError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return [], [], 3
        except OSError as exc:
            print(
                f"error: could not reach target {target!r}: {exc}",
                file=sys.stderr,
            )
            return [], [], 3

    else:
        engine = DesyncEngine(
            target,
            scope=scope,
            timeout=args.timeout,
            safe=args.safe,
            reuse_connection=args.reuse_connection,
            retries=args.retries,
        )
        techniques = (
            all_techniques()
            if args.technique == "all"
            else technique_by_name(args.technique)
        )
        try:
            findings = engine.run(techniques)
        except OutOfScopeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return [], [], 3
        except OSError as exc:
            print(
                f"error: could not reach target {target!r}: {exc}",
                file=sys.stderr,
            )
            return [], [], 3

    return findings, engine.suppressed, (1 if findings else 0)


def run(args: argparse.Namespace) -> int:
    """Execute a scan for the parsed args.

    Loads the scope (required), builds the list of targets (from the positional
    URL or ``--target-file``), drives the two-stage desync engine over the
    selected technique(s) for **each** target in sequence, aggregates all
    findings and suppressed-pipelining entries, and prints the result in the
    requested format. Returns an exit code per the module docstring.

    When scanning multiple targets via ``--target-file``:
    - Scope or connectivity errors for individual targets are reported to stderr
      and that target is skipped; remaining targets continue to be scanned.
    - Exit code 1 if **any** target produced findings.
    - Exit code 3 if the scope file or target file could not be read (fatal),
      or if every target hit a scope / connectivity error.
    - Exit code 0 if all targets were clean.
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

    # Build the list of targets.
    if getattr(args, "target_file", None):
        try:
            targets = _load_target_file(args.target_file)
        except OSError as exc:
            print(f"error: could not read target file: {exc}", file=sys.stderr)
            return 3
        if not targets:
            print(
                f"error: target file {args.target_file!r} contains no targets "
                "(all lines are blank or comments)",
                file=sys.stderr,
            )
            return 3
    else:
        targets = [args.target]

    # Scan each target; aggregate findings and suppressed entries.
    all_findings: list[Finding] = []
    all_suppressed: list[dict] = []
    # Track whether any target had an error so the exit code is meaningful when
    # the target list is a mix of good and bad entries.
    any_error = False
    any_scan_ran = False

    for target in targets:
        findings, suppressed, code = _scan_single(target, scope, args)
        if code == 3:
            any_error = True
            # Skip to the next target; error already printed to stderr.
            continue
        any_scan_ran = True
        all_findings.extend(findings)
        all_suppressed.extend(suppressed)

    if not any_scan_ran:
        # Every target hit a scope/connectivity error.
        return 3

    print(_render(all_findings, args.output_format, all_suppressed))

    if all_findings:
        return 1
    if any_error:
        # Some targets were skipped; none produced findings, but we can't call
        # the scan entirely clean.
        return 3
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Validate target / target-file: exactly one must be provided.
    has_target = bool(args.target)
    has_target_file = bool(getattr(args, "target_file", None))

    if has_target and has_target_file:
        parser.error(
            "--target-file and a positional URL are mutually exclusive; "
            "provide one or the other, not both"
        )
    if not has_target and not has_target_file:
        parser.error(
            "a target URL or --target-file is required (or use --version / --help)"
        )

    return run(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
