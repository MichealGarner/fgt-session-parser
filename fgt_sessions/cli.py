"""Command-line interface for fgt-sessions.

Exit codes: 0 ok, 1 setup error (cannot read input),
2 input had content but no sessions could be parsed.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional, Sequence

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .model import Session
from .parser import parse_sessions


def _ip_match(ip: str, spec: str) -> bool:
    """True if ip equals spec, or falls inside spec when spec is a CIDR."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return ip == spec


def _total_bytes(s: Session) -> int:
    return (s.bytes_org or 0) + (s.bytes_reply or 0)


def _human(n: Optional[int]) -> str:
    if n is None:
        return "-"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _matches(s: Session, args: argparse.Namespace) -> bool:
    o = s.origin
    if args.policy is not None and s.policy_id != args.policy:
        return False
    if args.proto and s.proto_name != args.proto:
        return False
    if args.src and not (o and _ip_match(o.src, args.src)):
        return False
    if args.dst and not (o and _ip_match(o.dst, args.dst)):
        return False
    if args.older_than is not None and not (
        s.duration is not None and s.duration > args.older_than
    ):
        return False
    if args.newer_than is not None and not (
        s.duration is not None and s.duration < args.newer_than
    ):
        return False
    return True


def _to_json(sessions: list[Session]) -> str:
    rows = []
    for s in sessions:
        d = asdict(s)
        d["proto_name"] = s.proto_name
        d.pop("extra", None)
        rows.append(d)
    return json.dumps(rows, indent=2)


def _table(sessions: list[Session]) -> Table:
    t = Table(show_lines=False)
    for col in ("Proto", "Source", "Destination", "NAT", "Policy",
                "State", "Age", "Expire", "Sent", "Received"):
        t.add_column(
            col,
            min_width=len(col),
            no_wrap=col in ("Source", "Destination", "NAT", "Sent", "Received"),
        )
    for s in sessions:
        o = s.origin or (s.hops[0] if s.hops else None)
        src = f"{o.src}:{o.sport}" if o else "-"
        dst = f"{o.dst}:{o.dport}" if o else "-"
        nat = f"{o.nat_ip}:{o.nat_port}" if o and o.nat_ip else "-"
        t.add_row(
            s.proto_name,
            escape(src),
            escape(dst),
            escape(nat),
            "-" if s.policy_id is None else str(s.policy_id),
            s.proto_state or "-",
            "-" if s.duration is None else str(s.duration),
            "-" if s.expire is None else str(s.expire),
            _human(s.bytes_org),
            _human(s.bytes_reply),
        )
    return t


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fgt-sessions",
        description="Turn 'diagnose sys session list' output into a readable table.",
    )
    p.add_argument("file", help="saved session output, or - for stdin")
    p.add_argument("--policy", type=int, help="only sessions matching this policy ID")
    p.add_argument("--src", help="origin source IP or CIDR")
    p.add_argument("--dst", help="origin destination IP or CIDR")
    p.add_argument("--proto", choices=["tcp", "udp", "icmp"], help="protocol")
    p.add_argument("--older-than", type=int, metavar="SECONDS",
                   help="only sessions whose age is greater than SECONDS")
    p.add_argument("--newer-than", type=int, metavar="SECONDS",
                   help="only sessions whose age is less than SECONDS")
    p.add_argument("--top", type=int, metavar="N",
                   help="show the N busiest sessions by total bytes")
    p.add_argument("--json", action="store_true", help="JSON output instead of a table")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.file == "-":
            text = sys.stdin.read()
        else:
            text = Path(args.file).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"fgt-sessions: cannot read input: {exc}", file=sys.stderr)
        return 1

    sessions, skipped = parse_sessions(text)
    if skipped:
        print(f"fgt-sessions: skipped {skipped} unparseable block(s)", file=sys.stderr)
    if text.strip() and not sessions:
        print("fgt-sessions: no sessions found; is this 'diagnose sys session list' output?",
              file=sys.stderr)
        return 2

    total = len(sessions)
    sessions = [s for s in sessions if _matches(s, args)]
    if args.top is not None:
        sessions = sorted(sessions, key=_total_bytes, reverse=True)[: args.top]

    if args.json:
        print(_to_json(sessions))
    else:
        console = Console()
        console.print(_table(sessions))
        console.print(f"{len(sessions)} of {total} session(s) shown")
    return 0


if __name__ == "__main__":
    sys.exit(main())
