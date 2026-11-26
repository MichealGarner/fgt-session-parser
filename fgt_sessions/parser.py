"""Parse 'diagnose sys session list' text into Session objects.

The format varies between FortiOS versions, so the parser is tolerant:
it tokenises key=value pairs, keeps the ones it understands, and stores
the rest in Session.extra rather than failing.
"""

from __future__ import annotations

import re
from typing import Optional

from .model import Hop, Session

BLOCK_START = "session info:"

KV_RE = re.compile(r"(\w+)=(\S*)")

STAT_RE = re.compile(
    r"statistic\(.*?\):\s*org=(\d+)/(\d+)/\d+\s+reply=(\d+)/(\d+)/\d+"
)

# hook=post dir=org act=snat 10.0.0.5:50422->198.51.100.8:443(203.0.113.2:50422)
HOOK_RE = re.compile(
    r"hook=(?P<hook>\w+)\s+dir=(?P<dir>\w+)"
    r"(?:\s+act=(?P<act>\w+))?\s+"
    r"(?P<src>\S+):(?P<sport>\d+)->"
    r"(?P<dst>\S+?):(?P<dport>\d+)(?=\(|\s|$)"
    r"(?:\((?P<nip>\S+):(?P<nport>\d+)\))?"
)

INT_FIELDS = {
    "duration": "duration",
    "expire": "expire",
    "timeout": "timeout",
    "policy_id": "policy_id",
    "vd": "vd",
}


def _to_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except ValueError:
        return None


NO_POLICY = 4294967295  # 0xFFFFFFFF: local-in/out traffic with no firewall policy


def _split_blocks(text: str) -> list[list[str]]:
    """Group lines into one list per 'session info:' block.

    Anything before the first block (the echoed command, banners) is ignored.
    """
    blocks: list[list[str]] = []
    for line in text.splitlines():
        if line.lstrip().startswith(BLOCK_START):
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)
    return blocks


def _parse_block(lines: list[str]) -> Optional[Session]:
    kv: dict[str, str] = {}
    hops: list[Hop] = []
    stats: Optional[tuple[int, int, int, int]] = None

    for line in lines:
        stripped = line.strip()

        m = HOOK_RE.search(stripped) if stripped.startswith("hook=") else None
        if m:
            nip, nport = m.group("nip"), m.group("nport")
            nat_ip: Optional[str] = nip
            nat_port: Optional[int] = int(nport) if nport else None
            if nip == "0.0.0.0" and nat_port == 0:  # 'no NAT' placeholder
                nat_ip, nat_port = None, None
            hops.append(
                Hop(
                    hook=m.group("hook"),
                    direction=m.group("dir"),
                    action=m.group("act"),
                    src=m.group("src"),
                    sport=int(m.group("sport")),
                    dst=m.group("dst"),
                    dport=int(m.group("dport")),
                    nat_ip=nat_ip,
                    nat_port=nat_port,
                )
            )
            continue

        if stripped.startswith("hook="):
            continue  # a hook line we could not parse; do not feed it to kv

        m = STAT_RE.search(stripped)
        if m:
            stats = tuple(int(g) for g in m.groups())  # type: ignore[assignment]
            continue

        for key, value in KV_RE.findall(stripped):
            kv.setdefault(key, value)  # first occurrence wins

    proto = _to_int(kv.get("proto", ""))
    if proto is None or not hops:
        return None

    session = Session(proto=proto, proto_state=kv.get("proto_state"), hops=hops)
    for key, attr in INT_FIELDS.items():
        if key in kv:
            setattr(session, attr, _to_int(kv[key]))
    if "vd" in kv:  # seen as 'vd=0:20' on 7.6.6; the leading number is the index
        session.vd = _to_int(kv["vd"].split(":")[0])
    if session.policy_id == NO_POLICY:
        session.policy_id = None
    if stats:
        (session.bytes_org, session.packets_org,
         session.bytes_reply, session.packets_reply) = stats

    known = {"proto", "proto_state", *INT_FIELDS}
    session.extra = {k: v for k, v in kv.items() if k not in known}
    return session


def parse_sessions(text: str) -> tuple[list[Session], int]:
    """Return (sessions, skipped_block_count)."""
    sessions: list[Session] = []
    skipped = 0
    for block in _split_blocks(text):
        session = _parse_block(block)
        if session is None:
            skipped += 1
        else:
            sessions.append(session)
    return sessions, skipped
