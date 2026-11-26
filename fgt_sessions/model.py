"""Data model for a parsed FortiGate session."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}

# TCP proto_state values per Fortinet's session table KB; 01 = ESTABLISHED was
# confirmed on FortiOS 7.6.6. Other protocols and unknown values stay raw.
# Names from the FortiOS CLI reference ("diagnose sys session filter proto-state").
TCP_STATES = {
    0: "NONE",
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT",
    5: "TIME_WAIT",
    6: "CLOSE",
    7: "CLOSE_WAIT",
    8: "LAST_ACK",
    9: "LISTEN",
}


@dataclass
class Hop:
    """One 'hook=' line: a direction-specific view of the session tuple."""

    hook: str                      # pre / post
    direction: str                 # org / reply
    action: Optional[str]          # snat / dnat / None
    src: str
    sport: int
    dst: str
    dport: int
    nat_ip: Optional[str] = None
    nat_port: Optional[int] = None


@dataclass
class Session:
    proto: int
    proto_state: Optional[str] = None
    duration: Optional[int] = None
    expire: Optional[int] = None
    timeout: Optional[int] = None
    policy_id: Optional[int] = None
    vd: Optional[int] = None
    bytes_org: Optional[int] = None
    packets_org: Optional[int] = None
    bytes_reply: Optional[int] = None
    packets_reply: Optional[int] = None
    hops: list[Hop] = field(default_factory=list)
    extra: dict[str, str] = field(default_factory=dict)  # unrecognised key=value pairs

    @property
    def proto_name(self) -> str:
        return PROTO_NAMES.get(self.proto, str(self.proto))

    @property
    def state_name(self) -> Optional[str]:
        """TCP state names for the two proto_state digits, joined with "/".

        Fortinet's Administration Guide says a TCP proto_state has two digits
        because FortiGate tracks both directions. It does not say which digit is
        which direction, so the names are shown in the order the digits appear.
        Returns None if not TCP or the value is not two digits.
        """
        if self.proto != 6 or not self.proto_state:
            return None
        if len(self.proto_state) != 2 or not self.proto_state.isdigit():
            return None
        return "/".join(TCP_STATES[int(d)] for d in self.proto_state)

    @property
    def origin(self) -> Optional[Hop]:
        """The original-direction hop, if present."""
        for hop in self.hops:
            if hop.direction == "org":
                return hop
        return None
