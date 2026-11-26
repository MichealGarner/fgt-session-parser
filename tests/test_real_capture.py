from pathlib import Path

from fgt_sessions.model import Session
from fgt_sessions.parser import parse_sessions

REAL = Path(__file__).parent / "fixtures" / "real_7_6_6_local_ssh.txt"


def test_real_local_ssh_session():
    sessions, skipped = parse_sessions(REAL.read_text())
    assert (len(sessions), skipped) == (1, 0)
    s = sessions[0]
    assert s.proto_state == "01" and s.state_name == "NONE/ESTABLISHED"
    assert (s.bytes_org, s.packets_org) == (8693, 103)
    assert (s.bytes_reply, s.packets_reply) == (14136, 111)
    assert s.vd == 0
    assert s.policy_id is None  # 4294967295 means no policy (local session)
    o = s.origin
    assert (o.hook, o.src, o.sport, o.dst, o.dport) == ("pre", "192.168.1.50", 48346, "192.168.1.1", 22)
    assert o.nat_ip is None
    assert s.extra["npu_state"] == "00000000"
    assert s.extra["src_mac"] == "02:00:00:00:00:01"


def test_state_names():
    def tcp(state):
        return Session(proto=6, proto_state=state).state_name

    assert tcp("01") == "NONE/ESTABLISHED"
    assert tcp("11") == "ESTABLISHED/ESTABLISHED"
    assert tcp("37") == "SYN_RECV/CLOSE_WAIT"
    assert tcp("89") == "LAST_ACK/LISTEN"
    assert tcp("1") is None       # not two digits
    assert tcp("1a") is None
    assert tcp(None) is None
    assert Session(proto=17, proto_state="01").state_name is None


def test_multivdom_capture():
    from collections import Counter
    from pathlib import Path
    from fgt_sessions.parser import parse_sessions

    text = Path(__file__).parent.joinpath("fixtures", "real_7_6_6_multivdom.txt").read_text()
    sessions, skipped = parse_sessions(text)
    assert len(sessions) == 20 and skipped == 0
    states = Counter((s.proto, s.proto_state) for s in sessions)
    # Every established TCP session on this unit, forwarded or local, reads 01.
    assert states[(6, "01")] == 10
    # UDP: 00 = no reply seen, 01 = reply seen.
    assert states[(17, "00")] == 4 and states[(17, "01")] == 6


def test_half_closed_capture():
    from pathlib import Path
    from fgt_sessions.parser import parse_sessions

    text = Path(__file__).parent.joinpath("fixtures", "real_7_6_6_halfclosed.txt").read_text()
    sessions, skipped = parse_sessions(text)
    assert len(sessions) == 1 and skipped == 0
    s = sessions[0]
    # Server closed first: second digit moved from 1 (ESTABLISHED) to 7 (CLOSE_WAIT).
    assert s.proto_state == "07"
    assert s.state_name == "NONE/CLOSE_WAIT"
