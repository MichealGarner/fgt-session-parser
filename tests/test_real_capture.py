from pathlib import Path

from fgt_sessions.model import Session
from fgt_sessions.parser import parse_sessions

REAL = Path(__file__).parent / "fixtures" / "real_7_6_6_local_ssh.txt"


def test_real_local_ssh_session():
    sessions, skipped = parse_sessions(REAL.read_text())
    assert (len(sessions), skipped) == (1, 0)
    s = sessions[0]
    assert s.proto_state == "01" and s.state_name == "ESTABLISHED"
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

    assert tcp("01") == "ESTABLISHED"
    assert tcp("02") == "SYN_SENT"
    assert tcp("05") == "TIME_WAIT"
    assert tcp("07") == "CLOSE_WAIT"
    assert tcp("11") is None      # two-digit form seen in Fortinet docs: kept raw
    assert tcp("99") is None
    assert tcp(None) is None
    assert Session(proto=17, proto_state="01").state_name is None
