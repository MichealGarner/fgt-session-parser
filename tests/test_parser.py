from pathlib import Path

import pytest

from fgt_sessions.parser import parse_sessions

FIXTURE = Path(__file__).parent / "fixtures" / "sample_sessions.txt"


@pytest.fixture(scope="module")
def sample():
    sessions, skipped = parse_sessions(FIXTURE.read_text())
    return sessions, skipped


def test_multi_session_count(sample):
    sessions, skipped = sample
    assert len(sessions) == 3
    assert skipped == 0


def test_tcp_snat_session(sample):
    s = sample[0][0]
    assert s.proto == 6
    assert s.proto_name == "tcp"
    assert s.policy_id == 5
    assert s.vd == 0
    assert s.bytes_org == 1234 and s.packets_org == 12
    assert s.bytes_reply == 5678 and s.packets_reply == 10
    o = s.origin
    assert (o.src, o.sport, o.dst, o.dport) == ("192.168.1.5", 50422, "198.51.100.8", 443)
    assert (o.nat_ip, o.nat_port) == ("203.0.113.2", 50422)
    assert o.action == "snat"


def test_udp_session_no_crash(sample):
    s = sample[0][1]
    assert s.proto_name == "udp"
    assert s.origin.dport == 53


def test_unknown_key_kept_in_extra(sample):
    s = sample[0][2]
    assert s.extra.get("newfield") == "abc"
    assert s.policy_id == 12


def test_truncated_block_is_skipped_and_counted():
    # A block with no hook= lines has no tuple to report, so it is skipped.
    text = "session info: proto=6 proto_state=01 duration=5\n"
    sessions, skipped = parse_sessions(text)
    assert sessions == []
    assert skipped == 1


def test_empty_input():
    assert parse_sessions("") == ([], 0)


PUBLISHED = Path(__file__).parent / "fixtures" / "published_lines.txt"


def test_published_hook_names_and_no_nat_placeholder():
    sessions, skipped = parse_sessions(PUBLISHED.read_text())
    assert (len(sessions), skipped) == (2, 0)
    first = sessions[0]
    assert [h.hook for h in first.hops] == ["out", "in"]
    assert first.origin.nat_ip is None and first.origin.nat_port is None
    assert first.extra["npu_state"] == "0x4000"
    assert first.policy_id == 44


def test_published_udp_snat_session():
    s = parse_sessions(PUBLISHED.read_text())[0][1]
    assert s.proto_name == "udp"
    assert (s.origin.nat_ip, s.origin.nat_port) == ("203.0.113.5", 50142)
    assert s.duration == 187 and s.expire == 14


def test_proto_state_is_kept_raw():
    s = parse_sessions(PUBLISHED.read_text())[0][0]
    assert s.proto_state == "01"
