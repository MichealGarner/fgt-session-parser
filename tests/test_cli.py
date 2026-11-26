import json
from pathlib import Path

from fgt_sessions.cli import main

FIXTURE = str(Path(__file__).parent / "fixtures" / "sample_sessions.txt")


def run_json(capsys, *args):
    code = main([FIXTURE, "--json", *args])
    out = capsys.readouterr().out
    return code, json.loads(out)


def test_json_all_sessions(capsys):
    code, rows = run_json(capsys)
    assert code == 0
    assert len(rows) == 3
    assert rows[0]["proto_name"] == "tcp"
    assert "extra" not in rows[0]


def test_filter_policy(capsys):
    _, rows = run_json(capsys, "--policy", "7")
    assert [r["policy_id"] for r in rows] == [7]


def test_filter_proto(capsys):
    _, rows = run_json(capsys, "--proto", "udp")
    assert len(rows) == 1 and rows[0]["proto"] == 17


def test_filter_src_cidr_and_exact(capsys):
    _, rows = run_json(capsys, "--src", "192.168.1.0/24")
    assert len(rows) == 3
    _, rows = run_json(capsys, "--src", "192.168.1.20")
    assert [r["policy_id"] for r in rows] == [12]


def test_filter_dst(capsys):
    _, rows = run_json(capsys, "--dst", "198.51.100.0/24")
    assert len(rows) == 2


def test_top_sorts_by_total_bytes(capsys):
    _, rows = run_json(capsys, "--top", "2")
    assert [r["policy_id"] for r in rows] == [12, 5]


def test_table_output_runs(capsys):
    assert main([FIXTURE]) == 0
    out = capsys.readouterr().out
    assert "3 of 3 session(s) shown" in out


def test_missing_file_returns_1(capsys):
    assert main(["no-such-file.txt"]) == 1
    assert "cannot read input" in capsys.readouterr().err


def test_wrong_format_returns_2(tmp_path, capsys):
    f = tmp_path / "junk.txt"
    f.write_text("this is not session output\n")
    assert main([str(f)]) == 2
