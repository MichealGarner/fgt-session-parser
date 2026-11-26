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


def test_older_than(capsys):
    _, rows = run_json(capsys, "--older-than", "30")
    assert sorted(r["policy_id"] for r in rows) == [5, 12]


def test_newer_than(capsys):
    _, rows = run_json(capsys, "--newer-than", "30")
    assert [r["policy_id"] for r in rows] == [7]


def test_age_filters_combine(capsys):
    _, rows = run_json(capsys, "--older-than", "10", "--newer-than", "100")
    assert sorted(r["policy_id"] for r in rows) == [5, 7]


def test_age_filter_excludes_sessions_without_duration(tmp_path, capsys):
    f = tmp_path / "s.txt"
    f.write_text(
        "session info: proto=6 proto_state=01\n"
        "hook=out dir=org act=noop 10.0.0.1:1000->10.0.0.2:80(0.0.0.0:0)\n"
    )
    assert main([str(f), "--json", "--older-than", "0"]) == 0
    assert json.loads(capsys.readouterr().out) == []


PUBLISHED = str(Path(__file__).parent / "fixtures" / "published_lines.txt")


def test_summary_sorted_by_total_bytes(capsys):
    code, rows = run_json(capsys, "--summary")
    assert code == 0
    assert [r["policy_id"] for r in rows] == [12, 5, 7]
    assert rows[1]["bytes_org"] == 1234 and rows[1]["bytes_reply"] == 5678
    assert rows[1]["bytes_total"] == 6912


def test_summary_top_limits_policies(capsys):
    _, rows = run_json(capsys, "--summary", "--top", "1")
    assert [r["policy_id"] for r in rows] == [12]


def test_summary_respects_filters(capsys):
    _, rows = run_json(capsys, "--summary", "--proto", "udp")
    assert [(r["policy_id"], r["sessions"]) for r in rows] == [(7, 1)]


def test_summary_groups_sessions_and_reports_unknown_bytes(capsys):
    assert main([PUBLISHED, "--summary", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows == [{
        "policy_id": 44, "sessions": 2,
        "bytes_org": None, "bytes_reply": None, "bytes_total": None,
    }]


def test_summary_table_runs(capsys):
    assert main([FIXTURE, "--summary"]) == 0
    assert "3 polic(ies) from 3 of 3 session(s)" in capsys.readouterr().out
