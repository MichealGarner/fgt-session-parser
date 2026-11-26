# fgt-session-parser

Turns FortiGate `diagnose sys session list` output into a readable table or JSON.

The raw output is one long block of `key=value` pairs per session. This tool pulls out
the fields you usually want (protocol, source, destination, NAT, policy, age, expiry,
bytes each way) and lets you filter and sort them.

## Install

```
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Use

Save the output from the FortiGate to a file, then:

```
fgt-sessions sessions.txt
fgt-sessions sessions.txt --policy 12
fgt-sessions sessions.txt --src 192.168.1.0/24 --proto tcp
fgt-sessions sessions.txt --top 10
fgt-sessions sessions.txt --summary
fgt-sessions sessions.txt --summary --proto udp --older-than 60
fgt-sessions sessions.txt --older-than 180 --dst 198.51.100.0/24
fgt-sessions sessions.txt --json
```

Use `-` as the file name to read from stdin.

| Option | Meaning |
|------|------|
| `--policy N` | Only sessions that matched firewall policy N |
| `--src IP/CIDR` | Origin source address, exact or inside a network |
| `--dst IP/CIDR` | Origin destination address, exact or inside a network |
| `--proto tcp\|udp\|icmp` | Protocol |
| `--older-than SECONDS` | Only sessions older than this. Answers "did this flow start before the event?" |
| `--newer-than SECONDS` | Only sessions younger than this |
| `--top N` | The N busiest sessions by total bytes (with `--summary`, the N busiest policies) |
| `--summary` | One row per policy: session count and bytes sent, received and total |
| `--json` | JSON instead of a table |

Age and Expire are in seconds. Sent and Received are the original and reply directions.

## Exit codes

| Code | Meaning |
|------|------|
| 0 | OK |
| 1 | Cannot read the input |
| 2 | The input had content but no sessions could be parsed |

## What it does not do yet

- `proto_state` is shown as the raw value. The meaning of each value has not been
  verified against a live unit, so the tool does not name states.
- Tested against hand-built and published sample lines, not full captures from every
  FortiOS version. IPv6 sessions are untested. See `NOTES.md` for the open checks.
- Blocks it cannot parse are skipped and counted on stderr, not repaired.

## Tests

```
pytest -q
```
