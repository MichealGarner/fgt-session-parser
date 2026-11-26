# Open checks and findings

## Resolved

- **`proto_state` meaning (resolved 2026-11-26).** On FortiOS 7.6.6 an idle SSH session to
  the unit shows `proto_state=01`, which is ESTABLISHED in Fortinet's session table KB:
  0 NONE, 1 ESTABLISHED, 2 SYN_SENT, 3 SYN & SYN/ACK, 4 FIN_WAIT, 5 TIME_WAIT, 6 CLOSE,
  7 CLOSE_WAIT (07 from a separate Fortinet KB article). The tool names TCP states only
  and leaves anything else raw.
- Real capture added: `tests/fixtures/real_7_6_6_local_ssh.txt` (IPs and MAC genericised).
  It showed three things the from-memory format got wrong, all now handled:
  `vd=0:20` (index:id), `policy_id=4294967295` for local sessions (no policy), and a
  `total session: N` footer.

## Still to check

1. **Two-digit `proto_state`.** Fortinet's 7.4 admin guide shows `proto_state=11` on a
   TCP session. 7.6.6 printed `01`. Such values are shown raw. Find out when/why.
2. **More real blocks.** UDP, ICMP, SNAT, DNAT, IPsec and IPv6 sessions from 7.6.6.
   The IPv6 `hook=` address format is untested.
3. **Hook names seen:** pre, post, in, out. Check for others (fwd?).
4. **UDP `proto_state`.** Published sample shows 01 for UDP; the synthetic fixture uses 00.
   State names are not shown for UDP until the meaning is verified.
5. **Per-VDOM output.** Any header per VDOM? Multi-VDOM units untested.

## Blog corrections needed

- NSE4 CLI reference Part 2 (session table) has the wrong `proto_state` table
  (01 SYN_SENT ... 03 ESTABLISHED) and reads `proto_state=05` as CLOSE_WAIT.
  Per Fortinet, 05 is TIME_WAIT and CLOSE_WAIT is 07.
