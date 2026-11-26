# Open checks and findings

## Resolved

- **`proto_state` meaning (corrected 2026-11-26).** Fortinet's Administration Guide says a
  TCP `proto_state` has two digits because both directions are tracked. The CLI reference
  (`diagnose sys session filter proto-state`) names the values 0 ANY/NONE, 1 ESTABLISHED,
  2 SYN_SENT, 3 SYN_RECV, 4 FIN_WAIT, 5 TIME_WAIT, 6 CLOSE, 7 CLOSE_WAIT, 8 LAST_ACK,
  9 LISTEN. On 7.6.6 an idle local SSH session shows `01`; the guide's forwarded TCP
  example shows `11`. The tool now names each digit and joins them with `/`. ICMP always
  shows `00`; UDP uses 0 (no reply seen) and 1 (reply seen), per the guide.
- Real capture added: `tests/fixtures/real_7_6_6_local_ssh.txt` (IPs and MAC genericised).
  It showed three things the from-memory format got wrong, all now handled:
  `vd=0:20` (index:id), `policy_id=4294967295` for local sessions (no policy), and a
  `total session: N` footer.

## Still to check

1. **Which `proto_state` digit is which direction.** The guide does not say. Test with a
   forwarded TCP session and compare `01` (local) with `11` (forwarded).
2. **More real blocks.** UDP, ICMP, SNAT, DNAT, IPsec and IPv6 sessions from 7.6.6.
   The IPv6 `hook=` address format is untested.
3. **Hook names seen:** pre, post, in, out. Check for others (fwd?).
4. **UDP `proto_state`.** The guide says 0 = no reply seen, 1 = reply seen. State names
   are still not shown for UDP; check on a real UDP session before adding them.
5. **Per-VDOM output.** Any header per VDOM? Multi-VDOM units untested.

## Blog corrections needed

- NSE4 CLI reference Part 2 (session table): corrected 2026-11-26.

## Real 7.6.6 observations (2026-11-26)
- Multi-VDOM capture, 20 sessions: all 10 TCP read `01`, forwarded and local, so the guide's `11` example did not reproduce. UDP: `00` with no reply, `01` with reply.
- Half-closed capture: client held a connection open to sshd with no data; sshd closed it from the server side. State went `01` -> `07` (CLOSE_WAIT) and `expire` dropped from 3600 to the half-close timer. Second digit changed, first stayed `0`. Session gone after the timer.
- Still open: what the first digit means, and which digit is which direction. Needs a client-closes-first capture.
