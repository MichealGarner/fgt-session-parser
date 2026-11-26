# Things to verify when back online

1. **`proto_state` meaning.** Two published posts disagree:
   - packet-flow Part 2 (session table): 00 NONE, 01 ESTABLISHED, 02 SYN_SENT, 03 SYN_RECV ...
   - NSE4 CLI reference Part 2: 01 SYN_SENT, 02 SYN_RCVD, 03 ESTABLISHED ...
   Neither is trusted yet. The tool shows the raw value. To settle it: open one SSH
   session through a lab FortiGate, filter to it, read `proto_state` while idle
   (known ESTABLISHED), then close it and read again. Check Fortinet docs too.
   Whichever post is wrong needs correcting on the blog.
2. **Full real blocks.** Capture one each of TCP, UDP, ICMP, SNAT, DNAT, IPsec and
   IPv6 sessions on 7.6.6 and add them (IPs genericised) to tests/fixtures/.
   The IPv6 `hook=` address format is untested.
3. **Hook names seen so far:** pre, post, in, out. Check for others (fwd?).
4. **Output framing.** Is there a "total session" footer? Blank lines between
   blocks? Any per-VDOM header? The parser ignores text before the first
   `session info:` and keeps unmatched lines in the previous block.
5. **UDP proto_state.** Published sample shows 01 for UDP; the synthetic fixture
   uses 00.
