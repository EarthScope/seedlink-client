# Changelog

## Unreleased

- Log connection loss and pending reconnect during streaming
- Track and resume per-station sequences for wildcard station IDs in the state file
- Pipeline v4 STATION/SELECT/DATA negotiation commands instead of waiting for each reply
- Wrap the v3 DATA/FETCH resume sequence number at 24 bits, matching libslink
- Raise SeedLinkError on non-ASCII v4 header bytes so collect() reconnects instead of crashing
- Reject commands containing non-ASCII or control characters, preventing CR/LF command injection
- Skip an undecodable v3 packet with a warning instead of reconnecting to it forever
- Raise SeedLinkError with the server's message when an INFO request is rejected
- Treat an idle timeout of 0 (-nt 0) as disabled, matching slinktool
- Reset the idle timeout on keepalive/INFO replies too, matching libslink
- Bound reading a partly received packet by the idle timeout so a stalled frame can't hang collect()
- Close the connection when negotiate() fails rather than leave a partial selection on the server
- Mask AUTH passwords and tokens in debug logs and error messages
- Fsync the state file before renaming it into place, and stop briefly altering the process umask
- Reject --auth without both a username and password instead of sending an empty one
- Report CLI file errors (dumpfile, state file) as errors rather than tracebacks or silence
- Treat only '*' and '?' as station ID wildcards, matching the protocol specification; '[' is now literal
- Reject v3 station IDs that are not NET_STA, and accept 'STA NET' in the shell's v3 STATION command
- Resume a wildcard station ID that matches an exact one with plain DATA, and save it as UNSET in multi-station mode
- Combine the selectors of all matching wildcard station IDs for a station received via them
- Continue v4 negotiation when a station also matched by a wildcard station ID is rejected

## 0.2.0

- Add -3/-4 shorthand flags to pin the protocol version, alongside --protocol
- Print packet details in the interactive shell with -p/-u, plus runtime `details`/`samples` commands to change the level mid-session
- Many, many fixes and improvements

## 0.1.0

- Initial code.  SeedLink v3 and v4 functional and sync and async APIs.

