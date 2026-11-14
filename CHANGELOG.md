# Changelog

## Unreleased

- Log connection loss and pending reconnect during streaming
- Track and resume each station received via a wildcard station ID individually in the state file,
  with the combined selectors of all matching wildcards; in multi-station mode the wildcard itself is saved as UNSET
- Continue v4 negotiation when a station also matched by a wildcard station ID is rejected
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
- Resume a v4 time window from a known sequence number with DATA <seq> <start> [<end>]
- Fail v3 negotiation when none of a station's selectors are accepted, instead of receiving all of its streams
- Fail negotiation on a reply that is neither OK nor ERROR, rather than treating it as a rejection
- Report an unreadable or invalid state file as an error before connecting, without overwriting it
- Include the station ID in verbose packet lines
- Track only stations received via a wildcard whose IDs contain letters, digits, underscores and dashes
- Do not combine negated selectors of multiple wildcard station IDs for a tracked station
- Do not track stations received via a wildcard in v3 uni-station mode
- Reject station IDs longer than 21 characters when adding streams
- Skip stream list entries with an empty station ID, and use the default selectors for an empty selector
- Report an empty stream list file as an error instead of requesting all stations
- Report an undecodable stream list file as a CLI error instead of a traceback
- Fail the connection on a BATCH reply that is neither OK nor ERROR
- Treat only an AUTH ERROR reply as an authentication failure; retry on any other invalid reply
- Reject v3 packet sequence numbers that are not 6 hex digits
- Reject v3 miniSEED records longer than 1 MiB
- Reject v4 packets carrying a reserved sequence number
- Detect the length of v3 miniSEED records without a Blockette 1000 from the next packet header
- Do not count the caller's time between packets toward the idle timeout
- Stop instead of reconnecting forever on configuration errors, e.g. a rejected forced protocol or invalid station ID
- Log and skip v4 JSON ERROR packets during streaming instead of reconnecting
- Fall back to v3 when the server advertises no recognized protocol version
- Send SLPROTO for a forced protocol version even when the server does not advertise it
- Report malformed state file lines as errors, and convert legacy comma-delimited timestamps to ISO
- Zero-pad v3 DATA/FETCH sequence numbers to 6 hex digits, matching the protocol specification
- Send keepalives only after the keepalive interval with no data, one at a time
- Bound connect, TLS handshake, and command I/O by default limits when no timeout is set
- Report the CLI as seedlink-client-cli in USERAGENT to distinguish it from the library
- Omit invalid timestamps from the state file
- Require pymseed >=1.0.1,<2
- Convert negated selectors between v3 and v4 syntax
- Log untracked wildcard-matched stations at debug level

## 0.2.0

- Add -3/-4 shorthand flags to pin the protocol version, alongside --protocol
- Print packet details in the interactive shell with -p/-u, plus runtime `details`/`samples`
  commands to change the level mid-session
- Many, many fixes and improvements

## 0.1.0

- Initial code.  SeedLink v3 and v4 functional and sync and async APIs.
