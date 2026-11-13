# Changelog

## Unreleased

- Log connection loss and pending reconnect during streaming
- Track and resume per-station sequences for wildcard station IDs in the state file
- Pipeline v4 STATION/SELECT/DATA negotiation commands instead of waiting for each reply
- Wrap the v3 DATA/FETCH resume sequence number at 24 bits, matching libslink
- Raise SeedLinkError on non-ASCII v4 header bytes so collect() reconnects instead of crashing

## 0.2.0

- Add -3/-4 shorthand flags to pin the protocol version, alongside --protocol
- Print packet details in the interactive shell with -p/-u, plus runtime `details`/`samples` commands to change the level mid-session
- Many, many fixes and improvements

## 0.1.0

- Initial code.  SeedLink v3 and v4 functional and sync and async APIs.

