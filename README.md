# _v.1

A small, dependency-light Rust CLI that scans sshd-style auth logs for
brute-force login attempts and user-enumeration bursts.

## Why

Most brute-force detection is either "grep the log yourself" or a full
SIEM. `sentinel` sits in between: point it at an `auth.log`, get a report
of which IPs hammered your SSH port and how hard.

## How it works

1. **Parse** — a regex pulls the timestamp, status (`Failed password` /
   `Accepted password`), optional `invalid user` marker, username, and
   source IP out of each line.
2. **Analyze** — for each IP, a sliding time window (default 60s) counts
   failed attempts. If the count in any window reaches the threshold
   (default 5), the IP is flagged; overlapping windows are merged into one
   burst so a long attack shows up as a single finding, not dozens.
3. **Report** — findings print as a table or, with `--json`, as JSON for
   piping into other tooling.

## Build

```bash
cargo build --release
```

## Usage

```bash
sentinel --file samples/auth.log
sentinel --file /var/log/auth.log --threshold 8 --window 30
sentinel --file /var/log/auth.log --json
```

`--threshold` and `--window` must both be positive values. A threshold of
`1` reports every failed login; use the defaults for a more conservative
starting point.

```
USAGE:
    sentinel --file <path> [OPTIONS]

OPTIONS:
    -f, --file <path>        Path to an sshd-style auth log (required)
    -t, --threshold <n>      Failed attempts within the window to flag an IP (default: 5)
    -w, --window <secs>      Sliding time window in seconds (default: 60)
        --json                Output JSON instead of a table
    -h, --help                Show this help message
```

### Example

Against the included `samples/auth.log`:

```
sentinel — auth log analysis
10 log lines parsed

IP                FAILED      USERS       FROM         TO
----------------------------------------------------------
203.0.113.5            6          6   03:14:10   03:14:41

1 suspicious IP(s) flagged.
```

## Tests

```bash
cargo test
```

Covers log parsing (valid lines, unrelated lines), the sliding-window
analyzer (threshold, window boundaries, burst merging, ignoring successful
logins), report time formatting, and validation of command-line settings.

## Limitations

- Only the time-of-day (`HH:MM:SS`) is used for windowing, not the date —
  fine for analyzing a single day's log or a rotated file, but a log
  spanning midnight will wrap incorrectly. A future version could parse
  the full timestamp with a year supplied on the command line.
- Only recognizes the standard OpenSSH `sshd` log format shown above;
  other daemons or non-default log formats aren't parsed.
- IPv4 only.

## License

MIT
