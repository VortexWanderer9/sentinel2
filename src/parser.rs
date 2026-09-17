//! Parses sshd-style auth log lines into structured `LogEvent`s.
//!
//! Recognizes lines like:
//!   Jan 10 03:14:22 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2
//!   Jan 10 03:14:25 host sshd[1234]: Failed password for root from 203.0.113.5 port 51516 ssh2
//!   Jan 10 03:15:01 host sshd[1234]: Accepted password for deploy from 198.51.100.7 port 51600 ssh2
//!
//! Only the time-of-day is used for windowing (not the date), which is
//! sufficient for spotting bursts of activity within a single log file.
//! See README.md for that limitation.

use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq)]
pub enum EventKind {
    FailedPassword,
    Accepted,
    InvalidUser,
}

#[derive(Debug, Clone)]
pub struct LogEvent {
    pub time_secs: u32,
    pub kind: EventKind,
    pub user: String,
    pub ip: String,
}

fn line_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?x)
            ^\S+\s+\S+\s+(?P<time>\d{2}:\d{2}:\d{2})   # 'Jan 10 03:14:22'
            \s+\S+\s+sshd\[\d+\]:\s+
            (?P<status>Failed\ password|Accepted\ password)
            \s+for\s+
            (?:(?P<invalid>invalid\ user)\s+)?
            (?P<user>\S+)
            \s+from\s+
            (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
            ",
        )
        .expect("static regex is valid")
    })
}

/// Converts "HH:MM:SS" into seconds-since-midnight.
fn time_to_secs(time_str: &str) -> Option<u32> {
    let mut parts = time_str.split(':');
    let h: u32 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let s: u32 = parts.next()?.parse().ok()?;
    Some(h * 3600 + m * 60 + s)
}

pub fn parse_log(raw: &str) -> Vec<LogEvent> {
    let re = line_regex();
    let mut events = Vec::new();

    for line in raw.lines() {
        let Some(caps) = re.captures(line) else {
            continue;
        };

        let Some(time_secs) = caps.name("time").and_then(|m| time_to_secs(m.as_str())) else {
            continue;
        };

        let status = &caps["status"];
        let is_invalid_user = caps.name("invalid").is_some();

        let kind = if is_invalid_user {
            EventKind::InvalidUser
        } else if status == "Accepted password" {
            EventKind::Accepted
        } else {
            EventKind::FailedPassword
        };

        events.push(LogEvent {
            time_secs,
            kind,
            user: caps["user"].to_string(),
            ip: caps["ip"].to_string(),
        });
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_password_for_invalid_user() {
        let line = "Jan 10 03:14:22 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2";
        let events = parse_log(line);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::InvalidUser);
        assert_eq!(events[0].user, "admin");
        assert_eq!(events[0].ip, "203.0.113.5");
        assert_eq!(events[0].time_secs, 3 * 3600 + 14 * 60 + 22);
    }

    #[test]
    fn parses_accepted_login() {
        let line = "Jan 10 03:15:01 host sshd[1234]: Accepted password for deploy from 198.51.100.7 port 51600 ssh2";
        let events = parse_log(line);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::Accepted);
        assert_eq!(events[0].user, "deploy");
    }

    #[test]
    fn ignores_unrelated_lines() {
        let line = "Jan 10 03:15:02 host systemd[1]: Started Session.";
        let events = parse_log(line);
        assert!(events.is_empty());
    }
}
