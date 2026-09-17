//! Detects brute-force patterns from parsed log events.
//!
//! Strategy: for each IP, look at every failed/invalid-user attempt as the
//! start of a candidate window `[t, t + window_secs)`. Count how many failed
//! attempts from that IP fall inside the window. If the count reaches
//! `threshold`, the IP is flagged. Overlapping windows from the same IP are
//! merged into a single finding covering the full burst.

use crate::parser::{EventKind, LogEvent};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq)]
pub struct Finding {
    pub ip: String,
    pub failed_count: u32,
    pub distinct_users: u32,
    pub window_start: u32,
    pub window_end: u32,
}

fn is_failed(kind: &EventKind) -> bool {
    matches!(kind, EventKind::FailedPassword | EventKind::InvalidUser)
}

pub fn analyze(events: &[LogEvent], threshold: u32, window_secs: u32) -> Vec<Finding> {
    // Group failed-attempt timestamps + users per IP, in chronological order.
    let mut by_ip: BTreeMap<&str, Vec<&LogEvent>> = BTreeMap::new();
    for e in events.iter().filter(|e| is_failed(&e.kind)) {
        by_ip.entry(e.ip.as_str()).or_default().push(e);
    }

    let mut findings = Vec::new();

    for (ip, mut attempts) in by_ip {
        attempts.sort_by_key(|e| e.time_secs);

        // Two-pointer sliding window over this IP's failed attempts.
        let mut start_idx = 0usize;
        let mut merged: Option<(u32, u32, usize, usize)> = None; // (win_start, win_end, first_idx, last_idx)

        for end_idx in 0..attempts.len() {
            while attempts[end_idx].time_secs - attempts[start_idx].time_secs
                > window_secs.saturating_sub(1)
            {
                start_idx += 1;
            }
            let count = (end_idx - start_idx + 1) as u32;
            if count >= threshold {
                let win_start = attempts[start_idx].time_secs;
                let win_end = attempts[end_idx].time_secs;
                match &mut merged {
                    Some((_, m_end, _, m_last)) if win_start <= *m_end => {
                        // Overlaps the current burst: extend it.
                        *m_end = win_end;
                        *m_last = end_idx;
                    }
                    _ => {
                        merged = Some((win_start, win_end, start_idx, end_idx));
                    }
                }
            }
        }

        if let Some((win_start, win_end, first_idx, last_idx)) = merged {
            let slice = &attempts[first_idx..=last_idx];
            let mut users: Vec<&str> = slice.iter().map(|e| e.user.as_str()).collect();
            users.sort_unstable();
            users.dedup();

            findings.push(Finding {
                ip: ip.to_string(),
                failed_count: slice.len() as u32,
                distinct_users: users.len() as u32,
                window_start: win_start,
                window_end: win_end,
            });
        }
    }

    findings.sort_by(|a, b| b.failed_count.cmp(&a.failed_count));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::EventKind;

    fn ev(time_secs: u32, ip: &str, user: &str) -> LogEvent {
        LogEvent {
            time_secs,
            kind: EventKind::FailedPassword,
            user: user.to_string(),
            ip: ip.to_string(),
        }
    }

    #[test]
    fn flags_ip_with_burst_of_failures() {
        let events = vec![
            ev(0, "1.2.3.4", "root"),
            ev(5, "1.2.3.4", "admin"),
            ev(10, "1.2.3.4", "test"),
            ev(15, "1.2.3.4", "deploy"),
            ev(20, "1.2.3.4", "guest"),
        ];
        let findings = analyze(&events, 5, 60);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].ip, "1.2.3.4");
        assert_eq!(findings[0].failed_count, 5);
        assert_eq!(findings[0].distinct_users, 5);
    }

    #[test]
    fn does_not_flag_ip_below_threshold() {
        let events = vec![ev(0, "1.2.3.4", "root"), ev(5, "1.2.3.4", "admin")];
        let findings = analyze(&events, 5, 60);
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_attempts_spread_outside_window() {
        let events = vec![
            ev(0, "1.2.3.4", "root"),
            ev(100, "1.2.3.4", "admin"),
            ev(200, "1.2.3.4", "test"),
            ev(300, "1.2.3.4", "root"),
            ev(400, "1.2.3.4", "guest"),
        ];
        // 5 attempts total but none within a 60s window of each other.
        let findings = analyze(&events, 5, 60);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_successful_logins() {
        let mut events = vec![
            ev(0, "1.2.3.4", "root"),
            ev(5, "1.2.3.4", "admin"),
            ev(10, "1.2.3.4", "test"),
            ev(15, "1.2.3.4", "root"),
        ];
        events.push(LogEvent {
            time_secs: 20,
            kind: EventKind::Accepted,
            user: "deploy".to_string(),
            ip: "1.2.3.4".to_string(),
        });
        // Only 4 failed attempts -> below threshold of 5.
        let findings = analyze(&events, 5, 60);
        assert!(findings.is_empty());
    }
}
