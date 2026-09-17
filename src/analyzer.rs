//! Detects brute-force patterns from parsed log events.
//! Fleshed out in a later commit.

use crate::parser::LogEvent;

#[derive(Debug)]
pub struct Finding {
    pub ip: String,
    pub failed_count: u32,
    pub distinct_users: u32,
    pub window_start: u32,
    pub window_end: u32,
}

pub fn analyze(_events: &[LogEvent], _threshold: u32, _window_secs: u32) -> Vec<Finding> {
    Vec::new()
}
