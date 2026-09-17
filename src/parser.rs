//! Parses sshd-style auth log lines into structured `LogEvent`s.
//! Fleshed out in a later commit.

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

pub fn parse_log(_raw: &str) -> Vec<LogEvent> {
    Vec::new()
}
