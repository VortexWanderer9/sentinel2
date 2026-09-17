//! Formats analysis results as a terminal table or JSON.
//! Fleshed out in a later commit.

use crate::analyzer::Finding;
use crate::parser::LogEvent;

pub fn print_table(_findings: &[Finding], _events: &[LogEvent]) {
    println!("(report not yet implemented)");
}

pub fn print_json(_findings: &[Finding], _events: &[LogEvent]) {
    println!("{{}}");
}
