//! Formats analysis results as a terminal table or JSON.

use crate::analyzer::Finding;
use crate::parser::LogEvent;

fn fmt_hms(secs: u32) -> String {
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

pub fn print_table(findings: &[Finding], events: &[LogEvent]) {
    println!("sentinel — auth log analysis");
    println!("{} log lines parsed\n", events.len());

    if findings.is_empty() {
        println!("No brute-force patterns detected.");
        return;
    }

    println!(
        "{:<16} {:>7} {:>10} {:>10} {:>10}",
        "IP", "FAILED", "USERS", "FROM", "TO"
    );
    println!("{}", "-".repeat(58));

    for f in findings {
        println!(
            "{:<16} {:>7} {:>10} {:>10} {:>10}",
            f.ip,
            f.failed_count,
            f.distinct_users,
            fmt_hms(f.window_start),
            fmt_hms(f.window_end),
        );
    }

    println!(
        "\n{} suspicious IP(s) flagged.",
        findings.len()
    );
}

pub fn print_json(findings: &[Finding], events: &[LogEvent]) {
    let mut out = String::from("{\n");
    out.push_str(&format!("  \"events_parsed\": {},\n", events.len()));
    out.push_str("  \"findings\": [\n");

    for (i, f) in findings.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"ip\": \"{}\",\n", f.ip));
        out.push_str(&format!("      \"failed_count\": {},\n", f.failed_count));
        out.push_str(&format!("      \"distinct_users\": {},\n", f.distinct_users));
        out.push_str(&format!(
            "      \"window_start\": \"{}\",\n",
            fmt_hms(f.window_start)
        ));
        out.push_str(&format!(
            "      \"window_end\": \"{}\"\n",
            fmt_hms(f.window_end)
        ));
        out.push_str(if i + 1 == findings.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }

    out.push_str("  ]\n}");
    println!("{out}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_time_correctly() {
        assert_eq!(fmt_hms(0), "00:00:00");
        assert_eq!(fmt_hms(3661), "01:01:01");
        assert_eq!(fmt_hms(86399), "23:59:59");
    }
}
