// sentinel - a brute-force / suspicious SSH login detector for auth logs
//
// Usage:
//   sentinel --file path/to/auth.log [--threshold 5] [--window 60] [--json]
//
// See README.md for details.

mod parser;
mod analyzer;
mod report;

use std::env;
use std::process;

pub struct Config {
    pub file_path: String,
    pub threshold: u32,
    pub window_secs: u32,
    pub json: bool,
}

impl Config {
    fn from_args(args: &[String]) -> Result<Config, String> {
        let mut file_path: Option<String> = None;
        let mut threshold: u32 = 5;
        let mut window_secs: u32 = 60;
        let mut json = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--file" | "-f" => {
                    i += 1;
                    let val = args.get(i).ok_or("--file requires a path argument")?;
                    file_path = Some(val.clone());
                }
                "--threshold" | "-t" => {
                    i += 1;
                    let val = args.get(i).ok_or("--threshold requires a number")?;
                    threshold = val
                        .parse()
                        .map_err(|_| format!("invalid --threshold value: {val}"))?;
                    if threshold == 0 {
                        return Err("--threshold must be at least 1".to_string());
                    }
                }
                "--window" | "-w" => {
                    i += 1;
                    let val = args.get(i).ok_or("--window requires a number of seconds")?;
                    window_secs = val
                        .parse()
                        .map_err(|_| format!("invalid --window value: {val}"))?;
                    if window_secs == 0 {
                        return Err("--window must be at least 1 second".to_string());
                    }
                }
                "--json" => {
                    json = true;
                }
                "--help" | "-h" => {
                    print_usage();
                    process::exit(0);
                }
                other => {
                    return Err(format!("unrecognized argument: {other}"));
                }
            }
            i += 1;
        }

        let file_path = file_path.ok_or("missing required --file <path> argument")?;

        Ok(Config {
            file_path,
            threshold,
            window_secs,
            json,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn rejects_zero_threshold() {
        let error = Config::from_args(&args(&["sentinel", "--file", "auth.log", "--threshold", "0"]))
            .expect_err("zero must not be a valid threshold");
        assert_eq!(error, "--threshold must be at least 1");
    }

    #[test]
    fn rejects_zero_window() {
        let error = Config::from_args(&args(&["sentinel", "--file", "auth.log", "--window", "0"]))
            .expect_err("zero must not be a valid window");
        assert_eq!(error, "--window must be at least 1 second");
    }
}

fn print_usage() {
    println!(
        "sentinel - brute-force / suspicious SSH login detector\n\n\
         USAGE:\n    sentinel --file <path> [OPTIONS]\n\n\
         OPTIONS:\n    \
         -f, --file <path>        Path to an sshd-style auth log (required)\n    \
         -t, --threshold <n>      Failed attempts within the window to flag an IP (default: 5)\n    \
         -w, --window <secs>      Sliding time window in seconds (default: 60)\n        \
         --json                Output JSON instead of a table\n    \
         -h, --help                Show this help message"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let config = match Config::from_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}\n");
            print_usage();
            process::exit(2);
        }
    };

    let raw_lines = match std::fs::read_to_string(&config.file_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("error: could not read '{}': {e}", config.file_path);
            process::exit(1);
        }
    };

    let events = parser::parse_log(&raw_lines);
    let findings = analyzer::analyze(&events, config.threshold, config.window_secs);

    if config.json {
        report::print_json(&findings, &events);
    } else {
        report::print_table(&findings, &events);
    }
}
