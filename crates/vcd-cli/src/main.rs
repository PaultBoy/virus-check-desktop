//! `vcd` — local file triage.
//!
//! Exit codes: `0` nothing detected, `1` malicious or suspicious finding,
//! `2` the scan itself failed.

use std::path::Path;
use std::process::ExitCode;

use vcd_core::{Coverage, EngineReport, EngineStatus, ScanReport, Scanner, Verdict};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run(&args)
}

fn run(args: &[String]) -> ExitCode {
    let Some(command) = args.first().map(String::as_str) else {
        print_usage();
        return ExitCode::from(2);
    };

    match command {
        "help" | "-h" | "--help" => {
            print_usage();
            ExitCode::SUCCESS
        }
        "version" | "-v" | "--version" => {
            println!("vcd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "scan" => scan_command(&args[1..]),
        other => {
            eprintln!("error: unknown command '{other}'");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn scan_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first() else {
        eprintln!("error: scan needs a path");
        return ExitCode::from(2);
    };

    let mut json = false;
    for extra in &args[1..] {
        if extra == "--json" {
            json = true;
        } else {
            eprintln!("error: unknown option '{extra}'");
            return ExitCode::from(2);
        }
    }

    match Scanner::with_builtin().scan(Path::new(path)) {
        Ok(report) => {
            if json {
                match serde_json::to_string_pretty(&report) {
                    Ok(text) => println!("{text}"),
                    Err(error) => {
                        eprintln!("error: cannot serialize report: {error}");
                        return ExitCode::from(2);
                    }
                }
            } else {
                print_human(&report);
            }

            if matches!(report.verdict, Verdict::Malicious | Verdict::Suspicious) {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn print_human(report: &ScanReport) {
    println!("Target   {}", report.target.display());
    println!("Size     {}", human_size(report.size));
    match &report.extension {
        Some(extension) => println!(
            "Type     {} (named .{extension})",
            report.content_type.as_str()
        ),
        None => println!("Type     {}", report.content_type.as_str()),
    }
    println!("MD5      {}", report.hashes.md5);
    println!("SHA-1    {}", report.hashes.sha1);
    println!("SHA-256  {}", report.hashes.sha256);
    println!();
    println!("Engines");

    for engine in &report.engines {
        println!(
            "  {:<14} {:<13} {:>5} ms  {}",
            engine.engine,
            engine.status.as_str(),
            engine.duration_ms,
            coverage_label(&engine.coverage)
        );

        match &engine.status {
            EngineStatus::Unavailable { hint } => println!("                 hint: {hint}"),
            EngineStatus::Failed { error } => println!("                 error: {error}"),
            _ => {}
        }

        for fact in &engine.facts {
            println!("    {}: {}", fact.name, shorten(&fact.value, 80));
        }

        print_detections(engine);
    }

    println!();
    println!("Verdict  {}", report.verdict.label());
    println!("Took     {} ms", report.duration_ms);
}

fn print_detections(engine: &EngineReport) {
    for detection in &engine.detections {
        println!(
            "    - [{}] {}: {}",
            detection.severity.as_str(),
            detection.name,
            detection.detail
        );
    }
}

/// Keep a fact readable in a terminal; the JSON keeps the full value.
fn shorten(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }

    let mut shortened: String = value.chars().take(limit.saturating_sub(3)).collect();
    shortened.push_str("...");
    shortened
}

fn coverage_label(coverage: &Coverage) -> String {    match coverage {
        Coverage::Complete => "coverage: complete".to_string(),
        Coverage::Partial {
            scanned_bytes,
            reason,
        } => format!("coverage: {} scanned ({reason})", human_size(*scanned_bytes)),
        Coverage::None { reason } => format!("coverage: none ({reason})"),
    }
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {} ({bytes} bytes)", UNITS[unit])
    }
}

fn print_usage() {
    println!(
        "\
vcd - local malware triage. No upload, no size cap of its own.

Usage:
  vcd scan <path> [--json]   Analyze one file
  vcd version                Print the version

Exit codes:
  0  nothing detected
  1  malicious or suspicious finding
  2  the scan itself failed"
    );
}
