//! `vcd` — local file triage.
//!
//! Exit codes: `0` nothing detected, `1` malicious or suspicious finding,
//! `2` the scan itself failed.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use vcd_core::{
    Coverage, DirectoryReport, EngineReport, EngineStatus, ScanReport, ScanScope, Scanner, Verdict,
};

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

    let target = Path::new(path);
    let started = Instant::now();
    let scope = if target.is_dir() {
        ScanScope::Tree
    } else {
        ScanScope::SingleFile
    };

    // Built once: a tree scan shares one ClamAV daemon across every file.
    let scanner = Scanner::with_local_engines(scope);

    if scope == ScanScope::Tree {
        return match scanner.scan_directory(target) {
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
                    print_tree(&report);
                    println!();
                    println!("Took     {}", human_duration(started.elapsed()));
                }

                tree_exit_code(&report)
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(2)
            }
        };
    }

    match scanner.scan(target) {
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
                println!(
                    "Took     {} (engine setup included)",
                    human_duration(started.elapsed())
                );
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
}

fn print_tree(report: &DirectoryReport) {
    println!("Root     {}", report.root.display());
    println!("Files    {}", report.summary.files);
    println!();

    for file in &report.files {
        let name = file
            .target
            .strip_prefix(&report.root)
            .unwrap_or(&file.target)
            .display()
            .to_string();
        let findings = findings_line(file);

        if findings.is_empty() {
            println!("{:<12} {}", file.verdict.label(), shorten(&name, 60));
        } else {
            println!(
                "{:<12} {}  {}",
                file.verdict.label(),
                shorten(&name, 60),
                shorten(&findings, 90)
            );
        }
    }

    for failure in &report.errors {
        println!(
            "{:<12} {}: {}",
            "ERROR",
            shorten(&failure.path.display().to_string(), 60),
            shorten(&failure.error, 90)
        );
    }

    println!();
    println!(
        "{} files | {} malicious | {} suspicious | {} undetected | {} inconclusive | {} unknown | {} errors",
        report.summary.files,
        report.summary.malicious,
        report.summary.suspicious,
        report.summary.undetected,
        report.summary.inconclusive,
        report.summary.unknown,
        report.summary.errors
    );
}

fn findings_line(file: &ScanReport) -> String {
    let mut parts = Vec::new();
    for engine in &file.engines {
        for detection in &engine.detections {
            parts.push(format!("{}: {}", engine.engine, detection.detail));
        }
    }
    parts.join("; ")
}

fn tree_exit_code(report: &DirectoryReport) -> ExitCode {
    if report.summary.malicious + report.summary.suspicious > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
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

/// Keep a value readable in a terminal; the JSON keeps the full text.
fn shorten(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }

    let mut shortened: String = value.chars().take(limit.saturating_sub(3)).collect();
    shortened.push_str("...");
    shortened
}

fn coverage_label(coverage: &Coverage) -> String {
    match coverage {
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

fn human_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis < 1000 {
        format!("{millis} ms")
    } else {
        format!("{:.1} s", duration.as_secs_f64())
    }
}

fn print_usage() {
    println!(
        "\
vcd - local malware triage. No upload, no size cap of its own.

Usage:
  vcd scan <path> [--json]   Analyze a file or a directory tree
  vcd version                Print the version

Exit codes:
  0  nothing detected
  1  malicious or suspicious finding
  2  the scan itself failed"
    );
}
