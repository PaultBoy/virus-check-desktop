//! `vcd` — local file triage.
//!
//! Exit codes: `0` nothing detected, `1` malicious or suspicious finding,
//! `2` the scan could not inspect what it was given: an engine failed, content
//! was skipped, or a file could not be read.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use vcd_core::{
    Backend, Coverage, DetonateOptions, Detonation, DirectoryReport, EngineReport, EngineStatus,
    ScanReport, ScanScope, Scanner, Verdict, clamav_status, detect_support, detonate_with,
    enable_windows_sandbox, install_portable_clamav,
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
        "detonate" => detonate_command(&args[1..]),
        "sandbox" => sandbox_command(&args[1..]),
        "clamav" => clamav_command(&args[1..]),
        other => {
            eprintln!("error: unknown command '{other}'");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn clamav_command(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("install") => match install_portable_clamav() {
            Ok(root) => {
                println!("ClamAV is ready at {}", root.display());
                println!("Directory scans will use it in process; no administrator was needed.");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("error: {error}");
                ExitCode::from(2)
            }
        },
        Some("status") | None => {
            let status = clamav_status();

            match &status.portable {
                Some(root) => println!("Portable install  {}", root.display()),
                None => println!("Portable install  not installed (run: vcd clamav install)"),
            }

            match &status.system {
                Some(root) => println!("System install    {}", root.display()),
                None => println!("System install    not found"),
            }

            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("error: unknown clamav action '{other}' (expected install or status)");
            ExitCode::from(2)
        }
    }
}

fn sandbox_command(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("enable") => enable_sandbox(),
        Some("status") | None => {
            let support = detect_support();
            println!("Edition          {}", support.edition.as_str());
            println!(
                "Windows Sandbox  {}",
                if support.windows_sandbox {
                    "installed"
                } else {
                    "not installed"
                }
            );
            println!(
                "Sandboxie        {}",
                if support.sandboxie {
                    "installed"
                } else {
                    "not installed"
                }
            );
            match support.recommended() {
                Some(backend) => println!("Recommended      {}", backend.as_str()),
                None => println!("Recommended      none"),
            }
            println!();
            println!("{}", support.guidance());
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("error: unknown sandbox action '{other}' (expected status or enable)");
            ExitCode::from(2)
        }
    }
}

fn enable_sandbox() -> ExitCode {
    let support = detect_support();

    if support.windows_sandbox {
        println!("Windows Sandbox is already installed.");
        return ExitCode::SUCCESS;
    }

    if !support.edition.supports_windows_sandbox() {
        eprintln!(
            "error: Windows Sandbox requires Pro/Enterprise (this is {}). Install Sandboxie-Plus instead.",
            support.edition.as_str()
        );
        return ExitCode::from(2);
    }

    match enable_windows_sandbox() {
        Ok(log) => {
            println!("A UAC prompt is asking to enable Windows Sandbox.");
            println!("Log:    {}", log.display());
            println!("A reboot is required before the sandbox works.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn detonate_command(args: &[String]) -> ExitCode {
    let Some(path) = args.first() else {
        eprintln!("error: detonate needs a path");
        return ExitCode::from(2);
    };

    let mut options = DetonateOptions::default();
    let mut backend: Option<Backend> = None;
    let mut json = false;
    let mut index = 1;

    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--network" => options.network = true,
            "--backend" => {
                index += 1;
                backend = match args.get(index).map(String::as_str) {
                    Some("windows") => Some(Backend::WindowsSandbox),
                    Some("sandboxie") => Some(Backend::Sandboxie),
                    _ => {
                        eprintln!(
                            "error: --backend expects 'windows' (virtual machine) or 'sandboxie' (shared kernel)"
                        );
                        return ExitCode::from(2);
                    }
                };
            }
            "--duration" | "--timeout" => {
                let flag = args[index].clone();
                index += 1;
                let value = args.get(index).and_then(|value| value.parse::<u64>().ok());
                match (flag.as_str(), value) {
                    ("--duration", Some(seconds)) if (1..=300).contains(&seconds) => {
                        options.duration = Duration::from_secs(seconds);
                    }
                    ("--timeout", Some(seconds)) if (30..=900).contains(&seconds) => {
                        options.timeout = Duration::from_secs(seconds);
                    }
                    ("--duration", _) => {
                        eprintln!("error: --duration expects 1 to 300 seconds");
                        return ExitCode::from(2);
                    }
                    _ => {
                        eprintln!("error: --timeout expects 30 to 900 seconds");
                        return ExitCode::from(2);
                    }
                }
            }
            other => {
                eprintln!("error: unknown option '{other}'");
                return ExitCode::from(2);
            }
        }
        index += 1;
    }

    if options.timeout <= options.duration {
        eprintln!(
            "error: --timeout ({} s) must be greater than --duration ({} s): booting and collecting happen inside it",
            options.timeout.as_secs(),
            options.duration.as_secs()
        );
        return ExitCode::from(2);
    }

    let support = detect_support();
    let backend = match backend.or_else(|| support.recommended()) {
        Some(backend) => backend,
        None => {
            eprintln!("error: no detonation backend available");
            eprintln!("       {}", support.guidance());
            return ExitCode::from(2);
        }
    };

    match detonate_with(Path::new(path), &options, backend) {
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
                print_detonation(&report);
            }

            // A run that was stopped before the sample started collected
            // nothing; exiting 0 would read as success to a script.
            let collected_nothing =
                !report.executed && report.timed_out && report.unsupported.is_none();
            if report.error.is_some() || collected_nothing {
                ExitCode::from(2)
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

fn print_detonation(report: &Detonation) {
    println!("Sample     {}", report.sample.display());
    println!("Backend    {}", report.backend.as_str());
    println!(
        "Networking {}",
        if report.network_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );

    match (&report.unsupported, report.executed) {
        (Some(extension), _) => {
            println!("Executed   no: {extension} is not a type Windows can run")
        }
        (None, true) => println!("Executed   yes"),
        (None, false) => println!("Executed   no"),
    }
    if let Some(error) = &report.error {
        println!("Error      {error}");
    }
    println!(
        "Result     {:.1} s{}",
        report.duration_ms as f64 / 1000.0,
        if report.timed_out {
            ", timed out (partial data)"
        } else {
            ""
        }
    );

    println!();
    println!("Processes  {}", report.processes.len());
    for process in report.processes.iter().take(20) {
        println!(
            "  pid {} (parent {}) {}{}",
            process.pid,
            process.parent,
            process.name.as_deref().unwrap_or("?"),
            process
                .command
                .as_deref()
                .map(|command| format!("  {command}"))
                .unwrap_or_default()
        );
    }

    if report.connections.is_empty() {
        println!("Network    no connections observed");
    } else {
        println!("Network    {} connection(s)", report.connections.len());
        for connection in report.connections.iter().take(20) {
            println!(
                "  {} from pid {} ({})",
                connection.remote, connection.pid, connection.state
            );
        }
    }

    if report.dns.is_empty() {
        println!("DNS        no lookups observed");
    } else {
        println!("DNS        {}", report.dns.join(", "));
    }

    println!(
        "Files      {} created, {} modified",
        report.files_created.len(),
        report.files_modified.len()
    );
    for path in report.files_created.iter().take(20) {
        println!("  + {path}");
    }

    println!("Registry   {} change(s)", report.registry_changed.len());
    for change in &report.registry_changed {
        println!("  {change}");
    }

    println!("Dropped    {} file(s) kept", report.dropped.len());
    for path in &report.dropped {
        println!("  - {}", path.display());
    }

    println!();
    println!("Caveats");
    for caveat in &report.caveats {
        println!("  - {caveat}");
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
            } else if could_not_conclude(&report) {
                ExitCode::from(2)
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
    } else if report.files.iter().any(could_not_conclude) || !report.errors.is_empty() {
        // A tree with an engine failure, content nobody inspected, or files
        // that could not be read is not a clean tree.
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// A missing optional engine leaves the verdict inconclusive but is not a
/// failure: the engines that are installed inspected everything they own. An
/// engine that failed, or one that inspected zero bytes of the target, is.
fn could_not_conclude(report: &ScanReport) -> bool {
    report.engines.iter().any(|engine| {
        matches!(engine.status, EngineStatus::Failed { .. })
            || matches!(
                engine.coverage,
                Coverage::Partial {
                    scanned_bytes: 0,
                    ..
                }
            )
    })
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
        } => format!(
            "coverage: {} scanned ({reason})",
            human_size(*scanned_bytes)
        ),
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
  vcd detonate <path> [--duration N] [--timeout N] [--backend windows|sandboxie] [--network] [--json]
                             Run the sample in a sandbox
  vcd sandbox status         Show which backends this machine can use
  vcd sandbox enable         Enable Windows Sandbox (Pro/Enterprise, needs admin + reboot)
  vcd clamav install         Download ClamAV into your profile (no administrator needed)
  vcd clamav status          Show the ClamAV installations found
  vcd version                Print the version

Exit codes:
  0  nothing detected
  1  malicious or suspicious finding
  2  an engine failed, content was skipped, or a file could not be read"
    );
}
