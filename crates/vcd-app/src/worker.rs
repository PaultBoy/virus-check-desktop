//! Background scan thread.
//!
//! One thread owns the [`Scanner`] for the whole session, so the managed ClamAV
//! daemon stays warm between scans. Engines are built lazily on the first scan:
//! starting the daemon can take seconds and the window should appear instantly.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;

use vcd_core::{
    Backend, DetonateOptions, Detonation, ScanControl, ScanProgress, ScanReport, ScanScope,
    Scanner, Summary,
};

pub enum Command {
    ScanFile(PathBuf),
    ScanFolder(PathBuf),
    Cancel,
    Detonate(PathBuf, DetonateOptions, Backend),
}

pub enum Event {
    /// Engines are being prepared (ClamAV database, YARA rules).
    Starting,
    Started {
        total: usize,
    },
    File(Box<ScanReport>),
    Error {
        path: PathBuf,
        error: String,
    },
    Finished(Box<Summary>),
    Failed(String),
    Detonation(Box<Detonation>),
    DetonationFailed(String),
}

pub struct Worker {
    commands: Sender<Command>,
    events: Receiver<Event>,
}

impl Worker {
    pub fn spawn() -> Self {
        let (command_tx, command_rx) = channel::<Command>();
        let (event_tx, event_rx) = channel::<Event>();
        let cancel = Arc::new(AtomicBool::new(false));

        let cancel_flag = Arc::clone(&cancel);
        thread::spawn(move || run(command_rx, event_tx, cancel_flag));

        Self {
            commands: command_tx,
            events: event_rx,
        }
    }

    pub fn send(&self, command: Command) {
        let _ = self.commands.send(command);
    }

    pub fn cancel(&self) {
        self.send(Command::Cancel);
    }

    pub fn try_recv(&self) -> Option<Event> {
        self.events.try_recv().ok()
    }
}

fn run(commands: Receiver<Command>, events: Sender<Event>, cancel: Arc<AtomicBool>) {
    let mut cached: Option<(ScanScope, Scanner)> = None;

    while let Ok(command) = commands.recv() {
        match command {
            Command::Cancel => cancel.store(true, Ordering::SeqCst),
            Command::Detonate(path, options, backend) => {
                match vcd_core::detonate_with(&path, &options, backend) {
                    Ok(report) => {
                        let _ = events.send(Event::Detonation(Box::new(report)));
                    }
                    Err(error) => {
                        let _ = events.send(Event::DetonationFailed(error.to_string()));
                    }
                }
            }
            Command::ScanFile(path) => {
                cancel.store(false, Ordering::SeqCst);
                let _ = events.send(Event::Starting);
                let scanner = scanner_for(&mut cached, ScanScope::SingleFile);
                let _ = events.send(Event::Started { total: 1 });

                match scanner.scan(&path) {
                    Ok(report) => {
                        let summary = summary_of(&report);
                        let _ = events.send(Event::File(Box::new(report)));
                        let _ = events.send(Event::Finished(Box::new(summary)));
                    }
                    Err(error) => {
                        let _ = events.send(Event::Failed(error.to_string()));
                    }
                }
            }
            Command::ScanFolder(path) => {
                cancel.store(false, Ordering::SeqCst);
                let _ = events.send(Event::Starting);
                let scanner = scanner_for(&mut cached, ScanScope::Tree);

                let result = scanner.scan_directory_with(&path, &mut |progress| {
                    match progress {
                        ScanProgress::Planned { total } => {
                            let _ = events.send(Event::Started { total });
                        }
                        ScanProgress::File { report, .. } => {
                            let _ = events.send(Event::File(Box::new(report.clone())));
                        }
                    }

                    if cancel.load(Ordering::SeqCst) {
                        ScanControl::Stop
                    } else {
                        ScanControl::Continue
                    }
                });

                match result {
                    Ok(report) => {
                        for failure in &report.errors {
                            let _ = events.send(Event::Error {
                                path: failure.path.clone(),
                                error: failure.error.clone(),
                            });
                        }
                        let _ = events.send(Event::Finished(Box::new(report.summary)));
                    }
                    Err(error) => {
                        let _ = events.send(Event::Failed(error.to_string()));
                    }
                }
            }
        }
    }
}

/// One scanner per scope: switching scope drops the old one, which is what
/// stops a ClamAV daemon that the new scan does not need.
fn scanner_for(cached: &mut Option<(ScanScope, Scanner)>, scope: ScanScope) -> &Scanner {
    if cached.as_ref().is_none_or(|(current, _)| *current != scope) {
        *cached = None;
        *cached = Some((scope, Scanner::with_local_engines(scope)));
    }

    &cached.as_ref().expect("scanner just inserted").1
}

fn summary_of(report: &ScanReport) -> Summary {
    let mut summary = Summary {
        files: 1,
        malicious: 0,
        suspicious: 0,
        undetected: 0,
        inconclusive: 0,
        unknown: 0,
        errors: 0,
        duration_ms: report.duration_ms,
    };

    match report.verdict {
        vcd_core::Verdict::Malicious => summary.malicious = 1,
        vcd_core::Verdict::Suspicious => summary.suspicious = 1,
        vcd_core::Verdict::Undetected => summary.undetected = 1,
        vcd_core::Verdict::Inconclusive => summary.inconclusive = 1,
        vcd_core::Verdict::Unknown => summary.unknown = 1,
    }

    summary
}
