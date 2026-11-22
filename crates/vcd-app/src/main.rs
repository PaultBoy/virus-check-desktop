#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Virus Check Desktop: a window over the scan engine.
//!
//! The UI thread never scans. It sends a path to a worker thread and renders
//! the events that come back, so the window stays responsive while ClamAV loads
//! its database or a tree with thousands of files is being walked.

mod worker;

use std::path::{Path, PathBuf};
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use vcd_core::{Coverage, ScanReport, Severity, Summary, Verdict};

use worker::{Command, Event, Worker};

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 780.0])
            .with_min_inner_size([900.0, 520.0])
            .with_title("Virus Check Desktop"),
        ..Default::default()
    };

    eframe::run_native(
        "Virus Check Desktop",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Starting,
    Scanning,
    Done,
}

struct App {
    worker: Worker,
    phase: Phase,
    files: Vec<ScanReport>,
    errors: Vec<(PathBuf, String)>,
    selected: Option<usize>,
    total: usize,
    finished: Option<Summary>,
    failure: Option<String>,
    root: Option<PathBuf>,
    scan_started: Option<std::time::Instant>,
    smoke_deadline: Option<std::time::Instant>,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let smoke = std::env::var_os("VCD_SMOKE").is_some();
        let mut app = Self {
            worker: Worker::spawn(),
            phase: Phase::Idle,
            files: Vec::new(),
            errors: Vec::new(),
            selected: None,
            total: 0,
            finished: None,
            failure: None,
            root: None,
            scan_started: None,
            smoke_deadline: smoke.then(|| std::time::Instant::now() + Duration::from_secs(18)),
        };

        // Smoke hook: scan a path on startup so the window can be captured with
        // real results. Never set by normal use.
        if let Some(path) = std::env::var_os("VCD_SMOKE_SCAN") {
            let path = PathBuf::from(path);
            if path.is_dir() {
                app.start_folder(path);
            } else {
                app.start_file(path);
            }
        }

        app
    }

    fn start_file(&mut self, path: PathBuf) {
        self.reset(&path);
        self.worker.send(Command::ScanFile(path));
    }

    fn start_folder(&mut self, path: PathBuf) {
        self.reset(&path);
        self.worker.send(Command::ScanFolder(path));
    }

    fn reset(&mut self, path: &Path) {
        self.files.clear();
        self.errors.clear();
        self.selected = None;
        self.total = 0;
        self.finished = None;
        self.failure = None;
        self.root = if path.is_dir() {
            Some(path.to_path_buf())
        } else {
            path.parent().map(Path::to_path_buf)
        };
        self.phase = Phase::Starting;
        self.scan_started = Some(std::time::Instant::now());
    }

    fn busy(&self) -> bool {
        matches!(self.phase, Phase::Starting | Phase::Scanning)
    }

    fn drain_events(&mut self) {
        while let Some(event) = self.worker.try_recv() {
            match event {
                Event::Starting => {
                    self.phase = Phase::Starting;
                    self.failure = None;
                }
                Event::Started { total } => {
                    self.phase = Phase::Scanning;
                    self.total = total;
                }
                Event::File(report) => self.files.push(*report),
                Event::Error { path, error } => self.errors.push((path, error)),
                Event::Finished(summary) => {
                    self.finished = Some(*summary);
                    self.phase = Phase::Done;
                    if self.selected.is_none() && !self.files.is_empty() {
                        self.selected = Some(0);
                    }
                }
                Event::Failed(error) => {
                    self.failure = Some(error);
                    self.phase = Phase::Idle;
                }
            }
        }
    }

    fn handle_drops(&mut self, ctx: &egui::Context) {
        if self.busy() {
            return;
        }

        let dropped = ctx.input(|input| {
            input
                .raw
                .dropped_files
                .iter()
                .find_map(|file| file.path.clone())
        });

        if let Some(path) = dropped {
            if path.is_dir() {
                self.start_folder(path);
            } else {
                self.start_file(path);
            }
        }
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading("Virus Check Desktop");
            ui.separator();

            if ui
                .add_enabled(!self.busy(), egui::Button::new("Scan file…"))
                .clicked()
                && let Some(path) = rfd::FileDialog::new().pick_file()
            {
                self.start_file(path);
            }

            if ui
                .add_enabled(!self.busy(), egui::Button::new("Scan folder…"))
                .clicked()
                && let Some(path) = rfd::FileDialog::new().pick_folder()
            {
                self.start_folder(path);
            }

            if self.busy() && ui.button("Cancel").clicked() {
                self.worker.cancel();
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new("drop a file or folder anywhere").weak());
            });
        });
        ui.add_space(4.0);
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(3.0);
        ui.horizontal(|ui| {
            match self.phase {
                Phase::Idle => {
                    ui.label("Ready");
                }
                Phase::Starting => {
                    ui.spinner();
                    ui.label("starting engines (the ClamAV database can take a few seconds)…");
                }
                Phase::Scanning => {
                    ui.spinner();
                    let done = self.files.len();
                    ui.label(format!("scanned {done} / {}", self.total));
                    let ratio = if self.total == 0 {
                        0.0
                    } else {
                        done as f32 / self.total as f32
                    };
                    ui.add(
                        egui::ProgressBar::new(ratio)
                            .desired_width(220.0)
                            .show_percentage(),
                    );
                }
                Phase::Done => {
                    if let Some(summary) = &self.finished {
                        let elapsed = self
                            .scan_started
                            .map(|start| start.elapsed().as_secs_f64())
                            .unwrap_or(summary.duration_ms as f64 / 1000.0);
                        ui.label(format!(
                            "{} files | {} malicious | {} suspicious | {} undetected | {} inconclusive | {} unknown | {} errors | {elapsed:.1} s",
                            summary.files,
                            summary.malicious,
                            summary.suspicious,
                            summary.undetected,
                            summary.inconclusive,
                            summary.unknown,
                            summary.errors
                        ));
                    }
                }
            }

            if let Some(failure) = &self.failure {
                ui.colored_label(malicious_color(), failure);
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new("local only | nothing is uploaded").weak());
            });
        });
        ui.add_space(3.0);
    }

    fn results(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);

        if self.files.is_empty() && self.errors.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(90.0);
                ui.label(RichText::new("Drop a file or a folder here").size(22.0).weak());
                ui.label(RichText::new("or use the buttons above").weak());
            });
            return;
        }

        let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 6.0;
        let mut clicked = None;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, self.files.len(), |ui, range| {
                for index in range {
                    let file = &self.files[index];
                    let line = format!(
                        "{:<12}  {:<58}  {}",
                        file.verdict.label(),
                        self.display_path(&file.target),
                        findings(file)
                    );
                    let text = RichText::new(line)
                        .monospace()
                        .color(verdict_color(file.verdict));

                    if ui
                        .scope(|ui| {
                            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                            ui.visuals_mut().override_text_color =
                                Some(verdict_color(file.verdict));
                            ui.selectable_label(self.selected == Some(index), text)
                        })
                        .inner
                        .clicked()
                    {
                        clicked = Some(index);
                    }
                }
            });

        if let Some(index) = clicked {
            self.selected = Some(index);
        }

        if !self.errors.is_empty() {
            ui.separator();
            egui::CollapsingHeader::new(format!("{} files could not be read", self.errors.len()))
                .show(ui, |ui| {
                    for (path, error) in &self.errors {
                        ui.label(
                            RichText::new(format!("{}: {error}", path.display()))
                                .monospace()
                                .color(Color32::from_rgb(200, 190, 90)),
                        );
                    }
                });
        }
    }

    fn detail(&mut self, ui: &mut egui::Ui, index: usize) {
        let file = &self.files[index];

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(file.verdict.label())
                        .size(22.0)
                        .strong()
                        .color(verdict_color(file.verdict)),
                );
                ui.label(
                    RichText::new(file.target.display().to_string())
                        .monospace()
                        .weak(),
                );
                ui.separator();

                egui::Grid::new("file_meta")
                    .num_columns(2)
                    .spacing([14.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("Size");
                        ui.label(human_size(file.size));
                        ui.end_row();

                        ui.label("Type");
                        ui.label(file.content_type.as_str());
                        ui.end_row();

                        if let Some(extension) = &file.extension {
                            ui.label("Extension");
                            ui.label(format!(".{extension}"));
                            ui.end_row();
                        }

                        ui.label("SHA-256");
                        ui.label(RichText::new(&file.hashes.sha256).monospace());
                        ui.end_row();

                        ui.label("SHA-1");
                        ui.label(RichText::new(&file.hashes.sha1).monospace());
                        ui.end_row();

                        ui.label("MD5");
                        ui.label(RichText::new(&file.hashes.md5).monospace());
                        ui.end_row();
                    });

                ui.separator();

                for engine in &file.engines {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&engine.engine).strong());
                        ui.label(RichText::new(engine.status.as_str()).weak());
                        ui.label(RichText::new(coverage_text(&engine.coverage)).weak());
                        if engine.duration_ms > 0 {
                            ui.label(
                                RichText::new(format!("{} ms", engine.duration_ms)).weak(),
                            );
                        }
                    });

                    for fact in &engine.facts {
                        ui.label(
                            RichText::new(format!(
                                "{}: {}",
                                fact.name,
                                shorten(&fact.value, 160)
                            ))
                            .monospace()
                            .weak(),
                        );
                    }

                    for detection in &engine.detections {
                        ui.label(
                            RichText::new(format!(
                                "[{}] {}",
                                detection.severity.as_str(),
                                detection.detail
                            ))
                            .color(severity_color(detection.severity)),
                        );
                    }

                    ui.add_space(6.0);
                }

                ui.separator();
                if ui.button("Copy JSON").clicked()
                    && let Ok(json) = serde_json::to_string_pretty(file)
                {
                    ui.ctx().copy_text(json);
                }
            });
    }

    fn display_path(&self, path: &Path) -> String {
        match &self.root {
            Some(root) => path
                .strip_prefix(root)
                .unwrap_or(path)
                .display()
                .to_string(),
            None => path.display().to_string(),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        if self.busy() {
            ctx.request_repaint_after(Duration::from_millis(120));
        }

        if let Some(deadline) = self.smoke_deadline {
            ctx.request_repaint();
            if std::time::Instant::now() >= deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }

        self.handle_drops(ctx);

        egui::TopBottomPanel::top("top").show(ctx, |ui| self.top_bar(ui));
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| self.status_bar(ui));

        if let Some(index) = self.selected.filter(|index| *index < self.files.len()) {
            egui::SidePanel::right("detail")
                .resizable(true)
                .default_width(460.0)
                .show(ctx, |ui| self.detail(ui, index));
        }

        egui::CentralPanel::default().show(ctx, |ui| self.results(ui));
    }
}

/// Keep a value readable in the panel; the JSON keeps the full text.
fn shorten(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }

    let mut shortened: String = value.chars().take(limit.saturating_sub(3)).collect();
    shortened.push_str("...");
    shortened
}

fn findings(file: &ScanReport) -> String {    let mut parts = Vec::new();
    for engine in &file.engines {
        for detection in &engine.detections {
            parts.push(format!("{}: {}", engine.engine, detection.detail));
        }
    }

    let joined = parts.join("; ");
    if joined.chars().count() <= 90 {
        joined
    } else {
        let mut shortened: String = joined.chars().take(87).collect();
        shortened.push_str("...");
        shortened
    }
}

fn verdict_color(verdict: Verdict) -> Color32 {
    match verdict {
        Verdict::Malicious => malicious_color(),
        Verdict::Suspicious => Color32::from_rgb(230, 168, 70),
        Verdict::Undetected => Color32::from_rgb(130, 190, 140),
        Verdict::Inconclusive => Color32::from_rgb(200, 190, 90),
        Verdict::Unknown => Color32::from_rgb(150, 150, 150),
    }
}

fn malicious_color() -> Color32 {
    Color32::from_rgb(233, 94, 94)
}

fn severity_color(severity: Severity) -> Color32 {
    match severity {
        Severity::Malicious => malicious_color(),
        Severity::Suspicious => Color32::from_rgb(230, 168, 70),
        Severity::Info => Color32::from_rgb(150, 170, 200),
    }
}

fn coverage_text(coverage: &Coverage) -> String {
    match coverage {
        Coverage::Complete => "coverage: complete".to_string(),
        Coverage::Partial { reason, .. } => format!("coverage: partial ({reason})"),
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
