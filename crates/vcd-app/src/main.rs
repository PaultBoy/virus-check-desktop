#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Virus Check Desktop: a window over the scan engine.
//!
//! The UI thread never scans. It sends a path to a worker thread and renders
//! the events that come back, so the window stays responsive while ClamAV loads
//! its database or a tree with thousands of files is being walked.

mod i18n;
mod worker;

use std::path::{Path, PathBuf};
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use i18n::Strings;
use vcd_core::{
    Backend, ClamavStatus, Coverage, DetonateOptions, Detonation, InstallStep, SandboxSupport,
    ScanReport, Severity, Summary, Verdict, clamav_status, detect_support, enable_windows_sandbox,
};

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
    scan_elapsed: Option<Duration>,
    detonating: bool,
    detonation: Option<Detonation>,
    support: SandboxSupport,
    clamav: ClamavStatus,
    installing_clamav: bool,
    clamav_progress: Option<InstallStep>,
    clamav_error: Option<String>,
    installing_sandboxie: bool,
    show_clamav_prompt: bool,
    show_sandbox_prompt: bool,
    sandbox_index: Option<usize>,
    sandbox_error: Option<String>,
    smoke_sandbox_prompt: bool,
    strings: Strings,
    notice: Option<String>,
    smoke_detonate: bool,
    smoke_backend: Option<Backend>,
    smoke_deadline: Option<std::time::Instant>,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let smoke = std::env::var_os("VCD_SMOKE").is_some();
        let smoke_detonate = std::env::var_os("VCD_SMOKE_DETONATE").is_some();
        let smoke_backend = match std::env::var("VCD_SMOKE_BACKEND").as_deref() {
            Ok("sandboxie") => Some(Backend::Sandboxie),
            Ok("windows") => Some(Backend::WindowsSandbox),
            _ => None,
        };
        let smoke_seconds = if smoke_detonate { 130 } else { 18 };
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
            scan_elapsed: None,
            detonating: false,
            detonation: None,
            support: detect_support(),
            clamav: {
                let status = clamav_status();
                if std::env::var_os("VCD_SMOKE_NO_CLAMAV").is_some() {
                    ClamavStatus {
                        portable: None,
                        system: None,
                    }
                } else {
                    status
                }
            },
            installing_clamav: false,
            clamav_progress: None,
            clamav_error: None,
            installing_sandboxie: false,
            show_clamav_prompt: false,
            show_sandbox_prompt: false,
            sandbox_index: None,
            sandbox_error: None,
            smoke_sandbox_prompt: std::env::var_os("VCD_SMOKE_SANDBOX_PROMPT").is_some(),
            strings: Strings::system(),
            notice: None,
            smoke_detonate,
            smoke_backend,
            smoke_deadline: smoke
                .then(|| std::time::Instant::now() + Duration::from_secs(smoke_seconds)),
        };

        app.show_clamav_prompt = !app.clamav.available();

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
        self.detonation = None;
        self.detonating = false;
        self.notice = None;
        self.root = if path.is_dir() {
            Some(path.to_path_buf())
        } else {
            path.parent().map(Path::to_path_buf)
        };
        self.phase = Phase::Starting;
        self.scan_started = Some(std::time::Instant::now());
        self.scan_elapsed = None;
    }

    fn busy(&self) -> bool {
        matches!(self.phase, Phase::Starting | Phase::Scanning)
            || self.detonating
            || self.installing_clamav
            || self.installing_sandboxie
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
                    self.scan_elapsed = self.scan_started.map(|start| start.elapsed());
                    if self.selected.is_none() && !self.files.is_empty() {
                        self.selected = Some(0);
                    }
                    if self.smoke_detonate
                        && !self.detonating
                        && self.detonation.is_none()
                        && let Some(index) = self.selected
                        && self.files.get(index).is_some_and(detonable)
                        && let Some(backend) = self.smoke_backend.or(self.support.recommended())
                    {
                        self.start_detonation(index, backend);
                    }

                    if self.smoke_sandbox_prompt
                        && let Some(index) = self.selected
                        && self.files.get(index).is_some_and(detonable)
                    {
                        self.sandbox_index = Some(index);
                        self.show_sandbox_prompt = true;
                    }
                }
                Event::Failed(error) => {
                    self.failure = Some(error);
                    self.phase = Phase::Idle;
                }
                Event::Detonation(report) => {
                    self.detonating = false;
                    self.detonation = Some(*report);
                    self.show_sandbox_prompt = false;
                    self.sandbox_error = None;
                }
                Event::DetonationFailed(error) => {
                    self.detonating = false;
                    self.sandbox_error = Some(error.clone());
                    self.failure = Some(error);
                }
                Event::SandboxieInstallLaunched => {
                    self.installing_sandboxie = false;
                    self.support = detect_support();
                    // The dialog cannot see the wizard finish, so close it and
                    // let the notice explain what to do next.
                    self.show_sandbox_prompt = false;
                    self.sandbox_error = None;
                    self.notice = Some(self.strings.sandboxie_install_notice().to_string());
                }
                Event::SandboxieInstallFailed(error) => {
                    self.installing_sandboxie = false;
                    self.sandbox_error = Some(error.clone());
                    self.failure = Some(error);
                }
                Event::ClamavProgress(step) => {
                    self.installing_clamav = true;
                    self.clamav_progress = Some(step);
                    self.clamav_error = None;
                }
                Event::ClamavInstalled(root) => {
                    self.installing_clamav = false;
                    self.clamav_progress = None;
                    self.clamav = clamav_status();
                    self.show_clamav_prompt = false;
                    let ready = self.strings.clamav_ready();
                    self.notice = Some(format!("{ready} · {}", root.display()));
                }
                Event::ClamavFailed(error) => {
                    self.installing_clamav = false;
                    self.clamav_progress = None;
                    self.clamav_error = Some(error);
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

    fn start_detonation(&mut self, index: usize, backend: Backend) {
        let path = self.files[index].target.clone();
        self.detonation = None;
        self.detonating = true;
        self.worker
            .send(Command::Detonate(path, DetonateOptions::default(), backend));
    }

    /// Backend choice for detonation, shown over the window when the sample is
    /// about to be loaded. The recommended backend is labelled as such.
    fn sandbox_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_sandbox_prompt {
            return;
        }

        let Some(index) = self.sandbox_index.filter(|index| *index < self.files.len()) else {
            self.show_sandbox_prompt = false;
            return;
        };

        let title = self.strings.sandbox_title();
        let body = self.strings.sandbox_body();
        let not_now = self.strings.not_now();
        let booting = self.strings.booting_sandbox();
        let recommended = self.support.recommended();
        let backends = self.support.available();
        let supports_vm = self.support.edition.supports_windows_sandbox();
        let detonating = self.detonating;
        let installing = self.installing_sandboxie;
        let error = self.sandbox_error.clone();
        let sample = self.files[index]
            .target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("sample")
            .to_string();

        let mut chosen = None;
        let mut close = false;
        let mut enable = false;
        let mut install = false;

        egui::Modal::new(egui::Id::new("sandbox_prompt")).show(ctx, |ui| {
            ui.set_max_width(520.0);
            ui.heading(title);
            ui.label(RichText::new(sample).monospace().weak());
            ui.add_space(8.0);
            ui.label(body);

            if let Some(error) = &error {
                ui.add_space(8.0);
                ui.colored_label(malicious_color(), error);
            }

            ui.add_space(10.0);

            if detonating {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(booting);
                });
            } else if installing {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(self.strings.installing_sandboxie());
                });
            } else {
                if backends.is_empty() {
                    let message = if supports_vm {
                        self.strings.no_backend_pro()
                    } else {
                        self.strings.no_backend_home()
                    };
                    ui.label(message);
                    ui.add_space(6.0);
                    if supports_vm && ui.button(self.strings.enable_sandbox()).clicked() {
                        enable = true;
                    }
                    if ui.button(self.strings.install_sandboxie()).clicked() {
                        install = true;
                    }
                } else {
                    for backend in backends {
                        let label = if Some(backend) == recommended {
                            format!("{} ({})", backend.as_str(), self.strings.recommended())
                        } else {
                            backend.as_str().to_string()
                        };

                        if ui.button(label).clicked() {
                            chosen = Some(backend);
                        }

                        let description = match backend {
                            Backend::WindowsSandbox => self.strings.backend_windows(),
                            Backend::Sandboxie => self.strings.backend_sandboxie(),
                        };
                        ui.label(RichText::new(description).weak());
                        ui.add_space(6.0);
                    }

                    // Sandboxie works on every edition, so the offer is not
                    // limited to machines where Windows Sandbox is impossible.
                    if !self.support.sandboxie {
                        ui.separator();
                        ui.label(RichText::new(self.strings.sandboxie_missing_hint()).weak());
                        if ui.button(self.strings.install_sandboxie()).clicked() {
                            install = true;
                        }
                    }
                }

                ui.add_space(6.0);
                if ui.button(not_now).clicked() {
                    close = true;
                }
            }
        });

        if !detonating && !installing && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            close = true;
        }

        if close {
            self.show_sandbox_prompt = false;
            self.sandbox_error = None;
        }

        if enable {
            match enable_windows_sandbox() {
                Ok(log) => {
                    self.notice = Some(self.strings.enable_notice(&log.display().to_string()))
                }
                Err(failure) => self.sandbox_error = Some(failure),
            }
        }

        if install && !self.installing_sandboxie {
            self.installing_sandboxie = true;
            self.sandbox_error = None;
            self.worker.send(Command::InstallSandboxie);
        }

        if let Some(backend) = chosen {
            self.show_sandbox_prompt = true;
            self.start_detonation(index, backend);
        }
    }

    /// Setup prompt shown over the window when ClamAV is missing: one decision,
    /// explained, with its cost.
    fn clamav_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_clamav_prompt {
            return;
        }

        let title = self.strings.clamav_dialog_title();
        let body = self.strings.clamav_dialog_body();
        let download = if self.clamav_error.is_some() {
            self.strings.retry()
        } else {
            self.strings.download_clamav()
        };
        let not_now = self.strings.not_now();
        let preparing = self.strings.preparing_clamav();
        let installing = self.installing_clamav;
        let step = self
            .clamav_progress
            .map(|step| self.strings.install_step(step));
        let error = self.clamav_error.clone();
        let mut download_clicked = false;
        let mut close_clicked = false;

        egui::Modal::new(egui::Id::new("clamav_prompt")).show(ctx, |ui| {
            ui.set_max_width(470.0);
            ui.heading(title);
            ui.add_space(8.0);
            ui.label(body);

            if let Some(error) = &error {
                ui.add_space(8.0);
                ui.colored_label(malicious_color(), error);
            }

            ui.add_space(12.0);

            if installing {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(step.unwrap_or(preparing));
                });
            } else {
                ui.horizontal(|ui| {
                    if ui.button(download).clicked() {
                        download_clicked = true;
                    }
                    if ui.button(not_now).clicked() {
                        close_clicked = true;
                    }
                });
            }
        });

        if !installing && ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            close_clicked = true;
        }

        if close_clicked {
            self.show_clamav_prompt = false;
        }

        if download_clicked {
            self.installing_clamav = true;
            self.clamav_progress = None;
            self.clamav_error = None;
            self.worker.send(Command::InstallClamav);
        }
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading("Virus Check Desktop");
            ui.separator();

            if ui
                .add_enabled(!self.busy(), egui::Button::new(self.strings.scan_file()))
                .clicked()
                && let Some(path) = rfd::FileDialog::new().pick_file()
            {
                self.start_file(path);
            }

            if ui
                .add_enabled(!self.busy(), egui::Button::new(self.strings.scan_folder()))
                .clicked()
                && let Some(path) = rfd::FileDialog::new().pick_folder()
            {
                self.start_folder(path);
            }

            if matches!(self.phase, Phase::Starting | Phase::Scanning)
                && ui.button(self.strings.cancel()).clicked()
            {
                self.worker.cancel();
            }

            if self.clamav.available() {
                ui.separator();
                ui.label(RichText::new(self.strings.clamav_ready()).weak());
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(self.strings.drop_hint()).weak());
            });
        });
        ui.add_space(4.0);
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(3.0);
        ui.horizontal(|ui| {
            if self.installing_clamav {
                ui.spinner();
                let step = self
                    .clamav_progress
                    .map(|step| self.strings.install_step(step))
                    .unwrap_or_else(|| self.strings.preparing_clamav());
                ui.label(step);
            } else if self.detonating {
                ui.spinner();
                ui.label(self.strings.detonating());
            } else if self.installing_sandboxie {
                ui.spinner();
                ui.label(self.strings.installing_sandboxie());
            } else {
                match self.phase {
                    Phase::Idle => {
                        ui.label(self.strings.ready());
                    }
                    Phase::Starting => {
                        ui.spinner();
                        ui.label(self.strings.starting_engines());
                    }
                    Phase::Scanning => {
                        ui.spinner();
                        let done = self.files.len();
                        ui.label(self.strings.scanned(done, self.total));
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
                                .scan_elapsed
                                .map(|elapsed| elapsed.as_secs_f64())
                                .unwrap_or(summary.duration_ms as f64 / 1000.0);
                            ui.label(self.strings.summary(summary, elapsed));
                        }
                    }
                }
            }

            if let Some(failure) = &self.failure {
                ui.colored_label(malicious_color(), failure);
            }

            if let Some(notice) = &self.notice {
                ui.label(RichText::new(notice).color(Color32::from_rgb(150, 190, 230)));
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(self.strings.local_only()).weak());
            });
        });
        ui.add_space(3.0);
    }

    fn results(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);

        if self.files.is_empty() && self.errors.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(90.0);
                ui.label(RichText::new(self.strings.drop_here()).size(22.0).weak());
                ui.label(RichText::new(self.strings.or_buttons()).weak());
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
                        self.strings.verdict(file.verdict),
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
            if self.selected != Some(index) {
                self.detonation = None;
            }
            self.selected = Some(index);
        }

        if !self.errors.is_empty() {
            ui.separator();
            egui::CollapsingHeader::new(self.strings.unreadable(self.errors.len())).show(
                ui,
                |ui| {
                    for (path, error) in &self.errors {
                        ui.label(
                            RichText::new(format!("{}: {error}", path.display()))
                                .monospace()
                                .color(Color32::from_rgb(200, 190, 90)),
                        );
                    }
                },
            );
        }
    }

    fn detail(&mut self, ui: &mut egui::Ui, index: usize) {
        let file = self.files[index].clone();
        let mut request_sandbox_prompt = false;

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(self.strings.verdict(file.verdict))
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
                        ui.label(self.strings.size());
                        ui.label(human_size(file.size));
                        ui.end_row();

                        ui.label(self.strings.kind());
                        ui.label(file.content_type.as_str());
                        ui.end_row();

                        if let Some(extension) = &file.extension {
                            ui.label(self.strings.extension());
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
                            ui.label(RichText::new(format!("{} ms", engine.duration_ms)).weak());
                        }
                    });

                    for fact in &engine.facts {
                        ui.label(
                            RichText::new(format!("{}: {}", fact.name, shorten(&fact.value, 160)))
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

                if detonable(&file) {
                    if ui
                        .add_enabled(
                            !self.busy(),
                            egui::Button::new(self.strings.detonate_action()),
                        )
                        .clicked()
                    {
                        request_sandbox_prompt = true;
                    }
                } else {
                    ui.label(RichText::new(self.strings.detonation_only()).weak());
                }

                if self.detonating {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(self.strings.booting_sandbox());
                    });
                }

                if let Some(detonation) = &self.detonation {
                    render_detonation(ui, detonation, &self.strings);
                }

                ui.separator();
                if ui.button(self.strings.copy_json()).clicked()
                    && let Ok(json) = serde_json::to_string_pretty(&file)
                {
                    ui.ctx().copy_text(json);
                }
            });

        if request_sandbox_prompt {
            // Re-detect here, not at startup only: the user may have installed a
            // backend since the window opened.
            self.support = detect_support();
            self.sandbox_index = Some(index);
            self.sandbox_error = None;
            self.show_sandbox_prompt = true;
        }
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

        self.clamav_dialog(ctx);
        self.sandbox_dialog(ctx);
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

fn detonable(file: &ScanReport) -> bool {
    matches!(
        file.extension.as_deref(),
        Some(
            "exe"
                | "scr"
                | "com"
                | "pif"
                | "cpl"
                | "msi"
                | "bat"
                | "cmd"
                | "ps1"
                | "vbs"
                | "vbe"
                | "js"
                | "jse"
                | "wsf"
                | "hta"
        )
    )
}

fn render_detonation(ui: &mut egui::Ui, detonation: &Detonation, strings: &Strings) {
    ui.separator();
    ui.label(RichText::new(strings.detonation_title()).strong());
    ui.label(format!(
        "{}: {}",
        strings.backend(),
        detonation.backend.as_str()
    ));
    ui.label(strings.executed(
        detonation.executed,
        detonation.timed_out,
        detonation.duration_ms as f64 / 1000.0,
    ));
    ui.label(strings.network(detonation.network_enabled));

    if let Some(error) = &detonation.error {
        ui.colored_label(malicious_color(), error);
    }
    if let Some(extension) = &detonation.unsupported {
        ui.label(strings.not_runnable(extension));
    }

    if !detonation.processes.is_empty() {
        ui.label(strings.processes(detonation.processes.len()));
        for process in detonation.processes.iter().take(10) {
            ui.label(
                RichText::new(format!(
                    "  {} (pid {})",
                    process.name.as_deref().unwrap_or("?"),
                    process.pid
                ))
                .monospace()
                .weak(),
            );
        }
    }

    if !detonation.connections.is_empty() {
        ui.label(strings.connections(detonation.connections.len()));
        for connection in detonation.connections.iter().take(10) {
            ui.label(
                RichText::new(format!("  {} ({})", connection.remote, connection.state))
                    .monospace()
                    .weak(),
            );
        }
    }

    if !detonation.dns.is_empty() {
        ui.label(format!("dns: {}", detonation.dns.join(", ")));
    }

    if !detonation.files_created.is_empty() {
        ui.label(strings.files_created(detonation.files_created.len()));
        for path in detonation.files_created.iter().take(8) {
            ui.label(RichText::new(format!("  + {path}")).monospace().weak());
        }
    }

    if !detonation.registry_changed.is_empty() {
        ui.label(strings.registry_changes(detonation.registry_changed.len()));
        for change in detonation.registry_changed.iter().take(8) {
            ui.label(RichText::new(format!("  {change}")).monospace().weak());
        }
    }

    if !detonation.dropped.is_empty() {
        ui.label(strings.dropped(detonation.dropped.len()));
        for path in detonation.dropped.iter().take(5) {
            ui.label(
                RichText::new(format!("  {}", path.display()))
                    .monospace()
                    .weak(),
            );
        }
    }

    for caveat in &detonation.caveats {
        ui.label(RichText::new(format!("! {caveat}")).color(Color32::from_rgb(200, 190, 90)));
    }
}

fn findings(file: &ScanReport) -> String {
    let mut parts = Vec::new();
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
        // Without the byte count, "partial" cannot be told apart from "nothing".
        Coverage::Partial {
            scanned_bytes,
            reason,
        } => format!(
            "coverage: partial ({} scanned, {reason})",
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
