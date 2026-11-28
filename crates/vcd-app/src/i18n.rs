//! User-interface strings, chosen from the language Windows reports for the
//! user. Technical content (engine facts, caveats, signatures) stays in
//! English: it is data, not interface.

use vcd_core::{InstallStep, Summary, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Es,
}

/// `GetUserDefaultUILanguage` returns a LANGID; the low 10 bits are the
/// primary language. Only English and Spanish are shipped; anything else
/// falls back to English.
pub fn system_language() -> Lang {
    unsafe extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }

    let langid = unsafe { GetUserDefaultUILanguage() };
    match langid & 0x03FF {
        0x0A => Lang::Es,
        _ => Lang::En,
    }
}

pub struct Strings {
    lang: Lang,
}

impl Strings {
    pub fn system() -> Self {
        Self {
            lang: system_language(),
        }
    }

    fn pick(&self, en: &'static str, es: &'static str) -> &'static str {
        match self.lang {
            Lang::En => en,
            Lang::Es => es,
        }
    }

    pub fn scan_file(&self) -> &'static str {
        self.pick("Scan file…", "Escanear archivo…")
    }

    pub fn scan_folder(&self) -> &'static str {
        self.pick("Scan folder…", "Escanear carpeta…")
    }

    pub fn cancel(&self) -> &'static str {
        self.pick("Cancel", "Cancelar")
    }

    pub fn clamav_ready(&self) -> &'static str {
        self.pick("ClamAV ready", "ClamAV listo")
    }

    pub fn drop_hint(&self) -> &'static str {
        self.pick(
            "drop a file or folder anywhere",
            "arrastra un archivo o carpeta aquí",
        )
    }

    pub fn drop_here(&self) -> &'static str {
        self.pick(
            "Drop a file or a folder here",
            "Arrastra un archivo o una carpeta aquí",
        )
    }

    pub fn or_buttons(&self) -> &'static str {
        self.pick("or use the buttons above", "o usa los botones de arriba")
    }

    pub fn ready(&self) -> &'static str {
        self.pick("Ready", "Listo")
    }

    pub fn starting_engines(&self) -> &'static str {
        self.pick(
            "starting engines (the ClamAV database can take a few seconds)…",
            "iniciando motores (la base de ClamAV puede tardar unos segundos)…",
        )
    }

    pub fn scanned(&self, done: usize, total: usize) -> String {
        match self.lang {
            Lang::En => format!("scanned {done} / {total}"),
            Lang::Es => format!("escaneados {done} / {total}"),
        }
    }

    pub fn detonating(&self) -> &'static str {
        self.pick(
            "detonating in the sandbox (up to ~2 min)…",
            "detonando en el aislamiento (hasta ~2 min)…",
        )
    }

    pub fn booting_sandbox(&self) -> &'static str {
        self.pick(
            "booting the sandbox, running the sample…",
            "iniciando el aislamiento y ejecutando la muestra…",
        )
    }

    pub fn preparing_clamav(&self) -> &'static str {
        self.pick("preparing ClamAV…", "preparando ClamAV…")
    }

    pub fn local_only(&self) -> &'static str {
        self.pick(
            "local only | nothing is uploaded",
            "solo local | no se sube nada",
        )
    }

    pub fn unreadable(&self, count: usize) -> String {
        match self.lang {
            Lang::En => format!("{count} files could not be read"),
            Lang::Es => format!("no se pudieron leer {count} archivos"),
        }
    }

    pub fn summary(&self, summary: &Summary, elapsed_seconds: f64) -> String {
        match self.lang {
            Lang::En => format!(
                "{} files | {} malicious | {} suspicious | {} undetected | {} inconclusive | {} unknown | {} errors | {elapsed_seconds:.1} s",
                summary.files,
                summary.malicious,
                summary.suspicious,
                summary.undetected,
                summary.inconclusive,
                summary.unknown,
                summary.errors
            ),
            Lang::Es => format!(
                "{} archivos | {} maliciosos | {} sospechosos | {} no detectados | {} inconclusos | {} desconocidos | {} errores | {elapsed_seconds:.1} s",
                summary.files,
                summary.malicious,
                summary.suspicious,
                summary.undetected,
                summary.inconclusive,
                summary.unknown,
                summary.errors
            ),
        }
    }

    pub fn verdict(&self, verdict: Verdict) -> &'static str {
        match (self.lang, verdict) {
            (Lang::En, Verdict::Malicious) => "MALICIOUS",
            (Lang::En, Verdict::Suspicious) => "SUSPICIOUS",
            (Lang::En, Verdict::Undetected) => "UNDETECTED",
            (Lang::En, Verdict::Inconclusive) => "INCONCLUSIVE",
            (Lang::En, Verdict::Unknown) => "UNKNOWN",
            (Lang::Es, Verdict::Malicious) => "MALICIOSO",
            (Lang::Es, Verdict::Suspicious) => "SOSPECHOSO",
            (Lang::Es, Verdict::Undetected) => "NO DETECTADO",
            (Lang::Es, Verdict::Inconclusive) => "INCONCLUSIVO",
            (Lang::Es, Verdict::Unknown) => "DESCONOCIDO",
        }
    }

    pub fn size(&self) -> &'static str {
        self.pick("Size", "Tamaño")
    }

    pub fn kind(&self) -> &'static str {
        self.pick("Type", "Tipo")
    }

    pub fn extension(&self) -> &'static str {
        self.pick("Extension", "Extensión")
    }

    pub fn copy_json(&self) -> &'static str {
        self.pick("Copy JSON", "Copiar JSON")
    }

    pub fn detonation_title(&self) -> &'static str {
        self.pick("Sandbox detonation", "Detonación en aislamiento")
    }

    pub fn backend(&self) -> &'static str {
        self.pick("backend", "aislamiento")
    }

    pub fn executed(&self, executed: bool, timed_out: bool, seconds: f64) -> String {
        let status = match (self.lang, executed) {
            (Lang::En, true) => "yes",
            (Lang::En, false) => "no",
            (Lang::Es, true) => "sí",
            (Lang::Es, false) => "no",
        };
        let timed = if timed_out {
            match self.lang {
                Lang::En => ", timed out (partial data)",
                Lang::Es => ", se agotó el tiempo (datos parciales)",
            }
        } else {
            ""
        };

        match self.lang {
            Lang::En => format!("executed: {status} | {seconds:.1} s{timed}"),
            Lang::Es => format!("ejecutado: {status} | {seconds:.1} s{timed}"),
        }
    }

    pub fn network(&self, enabled: bool) -> String {
        match (self.lang, enabled) {
            (Lang::En, true) => "network: enabled".to_string(),
            (Lang::En, false) => "network: disabled".to_string(),
            (Lang::Es, true) => "red: habilitada".to_string(),
            (Lang::Es, false) => "red: deshabilitada".to_string(),
        }
    }

    pub fn processes(&self, count: usize) -> String {
        match self.lang {
            Lang::En => format!("processes ({count})"),
            Lang::Es => format!("procesos ({count})"),
        }
    }

    pub fn connections(&self, count: usize) -> String {
        match self.lang {
            Lang::En => format!("connections ({count})"),
            Lang::Es => format!("conexiones ({count})"),
        }
    }

    pub fn files_created(&self, count: usize) -> String {
        match self.lang {
            Lang::En => format!("files created ({count})"),
            Lang::Es => format!("archivos creados ({count})"),
        }
    }

    pub fn registry_changes(&self, count: usize) -> String {
        match self.lang {
            Lang::En => format!("registry changes ({count})"),
            Lang::Es => format!("cambios en el registro ({count})"),
        }
    }

    pub fn dropped(&self, count: usize) -> String {
        match self.lang {
            Lang::En => format!("dropped files kept ({count})"),
            Lang::Es => format!("archivos dejados por la muestra ({count})"),
        }
    }

    pub fn not_runnable(&self, extension: &str) -> String {
        match self.lang {
            Lang::En => format!("not executed: {extension} is not runnable"),
            Lang::Es => format!("no ejecutado: {extension} no es ejecutable"),
        }
    }

    pub fn detonation_only(&self) -> &'static str {
        self.pick(
            "the sandbox launches the file as it is, so it needs an executable or script name (.exe, .bat, .ps1, …)",
            "el aislamiento lanza el archivo tal cual, así que necesita un nombre de ejecutable o script (.exe, .bat, .ps1, …)",
        )
    }

    pub fn detonate_action(&self) -> &'static str {
        self.pick("Load in a sandbox…", "Ejecutar aislado…")
    }

    pub fn sandbox_title(&self) -> &'static str {
        self.pick("Load in a sandbox", "Ejecutar aislado")
    }

    pub fn sandbox_body(&self) -> &'static str {
        self.pick(
            "The sample runs isolated from your system. Pick the backend; the\n\
             recommended one gives the stronger boundary.",
            "La muestra se ejecuta aislada de tu sistema. Elige el tipo de\n\
             aislamiento; el recomendado ofrece la barrera más fuerte.",
        )
    }

    pub fn recommended(&self) -> &'static str {
        self.pick("recommended", "recomendado")
    }

    pub fn backend_windows(&self) -> &'static str {
        self.pick(
            "virtual machine: the sample cannot touch the real system",
            "máquina virtual: la muestra no puede tocar el sistema real",
        )
    }

    pub fn backend_sandboxie(&self) -> &'static str {
        self.pick(
            "shared kernel: works on any Windows edition, weaker boundary",
            "kernel compartido: funciona en cualquier edición de Windows, barrera más débil",
        )
    }

    pub fn no_backend_pro(&self) -> &'static str {
        self.pick(
            "No backend is available yet. Enable Windows Sandbox (administrator + reboot), or install Sandboxie-Plus.",
            "Todavía no hay ningún aislamiento disponible. Habilita Windows Sandbox (administrador + reinicio) o instala Sandboxie-Plus.",
        )
    }

    pub fn no_backend_home(&self) -> &'static str {
        self.pick(
            "Windows Sandbox is not available here; it needs Pro/Enterprise. Sandboxie-Plus works on every Windows edition.",
            "Windows Sandbox no está disponible aquí; necesita Pro/Enterprise. Sandboxie-Plus funciona en cualquier edición de Windows.",
        )
    }

    pub fn install_sandboxie(&self) -> &'static str {
        self.pick("Install Sandboxie-Plus…", "Instalar Sandboxie-Plus…")
    }

    pub fn sandboxie_missing_hint(&self) -> &'static str {
        self.pick(
            "Sandboxie-Plus adds the shared-kernel backend; it works on every Windows edition.",
            "Sandboxie-Plus añade el aislamiento de kernel compartido; funciona en cualquier edición de Windows.",
        )
    }

    pub fn sandboxie_install_hint(&self) -> &'static str {
        self.pick(
            "Windows asks for administrator for PowerShell; the app then downloads the installer, checks its pinned SHA-256 and runs it silently.",
            "Windows pide administrador para PowerShell; después la app descarga el instalador, comprueba su SHA-256 fijado y lo ejecuta en silencio.",
        )
    }

    pub fn installing_sandboxie(&self) -> &'static str {
        self.pick(
            "installing Sandboxie-Plus (about 25 MB)…",
            "instalando Sandboxie-Plus (unos 25 MB)…",
        )
    }

    pub fn enable_sandbox(&self) -> &'static str {
        self.pick("Enable Windows Sandbox…", "Habilitar Windows Sandbox…")
    }

    pub fn enable_notice(&self, log: &str) -> String {
        match self.lang {
            Lang::En => {
                format!("accept the administrator prompt; a reboot is required (log: {log})")
            }
            Lang::Es => {
                format!("acepta la solicitud de administrador; hace falta reiniciar (log: {log})")
            }
        }
    }

    pub fn clamav_dialog_title(&self) -> &'static str {
        self.pick("ClamAV is not installed", "ClamAV no está instalado")
    }

    pub fn clamav_dialog_body(&self) -> &'static str {
        self.pick(
            "ClamAV adds its own signature engine (~3.6 M signatures) on top of\n\
             Defender and YARA. The download is about 500 MB, goes into your\n\
             user profile, and needs no administrator.",
            "ClamAV suma su propio motor de firmas (~3,6 M) además de Defender\n\
             y YARA. La descarga son unos 500 MB, va a tu perfil de usuario\n\
             y no requiere administrador.",
        )
    }

    pub fn download_clamav(&self) -> &'static str {
        self.pick("Download ClamAV", "Descargar ClamAV")
    }

    pub fn retry(&self) -> &'static str {
        self.pick("Retry", "Reintentar")
    }

    pub fn not_now(&self) -> &'static str {
        self.pick("Not now", "Ahora no")
    }

    pub fn install_step(&self, step: InstallStep) -> &'static str {
        match self.lang {
            // English lives in core, so the CLI prints the same sentences.
            Lang::En => step.english(),
            Lang::Es => match step {
                InstallStep::Downloading => "Descargando ClamAV (unos 214 MB)…",
                InstallStep::Extracting => "Extrayendo sin instalar…",
                InstallStep::Updating => "Descargando la base de firmas (unos 300 MB)…",
                InstallStep::Ready => "ClamAV está listo",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sandboxie_offer_is_translated() {
        let en = Strings { lang: Lang::En };
        let es = Strings { lang: Lang::Es };

        assert_eq!(en.install_sandboxie(), "Install Sandboxie-Plus…");
        assert_eq!(es.install_sandboxie(), "Instalar Sandboxie-Plus…");
        assert_ne!(en.installing_sandboxie(), es.installing_sandboxie());
        assert!(en.sandboxie_install_hint().contains("administrator"));
        assert!(es.sandboxie_install_hint().contains("administrador"));
    }

    #[test]
    fn every_language_produces_every_verdict() {
        for lang in [Lang::En, Lang::Es] {
            let strings = Strings { lang };
            for verdict in [
                Verdict::Malicious,
                Verdict::Suspicious,
                Verdict::Undetected,
                Verdict::Inconclusive,
                Verdict::Unknown,
            ] {
                assert!(
                    !strings.verdict(verdict).is_empty(),
                    "{verdict:?} in {lang:?}"
                );
            }
            assert_eq!(
                strings.verdict(Verdict::Undetected),
                match lang {
                    Lang::En => "UNDETECTED",
                    Lang::Es => "NO DETECTADO",
                }
            );
        }
    }

    #[test]
    fn the_summary_is_translated_not_just_formatted() {
        let summary = Summary {
            files: 3,
            malicious: 1,
            suspicious: 0,
            undetected: 2,
            inconclusive: 0,
            unknown: 0,
            errors: 0,
            duration_ms: 1_500,
        };

        let en = Strings { lang: Lang::En };
        let es = Strings { lang: Lang::Es };
        assert!(en.summary(&summary, 1.5).contains("3 files"));
        assert!(es.summary(&summary, 1.5).contains("3 archivos"));
        assert_ne!(en.summary(&summary, 1.5), es.summary(&summary, 1.5));
    }
}
