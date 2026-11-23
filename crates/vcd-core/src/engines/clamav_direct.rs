//! In-process ClamAV through `libclamav.dll`.
//!
//! Spawning `clamscan` costs a full database load per file (~6.6 s here). This
//! module calls ClamAV's C API directly: the engine is created, the database
//! loaded and the signatures compiled once, and every scan after that is a
//! function call. It works on the same GPLv2 terms as the rest of the project.
//!
//! The FFI surface is deliberately small and declared here from the shipped
//! `clamav.h` (1.5.5): init, engine creation, two numeric settings, load,
//! compile, scan and free. Anything else stays in the process backend.

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_ulong, c_void};
use std::path::Path;

use libloading::Library;

const CL_SUCCESS: c_int = 0;
const CL_VIRUS: c_int = 1;

const CL_ENGINE_MAX_SCANSIZE: c_uint = 0;
const CL_ENGINE_MAX_FILESIZE: c_uint = 1;
const CL_ENGINE_MAX_RECURSION: c_uint = 2;
const CL_ENGINE_MAX_FILES: c_uint = 3;
const CL_ENGINE_MAX_SCANTIME: c_uint = 31;
const CL_ENGINE_TMPDIR: c_uint = 13;
const CL_ENGINE_CVDCERTSDIR: c_uint = 37;

const CL_DB_PHISHING: u32 = 0x2;
const CL_DB_PHISHING_URLS: u32 = 0x8;
const CL_DB_BYTECODE: u32 = 0x2000;
const CL_DB_STDOPT: u32 = CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE;

const SCAN_GENERAL_HEURISTICS: u32 = 0x4;

/// Archive, ELF, PDF, SWF, HWP3, XML docs, mail, OLE2, HTML, PE, OneNote, image.
const SCAN_PARSE_ALL: u32 =
    0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800;

/// ClamAV's own per-file ceiling.
const MAX_FILE_BYTES: i64 = 2 * 1024 * 1024 * 1024;

#[repr(C)]
struct ScanOptions {
    general: u32,
    parse: u32,
    heuristic: u32,
    mail: u32,
    dev: u32,
}

type FnInit = unsafe extern "C" fn(c_uint) -> c_int;
type FnEngineNew = unsafe extern "C" fn() -> *mut c_void;
type FnSetNum = unsafe extern "C" fn(*mut c_void, c_uint, i64) -> c_int;
type FnSetStr = unsafe extern "C" fn(*mut c_void, c_uint, *const c_char) -> c_int;
type FnLoad = unsafe extern "C" fn(*const c_char, *mut c_void, *mut c_uint, u32) -> c_int;
type FnCompile = unsafe extern "C" fn(*mut c_void) -> c_int;
type FnFree = unsafe extern "C" fn(*mut c_void) -> c_int;
type FnScanFile = unsafe extern "C" fn(
    *const c_char,
    *mut *const c_char,
    *mut c_ulong,
    *const c_void,
    *mut ScanOptions,
) -> c_int;
type FnVersion = unsafe extern "C" fn() -> *const c_char;

pub struct ClamAvDirect {
    /// Must outlive the engine and every function pointer taken from it.
    library: Library,
    engine: *mut c_void,
    free: FnFree,
    scan_file: FnScanFile,
    version: String,
    signatures: u32,
}

// ClamAV's engine is safe to use from multiple threads; the handle is immutable
// from our side and the only mutation happens inside libclamav, which locks.
unsafe impl Send for ClamAvDirect {}
unsafe impl Sync for ClamAvDirect {}

impl ClamAvDirect {
    pub fn load(install: &Path) -> Result<Self, String> {
        let dll = install.join("libclamav.dll");
        let database = install.join("database");

        if !dll.is_file() {
            return Err(format!("{} not found", dll.display()));
        }
        if !database.is_dir() {
            return Err(format!("{} not found", database.display()));
        }

        // libclamav depends on the DLLs next to it; make that directory
        // searchable for the loader without touching the user's environment.
        set_dll_directory(install);

        let library = unsafe { Library::new(&dll) }
            .map_err(|error| format!("cannot load {}: {error}", dll.display()))?;

        let init: FnInit = symbol(&library, b"cl_init\0")?;
        let engine_new: FnEngineNew = symbol(&library, b"cl_engine_new\0")?;
        let set_num: FnSetNum = symbol(&library, b"cl_engine_set_num\0")?;
        let set_str: FnSetStr = symbol(&library, b"cl_engine_set_str\0")?;
        let load: FnLoad = symbol(&library, b"cl_load\0")?;
        let compile: FnCompile = symbol(&library, b"cl_engine_compile\0")?;
        let free: FnFree = symbol(&library, b"cl_engine_free\0")?;
        let scan_file: FnScanFile = symbol(&library, b"cl_scanfile\0")?;
        let version: FnVersion = symbol(&library, b"cl_retver\0")?;

        unsafe {
            if init(0) != CL_SUCCESS {
                return Err("cl_init failed".to_string());
            }

            let engine = engine_new();
            if engine.is_null() {
                return Err("cl_engine_new returned null".to_string());
            }

            let engine_guard = FreeGuard { engine, free };

            set_num(engine, CL_ENGINE_MAX_FILESIZE, MAX_FILE_BYTES);
            set_num(engine, CL_ENGINE_MAX_SCANSIZE, MAX_FILE_BYTES);
            set_num(engine, CL_ENGINE_MAX_FILES, 10_000);
            set_num(engine, CL_ENGINE_MAX_RECURSION, 17);
            set_num(engine, CL_ENGINE_MAX_SCANTIME, 0);

            // This libclamav build resolves the certificate and temp
            // directories relative to its build tree, which does not exist on a
            // user machine; point both at real paths before loading the DB.
            let certs = cstring(&install.join("certs"))?;
            set_str(engine, CL_ENGINE_CVDCERTSDIR, certs.as_ptr());
            let temp = cstring(&std::env::temp_dir())?;
            set_str(engine, CL_ENGINE_TMPDIR, temp.as_ptr());

            let database = cstring(&database)?;
            let mut signatures: c_uint = 0;
            if load(database.as_ptr(), engine, &mut signatures, CL_DB_STDOPT) != CL_SUCCESS {
                return Err("cl_load failed (wrong database or version mismatch)".to_string());
            }

            if compile(engine) != CL_SUCCESS {
                return Err("cl_engine_compile failed".to_string());
            }

            std::mem::forget(engine_guard);

            let version_text = {
                let pointer = version();
                if pointer.is_null() {
                    "unknown".to_string()
                } else {
                    CStr::from_ptr(pointer).to_string_lossy().into_owned()
                }
            };

            Ok(Self {
                library,
                engine,
                free,
                scan_file,
                version: version_text,
                signatures,
            })
        }
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn signatures(&self) -> u32 {
        self.signatures
    }

    /// Returns the signature names and the bytes ClamAV inspected. An error
    /// means the engine refused or failed, never "clean".
    pub fn scan(&self, path: &Path) -> Result<(Vec<String>, u64), String> {
        let path = path
            .to_str()
            .ok_or_else(|| "path is not valid UTF-8".to_string())?;
        let path = CString::new(path).map_err(|_| "path contains a NUL byte".to_string())?;

        let mut virname: *const c_char = std::ptr::null();
        let mut scanned: c_ulong = 0;
        let mut options = ScanOptions {
            general: SCAN_GENERAL_HEURISTICS,
            parse: SCAN_PARSE_ALL,
            heuristic: 0,
            mail: 0,
            dev: 0,
        };

        let code = unsafe {
            (self.scan_file)(
                path.as_ptr(),
                &mut virname,
                &mut scanned,
                self.engine,
                &mut options,
            )
        };

        match code {
            CL_SUCCESS => Ok((Vec::new(), scanned as u64)),
            CL_VIRUS => {
                let name = if virname.is_null() {
                    "unnamed signature".to_string()
                } else {
                    unsafe { CStr::from_ptr(virname) }
                        .to_string_lossy()
                        .into_owned()
                };
                Ok((vec![name], scanned as u64))
            }
            other => Err(format!("libclamav scan failed with code {other}")),
        }
    }
}

impl Drop for ClamAvDirect {
    fn drop(&mut self) {
        if !self.engine.is_null() {
            unsafe {
                (self.free)(self.engine);
            }
            self.engine = std::ptr::null_mut();
        }
        // `library` stays alive until after this drop body runs.
        let _ = &self.library;
    }
}

/// Frees the engine if any step after `cl_engine_new` fails.
struct FreeGuard {
    engine: *mut c_void,
    free: FnFree,
}

impl Drop for FreeGuard {
    fn drop(&mut self) {
        if !self.engine.is_null() {
            unsafe {
                (self.free)(self.engine);
            }
        }
    }
}

fn cstring(path: &Path) -> Result<CString, String> {
    CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| format!("path contains a NUL byte: {}", path.display()))
}

fn symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, String> {
    unsafe { library.get::<T>(name) }
        .map(|symbol| *symbol)
        .map_err(|error| {
            format!(
                "{} missing from libclamav: {error}",
                String::from_utf8_lossy(name).trim_end_matches('\0')
            )
        })
}

/// Windows resolves a DLL's dependencies from the process search path, not from
/// the DLL's own folder; point the loader at the ClamAV directory first.
fn set_dll_directory(directory: &Path) {
    let wide: Vec<u16> = directory
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe extern "system" {
        fn SetDllDirectoryW(path: *const u16) -> i32;
    }

    unsafe {
        SetDllDirectoryW(wide.as_ptr());
    }
}

use std::os::windows::ffi::OsStrExt;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parse_options_cover_archives_and_pe() {
        assert_eq!(SCAN_PARSE_ALL & 0x1, 0x1); // archive
        assert_eq!(SCAN_PARSE_ALL & 0x200, 0x200); // PE
        assert_eq!(SCAN_PARSE_ALL & 0x800, 0x800); // image
    }

    #[test]
    fn load_without_the_library_is_an_error_not_a_panic() {
        let error = ClamAvDirect::load(&PathBuf::from(r"C:\definitely-not-clamav"));
        assert!(error.is_err());
    }

    #[test]
    #[ignore = "needs ClamAV installed; run manually"]
    fn loads_the_installed_engine() {
        let engine =
            ClamAvDirect::load(Path::new(r"C:\Program Files\ClamAV")).expect("load libclamav");
        assert!(engine.signatures() > 1_000);
        assert!(!engine.version().is_empty());
    }
}
