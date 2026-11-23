# Virus Check Desktop

Local malware triage for Windows. Files are analyzed on your machine: nothing is
uploaded, and the tool imposes no size cap of its own.

> Not affiliated with VirusTotal. This is not a clone of it: it runs local
> engines and reports what each one actually inspected.

## Status

Early. The static core and CLI work today; the ClamAV, Defender, YARA and
Windows Sandbox engines are the next tasks (see `odd/tasks/virus-check-desktop.md`).

## What it does now

```
vcd scan .\invoice.pdf
vcd scan .\samples\        # whole tree, one ClamAV database load for all files
```

- Types the file from its magic bytes, not its extension.
- Computes MD5, SHA-1 and SHA-256 in one streaming pass, so memory use is
  independent of the file size.
- Flags masquerading: executable content behind a document extension, and
  double extensions such as `photo.jpg.exe`.
- Parses PE headers: entry point outside every section, writable+executable
  sections, section count, managed assemblies.
- Reads the import table and samples section bodies for entropy, within a fixed
  budget; a large native image with no imports is flagged.
- Runs ClamAV when `clamscan` is available, parses its `FOUND` signatures, and
  reports a file above ClamAV's 2 GiB cap as unscanned rather than clean.
- Runs Microsoft Defender's command line scanner with `-DisableRemediation`, so
  a scan never quarantines or deletes the user's files.
- Matches YARA rules in process through YARA-X: two built-in rules (EICAR and
  encoded PowerShell commands) plus every `*.yar`/`*.yara` file dropped in
  `%LOCALAPPDATA%\VirusCheckDesktop\rules`. Severity comes from the rule's
  `severity` metadata (`malicious`, `suspicious`, `info`).
- Scans a directory tree recursively (links skipped), prints one line per file
  and a summary, and lists unreadable files as errors instead of dropping them.
- Reports per-engine coverage, so a skipped range can never hide behind a
  quiet verdict.

Exit codes: `0` nothing detected, `1` malicious or suspicious, `2` scan failed.

`--json` prints the same report as machine-readable JSON.

## Requirements

- Windows 10/11
- Rust 1.90+ with the MSVC toolchain (Rust build only)
- Optional: ClamAV on `PATH` or in `C:\Program Files\ClamAV` for signature
  scanning. Without it the report says so and the verdict is `Inconclusive`.

## Build and test

```powershell
cargo test --workspace
cargo build --release
```

The CLI lands in `target/release/vcd.exe`.

## Known limitations

- A single-file scan still pays one `clamscan` startup (~6.6 s): starting a
  daemon for one file costs the same or more. Directory scans use a managed
  `clamd` and load the database once.
- A clean Defender answer may come from its scan cache (real-time protection
  already read the file when it was written), and paths listed in Defender's
  exclusions are invisible to us without administrator rights. The engine
  reports that caveat with every result.

## Desktop app

```powershell
cargo run -p vcd-app --release
```

or run `target/release/virus-check-desktop.exe` (single file, no runtime to
install). Drag a file or a folder onto the window, or use the buttons. The
window never scans on the UI thread: a worker owns the engines, so the ClamAV
daemon stays warm and the list fills as files finish. Selecting a row shows the
hashes, per-engine facts and findings; **Copy JSON** exports that report.

## Detonation

```powershell
vcd detonate .\sample.exe --backend sandboxie
vcd sandbox status
```

Two backends, chosen explicitly or by what the machine can run:

| Backend | Editions | Boundary |
| --- | --- | --- |
| Windows Sandbox | Pro / Enterprise / Education | virtual machine |
| Sandboxie-Plus | any, including Home | shared kernel (driver-level) |

`vcd sandbox status` reports the edition and which backend is installed.
`vcd sandbox enable` offers to turn on Windows Sandbox on Pro/Enterprise
(administrator prompt, then a reboot). The desktop app shows one button per
installed backend and, when none is installed, the exact next step for the
detected edition.

Both backends map the payload read-only (Windows Sandbox) or run it inside a
box with network blocked by default, record processes, TCP connections, DNS
lookups and dropped files (copied back for rescanning), and stop on a timeout.
Registry changes are captured in Windows Sandbox only: Sandboxie virtualizes
them into a hive this tool does not decode, and the report says so.

Caveats the report states for itself: Sandboxie shares the kernel, its process
list is polling-based so very short-lived processes can be missed, and no
observed behaviour is not proof of benign behaviour. Delete the detonation
workspace (its path is reported) when you are done with the samples.

## Design rule

No report may claim more than was actually inspected. Every engine returns its
own `Coverage`:

| Coverage | Meaning |
| --- | --- |
| `Complete` | every byte the engine is responsible for was inspected |
| `Partial` | part of the file was inspected; the reason names the engine's own cap |
| `None` | nothing was inspected; the reason says why |

A verdict is `Undetected` only when no engine reported a detection *and* every
engine covered its whole range. Otherwise it is `Inconclusive` (a range was
skipped, an engine could not run, or an engine failed) or `Unknown` (nothing was
inspected at all).

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you state otherwise, any contribution you intentionally
submit for inclusion in this project shall be dual-licensed as above, without
additional terms or conditions.

## Known measurements

| File | Time | Notes |
| --- | --- | --- |
| 2 GiB, hashing only | 2.7 s | MD5+SHA-1+SHA-256, three threads over one sequential read |
| 352 KiB, with ClamAV | 6.6 s | single file: `clamscan` loads the database per process |
| 8 files, directory tree | 8.3 s | one managed `clamd` for the whole tree |
| EICAR inside a zip | 0.07 s | Defender detection path: exit 2 and the signature name |
| Any file, YARA-X | < 0.01 s | in-process pattern matching, no database to load |

Files above 4 MiB hash each algorithm on its own thread over shared read-only
chunks; smaller files stay on the single-threaded path, where thread setup would
cost more than it saves.
