# Virus Check Desktop

Local malware triage for Windows. Files are analyzed on your machine: nothing is
uploaded, and the tool imposes no size cap of its own.

## Install

Download the latest release from GitHub releases and run it; there is no runtime
to install.

- `virus-check-desktop.exe` — the desktop app
- `vcd.exe` — the command line (`scan`, `detonate`, `sandbox`)

Releases are built by GitHub Actions on every tag. See **Build and test** to
build from source.

## Status

Working end to end: static analysis (content typing, PE structure, YARA-X,
ClamAV, Defender), directory scans with a managed ClamAV daemon, optional
detonation in Windows Sandbox or Sandboxie, and the desktop app. The task log
and the decisions behind it live in `odd/tasks/virus-check-desktop.md`.

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
- Runs ClamAV in process through `libclamav.dll` for directory scans (the
  database loads once, ~3.6 M signatures, every file after that is a function
  call) and through `clamscan` for a single file, with explicit size and time
  limits. Reports a file above ClamAV's 2 GiB cap, or content ClamAV skipped for
  its own limits, as partial coverage rather than clean. `vcd clamav install`
  sets it up without an administrator and verifies the pinned MSI digest.
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

Exit codes: `0` nothing detected, `1` malicious or suspicious, `2` scan failed or
inconclusive.

`--json` prints the same report as machine-readable JSON.

## Requirements

- Windows 10/11
- Rust 1.95+ with the MSVC toolchain (building from source only)
- Optional: ClamAV for signature scanning. The app (or `vcd clamav install`)
  downloads the official package into `%LOCALAPPDATA%\VirusCheckDesktop\clamav`
  and updates its signatures without an administrator; a system-wide install
  also works. Without ClamAV the report says so and the verdict is
  `Inconclusive`.
- Optional: Sandboxie-Plus for detonation on Windows Home; Windows Sandbox for
  the VM backend on Pro/Enterprise/Education.

## Build and test

```powershell
cargo test --workspace
cargo build --release
```

The CLI lands in `target/release/vcd.exe`.

## Known limitations

- A single-file scan still pays one `clamscan` startup (~6.6 s): starting a
  daemon or loading the library for one file costs the same or more. Directory
  scans load ClamAV's database once into the process (~7 s, ~300 MB resident)
  and then scan each file in milliseconds.
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
window never scans on the UI thread: a worker owns the engines, so they are
built once and the list fills as files finish. Selecting a row shows the
hashes, per-engine facts and findings; **Copy JSON** exports that report. If
ClamAV is missing, the app opens a setup dialog that installs it into the user
profile with visible progress and no administrator prompt. The interface follows
the Windows UI language (English and Spanish are shipped; anything else falls
back to English); engine facts and caveats stay in English because they are
data, not interface text.

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
(administrator prompt, then a reboot). The desktop app opens a modal to choose the backend when a sample is detonated,
with the recommended one labelled as such; it keeps the run's progress in that
modal until the sandbox reports back.

Both backends map the payload read-only (Windows Sandbox) or run it inside a
box with network blocked by default, record processes, TCP connections, DNS
lookups and dropped files (copied back for rescanning), and stop on a timeout.
Registry changes are captured in Windows Sandbox only: Sandboxie virtualizes
them into a hive this tool does not decode, and the report says so.

Caveats the report states for itself: Sandboxie shares the kernel, its process
list is polling-based so very short-lived processes can be missed, and no
observed behaviour is not proof of benign behaviour. Delete the detonation
workspace (its path is reported) when you are done with the samples.

## Architecture

- `crates/vcd-core` — streaming hashes, content typing, PE and import analysis,
  the engines (content-type, pe-structure, defender, yara, clamav), the
  coverage/verdict model, directory scanning and both detonation backends.
- `crates/vcd-cli` — `vcd`: `scan`, `detonate`, `sandbox`, `clamav`.
- `crates/vcd-app` — the egui desktop shell. A worker thread owns the scanner so
  engines are built once and the window never blocks.

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

GNU General Public License, version 2 or (at your option) any later version.
See [LICENSE](LICENSE).

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

Unless you state otherwise, any contribution you intentionally submit for
inclusion in this project is licensed under the same terms.

## Known measurements

| File | Time | Notes |
| --- | --- | --- |
| 2 GiB, hashing only | 2.7 s | MD5+SHA-1+SHA-256, three threads over one sequential read |
| 352 KiB, with ClamAV | 6.6 s | single file: `clamscan` loads the database per process |
| Directory tree, ClamAV | ~7 s + ms per file | `libclamav` in process: one database load for the whole tree |
| EICAR inside a zip | 0.07 s | Defender detection path: exit 2 and the signature name |
| Any file, YARA-X | < 0.01 s | in-process pattern matching, no database to load |

Files above 4 MiB hash each algorithm on its own thread over shared read-only
chunks; smaller files stay on the single-threaded path, where thread setup would
cost more than it saves.
