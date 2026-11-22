# Virus Check Desktop

Local-first malware triage for Windows. Static analysis of any file at any size, plus isolated detonation in Windows Sandbox.
Branch: `main` (feature work in `feat/*`). Delivery: `single-pr` forecast pending. Runner: `cargo test --workspace`.

## Specs

S1. "no tenga límite de tamaño de archivo"
   - No artificial cap of our own: hashing, type identification and streaming inspection work on any size the filesystem can store.
   - Each engine declares what it actually inspected: `Coverage::Complete | Partial { scanned_bytes, reason } | None { reason }`. No single "clean" verdict hides an engine that skipped bytes.
   - Acceptance: scanning a file larger than an engine's own cap still produces a full report with that engine marked `Partial`/`None` and the cap named in `reason`.
   - Check: unit test with a stub engine that reports `Partial`; integration scan of a sparse multi-GiB file must not load it into memory.

S2. "que ejecute todos los tipos de archivo"
   - Accepted interpretation (assumption, not literal): every file type is *analyzed*; only types Windows can execute are *detonated*, and always inside an isolated sandbox.
   - Static coverage is universal: content-type by magic bytes, not extension.
   - Detonation applies to PE, scripts, and Office documents with macros, in Windows Sandbox with a read-only mapped drop folder.
   - Acceptance: a file with an unknown or disguised extension is still typed and analyzed; a request to detonate an unsupported type returns a typed `Skipped` reason instead of failing.

S3. "se ejecute en local con un programa"
   - Offline by default. No file leaves the machine. Optional network lookups are off unless the user enables them.
   - Acceptance: the scanner runs with no network access and produces a complete report.

S4. "Se subiría a GitHub con el nombre de Virus Check Desktop"
   - Repository slug `virus-check-desktop`, product name "Virus Check Desktop".
   - Acceptance: repo builds from a clean clone with documented prerequisites only.

S5. Honest verdicts
   - `Malicious | Suspicious | Undetected | Inconclusive | Unknown`. `Undetected` means "no engine in this run reported a detection", never "safe". `Inconclusive` when some inspected range was skipped; `Unknown` when nothing was inspected.
   - Acceptance: aggregation table covered by tests.

## Tasks

- T1 core: streaming digests, content typing, report/verdict model, scanner, CLI. S1, S2, S5. inline. done → b1fa47f
- T2a PE header structure: section table, entry point bounds, W+X sections, CLR flag. S2. inline. done → b1fa47f
- T2b PE body facts: per-section entropy, imports, packer hints (bounded reads). S2. inline.
- T2c container recursion: ZIP/7z/gzip extraction with depth and byte limits, re-entering the pipeline. S1, S2. inline.
- T3 ClamAV engine: local `clamscan`/`clamd` detection, `--max-filesize` 2 GiB cap reported as Partial. S1, S5. inline.
- T4 Defender engine: `MpCmdRun.exe -Scan -ScanType 3 -File`, threat parsing. S5. inline.
- T5 YARA engine: YARA-X `yr` CLI, compiled rules, chunked scanning with overlap for oversized files. S1, S2. inline.
- T6 sandbox: `.wsb` generation, mapped read-only payload, PowerShell telemetry (process tree via WMI, TCP connections, DNS cache, file/registry diffs), result JSON back to host, timeout + teardown. S2. inline.
- T7 UI: desktop shell over the core. S3, S4. inline.
- T8 packaging + CI: `cargo build --release`, release artifact, GitHub Actions on windows-latest. S4. inline.
- T9 docs: README (prerequisites, engine setup, limits), SECURITY.md. S1, S4. inline.

## Log

L1. User request, verbatim: "Me gustaría crear una alternativa a VirusTotal que no tenga límite de tamaño de archivo, que ejecute todos los tipos de archivo, y que se ejecute en local con un programa. Se subiría a GitHub con el nombre de Virus Check Desktop."

L2. Scope decision taken on the page "Alcance de Virus Check Desktop v1": "Estatico + sandbox de detonacion". So detonation is in v1; static analysis is its prerequisite, not a substitute.

L3. Stack decision, revised twice with evidence. First attempt: Rust workspace. Rejected because the machine has a Rust toolchain but no MSVC linker and no Visual Studio at all (`link.exe`, `cl`, `vswhere` all missing); installing Build Tools is a multi-gigabyte admin install. Second and current: C# on .NET 10, which needs only the SDK. The SDK was missing too (runtimes only), so it was installed user-scoped with `dotnet-install.ps1 -Channel 10.0` into `%LOCALAPPDATA%\Microsoft\dotnet` (10.0.404), no admin and no reboot. C# is the fitting owner for a Windows desktop app: native UI, streaming file IO, process orchestration for external engines, single-file publish.

L4. Limits established from primary sources, not assumed: `clamscan(1)` documents `--max-filesize` default 100 MB with a maximum of 2 GB, `--max-scansize` default 400 MB, `--max-files` 10000, `--max-recursion` 17. Therefore "unlimited size" cannot mean "ClamAV scans everything"; it must mean no cap of our own plus per-engine coverage reporting (S1). Windows Sandbox is present on Windows 11 Pro but its optional feature is not enabled on this machine (`WindowsSandbox.exe` absent; feature state needs elevation to query). Enabling it requires admin and a reboot: user action, tracked in T6.

L5. Repository initialised at `D:\Proyectos\Virus Check Desktop` (the earlier `VirusTotal Desktop` folder was empty; the "VirusTotal" name is a trademark and stays out of paths and slugs).

L6. Open decision, not blocking: license. Recommendation GPL-3.0-or-later for a security tool meant to stay auditable; ClamAV is invoked as a separate process, so its GPLv2 does not reach our code.

L7. `Verdict.Clean` was renamed to `Verdict.Undetected` after the first end-to-end run: with only the built-in engine, a PE named `.bin` came back "CLEAN", which reads as a guarantee the run cannot make. `Undetected` states exactly one fact: no engine in this run reported a detection.

L8. T1 evidence (observed, not assumed): 21 tests pass; `vcd scan` on `cmd.exe` copied to `invoice.pdf` reports PE + `extension-mismatch` and exits 1; a 2.5 GiB file with a PE header is scanned in 16.2 s wall time with constant memory, coverage complete. Throughput ~165 MB/s for MD5+SHA-1+SHA-256 in one pass on this CPU.

L9. Verdict semantics needed a fix before the PE engine could exist: an engine that does not apply to a type (`Skipped`) must be neutral, otherwise every non-PE file would degrade to Inconclusive. `Unavailable` and `Failed` are the opposite case: a check that should have run did not, so they make the run incomplete. T2a evidence: `cmd.exe` parses with zero findings; a managed DLL reports `pe-dotnet`; a crafted PE with the entry point outside its sections reports `pe-entrypoint-outside-sections`.

L10. Stack reversed back to Rust, on the user's instruction and after verifying the toolchain instead of assuming it. Evidence: `vswhere` now reports Visual Studio 2022 Community with the C++ tools, and a `rustc` hello-world links and runs; `WindowsSandbox.exe` is present, so the optional feature the user enabled is really installed. The C# tree was a spike, not a delivered artifact: it lived only in the three local commits, none pushed.

L11. Port verified by differential run, not by inspection: same 9-file corpus (system PE, managed DLL renamed `.pdf`, zip, json, xml, text, empty, random binary) through the old C# binary and the new Rust binary produced identical human output and identical exit codes; the 2 GiB SHA-256 matches. The C# spike is preserved on branch `spike/csharp`.

L12. Performance regression accepted and recorded, not hidden: 2 GiB in 12.2 s with Rust versus 6.2 s with .NET. .NET hashes MD5/SHA-1 through Windows CNG with hardware acceleration; the `md-5`/`sha1` crates are pure Rust. Correctness is identical; throughput is a follow-up task (parallelize the three hashers or defer MD5/SHA-1 to reputation lookups). Recorded in the README under known measurements.

