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
- T1b hashing throughput: three threads over one sequential read above 4 MiB. S1. inline. done → ef0e891
- T2a PE header structure: section table, entry point bounds, W+X sections, CLR flag. S2. inline. done → b1fa47f
- T2b PE body facts: per-section entropy, import table, packer hints (bounded reads), structured facts. S2. inline. done → 44a8798
- T2c container recursion: ZIP/7z/gzip extraction with depth and byte limits, re-entering the pipeline. S1, S2. inline.
- T3 ClamAV engine: local `clamscan`, `FOUND` parsing, 2 GiB cap reported as Partial{0}, timeout and process boundary. S1, S5. inline. done → 165fb40
- T3b ClamAV daemon: managed `clamd` on loopback port 3311, config under `%LOCALAPPDATA%`, reused if already listening, stopped when this run owns it, fallback to `clamscan` with the reason in a fact. S1. inline. done. 8 files in 8.3 s versus ~53 s with one process per file.
- T4 Defender engine: `MpCmdRun -Scan -ScanType 3 -File` with `-DisableRemediation`, exit-code contract, threat-name parsing. S5. inline. done. Verified against EICAR inside a zip (0.16 s) and end to end through the CLI.
- T5 YARA engine: in-process `yara-x` (no spawn), embedded rules plus `%LOCALAPPDATA%\VirusCheckDesktop\rules`, severity from rule metadata. S1, S2. inline. done. Verified live with a builtin rule and a user rule.
- T6 sandbox: `.wsb` generation, mapped read-only payload, PowerShell telemetry (process tree via WMI, TCP connections, DNS cache, file/registry diffs), result JSON back to host, timeout + teardown. S2. inline.
- T7 UI: desktop shell over the core. S3, S4. inline.
- T8 packaging + CI: `cargo build --release`, release artifact, GitHub Actions on windows-latest. S4. inline.
- T9 docs: README (prerequisites, engine setup, limits), SECURITY.md. S1, S4. inline.
- T10 directory scanning: recursive walk without following links, per-file reports, errors listed separately, JSON tree report. S1. inline. done.

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

L13. License decided by the user: MIT OR Apache-2.0, the Rust convention. `LICENSE-MIT` written, `LICENSE-APACHE` downloaded from apache.org rather than transcribed, and the workspace `license` field updated. No dependency forces a copyleft choice: ClamAV is spawned as a process and YARA-X is permissively licensed.

L14. T2b hashing fixed by measurement, not by guess: three worker threads consume shared `Arc` chunks from one sequential read, with a bounded queue of two chunks per worker. 2 GiB went from 12.2 s to 2.7 s (~800 MB/s) with an identical SHA-256, and memory stayed constant. Files under 4 MiB keep the single-threaded path because thread setup costs more than it saves there.

L15. T2b PE facts and T3 ClamAV. Engines can now return `Fact`s next to `Detection`s, because a report that can only say "nothing found" cannot show entropy 7.81 or an import list. `Coverage::Partial { scanned_bytes: 0 }` is now treated as *not inspected*: that is exactly the ClamAV case for a file above its 2 GiB cap, and the previous semantics would have counted it as inspected. ClamAV runs as a process with stdout redirected to a file (a pipe nobody drains deadlocks the child), a 10-minute wall clock, and `--max-scantime=600000` for its own parser. Integration state on this machine: ClamAV is not installed, so the engine reports `Unavailable`, the verdict is `Inconclusive`, and the CLI prints the install hint. The parser, the cap path and the failure path are covered by tests; a real `clamscan` run is still pending on a machine that has it.

L16. ClamAV installed and the engine verified against it. `winget install Cisco.ClamAV` gave 1.5.5, but the silent MSI leaves no `freshclam.conf`, no database and no `clamd` service: the config had to be copied from `conf_examples` and `freshclam` run elevated (a UAC prompt, because everything lives under Program Files). Result: 7 database files, database version 28191. End-to-end: `vcd scan notepad.exe` now reports `clamav completed`, coverage complete, verdict `UNDETECTED`, exit 0. The 2 GiB path was verified with a 3 GiB sparse file: ClamAV reports `0 B scanned`, no process is spawned, verdict `INCONCLUSIVE`. Detection output is still only covered by parser tests: writing EICAR would trip Defender's real-time protection and fire a user-facing alert, so that check is left to the user.

L17. Measured problem, not accepted silently: a 352 KiB scan takes 6.6 s, twice in a row, because `clamscan` loads the whole signature database per process and the silent MSI installed no `clamd`. That is unusable for a desktop app that scans several files. The fix is architectural and tracked as T3b: the app owns a `clamd` instance (config and database under `%LOCALAPPDATA%`, spawned as a child, torn down on exit) and scans through `clamdscan`, with `clamscan` as the fallback. Expected cost drops from seconds to tens of milliseconds.

L18. Detection verified by the user with EICAR: `clamav-signature: Eicar-Signature`, verdict `MALICIOUS`, so the ClamAV process boundary, output parsing and verdict mapping are all exercised against a real detection. The 6.6 s cost showed up again in the same run, which is why T3b exists.

L19. (Superseded by L20.) T4 was first abandoned on the belief that `MpCmdRun`'s custom scan is a no-op.

L20. T4 reversed with a decisive experiment. Timing was never evidence of a no-op: Defender keeps a scan cache that real-time protection populates when a file is written, which is why 100 MB of random bytes "scanned" in 30 ms and a 2000-file tree in 140 ms — both had just been read by RTP. The test that discriminates: EICAR built inside a zip **in memory** (the plaintext never touches the disk, so RTP cannot pre-scan the content) and scanned with `-DisableRemediation`. `MpCmdRun` returned exit 2 in 0.16 s with `Threat : Virus:DOS/EICAR_Test_File` and `file: eicar.zip->eicar.txt`, proving it reads content, extracts archives, and reports the signature. The engine now ships with `-DisableRemediation` (a scanner must never delete the user's files), the exit code as the contract, the `Threat` line parsed for the name, and a `caveat` fact stating that a clean answer may come from the cache and that excluded paths are invisible without admin rights. End-to-end through our CLI on that zip: `defender` malicious in 67 ms, `clamav` EICAR in 6.3 s, verdict `MALICIOUS`, exit 1.


L21. T5 YARA-X shipped in process. yara-x 1.24 (BSD-3), default features off except constant-folding, fast-regexp and exact-atoms, which keeps the 25 format modules and their crypto dependencies out; wasmtime still comes along and the first build cost 49 s. Rules come from the embedded `builtin.yar` (EICAR, encoded PowerShell) plus every `*.yar`/`*.yara` in `%LOCALAPPDATA%\VirusCheckDesktop\rules`; a rule file that fails to compile is skipped and reported as a fact, never silently dropped, and severity comes from the rule's `severity` metadata with `suspicious` as the default. Verified live: the builtin rule flags a script containing `-EncodedCommand` (suspicious, exit 1) with `rules: 2`, and a temporary user rule matching a marker reports `rules: 3` and a malicious detection. Cost: 0 ms for YARA against 6.3 s for ClamAV in the same run, which keeps the daemon/scan-cache work (T3b) as the dominant expense.

L22. T3b and directory scanning shipped together, because neither pays alone. Managed `clamd`: config, log and pid under `%LOCALAPPDATA%\VirusCheckDesktop\clamav`, fixed loopback port 3311, a `owner.pid` marker that lets a later run adopt and stop an orphan from a crashed run, `--stop` plus kill on drop, and fallback to `clamscan` with the reason in a `daemon` fact. `Scanner::with_local_engines(scope)` picks the mode: a single file keeps `clamscan` (starting a daemon costs the same ~6.6 s), a tree gets the daemon. Verified live: 6 copies of notepad.exe plus a text file and an encoded-PowerShell script scanned in 8.3 s total (about 53 s if each file loaded the database), `mode: clamd (database loaded once)`, zero listeners left on 3311 afterwards; single file unchanged at 6.8 s with `mode: clamscan`. Directory scan walks without following links, sorts paths for deterministic output, and lists unreadable files as errors instead of dropping them or calling them clean. Exit code 1 when anything is malicious or suspicious.
