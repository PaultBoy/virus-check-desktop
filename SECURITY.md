# Security policy

Virus Check Desktop analyzes untrusted files and, when asked, executes them
inside a sandbox. Treat every sample and every dropped file as live malware.

## Reporting a vulnerability

Report privately through **GitHub Security Advisories** (Security → Advisories →
Report a vulnerability) in this repository. Do not open a public issue for a
vulnerability. Please include the version, the Windows build, the steps to
reproduce, and the observed effect.

## What the tool promises

- It never uploads a scanned file. All engines are local.
- It never executes a sample unless `vcd detonate` (or the Detonate button) is
  invoked explicitly.
- `clamscan`/`clamdscan` and `MpCmdRun` run with no remediation: the tool does
  not quarantine, delete or modify the files it scans.
- The prepare/scan pipeline opens files read-only.

## Known boundaries, stated on purpose

- **Sandboxie does not isolate at the kernel.** A flaw in its driver, or a
  sample that targets it, can escape. Windows Sandbox is a virtual machine and
  is preferred; the report says which backend ran.
- **Windows Sandbox telemetry is written by the guest.** A sample that targets
  the harness can tamper with or delete the report. The report carries this
  caveat.
- **Sandboxie telemetry is host polling.** Very short-lived processes can be
  missed, and registry writes are not decoded.
- **Absence of observed behaviour is not proof of benign behaviour.** A sample
  can detect the sandbox and stay quiet.
- **Dropped files are stored on disk** under
  `%LOCALAPPDATA%\VirusCheckDesktop\detonations\`. They are live samples;
  delete the workspace when you are done, and do not run them on the host.
- Enabling Windows Sandbox requires administrator rights and a reboot; the tool
  cannot enable firmware virtualization for you.

## Supported versions

Only the latest release (and `main`) receive fixes.
