# Linux CVE Tool v2.0.0

[简体中文](README.md) | **English**

Cross-checks every installed package on a Linux host against six official
vulnerability data sources and reports four separate verdicts — affected, fixed,
not affected, unknown — then performs controlled automatic remediation and
re-verification on distributions where the licence and support status allow it.

v2.0.0 is a complete rewrite. v1.x answered one question ("is this host's kernel
affected by CVE-2026-98432?"); v2 applies the same determination model to any
CVE against any installed package.

**What this tool deliberately does not do** — this matters more than the feature list:

- It does not treat "not listed by the vendor" as "not affected". No evidence means
  `UNKNOWN`, and the exit code says so.
- It does not approximate distribution version comparison with semantic versioning.
  dpkg's `~` pre-release ordering and rpm's epoch precedence are implemented natively.
- It does not present HTTPS transport or hash checks as a vendor signature.
  Signature status and integrity status are recorded separately.
- It does not report "zero vulnerabilities" when the data is incomplete.
  Insufficient coverage returns exit code 9, so scripts cannot read it as "safe".
- It never reboots the server.

Current version **v2.0.0**; see [CHANGELOG.md](CHANGELOG.md).

## Install

Single-machine install (detects the architecture, verifies SHA256, drops the binary
in `/usr/local/bin`, writes no config):

```bash
curl -fsSL https://github.com/AronWang001/linux-cve/releases/download/v2.0.0/install.sh | sudo sh
```

Pin a version or destination:

```bash
VERSION=v2.0.0 DEST=/usr/local/bin sh install.sh
```

Prebuilt packages exist for amd64 and arm64 only; for other architectures, or to
build from source, see [Building from source](#build-from-source). The old
repository name `linux-cve-2026-98432-fix` still redirects (301).

## Quick start

```bash
# 1. Collect installed packages, kernel, distribution
sudo linux-cve inventory

# 2. Sync vulnerability data (slow the first time, incremental afterwards)
sudo linux-cve feed update --all

# 3. Scan
sudo linux-cve scan

# 4. Inspect results
sudo linux-cve list --vulnerable
sudo linux-cve report --out /var/log/linux-cve/report.md

# 5. Rehearse remediation, then execute it
sudo linux-cve plan
sudo linux-cve fix --yes
```

`fix` additionally requires `allow_auto_fix = true` in
`/etc/linux-cve/config.toml`. The switch defaults to off and `--yes` cannot
override it: permission and confirmation are two different things.

`scan` exit codes are designed for CI:

| Code | Meaning |
| --- | --- |
| 0 | Scan complete, nothing affected, coverage complete |
| 3 | Scan complete, affected packages found |
| 9 | Scan complete, but coverage is insufficient — not evidence of safety |
| 1 / 2 / 4 / 5 / 6 / 7 / 130 | runtime error / usage / unsupported / permission / remediation failed / integrity / interrupted |

## The six data sources

| Source | Trust | Form | Measured scale (2026-11-24) |
| --- | --- | --- | --- |
| Debian Security Tracker | B (HTTPS+SHA256) | single JSON, ~90 MB | 210,415 advisories / 222,161 fixes |
| Ubuntu OVAL | B | bzip2 OVAL per codename | noble: 270.8 MB XML → 37,611 advisories / 48,617 fixes (20.0 s) |
| Alpine secdb | B | JSON per release × repository | 3.20: 8,299 advisories / 8,344 fixes (3.1 s) |
| Arch Security Tracker | B | single JSON | 8,035 advisories / 7,401 fixes / 303 not affected (1.8 s) |
| Red Hat CSAF | A (detached GPG) | one JSON + `.asc` per RHSA | 32,407 total; 2026 slice 10,409 docs → 66,991 advisories / 810,817 fixes |
| SUSE CSAF | A (detached GPG) | one JSON + `.asc` per advisory | 45,765 total; 2026 slice 13,561 docs → 149,788 advisories / 965,304 fixes |

All six together: **481,139 advisories and 2,062,599 fix records**, a 1.5 GB
SQLite database, and 6.1 GB of raw artifacts stored content-addressed by sha256.
CSAF sources are large; use `feed update rhel-csaf --since 2026` to keep the
year slice only.

Signing key fingerprints for A-level sources are hard-coded in
`internal/feed/registry.go`. A vendor key rotation requires a code change and a
release — the tool will never silently accept a new key.
See [docs/data-sources.md](docs/data-sources.md) (Chinese) for the measured
structure of each source.

## Three orthogonal state dimensions

| Dimension | Values | Question answered |
| --- | --- | --- |
| `VulnState` | `VULNERABLE` / `FIXED` / `NOT_AFFECTED` / `UNKNOWN` / `UNSUPPORTED` | Is the CVE present right now? |
| `RemediationState` | `FIX_AVAILABLE` / `NO_FIX` / `FIX_PENDING_MIRROR` / `MANUAL_REQUIRED` / `BLOCKED` / `NOT_APPLICABLE` / `UNKNOWN` | Can it be fixed, and how? |
| `RebootState` | `NOT_REQUIRED` / `REQUIRED` / `UNKNOWN` | Has the fix taken effect? |

"Fixed" only means the installed version is at or above the vendor's stated fixed
version. Whether it is actually in effect depends on service and host restarts —
two different things, reported separately.

## Commands

| Command | Purpose |
| --- | --- |
| `inventory [--json] [--save]` | Collect packages / kernel / distribution |
| `feed update [source...] [--all] [--since N]` | Sync data; `--since` applies to CSAF sources |
| `feed status [--json]` | Trust level, signature state, last success per source |
| `scan [--json] [--dry-run]` | Determine and persist findings |
| `list [--vulnerable] [--state S] [--json] [--limit N]` | List the latest scan |
| `show <CVE> [--json]` | Evidence chain for a single CVE |
| `plan [--package P] [--json]` | Build a remediation plan, change nothing |
| `fix [--yes] [--dry-run] [--package P] [--json]` | Execute and re-verify |
| `report [--out path]` | Markdown report |
| `support [--json]` | Support matrix and auto-fix permission |
| `db status` / `db migrate` | Database state and migrations |
| `version [--json]` | Version information |

Full flags, output samples and exit codes: [docs/cli.md](docs/cli.md) (Chinese).

## Support matrix

| Distribution | Release | Detection | Auto-fix |
| --- | --- | --- | --- |
| Debian | 13 trixie | ✅ host + container | ✅ host-verified |
| Debian | 12 bookworm | 🟡 | ✅ enabled |
| Debian | 11 bullseye | 🟡 (EOL) | ❌ |
| Ubuntu | 24.04 noble | ✅ container | ❌ (ESM out of scope) |
| Ubuntu | 22.04 jammy | 🟡 | ❌ (ESM out of scope) |
| Alpine | 3.20 | ✅ container | ❌ (EOL) |
| Alpine | 3.19 / 3.21 | 🟡 | ❌ (all EOL) |
| Arch | rolling | 🟡 | ❌ (no fixed-version semantics) |
| RHEL | 8 / 9 / 10 | 🟡 | ❌ |
| SLES | 15.6 / 16.0 | 🟡 | ❌ |
| openSUSE Leap | 15.6 / 16.0 | 🟡 | ❌ |

`✅ host` means a real standalone machine; `✅ container` means the same binary
run inside the official image with a real feed sync and a real scan (CI reruns it
on every commit) — real but sharing the host kernel, so not a bare-metal claim.
`🟡` means the parser and data are verified against real vendor publications but
the tool has not been run on that distribution yet. Unregistered releases are always `UNKNOWN` — there is no "closest
match" fallback. Lifecycle dates: [docs/support-matrix.md](docs/support-matrix.md).

## Build from source

```bash
go build -o linux-cve ./cmd/linux-cve     # Go 1.24+
go test ./...
```

Pure Go, no cgo (SQLite via `modernc.org/sqlite`), cross-compiles to amd64 and
arm64 Linux.

## Data and privacy

- All determination happens locally; the package inventory is never uploaded.
- The database lives at `/var/lib/linux-cve/cve.db`; raw publications are stored
  read-only and immutable under `/var/lib/linux-cve/artifacts/`.
- Only the official sources listed above and vendor key URLs are contacted.

## Known limitations

- "Not listed" is not "not affected". The report and exit code make the
  uncertainty explicit; they cannot eliminate it.
- Debian and Ubuntu publish advisories per source package, so binary packages are
  matched through a source-package bridge. Bridge failures are counted separately
  and never counted as "not affected".
- Debian's `status=open` (confirmed affected, no patch) is reported as
  `VULNERABLE` + `NO_FIX`. On old CVEs this is a large number — a fact, not noise.
- VEX feeds for Red Hat and SUSE are not ingested in this release, so
  "not affected" declarations only come from `known_not_affected` inside RHSA
  documents (26,327 records); SUSE has none.
- Automatic remediation is limited to Debian 12/13 and must be re-verified
  afterwards; a failed re-verification returns exit code 6.

## Documentation

| Document | Content |
| --- | --- |
| [docs/cli.md](docs/cli.md) | Commands, flags, output, exit codes |
| [docs/data-sources.md](docs/data-sources.md) | Measured structure of the six sources |
| [docs/security-model.md](docs/security-model.md) | Trust levels, signatures, failure semantics |
| [docs/support-matrix.md](docs/support-matrix.md) | Lifecycle and auto-fix permission |
| [docs/architecture.md](docs/architecture.md) | Layers and data flow |
| [docs/data-model.md](docs/data-model.md) | Database schema |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common failures |
| [docs/migration-v1-v2.md](docs/migration-v1-v2.md) | Migrating from v1.x |

## Licence

See [LICENSE](LICENSE).
