# CVE-2026-98432 Detection and Remediation Tool

[简体中文](README.md) | **English**

This tool checks whether the kernel currently running on a Linux server is affected by CVE-2026-98432 and, on distributions that have been fully adapted and verified, installs the official fixed kernel package. It covers distribution identification, kernel-to-package mapping, vulnerability assessment, kernel installation, and post-installation verification. It does not modify application configuration and never reboots the server.

Automatic remediation is limited to Debian 12/13 and Amazon Linux 2/2023. Ubuntu and Red Hat Enterprise Linux are detection-only because no confirmed fixed package has been published. All other listed distributions are identified and reported but never enter the installation path. See [Supported Distributions](#supported-distributions) for the current matrix.

Current version: v1.2.0. See [CHANGELOG.md](CHANGELOG.md) for changes.

## Vulnerability Information

| Item | Detail |
| --- | --- |
| Identifier | CVE-2026-98432 |
| Component | Linux kernel IPv4 subsystem (`tcp_v4_syn_recv_sock`, `tcp_v4_reqsk_destructor`) |
| Class | Use-after-free |
| Trigger | When retransmitted TCP SYNs are processed concurrently, or when request-socket migration is enabled via `tcp_migrate_req`, `inet_opt` and `ireq_opt` may be freed before the RCU grace period ends |
| Impact | Kernel memory corruption that can lead to denial of service. The exact impact and exploitation requirements are defined by each distribution's advisory |
| Upstream fix | `ipv4: free inet_opt and ireq_opt after an RCU grace period`, merged in 7.2.10, 6.18.56, 6.12.113, and 6.1.190 (commit `26d4c36d318c`) |
| Published | 2026-10-15 |

Whether a distribution is affected and which version carries the fix are determined by that distribution's own advisory. The tool does not infer one distribution's status from another's, does not derive distribution fix status from the upstream version number, and does not assess CVSS scores or real-world exploitability.

## Features

- Distribution identification: reads `ID`, `VERSION_ID`, and `VERSION_CODENAME` from `/etc/os-release` and adds distribution-specific signals such as Oracle's UEK marker and Amazon Linux release numbers. `ID_LIKE` is not used to collapse identities: Ubuntu is never treated as Debian, and Rocky Linux, AlmaLinux, and Oracle Linux are never treated as RHEL.
- Architecture detection: normalizes `uname -m` (`x86_64` becomes `amd64`, `aarch64` becomes `arm64`) and cross-checks the result against the architecture reported by the package manager. A mismatch produces `UNKNOWN`.
- Kernel mapping: maps the running kernel to the kernel package actually installed, rather than taking the newest kernel package present on the machine.
- Status assessment: looks up the locally verified baseline by distribution, release, and kernel branch, and compares versions using the semantics of the relevant package manager.
- Automatic remediation: installs the official fixed kernel only on allowlisted distributions, then re-checks the package database, kernel image, initramfs, and boot entries.
- Reporting: `--report` writes a detection report with the supporting evidence; `--list-distros` prints the support matrix.

## Requirements

- Operating systems: automatic remediation is available on Debian 12 (bookworm), Debian 13 (trixie), Amazon Linux 2, and Amazon Linux 2023. Detection is available on Ubuntu 20.04/22.04/24.04 and RHEL 8/9/10. Identification is available on Rocky Linux, AlmaLinux, Oracle Linux, Fedora, openSUSE Leap, SUSE Linux Enterprise, Arch Linux, and Alpine Linux. A distribution version outside an adapter's declared range returns `UNSUPPORTED`.
- Architecture: the remediation path enforces an architecture allowlist. Debian is limited to amd64; Amazon Linux 2/2023 support x86_64 and aarch64. Detection-only and identification-only distributions are not blocked on architecture, but the running kernel must still map to a distribution package.
- Privileges: root is required. Only `--list-distros` can be run as an unprivileged user.
- Dependencies: Bash 4.0 or later, coreutils, `awk`, `sed`, `grep`, `tar`, `find`, and the package manager tools for the target distribution (`dpkg`/`apt-get`/`apt-cache`, `rpm`/`dnf`/`yum`, `apk`, `pacman`, `zypper`). The bootstrap installer additionally requires `curl` and `sha256sum` (or `shasum`).
- Network: access to the distribution's official repositories. The bootstrap installer also requires access to GitHub.

## Installation

### One-command execution

```bash
curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.2.0/install.sh | sudo bash
```

`install.sh` is a bootstrap installer and makes no system changes itself. It downloads the source archive for the pinned tag into a temporary directory, fetches `SHA256SUMS` from the release, verifies `fix.sh`, `install.sh`, every file under `lib/` and `adapters/`, and the baseline YAML under `data/`, and only then executes `fix.sh` with the same arguments. After detection it prints the planned change and installs the kernel only after you answer `Y`. The confirmation prompt reads from `/dev/tty`, so it still works when the installer is piped into `bash`; `sudo` may ask for a password.

Verification fails closed. A missing or empty `SHA256SUMS`, a manifest that does not cover every script, any hash mismatch, an absolute path or `..` in the archive, or the absence of both `sha256sum` and `shasum` stops the run before any tool code executes. `SHA256SUMS` comes from the same repository as the archive and is not an independent signature; it must not be described as signature verification. Downloading and reviewing the script before production use is still recommended.

### Read-only check

```bash
curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.2.0/install.sh | sudo bash -s -- --check
```

This reads system state only: no repository index refresh, no package installation, no configuration changes. `--check` governs the detection and remediation phases; it does not prevent `install.sh` from downloading the archive. If the local package index is empty, candidate versions will be reported as unknown, so run `apt-get update` or `dnf makecache` first.

### Unattended execution

```bash
curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.2.0/install.sh | sudo bash -s -- --yes
```

`--yes` skips the confirmation prompt only. It does not bypass the distribution allowlist, advisory verification, or version checks. Distributions outside the allowlist never enter the installation path, even with `--yes`.

### Download, review, then run

```bash
curl -fsSLO https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.2.0/install.sh
less install.sh
sudo bash install.sh --check
sudo bash install.sh
```

### Clone and run

`fix.sh` depends on the `lib/`, `adapters/`, and `data/` directories next to it and cannot be used on its own:

```bash
git clone --branch v1.2.0 --depth 1 https://github.com/AronWang001/linux-cve-2026-98432-fix.git
cd linux-cve-2026-98432-fix
sudo bash fix.sh --check
sudo bash fix.sh
```

### Verify release artifacts

`SHA256SUMS` covers `fix.sh`, `install.sh`, every script under `lib/` and `adapters/`, and the baseline YAML under `data/`. Verify it against the source archive:

```bash
mkdir -p /tmp/cve-verify && cd /tmp/cve-verify
base=https://github.com/AronWang001/linux-cve-2026-98432-fix/releases/download/v1.2.0
curl -fsSLO "${base}/SHA256SUMS"
curl -fsSL -o src.tar.gz https://github.com/AronWang001/linux-cve-2026-98432-fix/archive/refs/tags/v1.2.0.tar.gz
tar -xzf src.tar.gz
cd linux-cve-2026-98432-fix-1.2.0
sha256sum -c ../SHA256SUMS
```

Every entry should report `OK`. The extracted directory name follows the repository name; adjust it if it differs. Where `sha256sum` is unavailable, use `shasum -a 256 -c ../SHA256SUMS`.

## Options and Exit Codes

### Options

| Option | Description |
| --- | --- |
| `-c`, `--check` | Read-only detection: no index refresh, no installation, no system changes |
| `-y`, `--yes` | Skip interactive confirmation; does not bypass the allowlist, advisory verification, or version checks |
| `--list-distros` | Print the support matrix: detection support, automatic remediation support, official patch status, and verification date. Does not require root |
| `--report [file]` | Write a detection report to the current directory as `cve-2026-98432-report-<timestamp>.txt` by default. The report contains no passwords, tokens, or private keys |
| `--no-color` | Disable colored output, for log collection |
| `-h`, `--help` | Show help |
| `-V`, `--version` | Show version information |

### Exit codes

| Status | Meaning | Exit code |
| --- | --- | --- |
| `FIXED` | The running kernel already meets the official fixed version | 0 |
| `PENDING_REBOOT` | The fixed kernel is installed but the old kernel is still running | 3 |
| `VULNERABLE_PATCH_AVAILABLE` | A fixed package is available and the running kernel is still affected | 2 |
| `PATCH_NOT_RELEASED` | No confirmed fixed package has been published; status only, nothing installed | 6 |
| `PATCH_TESTING_ONLY` | A fixed package exists only in a testing repository; production repositories do not have it, nothing installed | 7 |
| `UNKNOWN` | Advisory, kernel origin, package mapping, or version cannot be confirmed | 4 |
| `UNSUPPORTED` | System, release, architecture, or kernel flavor is not supported | 1 |
| Cancelled | The operator declined at the confirmation prompt; no changes made | 5 |
| Runtime error | Missing dependency, non-root invocation, invalid argument, installation or verification failure | 1 |

Installation runs only when the status is `VULNERABLE_PATCH_AVAILABLE`, the adapter permits automatic remediation, and the baseline record has `autofix: yes`. Exit code 1 covers both unsupported environments and runtime errors; the printed assessment distinguishes the two.

### Re-check after reboot

After the kernel is installed, the running kernel is still the old one, so a reboot is required:

```bash
sudo reboot
```

Run `--check` again after the reboot. The remediation is complete only when the result is `FIXED`. If the result is still `PENDING_REBOOT`, or the old kernel is still running, inspect the bootloader default entry, `grubenv`, and any cloud provider boot configuration.

## Supported Distributions

The baseline was last verified on 2026-11-01. Entries come from official advisories and security trackers, are reviewed manually, and are stored in `data/cve-2026-98432.yml`. This is not a live feed. Run `sudo bash fix.sh --list-distros` to see what the installed tool reports; `bash fix.sh --list-distros` also works as an unprivileged user.

### Automatic detection and remediation

| Distribution | Kernel branch | Kernel package | Fixed version | Advisory |
| --- | --- | --- | --- | --- |
| Debian 12 (bookworm) | 6.1 | `linux-image-amd64` and related meta packages | `6.1.190-1` | [DLA-4841-1](https://security-tracker.debian.org/tracker/DLA-4841-1) |
| Debian 12 (bookworm) | 6.12 | `linux-image-6.12-amd64` | `6.12.113-1~deb12u1` | [DLA-4850-1](https://security-tracker.debian.org/tracker/DLA-4850-1) |
| Debian 13 (trixie) | 6.12 | `linux-image-amd64` and related meta packages | `6.12.113-1` | [DSA-6568-1](https://security-tracker.debian.org/tracker/DSA-6568-1) |
| Amazon Linux 2 | 4.14 | `kernel` | `4.14.355-287.758.amzn2` | [ALAS2-2026-4065](https://alas.aws.amazon.com/AL2/ALAS2-2026-4065.html) |
| Amazon Linux 2 | 5.4 | `kernel` | `5.4.302-229.503.amzn2` | [ALAS2KERNEL-5.4-2026-135](https://alas.aws.amazon.com/AL2/ALAS2KERNEL-5.4-2026-135.html) |
| Amazon Linux 2 | 5.10 | `kernel` | `5.10.271-272.1121.amzn2` | [ALAS2KERNEL-5.10-2026-137](https://alas.aws.amazon.com/AL2/ALAS2KERNEL-5.10-2026-137.html) |
| Amazon Linux 2 | 5.15 | `kernel` | `5.15.222-158.256.amzn2` | [ALAS2KERNEL-5.15-2026-120](https://alas.aws.amazon.com/AL2/ALAS2KERNEL-5.15-2026-120.html) |
| Amazon Linux 2023 | 6.1 | `kernel` | `6.1.189-236.400.amzn2023` | [ALAS2023-2026-3365](https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3365.html) |
| Amazon Linux 2023 | 6.12 | `kernel6.12` | `6.12.113-138.209.amzn2023` | [ALAS2023-2026-3335](https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3335.html) |
| Amazon Linux 2023 | 6.18 | `kernel6.18` | `6.18.56-125.164.amzn2023` | [ALAS2023-2026-3251](https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3251.html) |

Debian 12 uses `6.12.113-1~deb12u1`, a backport that must not be confused with `6.12.113-1` on Debian 13. All four Amazon Linux 2 branches ship a package named `kernel`, so they are distinguished by full EVR. On Amazon Linux 2023, 6.12 and 6.18 are separate packages, `kernel6.12` and `kernel6.18`, with independent baselines.

### Fixed packages published, detection only

For the distributions below, the official fixed packages exist and the tool reports the exact version and repository channel. Automatic remediation stays disabled because the install-and-reboot path has not been validated on a real virtual machine.

| Distribution | Kernel branch | Kernel package | Fixed version | Advisory / patch | Status |
| --- | --- | --- | --- | --- | --- |
| Oracle Linux 8 (UEKR7) | 5.15 | `kernel-uek` | `5.15.0-325.221.6.4.el8uek` | [ELSA-2026-500398](https://linux.oracle.com/errata/ELSA-2026-500398.html) | Detection only |
| Oracle Linux 9 (UEKR7) | 5.15 | `kernel-uek` | `5.15.0-325.221.6.4.el9uek` | [ELSA-2026-500398](https://linux.oracle.com/errata/ELSA-2026-500398.html) | Detection only |
| Oracle Linux 8 (UEKR6) | 5.4 | `kernel-uek` | `5.4.17-2136.360.3.1.el8uek` | [ELSA-2026-500397](https://linux.oracle.com/errata/ELSA-2026-500397.html) | Detection only |
| Oracle Linux 7 (UEKR6) | 5.4 | `kernel-uek` | `5.4.17-2136.360.3.1.el7uek` | [ELSA-2026-500397](https://linux.oracle.com/errata/ELSA-2026-500397.html) | Detection only, ELS subscription required |
| Oracle Linux 9 (UEKR8) | 6.12 | `kernel-uek` | `6.12.0-207.111.5.4.el9uek` | [ELSA-2026-500399](https://linux.oracle.com/errata/ELSA-2026-500399.html) | Detection only |
| Oracle Linux 10 (UEKR8) | 6.12 | `kernel-uek` | `6.12.0-207.111.5.4.el10uek` | [ELSA-2026-500399](https://linux.oracle.com/errata/ELSA-2026-500399.html) | Detection only |
| openSUSE Leap 16.0 | 6.12 | `kernel-default` | `6.12.0-160000.40.1` | openSUSE-Leap-16.0-1973 | Detection only |
| SLES 16.0 | 6.12 | `kernel-default` | `6.12.0-160000.40.1` | SUSE-SLES-16.0-1973 | Detection only |
| SLES 15 SP4-LTSS | 5.14 | `kernel-default` | `5.14.21-150400.24.246.1` | SUSE-SLE-Product-SLES-15-SP4-LTSS-2026-4937 | Detection only, LTSS subscription required |
| SLES 15 SP5-LTSS | 5.14 | `kernel-default` | `5.14.21-150500.55.195.1` | SUSE-SLE-Product-SLES-15-SP5-LTSS-2026-4936 | Detection only, LTSS subscription required |
| SLES 15 SP6-LTSS | 6.4 | `kernel-default` | `6.4.0-150600.23.143.1` | SUSE-SLE-Product-SLES-15-SP6-LTSS-2026-4934 | Detection only, LTSS subscription required |
| SLES 15 SP7 | 6.4 | `kernel-default` | Conflicting official status, see below | SUSE CVE page | `UNKNOWN` |
| SLE Micro 6.2 | 6.12 | `kernel-default` | `6.12.0-160000.40.1` | SUSE-SL-Micro-6.2-1973 | Detection only, transactional updates |
| AlmaLinux 8 | 4.18 | `kernel` | `4.18.0-553.180.2.el8_10` (testing) | [AlmaLinux announcement](https://almalinux.org/blog/2026-10-30-cve-2026-98432/) | Testing repository only |
| AlmaLinux 9 | 5.14 | `kernel` | `5.14.0-687.61.2.el9_8` (testing) | [AlmaLinux announcement](https://almalinux.org/blog/2026-10-30-cve-2026-98432/) | Testing repository only |
| AlmaLinux 10 | 6.12 | `kernel` | `6.12.0-211.69.2.el10_2` (testing) | [AlmaLinux announcement](https://almalinux.org/blog/2026-10-30-cve-2026-98432/) | Testing repository only |

Notes:

- UEKR6, UEKR7, and UEKR8 are separate baselines on Oracle Linux. The `el7uek`, `el8uek`, `el9uek`, and `el10uek` suffixes are not interchangeable, and OL8 and OL9 each carry two generations at the same time; the tool selects by the running kernel branch. RHCK has no separate erratum and remains `UNKNOWN`.
- On SUSE, `kernel-default-base` has a longer EVR than `kernel-default` (for example `6.12.0-160000.40.1.160000.2.30` on SLES 16.0). Matching uses the installed package name, so the short EVR is never reused.
- The official SUSE "List of released packages" section lists `kernel-default >= 6.4.0-150700.53.90.1` for SLES 15 SP7, while the product status table still reports `In progress`. The tool treats that conflict as `UNKNOWN` rather than a published fix.
- AlmaLinux testing kernels require the `almalinux-testing` repository, which the tool never enables. The status is `PATCH_TESTING_ONLY` (exit code 7).
- Automatic remediation is `no` for every distribution in this table; `--yes` cannot override it.

### Detection only: no fixed package published

| Distribution | Official status | Advisory |
| --- | --- | --- |
| Ubuntu 20.04 LTS | Vulnerable, work in progress in 5.15.0-203.213 | [Ubuntu CVE](https://ubuntu.com/security/CVE-2026-98432) |
| Ubuntu 22.04 LTS | Vulnerable, work in progress in 5.15.0-203.213 | [Ubuntu CVE](https://ubuntu.com/security/CVE-2026-98432) |
| Ubuntu 24.04 LTS | Vulnerable, work in progress in 6.8.0-149.149 | [Ubuntu CVE](https://ubuntu.com/security/CVE-2026-98432) |
| RHEL 8 | kernel and kernel-rt both `Affected`, `affected_release` empty | [Red Hat CVE](https://access.redhat.com/security/cve/cve-2026-98432) |
| RHEL 9 | kernel and kernel-rt both `Affected`, `affected_release` empty | [Red Hat CVE](https://access.redhat.com/security/cve/cve-2026-98432) |
| RHEL 10 | kernel `Affected`, `affected_release` empty | [Red Hat CVE](https://access.redhat.com/security/cve/cve-2026-98432) |

The versions marked work in progress are in-development package versions, not published fixes, and are never used as a remediation baseline. These systems return `PATCH_NOT_RELEASED` (exit code 6) and no installation command is invoked.

### Identification only: status cannot be confirmed

| Distribution | Why automatic remediation is not enabled |
| --- | --- |
| Rocky Linux | The errata site is a front-end application; no machine-readable erratum for this CVE was obtained. RHEL conclusions are not applied to Rocky Linux |
| Oracle Linux (RHCK) | Only UEK errata were published; RHCK has no separate advisory, and the UEK fixed version cannot be applied to it |
| Fedora Linux | Stable carries 7.2.13/7.2.14, but the official build records were not checked for upstream commit `26d4c36` |
| Arch Linux | Core ships 7.2.11, above the upstream 7.2.10 fix point, but the packaging source was not reviewed; security updates normally require a full `pacman -Syu` |
| Alpine Linux | No record in secdb, and `linux-lts`, `linux-virt`, and `linux-edge` cannot be treated as interchangeable |

These systems report distribution, release, architecture, running kernel, the corresponding kernel package, and the advisory entry point. The status is `UNKNOWN` (exit code 4) and the installation path is never reached.

### Unsupported cases

| Case | Behavior |
| --- | --- |
| Distribution not covered | `UNSUPPORTED`, exit code 1, no changes made |
| Release outside the adapter's range (for example Debian 11 or Ubuntu 18.04) | `UNSUPPORTED`, exit code 1 |
| Architecture not allowed on a remediation-capable distribution | `UNSUPPORTED`, exit code 1, for example arm64 on Debian |
| Container environment | `UNKNOWN`, exit code 4. `uname -r` inside a container reports the host kernel and cannot be used for assessment |
| Self-built or third-party kernel | `UNKNOWN`, exit code 4 |

## Detection and Remediation

### Assessment steps

1. Parse `/etc/os-release` and distribution-specific signals to determine distribution, release, and kernel flavor.
2. Normalize the architecture and cross-check it against the package manager's reported architecture.
3. Map the running kernel to the installed kernel package and read its version.
4. Look up the matching verified record in `data/cve-2026-98432.yml` to obtain the fixed version, advisory identifier, and whether automatic remediation is permitted.
5. Compare the running kernel with the fixed version using the package manager's version semantics and emit one of seven statuses.

### Remediation steps

1. Print the current system, running kernel, assessment result, and advisory evidence.
2. Print the package to be installed, target version, repository, and expected changes.
3. Wait for confirmation; `--yes` skips this step.
4. Refresh package manager metadata (`apt-get update`, `dnf makecache`, or `yum makecache`).
5. Re-validate the candidate version, requiring the same branch and a version at or above the fixed baseline.
6. Install kernel-related packages only; no full system upgrade.
7. Query the package database again to confirm the version and kernel image actually installed.
8. Verify the initramfs (`/boot/initrd.img-*` or `/boot/initramfs-*.img`).
9. Detect the bootloader in use (GRUB, GRUB2, or systemd-boot) and check that a boot entry contains the new kernel.
10. Print the reboot instructions. The tool never reboots the host.

A package manager exit status of 0 is not treated as success. The run ends with exit code 1 and prints the manual command when the package database or kernel image check fails, the initramfs is missing, or no boot entry contains the new kernel and the configuration cannot be regenerated automatically. If no bootloader configuration is found at all, the tool only warns; confirm the boot entry yourself before rebooting.

### Safety considerations

What the tool does not do:

- It uses only the distribution's official repositories or repositories the operator has already configured. It does not add third-party repositories and does not build kernels.
- It does not remove old kernels, does not perform full system upgrades, and does not reboot.
- It does not modify SSH, firewall, network, proxy, or application configuration.
- On RPM-based systems it does not rebuild the boot configuration; if a boot entry is missing it stops and prints the manual command.
- `--check` leaves the system unchanged; `--report` additionally writes one report file whose fields come from an allowlist and contain no credentials.

Before you run it:

- The one-command form downloads and executes a remote script as root. The script comes from the GitHub repository and release assets over HTTPS, but it is not code-signed. Review it before running it in production.
- Kernel updates require a reboot and interrupt running services. Schedule them in a maintenance window. In production, run `--check` on an equivalently configured test machine and complete one real upgrade before rolling out.
- Installing the fixed kernel does not fix the running system. Remediation is complete only after booting the new kernel and re-checking for `FIXED`.
- The baseline is maintained manually. If an official advisory differs from the baseline, the advisory takes precedence; wait for a baseline update before running the tool.

## Testing

### Test suites

| Suite | Cases | Coverage |
| --- | --- | --- |
| `tests/test.sh` | 26 | Debian regression: environment detection, status assessment, index refresh and install failures, initramfs and bootloader failures, `--check`, operator cancellation, full installation, backport branch, version comparison, static checks |
| `tests/test_detection.sh` | 16 | Ubuntu 20.04/22.04/24.04, RHEL 8/9/10, Rocky vs AlmaLinux, Oracle UEK vs RHCK, AL2 vs AL2023, Fedora/SUSE/Arch/Alpine identification, x86_64 and aarch64, architecture rejection, no install when no fix exists, unreachable advisory, missing baseline, container environment, empty APT index, `--list-distros` and `--report` |
| `tests/test_amazon_linux.sh` | 11 | Independent baselines for AL2 4.14/5.10/5.15 and AL2023 6.1/6.12/6.18, full installation, dnf failure, missing initramfs, operator cancellation |
| `tests/test_version.sh` | 5 | RPM EVR (epoch, release, `~`), apk revision and suffixes, pacman, dpkg backport versions, unknown version families |
| `tests/test_safety.sh` | 8 | No installation on non-allowlisted distributions even with `--yes`, `--check` is read-only, `--report` has no side effects, adapter capability declarations are complete, allowlist minimality, static scan |
| `tests/test_new_distros.sh` | 14 | Oracle UEKR6/R7/R8 and RHCK rejection, SUSE product/service pack/flavor matching, SP7 status conflict, SLE Micro transactional updates, AlmaLinux testing and `--yes` cannot bypass |
| `tests/test_baseline.sh` | 7 | Baseline static checks: unique IDs and combination keys, complete EVR and advisory, no wildcard `fixed` records, evidence for `autofix=yes` |
| `tests/test_installer.sh` | 7 | Whole-archive verification: hash mismatch, missing manifest entry, path traversal, unsafe archive member, clean manifest passes |

94 cases in total.

### Test environments

- Local: Windows with Git Bash. A fake root is assembled and mock implementations of `dpkg`, `apt-get`, `rpm`, `dnf`, `yum`, `apk`, `pacman`, and `uname` are injected.
- CI: GitHub Actions runs the eight suites plus ShellCheck 0.11.0 (`-S style -x`), and a read-only identification smoke job across 12 distribution containers.
- Container smoke coverage: Debian 12/13, Ubuntu 22.04/24.04, Rocky Linux 9, AlmaLinux 9, Fedora, openSUSE Leap 15.6, Alpine 3.20, Arch Linux, Amazon Linux 2/2023.

### What the tests do not cover

The suites validate assessment logic, installation flow, and failure handling against mocked package manager output; they do not install a real kernel. The container smoke jobs verify distribution identification and the container refusal path (`UNKNOWN`) only. They do not verify kernel upgrades, initramfs generation, boot entry updates, or behavior after reboot. The Amazon Linux flow has not been exercised end to end on a real AWS instance.

## Known Limitations

1. Automatic remediation covers Debian 12/13 and Amazon Linux 2/2023 only. Oracle Linux UEK, SUSE/openSUSE, and AlmaLinux are detection-only; every baseline record for them has `autofix: no`.
2. The new Oracle Linux, SUSE/openSUSE, and AlmaLinux baselines have not been validated on a real virtual machine through install, boot entry inspection, reboot, and a re-check that returns `FIXED`. Container and mocked tests are not a substitute, so remediation stays disabled.
3. The Oracle Linux 7 UEKR6 fixed package is published in the `ol7_x86_64_UEKR6_ELS` channel and requires an active ELS subscription. The tool does not evaluate subscription state; it only reports the official EVR and channel.
4. SUSE LTSS baselines require the corresponding subscription and repository entitlement. `kernel-default`, `kernel-default-base`, `kernel-azure`, `kernel-rt`, `kernel-64kb`, and `kernel-kvmsmall` are tracked separately; flavors without a record return `UNKNOWN`.
5. The SUSE page for SLES 15 SP7 lists fixed packages while the product status table still says `In progress`. The tool treats this as `UNKNOWN`.
6. AlmaLinux 8/9/10 fixed kernels exist only in the testing repository. The tool never enables `almalinux-testing` and never installs testing kernels.
7. Amazon Linux kernel installation has not been performed on a real AWS instance. Its `dnf`/`yum` flow, post-reboot effect, and boot behavior are covered by mocked tests.
8. Debian is supported on amd64 only. Remediation support for other distributions follows the support matrix.
9. Container environments are not assessed and return `UNKNOWN`.
10. Self-built or third-party kernels cannot be mapped to a distribution package and return `UNKNOWN`.
11. Amazon Linux `kernel-livepatch` is out of scope; remediation means booting into the new kernel.
12. On RPM-based and SUSE systems the tool does not rebuild the boot configuration. If a boot entry is missing it stops and prints the manual command.
13. Distribution derivatives do not inherit conclusions. Rocky Linux, AlmaLinux, and Oracle Linux never use RHEL results, and RHCK never uses UEK results.
14. Baseline updates are committed manually after checking official advisories. The tool does not fetch advisories at runtime.

## Troubleshooting

| Symptom | Cause | Action |
| --- | --- | --- |
| `UNKNOWN`, with a message that the running kernel cannot be mapped to an installed kernel package | Self-built kernel, third-party kernel, or execution inside a container | Use the distribution kernel; run container checks on the host |
| `UNSUPPORTED`, with a message that the distribution or release is not covered | Distribution not covered, or release outside the adapter range | Handle manually per the official advisory, or use `--list-distros` to see the supported range |
| `PATCH_NOT_RELEASED` | No fixed package published yet | Monitor the advisory, update the baseline after publication, and re-run |
| Message that no kernel package meeting the version requirement exists in the repositories | Security repository disabled or index out of date | Check the official repository configuration, run `apt-get update` or `dnf makecache`, and retry |
| `apt-get update` failed | Network or repository configuration problem | Check connectivity and `/etc/apt/sources.list` as indicated |
| No valid initramfs found | The kernel package post-install script did not complete | Run `update-initramfs -c -k <release>` as indicated; on RPM-based systems run `dracut -f` |
| New kernel not present in the boot configuration | Boot configuration not updated | Debian retries `update-grub` automatically; on RPM-based systems run `grub2-mkconfig` as indicated |
| Message that root privileges are required | Not run with sudo | Run `sudo bash fix.sh` |
| `--check` reports the candidate version as unknown | Local package index is empty and `--check` does not refresh it | Run `apt-get update` or `dnf makecache` first, or run the remediation flow directly |

## Updating the Baseline

1. Open the relevant official advisory (Debian Security Tracker, ALAS, Ubuntu, Red Hat, and so on).
2. Confirm the kernel package name, EVR, repository channel, and architecture.
3. Update `fixed_version`, `advisory`, `advisory_url`, `verified`, and `notes` for the matching record in `data/cve-2026-98432.yml`.
4. Change `autofix` to `yes` only after adaptation and testing are complete.
5. Run the full test suite and update `CHANGELOG.md`.

## Project Layout

```
install.sh                  Bootstrap installer: downloads the tagged archive, verifies fix.sh SHA256, runs fix.sh
fix.sh                      Entry point: argument parsing, flow orchestration, state machine exit
lib/
  common.sh                 Exit codes, colors, logging, paths, container detection
  detect.sh                 Distribution, release, architecture, and kernel detection
  version.sh                dpkg, rpm, apk, and pacman version comparison
  advisory.sh               Baseline loading and lookup
  kernel.sh                 Running kernel to package mapping
  package_manager.sh        apt, dnf, yum abstraction
  install.sh                Plan output, installation, post-install verification, reboot notice
  status.sh                 Seven-state machine
  report.sh                 --list-distros and --report
adapters/                   11 distribution adapters declaring identity, release range, and capabilities
data/cve-2026-98432.yml     Verified official remediation baseline
tests/                      8 test suites, mocks, and the container smoke script
```

## License

MIT. See [LICENSE](LICENSE).
