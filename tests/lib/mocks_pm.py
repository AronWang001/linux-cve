#!/usr/bin/env python3
"""rpm / dnf / yum / apk / pacman 的最小模拟实现。

只实现 fix.sh 实际用到的调用，状态来自 MOCK_ROOT：
  installed.tsv : name<TAB>version<TAB>release（rpm）
                  name<TAB>version（apk / pacman）
  available.tsv : name<TAB>EVR
  flags/<name>  : 存在即触发对应故障
  uname_r/uname_m, rpm_arch
"""

import os
import sys


def root():
    return os.environ.get("MOCK_ROOT", ".")


def sysroot():
    """假根目录（fix.sh 的实际文件系统视图，由 FIX_SYSROOT 指定）。"""
    value = os.environ.get("FIX_SYSROOT", "")
    return value.rstrip("/") if value else root()


def path(*parts):
    return os.path.join(root(), *parts)


def read_tsv(name):
    target = path(name)
    if not os.path.exists(target):
        return []
    rows = []
    with open(target, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n").rstrip("\r")
            if not line:
                continue
            rows.append(line.split("\t"))
    return rows


def write_tsv(name, rows):
    with open(path(name), "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write("\t".join(row) + "\n")


def flag(name):
    return os.path.exists(path("flags", name))


def mark(name):
    os.makedirs(path("calls"), exist_ok=True)
    with open(path("calls", name), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("1\n")


def arch():
    target = path("rpm_arch")
    if os.path.exists(target):
        with open(target, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    return "x86_64"


def rpm_rows():
    rows = []
    for row in read_tsv("installed.tsv"):
        if len(row) >= 3:
            rows.append((row[0], row[1], row[2]))
    return rows


def unescape(text):
    return text.replace("\\n", "\n").replace("\\t", "\t")


def rpm_expand(fmt, name, version, release):
    return unescape(
        fmt.replace("%{NAME}", name)
        .replace("%{VERSION}", version)
        .replace("%{RELEASE}", release)
        .replace("%{ARCH}", arch())
        .replace("%{EPOCH}", "(none)")
    )


def cmd_rpm(argv):
    if "--eval" in argv:
        index = argv.index("--eval")
        expr = argv[index + 1] if index + 1 < len(argv) else ""
        sys.stdout.write(expr.replace("%{_arch}", arch()) + "\n")
        return 0

    if "-qa" in argv:
        fmt = "%{NAME}\t%{VERSION}\t%{RELEASE}\n"
        if "-q" in argv and "--qf" in argv:
            fmt = argv[argv.index("--qf") + 1]
        elif "--qf" in argv:
            fmt = argv[argv.index("--qf") + 1]
        for name, version, release in rpm_rows():
            sys.stdout.write(rpm_expand(fmt, name, version, release))
        return 0

    if "-q" in argv:
        targets = [a for a in argv[1:] if not a.startswith("-")]
        if not targets:
            return 1
        name = targets[0]
        for pkg, version, release in rpm_rows():
            if pkg == name:
                sys.stdout.write("%s-%s-%s.%s\n" % (pkg, version, release, arch()))
                return 0
        return 1

    return 1


VALUE_OPTS = {
    "--qf",
    "--queryformat",
    "--latest-limit",
    "--repoid",
    "--enablerepo",
    "--disablerepo",
    "--setopt",
    "-c",
    "--config",
    "--releasever",
    "--arch",
}


def positional(args):
    """从参数列表中取出位置参数，跳过选项及其取值。

    例如 repoquery --available --latest-limit 1 --qf '%{...}' kernel
    位置参数应为 ['kernel']，而不是 ['1', '%{...}', 'kernel']。
    """
    result = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in VALUE_OPTS:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        result.append(arg)
    return result


def cmd_dnf(argv):
    args = [a for a in argv if a not in ("-q", "-y", "--quiet")]
    if not args:
        return 2

    if args[0] == "makecache":
        mark("dnf_makecache")
        if flag("dnf_makecache_fail"):
            sys.stderr.write("Error: Failed to download metadata for repo 'amazonlinux'\n")
            return 1
        return 0

    if args[0] == "repoquery":
        qf = "%{epoch}:%{version}-%{release}"
        if "--qf" in args:
            qf = args[args.index("--qf") + 1]
        targets = [a for a in positional(args[1:]) if not a.startswith("%")]
        if not targets:
            return 1
        avail = {row[0]: row[1] for row in read_tsv("available.tsv") if len(row) >= 2}
        name = targets[0]
        for candidate in targets:
            if candidate in avail:
                name = candidate
                break
        best = avail.get(name)
        if best is None:
            return 1
        rendered = (
            qf.replace("%{epoch}", "0")
            .replace("%{version}", best.rsplit("-", 1)[0])
            .replace("%{release}", best.rsplit("-", 1)[-1])
            .replace("%{repoid}", "amazonlinux")
        )
        sys.stdout.write(unescape(rendered) + "\n")
        return 0

    if args[0] in ("install", "update", "upgrade"):
        mark("dnf_" + args[0])
        if flag("dnf_install_fail"):
            sys.stderr.write("Error: Transaction test error:\n")
            sys.stderr.write("  package %s conflicts\n" % " ".join(args[1:]))
            return 1
        specs = [a for a in args[1:] if not a.startswith("-")]
        if not specs:
            return 1
        spec = specs[0]
        avail = {row[0]: row[1] for row in read_tsv("available.tsv") if len(row) >= 2}
        installed = {row[0]: (row[1], row[2]) for row in rpm_rows()}

        target = None
        for name, evr in avail.items():
            if spec == "%s-%s" % (name, evr):
                target = (name, evr)
                break
        if target is None and spec in avail:
            target = (spec, avail[spec])
        if target is None and spec in installed:
            return 0
        if target is None:
            sys.stderr.write("Error: Unable to find a match: %s\n" % spec)
            return 1

        name, evr = target
        if "-" not in evr:
            sys.stderr.write("Error: bad EVR %s\n" % evr)
            return 1
        version, release = evr.rsplit("-", 1)
        rows = [r for r in rpm_rows() if r[0] != name]
        rows.append((name, version, release))
        write_tsv("installed.tsv", [list(r) for r in rows])

        boot = sysroot() + "/boot"
        os.makedirs(boot, exist_ok=True)
        with open(os.path.join(boot, "vmlinuz-%s.%s" % (evr, arch())), "w", encoding="utf-8", newline="\n") as handle:
            handle.write("mock kernel\n")
        if not flag("skip_initramfs"):
            with open(os.path.join(boot, "initramfs-%s.%s.img" % (evr, arch())), "w", encoding="utf-8", newline="\n") as handle:
                handle.write("mock initramfs\n")
        if not flag("skip_grub_entry"):
            cfg = os.path.join(boot, "grub2", "grub.cfg")
            os.makedirs(os.path.dirname(cfg), exist_ok=True)
            with open(cfg, "a", encoding="utf-8", newline="\n") as handle:
                handle.write("\tmenuentry 'Amazon Linux %s' {}\n" % evr)
        sys.stdout.write("Installed: %s-%s\n" % (name, evr))
        return 0

    sys.stderr.write("mock dnf: unsupported %s\n" % args[0])
    return 2


def cmd_yum(argv):
    args = [a for a in argv if a not in ("-q", "-y")]
    if not args:
        return 2
    if args[0] == "makecache":
        mark("yum_makecache")
        if flag("dnf_makecache_fail"):
            sys.stderr.write("Error: Failed to download metadata\n")
            return 1
        return 0
    if "--showduplicates" in argv or args[0] == "list":
        targets = [a for a in positional(args) if a not in ("list", "available", "installed")]
        if not targets:
            for row in read_tsv("available.tsv"):
                if len(row) >= 2:
                    sys.stdout.write("%s.x86_64  %s  amzn2-core\n" % (row[0], row[1]))
            return 0
        name = targets[0]
        for row in read_tsv("available.tsv"):
            if len(row) >= 2 and row[0] == name:
                sys.stdout.write("%s.x86_64  %s  amzn2-core\n" % (row[0], row[1]))
        return 0
    if args[0] in ("install", "update"):
        return cmd_dnf([args[0]] + args[1:])
    return 2


def apk_rows():
    rows = []
    for row in read_tsv("installed.tsv"):
        if len(row) >= 2:
            rows.append((row[0], row[1]))
    return rows


def cmd_apk(argv):
    if not argv:
        return 2
    if argv[0] == "info":
        if "-e" in argv:
            targets = [a for a in argv[1:] if not a.startswith("-")]
            names = {r[0] for r in apk_rows()}
            return 0 if targets and targets[0] in names else 1
        if "-v" in argv:
            targets = [a for a in argv[1:] if not a.startswith("-")]
            for name, version in apk_rows():
                if not targets or targets[0] == name:
                    sys.stdout.write("%s-%s\n" % (name, version))
            return 0
    return 2


def cmd_pacman(argv):
    if not argv:
        return 2
    if argv[0] == "-Q":
        targets = [a for a in argv[1:] if not a.startswith("-")]
        names = {r[0] for r in apk_rows()}
        if not targets:
            for name, version in apk_rows():
                sys.stdout.write("%s %s\n" % (name, version))
            return 0
        for name, version in apk_rows():
            if name == targets[0]:
                sys.stdout.write("%s %s\n" % (name, version))
                return 0
        return 1
    return 2


def main():
    if len(sys.argv) < 2:
        return 2
    prog = sys.argv[1]
    argv = sys.argv[2:]
    handlers = {
        "rpm": cmd_rpm,
        "dnf": cmd_dnf,
        "yum": cmd_yum,
        "apk": cmd_apk,
        "pacman": cmd_pacman,
    }
    handler = handlers.get(prog)
    if handler is None:
        sys.stderr.write("mock: unsupported program %s\n" % prog)
        return 2
    return handler(argv)


if __name__ == "__main__":
    sys.exit(main())
