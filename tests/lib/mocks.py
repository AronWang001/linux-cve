#!/usr/bin/env python3
"""Debian 环境模拟器：为 fix.sh 的自动化测试提供 dpkg / apt 行为。

被 tests/test.sh 以 `python mocks.py <prog> [args...]` 形式调用。
状态目录由环境变量 MOCK_ROOT 指定，文件系统根由 FIX_SYSROOT 指定。

状态文件：
  installed.tsv   pkg<TAB>version<TAB>status
  available.tsv   pkg<TAB>version（APT 可见的候选版本）
  deps.tsv        metapkg<TAB>imagepkg<TAB>imageversion<TAB>release
  grub_exclude.txt  每行一个不应写入 grub.cfg 的 release

开关文件（存在即生效）：
  flags/apt_update_fail      apt-get update 失败
  flags/apt_install_fail     apt-get install 失败
  flags/skip_initramfs       不生成 initrd
  flags/skip_grub_entry      安装时不写入 grub 条目
  flags/grub_fail            update-grub 失败
  flags/no_apt_lists         不生成 APT 索引元数据

标记文件（用于断言）：
  calls/apt_update           调用过 apt-get update
  calls/apt_install          调用过 apt-get install
"""

import os
import re
import sys


def state_path(*parts):
    return os.path.join(os.environ["MOCK_ROOT"], *parts)


def read_tsv(name):
    rows = []
    path = state_path(name)
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if line:
                    rows.append(line.split("\t"))
    return rows


def write_tsv(name, rows):
    with open(state_path(name), "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write("\t".join(row) + "\n")


def flag(name):
    return os.path.exists(state_path("flags", name))


def mark(name):
    os.makedirs(state_path("calls"), exist_ok=True)
    with open(state_path("calls", name), "w", encoding="utf-8") as handle:
        handle.write("1\n")


# ---------------------------------------------------------------------------
# Debian 版本比较（与 dpkg 语义一致）
# ---------------------------------------------------------------------------

def _order(char):
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    if char == "~":
        return -1
    if char == "":
        return 0
    return ord(char) + 256


def _verrevcmp(left, right):
    i = j = 0
    while i < len(left) or j < len(right):
        first_diff = 0
        while (i < len(left) and not left[i].isdigit()) or (
            j < len(right) and not right[j].isdigit()
        ):
            lc = _order(left[i]) if i < len(left) else 0
            rc = _order(right[j]) if j < len(right) else 0
            if lc != rc:
                return lc - rc
            i += 1
            j += 1
        while i < len(left) and left[i] == "0":
            i += 1
        while j < len(right) and right[j] == "0":
            j += 1
        while (
            i < len(left)
            and j < len(right)
            and left[i].isdigit()
            and right[j].isdigit()
        ):
            if not first_diff:
                first_diff = ord(left[i]) - ord(right[j])
            i += 1
            j += 1
        if i < len(left) and left[i].isdigit():
            return 1
        if j < len(right) and right[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split(version):
    epoch = 0
    rest = version
    if ":" in rest:
        head, rest = rest.split(":", 1)
        epoch = int(head)
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream, revision = rest, ""
    return epoch, upstream, revision


def compare(left, right):
    le, lu, lr = _split(left)
    re_, ru, rr = _split(right)
    if le != re_:
        return -1 if le < re_ else 1
    result = _verrevcmp(lu, ru)
    if result != 0:
        return -1 if result < 0 else 1
    result = _verrevcmp(lr, rr)
    if result != 0:
        return -1 if result < 0 else 1
    return 0


# ---------------------------------------------------------------------------
# 状态访问
# ---------------------------------------------------------------------------

def installed():
    data = {}
    for row in read_tsv("installed.tsv"):
        if len(row) >= 3:
            data[row[0]] = (row[1], row[2])
    return data


def available():
    data = {}
    for row in read_tsv("available.tsv"):
        if len(row) >= 2:
            pkg, ver = row[0], row[1]
            if pkg not in data or compare(ver, data[pkg]) > 0:
                data[pkg] = ver
    return data


def deps():
    data = {}
    for row in read_tsv("deps.tsv"):
        if len(row) >= 4:
            data[row[0]] = (row[1], row[2], row[3])
    return data


def sysroot():
    return os.environ.get("FIX_SYSROOT", "").rstrip("/")


def root_file(rel_path):
    return sysroot() + rel_path


def write_boot_files(release, with_initramfs):
    for path in ("/boot/vmlinuz-" + release,):
        full = root_file(path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(b"\x7fELF mock kernel\n")
    if with_initramfs:
        full = root_file("/boot/initrd.img-" + release)
        with open(full, "wb") as handle:
            handle.write(b"mock initramfs\n")


def append_grub_entry(release):
    cfg = root_file("/boot/grub/grub.cfg")
    if not os.path.isfile(cfg):
        return
    with open(cfg, "a", encoding="utf-8") as handle:
        handle.write("\tmenuentry 'Debian GNU/Linux, kernel %s' {\n" % release)
        handle.write("\t\tlinux /boot/vmlinuz-%s root=/dev/sda1\n\t}\n" % release)


# ---------------------------------------------------------------------------
# dpkg
# ---------------------------------------------------------------------------

def cmd_dpkg(argv):
    if not argv:
        return 2
    if argv[0] == "--compare-versions":
        if len(argv) != 4:
            sys.stderr.write("dpkg: --compare-versions needs three arguments\n")
            return 2
        left, op, right = argv[1], argv[2], argv[3]
        result = compare(left, right)
        checks = {
            "lt": result < 0,
            "le": result <= 0,
            "eq": result == 0,
            "ne": result != 0,
            "ge": result >= 0,
            "gt": result > 0,
        }
        if op not in checks:
            sys.stderr.write("dpkg: unknown operator %s\n" % op)
            return 2
        return 0 if checks[op] else 1
    if argv[0] == "--print-architecture":
        sys.stdout.write("amd64\n")
        return 0
    if argv[0] in ("-S", "--search"):
        if len(argv) < 2:
            return 2
        target = argv[1]
        prefix = sysroot() + "/boot/vmlinuz-"
        for pkg in installed():
            if not pkg.startswith("linux-image-"):
                continue
            release = pkg[len("linux-image-"):]
            if target == prefix + release:
                sys.stdout.write("%s: %s\n" % (pkg, argv[1]))
                return 0
        sys.stderr.write("dpkg-query: no path found matching pattern %s\n" % target)
        return 1
    sys.stderr.write("mock dpkg: unsupported arguments: %s\n" % " ".join(argv))
    return 2


# ---------------------------------------------------------------------------
# dpkg-query
# ---------------------------------------------------------------------------

def _expand_format(fmt, pkg, version, status):
    status_abbrev = "ii " if status == "installed" else "rc "
    out = fmt
    out = out.replace("${Package}", pkg)
    out = out.replace("${Version}", version)
    out = out.replace("${db:Status-Abbrev}", status_abbrev)
    out = out.replace("${Status}", "install ok installed" if status == "installed" else "deinstall ok config-files")
    out = out.replace("\\n", "\n").replace("\\t", "\t")
    return out


def _match(pkg, patterns):
    import fnmatch

    for pattern in patterns:
        if fnmatch.fnmatchcase(pkg, pattern):
            return True
    return False


def cmd_dpkg_query(argv):
    fmt = "${Package}\t${Version}\n"
    patterns = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in ("-W", "--show"):
            index += 1
            continue
        if arg == "-f" or arg == "--showformat":
            fmt = argv[index + 1]
            index += 2
            continue
        if arg.startswith("-f=") or arg.startswith("--showformat="):
            fmt = arg.split("=", 1)[1]
            index += 1
            continue
        patterns.append(arg)
        index += 1

    data = installed()
    wildcard = any(any(ch in pattern for ch in "*?[") for pattern in patterns)
    matched = [pkg for pkg in sorted(data) if _match(pkg, patterns)]

    if not matched:
        if wildcard:
            return 0
        sys.stderr.write("dpkg-query: no packages found matching %s\n" % " ".join(patterns))
        return 1

    for pkg in matched:
        version, status = data[pkg]
        sys.stdout.write(_expand_format(fmt, pkg, version, status))
    return 0


# ---------------------------------------------------------------------------
# apt-cache
# ---------------------------------------------------------------------------

def cmd_apt_cache(argv):
    if argv and argv[0] == "policy":
        if len(argv) < 2:
            return 2
        pkg = argv[1]
        inst = installed().get(pkg)
        cand = available().get(pkg)
        sys.stdout.write("%s:\n" % pkg)
        sys.stdout.write("  Installed: %s\n" % (inst[0] if inst else "(none)"))
        sys.stdout.write("  Candidate: %s\n" % (cand if cand else "(none)"))
        sys.stdout.write("  Version table:\n")
        if cand:
            sys.stdout.write("     %s 500\n" % cand)
            sys.stdout.write("        500 https://security.debian.org/debian-security bookworm-security/main amd64 Packages\n")
        return 0
    if argv and argv[0] == "search":
        pattern = None
        idx = 1
        while idx < len(argv):
            if argv[idx] in ("--names-only", "-n"):
                idx += 1
                if idx < len(argv):
                    pattern = argv[idx]
                    idx += 1
                continue
            pattern = argv[idx]
            idx += 1
        if pattern is None:
            return 2
        for pkg in sorted(available()):
            if re.search(pattern, pkg):
                sys.stdout.write("%s - mock kernel package\n" % pkg)
        return 0
    return 2


# ---------------------------------------------------------------------------
# apt-get
# ---------------------------------------------------------------------------

def strip_options(args):
    """去掉 apt-get 的选项（含 -o KEY=VALUE 这种成对参数），返回位置参数。"""
    out = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("-o", "--option"):
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        out.append(arg)
        index += 1
    return out


def split_action(argv):
    positionals = strip_options(argv)
    if not positionals:
        return None, []
    return positionals[0], positionals[1:]


def cmd_apt_get(argv):
    action, rest = split_action(argv)
    if action is None:
        return 2
    if action == "update":
        mark("apt_update")
        if flag("apt_update_fail"):
            sys.stderr.write("Err:1 https://security.debian.org/debian-security bookworm-security InRelease\n")
            sys.stderr.write("  Temporary failure resolving 'security.debian.org'\n")
            sys.stderr.write("E: Failed to fetch some archives.\n")
            return 100
        sys.stdout.write("Hit:1 https://security.debian.org/debian-security bookworm-security InRelease\n")
        sys.stdout.write("Reading package lists... Done\n")
        return 0
    if action == "install":
        mark("apt_install")
        if flag("apt_install_fail"):
            sys.stderr.write("Reading package lists... Done\n")
            sys.stderr.write("E: Unable to correct problems, you have held broken packages.\n")
            return 100
        targets = rest
        if not targets:
            sys.stderr.write("E: no package specified\n")
            return 100
        data = installed()
        deps_map = deps()
        avail = available()
        for target in targets:
            if target in deps_map:
                pkg, version, release = deps_map[target]
            elif target in avail:
                pkg = target
                version = avail[target]
                release = pkg[len("linux-image-"):]
            else:
                sys.stderr.write("E: Unable to locate package %s\n" % target)
                return 100
            data[pkg] = (version, "installed")
            write_boot_files(release, with_initramfs=not flag("skip_initramfs"))
            if not flag("skip_grub_entry"):
                append_grub_entry(release)
            sys.stdout.write("Setting up %s (%s) ...\n" % (pkg, version))
        rows = [[pkg, ver, st] for pkg, (ver, st) in data.items()]
        write_tsv("installed.tsv", rows)
        return 0
    sys.stderr.write("mock apt-get: unsupported action %s\n" % action)
    return 2


# ---------------------------------------------------------------------------
# update-grub
# ---------------------------------------------------------------------------

def cmd_update_grub(argv):
    mark("update_grub")
    if flag("grub_fail"):
        sys.stderr.write("error: cannot find a device for / (is /dev mounted?).\n")
        return 1
    exclude = set()
    path = state_path("grub_exclude.txt")
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as handle:
            exclude = {line.strip() for line in handle if line.strip()}
    cfg = root_file("/boot/grub/grub.cfg")
    os.makedirs(os.path.dirname(cfg), exist_ok=True)
    with open(cfg, "w", encoding="utf-8") as handle:
        handle.write("### BEGIN /etc/grub.d/10_linux ###\n")
        for pkg in sorted(installed()):
            if not pkg.startswith("linux-image-"):
                continue
            release = pkg[len("linux-image-"):]
            if release in exclude:
                continue
            if not os.path.isfile(root_file("/boot/vmlinuz-" + release)):
                continue
            handle.write("\tmenuentry 'Debian GNU/Linux, kernel %s' {\n" % release)
            handle.write("\t\tlinux /boot/vmlinuz-%s root=/dev/sda1\n\t}\n" % release)
    sys.stdout.write("Generating grub configuration file ...\ndone\n")
    return 0


def main():
    if len(sys.argv) < 2:
        return 2
    prog = sys.argv[1]
    argv = sys.argv[2:]
    handlers = {
        "dpkg": cmd_dpkg,
        "dpkg-query": cmd_dpkg_query,
        "apt-cache": cmd_apt_cache,
        "apt-get": cmd_apt_get,
        "update-grub": cmd_update_grub,
    }
    handler = handlers.get(prog)
    if handler is None:
        sys.stderr.write("mock: unknown program %s\n" % prog)
        return 2
    return handler(argv)


if __name__ == "__main__":
    sys.exit(main())
