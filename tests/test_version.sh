#!/usr/bin/env bash
#
# tests/test_version.sh - 版本比较边界
#
# 不同发行版必须使用各自的包管理器语义：
#   rpm    -> epoch:version-release（rpmvercmp）
#   apk    -> -rN 修订号 + _alpha/_beta/_pre/_rc/_p 后缀
#   pacman -> pkgver-pkgrel
#   debian -> dpkg --compare-versions

# shellcheck disable=SC2016
set -uo pipefail

# shellcheck source=tests/lib/harness.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/harness.sh"

h_init "版本比较边界测试"

run_snippet() {
    local snippet="$1"
    OUT="$(
        PATH="${MOCKBIN_POSIX}:${PATH}" bash -c "source '${FIX_SH}'; set +e; ${snippet}" 2>&1
    )"
    RC=$?
}

CMP_HELPER='
check() {
    local fam="$1" a="$2" b="$3" want="$4" got
    got="$(vercmp_family "$fam" "$a" "$b")"
    if [[ "$got" != "$want" ]]; then
        printf "FAIL %s [%s] vs [%s] want=%s got=%s\n" "$fam" "$a" "$b" "$want" "$got"
    fi
}
'

begin_case "V1. RPM EVR 比较（epoch / release / 波浪号 / 数值段）"
run_snippet "${CMP_HELPER}
check rpm '1.0-1' '1.0-1' 0
check rpm '1.0-2' '1.0-1' 1
check rpm '1.0-1' '1.0-2' -1
check rpm '1:1.0-1' '2.0-1' 1
check rpm '2.0-1' '1:0.9-1' -1
check rpm '5.14.0-427.13.1.el9_4' '5.14.0-427.9.1.el9_4' 1
check rpm '6.1.189-236.400.amzn2023' '6.1.189-236.399.amzn2023' 1
check rpm '1.0~rc1-1' '1.0-1' -1
check rpm '1.0-1~beta' '1.0-1' -1
check rpm '2.0-1' '10.0-1' -1
check rpm '6.12.113-138.209.amzn2023' '6.12.113-138.209.amzn2023' 0
echo DONE"
assert_rc 0
assert_has "DONE"
assert_lacks "FAIL"
end_case

begin_case "V2. apk 版本比较（修订号与后缀）"
run_snippet "${CMP_HELPER}
check alpine '1.0-r0' '1.0-r1' -1
check alpine '1.0-r1' '1.0-r0' 1
check alpine '1.0_alpha1' '1.0' -1
check alpine '1.0_rc2' '1.0_rc1' 1
check alpine '1.0_p1' '1.0' 1
check alpine '6.6.44-r0' '6.6.44-r0' 0
check alpine '1.2.10-r0' '1.2.9-r0' 1
check alpine '1.2.3-r10' '1.2.3-r9' 1
echo DONE"
assert_rc 0
assert_has "DONE"
assert_lacks "FAIL"
end_case

begin_case "V3. pacman 版本比较（pkgver-pkgrel）"
run_snippet "${CMP_HELPER}
check arch '6.12.10.arch1-1' '6.12.10.arch1-1' 0
check arch '6.12.11.arch1-1' '6.12.10.arch1-1' 1
check arch '6.12.10.arch1-2' '6.12.10.arch1-1' 1
check arch '6.9.1.arch1-1' '6.12.10.arch1-1' -1
check arch '6.12.10.arch1-1' '6.12.10.arch1-2' -1
echo DONE"
assert_rc 0
assert_has "DONE"
assert_lacks "FAIL"
end_case

begin_case "V4. Debian 版本比较（epoch / 回移）"
run_snippet 'check() { version_ge "$1" "$2" && echo "GE $1 $2" || echo "LT $1 $2"; }
check "1:1.0-1" "2.0-1"
check "6.12.113-1~deb12u1" "6.12.113-1"
check "6.1.190-1+deb12u1" "6.1.190-1"
check "6.1.174-1" "6.1.190-1"
echo DONE'
assert_rc 0
assert_has "GE 1:1.0-1 2.0-1"
assert_has "LT 6.12.113-1~deb12u1 6.12.113-1"
assert_has "GE 6.1.190-1+deb12u1 6.1.190-1"
assert_has "LT 6.1.174-1 6.1.190-1"
end_case

begin_case "V5. 未知包管理家族不得使用通用字符串比较"
run_snippet 'if vercmp_family gentoo "1.0" "2.0" >/dev/null; then echo "accept"; else echo "unsupported"; fi'
assert_rc 0
assert_has "unsupported"
end_case

finish_suite
