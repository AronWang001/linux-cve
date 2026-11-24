#!/usr/bin/env bash
# version_diff.sh — 原生版本比较差分测试
#
# 在对应 Linux 容器内，对同一组版本对，分别用：
#   1. Go 实现（tests/vercmp_probe.go，调用 internal/version.Compare）
#   2. 原生命令（dpkg / rpm / apk / pacman）
# 比较两者返回的符号是否一致（-1 / 0 / 1）。
#
# 用法：tests/version_diff.sh <dpkg|rpm|apk|pacman>
#   依赖：容器内已装对应包管理器，且 Go 工具链可用（CI 里用 setup-go）。
#
# 退出码：0 = 全部一致；1 = 存在符号不一致或工具缺失。
#
# 注意：本脚本只在 CI 的 Linux 容器中运行；本地 Windows 缺容器/原生命令时
# 标记为 BLOCKED，不得冒称通过。

set -euo pipefail

MANAGER="${1:-}"
CASES="${CASES:-tests/version_diff_cases.txt}"

case "$MANAGER" in
  dpkg)   NATIVE_PKG=dpkg ;;
  rpm)    NATIVE_PKG=rpm ;;
  apk)    NATIVE_PKG=apk ;;
  pacman) NATIVE_PKG=pacman ;;
  *)
    echo "用法: $0 <dpkg|rpm|apk|pacman>" >&2
    exit 2 ;;
esac

# 0) 前置检查：原生命令与 Go 工具链必须可用，缺失即 BLOCKED（退出码 1）
if ! command -v "$NATIVE_PKG" >/dev/null 2>&1; then
  echo "BLOCKED: 原生命令 $NATIVE_PKG 不存在，无法做差分测试" >&2
  exit 1
fi
if ! command -v go >/dev/null 2>&1; then
  echo "BLOCKED: Go 工具链不存在，无法编译探测程序" >&2
  exit 1
fi

# 1) 编译 Go 探测程序为临时二进制（比逐对 go run 快得多）
PROBE="$(mktemp)"
trap 'rm -f "$PROBE"' EXIT
go build -o "$PROBE" ./tests/vercmp_probe.go

# 2) 过滤出非注释用例，剥离 #DIFF 前缀
raw_cases() {
  grep -v '^#' "$CASES" | grep -v '^[[:space:]]*$' \
    | sed 's/^#DIFF[[:space:]]*//'
}

# 3) 原生符号归一为 -1/0/1
#    dpkg:  三次 --compare-versions 判定
#    rpm:   rpm.vercmp lua 输出 -1/0/1
#    apk:   apk version -t 输出 '<' '=' '>'
#    pacman: vercmp 输出 -1/0/1
native_sign() {
  local a="$1" b="$2"
  case "$MANAGER" in
    dpkg)
      if dpkg --compare-versions "$a" lt "$b"; then echo -1
      elif dpkg --compare-versions "$a" eq "$b"; then echo 0
      else echo 1; fi ;;
    rpm)
      rpm --eval "%{lua:print(rpm.vercmp('$a','$b'))}" ;;
    apk)
      local r
      r="$(apk version -t "$a" "$b" 2>/dev/null || true)"
      case "$r" in
        '<') echo -1 ;; '=') echo 0 ;; '>') echo 1 ;; *) echo "ERR:$r" ;; esac ;;
    pacman)
      vercmp "$a" "$b" ;;
  esac
}

# 4) 逐对比较
#
# 用例两种形态：
#   a<TAB>b                  普通用例，比较 Go 与原生的符号
#   !管理器<TAB>a<TAB>b      非法输入，仅在该管理器下断言 Go 报 ERR
fail=0
count=0
while IFS= read -r line; do
  [ -n "$line" ] || continue

  case "$line" in
    \!*)
      want_mgr="${line%%$'\t'*}"
      want_mgr="${want_mgr#!}"
      rest="${line#*$'\t'}"
      a="${rest%%$'\t'*}"
      b="${rest#*$'\t'}"
      if [ "$want_mgr" != "$MANAGER" ]; then
        continue
      fi
      count=$((count+1))
      go_sign="$("$PROBE" "$MANAGER" <<< "$(printf '%s\t%s\n' "$a" "$b")" | awk '{print $1}')"
      if [ "$go_sign" != "ERR" ]; then
        echo "MISMATCH(非法版本应报 ERR，实际 $go_sign): $a vs $b"
        fail=1
      fi
      continue
      ;;
  esac

  # @管理器[,管理器]：只在这些管理器下比较语法专有的用例
  case "$line" in
    @*)
      want_mgrs="${line%%$'\t'*}"
      want_mgrs="${want_mgrs#@}"
      rest="${line#*$'\t'}"
      a="${rest%%$'\t'*}"
      b="${rest#*$'\t'}"
      hit=0
      old_ifs="$IFS"; IFS=','
      for mm in $want_mgrs; do
        [ "$mm" = "$MANAGER" ] && hit=1
      done
      IFS="$old_ifs"
      [ "$hit" -eq 1 ] || continue
      ;;
    *)
      a="${line%%$'\t'*}"
      b="${line#*$'\t'}"
      ;;
  esac
  a="$(printf '%s' "$a" | xargs)"
  b="$(printf '%s' "$b" | xargs)"

  go_sign="$("$PROBE" "$MANAGER" <<< "$(printf '%s\t%s\n' "$a" "$b")" | awk '{print $1}')"
  nat_sign="$(native_sign "$a" "$b")"

  count=$((count+1))
  if [ "$go_sign" = "ERR" ]; then
    # Go 侧判定非法：若原生侧也报错则跳过，否则记为不一致（需人工判断是否预期差异）
    if [ "${nat_sign:0:3}" = "ERR" ]; then
      continue
    fi
    echo "MISMATCH(Go=ERR,native=$nat_sign): $a vs $b"
    fail=1
    continue
  fi
  if [ "$go_sign" != "$nat_sign" ]; then
    echo "MISMATCH(Go=$go_sign,native=$nat_sign): $a vs $b"
    fail=1
  fi
done < <(raw_cases)

echo "== $MANAGER: 比较 $count 对，$([ "$fail" -eq 0 ] && echo PASS || echo FAIL) =="
exit "$fail"
