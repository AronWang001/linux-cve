#!/bin/sh
# linux-cve v2.0.0 安装脚本
#
# 只做三件事：下载对应架构的发布包、校验 SHA256、把二进制放到 /usr/local/bin。
# 不写配置文件，不改 /etc，不启动服务。首次使用还需要：
#   linux-cve feed update --all && linux-cve scan
#
# 用法：
#   curl -fsSL https://github.com/AronWang001/linux-cve/releases/download/v2.0.0/install.sh | sudo sh
#   VERSION=v2.0.0 DEST=/usr/local/bin sh install.sh

set -eu

REPO="AronWang001/linux-cve"
VERSION="${VERSION:-v2.0.0}"
DEST="${DEST:-/usr/local/bin}"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"

say() { printf '%s\n' "$*" >&2; }
die() { say "错误：$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "需要 root（安装到 ${DEST}）"

# 架构：发布包只提供 amd64 与 arm64。
arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "不支持的架构：${arch}（仅提供 amd64 / arm64）" ;;
esac

os=$(uname -s)
[ "$os" = "Linux" ] || die "只支持 Linux，当前是 ${os}"

name="linux-cve_${VERSION#v}_linux_${arch}"
tarball="${name}.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    die "需要 curl 或 wget"
  fi
}

say "下载 ${tarball}"
fetch "${BASE}/${tarball}" "${tmp}/${tarball}"

# 校验和不是可选项：没有它，HTTPS 断了就只剩「下载成功」四个字。
say "下载 SHA256SUMS"
fetch "${BASE}/SHA256SUMS" "${tmp}/SHA256SUMS"

# SHA256SUMS 的写法不止一种：`sha256sum *.tar.gz` 给的是 "hash  name"，
# `sha256sum ./*.tar.gz` 给的是 "hash  ./name"，某些工具还会写成 "*name"。
# 只认一种写法就会在另一种上误报「没有记录」，白白挡住安装。
want=$(awk -v f="${tarball}" '
  {
    n = $NF
    sub(/^\*/, "", n)
    sub(/^\.\//, "", n)
    if (n == f) { print $1; exit }
  }' "${tmp}/SHA256SUMS")
[ -n "${want}" ] || die "SHA256SUMS 中没有 ${tarball} 的记录"

if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "${tmp}/${tarball}" | awk '{print $1}')
else
  got=$(shasum -a 256 "${tmp}/${tarball}" | awk '{print $1}')
fi
[ "${want}" = "${got}" ] || die "SHA256 不匹配：期望 ${want}，实际 ${got}"

say "解压"
tar -xzf "${tmp}/${tarball}" -C "${tmp}"
[ -f "${tmp}/linux-cve" ] || die "发布包中没有 linux-cve 可执行文件"

install -m 0755 "${tmp}/linux-cve" "${DEST}/linux-cve"
say "已安装到 ${DEST}/linux-cve"

"${DEST}/linux-cve" version 2>/dev/null || true

cat >&2 <<'EOF'

下一步（需要 root）：
  linux-cve feed update --all      # 首次同步情报，Debian 约 20 秒
  linux-cve scan                   # 扫描本机
  linux-cve report                 # 生成报告

自动修复默认关闭。需要时在 /etc/linux-cve/config.toml 写入：
  [remediation]
  allow_auto_fix = true
EOF
