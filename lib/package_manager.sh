#!/usr/bin/env bash
#
# lib/package_manager.sh - 包管理器抽象
#
# 只使用发行版官方仓库或用户当前已配置的仓库：
#   * 不新增第三方源
#   * 不做全系统升级
#   * 只操作内核相关包
#
# 自动修复的发行版白名单由 adapter + 基线记录共同决定，
# 本模块不自行判断「是否允许安装」。

apt_candidate() {
    local pkg="$1" out=""
    out="$(LC_ALL=C apt-cache policy "${pkg}" 2>/dev/null | awk '/^ *Candidate:/ {print $2; exit}' || true)"
    [[ -n ${out} ]] || return 1
    printf '%s\n' "${out}"
}

# 候选版本是否可用：存在、分支一致、且达到修复版本（Debian 语义）
candidate_usable() {
    local cand="$1" cand_branch=""
    [[ -n ${cand} ]] || return 1
    [[ ${cand} != "(none)" ]] || return 1
    cand_branch="$(kernel_branch "${cand}" || true)"
    [[ ${cand_branch} == "${KERNEL_BRANCH}" ]] || return 1
    version_ge "${cand}" "${FIXED_VERSION}"
}

# 归一化 dnf 输出的 epoch：(none):1.2.3-4 -> 1.2.3-4
_rpm_strip_epoch() {
    local v="$1"
    v="${v#(none):}"
    if [[ ${v} == 0:* ]]; then
        v="${v#0:}"
    fi
    printf '%s' "${v}"
}

rpm_candidate() {
    local pkg="$1" out=""

    if have dnf; then
        out="$(LC_ALL=C dnf -q repoquery --available --latest-limit 1 \
            --qf '%{epoch}:%{version}-%{release}' "${pkg}" 2>/dev/null | head -n 1 || true)"
    elif have yum; then
        out="$(LC_ALL=C yum -q --showduplicates list "${pkg}" 2>/dev/null |
            awk 'NF >= 2 && $1 ~ /^[A-Za-z0-9_.+-]+$/ {print $2}' | tail -n 1 || true)"
    fi

    [[ -n ${out} ]] || return 1
    out="$(_rpm_strip_epoch "${out}")"
    [[ -n ${out} ]] || return 1
    [[ ${out} != "None" ]] || return 1
    printf '%s\n' "${out}"
}

rpm_candidate_repo() {
    local pkg="$1" out=""
    if have dnf; then
        out="$(LC_ALL=C dnf -q repoquery --available --latest-limit 1 \
            --qf '%{repoid}' "${pkg}" 2>/dev/null | head -n 1 || true)"
    fi
    printf '%s\n' "${out:-未知}"
}

# RPM 候选：分支一致且 EVR >= 基线
candidate_usable_rpm() {
    local cand="$1" cand_branch=""
    [[ -n ${cand} ]] || return 1
    cand_branch="$(kernel_branch "${cand}" || true)"
    [[ ${cand_branch} == "${KERNEL_BRANCH}" ]] || return 1
    version_ge_family "rpm" "${cand}" "${FIXED_VERSION}"
}

pm_name() {
    case "${DISTRO_FAMILY}" in
        debian) printf 'apt\n' ;;
        rpm) if have dnf; then printf 'dnf\n'; else printf 'yum\n'; fi ;;
        suse) printf 'zypper\n' ;;
        arch) printf 'pacman\n' ;;
        alpine) printf 'apk\n' ;;
        *) printf 'unknown\n' ;;
    esac
}

pm_update_index() {
    case "${DISTRO_FAMILY}" in
        debian)
            log_info "执行 apt-get update ..."
            if ! DEBIAN_FRONTEND=noninteractive apt-get \
                -o DPkg::Lock::Timeout=120 \
                -o Acquire::Retries=3 \
                update; then
                log_err "apt-get update 执行失败，已停止，未安装任何内核。"
                log_err "请检查网络连通性与 /etc/apt/sources.list 配置后重试。"
                return 1
            fi
            ;;
        rpm)
            if have dnf; then
                log_info "执行 dnf makecache ..."
                if ! dnf -q makecache; then
                    log_err "dnf makecache 执行失败，已停止，未安装任何内核。"
                    return 1
                fi
            else
                log_info "执行 yum makecache ..."
                if ! yum -q makecache; then
                    log_err "yum makecache 执行失败，已停止，未安装任何内核。"
                    return 1
                fi
            fi
            ;;
        *)
            log_err "该发行版未启用自动修复，拒绝刷新软件源索引。"
            return 1
            ;;
    esac
    log_ok "软件源索引刷新完成"
    return 0
}

pm_install() {
    local pkg="$1" evr="$2"

    case "${DISTRO_FAMILY}" in
        debian)
            log_info "执行 apt-get install ${pkg} ..."
            if ! DEBIAN_FRONTEND=noninteractive apt-get install -y \
                -o DPkg::Lock::Timeout=120 \
                -o Dpkg::Options::=--force-confdef \
                -o Dpkg::Options::=--force-confold \
                --no-install-recommends "${pkg}"; then
                log_err "内核安装失败（apt-get install 返回非零），已停止后续操作。"
                log_err "系统未重启，当前仍运行 ${KERNEL_RELEASE}。请根据上方 APT 报错处理后重试。"
                return 1
            fi
            ;;
        rpm)
            local spec="${pkg}-${evr}"
            if have dnf; then
                log_info "执行 dnf install ${spec} ..."
                if ! dnf -y install --setopt=install_weak_deps=False --best "${spec}"; then
                    log_err "内核安装失败（dnf install 返回非零），已停止后续操作。"
                    log_err "系统未重启，当前仍运行 ${KERNEL_RELEASE}。请根据上方 DNF 报错处理后重试。"
                    return 1
                fi
            else
                log_info "执行 yum install ${spec} ..."
                if ! yum -y install "${spec}"; then
                    log_err "内核安装失败（yum install 返回非零），已停止后续操作。"
                    log_err "系统未重启，当前仍运行 ${KERNEL_RELEASE}。请根据上方 YUM 报错处理后重试。"
                    return 1
                fi
            fi
            ;;
        *)
            log_err "该发行版未启用自动修复，拒绝执行安装。"
            return 1
            ;;
    esac

    log_ok "安装命令执行完成，开始校验实际安装结果"
    return 0
}

# 安装前展示将被变更的包（只读描述，不调用包管理器，避免任何副作用）
pm_plan_lines() {
    local pkg="$1" evr="$2"
    case "${DISTRO_FAMILY}" in
        debian)
            printf '  - %s -> %s\n' "${pkg}" "${evr}"
            if [[ -n ${TARGET_RELEASE:-} ]]; then
                printf '  - linux-image-%s（APT 依赖解析目标）\n' "${TARGET_RELEASE}"
            fi
            ;;
        rpm)
            printf '  - %s-%s\n' "${pkg}" "${evr}"
            ;;
        *)
            ;;
    esac
}
