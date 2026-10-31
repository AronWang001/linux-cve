#!/usr/bin/env bash
#
# lib/install.sh - 修复计划、安装、安装后校验与重启提示
#
# 铁律：
#   * 只有 adapter 显式允许自动修复 + 基线已核验 + 候选版本达标，才进入安装
#   * 不删除旧内核、不自动重启、不做全系统升级、不改业务配置
#   * 包管理器返回 0 不等于修复成功，必须回查包数据库与引导配置

# ---------------------------------------------------------------------------
# 选择目标包
# ---------------------------------------------------------------------------

select_target_package() {
    local flavour="" cand="" pkg="" ver="" best="" best_ver="" search_re=""

    flavour="$(kernel_flavour)"
    if [[ ${DISTRO_RELEASE} == "12" ]] && [[ ${KERNEL_BRANCH} == "6.12" ]]; then
        TARGET_PKG="linux-image-6.12-${flavour}"
    else
        TARGET_PKG="linux-image-${flavour}"
    fi

    if cand="$(apt_candidate "${TARGET_PKG}")" && candidate_usable "${cand}"; then
        TARGET_VERSION="${cand}"
        return 0
    fi

    # 回退：在同一分支的具体镜像包中挑选最高可用版本
    search_re="^linux-image-${KERNEL_BRANCH//./\\.}\\..*-${flavour}$"
    while read -r pkg _; do
        [[ -n ${pkg} ]] || continue
        case "${pkg}" in
            *-unsigned) continue ;;
        esac
        ver="$(apt_candidate "${pkg}" || true)"
        candidate_usable "${ver}" || continue
        if [[ -z ${best_ver} ]] || dpkg --compare-versions "${ver}" gt "${best_ver}"; then
            best="${pkg}"
            best_ver="${ver}"
        fi
    done < <(LC_ALL=C apt-cache search --names-only "${search_re}" 2>/dev/null || true)

    if [[ -n ${best} ]]; then
        TARGET_PKG="${best}"
        TARGET_VERSION="${best_ver}"
        return 0
    fi

    return 1
}

resolve_target_release() {
    local name="${TARGET_PKG#linux-image-}"
    if [[ ${name} =~ ^[0-9][^[:space:]]*-${ARCH}$ ]]; then
        TARGET_RELEASE="${name}"
    else
        TARGET_RELEASE=""
    fi
}

# Amazon Linux：目标包由基线记录给出，候选 EVR 必须同分支且达标
select_target_rpm() {
    local cand=""

    TARGET_PKG="${BASELINE_PACKAGE:-kernel}"
    if ! cand="$(rpm_candidate "${TARGET_PKG}")"; then
        return 1
    fi
    candidate_usable_rpm "${cand}" || return 1
    TARGET_VERSION="${cand}"
    TARGET_RELEASE="${cand}"
    return 0
}

# ---------------------------------------------------------------------------
# 计划与确认
# ---------------------------------------------------------------------------

confirm() {
    local prompt="$1" reply=""

    if [[ ${ASSUME_YES} -eq 1 ]]; then
        log_warn "已指定 --yes，跳过交互确认"
        return 0
    fi

    if [[ ${FIX_NO_TTY:-0} -eq 1 ]]; then
        printf '%s [y/N] ' "${prompt}" >&2
        IFS= read -r reply || reply=""
    elif { : </dev/tty; } 2>/dev/null; then
        printf '%s [y/N] ' "${prompt}" >/dev/tty
        IFS= read -r reply </dev/tty || reply=""
    else
        printf '%s [y/N] ' "${prompt}" >&2
        IFS= read -r reply || reply=""
    fi

    case "${reply,,}" in
        y | yes | 是) return 0 ;;
        "")
            log_warn "未获取到输入，按取消处理"
            return 1
            ;;
        *) return 1 ;;
    esac
}

print_plan() {
    step_title 3 "修复计划"
    kv "目标软件包" "${TARGET_PKG}"
    kv "可安装版本" "${TARGET_VERSION}"
    kv "修复版本基准" "${FIXED_VERSION}"
    if [[ -n ${TARGET_RELEASE} ]]; then
        kv "预计新内核" "${TARGET_RELEASE}"
    else
        kv "预计新内核" "由 APT 依赖解析决定（分支 ${KERNEL_BRANCH}）"
    fi
    if [[ ${DISTRO_FAMILY} == "rpm" ]]; then
        kv "仓库来源" "$(rpm_candidate_repo "${TARGET_PKG}")"
    fi

    printf '\n  即将执行：\n'
    case "${DISTRO_FAMILY}" in
        debian)
            printf '   1. apt-get update（仅刷新索引）\n'
            printf '   2. apt-get install %s\n' "${TARGET_PKG}"
            ;;
        rpm)
            printf '   1. %s makecache（仅刷新元数据）\n' "$(pm_name)"
            printf '   2. %s install %s-%s\n' "$(pm_name)" "${TARGET_PKG}" "${TARGET_VERSION}"
            ;;
        *)
            printf '   （该发行版未启用自动修复）\n'
            ;;
    esac
    printf '   3. 校验安装结果、initramfs 与引导配置\n'

    printf '\n  预计变更的软件包：\n'
    pm_plan_lines "${TARGET_PKG}" "${TARGET_VERSION}"

    printf '\n  %s不会执行：自动重启、删除旧内核、升级无关软件包、编译内核，%s\n' "${C_DIM}" "${C_RESET}"
    printf '  %s也不会修改 SSH / 防火墙 / 网络 / 业务配置。%s\n' "${C_DIM}" "${C_RESET}"
    printf '\n'
}

# ---------------------------------------------------------------------------
# 安装后校验
# ---------------------------------------------------------------------------

verify_install() {
    local pkg="" evr="" ident="" newest="" newest_ver=""

    while IFS=$'\t' read -r pkg evr ident; do
        [[ -n ${ident} ]] || continue
        kernel_evr_ge "${evr}" "${FIXED_VERSION}" || continue
        if [[ ${DISTRO_FAMILY} == "debian" ]]; then
            has_vmlinuz "${ident}" || continue
        fi
        if [[ -z ${newest_ver} ]] || ! kernel_evr_ge "${newest_ver}" "${evr}"; then
            newest="${ident}"
            newest_ver="${evr}"
        fi
    done < <(kernel_scan_installed)

    if [[ -z ${newest} ]]; then
        log_err "安装命令返回成功，但未检测到达到修复版本 ${FIXED_VERSION} 的内核镜像。"
        log_err "安装成功不等于漏洞已修复，请执行 '$(pm_query_hint)' 核对后重试。"
        exit "${EX_ERROR}"
    fi

    NEW_KERNEL_RELEASE="${newest}"
    NEW_KERNEL_VERSION="${newest_ver}"
    if [[ ${NEW_KERNEL_RELEASE} == "${NEW_KERNEL_VERSION}" ]]; then
        log_ok "已安装修复内核：${NEW_KERNEL_RELEASE}"
    else
        log_ok "已安装修复内核：${NEW_KERNEL_RELEASE}（${NEW_KERNEL_VERSION}）"
    fi
}

pm_query_hint() {
    case "${DISTRO_FAMILY}" in
        debian) printf 'dpkg -l | grep linux-image' ;;
        rpm) printf 'rpm -qa kernel\\*' ;;
        alpine) printf 'apk info -v' ;;
        arch) printf 'pacman -Q' ;;
        *) printf '包管理器查询命令' ;;
    esac
}

_initramfs_candidates() {
    local ident="$1" evr="$2" native=""
    case "${DISTRO_FAMILY}" in
        debian)
            printf '%s\n' "/boot/initrd.img-${ident}"
            ;;
        rpm)
            case "${ARCH}" in
                amd64) native="x86_64" ;;
                arm64) native="aarch64" ;;
                *) native="${ARCH_RAW}" ;;
            esac
            printf '%s\n' "/boot/initramfs-${evr}.img"
            printf '%s\n' "/boot/initramfs-${evr}.${native}.img"
            ;;
        *)
            ;;
    esac
}

check_initramfs() {
    local ident="$1" evr="${2:-}" path="" found=0

    while read -r path; do
        [[ -n ${path} ]] || continue
        if [[ -s "$(sysfile "${path}")" ]]; then
            log_ok "initramfs 已生成：${path}"
            return 0
        fi
        found=1
    done < <(_initramfs_candidates "${ident}" "${evr}")

    # 容器等环境没有 /boot，无法校验时不谎报成功
    if [[ ${found} -eq 1 ]] && [[ ! -d "$(sysfile /boot)" ]]; then
        log_warn "未找到 /boot（可能是容器环境），跳过 initramfs 校验。"
        return 0
    fi

    if [[ ${DISTRO_FAMILY} == "rpm" ]]; then
        log_err "未检测到有效的 initramfs（/boot/initramfs-${evr}.img）"
        log_err "请手动执行 'dracut -f /boot/initramfs-${evr}.img ${evr}' 排查后再次运行本脚本。"
        exit "${EX_ERROR}"
    fi

    log_err "未检测到有效的 initramfs：/boot/initrd.img-${ident}"
    log_err "请手动执行 'update-initramfs -c -k ${ident}'，确认无误后再次运行本脚本。"
    exit "${EX_ERROR}"
}

# 识别实际使用的 bootloader，返回配置路径
bootloader_config_path() {
    local candidate=""
    case "${DISTRO_FAMILY}" in
        debian)
            for candidate in "/boot/grub/grub.cfg" "/boot/grub2/grub.cfg"; do
                if [[ -f "$(sysfile "${candidate}")" ]]; then
                    printf '%s\n' "${candidate}"
                    return 0
                fi
            done
            ;;
        rpm)
            for candidate in "/boot/grub2/grub.cfg" "/boot/grub/grub.cfg" "/boot/efi/EFI/redhat/grub.cfg" "/boot/efi/EFI/amazon/grub.cfg"; do
                if [[ -f "$(sysfile "${candidate}")" ]]; then
                    printf '%s\n' "${candidate}"
                    return 0
                fi
            done
            ;;
    esac
    return 1
}

bootloader_entries_dir() {
    local dir=""
    for dir in "/boot/loader/entries" "/boot/efi/loader/entries"; do
        if [[ -d "$(sysfile "${dir}")" ]]; then
            printf '%s\n' "${dir}"
            return 0
        fi
    done
    return 1
}

check_bootloader() {
    local ident="$1"
    local evr="${2:-$1}"
    local cfg="" entries="" needle=""
    needle="${ident}"

    # Debian 的 GRUB 菜单以 /boot 下的内核文件名标识；RPM 系以 EVR 标识
    [[ ${DISTRO_FAMILY} == "rpm" ]] && needle="${evr}"

    if cfg="$(bootloader_config_path)"; then
        if grep -Fqs -- "${needle}" "$(sysfile "${cfg}")"; then
            log_ok "引导配置已包含新内核：${cfg}"
            return 0
        fi

        if [[ ${DISTRO_FAMILY} == "debian" ]]; then
            log_warn "GRUB 配置中未找到新内核 ${ident}，尝试重新生成引导配置"
            if have update-grub; then
                if ! update-grub; then
                    log_err "update-grub 执行失败，引导配置可能未更新，已停止。"
                    log_err "请手动执行 'update-grub' 排查后，再次运行本脚本。"
                    exit "${EX_ERROR}"
                fi
            elif have grub-mkconfig; then
                if ! grub-mkconfig -o "$(sysfile "${cfg}")"; then
                    log_err "grub-mkconfig 执行失败，引导配置可能未更新，已停止。"
                    log_err "请手动执行 'grub-mkconfig -o /boot/grub/grub.cfg' 排查后，再次运行本脚本。"
                    exit "${EX_ERROR}"
                fi
            else
                log_err "系统中未找到 update-grub / grub-mkconfig，无法更新引导配置，已停止。"
                exit "${EX_ERROR}"
            fi
            if grep -Fqs -- "${needle}" "$(sysfile "${cfg}")"; then
                log_ok "GRUB 配置已更新并包含新内核：${cfg}"
                return 0
            fi
            log_err "重新生成后 GRUB 配置中仍不包含新内核 ${ident}，引导项可能不可用，已停止。"
            log_err "请检查 /etc/default/grub 与 /etc/grub.d/ 配置后重试。"
            exit "${EX_ERROR}"
        fi

        # RPM 系：不擅自重建引导配置，避免破坏云厂商启动项
        log_err "引导配置 ${cfg} 中未找到新内核 ${evr}，已停止，未执行任何引导重建。"
        log_err "请手动执行 'grub2-mkconfig -o ${cfg}' 并确认启动项后重试。"
        exit "${EX_ERROR}"
    fi

    if entries="$(bootloader_entries_dir)"; then
        if grep -rFqs -- "${needle}" "$(sysfile "${entries}")" 2>/dev/null; then
            log_ok "systemd-boot 启动项已包含新内核：${entries}"
            return 0
        fi
        log_warn "systemd-boot 启动项中未找到 ${needle}，请重启前自行确认默认启动项。"
        return 0
    fi

    log_warn "未检测到 GRUB 或 systemd-boot 配置，无法确认引导项。"
    log_warn "请重启前自行确认引导程序已包含新内核 ${ident}。"
    return 0
}

# ---------------------------------------------------------------------------
# 重启提示
# ---------------------------------------------------------------------------

print_reboot_notice() {
    printf '\n%s────────────────────────────────────────────────────────%s\n' "${C_BOLD}" "${C_RESET}"
    printf '%s 修复结果%s\n' "${C_BOLD}" "${C_RESET}"
    printf '%s────────────────────────────────────────────────────────%s\n' "${C_BOLD}" "${C_RESET}"
    kv "原运行内核" "${KERNEL_RELEASE}（${RUNNING_VERSION:-未知}）"
    kv "新安装内核" "${NEW_KERNEL_RELEASE}（${NEW_KERNEL_VERSION:-未知}）"
    kv "安装状态" "成功，修复内核已就位"
    kv "是否需要重启" "需要"

    cat <<EOF

  ${C_YELLOW}${C_BOLD}新内核已经安装，但当前服务器仍在运行旧内核。${C_RESET}
  需要安排维护窗口重启服务器，才能让修复后的内核正式生效。
  重启前本机仍然受 ${CVE_ID} 影响，请勿视为已修复。

  重启命令（复制后自行执行，本脚本不会自动重启）：

      ${C_BOLD}reboot${C_RESET}

  重启后请再次执行本脚本进行二次验证：

      sudo bash ${SCRIPT_NAME} --check

EOF
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

run_fix_debian() {
    if ! select_target_package; then
        log_err "软件源中未找到分支 ${KERNEL_BRANCH} 且版本 >= ${FIXED_VERSION} 的内核包。"
        log_err "请确认已启用 ${DISTRO_CODENAME:-${DISTRO_RELEASE}}-security 源并执行 apt-get update 后重试，本脚本不做任何修改。"
        exit "${EX_ERROR}"
    fi
    resolve_target_release
    print_plan

    if ! confirm "确认安装上述内核更新？"; then
        log_warn "已取消，系统未做任何修改。"
        exit "${EX_CANCELLED}"
    fi

    step_title 4 "更新内核"

    if ! pm_update_index; then
        exit "${EX_ERROR}"
    fi

    local cand=""
    cand="$(apt_candidate "${TARGET_PKG}" || true)"
    if ! candidate_usable "${cand}"; then
        log_err "更新索引后，${TARGET_PKG} 的候选版本仍不可用（当前：${cand:-未知}）。"
        log_err "修复需要 >= ${FIXED_VERSION}，请检查软件源是否包含 ${DISTRO_CODENAME:-${DISTRO_RELEASE}}-security。"
        exit "${EX_ERROR}"
    fi
    TARGET_VERSION="${cand}"

    if ! pm_install "${TARGET_PKG}" "${TARGET_VERSION}"; then
        exit "${EX_ERROR}"
    fi
    verify_install
    check_initramfs "${NEW_KERNEL_RELEASE}" "${NEW_KERNEL_VERSION}"
    check_bootloader "${NEW_KERNEL_RELEASE}" "${NEW_KERNEL_VERSION}"

    print_reboot_notice
    exit "${EX_PENDING_REBOOT}"
}

run_fix_rpm() {
    if ! select_target_rpm; then
        log_err "软件源中未找到分支 ${KERNEL_BRANCH} 且 EVR >= ${FIXED_VERSION} 的内核包 ${BASELINE_PACKAGE:-kernel}。"
        log_err "请确认官方仓库可用并已刷新元数据后重试，本脚本不做任何修改。"
        exit "${EX_ERROR}"
    fi
    print_plan

    if ! confirm "确认安装上述内核更新？"; then
        log_warn "已取消，系统未做任何修改。"
        exit "${EX_CANCELLED}"
    fi

    step_title 4 "更新内核"

    if ! pm_update_index; then
        exit "${EX_ERROR}"
    fi

    local cand=""
    cand="$(rpm_candidate "${TARGET_PKG}" || true)"
    if ! candidate_usable_rpm "${cand}"; then
        log_err "更新元数据后，${TARGET_PKG} 的候选版本仍不可用（当前：${cand:-未知}）。"
        log_err "修复需要 >= ${FIXED_VERSION}，请检查官方仓库配置。"
        exit "${EX_ERROR}"
    fi
    TARGET_VERSION="${cand}"

    if ! pm_install "${TARGET_PKG}" "${TARGET_VERSION}"; then
        exit "${EX_ERROR}"
    fi
    verify_install
    check_initramfs "${NEW_KERNEL_RELEASE}" "${NEW_KERNEL_VERSION}"
    check_bootloader "${NEW_KERNEL_RELEASE}" "${NEW_KERNEL_VERSION}"

    print_reboot_notice
    exit "${EX_PENDING_REBOOT}"
}

run_fix() {
    case "${DISTRO_FAMILY}" in
        debian) run_fix_debian ;;
        rpm) run_fix_rpm ;;
        *)
            log_err "该发行版未启用自动修复（family=${DISTRO_FAMILY:-unknown}），拒绝执行安装。"
            exit "${EX_ERROR}"
            ;;
    esac
}
