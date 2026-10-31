#!/usr/bin/env bash
#
# lib/detect.sh - 系统识别：发行版、版本、架构、内核、容器环境
#
# 原则：必须交叉确认，不能仅凭 ID_LIKE 把 Ubuntu 认成 Debian，
#       也不能把 Rocky / AlmaLinux / Oracle Linux 折叠成 RHEL。

# ShellCheck 单文件分析看不到跨文件使用点：本文件产出的全局状态由
# fix.sh / lib/*.sh / adapters/*.sh 读取，故整体关闭「变量未使用」提示。
# shellcheck disable=SC2034

# 解析 /etc/os-release（回退 /usr/lib/os-release）
detect_os_release() {
    local file="" key="" val="" found=0
    local os_id="" os_ver="" os_code="" os_pretty="" os_name="" os_like=""

    for file in "$(sysfile /etc/os-release)" "$(sysfile /usr/lib/os-release)"; do
        [[ -r ${file} ]] || continue
        while IFS='=' read -r key val; do
            val="${val%\"}"
            val="${val#\"}"
            val="${val%\'}"
            val="${val#\'}"
            case "${key}" in
                ID) os_id="${val}" ;;
                VERSION_ID) os_ver="${val}" ;;
                VERSION_CODENAME) os_code="${val}" ;;
                PRETTY_NAME) os_pretty="${val}" ;;
                NAME) os_name="${val}" ;;
                ID_LIKE) os_like="${val}" ;;
            esac
        done <"${file}"
        found=1
        break
    done

    if [[ ${found} -eq 0 ]] || [[ -z ${os_id} ]]; then
        return 1
    fi

    OS_ID="${os_id,,}"
    OS_VERSION_ID="${os_ver}"
    OS_CODENAME="${os_code}"
    OS_NAME="${os_name:-${os_id}}"
    OS_PRETTY="${os_pretty:-${OS_NAME} ${os_ver}}"
    OS_ID_LIKE="${os_like,,}"
    return 0
}

# 规范化 CPU 架构：内部统一使用 amd64 / arm64 / 其他原样
normalize_arch() {
    case "$1" in
        x86_64 | amd64) printf 'amd64\n' ;;
        aarch64 | arm64) printf 'arm64\n' ;;
        i386 | i486 | i586 | i686 | x86) printf 'x86\n' ;;
        armv7l | armv6l) printf 'arm\n' ;;
        ppc64le | s390x | riscv64) printf '%s\n' "$1" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

# 发行版 ID -> adapter 文件
adapter_file_for_id() {
    case "$1" in
        debian) printf 'debian.sh\n' ;;
        ubuntu) printf 'ubuntu.sh\n' ;;
        rhel) printf 'rhel.sh\n' ;;
        rocky) printf 'rocky.sh\n' ;;
        almalinux) printf 'almalinux.sh\n' ;;
        ol) printf 'oracle_linux.sh\n' ;;
        amzn) printf 'amazon_linux.sh\n' ;;
        fedora) printf 'fedora.sh\n' ;;
        opensuse-leap | opensuse-tumbleweed | opensuse | sles | sled) printf 'suse.sh\n' ;;
        arch | archarm) printf 'arch.sh\n' ;;
        alpine) printf 'alpine.sh\n' ;;
        *) return 1 ;;
    esac
}

# 发行版版本号规范化：RHEL 系的 VERSION_ID 可能是 9.4，Alpine 是 3.20.3
normalize_release() {
    local distro="$1" version="$2"
    case "${distro}" in
        debian | amazon | fedora)
            printf '%s\n' "${version%%.*}"
            ;;
        rhel | rocky | almalinux | oracle)
            printf '%s\n' "${version%%.*}"
            ;;
        ubuntu)
            printf '%s\n' "$(printf '%s' "${version}" | cut -d. -f1,2)"
            ;;
        alpine)
            printf '%s\n' "$(printf '%s' "${version}" | cut -d. -f1,2)"
            ;;
        suse)
            printf '%s\n' "${version}"
            ;;
        arch)
            printf 'rolling\n'
            ;;
        *)
            printf '%s\n' "${version}"
            ;;
    esac
}

# 识别发行版并加载对应 adapter
identify_distro() {
    local adapter_file="" path=""

    if ! detect_os_release; then
        OS_PRETTY="未知"
        DISTRO_ID=""
        DISTRO_FAMILY=""
        ADAPTER_NAME="未知系统"
        return 1
    fi

    if ! adapter_file="$(adapter_file_for_id "${OS_ID}")"; then
        DISTRO_ID="${OS_ID}"
        DISTRO_FAMILY=""
        ADAPTER_NAME="${OS_NAME}"
        DISTRO_RELEASE="$(normalize_release "${OS_ID}" "${OS_VERSION_ID}")"
        DISTRO_CODENAME="${OS_CODENAME}"
        return 2
    fi

    path="${LIB_ROOT}/adapters/${adapter_file}"
    if [[ ! -r ${path} ]]; then
        DISTRO_ID="${OS_ID}"
        DISTRO_FAMILY=""
        ADAPTER_NAME="${OS_NAME}"
        return 3
    fi

    # adapter 只负责声明身份与能力，不执行任何系统操作
    # shellcheck source=/dev/null
    source "${path}"

    DISTRO_ID="${ADAPTER_ID}"
    DISTRO_FAMILY="${ADAPTER_FAMILY}"
    DISTRO_RELEASE="$(normalize_release "${OS_ID}" "${OS_VERSION_ID}")"
    DISTRO_CODENAME="${OS_CODENAME:-${ADAPTER_CODENAME:-}}"
    return 0
}

# 发行版专属附加识别（例如 Oracle Linux 的 UEK / RHCK）
distro_extra_detect() {
    KERNEL_FLAVOR=""
    ORACLE_KERNEL_TYPE=""

    case "${DISTRO_ID}" in
        oracle)
            # UEK 与 RHCK 使用完全不同的包与基线，必须分开判断
            if [[ ${KERNEL_RELEASE} == *uek* ]]; then
                ORACLE_KERNEL_TYPE="uek"
                KERNEL_FLAVOR="kernel-uek"
            else
                ORACLE_KERNEL_TYPE="rhck"
                KERNEL_FLAVOR="kernel"
            fi
            ;;
        amazon | rhel | rocky | almalinux | fedora)
            KERNEL_FLAVOR="kernel"
            ;;
        alpine)
            case "${KERNEL_RELEASE}" in
                *-lts) KERNEL_FLAVOR="linux-lts" ;;
                *-virt) KERNEL_FLAVOR="linux-virt" ;;
                *-edge) KERNEL_FLAVOR="linux-edge" ;;
                *) KERNEL_FLAVOR="" ;;
            esac
            ;;
        arch)
            # 顺序敏感：*-rt-lts 必须排在 *-lts 之前，否则会被 *-lts 抢先匹配
            case "${KERNEL_RELEASE}" in
                *-rt-lts) KERNEL_FLAVOR="linux-rt-lts" ;;
                *-rt) KERNEL_FLAVOR="linux-rt" ;;
                *-lts) KERNEL_FLAVOR="linux-lts" ;;
                *-zen) KERNEL_FLAVOR="linux-zen" ;;
                *-hardened) KERNEL_FLAVOR="linux-hardened" ;;
                *) KERNEL_FLAVOR="linux" ;;
            esac
            ;;
        *)
            KERNEL_FLAVOR=""
            ;;
    esac
}

# 检测内核与分支
detect_kernel() {
    KERNEL_RELEASE="$(uname -r)"
    if [[ -z ${KERNEL_RELEASE} ]]; then
        die "无法获取当前运行内核版本（uname -r 为空），已停止。"
    fi
    if ! KERNEL_BRANCH="$(kernel_branch "${KERNEL_RELEASE}")"; then
        die "无法解析内核版本号：${KERNEL_RELEASE}，已停止。"
    fi
}

detect_reboot_flags() {
    if [[ -e "$(sysfile /var/run/reboot-required)" ]] || [[ -e "$(sysfile /run/reboot-required)" ]]; then
        REBOOT_FLAG=1
    else
        REBOOT_FLAG=0
    fi
}

# 架构检测：识别 amd64/arm64，其余架构仅在检测层面展示
# 包管理器报告的架构只用于交叉确认，不能覆盖 uname 的结果
detect_arch() {
    local pm_arch=""
    ARCH_RAW="$(uname -m)"
    ARCH="$(normalize_arch "${ARCH_RAW}")"
    PM_ARCH=""
    ARCH_CONFLICT=0

    case "${DISTRO_FAMILY}" in
        debian)
            have dpkg && pm_arch="$(dpkg --print-architecture 2>/dev/null || true)"
            ;;
        rpm | suse)
            have rpm && pm_arch="$(rpm --eval '%{_arch}' 2>/dev/null || true)"
            ;;
    esac

    case "${pm_arch}" in
        amd64 | x86_64) PM_ARCH="amd64" ;;
        arm64 | aarch64) PM_ARCH="arm64" ;;
        i386 | i686) PM_ARCH="x86" ;;
        *) PM_ARCH="${pm_arch}" ;;
    esac

    if [[ -n ${PM_ARCH} ]] && [[ ${PM_ARCH} != "${ARCH}" ]]; then
        ARCH_CONFLICT=1
    fi
}
