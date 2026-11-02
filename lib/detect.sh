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
        cloudlinux | cloudlinuxos) printf 'cloudlinux.sh\n' ;;
        ol) printf 'oracle_linux.sh\n' ;;
        amzn) printf 'amazon_linux.sh\n' ;;
        fedora) printf 'fedora.sh\n' ;;
        opensuse-leap | opensuse-tumbleweed | opensuse | sles | sled | sl-micro | sle-micro) printf 'suse.sh\n' ;;
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
        rhel | rocky | almalinux | oracle | ol | cloudlinux | cloudlinuxos)
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

# ---------------------------------------------------------------------------
# CloudLinux：身份与内核流
# ---------------------------------------------------------------------------

# 交叉确认 CloudLinux 身份。返回 0 表示可以继续判定。
# CloudLinux 9/10 运行的是 AlmaLinux 构建的内核，仅凭 uname -r 会误判成
# AlmaLinux；反过来，CloudLinux for Ubuntu 22.04 没有 RPM 数据库，不能套
# 用 RPM 判定流程。两种情况都必须能识别出来。
cloudlinux_verify_identity() {
    CL_IDENTITY_OK=1
    CL_IDENTITY_REASON=""
    CL_RELEASE_FILE=""
    CL_RELEASE_PKG=""
    CL_RPM_PRESENT=0

    if have rpm; then
        CL_RPM_PRESENT=1
    fi

    if [[ -r "$(sysfile /etc/cloudlinux-release)" ]]; then
        CL_RELEASE_FILE="$(head -n 1 "$(sysfile /etc/cloudlinux-release)" 2>/dev/null | tr -d '\r' || true)"
    fi

    if [[ ${CL_RPM_PRESENT} -eq 1 ]]; then
        # 默认输出形如 cloudlinux-release-9.6-2.el9.x86_64，去掉包名与架构
        CL_RELEASE_PKG="$(rpm -q cloudlinux-release 2>/dev/null | head -n 1 | tr -d '\r' || true)"
        if [[ -n ${CL_RELEASE_PKG} ]]; then
            CL_RELEASE_PKG="${CL_RELEASE_PKG#cloudlinux-release-}"
            CL_RELEASE_PKG="${CL_RELEASE_PKG%.*}"
        fi
    fi

    # CloudLinux for Ubuntu 22.04：apt 系统、无 RPM 数据库，内核来自 Canonical
    if [[ ${CL_RPM_PRESENT} -eq 0 ]]; then
        CL_IDENTITY_OK=0
        CL_IDENTITY_REASON="检测到 CloudLinux 标识，但系统中没有 RPM 数据库（疑似 CloudLinux for Ubuntu 22.04，内核由 Canonical 提供）。该产品的内核修复仍由 Canonical 推进，本工具不做 RPM 判定，也不安装任何软件。"
        return 1
    fi

    if [[ -z ${CL_RELEASE_FILE} ]] && [[ -z ${CL_RELEASE_PKG} ]]; then
        CL_IDENTITY_OK=0
        CL_IDENTITY_REASON="未找到 /etc/cloudlinux-release，也未安装 cloudlinux-release 软件包，无法交叉确认 CloudLinux 身份（仅凭 ID_LIKE 不足以判定）。"
        return 1
    fi

    if [[ -n ${CL_RELEASE_FILE} ]] && [[ ${CL_RELEASE_FILE,,} != *cloudlinux* ]]; then
        CL_IDENTITY_OK=0
        CL_IDENTITY_REASON="/etc/cloudlinux-release 的内容与 CloudLinux 不符（${CL_RELEASE_FILE}），无法确认发行版身份。"
        return 1
    fi

    local file_major="" pkg_major=""
    if [[ ${CL_RELEASE_FILE} =~ ([0-9]+)\.[0-9]+ ]]; then
        file_major="${BASH_REMATCH[1]}"
    fi
    if [[ ${CL_RELEASE_PKG} =~ ^([0-9]+)\. ]]; then
        pkg_major="${BASH_REMATCH[1]}"
    fi

    if [[ -n ${file_major} ]] && [[ ${file_major} != "${DISTRO_RELEASE}" ]]; then
        CL_IDENTITY_OK=0
        CL_IDENTITY_REASON="/etc/cloudlinux-release 的主版本 ${file_major} 与 /etc/os-release 的 ${DISTRO_RELEASE} 不一致，无法确认发行版版本。"
        return 1
    fi
    if [[ -n ${pkg_major} ]] && [[ ${pkg_major} != "${DISTRO_RELEASE}" ]]; then
        CL_IDENTITY_OK=0
        CL_IDENTITY_REASON="cloudlinux-release 软件包的主版本 ${pkg_major} 与 /etc/os-release 的 ${DISTRO_RELEASE} 不一致，无法确认发行版版本。"
        return 1
    fi
    return 0
}

# 由运行内核包与分支推导 CloudLinux 变体。必须在 kernel_resolve_running 之后调用。
#   7 + 3.10        -> CL7 标准内核（官方明确不受影响）
#   7 + 4.18        -> CL7h（Hybrid）
#   8 + 4.18        -> CL8 标准内核
#   8/9 + kernel-lts-> TuxCare ELS（LTS）
#   9 + 5.14 kernel -> CL9 标准内核（AlmaLinux 内核）
#   10 + 6.12 kernel-> CL10 标准内核
cloudlinux_detect_stream() {
    CL_VARIANT=""
    CL_STREAM=""

    if [[ -z ${RUNNING_PKG} ]]; then
        return 1
    fi

    if [[ ${RUNNING_PKG} == "kernel-lts" ]]; then
        CL_VARIANT="CL${DISTRO_RELEASE} LTS（TuxCare ELS）"
        CL_STREAM="lts-els"
        return 0
    fi

    case "${DISTRO_RELEASE}" in
        7)
            if [[ ${KERNEL_BRANCH} == "3.10" ]]; then
                CL_VARIANT="CL7 标准内核"
                CL_STREAM="standard-3.10"
            elif [[ ${KERNEL_BRANCH} == "4.18" ]]; then
                CL_VARIANT="CL7h（Hybrid）"
                CL_STREAM="hybrid-4.18"
            fi
            ;;
        8)
            if [[ ${KERNEL_BRANCH} == "4.18" ]]; then
                CL_VARIANT="CL8 标准内核"
                CL_STREAM="standard-4.18"
            fi
            ;;
        9)
            if [[ ${RUNNING_PKG} == "kernel" ]] && [[ ${KERNEL_BRANCH} == "5.14" ]]; then
                CL_VARIANT="CL9 标准内核"
                CL_STREAM="standard-5.14"
            fi
            ;;
        10)
            if [[ ${RUNNING_PKG} == "kernel" ]] && [[ ${KERNEL_BRANCH} == "6.12" ]]; then
                CL_VARIANT="CL10 标准内核"
                CL_STREAM="standard-6.12"
            fi
            ;;
    esac

    [[ -n ${CL_STREAM} ]]
}

# 发行版专属附加识别（例如 Oracle Linux 的 UEK / RHCK）
distro_extra_detect() {
    KERNEL_FLAVOR=""
    ORACLE_KERNEL_TYPE=""
    ORACLE_UEK_GEN=""
    SUSE_PRODUCT=""
    PRODUCT_KEY=""
    CL_VARIANT=""
    CL_STREAM=""
    CL_IDENTITY_OK=1
    CL_IDENTITY_REASON=""
    CL_RELEASE_FILE=""
    CL_RELEASE_PKG=""
    CL_RPM_PRESENT=0

    case "${DISTRO_ID}" in
        oracle)
            PRODUCT_KEY="oracle-linux"
            # UEK 与 RHCK 使用完全不同的包与基线，必须分开判断
            if [[ ${KERNEL_RELEASE} == *uek* ]]; then
                ORACLE_KERNEL_TYPE="uek"
                KERNEL_FLAVOR="kernel-uek"
                # UEK 代际由运行内核版本决定，不能按发行版版本推断：
                # OL8 同时存在 UEKR6 与 UEKR7，OL9 同时存在 UEKR7 与 UEKR8。
                case "${KERNEL_BRANCH}" in
                    5.4) ORACLE_UEK_GEN="uek6" ;;
                    5.15) ORACLE_UEK_GEN="uek7" ;;
                    6.12) ORACLE_UEK_GEN="uek8" ;;
                    *) ORACLE_UEK_GEN="unknown" ;;
                esac
            else
                ORACLE_KERNEL_TYPE="rhck"
                KERNEL_FLAVOR="kernel"
            fi
            ;;
        suse)
            case "${OS_ID}" in
                opensuse-leap) SUSE_PRODUCT="opensuse-leap" ;;
                opensuse-tumbleweed) SUSE_PRODUCT="opensuse-tumbleweed" ;;
                sles) SUSE_PRODUCT="sles" ;;
                sled) SUSE_PRODUCT="sled" ;;
                sl-micro | sle-micro | opensuse-micro) SUSE_PRODUCT="sle-micro" ;;
                *) SUSE_PRODUCT="${OS_ID}" ;;
            esac
            # SUSE 的 flavor 由运行内核后缀决定，不能按产品猜测
            case "${KERNEL_RELEASE}" in
                *-default) KERNEL_FLAVOR="kernel-default" ;;
                *-azure) KERNEL_FLAVOR="kernel-azure" ;;
                *-rt) KERNEL_FLAVOR="kernel-rt" ;;
                *-64kb) KERNEL_FLAVOR="kernel-64kb" ;;
                *-kvmsmall) KERNEL_FLAVOR="kernel-kvmsmall" ;;
                *) KERNEL_FLAVOR="" ;;
            esac
            PRODUCT_KEY="${SUSE_PRODUCT}"
            ;;
        almalinux)
            KERNEL_FLAVOR="kernel"
            PRODUCT_KEY="almalinux"
            ;;
        cloudlinux)
            PRODUCT_KEY="cloudlinux"
            # 身份交叉确认：os-release + /etc/cloudlinux-release + cloudlinux-release RPM
            cloudlinux_verify_identity || true
            # 变体（CL7/CL7h/CL8/LTS/CL9/CL10）依赖运行内核包，
            # 在 kernel_resolve_running 之后由 cloudlinux_detect_stream 判定。
            KERNEL_FLAVOR=""
            ;;
        amazon | rhel | rocky | fedora)
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
