#!/usr/bin/env bash
#
# lib/version.sh - 版本比较
#
# 不同发行版必须使用各自的包管理器语义，禁止用字符串排序代替：
#   debian -> dpkg --compare-versions
#   rpm    -> rpmvercmp（epoch:version-release）
#   suse   -> 同 rpm（zypper 使用 RPM 版本语义）
#   arch   -> pacman vercmp（pkgver-pkgrel）
#   alpine -> apk 版本语义（含 _alpha/_beta/_pre/_rc/_p 后缀与 -rN 修订号）
#
# 所有比较函数统一输出 -1 / 0 / 1，便于调用方判断。

# 按 ASCII 码逐字符比较，避免受当前 locale 排序规则影响；返回 0 表示 $1 < $2
_ascii_lt() {
    local a="$1" b="$2" i=0 ca=0 cb=0
    local -i la=${#a} lb=${#b} n=0
    n=$((la < lb ? la : lb))
    for ((i = 0; i < n; i++)); do
        printf -v ca '%d' "'${a:i:1}"
        printf -v cb '%d' "'${b:i:1}"
        if ((ca < cb)); then
            return 0
        elif ((ca > cb)); then
            return 1
        fi
    done
    ((la < lb))
}

# 数字串比较（忽略前导零）：返回 0 表示 $1 < $2
_num_lt() {
    local a="$1" b="$2"
    a="${a#"${a%%[!0]*}"}"
    b="${b#"${b%%[!0]*}"}"
    if [[ -z ${a} && -z ${b} ]]; then
        return 1
    elif [[ -z ${a} ]]; then
        return 0
    elif [[ -z ${b} ]]; then
        return 1
    fi
    if ((${#a} != ${#b})); then
        ((${#a} < ${#b}))
        return
    fi
    _ascii_lt "${a}" "${b}"
}

# rpmvercmp 语义：输出 -1 / 0 / 1
rpmvercmp() {
    local one="$1" two="$2"
    local i=0 j=0 c1="" c2=""
    local -i len1=${#one} len2=${#two}

    if [[ ${one} == "${two}" ]]; then
        printf '0\n'
        return 0
    fi

    while ((i < len1 || j < len2)); do
        # 跳过分隔符（~ 与 ^ 有特殊语义，需保留）
        while ((i < len1)); do
            c1="${one:i:1}"
            if [[ ${c1} == [0-9a-zA-Z] ]] || [[ ${c1} == '~' ]] || [[ ${c1} == '^' ]]; then
                break
            fi
            i=$((i + 1))
        done
        while ((j < len2)); do
            c2="${two:j:1}"
            if [[ ${c2} == [0-9a-zA-Z] ]] || [[ ${c2} == '~' ]] || [[ ${c2} == '^' ]]; then
                break
            fi
            j=$((j + 1))
        done

        c1=""
        c2=""
        ((i < len1)) && c1="${one:i:1}"
        ((j < len2)) && c2="${two:j:1}"

        # ~ 比包括「字符串结束」在内的任何字符都旧
        if [[ ${c1} == '~' ]] || [[ ${c2} == '~' ]]; then
            if [[ ${c1} == '~' ]] && [[ ${c2} == '~' ]]; then
                i=$((i + 1))
                j=$((j + 1))
                continue
            fi
            if [[ ${c1} == '~' ]]; then
                printf '%s\n' -1
            else
                printf '%s\n' 1
            fi
            return 0
        fi

        # ^ 比「字符串结束」新，但比任何其他字符旧
        if [[ ${c1} == '^' ]] || [[ ${c2} == '^' ]]; then
            if [[ ${c1} == '^' ]] && [[ ${c2} == '^' ]]; then
                i=$((i + 1))
                j=$((j + 1))
                continue
            fi
            if [[ ${c1} == '^' ]]; then
                if ((j < len2)); then
                    printf '%s\n' -1
                else
                    printf '%s\n' 1
                fi
            else
                if ((i < len1)); then
                    printf '%s\n' 1
                else
                    printf '%s\n' -1
                fi
            fi
            return 0
        fi

        # 任一方结束：仍有余下片段的一方更新
        if [[ -z ${c1} ]] || [[ -z ${c2} ]]; then
            if [[ -z ${c1} ]]; then
                printf '%s\n' -1
            else
                printf '%s\n' 1
            fi
            return 0
        fi

        # 数字段与字母段：数字比字母新
        if [[ ${c1} == [0-9] ]] && [[ ${c2} == [0-9] ]]; then
            local s1="" s2=""
            while ((i < len1)) && [[ ${one:i:1} == [0-9] ]]; do
                s1+="${one:i:1}"
                i=$((i + 1))
            done
            while ((j < len2)) && [[ ${two:j:1} == [0-9] ]]; do
                s2+="${two:j:1}"
                j=$((j + 1))
            done
            if [[ ${s1} != "${s2}" ]]; then
                if _num_lt "${s1}" "${s2}"; then
                    printf '%s\n' -1
                else
                    printf '%s\n' 1
                fi
                return 0
            fi
            continue
        fi

        if [[ ${c1} == [0-9] ]]; then
            printf '%s\n' 1
            return 0
        fi
        if [[ ${c2} == [0-9] ]]; then
            printf '%s\n' -1
            return 0
        fi

        local a1="" a2=""
        while ((i < len1)) && [[ ${one:i:1} == [a-zA-Z] ]]; do
            a1+="${one:i:1}"
            i=$((i + 1))
        done
        while ((j < len2)) && [[ ${two:j:1} == [a-zA-Z] ]]; do
            a2+="${two:j:1}"
            j=$((j + 1))
        done
        if [[ ${a1} != "${a2}" ]]; then
            if _ascii_lt "${a1}" "${a2}"; then
                printf '%s\n' -1
            else
                printf '%s\n' 1
            fi
            return 0
        fi
    done

    printf '0\n'
}

# 拆分 rpm EVR，输出 "epoch version release"
rpm_split_evr() {
    local evr="$1" epoch="0" rest=""
    if [[ ${evr} == *:* ]]; then
        epoch="${evr%%:*}"
        rest="${evr#*:}"
    else
        rest="${evr}"
    fi
    [[ -z ${epoch} ]] && epoch="0"
    if [[ ${rest} == *-* ]]; then
        printf '%s %s %s\n' "${epoch}" "${rest%-*}" "${rest##*-}"
    else
        printf '%s %s %s\n' "${epoch}" "${rest}" "0"
    fi
}

# RPM/SUSE EVR 比较：输出 -1 / 0 / 1
rpm_evr_cmp() {
    local a="$1" b="$2"
    local ae="" av="" ar="" be="" bv="" br="" out="" r=""
    out="$(rpm_split_evr "${a}")"
    read -r ae av ar <<<"${out}"
    out="$(rpm_split_evr "${b}")"
    read -r be bv br <<<"${out}"

    if [[ ${ae} != "${be}" ]]; then
        if _num_lt "${ae}" "${be}"; then
            printf '%s\n' -1
        else
            printf '%s\n' 1
        fi
        return 0
    fi
    r="$(rpmvercmp "${av}" "${bv}")"
    if [[ ${r} != "0" ]]; then
        printf '%s\n' "${r}"
        return 0
    fi
    rpmvercmp "${ar}" "${br}"
}

# apk 版本比较：输出 -1 / 0 / 1
apk_vercmp() {
    local a="$1" b="$2"
    local abase="$a" bbase="$b" arev="0" brev="0"
    local amain="" asuf="" bmain="" bsuf=""

    if [[ ${abase} == *-r* ]]; then
        arev="${abase##*-r}"
        abase="${abase%-r*}"
    fi
    if [[ ${bbase} == *-r* ]]; then
        brev="${bbase##*-r}"
        bbase="${bbase%-r*}"
    fi

    amain="${abase%%_*}"
    [[ ${abase} == *_* ]] && asuf="${abase#*_}"
    bmain="${bbase%%_*}"
    [[ ${bbase} == *_* ]] && bsuf="${bbase#*_}"

    local -A rank=([alpha]=1 [beta]=2 [pre]=3 [rc]=4 [cvs]=6 [svn]=7 [git]=8 [hg]=9 [p]=10)
    local asufname="${asuf%%[0-9]*}" bsufname="${bsuf%%[0-9]*}"
    local asufnum="${asuf#"${asufname}"}" bsufnum="${bsuf#"${bsufname}"}"
    local -i arank=5 brank=5
    [[ -n ${asufname} ]] && arank="${rank[${asufname}]:-5}"
    [[ -n ${bsufname} ]] && brank="${rank[${bsufname}]:-5}"

    # 主体版本按点分段做数值比较
    local -a aparts=() bparts=()
    IFS=. read -r -a aparts <<<"${amain}"
    IFS=. read -r -a bparts <<<"${bmain}"
    local -i n=${#aparts[@]} m=${#bparts[@]} k=0
    ((m > n)) && n=${m}
    for ((k = 0; k < n; k++)); do
        local av="${aparts[k]:-0}" bv="${bparts[k]:-0}"
        if [[ ${av} =~ ^[0-9]+$ ]] && [[ ${bv} =~ ^[0-9]+$ ]]; then
            if _num_lt "${av}" "${bv}"; then
                printf '%s\n' -1
                return 0
            elif _num_lt "${bv}" "${av}"; then
                printf '%s\n' 1
                return 0
            fi
        elif [[ ${av} != "${bv}" ]]; then
            if _ascii_lt "${av}" "${bv}"; then
                printf '%s\n' -1
            else
                printf '%s\n' 1
            fi
            return 0
        fi
    done

    if ((arank != brank)); then
        ((arank > brank)) && printf '%s\n' 1 || printf '%s\n' -1
        return 0
    fi

    [[ -z ${asufnum} ]] && asufnum="0"
    [[ -z ${bsufnum} ]] && bsufnum="0"
    if [[ ${asufnum} =~ ^[0-9]+$ ]] && [[ ${bsufnum} =~ ^[0-9]+$ ]]; then
        if [[ ${asufnum} != "${bsufnum}" ]]; then
            if _num_lt "${asufnum}" "${bsufnum}"; then
                printf '%s\n' -1
            else
                printf '%s\n' 1
            fi
            return 0
        fi
    fi

    if [[ ${arev} =~ ^[0-9]+$ ]] && [[ ${brev} =~ ^[0-9]+$ ]]; then
        if [[ ${arev} != "${brev}" ]]; then
            if _num_lt "${arev}" "${brev}"; then
                printf '%s\n' -1
            else
                printf '%s\n' 1
            fi
            return 0
        fi
    fi
    printf '0\n'
}

# pacman 版本比较：pkgver-pkgrel，pkgver 使用 rpmvercmp 语义
pacman_vercmp() {
    local a="$1" b="$2"
    local aver="${a%-*}" arel="${a##*-}" bver="${b%-*}" brel="${b##*-}"
    local r=""
    r="$(rpmvercmp "${aver}" "${bver}")"
    if [[ ${r} != "0" ]]; then
        printf '%s\n' "${r}"
        return 0
    fi
    if [[ ${arel} =~ ^[0-9]+$ ]] && [[ ${brel} =~ ^[0-9]+$ ]]; then
        if [[ ${arel} != "${brel}" ]]; then
            if _num_lt "${arel}" "${brel}"; then
                printf '%s\n' -1
            else
                printf '%s\n' 1
            fi
            return 0
        fi
    elif [[ ${arel} != "${brel}" ]]; then
        if _ascii_lt "${arel}" "${brel}"; then
            printf '%s\n' -1
        else
            printf '%s\n' 1
        fi
        return 0
    fi
    printf '%s\n' 0
}

# dpkg 比较：输出 -1 / 0 / 1
vercmp_dpkg() {
    local a="$1" b="$2"
    if dpkg --compare-versions "${a}" lt "${b}"; then
        printf '%s\n' -1
    elif dpkg --compare-versions "${a}" gt "${b}"; then
        printf '%s\n' 1
    else
        printf '%s\n' 0
    fi
}

# 按发行版家族选择比较器：输出 -1 / 0 / 1
vercmp_family() {
    local family="$1" a="$2" b="$3"
    case "${family}" in
        debian) vercmp_dpkg "${a}" "${b}" ;;
        rpm | suse) rpm_evr_cmp "${a}" "${b}" ;;
        alpine) apk_vercmp "${a}" "${b}" ;;
        arch) pacman_vercmp "${a}" "${b}" ;;
        *) return 2 ;;
    esac
}

# v1.0.0 兼容入口：判断 $1 >= $2（Debian 语义）
version_ge() {
    dpkg --compare-versions "$1" ge "$2"
}

# 通用入口：按家族判断 $2 >= $3
version_ge_family() {
    local family="$1" a="$2" b="$3" r=""
    r="$(vercmp_family "${family}" "${a}" "${b}")" || return 1
    [[ ${r} != "-1" ]]
}
