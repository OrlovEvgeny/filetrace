# shellcheck shell=sh
# Service handling shared by the package maintainer scripts and install.sh,
# which place this file in front of their own code.

ft_service=filetrace-agent
: "${ft_bindir:=/usr/bin}"

ft_say()
{
    printf 'filetrace: %s\n' "$*"
}

ft_warn()
{
    printf 'filetrace: %s\n' "$*" >&2
}

# The service manager running this host. "none" covers chroots and image builds.
ft_init_system()
{
    if [ -d /run/systemd/system ]; then
        echo systemd
    elif [ -e /run/openrc/softlevel ]; then
        echo openrc
    elif command -v update-rc.d >/dev/null 2>&1 || command -v chkconfig >/dev/null 2>&1; then
        echo sysv
    else
        echo none
    fi
}

# Debian's policy layer; exit code 101 forbids the action, as in image builds.
ft_policy_allows()
{
    [ -x /usr/sbin/policy-rc.d ] || return 0
    ft_code=0
    /usr/sbin/policy-rc.d "$ft_service" "$1" >/dev/null 2>&1 || ft_code=$?
    [ "$ft_code" -ne 101 ]
}

ft_host_check()
{
    ft_release=$(uname -r)
    ft_major=${ft_release%%.*}
    ft_minor=${ft_release#*.}
    ft_minor=${ft_minor%%[!0-9]*}
    if [ "$ft_major" -lt 6 ] || { [ "$ft_major" -eq 6 ] && [ "${ft_minor:-0}" -lt 1 ]; }; then
        ft_warn "kernel $ft_release is older than 6.1, the oldest the agent supports"
    fi
    if [ ! -e /sys/kernel/btf/vmlinux ]; then
        ft_warn "this kernel has no BTF (/sys/kernel/btf/vmlinux), which the agent needs"
    fi
}

ft_daemon_reload()
{
    [ ! -d /run/systemd/system ] || systemctl daemon-reload >/dev/null 2>&1 || true
}

ft_enable()
{
    case $(ft_init_system) in
    systemd) systemctl enable "$ft_service.service" >/dev/null 2>&1 || true ;;
    openrc) rc-update add "$ft_service" default >/dev/null 2>&1 || true ;;
    sysv)
        if command -v update-rc.d >/dev/null 2>&1; then
            update-rc.d "$ft_service" defaults >/dev/null 2>&1 || true
        else
            chkconfig --add "$ft_service" >/dev/null 2>&1 || true
        fi
        ;;
    esac
}

ft_disable()
{
    case $(ft_init_system) in
    systemd) systemctl disable "$ft_service.service" >/dev/null 2>&1 || true ;;
    openrc) rc-update del "$ft_service" default >/dev/null 2>&1 || true ;;
    sysv)
        if command -v update-rc.d >/dev/null 2>&1; then
            update-rc.d -f "$ft_service" remove >/dev/null 2>&1 || true
        else
            chkconfig --del "$ft_service" >/dev/null 2>&1 || true
        fi
        ;;
    esac
}

# The agent has no readiness signal; a status of 0 or 9 means it is collecting.
ft_wait_ready()
{
    ft_tries=10
    while [ "$ft_tries" -gt 0 ]; do
        ft_code=0
        "$ft_bindir/filetrace" agent status >/dev/null 2>&1 || ft_code=$?
        case $ft_code in
        0 | 9) return 0 ;;
        esac
        sleep 1
        ft_tries=$((ft_tries - 1))
    done
    return 1
}

# A failed start never fails the caller: the files are in place either way.
ft_start()
{
    if ! ft_policy_allows start; then
        ft_say "policy-rc.d forbids starting $ft_service here"
        return 0
    fi
    case $(ft_init_system) in
    systemd) systemctl start "$ft_service.service" >/dev/null 2>&1 || true ;;
    openrc) rc-service "$ft_service" start >/dev/null 2>&1 || true ;;
    sysv) "/etc/init.d/$ft_service" start >/dev/null 2>&1 || true ;;
    none)
        ft_say "no service manager is running here; start $ft_service yourself"
        return 0
        ;;
    esac
    if ft_wait_ready; then
        ft_say "$ft_service is running"
    else
        ft_warn "$ft_service did not start; 'filetrace doctor' reports what it is missing"
    fi
}

ft_restart_if_running()
{
    ft_policy_allows restart || return 0
    case $(ft_init_system) in
    systemd) systemctl try-restart "$ft_service.service" >/dev/null 2>&1 || true ;;
    openrc) rc-service --ifstarted "$ft_service" restart >/dev/null 2>&1 || true ;;
    sysv)
        if "/etc/init.d/$ft_service" status >/dev/null 2>&1; then
            "/etc/init.d/$ft_service" restart >/dev/null 2>&1 || true
        fi
        ;;
    esac
}

ft_stop()
{
    case $(ft_init_system) in
    systemd) systemctl stop "$ft_service.service" >/dev/null 2>&1 || true ;;
    openrc) rc-service --ifstarted "$ft_service" stop >/dev/null 2>&1 || true ;;
    sysv)
        [ ! -x "/etc/init.d/$ft_service" ] ||
            "/etc/init.d/$ft_service" stop >/dev/null 2>&1 || true
        ;;
    esac
}
