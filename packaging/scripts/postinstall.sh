# deb passes "configure" and the version it replaces, rpm the number of
# installed versions. apk passes nothing; its upgrades arrive with ft_event set.
case "$ft_format:${1:-}" in
deb:configure)
    if [ -n "${2:-}" ]; then
        ft_event=upgrade
    else
        ft_event=install
    fi
    ;;
deb:*) exit 0 ;;
rpm:1) ft_event=install ;;
rpm:*) ft_event=upgrade ;;
apk:*) ft_event=${ft_event:-install} ;;
esac

ft_daemon_reload

if [ "$ft_event" = install ]; then
    ft_host_check
    case $ft_format in
    deb)
        ft_enable
        ft_start
        ;;
    rpm)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl --no-reload preset "$ft_service.service" >/dev/null 2>&1 || true
        fi
        ft_say "start the agent with: systemctl enable --now $ft_service"
        ;;
    apk)
        ft_say "start the agent with: rc-update add $ft_service default && rc-service $ft_service start"
        ;;
    esac
    exit 0
fi

# The command and the agent speak one protocol version, so a running agent
# has to be replaced together with the command.
if "$ft_bindir/filetrace" config validate >/dev/null 2>&1; then
    ft_restart_if_running
else
    ft_warn "/etc/filetrace/config.toml is not valid for this version, so $ft_service was not restarted"
    ft_warn "fix what 'filetrace config validate' reports, then restart $ft_service"
fi
