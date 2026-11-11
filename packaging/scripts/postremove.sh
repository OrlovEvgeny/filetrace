case "$ft_format:${1:-}" in
deb:remove | rpm:0)
    ft_daemon_reload
    ;;
deb:purge)
    rm -f /var/log/filetrace-agent.log /var/log/filetrace-agent.log.*
    ;;
esac
