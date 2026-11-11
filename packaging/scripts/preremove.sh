# Runs for upgrades too; only a removal stops the service.
case "$ft_format:${1:-}" in
deb:remove | rpm:0 | apk:*) ;;
*) exit 0 ;;
esac

ft_stop
ft_disable
