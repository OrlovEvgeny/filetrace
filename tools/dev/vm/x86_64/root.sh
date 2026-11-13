#!/bin/sh
# usage: root.sh <kernel version prefix> <directory with filetrace and filetrace-agent>
#                <output directory> <command...>
# Runs in the amd64 image of this directory and leaves in the output directory the kernel as
# vmlinuz and the guest's root as initramfs.gz, for boot.sh --arch x86_64: busybox, PHP and curl
# with their libraries, the static filetrace binaries, tests/returns and its ft_refuse_uretprobe.
set -eu

kernel=$(ls /opt/kernels/vmlinuz-"$1"* 2>/dev/null | head -1)
if [ -z "$kernel" ]; then
    echo "root.sh: no kernel $1 among these:" >&2
    ls /opt/kernels >&2
    exit 2
fi
bin=$2
out=$3
shift 3

root=$(mktemp -d)
mkdir -p "$root/bin" "$root/etc" "$root/proc" "$root/sys" "$root/dev" "$root/tmp" "$root/run" \
    "$root/var/tmp" "$root/ft/bin" "$root/ft/tests"

cp /bin/busybox "$root/bin/"
for applet in $(busybox --list); do
    [ "$applet" = busybox ] || ln -s busybox "$root/bin/$applet"
done
echo "root:x:0:0:root:/:/bin/sh" >"$root/etc/passwd"
printf '127.0.0.1 localhost\n::1 localhost\n' >"$root/etc/hosts"
printf 'hosts: files\n' >"$root/etc/nsswitch.conf"

cp "$bin/filetrace" "$bin/filetrace-agent" "$root/ft/bin/"
cp -r /src/tests/returns "$root/ft/tests/"
gcc -std=c23 -O2 -Wall -Wextra -Werror -static -o "$root/ft/bin/ft_refuse_uretprobe" \
    /src/tests/returns/refuse_uretprobe.c

for binary in /usr/bin/php /usr/bin/curl; do
    mkdir -p "$root$(dirname "$binary")"
    cp -L "$binary" "$root$binary"
    ldd "$binary" | awk '$3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }'
done | sort -u | while read -r lib; do
    mkdir -p "$root$(dirname "$lib")"
    cp -L "$lib" "$root$lib"
done

cat >"$root/init" <<'INIT'
#!/bin/sh
export PATH=/ft/bin:/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t tmpfs tmp /tmp
mount -t tmpfs run /run
mount -t bpf bpf /sys/fs/bpf 2>/dev/null
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
ip link set lo up
hostname filetrace-vm
cd /ft
sh /command.sh
echo "FT_VM_EXIT=$?"
poweroff -f
INIT
chmod +x "$root/init"
printf '%s\n' "$*" >"$root/command.sh"

(cd "$root" && find . | cpio -o -H newc -R 0:0 --quiet | gzip -1) >"$out/initramfs.gz"
cp "$kernel" "$out/vmlinuz"
