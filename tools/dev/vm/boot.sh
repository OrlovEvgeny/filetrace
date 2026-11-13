#!/bin/sh
# usage: boot.sh <kernel version prefix> <build directory> <command...>
#        boot.sh --arch x86_64 <directory with vmlinuz and initramfs.gz>
# Exits with the command's exit code, or 125 when the kernel never reported one.
# A rootfs.tar in the build directory, such as the acceptance image's filesystem, is unpacked
# under the root first, with the acceptance scenarios in /acceptance.
# An x86_64 guest comes from x86_64/root.sh and runs under KVM when /dev/kvm opens here.
set -eu

# boot <kernel> <initramfs> <memory in MB> <console> <QEMU and its machine...>
boot() {
    kernel=$1
    initramfs=$2
    memory=$3
    console=$4
    shift 4
    timeout 1800 "$@" -smp 4 -m "$memory" \
        -nographic -no-reboot -nic none -kernel "$kernel" -initrd "$initramfs" \
        -append "console=$console quiet panic=-1 rdinit=/init" </dev/null |
        tr -d '\r' | tee /tmp/vm.log

    code=$(sed -n 's/^FT_VM_EXIT=\([0-9]*\).*/\1/p' /tmp/vm.log | tail -1)
    exit "${code:-125}"
}

if [ "$1" = --arch ] && [ "$2" = x86_64 ]; then
    # Opening <> would create a missing /dev/kvm as a file.
    if [ -c /dev/kvm ] && (: <>/dev/kvm) 2>/dev/null; then
        echo "x86_64 guest under KVM"
        accel=kvm
    else
        echo "x86_64 guest under emulation: no usable /dev/kvm"
        accel=tcg,thread=multi
    fi
    boot "$3/vmlinuz" "$3/initramfs.gz" 2048 ttyS0 \
        qemu-system-x86_64 -M q35 -cpu max -accel "$accel"
fi

kernel=$(ls /opt/kernels/vmlinuz-"$1"* | head -1)
build=$2
shift 2

root=$(mktemp -d)
memory=2048
base=
if [ -f "$build/rootfs.tar" ]; then
    base=1
    memory=3072
    tar -x -f "$build/rootfs.tar" -C "$root"
    cp -r /src/tests/acceptance "$root/acceptance"
fi
mkdir -p "$root/bin" "$root/lib" "$root/etc" "$root/proc" "$root/sys" "$root/dev" "$root/tmp" \
    "$root/run" "$root/var/tmp" "$root/ft/bin" "$root/ft/tests"

cp /bin/busybox "$root/bin/"
for applet in $(busybox --list); do
    [ "$applet" = busybox ] || [ -e "$root/bin/$applet" ] || ln -s busybox "$root/bin/$applet"
done
[ -e "$root/etc/passwd" ] || echo "root:x:0:0:root:/:/bin/sh" >"$root/etc/passwd"
printf '127.0.0.1 localhost\n::1 localhost\n' >"$root/etc/hosts"

for binary in filetrace filetrace-agent tests/ft_workload tests/ft_unit_tests ft_bench_syscalls; do
    cp "$build/$binary" "$root/ft/bin/"
    ldd "$build/$binary" | awk '$3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }'
done | sort -u | while read -r lib; do
    mkdir -p "$root$(dirname "$lib")"
    cp -L "$lib" "$root$lib"
done
# The workload linked to the shared C library, for the checks of looked-up names.
mkdir -p "$root/ft/bin/dynamic"
cp "$build/tests/dynamic/ft_workload" "$root/ft/bin/dynamic/"
# A PHP-FPM pool and a FastCGI client, for the checks of PHP request scripts.
for binary in /usr/sbin/php-fpm* /usr/bin/cgi-fcgi; do
    [ -e "$binary" ] || continue
    mkdir -p "$root$(dirname "$binary")"
    cp -L "$binary" "$root$binary"
    ldd "$binary" | awk '$3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }'
done | sort -u | while read -r lib; do
    [ -e "$root$lib" ] && continue
    mkdir -p "$root$(dirname "$lib")"
    cp -L "$lib" "$root$lib"
done
[ -e "$root/usr/bin/cgi-fcgi" ] && ln -sf /usr/bin/cgi-fcgi "$root/bin/cgi-fcgi"
cp -r /src/tests/integration "$root/ft/tests/"
cp /src/benchmarks/run.sh "$root/ft/bin/bench.sh"

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
if [ -n "$base" ]; then
    printf 'export PATH=/ft/bin:/usr/sbin:/usr/bin:/sbin:/bin\n' >"$root/command.sh"
fi
printf '%s\n' "$*" >>"$root/command.sh"

(cd "$root" && find . | cpio -o -H newc --quiet | gzip -1) >/tmp/initramfs.gz

boot "$kernel" /tmp/initramfs.gz "$memory" ttyAMA0 \
    qemu-system-aarch64 -M virt -cpu cortex-a72 -accel tcg,thread=multi
