#!/bin/sh
# usage: boot.sh <kernel version prefix> <build directory> <command...>
# Exits with the command's exit code, or 125 when the kernel never reported one.
set -eu

kernel=$(ls /opt/kernels/vmlinuz-"$1"* | head -1)
build=$2
shift 2

root=$(mktemp -d)
mkdir -p "$root/bin" "$root/lib" "$root/etc" "$root/proc" "$root/sys" "$root/dev" "$root/tmp" \
    "$root/run" "$root/var/tmp" "$root/ft/bin" "$root/ft/tests"

cp /bin/busybox "$root/bin/"
for applet in $(busybox --list); do
    [ "$applet" = busybox ] || ln -sf busybox "$root/bin/$applet"
done
echo "root:x:0:0:root:/:/bin/sh" >"$root/etc/passwd"

for binary in filetrace filetrace-agent tests/ft_workload tests/ft_unit_tests ft_bench_syscalls; do
    cp "$build/$binary" "$root/ft/bin/"
    ldd "$build/$binary" | awk '$3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }'
done | sort -u | while read -r lib; do
    mkdir -p "$root$(dirname "$lib")"
    cp -L "$lib" "$root$lib"
done
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
printf '%s\n' "$*" >"$root/command.sh"

(cd "$root" && find . | cpio -o -H newc --quiet | gzip -1) >/tmp/initramfs.gz

timeout 1800 qemu-system-aarch64 -M virt -cpu cortex-a72 -accel tcg,thread=multi -smp 4 -m 2048 \
    -nographic -no-reboot -nic none -kernel "$kernel" -initrd /tmp/initramfs.gz \
    -append "console=ttyAMA0 quiet panic=-1 rdinit=/init" </dev/null | tr -d '\r' | tee /tmp/vm.log

code=$(sed -n 's/^FT_VM_EXIT=\([0-9]*\).*/\1/p' /tmp/vm.log | tail -1)
exit "${code:-125}"
