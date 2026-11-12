"""Run bounded loopback checks against both probe attachments; requires root/BPF."""
import argparse
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument("--build", type=Path, default=Path("build/mapped-probe"))
parser.add_argument("--php", action="store_true")
args = parser.parse_args()


def counters(mode, command, **kwargs):
    completed = subprocess.run(
        [str(args.build / "run"), str(args.build / "probe.bpf.o"), mode, "--", *command],
        check=True, capture_output=True, text=True, timeout=15, **kwargs)
    result = dict((key, int(value)) for key, value in
                  (line.split("=", 1) for line in completed.stdout.splitlines()))
    print(mode, " ".join(f"{k}={v}" for k, v in result.items()), flush=True)
    return result


def php_case(mode, function, buffered):
    with tempfile.TemporaryDirectory(prefix="mapped-php-") as directory:
        payload = Path(directory) / "payload.bin"
        payload.write_bytes(b"x" * 65536)
        with socket.socket() as listener, socket.socket() as sender:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            sender.connect(listener.getsockname())
            peer, _ = listener.accept()
            with peer:
                peer.settimeout(10)
                received = bytearray()
                errors = []

                def drain():
                    try:
                        while len(received) < 65536:
                            chunk = peer.recv(65536)
                            if not chunk:
                                raise RuntimeError("short PHP output")
                            received.extend(chunk)
                    except Exception as error:
                        errors.append(error)

                thread = threading.Thread(target=drain, daemon=True)
                thread.start()
                body = ('readfile($argv[1]);' if function == "readfile" else
                        '$f=fopen($argv[1],"rb"); fpassthru($f); fclose($f);')
                if buffered:
                    body = "ob_start(); " + body + " ob_end_flush();"
                # The loader's child keeps its PID through Python -> PHP exec.
                wrapper = (
                    "import os,sys; os.dup2(int(sys.argv[1]),1); "
                    "os.execvp('php', ['php','-n','-d','output_buffering=0',"
                    "'-r',sys.argv[2],sys.argv[3]])")
                result = counters(mode, [sys.executable, "-c", wrapper,
                                        str(sender.fileno()), body, str(payload)],
                                  pass_fds=(sender.fileno(),))
                thread.join(timeout=11)
                assert not thread.is_alive() and not errors, errors
                assert received == b"x" * 65536
                assert result["observed_bytes"] == (0 if buffered else 65536), result
                print(f"PASS PHP {function} buffered={buffered}", flush=True)


for mode in ("fentry", "kprobe"):
    result = counters(mode, [sys.executable, str(HERE / "workload.py")])
    assert result == dict(sends=5, unsupported=0, multi_vector=1, invalid_range=0,
                          vma_miss=0, anonymous=1, unsafe_mapping=2, non_regular=0,
                          mapped_readonly=1, observed_bytes=4096), result
    if args.php:
        for function in ("readfile", "fpassthru"):
            for buffered in (False, True):
                php_case(mode, function, buffered)
print("PASS mapped-send diagnostics")
