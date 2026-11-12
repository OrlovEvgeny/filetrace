"""Small loopback workload; only our own PID is observed by the probe."""
import mmap
import os
import socket
import tempfile

with tempfile.TemporaryFile() as f:
    f.write(b'x' * 4096)
    f.flush()
    # Reopen read-only so a shared mapping does not have VM_MAYWRITE.
    fd = os.open(f'/proc/self/fd/{f.fileno()}', os.O_RDONLY)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        with socket.socket() as sender:
            sender.settimeout(3)
            sender.connect(listener.getsockname())
            peer, _ = listener.accept()
            with peer:
                peer.settimeout(3)
                def transmit(buf):
                    sender.sendall(buf)
                    remaining = len(buf)
                    while remaining:
                        data = peer.recv(remaining)
                        assert data
                        remaining -= len(data)
                with mmap.mmap(fd, 4096, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ) as mapped:
                    transmit(mapped)
                    transmit(bytes(mapped))
                    assert sender.sendmsg([b'header', memoryview(mapped)]) == 4102
                    remaining = 4102
                    while remaining:
                        data = peer.recv(remaining)
                        assert data
                        remaining -= len(data)
                with mmap.mmap(fd, 4096, flags=mmap.MAP_PRIVATE,
                               prot=mmap.PROT_READ | mmap.PROT_WRITE) as copied:
                    copied[0] = ord('y')
                    transmit(copied)
                with mmap.mmap(-1, 4096) as anon:
                    anon[:] = b'z' * 4096
                    transmit(anon)
    os.close(fd)
