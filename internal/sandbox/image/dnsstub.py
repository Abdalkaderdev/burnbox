import socket
import sys
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 53))
log = open(sys.argv[1], "a", buffering=1)
open(sys.argv[2], "w").close()
while True:
    data, addr = sock.recvfrom(4096)
    if len(data) < 17:
        continue
    i, labels = 12, []
    while i < len(data) and data[i] and len(labels) < 64:
        n = data[i]
        labels.append(data[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += n + 1
    end = i + 5
    qtype = int.from_bytes(data[i + 1:i + 3], "big")
    log.write("%.3f %s %d\n" % (time.time(), ".".join(labels), qtype))
    flags = 0x8000 | (int.from_bytes(data[2:4], "big") & 0x7900) | 0x0080 | 3
    sock.sendto(data[:2] + flags.to_bytes(2, "big") + data[4:6] + bytes(6) + data[12:end], addr)
