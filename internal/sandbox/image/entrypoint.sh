#!/bin/sh
set -u
cp -a /opt/burnbox/home/. "$HOME"/
cp -a /src/. /work/ 2>/dev/null
cd /work
python3 /opt/burnbox/dnsstub.py /out/dns.log /tmp/dns.ready &
i=0
while [ ! -e /tmp/dns.ready ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
timeout -k 5 "$BURNBOX_TIMEOUT" strace -ff -qq -s 256 -e signal=none \
  -e trace=execve,open,openat,connect,clone,clone3,fork,vfork \
  -o /out/trace sh -c "$BURNBOX_CMD" >/out/cmd.log 2>&1
echo $? >/out/exit
