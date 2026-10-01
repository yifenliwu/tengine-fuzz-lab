#!/usr/bin/env bash
# CI 版崩溃样本 ASAN 分诊
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"
cd "$LAB/bin/asan"

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:log_path=$LAB/asan_logs/asan"
pkill -f "bin/asan" 2>/dev/null || true; sleep 1
./sbin/nginx -p "$LAB/bin/asan" -c conf/nginx.conf &
sleep 2

found=0
for f in "$LAB"/fuzz/crashers/crash_*.req; do
    [ -f "$f" ] || continue
    before="$(pgrep -f 'bin/asan' | sort | tr '\n' ' ')"
    timeout 5 python3 - "$f" << 'PYEOF' 2>/dev/null
import socket, sys
raw = open(sys.argv[1], 'rb').read()
s = socket.create_connection(('127.0.0.1', 18080), timeout=3)
s.sendall(raw)
try: s.recv(1024)
except Exception: pass
s.close()
PYEOF
    sleep 1
    after="$(pgrep -f 'bin/asan' | sort | tr '\n' ' ')"
    if [ "$before" != "$after" ] || ls "$LAB"/asan_logs/asan* >/dev/null 2>&1; then
        echo "[!] 分诊命中: $f"
        found=1
        latest="$(ls -t "$LAB"/asan_logs/asan* 2>/dev/null | head -1)"
        [ -n "$latest" ] && cp "$latest" "$LAB/crashers/$(basename "$f" .req).asan.log"
        pkill -f "bin/asan" 2>/dev/null || true; sleep 1
        ./sbin/nginx -p "$LAB/bin/asan" -c conf/nginx.conf &
        sleep 2
    fi
done

pkill -f "bin/asan" 2>/dev/null || true
[ "$found" = "1" ] && echo "[*] ASAN 报告已落盘 crashers/*.asan.log" || echo "[*] 无样本在 ASAN 版复现"
