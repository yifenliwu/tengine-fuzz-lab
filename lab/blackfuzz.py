#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tengine 黑盒网络 Fuzzer —— 靶场专用（本地授权研究）

策略：
1. 语法引导的 URI/rewrite/头部 payload 生成（对准 rewrite 引擎、uri 转义、捕获组）
2. 崩溃检测：响应异常（连接重置/空响应/超时）+ worker PID 变化双确认
3. 崩溃样本自动落盘 crashers/，供 ASAN 版分诊

用法：python3 blackfuzz.py --target 127.0.0.1:18080 --workers 4 --duration 3600
"""
import argparse
import hashlib
import os
import random
import socket
import subprocess
import sys
import threading
import time

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crashers")
PID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "normal", "logs", "nginx.pid")

CHARS = ["+", "%2b", " ", "%20", "%25", "%", "..", "./", "/", "?", "&", "=", "#",
         "a", "A", "9", "\x00", "\xff", "%c0%af", "%ff", "~1", "(", ")", "$1", "$2"]
PATH_SEGS = ["vuln", "rift", "p", "concat", "status", "1", "x"]
HOP = ["Range", "Referer", "X-Forwarded-For", "Accept-Language", "Cookie",
       "X-Real-IP", "If-Modified-Since", "Content-Type"]


def gen_uri(rng):
    parts = []
    for _ in range(rng.randint(1, 12)):
        parts.append(rng.choice(PATH_SEGS))
        if rng.random() < 0.5:
            parts.append(rng.choice(CHARS) * rng.randint(1, 4))
        if rng.random() < 0.3:
            parts.append("/" * rng.randint(1, 3))
    uri = "/".join(parts)
    if rng.random() < 0.4:
        uri += "?" + "".join(rng.choice(CHARS) for _ in range(rng.randint(1, 30)))
    return uri[:4096]


def gen_headers(rng):
    hs = []
    for _ in range(rng.randint(0, 4)):
        name = rng.choice(HOP)
        val = "".join(rng.choice(CHARS) for _ in range(rng.randint(1, 40)))
        hs.append(f"{name}: {val}")
    if rng.random() < 0.1:
        hs.append(f"Range: bytes={rng.randint(0,9)}-{rng.choice(['0-18446744073709551615','5-',''])}")
    return "\r\n".join(hs)


def worker_pid():
    try:
        with open(PID_FILE) as f:
            return int(f.read().strip())
    except Exception:
        return None


def workers_count():
    try:
        out = subprocess.run(["pgrep", "-P", str(worker_pid())],
                             capture_output=True, text=True, timeout=5)
        return len([l for l in out.stdout.split() if l.strip()])
    except Exception:
        return -1


def send_probe(host, port, raw, timeout=3.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(raw)
        try:
            data = s.recv(2048)
        except socket.timeout:
            data = b""
        s.close()
        return data
    except (ConnectionResetError, BrokenPipeError):
        return None  # 疑似崩溃
    except socket.timeout:
        return b""


def fuzzer(host, port, duration, wid, stats):
    rng = random.Random(time.time() * 1000 + wid)
    end = time.time() + duration
    baseline_workers = workers_count()
    while time.time() < end:
        uri = gen_uri(rng)
        raw = f"GET {uri} HTTP/1.1\r\nHost: {host}\r\n{gen_headers(rng)}\r\nConnection: close\r\n\r\n".encode("latin-1", "ignore")
        resp = send_probe(host, port, raw)
        stats["req"] += 1
        crash = False
        if resp is None:
            crash = True
        elif resp == b"" and rng.random() < 0.05:  # 偶发空响应可能是慢，复核一次
            time.sleep(0.2)
            if send_probe(host, port, raw) is None:
                crash = True
        if crash:
            # 复核：服务是否真的挂了 vs 单次抖动
            time.sleep(0.3)
            ping = send_probe(host, port, b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
            now_workers = workers_count()
            if ping is None or (now_workers not in (-1,) and now_workers < baseline_workers):
                stats["crash"] += 1
                h = hashlib.sha256(raw).hexdigest()[:16]
                with open(os.path.join(OUT, f"crash_{h}.req"), "wb") as f:
                    f.write(raw)
                print(f"[W{wid}] CRASH! workers {baseline_workers}->{now_workers} 样本: crashers/crash_{h}.req", flush=True)
                # 等待 master 拉起新 worker 再继续
                for _ in range(20):
                    time.sleep(1)
                    if workers_count() >= baseline_workers:
                        break
                baseline_workers = workers_count()
        if stats["req"] % 500 == 0:
            print(f"[W{wid}] 请求 {stats['req']} 崩溃 {stats['crash']}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="127.0.0.1:18080")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--duration", type=int, default=3600)
    args = ap.parse_args()
    host, port = args.target.rsplit(":", 1)
    os.makedirs(OUT, exist_ok=True)
    from collections import defaultdict
    stats = defaultdict(int)
    threads = [threading.Thread(target=fuzzer, args=(host, int(port), args.duration, i, stats), daemon=True) for i in range(args.workers)]
    for t in threads: t.start()
    for t in threads: t.join()
    print(f"[完成] 总请求 {stats['req']}，确认崩溃 {stats['crash']}，样本在 {OUT}")


if __name__ == "__main__":
    main()
