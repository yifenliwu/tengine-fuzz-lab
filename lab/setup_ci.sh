#!/usr/bin/env bash
# Tengine 3.1.0 靶场搭建（CI 版，兼容 root/sudo）
# 用法: LAB_DIR 可选，默认脚本所在目录
set -e
LAB="$(cd "$(dirname "$0")" && pwd)"
cd "$LAB"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi

echo "[*] 安装依赖..."
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq build-essential libpcre2-dev libpcre3-dev zlib1g-dev libssl-dev curl > /dev/null 2>&1 || \
$SUDO apt-get install -y -qq build-essential libpcre2-dev zlib1g-dev libssl-dev curl > /dev/null

mkdir -p "$LAB"/{bin,fuzz,conf,html,crashers,asan_logs}
echo "[*] 下载 Tengine 3.1.0 源码..."
if [ ! -d tengine-3.1.0 ]; then
    curl -sL https://github.com/alibaba/tengine/archive/refs/tags/3.1.0.tar.gz | tar xz
fi
cd tengine-3.1.0

echo "[*] 编译正常版（黑盒 fuzz 目标）..."
./configure --prefix="$LAB/bin/normal" --with-cc-opt="-g -O1 -fno-omit-frame-pointer" \
    --without-http_upstream_keepalive_module > configure_normal.log 2>&1
make -j"$(nproc)" > make_normal.log 2>&1 && make install > /dev/null

echo "[*] 编译 ASAN 版（崩溃分诊）..."
make clean > /dev/null 2>&1 || true
./configure --prefix="$LAB/bin/asan" --with-cc-opt="-g -O1 -fsanitize=address -fno-omit-frame-pointer" \
    --with-ld-opt="-fsanitize=address" \
    --without-http_upstream_keepalive_module > configure_asan.log 2>&1
make -j"$(nproc)" > make_asan.log 2>&1 && make install > /dev/null

echo "[*] 写入 rewrite 重规则配置..."
cat > "$LAB/conf/nginx.conf" << 'EOF'
worker_processes 2;
daemon off;
error_log logs/error.log warn;
pid logs/nginx.pid;
events { worker_connections 1024; }
http {
    access_log off;
    server {
        listen 18080;
        root html;
        location / {
            # 已知 CVE-2026-9256 对照模式
            rewrite ^/((.+))$ /index.html?q=$1$2 last;
            # 混合捕获组（fuzz 覆盖面）
            rewrite ^/vuln/(.*)(/.*)$ /x?a=$1&b=$2 last;
            rewrite ^/rift/(.*)/(.*)\?(.*)$ /y?c=$1$2?$3 last;
            rewrite ^/p/([0-9]+)-([a-z]+)-(.*)$ /z?d=$1$2$3? last;
        }
        location /concat/ { concat_max_files 20; }
    }
}
EOF
cp "$LAB/conf/nginx.conf" "$LAB/bin/normal/conf/nginx.conf"
cp "$LAB/conf/nginx.conf" "$LAB/bin/asan/conf/nginx.conf"
echo OK > "$LAB/html/index.html"

echo "[*] 启动自检..."
cd "$LAB/bin/normal"
./sbin/nginx -t
./sbin/nginx -p "$LAB/bin/normal" -c conf/nginx.conf &
sleep 2
curl -s -o /dev/null -w "目标就绪 HTTP %{http_code}\n" http://127.0.0.1:18080/ || { ./sbin/nginx -s stop; exit 1; }
./sbin/nginx -s stop
cd "$LAB/bin/asan" && ASAN_OPTIONS=detect_leaks=0 ./sbin/nginx -t && echo "asan版 配置OK"
echo "[完成] 靶场就绪: $LAB"
