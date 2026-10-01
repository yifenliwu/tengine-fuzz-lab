# Tengine 靶场操作手册（runbook）

## 目标
在自有靶场对 Tengine 3.1.0 做黑盒网络 fuzz，寻找新的高危内存破坏漏洞（候选 CVE），并完成根因分析报告。

## 快速开始（WSL / Ubuntu / Debian）

```bash
# 1. 搭建（约 5 分钟，编译 2 遍）
sudo bash setup_tengine_lab.sh

# 2. 启动黑盒 fuzz 目标（正常版，端口 18080）
cd /opt/tengine-lab/bin/normal
nohup ./sbin/nginx -p /opt/tengine-lab/bin/normal -c conf/nginx.conf &

# 3. 启动黑盒 fuzzer（建议至少跑 2-6 小时）
cd /opt/tengine-lab/fuzz   # 把 blackfuzz.py 放到 fuzz/ 下
python3 blackfuzz.py --target 127.0.0.1:18080 --workers 4 --duration 21600

# 4. 若有 crashers/crash_*.req 产出 → ASAN 分诊
bash triage.sh
```

## 崩溃判读

- 黑盒层（blackfust.py）：连接重置 + worker PID 数下降双确认，样本落盘 `crashers/`
- ASAN 层（triage.sh）：拿到 `heap-buffer-overflow` 栈后做三件事
  1. 对照已知 CVE 栈：已知两 CVE 的崩溃点都在 `ngx_http_script_copy_capture_code`（上游函数分别是 `regex_start_code`/`regex_end_code`）。**栈不同 = 新漏洞线索**
  2. 最小化请求（二分删减头部/URI 段，保留崩溃）
  3. 根因分析：定位分配 pass 与写入 pass 的不一致点（diff 源码 `src/http/ngx_http_script.c` 及相关模块）

## 新 CVE 判定标准

| 情况 | 结论 |
|---|---|
| ASAN 栈与 CVE-2026-42945/9256 相同 | 已知漏洞，不报 |
| 崩溃在 Tengine 独有模块（concat/sysguard/upstream_check 等） | 高概率新 CVE，优先深挖 |
| 崩溃在核心但根因不同于已知两处 | 新 CVE 候选 |
| 利用性提升（如把潜在 RCE 做实） | 不是新 CVE，但可发重磅研究 |

## 上报流程

1. 检查 Tengine GitHub master 是否已修复（避免报已知问题）
2. 发邮件至 Tengine 安全披露渠道（GitHub SECURITY.md 中列明的安全邮箱），附：最小复现请求 + ASAN 栈 + 根因 diff + 影响版本
3. Alibaba 作为 CNA 分配 CVE 编号；协调披露期通常 90 天
4. 对方确认前不要公开细节

## 注意

- 仅对 127.0.0.1 的自有靶场 fuzz；禁止对公网任何 Tengine 发 payload
- worker_processes=2 是故意调低的：崩溃更快被观察到
- fuzz 期间 CPU 主要消耗在网络栈与 nginx，ASAN 版只用于分诊，不要同时跑
