FROM python:3.12-slim

# 换清华 apt 镜像(加速国内构建)
RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null \
    || sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list 2>/dev/null \
    || true

WORKDIR /app

# 系统依赖 + 运维排障工具:
#   curl — 健康检查
#   procps(ps/top)、iproute2(ip)、iputils-ping(ping)、dnsutils(dig/nslookup)、net-tools(netstat/ifconfig)
#   wget、vim-tiny、less、jq、lsof、telnet、tcpdump、file、ca-certificates
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    procps iproute2 iputils-ping dnsutils net-tools \
    wget vim-tiny less jq lsof telnet tcpdump file ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 先装依赖（利用缓存层,用清华 PyPI 镜像）
COPY pyproject.toml ./
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn -e ".[test]"

# 拷贝代码 + schema（config.yaml 由 k8s ConfigMap 覆盖，dev 用本地文件）
COPY athena_eval_engine/ ./athena_eval_engine/
COPY schema.sql ./schema.sql
# 运维/分析脚本（check_causal_levels.py、diff_trace_fingerprint.py）
COPY scripts/ ./scripts/

# TZ + 运行时设置（其余配置由 k8s ConfigMap/Secret 注入，dev 用本地 config.yaml）
ENV TZ=Asia/Shanghai \
    PYTHONUNBUFFERED=1

EXPOSE 8090

# fd 上限：先抬到 hard limit（容器内通常是 524288），失败再退回 65536。
# 单靠这里不够——kubectl exec 起的新进程继承的是镜像默认 soft limit(1024)，
# 所以应用启动时也会再设一次（evaluations._raise_nofile_limit）。
CMD ["sh", "-c", "ulimit -n unlimited 2>/dev/null || ulimit -n 65536; ulimit -n; exec python -m uvicorn athena_eval_engine.api.routes.evaluations:app --host 0.0.0.0 --port 8090 --workers 1"]
