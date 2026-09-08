#!/bin/bash
# port-forward.sh — k8s 端口映射（自动重连）
# 用法：bash port-forward.sh    Ctrl+C 停止

NS="secflow-ns"
export PATH="$HOME/.local/bin:$PATH"

echo "=== 启动端口映射（自动重连） ==="

cleanup() {
    echo ""; echo "Stopping all port-forwards..."
    kill ${PIDS[@]} 2>/dev/null
    wait 2>/dev/null
    exit 0
}
trap cleanup INT TERM

start_forward() {
    local svc=$1 ports=$2
    while true; do
        echo "[$(date +%H:%M:%S)] start $svc ..."
        kubectl -n $NS port-forward $svc $ports 2>&1
        echo "[$(date +%H:%M:%S)] WARN: $svc down, retry in 3s..."
        sleep 3
    done
}

PIDS=()

start_forward svc/eval-engine-mysql        3306:3306 &
PIDS+=($!)
echo "  svc/eval-engine-mysql -> localhost:3306"

start_forward svc/secflow-platform-project 18081:80 &
PIDS+=($!)
echo "  svc/secflow-platform-project -> localhost:18081"

start_forward svc/chirmera-platform-schedule 18082:80 &
PIDS+=($!)
echo "  svc/chirmera-platform-schedule -> localhost:18082"

start_forward svc/vbench-api 18083:80 &
PIDS+=($!)
echo "  svc/vbench-api -> localhost:18083"

start_forward svc/secflow-platform-vuln 18084:80 &
PIDS+=($!)
echo "  svc/secflow-platform-vuln -> localhost:18084"

echo ""
echo "=== 端口映射已启动（自动重连），Ctrl+C 停止 ==="
echo "hint: kubectl -n secflow-ns get svc"

wait
