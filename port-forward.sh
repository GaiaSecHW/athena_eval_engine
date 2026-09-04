#!/bin/bash
# 评测引擎 k8s 端口映射脚本
# 用法：bash port-forward.sh
# 按 Ctrl+C 停止所有映射

NS="secflow-ns"

echo "=== 启动端口映射 ==="

# MySQL（评测引擎数据库）
kubectl -n $NS port-forward svc/eval-engine-mysql 3306:3306 &
echo "MySQL: localhost:3306"

# Platform API（项目/任务列表） - 修正为正确的 service 名称
kubectl -n $NS port-forward svc/secflow-platform-project 18081:80 &
echo "Platform API: localhost:18081"

# Schedule API（kubectl exec 读取 trace）
kubectl -n $NS port-forward svc/chirmera-platform-schedule 18082:80 &
echo "Schedule API: localhost:18082"

# V-Bench API（benchmark 基线）
kubectl -n $NS port-forward svc/vbench-api 18083:80 &
echo "V-Bench API: localhost:18083"

echo ""
echo "=== 端口映射已启动，按 Ctrl+C 停止 ==="
echo "提示：svc 名称可用 kubectl -n secflow-ns get svc 确认"

wait
