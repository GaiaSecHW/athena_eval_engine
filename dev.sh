#!/usr/bin/env bash
# Athena Eval Engine 本地开发环境。
# 在项目根目录执行：source ./dev.sh

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "请使用 'source ./dev.sh' 加载开发环境。" >&2
    exit 1
fi

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_ACTIVATE="$PROJECT_ROOT/.venv/bin/activate"

if [[ ! -f "$VENV_ACTIVATE" ]]; then
    echo "未找到虚拟环境：$VENV_ACTIVATE" >&2
    echo "请先创建：python3 -m venv .venv" >&2
    return 1
fi

source "$VENV_ACTIVATE"
export PATH="$HOME/.local/bin:$PATH"

if ! command -v kubectl >/dev/null 2>&1; then
    echo "未找到 kubectl；port-forward 和远程 trace 发现将不可用。" >&2
fi

# 非敏感的本地开发默认值；已有环境变量会被保留。
export EVAL_MYSQL_HOST="${EVAL_MYSQL_HOST:-127.0.0.1}"
export EVAL_MYSQL_PORT="${EVAL_MYSQL_PORT:-3306}"
export EVAL_MYSQL_USER="${EVAL_MYSQL_USER:-eval}"
export EVAL_MYSQL_DATABASE="${EVAL_MYSQL_DATABASE:-athena_eval}"
export EVAL_LLM_BASE_URL="${EVAL_LLM_BASE_URL:-http://127.0.0.1:3030/v1}"
export EVAL_LLM_MODEL="${EVAL_LLM_MODEL:-deepseek_v4_flash_0731}"
export VBENCH_API_URL="${VBENCH_API_URL:-http://127.0.0.1:18083/api/v1}"
export PROJECT_API="${PROJECT_API:-http://127.0.0.1:18081}"
export SCHEDULE_API="${SCHEDULE_API:-http://127.0.0.1:18082}"
export DATA_ROOT="${DATA_ROOT:-/data/files}"

# .env 被 Git 忽略，可放 EVAL_MYSQL_PASSWORD、EVAL_LLM_API_KEY、PLATFORM_TOKEN 等敏感变量。
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    set -a
    source "$PROJECT_ROOT/.env"
    set +a
fi

echo
echo "========================================"
echo " Athena Eval Engine 开发环境已就绪"
echo "========================================"
echo
echo "常用命令："
echo "  python -m uvicorn athena_eval_engine.api.routes.evaluations:app --reload --port 8090"
echo "  python -m py_compile athena_eval_engine/api/routes/evaluations.py"
echo "  bash port-forward.sh"
echo
echo "提示：连远端服务前请在另一终端运行 bash port-forward.sh"
