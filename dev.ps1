# =====================================================
# Athena Eval Engine — 本地开发启动脚本
# 用法：在项目根目录执行  . .\dev.ps1
# =====================================================

# 激活虚拟环境
& "$PSScriptRoot\.venv\Scripts\Activate.ps1"

# ---- 环境变量（来自 k8s ConfigMap + Secret，优先级高于 config.yaml）----
$env:EVAL_MYSQL_HOST     = "127.0.0.1"
$env:EVAL_MYSQL_PORT     = "3306"
$env:EVAL_MYSQL_USER     = "eval"
$env:EVAL_MYSQL_PASSWORD = "Icsl@eval123456"
$env:EVAL_MYSQL_DATABASE = "athena_eval"

$env:EVAL_LLM_BASE_URL   = "http://127.0.0.1:3030/v1"
$env:EVAL_LLM_MODEL      = "deepseek_v4_flash_0731"
$env:EVAL_LLM_API_KEY    = "sk-bf-d66666fd-d5db-40cc-a096-cd7e621c3eeb"

$env:VBENCH_API_URL      = "http://127.0.0.1:18083/api/v1"
$env:PROJECT_API         = "http://127.0.0.1:18081"
$env:SCHEDULE_API        = "http://127.0.0.1:18082"
$env:DATA_ROOT           = "$PSScriptRoot\tests\fixtures\fetched"

$env:PLATFORM_TOKEN      = "k7adi5IagKAZ54aNxS77NsDZSpWveyPn6iaxmrwl-G4LXnETGWMbEaSsX1KVuqh8"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Athena Eval Engine 开发环境已就绪" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "常用命令：" -ForegroundColor Yellow
Write-Host "  python -m uvicorn athena_eval_engine.api.routes.evaluations:app --reload --port 8090  # 启动API"
Write-Host "  pytest tests/ -v                  # 跑全部测试"
Write-Host "  pytest tests/test_metrics.py -v   # 只跑指标测试"
Write-Host ""
Write-Host "提示：连远端服务需先在 Git Bash 中运行 port-forward.sh" -ForegroundColor DarkGray
Write-Host ""