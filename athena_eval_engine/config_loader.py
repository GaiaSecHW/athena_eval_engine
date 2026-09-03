"""配置加载器 — 从 config.yaml 或环境变量读取（k8s ConfigMap 挂载 config.yaml）。"""
from __future__ import annotations
import os
from pathlib import Path
import yaml

_CONFIG_PATH = os.environ.get("EVAL_CONFIG_FILE", str(Path(__file__).resolve().parent.parent / "config.yaml"))


def _load():
    p = Path(_CONFIG_PATH)
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


_cfg = _load()

# 数据库
DB = _cfg.get("database", {})
DB_HOST = os.environ.get("EVAL_MYSQL_HOST", DB.get("host", "127.0.0.1"))
DB_PORT = int(os.environ.get("EVAL_MYSQL_PORT", DB.get("port", 3306)))
DB_USER = os.environ.get("EVAL_MYSQL_USER", DB.get("user", "root"))
DB_PASSWORD = os.environ.get("EVAL_MYSQL_PASSWORD", DB.get("password", ""))
DB_DATABASE = os.environ.get("EVAL_MYSQL_DATABASE", DB.get("database", "athena_eval"))
SCHEMA_SQL = os.environ.get("EVAL_SCHEMA_SQL", DB.get("schema_sql", "schema.sql"))

# LLM
LLM = _cfg.get("llm", {})
LLM_BASE_URL = os.environ.get("EVAL_LLM_BASE_URL", LLM.get("base_url", "http://127.0.0.1:3030/v1"))
LLM_MODEL = os.environ.get("EVAL_LLM_MODEL", LLM.get("model", "glm-5.2"))
LLM_API_KEY = os.environ.get("EVAL_LLM_API_KEY", LLM.get("api_key", ""))

# V-Bench
VBENCH = _cfg.get("vbench", {})
VBENCH_API_URL = os.environ.get("VBENCH_API_URL", VBENCH.get("api_url", "https://secflow.ai.icsl.huawei.com/vbench/api/v1"))

# 平台 API
PLATFORM = _cfg.get("platform", {})
PROJECT_API = os.environ.get("PROJECT_API", PLATFORM.get("project_api", "http://127.0.0.1:18081"))
SCHEDULE_API = os.environ.get("SCHEDULE_API", PLATFORM.get("schedule_api", "http://127.0.0.1:18082"))
SCHED_POD = os.environ.get("SCHED_POD", PLATFORM.get("sched_pod", ""))
# 数据目录（k8s 部署时 /data 直接挂载；dev 用本地路径或 port-forward 挂载点）
DATA_ROOT = os.environ.get("DATA_ROOT", PLATFORM.get("data_root", "/data/files"))

# 平台 token
PLATFORM_TOKEN = os.environ.get("PLATFORM_TOKEN", _cfg.get("platform_token", ""))
