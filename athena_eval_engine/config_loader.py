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
# SSL 开关: MySQL 9.x 默认 caching_sha2_password，无 SSL 时 pymysql 需 RSA 加密密码 → 依赖 cryptography。
# 默认 False(开 SSL)，使密码在 TLS 隧道内传输，绕过 RSA。dev port-forward 遇防火墙 SSL reset 时设 true。
DB_SSL_DISABLED = os.environ.get("EVAL_MYSQL_SSL_DISABLED", str(DB.get("ssl_disabled", False))).lower() == "true"
SCHEMA_SQL = os.environ.get("EVAL_SCHEMA_SQL", DB.get("schema_sql", "schema.sql"))

# LLM
LLM = _cfg.get("llm", {})
_DEFAULT_LLM_BASE_URL = "http://127.0.0.1:3030/v1"
LLM_BASE_URL = os.environ.get("EVAL_LLM_BASE_URL", LLM.get("base_url", _DEFAULT_LLM_BASE_URL))
LLM_MODEL = os.environ.get("EVAL_LLM_MODEL", LLM.get("model", "glm-5.2"))
LLM_API_KEY = os.environ.get("EVAL_LLM_API_KEY", LLM.get("api_key", ""))
# 本地默认端点且无凭据时不访问 LLM；远程无鉴权网关保持兼容。无鉴权本地模型可显式开启。
_DEFAULT_LLM_ENABLED = bool(LLM_API_KEY) or LLM_BASE_URL != _DEFAULT_LLM_BASE_URL
LLM_ENABLED = os.environ.get("EVAL_LLM_ENABLED", str(LLM.get("enabled", _DEFAULT_LLM_ENABLED))).lower() == "true"

# V-Bench
VBENCH = _cfg.get("vbench", {})
VBENCH_API_URL = os.environ.get("VBENCH_API_URL", VBENCH.get("api_url", "http://vbench-api:80/api/v1"))

# 漏洞中心（Chimera，secflow-platform-vuln）— V-Bench 测评集的原始数据源
VULN_CENTER = _cfg.get("vuln_center", {})
VULN_CENTER_API_URL = os.environ.get("EVAL_VULN_CENTER_API_URL", VULN_CENTER.get("api_url", "http://secflow-platform-vuln:80/api/vuln/cases"))

# 平台 API
PLATFORM = _cfg.get("platform", {})
PROJECT_API = os.environ.get("PROJECT_API", PLATFORM.get("project_api", "http://secflow-platform-project:80"))
SCHEDULE_API = os.environ.get("SCHEDULE_API", PLATFORM.get("schedule_api", "http://chirmera-platform-schedule:80"))
# 漏洞 case 平台 API。集群内使用 Service 地址（与 vuln_center 同源）。
VULN_API_URL = os.environ.get("VULN_API_URL", PLATFORM.get(
    "vuln_api_url", "http://secflow-platform-vuln:80"))
SCHED_POD = os.environ.get("SCHED_POD", PLATFORM.get("sched_pod", ""))
# 数据目录（k8s 部署时 /data 直接挂载；dev 用本地路径或 port-forward 挂载点）
DATA_ROOT = os.environ.get("DATA_ROOT", PLATFORM.get("data_root", "/data/files"))

# 平台 token
PLATFORM_TOKEN = os.environ.get("PLATFORM_TOKEN", _cfg.get("platform_token", ""))
