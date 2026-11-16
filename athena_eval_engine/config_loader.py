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
# 数据目录（k8s 部署时 /data 直接挂载；dev 用本地路径或 port-forward 挂载点）
DATA_ROOT = os.environ.get("DATA_ROOT", PLATFORM.get("data_root", "/data/files"))

# 报告目录（统一单一来源，替代各模块 8 处 os.environ.get 分散解析）
EVAL_REPORTS_DIR = os.environ.get("EVAL_REPORTS_DIR", "/app/reports")

# 静态文件覆盖目录（k8s 下 /data/static 可写，便于热更新 HTML 而无需重建镜像）
EVAL_STATIC_OVERRIDE = os.environ.get("EVAL_STATIC_OVERRIDE", "/data/static")

# 异常日志文件路径（k8s 中通过环境变量配置，默认 /data/logs/eval_errors.log）
EVAL_ERROR_LOG = os.environ.get("EVAL_ERROR_LOG", "/data/logs/eval_errors.log")

# 对外访问地址（日报里的详情链接用；可用 EVAL_PUBLIC_URL 覆盖）
EVAL_PUBLIC_URL = os.environ.get(
    "EVAL_PUBLIC_URL", "http://chimera-g.icsl.huawei.com/eval").rstrip("/")

# 环境标识（green / yellow），日报标题用；系统设置页可覆盖
EVAL_ENV_NAME = os.environ.get("EVAL_ENV_NAME", "")

# 小鲁班消息发送接口
XIAOLUBAN_URL = os.environ.get(
    "XIAOLUBAN_URL", "http://xiaoluban.rnd.huawei.com:80/")


def get_reports_dir() -> str:
    """返回报告目录路径（单一来源）。"""
    return EVAL_REPORTS_DIR


def get_static_override_dir() -> str:
    """返回静态文件覆盖目录路径（单一来源）。"""
    return EVAL_STATIC_OVERRIDE


def get_error_log_path() -> str:
    """返回异常日志文件路径（单一来源）。"""
    return EVAL_ERROR_LOG


# 平台 token
PLATFORM_TOKEN = os.environ.get("PLATFORM_TOKEN", _cfg.get("platform_token", ""))


def _env_bool(name: str, default: bool) -> bool:
    """读取布尔环境变量；未设置时使用 default。"""
    def _parse(value) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "on")

    raw = os.environ.get(name)
    if raw is None:
        return _parse(default)
    return _parse(raw)


# 根因分析（case analysis）插件化配置
# local  = 保持原有 RootCauseAnalyzer 行为（默认）
# remote = 调用远程进化引擎；失败时可按配置回退本地
# shadow = 本地结果为准，同时调用远程做对比，不一致写告警
CASE_ANALYSIS = _cfg.get("case_analysis", {}) or {}
CASE_ANALYSIS_REMOTE = CASE_ANALYSIS.get("remote", {}) or {}
CASE_ANALYSIS_FALLBACK = CASE_ANALYSIS_REMOTE.get("fallback", {}) or {}
CASE_ANALYSIS_SHADOW = CASE_ANALYSIS.get("shadow", {}) or {}

CASE_ANALYSIS_MODE = os.environ.get(
    "EVAL_CASE_ANALYSIS_MODE", CASE_ANALYSIS.get("mode", "local")
).strip().lower()
CASE_ANALYSIS_BASE_URL = os.environ.get(
    "EVAL_CASE_ANALYSIS_BASE_URL", CASE_ANALYSIS_REMOTE.get("base_url", "")
).strip().rstrip("/")
CASE_ANALYSIS_API_PREFIX = os.environ.get(
    "EVAL_CASE_ANALYSIS_API_PREFIX", CASE_ANALYSIS_REMOTE.get("api_prefix", "/v1")
).strip() or "/v1"
CASE_ANALYSIS_TOKEN = os.environ.get(
    "EVAL_CASE_ANALYSIS_TOKEN", CASE_ANALYSIS_REMOTE.get("token", "")
)
CASE_ANALYSIS_TIMEOUT_SECONDS = float(os.environ.get(
    "EVAL_CASE_ANALYSIS_TIMEOUT",
    CASE_ANALYSIS_REMOTE.get("timeout_seconds", 900),
))
CASE_ANALYSIS_POLL_INTERVAL_SECONDS = float(os.environ.get(
    "EVAL_CASE_ANALYSIS_POLL_INTERVAL",
    CASE_ANALYSIS_REMOTE.get("poll_interval_seconds", 2),
))
CASE_ANALYSIS_MAX_CONCURRENCY = int(os.environ.get(
    "EVAL_CASE_ANALYSIS_MAX_CONCURRENCY",
    CASE_ANALYSIS_REMOTE.get("max_concurrency", 10),
))
CASE_ANALYSIS_DETAIL_MODE = os.environ.get(
    "EVAL_CASE_ANALYSIS_DETAIL_MODE",
    CASE_ANALYSIS_REMOTE.get("detail_mode", "artifact"),
).strip().lower()
CASE_ANALYSIS_DETAIL_REQUIRED = _env_bool(
    "EVAL_CASE_ANALYSIS_DETAIL_REQUIRED",
    CASE_ANALYSIS_REMOTE.get("detail_required", True),
)
CASE_ANALYSIS_FALLBACK_ENABLED = _env_bool(
    "EVAL_CASE_ANALYSIS_FALLBACK_ENABLED",
    CASE_ANALYSIS_FALLBACK.get("enabled", True),
)
CASE_ANALYSIS_FALLBACK_MODE = os.environ.get(
    "EVAL_CASE_ANALYSIS_FALLBACK_MODE",
    CASE_ANALYSIS_FALLBACK.get("mode", "local"),
).strip().lower()
CASE_ANALYSIS_SHADOW_AUTHORITATIVE = os.environ.get(
    "EVAL_CASE_ANALYSIS_SHADOW_AUTHORITATIVE",
    CASE_ANALYSIS_SHADOW.get("authoritative", "local"),
).strip().lower()

# gaiasec-server（WebVulnVerify 权威 case↔session 关系源）
GAISEC = _cfg.get("gaiasec", {})
GAISEC_SERVER_URL = os.environ.get("EVAL_GAISEC_SERVER_URL", GAISEC.get("server_url", "http://gaiasec-server"))
