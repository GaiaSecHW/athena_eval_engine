# DTS 问题单回归验证接口文档

## 概述

回归验证流程用于判断问题单对应的误报是否已消除。流程分两步：

1. **按任务 ID 查询问题单** — 获取某个挖掘任务下产生的全部问题单
2. **提交回归验证** — 对每个问题单提交漏洞是否仍然存在的判定

### 典型调用流程

```
步骤 1: GET /api/v2/dts/by-task/{task_id}
        → 获取问题单列表 [{dts_id, vuln_title, case_type, raw_report}, ...]

步骤 2: 对每个 dts_id，POST /api/v2/dts/regression-verify
        → 判断误报是否消除（passed/failed）
```

---

## 接口 1：按任务 ID 查询问题单

### 请求

```
GET /api/v2/dts/by-task/{task_id}
```

#### 路径参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `task_id` | string | 是 | 原始数据任务 ID（评测 manifest 中的 task_id） |

#### 查询参数

无。

#### 请求体

无。

### 响应

#### 成功响应（200）

```json
{
  "issues": [
    {
      "dts_id": "DTS-6294DF09",
      "vuln_title": "GitCode Actions 接口 limit 参数无上限校验导致数据库 DoS",
      "case_type": "FP",
      "raw_report": "# 漏洞报告\n\n## 漏洞描述\n接口 /v8/actions/workflow/list 的 limit 参数缺少上限校验..."
    },
    {
      "dts_id": "DTS-A1B2C3D4",
      "vuln_title": "用户输入未过滤导致 XSS",
      "case_type": "FN",
      "raw_report": "# 漏洞报告\n\n## 漏洞描述\n用户输入未经过滤直接输出到页面..."
    }
  ],
  "count": 2
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `issues` | array | 问题单列表（精简版） |
| `issues[].dts_id` | string | 问题单 ID，用于后续回归验证 |
| `issues[].vuln_title` | string | 漏洞标题 |
| `issues[].case_type` | string | 问题单类型：`FP`=误报单 / `FN`=漏报单 |
| `issues[].raw_report` | string | 基线对应原始漏洞报告（Markdown 格式，从 `analysis_data_path` 指向的 JSON 文件 `description` 字段读取） |
| `count` | int | 问题单总数 |

#### 说明

- 同一个 case + cause_code + breakpoint_level 可能因多次评测产生多条记录，接口已按 `created_at` 降序去重，只返回最新评测的记录。
- 如果表不存在或查询异常，返回 `{"issues": [], "count": 0}`，不报错。
- `raw_report` 从 PVC 持久化路径 `/app/reports/{evaluation_id}_dts_{case_id}.json` 的 `description` 字段读取，pod 重启不丢失；按 `case_id` 去重缓存避免同 case 多条问题单重复读文件；文件缺失或无 `analysis_data_path` 时返回空字符串。

---

## 接口 2：回归验证

### 请求

```
POST /api/v2/dts/regression-verify
Content-Type: application/json
```

#### 请求体

```json
{
  "task_id": "ae6ae5567f984d0eb05f1f09",
  "dts_id": "DTS-6294DF09",
  "vuln_title": "GitCode Actions 接口 limit 参数无上限校验导致数据库 DoS",
  "vuln_description": "接口 /v8/actions/workflow/list 的 limit 参数缺少上限校验...",
  "is_vulnerable": false
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `task_id` | string | 是 | 原始数据任务 ID，必须与问题单的 task_id 匹配 |
| `dts_id` | string | 是 | 问题单 ID（从接口 1 获取） |
| `vuln_title` | string | 否 | 漏洞标题（默认空字符串） |
| `vuln_description` | string | 否 | 漏洞描述（默认空字符串） |
| `is_vulnerable` | bool | 是 | 漏洞是否仍然存在 |

#### `is_vulnerable` 判定规则

| `is_vulnerable` | 含义 | 问题单状态 | `replay_result` |
|-----------------|------|-----------|-----------------|
| `false` | 漏洞已被消除，误报已修复 | `passed`（关闭） | `false_positive_resolved` |
| `true` | 漏洞仍然存在，误报未修复 | `failed`（未关闭，可再次回归） | `still_vulnerable` |

### 响应

#### 成功响应（200）

```json
{
  "dts_id": "DTS-6294DF09",
  "task_id": "ae6ae5567f984d0eb05f1f09",
  "vuln_title": "GitCode Actions 接口 limit 参数无上限校验导致数据库 DoS",
  "vuln_description": "接口 /v8/actions/workflow/list 的 limit 参数缺少上限校验...",
  "is_vulnerable": false,
  "result": "false_positive_resolved",
  "status": "passed",
  "message": "漏洞已消除，误报已修复",
  "issue": {
    "dts_id": "DTS-6294DF09",
    "evaluation_id": "EV-20261016164014-7357",
    "task_id": "ae6ae5567f984d0eb05f1f09",
    "case_id": "case-20260730-143025-ae39a48a98",
    "vuln_title": "GitCode Actions 接口 limit 参数无上限校验导致数据库 DoS",
    "agent_type": "turing,webvuln_verify",
    "case_type": "FP",
    "cause_code": "H",
    "breakpoint_level": "L8",
    "breakpoint_desc": "...",
    "evidence_uri": null,
    "root_cause": "{...}",
    "solution": "[...]",
    "analysis_data_path": "EV-20261016164014-7357_dts_case-20260730-143025-ae39a48a98.json",
    "replay_eval_id": "ae6ae5567f984d0eb05f1f09",
    "replay_result": "false_positive_resolved",
    "replay_data": "{\"task_id\":\"ae6ae5567f984d0eb05f1f09\",\"vuln_title\":\"...\",\"vuln_description\":\"...\",\"is_vulnerable\":false,\"result\":\"false_positive_resolved\",\"message\":\"漏洞已消除，误报已修复\"}",
    "status": "passed",
    "responsibility": "agent",
    "created_at": "2026-10-18T13:32:24.688000",
    "updated_at": "2026-10-18T14:05:00.123000",
    "closed_at": "2026-10-18T14:05:00.123000",
    "evaluation_name": "运行态-turing-2",
    "analysis_data": { ... },
    "session_chains": { ... }
  }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `dts_id` | string | 问题单 ID |
| `task_id` | string | 任务 ID |
| `vuln_title` | string | 漏洞标题（回显请求体） |
| `vuln_description` | string | 漏洞描述（回显请求体） |
| `is_vulnerable` | bool | 漏洞是否仍然存在（回显请求体） |
| `result` | string | `false_positive_resolved` 或 `still_vulnerable` |
| `status` | string | 问题单新状态：`passed` 或 `failed` |
| `message` | string | 结果描述 |
| `issue` | object | 更新后的完整问题单（含全部字段） |

#### 错误响应

**404 — 问题单不存在**

```json
{
  "detail": "问题单 'DTS-XXXX' 不存在"
}
```

**400 — task_id 不匹配**

```json
{
  "detail": "task_id 不匹配：问题单的 task_id='aaa' ≠ 请求的 task_id='bbb'"
}
```

**500 — 更新失败**

```json
{
  "detail": "更新问题单 'DTS-XXXX' 失败"
}
```

---

## 回归后误报率

回归验证完成后，可通过以下接口查询回归后误报率：

```
GET /api/v2/dts/post-regression-fpr/{evaluation_id}
```

返回：

```json
{
  "post_regression_fpr": 0.3333,
  "passed_count": 2,
  "failed_count": 1,
  "verified_total": 3,
  "open_count": 5,
  "total": 8
}
```

- `post_regression_fpr` = `failed / (passed + failed)`，即未消除的误报占比
- `open` 状态的问题单未参与回归验证，不计入分母

---

## 完整调用示例

### Python

```python
import requests

BASE_URL = "http://chimera-g.icsl.huawei.com/eval/api/v2/dts"
TASK_ID = "ae6ae5567f984d0eb05f1f09"

# 步骤 1：查询问题单列表
resp = requests.get(f"{BASE_URL}/by-task/{TASK_ID}")
data = resp.json()
print(f"共 {data['count']} 个问题单")

# 步骤 2：逐个提交回归验证
for issue in data["issues"]:
    dts_id = issue["dts_id"]
    vuln_title = issue["vuln_title"]
    raw_report = issue["raw_report"]  # 基线原始漏洞报告（Markdown）

    # 调用回归验证（假设漏洞已消除）
    verify_resp = requests.post(
        f"{BASE_URL}/regression-verify",
        json={
            "task_id": TASK_ID,
            "dts_id": dts_id,
            "vuln_title": vuln_title,
            "vuln_description": raw_report,  # 用原始报告作为漏洞描述
            "is_vulnerable": False,  # False=漏洞已消除，True=漏洞仍存在
        },
    )
    result = verify_resp.json()
    print(f"  {dts_id}: {result['status']} - {result['message']}")
```

### curl

```bash
# 步骤 1：查询问题单
curl -s "http://chimera-g.icsl.huawei.com/eval/api/v2/dts/by-task/ae6ae5567f984d0eb05f1f09" | python -m json.tool

# 步骤 2：回归验证
curl -s -X POST "http://chimera-g.icsl.huawei.com/eval/api/v2/dts/regression-verify" \
  -H "Content-Type: application/json" \
  -d '{
    "task_id": "ae6ae5567f984d0eb05f1f09",
    "dts_id": "DTS-6294DF09",
    "vuln_title": "GitCode Actions 接口 limit 参数无上限校验导致数据库 DoS",
    "vuln_description": "",
    "is_vulnerable": false
  }' | python -m json.tool
```

---

## 问题单状态流转

```
                回归验证
    open ──────────────────→ passed (is_vulnerable=false, 误报已消除)
      │
      │      回归验证
      └────────────────────→ failed (is_vulnerable=true, 误报未消除)
                               │
                               │      再次回归验证
                               └────────────────────→ passed / failed
```

- `open`：未参与回归验证
- `passed`：漏洞已消除，问题单关闭
- `failed`：漏洞仍存在，可再次提交回归验证
