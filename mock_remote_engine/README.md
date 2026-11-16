# Remote Evolution Engine Mock

用于联调 eval-engine Hook 1（case 级根因分析）的远程 mock 服务。它实现了：

- `POST /v1/case-analysis-jobs`
- `GET /v1/case-analysis-jobs/{job_id}`
- `GET /v1/case-analysis-jobs/{job_id}/result`
- `DELETE /v1/case-analysis-jobs/{job_id}`
- `GET /v1/artifacts/{analysis_id}`
- `GET /healthz` / `GET /readyz`

## 运行

```bash
python -m uvicorn mock_remote_engine.app:app --host 0.0.0.0 --port 8080
```

环境变量：

- `MOCK_FIXTURE_DIR`：fixture 目录，默认 `mock_remote_engine/fixtures`
- `MOCK_TOKEN`：非空时要求 `Authorization: Bearer ...`
- `MOCK_JOB_DELAY_SECONDS`：job 模拟处理时间，默认 `0.2`
- `MOCK_SCENARIO`：`normal|fail|slow|running_forever|invalid|insufficient|detail_404|missing_detail`

`fixtures/cluster_sample.json` 来自蓝区测试集群真实 DTS 分析结果与 WebVerify
trace 事件，已脱敏：不含 token、llm key、数据库密码等凭据。
