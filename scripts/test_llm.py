"""测试 v2 LLM 调用是否正常。

在 pod 上运行：kubectl exec -n secflow-ns <pod> -- python scripts/test_llm.py
本地运行需设置环境变量 EVAL_LLM_BASE_URL / EVAL_LLM_API_KEY / EVAL_LLM_MODEL。
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from athena_eval_engine.v2.infra import llm as llm_mod

print("=" * 60)
print("LLM 连通性测试")
print("=" * 60)

# 1. 检查配置
print(f"\n[配置]")
print(f"  base_url:  {llm_mod.DEFAULT_API_BASE}")
print(f"  model:     {llm_mod.DEFAULT_MODEL}")
print(f"  api_key:   {llm_mod.DEFAULT_API_KEY[:20]}...")
print(f"  enabled:   {llm_mod.is_enabled()}")
print(f"  max_concurrency: {llm_mod.get_max_concurrency()}")
print(f"  active:    {llm_mod.get_active_concurrency()}")

if not llm_mod.is_enabled():
    print("\n[错误] LLM 未启用，设置 EVAL_LLM_ENABLED=true")
    sys.exit(1)

# 2. 简单 chat 测试
print(f"\n[测试 1] chat() — 简单问答")
messages = [
    {"role": "user", "content": "回复一个字：好"},
]
t0 = time.time()
try:
    result = llm_mod.chat(messages, reasoning_effort="none", retries=1)
    elapsed = time.time() - t0
    print(f"  结果: {result[:100]}")
    print(f"  耗时: {elapsed:.1f}s")
    print(f"  状态: PASS")
except Exception as e:
    elapsed = time.time() - t0
    print(f"  错误: {str(e)[:200]}")
    print(f"  耗时: {elapsed:.1f}s")
    print(f"  状态: FAIL")

# 3. chat_json 测试 — 模拟 Prompt 2 (L1 判定)
print(f"\n[测试 2] chat_json() — 模拟 L1 判定 (小 JSON)")
messages = [
    {"role": "system", "content": '你是知识依赖分析员。只返回 JSON：{"need_knowledge": true/false, "reason": "简要说明"}'},
    {"role": "user", "content": "业务阶段: 漏洞模式识别\n漏洞类型: SQL注入\n\n判断该阶段是否需要外部知识支撑。"},
]
t0 = time.time()
try:
    result = llm_mod.chat_json(messages, reasoning_effort="none", retries=1)
    elapsed = time.time() - t0
    print(f"  结果: {result}")
    print(f"  耗时: {elapsed:.1f}s")
    print(f"  状态: {'PASS' if 'need_knowledge' in result else 'FAIL (缺 need_knowledge 字段)'}")
except Exception as e:
    elapsed = time.time() - t0
    print(f"  错误: {str(e)[:200]}")
    print(f"  耗时: {elapsed:.1f}s")
    print(f"  状态: FAIL")

# 4. chat_json 测试 — 模拟 Prompt 1 (阶段标注，大输出)
print(f"\n[测试 3] chat_json() — 模拟 Prompt 1 阶段标注 (大输出)")
_PROMPT1_SYSTEM = """你是漏洞挖掘过程分析员。判断每次知识访问发生在哪个业务阶段。

挖掘 Agent 的 5 个业务阶段：
1. 入口识别
2. 数据流追踪
3. 漏洞模式识别
4. Sink点定位
5. 漏洞判定与上报

只返回 JSON：
{
  "accesses": [
    {"event_idx": 数字, "business_phase": "阶段名称", "reason": "简要说明"}
  ]
}
"""

# 构造 10 个知识访问的事件序列
event_lines = []
for i in range(10):
    event_lines.append(f"[{i*10}] REASONING: 分析用户输入点，检查 API 参数是否可控 <<<知识访问")
    event_lines.append(f"[{i*10+1}] REASONING: 追踪数据流，检查参数在代码中的传递路径")
    event_lines.append(f"[{i*10+2}] REASONING: 识别到 SQL 查询拼接，可能存在注入风险")

event_sequence = "\n".join(event_lines)
access_indices = [i * 10 for i in range(10)]

user_content = (
    f"Agent 类型: 挖掘\n\n"
    f"第二层粗标注结果: 入口识别 + 漏洞模式识别\n\n"
    f"事件序列（按时间序）:\n{event_sequence}\n\n"
    f"知识访问的 event_idx 列表: {access_indices}\n\n"
    f"请对每个知识访问判断其所属业务阶段。"
)

messages = [
    {"role": "system", "content": _PROMPT1_SYSTEM},
    {"role": "user", "content": user_content},
]
input_chars = sum(len(str(m.get("content", ""))) for m in messages)
print(f"  输入字符数: {input_chars}")
print(f"  知识访问数: {len(access_indices)}")

t0 = time.time()
try:
    result = llm_mod.chat_json(messages, reasoning_effort="none", retries=1)
    elapsed = time.time() - t0
    accesses = result.get("accesses", [])
    print(f"  返回 accesses 数: {len(accesses)}")
    if accesses:
        print(f"  第一条: {accesses[0]}")
    print(f"  耗时: {elapsed:.1f}s")
    print(f"  状态: {'PASS' if len(accesses) > 0 else 'FAIL (accesses 为空)'}")
except Exception as e:
    elapsed = time.time() - t0
    print(f"  错误: {str(e)[:200]}")
    print(f"  耗时: {elapsed:.1f}s")
    print(f"  状态: FAIL")

# 5. 并发计数验证
print(f"\n[测试 4] 并发计数验证")
print(f"  active (调用前): {llm_mod.get_active_concurrency()}")
import threading
results = []
def _call():
    try:
        llm_mod.chat([{"role": "user", "content": "回复一个字：好"}],
                     reasoning_effort="none", retries=1)
        results.append("ok")
    except Exception as e:
        results.append(f"err: {str(e)[:50]}")

threads = [threading.Thread(target=_call) for _ in range(3)]
for t in threads:
    t.start()
# 等一小段时间检查并发计数
time.sleep(0.5)
active_during = llm_mod.get_active_concurrency()
print(f"  active (3 线程运行中): {active_during}")
for t in threads:
    t.join(timeout=120)
print(f"  active (调用后): {llm_mod.get_active_concurrency()}")
print(f"  结果: {results}")
print(f"  状态: {'PASS' if all(r == 'ok' for r in results) else 'FAIL'}")

print("\n" + "=" * 60)
print("测试完成")
print("=" * 60)