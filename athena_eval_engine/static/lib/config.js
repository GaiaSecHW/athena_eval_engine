// 全局配置常量（所有页面共享）
// Agent 类型集中配置
const AGENT_TYPES = ['turing','argo','secmate','dataflow','cvuln_verify','webvuln_verify'];
const AGENT_LABELS = {'turing':'Turing','argo':'Argo','secmate':'SecMate','dataflow':'Dataflow','cvuln_verify':'CVulnVerify','webvuln_verify':'WebVulnVerify'};
const TOOL_LABELS = {'turing':'Turing','argo':'Argo','secmate':'SecMate','cvuln_verify':'CVulnVerify','webvuln_verify':'WebVulnVerify','dataflow_vuln_scan':'DataflowVulnScan'};

// 主题
const THEMES = {
  light: {"--bg":"#f5f6f8","--panel":"#ffffff","--p2":"#f0f2f5","--bd":"#e1e4e8","--txt":"#1a1d23","--sub":"#6b7280","--acc":"#2563eb","--green":"#16a34a","--red":"#dc2626","--amber":"#d97706","--gray":"#9ca3af","--header-bg":"#ffffff","--bar-bg":"#e5e7eb","--hover-shadow":"0 8px 24px rgba(0,0,0,.1)"},
  dark: {"--bg":"#0b0e14","--panel":"#141821","--p2":"#1c212c","--bd":"#2a3140","--txt":"#e8eaed","--sub":"#a8b2c0","--acc":"#5b9cf6","--green":"#4ade80","--red":"#f87171","--amber":"#fbbf24","--gray":"#8b95a5","--header-bg":"rgba(20,24,33,.6)","--bar-bg":"var(--p2)","--hover-shadow":"0 8px 32px rgba(0,0,0,.3)"}
};

// 评测状态标签（首页/列表/详情共用）
const EVAL_STATUS_LABELS = {
  "CREATED":"创建中","QUEUED":"已暂停","RUNNING":"启动中","VALIDATING":"验证中",
  "INGESTING":"数据采集","PARSING":"解析 Trace","AI_MATCHING":"AI 匹配","CASE_MATCHING":"Case 匹配",
  "ROOT_CAUSE_ANALYSIS":"根因分析","RESOLVING":"事实写入","PAIRING":"配对","CALCULATING":"计算指标",
  "STATISTICAL_ANALYSIS":"统计分析","DIAGNOSING":"诊断","REPORTING":"生成报告","FINALIZING":"收尾中",
  "COMPLETED":"完成","COMPLETED_WITH_WARNINGS":"完成有告警","FAILED":"失败",
  "CANCEL_REQUESTED":"取消请求","CANCELLING":"取消中","CANCELLED":"已取消"
};

// DTS 问题单状态/常量
const DTS_STATUS_LABELS = {"open":"未关闭","passed":"回归通过","failed":"回归不通过"};
const DTS_STATUS_COLORS = {"open":"var(--gray)","passed":"var(--green)","failed":"var(--red)"};
const DTS_RESP_LABELS = {"agent":"Agent","knowledge":"知识库","knowledge_base":"知识库","memory":"记忆","external_data_source":"外部数据源","eval_process":"评测流程"};
const DTS_CASE_TYPE_LABELS = {"FP":"误报","FN":"漏报"};
const DTS_CAUSE_LABELS = {
  "A":"L2断(该查没查)","B":"L3断(查询太泛)","C":"L4断(查了没得)","D":"L5断(链路问题)","E":"L6断(查到没用)",
  "F":"L7断(用了没推动)","G":"L7负向(知识误导)","H":"L8断(流程缺陷)","I":"L8断(调用链中断)","J":"L8断(模型幻觉)","K":"L8断(验证否定真漏洞)"
};

// 指标定义（M5/M6/M11/M12/M13）— 与 DB metric_result 的 metric_id 一致
const MI = {
  M5:{n:"知识访问率",short:"知识访问",d:"Agent 工具调用中知识查询所占比例。",u:"ratio",
     range:[{v:0,t:"无访问",c:"red"},{v:0.05,t:"少量",c:"amber"},{v:0.15,t:"充分",c:"green"}],
     interp:(v)=>v==null?"未观测到知识访问":`知识访问率 ${(v*100).toFixed(2)}%`},
  M6:{n:"知识交付率",short:"知识交付",d:"知识查询中平台有效回复的比例。",u:"ratio",
     range:[{v:0,t:"无交付",c:"red"},{v:0.5,t:"部分",c:"amber"},{v:0.8,t:"充分",c:"green"}],
     interp:(v)=>v==null?"未观测到知识交付":`知识交付率 ${(v*100).toFixed(2)}%`},
  M11:{n:"记忆访问率",short:"记忆访问",d:"Agent 工具调用中记忆读取所占比例。",u:"ratio",
     range:[{v:0,t:"无访问",c:"red"},{v:0.05,t:"少量",c:"amber"},{v:0.15,t:"充分",c:"green"}],
     interp:(v)=>v==null?"未观测到记忆访问":`记忆访问率 ${(v*100).toFixed(2)}%`},
  M12:{n:"记忆交付率",short:"记忆交付",d:"记忆读取中成功返回的比例。",u:"ratio",
     range:[{v:0,t:"无交付",c:"red"},{v:0.5,t:"部分",c:"amber"},{v:0.8,t:"充分",c:"green"}],
     interp:(v)=>v==null?"未观测到记忆交付":`记忆交付率 ${(v*100).toFixed(2)}%`},
  M13:{n:"误报率",short:"误报率",d:"Agent 上报漏洞中误报的比例。",u:"ratio",
     range:[{v:0,t:"无误报",c:"green"},{v:0.3,t:"中等",c:"amber"},{v:1,t:"全误报",c:"red"}],
     interp:(v)=>v==null?"无数据":`误报率 ${(v*100).toFixed(2)}%`}
};

// 导航菜单
const NAV_ITEMS = [
  {route:"home", path:"/", label:"首页"},
  {route:"evals", path:"/evals", label:"评测"},
  {route:"dts", path:"/dts", label:"问题单"},
  {route:"report", path:"/report", label:"平台任务详情"}
];
const NAV_RIGHT = [
  {route:"create", path:"/create", label:"+ 新建评测"},
  {route:"system", path:"/system", label:"系统", debugOnly:true}
];
