/*
 * report-renderer.js — 报告渲染器
 * 由 render_static_report 内联到静态报告 HTML 中，使报告完全自包含（无外部 JS 依赖）。
 * 提取自 dashboard.html 的 renderReport 及其依赖函数。
 */
function $(i){return document.getElementById(i);}
function el(h){const d=document.createElement("div");d.innerHTML=h;return d.firstChild;}

function fmtDur(ms){
  if(ms===null||ms===undefined||isNaN(ms))return'<span class="na">NA</span>';
  var abs=Math.abs(ms);var sign=ms<0?'-':'';
  if(abs>=3600000){var h=Math.floor(abs/3600000);var m=Math.floor((abs%3600000)/60000);return sign+h+'<span class="ci">时</span> '+m+'<span class="ci">分</span>';}
  if(abs>=60000){var m2=Math.floor(abs/60000);var s=Math.floor((abs%60000)/1000);return sign+m2+'<span class="ci">分</span> '+s+'<span class="ci">秒</span>';}
  if(abs>=1000){return sign+(abs/1000).toFixed(1)+'<span class="ci">秒</span>';}
  return sign+Math.round(abs)+'<span class="ci">ms</span>';
}
function fmtTs(ts){
  if(!ts)return'';
  var d=new Date(ts+8*3600000);
  var p=function(n){return String(n).padStart(2,'0')};
  return p(d.getUTCMonth()+1)+'-'+p(d.getUTCDate())+' '+p(d.getUTCHours())+':'+p(d.getUTCMinutes())+':'+p(d.getUTCSeconds());
}
function fmt(v,u){
  if(v===null||v===undefined||isNaN(v))return'<span class="na">NA</span>';
  if(u==="ratio")return (v*100).toFixed(2)+'<span class="ci">%</span>';
  if(u==="ms")return fmtDur(v);
  if(u==="steps"||u==="tokens"){const a=Math.abs(v);let s;
    if(a>=1e9)s=(v/1e9).toFixed(2)+'B';else if(a>=1e6)s=(v/1e6).toFixed(2)+'M';else if(a>=1e3)s=(v/1e3).toFixed(1)+'K';else s=Math.round(v).toString();
    return s+'<span class="ci">'+(u==="tokens"?" tok":" steps")+'</span>';}
  return Number(v).toFixed(3);
}
const CONF_LABEL={TP:"真阳性",FP:"假阳性",FN:"假阴性",TN:"真阴性",NA:"未判定"};
const STATUS_LABEL={CALCULATED:"已计算",NA:"未计算",NO_DATA:"无数据"};
const RC_ALL={"NO_STRATUM":"基线全部为漏洞型，无对照样本","NO_VALID_DENOMINATOR":"No-KG 全部成功，无改善空间","NO_POSITIVE_GT":"无漏洞型基线","BOOTSTRAP_UNSTABLE":"样本量不足","NO_VALID":"数据不足","INSUFFICIENT_DATA":"样本量不足","NO_DISCORDANT_PAIRS":"KG 与 No-KG 结果一致，无差异对","INSUFFICIENT_PAIRS":"配对数不足","ALL_ZERO_DIFFERENCES":"所有配对差异为零","TOOL_EVENT_MISSING":"工具事件缺失","TOKEN_INVALID":"Token 数据无效","STEP_INVALID":"步数数据无效","TIME_INVALID":"时长数据无效"};
function fmtNum(v){if(v==null||isNaN(v))return'<span class="na">NA</span>';const a=Math.abs(v);
  if(a>=1e9)return(v/1e9).toFixed(2)+'B';
  if(a>=1e6)return(v/1e6).toFixed(2)+'M';
  if(a>=1e3)return(v/1e3).toFixed(1)+'K';
  return Math.round(v).toString();}
const MI={
  M1:{n:"平衡准确率",short:"准确率",d:"平衡准确率=(真正例率+真负例率)/2",u:"ratio",
     range:[{v:0,t:"全错",c:"red"},{v:0.5,t:"随机",c:"amber"},{v:1,t:"全对",c:"green"}],
     interp:(v)=>v==null?"无基准，无法计算":v>=0.8?`准确率 ${(v*100).toFixed(1)}%`:v>=0.5?`准确率 ${(v*100).toFixed(1)}%`:`准确率 ${(v*100).toFixed(1)}%`,
     formula:"平衡准确率=(真正例率+真负例率)/2, 真正例率=真正例/(真正例+假负例), 真负例率=真负例/(真负例+假正例)",
     kgKey:"ba_kg",nogkKey:"ba_nogk"},
  M13:{n:"误报率",short:"误报率",d:"误报率=(假正例+假负例)/(真正例+假正例+假负例+真负例)，仅统计sink命中的基线项",u:"ratio",
     range:[{v:0,t:"无误报",c:"green"},{v:0.5,t:"部分误报",c:"amber"},{v:1,t:"全误报",c:"red"}],
     interp:(v)=>v==null?"无基准":v===0?"无误报":`误报率 ${(v*100).toFixed(1)}%`,
     formula:"误报率=(假正例+假负例)/(真正例+假正例+假负例+真负例)，分母=sink命中的基线项（finding匹配+sink发现）",
     kgKey:"fpr_kg",nogkKey:"fpr_nogk"},
  M14:{n:"精确率",short:"精确率",d:"精确率=真正例/(真正例+假正例)",u:"ratio",
     range:[{v:0,t:"全错",c:"red"},{v:0.5,t:"部分",c:"amber"},{v:1,t:"全对",c:"green"}],
     interp:(v)=>v==null?"无基准":v>=0.8?`精确率 ${(v*100).toFixed(1)}%`:`精确率 ${(v*100).toFixed(1)}%`,
     formula:"精确率=真正例/(真正例+假正例)",
     kgKey:"precision_kg",nogkKey:"precision_nogk"},
  M4:{n:"漏报率",short:"漏报率",d:"漏报率=假负例/(假负例+真正例)",u:"ratio",
     range:[{v:0,t:"无漏报",c:"green"},{v:0.5,t:"部分漏报",c:"amber"},{v:1,t:"全漏报",c:"red"}],
     interp:(v)=>v==null?"无基准":v===0?"无漏报":`漏报率 ${(v*100).toFixed(1)}%`,
     formula:"漏报率=假负例/(假负例+真正例)",
     kgKey:"fnr_kg",nogkKey:"fnr_nogk"},
  M5:{n:"知识访问率",short:"知识访问",d:"Agent 工具调用中知识查询所占比例（交互级）。衡量 Agent 对知识的依赖程度。",u:"ratio",
     range:[{v:0,t:"无访问",c:"red"},{v:0.05,t:"少量",c:"amber"},{v:0.15,t:"充分",c:"green"}],
     interp:(v)=>v==null?"未观测到知识访问":v>=0.15?`知识访问率 ${(v*100).toFixed(2)}%, 充分`:v>=0.05?`知识访问率 ${(v*100).toFixed(2)}%, 少量`:`知识访问率 ${(v*100).toFixed(2)}%, 极低`,
     formula:"kg_count / total_tool_calls (知识查询次数 / 总工具调用次数)"},
  M6:{n:"知识交付率",short:"知识交付",d:"知识查询中平台有效回复的比例（交互级）。衡量知识质量。",u:"ratio",
     range:[{v:0,t:"无交付",c:"red"},{v:0.5,t:"部分",c:"amber"},{v:0.8,t:"充分",c:"green"}],
     interp:(v)=>v==null?"未观测到知识交付":v>=0.8?`知识交付率 ${v*100}%, 充分`:v>=0.5?`知识交付率 ${v*100}%, 部分`:`知识交付率 ${v*100}%, 不足`,
     formula:"successful_read_count / access_event_count (有效回复次数 / 总查询次数)"},
  M7:{n:"行为偏移",short:"行为偏移",d:"KG vs No-KG 工具使用分布差异。0=完全相同，1=完全不同。",u:"ratio",
     range:[{v:0,t:"无差异",c:"green"},{v:0.1,t:"轻微",c:"amber"},{v:0.3,t:"显著",c:"red"}],
     interp:(v)=>v==null?"无法计算":v<0.1?`行为偏移 ${v*100}%, 轻微`:v<0.3?`行为偏移 ${v*100}%, 明显`:`行为偏移 ${v*100}%, 显著`,
     formula:"median(JSD_i), JSD_i=(0.5*KL(P||M)+0.5*KL(Q||M))/ln2, M=(P+Q)/2, P/Q=工具使用概率分布"},
  M8:{n:"Token变化",short:"Token",d:"KG - No-KG 有效 token 消耗。负值=KG 更省。",u:"tokens",
     range:[{v:-1,t:"KG 更省",c:"green"},{v:0,t:"无变化",c:"amber"},{v:1,t:"KG 更耗",c:"red"}],
     interp:(v)=>v==null?"无法计算":v<0?`KG 少用 ${fmtNum(Math.abs(v))} token`:v>0?`KG 多用 ${fmtNum(v)} token`:"token 消耗无差异",
     formula:"median(KG_tokens - NoKG_tokens)"},
  M9:{n:"步数变化",short:"步数",d:"KG - No-KG 推理步数。负值=KG 更少步。",u:"steps",
     range:[{v:-1,t:"KG 更少",c:"green"},{v:0,t:"无变化",c:"amber"},{v:1,t:"KG 更多",c:"red"}],
     interp:(v)=>v==null?"无法计算":v<0?`KG 少 ${fmtNum(Math.abs(v))} 步`:v>0?`KG 多 ${fmtNum(v)} 步`:"步数无差异",
     formula:"median(KG_steps - NoKG_steps)"},
  M10:{n:"时长变化",short:"时长",d:"KG - No-KG 运行时长(ms)。负值=KG 更快。",u:"ms",
     range:[{v:-1,t:"KG 更快",c:"green"},{v:0,t:"无变化",c:"amber"},{v:1,t:"KG 更慢",c:"red"}],
     interp:(v)=>v==null?"无法计算":v<0?`KG 快 ${fmtDur(-v)}`:v>0?`KG 慢 ${fmtDur(v)}`:"时长无差异",
     formula:"median(KG_duration_ms - NoKG_duration_ms)"},
  M11:{n:"记忆访问率",short:"记忆访问",d:"Agent 工具调用中记忆读取所占比例（交互级）。衡量 Agent 对记忆的依赖程度。",u:"ratio",
     range:[{v:0,t:"无访问",c:"red"},{v:0.05,t:"少量",c:"amber"},{v:0.15,t:"充分",c:"green"}],
     interp:(v)=>v==null?"未观测到记忆访问":v>=0.15?`记忆访问率 ${(v*100).toFixed(2)}%, 充分`:v>=0.05?`记忆访问率 ${(v*100).toFixed(2)}%, 少量`:`记忆访问率 ${(v*100).toFixed(2)}%, 极低`,
     formula:"memory_read_count / total_tool_calls (记忆读取次数 / 总工具调用次数)"},
  M12:{n:"记忆交付率",short:"记忆交付",d:"记忆查询中成功读取的比例（交互级）。衡量记忆质量。",u:"ratio",
     range:[{v:0,t:"无交付",c:"red"},{v:0.5,t:"部分",c:"amber"},{v:0.8,t:"充分",c:"green"}],
     interp:(v)=>v==null?"未观测到记忆交付":v>=0.8?`记忆交付率 ${v*100}%, 充分`:v>=0.5?`记忆交付率 ${v*100}%, 部分`:`记忆交付率 ${v*100}%, 不足`,
     formula:"successful_memory_read_count / memory_access_event_count (成功记忆读取 / 记忆读取次数)"}
};
function mInfo(id){const m=MI[id];return m?`<div style="font-size:15px;color:var(--sub);margin-top:4px;line-height:1.5">${m.d}<br><span style="color:var(--gray);font-size:14px">单位：${m.u}</span></div>`:"";}
function dc(v,u){if(v===null||v===undefined||isNaN(v))return"";if(u==="ratio")return v>0?"dp":"dn";return v<0?"dp":"dn";}
function ci(m){if(!m||m.ci_lower==null||m.ci_upper==null||isNaN(m.ci_lower)||isNaN(m.ci_upper))return"";const u=m.unit==="ratio"?"pp":(m.unit==="ms"?"s":(m.unit||""));const lo=m.unit==="ratio"?(m.ci_lower*100).toFixed(2):(m.unit==="ms"?(m.ci_lower/1000).toFixed(1):Number(m.ci_lower).toFixed(2));const hi=m.unit==="ratio"?(m.ci_upper*100).toFixed(2):(m.unit==="ms"?(m.ci_upper/1000).toFixed(1):Number(m.ci_upper).toFixed(2));return`<div class="ci">95% CI [${lo}, ${hi}] ${u}</div>`;}
function row(m,l){const mid=l.split(" ")[0];const mi=MI[mid]||{n:l,u:""};if(!m)return`<tr><td><b>${mi.n||l}</b><div style="font-size:14px;color:var(--sub)">${mi.d||""}</div></td><td class="na">未计算</td><td>-</td><td></td><td></td></tr>`;const c=m.calculation_status!=="CALCULATED"?`<span class="na">${STATUS_LABEL[m.calculation_status]||m.calculation_status}<br><span style="font-size:14px">${RC_ALL[m.reason_code]||m.reason_code||""}</span></span>`:`<span class="${dc(m.estimate,m.unit)}">${fmt(m.estimate,m.unit)}</span>`;const n=m.n!=null?`<span class="ci">N=${m.n}</span>${m.median!=null?'<br><span class="ci">med '+fmt(m.median,m.unit)+'</span>':''}`:"-";const p=m.p_value!=null&&!isNaN(m.p_value)?`<span class="ci">p=${m.p_value<0.001?'<0.001':m.p_value.toFixed(3)}</span>`:(m.median!=null?'<span class="ci">Wilcoxon</span>':"");return`<tr><td><b>${mi.n||l}</b><div style="font-size:15px;color:var(--sub);line-height:1.5">${mi.d||""}<br><span style="color:var(--gray);font-size:14px">单位：${mi.u}</span></div></td><td class="num">${c}</td><td>${n}</td><td>${ci(m)}</td><td>${p}</td></tr>`;}

function selectReportTab(button,paneId){
  document.querySelectorAll('[data-report-tab]').forEach(el=>{el.style.display=el.id===paneId?'block':'none';});
  document.querySelectorAll('[data-report-tab-btn]').forEach(el=>{el.style.background='var(--panel)';el.style.color='var(--sub)';el.style.borderColor='var(--bd)';el.style.boxShadow='none';el.style.transform='none';el.setAttribute('aria-selected','false');});
  button.style.background='var(--acc)';button.style.color='#fff';button.style.borderColor='var(--acc)';button.style.boxShadow='0 8px 20px rgba(124,58,237,.28)';button.style.transform='translateY(-2px)';button.setAttribute('aria-selected','true');
}


function renderReport(d){
  const r=d.report||{},p0=r.p0||{},p1=r.p1||{},p2=r.p2||{},h=r.diagnostic_hits||[],nt=r.notes||[],rw=r.raw_stats||{},mc=p0.m2_m3_mcnemar||{};

  // 指标卡片：名称 + 值 + 解读 + 参考范围条
  function mCard(mid,m){
    const mi=MI[mid]||{n:mid,short:mid,d:"",u:"",range:[],interp:()=>""};
    const RC={...RC_ALL,"NO_VALID_DENOMINATOR":mid==="M3"?"No-KG 全部失败，无回归可能":"No-KG 全部成功，无改善空间"};
    if(!m||m.calculation_status!=="CALCULATED"){
      const rc=m?m.reason_code||m.calculation_status:"无数据";
      const reason=RC[rc]||rc||"无数据";
      const nNote=m&&m.n!=null?` (N=${m.n})`:"";
      return `<div class="mcard na"><div class="mc-label"><span style="font-family:monospace;font-size:12px;color:var(--gray)">${mid}</span> ${mi.short||""}</div><div class="mc-val na">N/A</div><div style="font-size:13px;color:var(--sub);margin-top:4px">${reason}${nNote}</div></div>`;
    }
    const v=m.estimate;
    if(v==null||isNaN(v))return `<div class="mcard na"><div class="mc-label"><span style="font-family:monospace;font-size:12px;color:var(--gray)">${mid}</span> ${mi.short||""}</div><div class="mc-val na">N/A</div><div style="font-size:13px;color:var(--sub);margin-top:4px">estimate 缺失</div></div>`;
    const interp=mi.interp?mi.interp(v):"";
    let col="var(--gray)";
    if(mi.range){
      for(let i=mi.range.length-1;i>=0;i--){if(v>=mi.range[i].v){col=mi.range[i].c==="green"?"var(--green)":mi.range[i].c==="red"?"var(--red)":"var(--amber)";break;}}
    }
    const valStr=fmt(v,m.unit);
    let rangeBar="";
    if(mi.range&&mi.range.length>=2){
      const min=mi.range[0].v,max=mi.range[mi.range.length-1].v;
      const pct=Math.min(100,Math.max(0,((v-min)/(max-min))*100));
      rangeBar=`<div class="bar-track" style="margin-top:6px;height:4px"><div class="bar-fill" style="width:${pct}%;background:${col}"></div></div>`;
    }
    var formulaHtml=mi.formula?"<details style='margin-top:4px'><summary style='cursor:pointer;font-size:12px;color:var(--gray)'>计算公式</summary><div style='font-size:12px;color:var(--sub);font-family:monospace;background:var(--p2);padding:4px 6px;border-radius:4px;margin-top:4px'>"+mi.formula+"</div></details>":"";
    // 混淆矩阵值：显示计算过程
    if(m.cm){
      var cmParts=[];
      if(mid==="M1"){
        cmParts.push("真正例="+m.cm.tp,"假负例="+m.cm.fn,"真负例="+m.cm.tn,"假正例="+m.cm.fp);
        var tpr=m.cm.tp+m.cm.fn>0?(m.cm.tp/(m.cm.tp+m.cm.fn)*100).toFixed(1):"0.0";
        var tnr=m.cm.tn+m.cm.fp>0?(m.cm.tn/(m.cm.tn+m.cm.fp)*100).toFixed(1):"0.0";
        cmParts.push("→ 真正例率="+tpr+"%, 真负例率="+tnr+"%");
      }else if(mid==="M4"){
        cmParts.push("假负例="+m.cm.fn,"真正例="+m.cm.tp);
        cmParts.push("→ "+m.cm.fn+"/("+(m.cm.fn+m.cm.tp)+")");
      }else if(mid==="M13"){
        cmParts.push("假正例="+m.cm.fp,"假负例="+m.cm.fn,"真正例="+m.cm.tp,"真负例="+m.cm.tn);
        cmParts.push("→ ("+m.cm.fp+"+"+m.cm.fn+")/("+(m.cm.tp+m.cm.fp+m.cm.fn+m.cm.tn)+")");
      }else if(mid==="M14"){
        cmParts.push("真正例="+m.cm.tp,"假正例="+m.cm.fp);
        cmParts.push("→ "+m.cm.tp+"/("+(m.cm.tp+m.cm.fp)+")");
      }
      if(cmParts.length){
        formulaHtml+="<div style='font-size:12px;color:var(--sub);margin-top:4px'>"+cmParts.join("，")+"</div>";
      }
    }
    // 原始计算值：从 method 字典提取分量
    if(m.method){
      var rvParts=[];
      if(mid==="M5"&&m.method.kg_tool_calls!=null){
        rvParts.push("知识查询次数="+m.method.kg_tool_calls,"总工具调用="+m.method.total_tool_calls);
        rvParts.push("→ "+m.method.kg_tool_calls+"/"+m.method.total_tool_calls);
      }else if(mid==="M6"&&m.method.successful_read_count!=null){
        rvParts.push("有效回复="+m.method.successful_read_count,"总查询次数="+m.method.access_event_count);
        rvParts.push("→ "+m.method.successful_read_count+"/"+m.method.access_event_count);
      }else if(mid==="M11"&&m.method.mem_read_count!=null){
        rvParts.push("记忆读取次数="+m.method.mem_read_count,"总工具调用="+m.method.total_tool_calls);
        rvParts.push("→ "+m.method.mem_read_count+"/"+m.method.total_tool_calls);
      }else if(mid==="M12"&&m.method.mem_successful_reads!=null){
        rvParts.push("成功记忆读取="+m.method.mem_successful_reads,"记忆读取次数="+m.method.mem_read_events);
        rvParts.push("→ "+m.method.mem_successful_reads+"/"+m.method.mem_read_events);
      }else if(mid==="M7"&&m.n!=null){
        rvParts.push("N="+m.n);
        if(m.median!=null)rvParts.push("中位数="+fmt(m.median,m.unit));
        if(m.q1!=null&&m.q3!=null)rvParts.push("IQR=["+fmt(m.q1,m.unit)+", "+fmt(m.q3,m.unit)+"]");
      }else if((mid==="M8"||mid==="M9"||mid==="M10")&&m.n!=null){
        rvParts.push("N="+m.n);
        if(m.median!=null)rvParts.push("中位数="+fmt(m.median,m.unit));
        if(m.q1!=null&&m.q3!=null)rvParts.push("IQR=["+fmt(m.q1,m.unit)+", "+fmt(m.q3,m.unit)+"]");
      }
      if(rvParts.length){
        formulaHtml+="<div style='font-size:12px;color:var(--sub);margin-top:4px'>"+rvParts.join("，")+"</div>";
      }
    }
    return '<div class="mcard" style="border-color:'+col+'33"><div class="mc-label"><span style="font-family:monospace;font-size:12px;color:var(--gray)">'+mid+'</span> '+(mi.short||"")+'</div><div class="mc-val" style="color:'+col+'">'+valStr+'</div><div style="font-size:12px;color:var(--sub);margin-top:4px;line-height:1.4">'+(m.d||mi.d||"")+'</div>'+rangeBar+formulaHtml+'</div>';
  }

  // 知识图谱与记忆介入情况：两种方案分别统计
  function buildKnowledgeHtml(group){
  const groupP1=group?(group.p1||{}):p1;
  const kar=groupP1.M5,kdr=groupP1.M6;
  const mar=groupP1.M11,mdr=groupP1.M12;
  const kgAccess=kar&&kar.calculation_status==="CALCULATED"?kar.estimate:null;
  const kgDelivery=kdr&&kdr.calculation_status==="CALCULATED"?kdr.estimate:null;
  const memAccess=mar&&mar.calculation_status==="CALCULATED"?mar.estimate:null;
  const memDelivery=mdr&&mdr.calculation_status==="CALCULATED"?mdr.estimate:null;
  const taskId=group&&group.task_id;
  const kgData=taskId?(d.knowledge_interactions||[]).filter(k=>k.task_run_id.includes("-"+taskId+"-KG")):(d.knowledge_interactions||[]);

  // 分别提取知识图谱交互和记忆交互
  const kgAll=[],memAll=[];
  var hasKgPre=false,hasMemPre=false;
  var kgPre={callCount:0,resultCount:0,noResponse:0,fail:0,blind:0,success:0};
  var memPre={callCount:0,resultCount:0,noResponse:0,fail:0,blind:0,success:0};
  kgData.forEach(k=>{
    if(k.kg_stats){hasKgPre=true;var s=k.kg_stats;kgPre.callCount+=s.call_count||0;kgPre.resultCount+=s.result_count||0;kgPre.noResponse+=s.no_response||0;kgPre.fail+=s.fail||0;kgPre.blind+=s.blind||0;kgPre.success+=s.success||0;}
    (k.interactions||[]).forEach(i=>kgAll.push(i));
    const mem=k.memory||{};
    if(k.mem_stats){hasMemPre=true;var s=k.mem_stats;memPre.callCount+=s.call_count||0;memPre.resultCount+=s.result_count||0;memPre.noResponse+=s.no_response||0;memPre.fail+=s.fail||0;memPre.blind+=s.blind||0;memPre.success+=s.success||0;}
    (mem.interactions||[]).forEach(i=>memAll.push(i));
  });

  // 统计辅助函数：计算主动查询、返回结果、有效返回、返回失败、知识盲区
  // isMem=true 时用本地文件读取的失败关键词，isMem=false（默认）用远程 API 的失败关键词
  function _stats(arr,isMem){
    const callCount=arr.filter(function(iv){return iv.type==="CALL";}).length;
    const resultCount=arr.filter(function(iv){return iv.type==="RESULT";}).length;
    const noResponse=Math.max(0,callCount-resultCount);
    var fail=0,blind=0,success=0;
    var failKw=isMem?["permission denied","cannot access","i/o error","is a directory","no space left"]:
      ["terminated","timeout","error","404","failed","exception","unreachable","connection refused"];
    var blindKw=isMem?["no such file","not found","does not exist","no data available"]:
      ["知识库暂无此类知识","no memory","not found","empty"];
    arr.forEach(function(iv){
      if(iv.type!=="RESULT"||!iv.output)return;
      var out=(iv.output||"").toLowerCase();
      if(failKw.some(function(k){return out.indexOf(k)>=0;})){
        fail++;
      }else if(blindKw.some(function(k){return out.indexOf(k)>=0;})){
        blind++;
      }else{
        success++;
      }
    });
    fail+=noResponse;
    return {callCount:callCount,resultCount:resultCount,noResponse:noResponse,fail:fail,blind:blind,success:success};
  }

  // 单个方案统计区块
  function _sectionHtml(title,icon,stats,accessRate,deliveryRate){
    const active=(accessRate!==null&&accessRate>0)||stats.callCount>0;
    var html="<div style='display:flex;gap:12px;align-items:center;margin-bottom:8px'>";
    html+=active?"<span style='font-size:24px'>"+icon+"</span>":"<span style='font-size:24px'>❌</span>";
    html+="<div><span style='font-weight:600;font-size:15px'>"+title+(active?"已介入":"未介入")+"</span>";
    html+="<div style='font-size:13px;color:var(--sub)'>主动查询：<b style='color:var(--txt)'>"+stats.callCount+"</b> 次 · 返回结果：<b style='color:var(--txt)'>"+stats.resultCount+"</b> 次</div></div></div>";
    if(stats.callCount>0){
      html+="<div style='display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px;padding-left:36px'>";
      html+="<span class='bdg b-COMPLETED' style='font-size:13px'>有效返回 "+stats.success+"</span>";
      html+="<span class='bdg b-FAILED' style='font-size:13px'>返回失败 "+stats.fail+"</span>";
      html+="<span class='bdg b-CREATED' style='font-size:13px'>知识盲区 "+stats.blind+"</span>";
      if(accessRate!=null&&!isNaN(accessRate))html+="<span class='bdg' style='font-size:13px;background:var(--p3);color:var(--sub)'>访问率 "+(accessRate*100).toFixed(2)+"%</span>";
      if(deliveryRate!=null&&!isNaN(deliveryRate))html+="<span class='bdg' style='font-size:13px;background:var(--p3);color:var(--sub)'>交付率 "+(deliveryRate*100).toFixed(2)+"%</span>";
      html+="</div>";
    }
    return html;
  }

  const kgStats=hasKgPre?kgPre:_stats(kgAll,false);
  const memStats=hasMemPre?memPre:_stats(memAll,true);
  const kgActive=(kgAccess!==null&&kgAccess>0)||kgStats.callCount>0;
  let kgHtml="";
  kgHtml+=_sectionHtml("知识图谱","🔍",kgStats,kgAccess,kgDelivery);
  kgHtml+=_sectionHtml("记忆","🧠",memStats,memAccess,memDelivery);

  // 知识对漏洞判定的影响（正向/负向/中性），来源 per_case_kg_analysis.impact
  var pcAnalysis=group?(group.per_case_kg_analysis||[]):(r.per_case_kg_analysis||[]);
  if(pcAnalysis.length){
    var posCount=pcAnalysis.filter(p=>p.impact==="POSITIVE").length;
    var negCount=pcAnalysis.filter(p=>p.impact==="NEGATIVE").length;
    var neuCount=pcAnalysis.filter(p=>p.impact==="NEUTRAL").length;
    kgHtml+="<div style='display:flex;gap:12px;margin-bottom:12px'>";
    kgHtml+="<span class='bdg b-COMPLETED' style='font-size:14px'>正向 "+posCount+"</span>";
    kgHtml+="<span class='bdg b-FAILED' style='font-size:14px'>负向 "+negCount+"</span>";
    kgHtml+="<span class='bdg b-CREATED' style='font-size:14px'>中性 "+neuCount+"</span>";
    kgHtml+="</div>";
  }

  // 混淆矩阵汇总（与 M13 误报率、匹配明细一致）
  var memActive=(memAccess!==null&&memAccess>0)||memStats.callCount>0;
  var caseResults=group?(group.case_results||[]):(d.case_results||[]);
  var kgTP=0,kgFP=0,kgFN=0,kgTN=0,kgNA=0;
  caseResults.forEach(function(c){
    var conf=c.confusion||"NA";
    if(conf==="TP")kgTP++;else if(conf==="FP"&&c.sink_hit)kgFP++;else if(conf==="FN")kgFN++;else if(conf==="TN"&&c.sink_hit)kgTN++;else kgNA++;
  });
  var kgFprNum=kgFP+kgFN,kgFprDen=kgTP+kgFP+kgFN+kgTN;
  var kgFprStr=kgFprDen>0?(kgFprNum/kgFprDen*100).toFixed(1)+"%":"—";
  kgHtml+="<div style='font-size:14px;color:var(--sub);margin-bottom:12px;padding:8px 12px;background:var(--p2);border-radius:8px'>混淆矩阵汇总：真阳性="+kgTP+" 假阳性="+kgFP+" 假阴性="+kgFN+" 真阴性="+kgTN+(kgNA?" 未判定="+kgNA:"")+"<span style='margin-left:16px'>误报率="+kgFprStr+"（分子="+kgFprNum+"=假阳性+假阴性 分母="+kgFprDen+"=sink命中的case数）</span></div>";

  // 基线漏洞 per-case 分析（有 case_results 就逐个展示，不依赖 kgActive/memActive）
  var hasAnyPcAnalysis=pcAnalysis.length>0;
  if(caseResults.length&&(kgActive||memActive||hasAnyPcAnalysis)){
    function _renderCaseCard(c,idx){
      var h="";
      var conf=c.confusion||"NA";
      var nogkConf=c.nogk_confusion||"NA";
      function confBadge(label,conf){
        var isCorrect=conf==="TP"||conf==="TN";
        var isFound=conf==="TP"||conf==="FP";
        var icon=isCorrect?'✅':'❌';
        var color=isCorrect?"var(--green)":"var(--red)";
        var judgment=isFound?"漏洞":"未发现";
        var correctness=isCorrect?"正确":"错误";
        return "<span style='font-weight:600;font-size:13px;color:"+color+"'>"+icon+" "+label+": "+judgment+" ("+correctness+")</span>";
      }
      h+="<div style='background:var(--p2);border-radius:10px;padding:12px;margin-bottom:10px'>";
      h+="<div style='display:flex;gap:8px;align-items:center;margin-bottom:6px'>";
      h+="<span class='bdg b-COMPLETED' style='font-size:11px'>问题"+(idx+1)+"</span>";
      var _exp=c.expected_label||"";
      var _expBadge=_exp==="VULNERABLE"?"<span class='bdg b-FAILED' style='font-size:11px'>基线: 漏洞</span>":_exp==="NON_VULNERABLE"?"<span class='bdg b-CREATED' style='font-size:11px'>基线: 非漏洞</span>":"";
      h+=_expBadge;
      h+="<span style='font-weight:600;font-size:14px'>"+(c.vulnerability_type||"漏洞")+"</span>";
      // sink 点: (文件名:行号/方法名)
      var _sinkFile=c.source_file||"";
      var _sinkLine=c.source_line||"";
      var _sinkFunc=c.source_function||"";
      if(_sinkFile){
        var _basename=_sinkFile.split(/[\\/]/).pop();
        var _sinkLoc=_sinkLine||_sinkFunc;
        h+="<span style='font-size:12px;color:var(--sub)'>（"+_basename+(_sinkLoc?":"+_sinkLoc:"")+"）</span>";
      }
      h+="<span style='font-size:12px;color:var(--gray);font-family:monospace'>"+(c.case_id||"")+"</span>";
      if(c.finding_session){
        h+="<span style='font-size:12px;color:var(--acc);font-family:monospace'>📝 "+String(c.finding_session).slice(0,12).replace(/</g,"&lt;")+"</span>";
      }
      var _confColor=conf==="TP"||conf==="TN"?"var(--green)":conf==="FP"||conf==="FN"?"var(--red)":"var(--gray)";
      h+="<span style='font-size:11px;font-weight:600;color:"+_confColor+"'>"+(CONF_LABEL[conf]||conf)+"</span>";
      h+="</div>";
      // session 链（与匹配明细表一致）
      if(c.session_chain&&c.session_chain.length){
        var _parts=c.session_chain.map(function(s){
          var sid=String(s.session_id||"").slice(0,8);
          var mark=s.has_finding?"📝":s.has_sink?"🎯":"";
          var color=s.has_finding?"var(--green)":s.has_sink?"var(--acc)":"var(--gray)";
          return "<code style='font-size:11px;color:"+color+"'>"+mark+sid+"</code>";
        });
        h+="<div style='font-size:11px;margin-top:2px;margin-bottom:6px'>"+_parts.join(" → ")+"</div>";
      }
      // per-case 知识介入分析
      var pcKa=pcAnalysis.find(function(p){return p.case_id===c.case_id;});
      // sink 匹配分析 + finding 匹配分析（分开渲染）
      var _hasNogk=r.has_nogk!==false;
      var _sinkInfo=c.sink_info||"";
      var _sinkAnalysis=c.sink_analysis||"";
      var _noFindReason=c.no_finding_reason||"";
      var _ki=c.knowledge_intervention||null;
      var _nogkSinkInfo=c.nogk_sink_info||"";
      var _nogkSinkAnalysis=c.nogk_sink_analysis||"";
      var _nogkNoFindReason=c.nogk_no_finding_reason||"";
      var _nogkKi=c.nogk_knowledge_intervention||null;
      var _hasKgSinkInfo=_sinkInfo||_sinkAnalysis;
      var _hasNogkSinkInfo=_hasNogk&&(_nogkSinkInfo||_nogkSinkAnalysis);
      var _hasKgFinding=!c.matched&&(_noFindReason||_ki||(pcKa&&(pcKa.reason||pcKa.query_summary)));
      var _hasNogkFinding=_hasNogk&&!c.nogk_matched&&(_nogkNoFindReason||_nogkKi);
      // 🎯 Sink 匹配分析（仅有 Finding 匹配分析时不显示，Finding 匹配不上才显示 Sink）
      var _kgShowSink=_hasKgSinkInfo&&!_hasKgFinding;
      var _nogkShowSink=_hasNogkSinkInfo&&!_hasNogkFinding;
      if(_kgShowSink||_nogkShowSink){
        h+="<div style='background:var(--p3);border-radius:8px;padding:10px;margin-bottom:8px;border-left:3px solid var(--acc)'>";
        h+="<div style='font-weight:600;font-size:13px;margin-bottom:6px'>🎯 Sink 匹配分析</div>";
        if(_kgShowSink){
          h+="<div style='margin-bottom:8px;padding:6px 8px;background:var(--p2);border-radius:6px'>";
          h+="<div style='font-size:11px;font-weight:600;color:var(--acc);margin-bottom:3px'>KG</div>";
          if(_sinkInfo)h+="<div style='font-size:12px;color:var(--sub);margin-bottom:3px'><b>匹配状态:</b> "+String(_sinkInfo).replace(/</g,"&lt;")+"</div>";
          var _kgHitSns=[];
          if(c.sink_hit_sessions&&c.sink_hit_sessions.length)_kgHitSns=_kgHitSns.concat(c.sink_hit_sessions);
          if(c.finding_session&&_kgHitSns.indexOf(c.finding_session)<0)_kgHitSns.push(c.finding_session);
          if(_kgHitSns.length)h+="<div style='margin-top:4px;padding:4px 8px;background:var(--p3);border-radius:4px;border-left:2px solid var(--acc)'><div style='font-size:11px;font-weight:600;color:var(--acc);margin-bottom:2px'>🎯 命中 session</div>"+_kgHitSns.map(function(s){return "<code style='font-size:12px;color:var(--txt)'>"+String(s).slice(0,12).replace(/</g,"&lt;")+"</code>";}).join(', ')+"</div>";
          if(_sinkAnalysis)h+="<div style='font-size:12px;color:var(--txt);margin-bottom:3px;line-height:1.5'><b>链分析:</b> "+String(_sinkAnalysis).replace(/</g,"&lt;")+"</div>";
          h+="</div>";
        }
        if(_nogkShowSink){
          h+="<div style='padding:6px 8px;background:var(--p2);border-radius:6px'>";
          h+="<div style='font-size:11px;font-weight:600;color:var(--sub);margin-bottom:3px'>No-KG</div>";
          if(_nogkSinkInfo)h+="<div style='font-size:12px;color:var(--sub);margin-bottom:3px'><b>匹配状态:</b> "+String(_nogkSinkInfo).replace(/</g,"&lt;")+"</div>";
          var _nogkHitSns=[];
          if(c.nogk_sink_hit_sessions&&c.nogk_sink_hit_sessions.length)_nogkHitSns=_nogkHitSns.concat(c.nogk_sink_hit_sessions);
          if(c.nogk_finding_session&&_nogkHitSns.indexOf(c.nogk_finding_session)<0)_nogkHitSns.push(c.nogk_finding_session);
          if(_nogkHitSns.length)h+="<div style='margin-top:4px;padding:4px 8px;background:var(--p3);border-radius:4px;border-left:2px solid var(--acc)'><div style='font-size:11px;font-weight:600;color:var(--acc);margin-bottom:2px'>🎯 命中 session</div>"+_nogkHitSns.map(function(s){return "<code style='font-size:12px;color:var(--txt)'>"+String(s).slice(0,12).replace(/</g,"&lt;")+"</code>";}).join(', ')+"</div>";
          if(_nogkSinkAnalysis)h+="<div style='font-size:12px;color:var(--txt);margin-bottom:3px;line-height:1.5'><b>链分析:</b> "+String(_nogkSinkAnalysis).replace(/</g,"&lt;")+"</div>";
          h+="</div>";
        }
        h+="</div>";
      }
      // 🔍 Finding 匹配分析（finding 提交与判定，仅在未匹配时显示）
      if(_hasKgFinding||_hasNogkFinding){
        h+="<div style='background:var(--p3);border-radius:8px;padding:10px;margin-bottom:8px;border-left:3px solid var(--amber)'>";
        h+="<div style='font-weight:600;font-size:13px;margin-bottom:6px'>🔍 Finding 匹配分析</div>";
        if(_hasKgFinding){
          h+="<div style='margin-bottom:8px;padding:6px 8px;background:var(--p2);border-radius:6px'>";
          h+="<div style='font-size:11px;font-weight:600;color:var(--acc);margin-bottom:3px'>KG</div>";
          if(pcKa&&(pcKa.reason||pcKa.query_summary)){
            var impColor=pcKa.impact==="POSITIVE"?"var(--green)":pcKa.impact==="NEGATIVE"?"var(--red)":"var(--amber)";
            var impText=pcKa.impact==="POSITIVE"?"正向 ✅":pcKa.impact==="NEGATIVE"?"负向 ❌":"中性 ⏳";
            var jText=conf==="TP"?"漏洞（真阳性）":conf==="FP"?"漏洞（假阳性）":conf==="FN"?"未找到（假阴性）":conf==="TN"?"非漏洞（真阴性）":"未判定";
            h+="<div style='margin-bottom:8px;padding:6px 8px;background:var(--p3);border-radius:6px'>";
            h+="<div style='font-weight:600;font-size:13px;margin-bottom:4px'>📝 AI 分析结论</div>";
            h+="<div style='display:flex;gap:16px;margin-bottom:4px'><span style='font-size:13px'>判定: <b>"+jText+"</b></span><span style='font-size:13px;color:"+impColor+"'>影响: "+impText+"</span></div>";
            if(pcKa.reason)h+="<div style='font-size:12px;color:var(--txt);margin-top:4px;line-height:1.5'>"+pcKa.reason+"</div>";
            h+="</div>";
          }
          if(_noFindReason)h+="<div style='font-size:12px;color:var(--amber);line-height:1.5'><b>未提交 finding 原因:</b> "+String(_noFindReason).replace(/</g,"&lt;")+"</div>";
          if(_ki&&typeof _ki==="object"){
            var _kiI=String(_ki.impact||"").toLowerCase();
            var _kiImpact=_kiI==="positive"?"正向 ✅":_kiI==="negative"?"负向 ❌":"中性 ⏳";
            var _kiImpactColor=_kiI==="positive"?"var(--green)":_kiI==="negative"?"var(--red)":"var(--gray)";
            h+="<div style='margin-top:6px;padding:6px 8px;background:var(--p3);border-radius:6px;border-left:2px solid "+_kiImpactColor+"'>";
            h+="<div style='font-size:11px;font-weight:600;color:var(--purple);margin-bottom:4px'>🧠 知识/记忆介入</div>";
            if(_ki.query)h+="<div style='font-size:12px;color:var(--sub);margin-bottom:3px'><b>问了什么:</b> "+String(_ki.query).replace(/</g,"&lt;")+"</div>";
            if(_ki.response)h+="<div style='font-size:12px;color:var(--sub);margin-bottom:3px;line-height:1.5'><b>回复了什么:</b> "+String(_ki.response).replace(/</g,"&lt;")+"</div>";
            if(_ki.decision)h+="<div style='font-size:12px;color:var(--txt);margin-bottom:3px;line-height:1.5'><b>Agent 决策:</b> "+String(_ki.decision).replace(/</g,"&lt;")+"</div>";
            h+="<div style='font-size:12px;color:"+_kiImpactColor+"'><b>影响方向:</b> "+_kiImpact+"</div>";
            h+="</div>";
          }
          h+="</div>";
        }
        if(_hasNogkFinding){
          h+="<div style='padding:6px 8px;background:var(--p2);border-radius:6px'>";
          h+="<div style='font-size:11px;font-weight:600;color:var(--sub);margin-bottom:3px'>No-KG</div>";
          if(_nogkNoFindReason)h+="<div style='font-size:12px;color:var(--amber);line-height:1.5'><b>未提交 finding 原因:</b> "+String(_nogkNoFindReason).replace(/</g,"&lt;")+"</div>";
          if(_nogkKi&&typeof _nogkKi==="object"){
            var _nkiI=String(_nogkKi.impact||"").toLowerCase();
            var _nkiImpact=_nkiI==="positive"?"正向 ✅":_nkiI==="negative"?"负向 ❌":"中性 ⏳";
            var _nkiImpactColor=_nkiI==="positive"?"var(--green)":_nkiI==="negative"?"var(--red)":"var(--gray)";
            h+="<div style='margin-top:6px;padding:6px 8px;background:var(--p3);border-radius:6px;border-left:2px solid "+_nkiImpactColor+"'>";
            h+="<div style='font-size:11px;font-weight:600;color:var(--purple);margin-bottom:4px'>🧠 知识/记忆介入</div>";
            if(_nogkKi.query)h+="<div style='font-size:12px;color:var(--sub);margin-bottom:3px'><b>问了什么:</b> "+String(_nogkKi.query).replace(/</g,"&lt;")+"</div>";
            if(_nogkKi.response)h+="<div style='font-size:12px;color:var(--sub);margin-bottom:3px;line-height:1.5'><b>回复了什么:</b> "+String(_nogkKi.response).replace(/</g,"&lt;")+"</div>";
            if(_nogkKi.decision)h+="<div style='font-size:12px;color:var(--txt);margin-bottom:3px;line-height:1.5'><b>Agent 决策:</b> "+String(_nogkKi.decision).replace(/</g,"&lt;")+"</div>";
            h+="<div style='font-size:12px;color:"+_nkiImpactColor+"'><b>影响方向:</b> "+_nkiImpact+"</div>";
            h+="</div>";
          }
          h+="</div>";
        }
        h+="</div>";
      }
      if(c.matched||(_hasNogk&&c.nogk_matched)){
        h+="<div style='display:flex;gap:16px;margin-bottom:6px'>"+(c.matched?confBadge("KG",conf):"")+(_hasNogk&&c.nogk_matched?confBadge("No-KG",nogkConf):"")+"</div>";
      }
      // 候选 finding（预筛选认为可能匹配但未最终匹配的 agent finding，以基线为中心）
      function _renderCands(label,cands){
        if(!cands||!cands.length) return "";
        var hh="<details style='margin-top:6px;border-top:1px solid var(--border);padding-top:6px'>";
        hh+="<summary style='font-size:12px;font-weight:600;color:var(--sub);margin-bottom:4px;cursor:pointer'>📋 "+label+" 候选 Finding（"+cands.length+" 条，预筛选匹配但未最终匹配）</summary>";
        // 基线漏洞信息（供人工对比）
        var blType=c.vulnerability_type||"";
        var blDesc=c.description||"";
        var blFile=c.source_file||"";
        var blFunc=c.source_function||"";
        var blLine=c.source_line||"";
        var blLoc=blLine||blFunc;
        if(blType||blDesc||blFile||blLoc){
          hh+="<div style='margin-bottom:8px;padding:8px;background:var(--p3);border-radius:6px;border-left:3px solid var(--acc)'>";
          hh+="<div style='font-size:11px;font-weight:600;color:var(--acc);margin-bottom:4px'>基线漏洞（对比参考）</div>";
          if(blType)hh+="<div style='font-size:12px;color:var(--txt)'><b>类型:</b> "+String(blType).replace(/</g,"&lt;")+"</div>";
          if(blFile||blLoc)hh+="<div style='font-size:12px;color:var(--sub)'><b>位置:</b> "+String(blLoc?blLoc+" @ ":"").replace(/</g,"&lt;")+String(blFile).replace(/</g,"&lt;")+"</div>";
          if(blDesc)hh+="<div style='font-size:12px;color:var(--sub);line-height:1.4;margin-top:2px;max-height:120px;overflow-y:auto'>"+String(blDesc).replace(/</g,"&lt;")+"</div>";
          hh+="</div>";
        }
        cands.forEach(function(cf,i){
          var vrColor=cf.validation_result==="CONFIRMED"?"var(--green)":cf.validation_result==="FALSE_POSITIVE"?"var(--red)":"var(--gray)";
          var vrText=cf.validation_result==="CONFIRMED"?"确认漏洞":cf.validation_result==="FALSE_POSITIVE"?"判为非漏洞":cf.validation_result||"未知";
          hh+="<div style='margin-bottom:6px;padding:8px;background:var(--p2);border-radius:6px'>";
          hh+="<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:4px'>";
          hh+="<span style='font-size:12px;color:"+vrColor+"'>["+(i+1)+"] "+vrText+"</span>";
          if(cf.vuln_type)hh+="<span style='font-size:11px;color:var(--sub)'>"+String(cf.vuln_type).replace(/</g,"&lt;")+"</span>";
          hh+="</div>";
          if(cf.title)hh+="<div style='font-size:12px;color:var(--txt);line-height:1.4;font-weight:600'>"+String(cf.title).replace(/</g,"&lt;")+"</div>";
          if(cf.description)hh+="<div style='font-size:12px;color:var(--sub);line-height:1.4;margin-top:2px;max-height:150px;overflow-y:auto'>"+String(cf.description).replace(/</g,"&lt;")+"</div>";
          if(cf.source||cf.sink){
            hh+="<div style='font-size:11px;color:var(--gray);margin-top:4px'>";
            if(cf.source)hh+="入口: <code>"+String(cf.source).replace(/</g,"&lt;")+"</code> ";
            if(cf.sink)hh+="出口: <code>"+String(cf.sink).replace(/</g,"&lt;")+"</code>";
            hh+="</div>";
          }
          hh+="<div style='font-size:11px;color:var(--gray);font-family:monospace;margin-top:2px'>"+String(cf.finding_id||"").replace(/</g,"&lt;")+"</div>";
          hh+="</div>";
        });
        hh+="</details>";
        return hh;
      }
      if(!c.matched) h+=_renderCands("KG",c.candidate_findings);
      if(_hasNogk&&!c.nogk_matched) h+=_renderCands("No-KG",c.nogk_candidate_findings);
      // 知识与记忆交互明细
      if(pcKa&&kgActive){
        // 知识图谱交互
        var ivs=pcKa.interactions||[];
        if(ivs.length){
          h+="<details style='margin-top:6px;border-top:1px solid var(--border);padding-top:6px'>";
          h+="<summary style='font-size:12px;font-weight:600;color:var(--sub);margin-bottom:4px;cursor:pointer'>🔍 知识交互（"+ivs.length+" 条）</summary>";
          ivs.forEach(function(iv,i){
            h+="<div style='margin-bottom:6px;padding:6px;background:var(--p2);border-radius:6px'>";
            var src=iv.session_id?("session: "+String(iv.session_id).slice(0,16)+"…"):"";
            if(iv.timestamp){src+=" · "+fmtTs(iv.timestamp);}
            h+="<div style='font-size:11px;color:var(--gray);margin-bottom:2px'>知识"+(i+1)+"："+(iv.tool||"")+(src?" <span style='color:var(--gray);font-size:10px'>["+src+"]</span>":"")+"</div>";
            var qp=iv.command_parsed||iv.question||"";
            var op=iv.output_parsed||iv.answer||"";
            var rawQ=iv.command||iv.question||"";
            var rawA=iv.answer||"";
            if(qp){
              h+="<div style='font-size:12px;color:var(--txt);line-height:1.4'><b>查询:</b> "+qp.replace(/</g,"&lt;")+"</div>";
            }
            if(op){
              h+="<div style='font-size:12px;color:var(--sub);line-height:1.4;margin-top:2px'><b>回答:</b> "+op.replace(/</g,"&lt;")+"</div>";
            }
            if(rawQ||rawA){
              h+="<details style='margin-top:2px'><summary style='font-size:11px;color:var(--gray);cursor:pointer'>原始数据</summary>";
              if(rawQ)h+="<div style='font-size:11px;color:var(--gray);word-break:break-all'><code>"+String(rawQ).replace(/</g,"&lt;").slice(0,400)+"</code></div>";
              if(rawA)h+="<div style='font-size:11px;color:var(--gray);word-break:break-all'><code>"+String(rawA).replace(/</g,"&lt;").slice(0,600)+"</code></div>";
              h+="</details>";
            }
            h+="</div>";
          });
          h+="</details>";
        }
        // 记忆交互
        var memIvs=pcKa.memory_interactions||[];
        if(memIvs.length){
          h+="<details style='margin-top:6px;border-top:1px solid var(--border);padding-top:6px'>";
          h+="<summary style='font-size:12px;font-weight:600;color:var(--sub);margin-bottom:4px;cursor:pointer'>🧠 记忆交互（"+memIvs.length+" 条）</summary>";
          memIvs.forEach(function(iv,i){
            h+="<div style='margin-bottom:6px;padding:6px;background:var(--p2);border-radius:6px'>";
            var src=iv.session_id?("session: "+String(iv.session_id).slice(0,16)+"…"):"";
            if(iv.timestamp){src+=" · "+fmtTs(iv.timestamp);}
            h+="<div style='font-size:11px;color:var(--gray);margin-bottom:2px'>记忆"+(i+1)+"："+(iv.tool||"")+(src?" <span style='color:var(--gray);font-size:10px'>["+src+"]</span>":"")+"</div>";
            var qp=iv.command_parsed||iv.question||"";
            var op=iv.output_parsed||iv.answer||"";
            var rawQ=iv.command||iv.question||"";
            var rawA=iv.answer||"";
            if(qp){
              h+="<div style='font-size:12px;color:var(--txt);line-height:1.4'><b>查询:</b> "+qp.replace(/</g,"&lt;")+"</div>";
            }
            if(op){
              h+="<div style='font-size:12px;color:var(--sub);line-height:1.4;margin-top:2px'><b>回答:</b> "+op.replace(/</g,"&lt;")+"</div>";
            }
            if(rawQ||rawA){
              h+="<details style='margin-top:2px'><summary style='font-size:11px;color:var(--gray);cursor:pointer'>原始数据</summary>";
              if(rawQ)h+="<div style='font-size:11px;color:var(--gray);word-break:break-all'><code>"+String(rawQ).replace(/</g,"&lt;").slice(0,400)+"</code></div>";
              if(rawA)h+="<div style='font-size:11px;color:var(--gray);word-break:break-all'><code>"+String(rawA).replace(/</g,"&lt;").slice(0,600)+"</code></div>";
              h+="</details>";
            }
            h+="</div>";
          });
          h+="</details>";
        }
      }
      h+="</div>";
      return h;
    }
    // 按漏洞/非漏洞分组展示
    var vulnCases=caseResults.filter(function(c){return c.expected_label==="VULNERABLE";});
    var nonVulnCases=caseResults.filter(function(c){return c.expected_label==="NON_VULNERABLE";});
    if(vulnCases.length){
      kgHtml+="<div style='font-size:15px;margin:12px 0 8px;font-weight:600'>🔴 漏洞基线（<b>"+vulnCases.length+"</b> 个）</div>";
      vulnCases.forEach(function(c,i){kgHtml+=_renderCaseCard(c,i);});
    }
    if(nonVulnCases.length){
      kgHtml+="<div style='font-size:15px;margin:12px 0 8px;font-weight:600'>🟢 非漏洞基线（<b>"+nonVulnCases.length+"</b> 个）</div>";
      nonVulnCases.forEach(function(c,i){kgHtml+=_renderCaseCard(c,i);});
    }
  }
  return kgHtml;
  }

  // 评测元信息
  const evalName=d.evaluation_name||d.evaluation_id;
  const vbenchName=d.vbench_project_name||"";
  const entriesInfo=d.entries_info||[];
  const kgInfo=entriesInfo.find(e=>e.condition==="KG")||{};
  const nogkInfo=entriesInfo.find(e=>e.condition==="NOGK")||{};

  $("rep").innerHTML=`
  <div style="margin-bottom:22px">
    <h2 style="font-size:22px;margin-bottom:6px;text-align:center">${evalName}</h2>
    <div style="color:var(--sub);font-size:16px;margin-bottom:8px"><span class="bdg b-${d.status||""}">${d.status||"-"}</span></div>
    ${(r.warnings&&r.warnings.length)?`<div style="background:rgba(251,191,36,.12);border:1px solid var(--amber);border-radius:8px;padding:10px 14px;margin-bottom:8px;font-size:14px"><b>告警：</b><ul style="margin:6px 0 0;padding-left:20px">${r.warnings.map(w=>`<li>${w}</li>`).join("")}</ul></div>`:""}
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px 20px;font-size:14px;color:var(--sub);background:var(--p2);border-radius:10px;padding:12px 16px">
      <div><span style="color:var(--gray)">KG 项目：</span><b>${kgInfo.project_name||"-"}</b> · <span style="color:var(--gray)">任务：</span><b>${kgInfo.task_name||"-"}</b></div>
      ${(r.has_nogk!==false)?`<div><span style="color:var(--gray)">No-KG 项目：</span><b>${nogkInfo.project_name||"-"}</b> · <span style="color:var(--gray)">任务：</span><b>${nogkInfo.task_name||"-"}</b></div>`:""}
      <div><span style="color:var(--gray)">基线来源：</span><b>${d.benchmark_source==='vuln_center'?'漏洞中心数据':(vbenchName||'无（无 GT 模式）')}</b></div>
      <div><span style="color:var(--gray)">评测 ID：</span><b style="font-family:monospace">${d.evaluation_id}</b></div>
      <div><span style="color:var(--gray)">运行时长：</span><b>${(d.started_at&&d.finished_at)?fmtDur(new Date(d.finished_at)-new Date(d.started_at)):'-'}</b> <span style="color:var(--gray);font-size:13px">（${(d.started_at||'').replace('T',' ').slice(0,19)} → ${(d.finished_at||'').replace('T',' ').slice(0,19)}）</span></div>
    </div>
  </div>

  <!-- 1. 按评测类别展示详情 -->
  ${(()=>{
    const rawGroups=r.metric_groups||[];
    const mg=(rawGroups.length?rawGroups:[{task_id:"",label:"评测结果",p0,p1,p2,diagnostic_hits:h}]).slice().sort((a,b)=>{
      const order={mining:0,verify:1};return (order[a.category]??2)-(order[b.category]??2);
    });
    function _statsTable(tid,label){
      const tools=d.tool_stats||[];const res=d.resource_stats||[];const oc=d.outcome_details||[];
      const hasNogk=(r.has_nogk!==false);
      const kgTool=tools.find(t=>t.task_run_id.includes("-"+tid+"-KG"))||tools.find(t=>t.task_run_id.includes("KG")&&!t.task_run_id.includes("NOGK"))||{};
      const nogkTool=hasNogk?(tools.find(t=>t.task_run_id.includes("-"+tid+"-NOGK"))||tools.find(t=>t.task_run_id.includes("NOGK"))||{}):{};
      const kgRes=res.find(t=>t.task_run_id.includes("-"+tid+"-KG"))||res.find(t=>t.task_run_id.includes("KG")&&!t.task_run_id.includes("NOGK"))||{};
      const nogkRes=hasNogk?(res.find(t=>t.task_run_id.includes("-"+tid+"-NOGK"))||res.find(t=>t.task_run_id.includes("NOGK"))||{}):{};
      const kgOc=oc.find(o=>o.task_run_id.includes("-"+tid+"-KG"))||oc.find(o=>o.task_run_id.includes("KG")&&!o.task_run_id.includes("NOGK"))||{};
      const nogkOc=hasNogk?(oc.find(o=>o.task_run_id.includes("-"+tid+"-NOGK"))||oc.find(o=>o.task_run_id.includes("NOGK"))||{}):{};
      const kgFound=kgTool.finding_count||0;const nogkFound=nogkTool.finding_count||0;
      const kgFP=kgTool.false_positive_count||0;const nogkFP=nogkTool.false_positive_count||0;
      const kgRecv=kgTool.analyze_received_count||(kgFound+kgFP);const nogkRecv=nogkTool.analyze_received_count||(nogkFound+nogkFP);
      const isVerify=label.includes("验证");
      const kgKi=(d.knowledge_interactions||[]).find(k=>k.task_run_id.includes("-"+tid+"-KG"))||{};
      const kgKg=kgKi.kg_stats?kgKi.kg_stats.call_count:(kgKi.interactions||[]).filter(iv=>iv.type==="CALL").length;
      const nogkKg=0;
      const kgMem=kgKi.mem_stats?kgKi.mem_stats.call_count:((kgKi.memory||{}).interactions||[]).filter(iv=>iv.type==="CALL").length;
      const nogkMem=0;
      const kgTokens=kgRes.tokens||0;const nogkTokens=nogkRes.tokens||0;
      const kgTools=kgTool.total_tools||0;const nogkTools=nogkTool.total_tools||0;
      const kgSteps=kgRes.steps||0;const nogkSteps=nogkRes.steps||0;
      const kgDur=kgRes.duration||0;const nogkDur=nogkRes.duration||0;
      const group=mg.find(g=>g.task_id===tid);
      const cr=Array.isArray(group&&group.case_results)?group.case_results:[];
      const baseline=cr.length||(d.baseline_count||0);
      const vulnN=cr.filter(c=>c.expected_label==="VULNERABLE").length;
      const nonVulnN=cr.filter(c=>c.expected_label==="NON_VULNERABLE").length;
      const ac=group&&group.alert_center;
      let acHtml="";
      if(ac){
        const kgAc=ac.kg||{};const nogkAc=ac.nogk||{};
        const kgT=kgAc.total||0;const nogkT=nogkAc.total||0;
        if(isVerify){
          const kc=kgAc.counts||{};const nogkCounts=hasNogk?(nogkAc.counts||{}):{};
          const acRow=(label,c,t)=>t?`<td class="num"><b style="font-size:16px">${t}</b>
            <span style="font-size:12px;margin-left:8px">
              <span style="color:var(--green)">是漏洞 ${c.vulnerable||0}</span> ·
              <span style="color:var(--red)">不是漏洞 ${c.not_vulnerable||0}</span> ·
              <span style="color:var(--amber)">研判中 ${c.pending||0}</span> ·
              <span style="color:var(--gray)">无法判定 ${c.inconclusive||0}</span>
            </span></td>`:'<td class="num">—</td>';
          acHtml=`<table style="margin-bottom:12px"><tr><th>告警中心收到漏洞数</th><th>KG（开知识图谱与记忆）</th>${hasNogk?'<th>No-KG（对照）</th>':''}</tr>
            <tr><td></td>${acRow("",kc,kgT)}${hasNogk?acRow("",nogkCounts,nogkT):''}</tr></table>`;
        }else{
          acHtml=`<div style="font-size:16px;margin-bottom:12px;padding:8px 12px;background:var(--p3);border-radius:8px">
            告警中心收到漏洞数 — KG：<b style="font-size:18px">${kgT}</b>${hasNogk?`<span style="margin-left:24px">No-KG：<b style="font-size:18px">${nogkT}</b></span>`:''}</div>`;
        }
      }
      const nogkTh=hasNogk?'<th>No-KG（对照）</th>':'';
      const nc=v=>hasNogk?`<td class="num">${v}</td>`:'';
      return `<div class="card" style="margin-bottom:16px">
        <h3>📊 ${label} — 漏洞检测统计</h3>
        ${acHtml}
        <div style="font-size:16px;margin-bottom:12px">基准漏洞数：<b style="font-size:18px">${baseline}</b>${cr.length?`<span style="margin-left:12px;font-size:14px;color:var(--gray)">漏洞 <b>${vulnN}</b> · 非漏洞 <b>${nonVulnN}</b></span>`:""}</div>
        <table><tr><th>统计项</th><th>KG（开知识图谱与记忆）</th>${nogkTh}</tr>
        <tr><td>${isVerify?"验证接收总数":"发现 finding 数"}</td><td class="num">${kgRecv}</td>${nc(nogkRecv)}</tr>
        <tr><td>${isVerify?"确认漏洞数":"上报漏洞数"}</td><td class="num">${kgFound}</td>${nc(nogkFound)}</tr>
        <tr><td>误报数（非漏洞）</td><td class="num">${kgFP}</td>${nc(nogkFP)}</tr>
        <tr><td>知识图谱查询次数</td><td class="num">${kgKg}</td>${nc(nogkKg)}</tr>
        <tr><td>记忆查询次数</td><td class="num">${kgMem}</td>${nc(nogkMem)}</tr>
        <tr><td>Token 消耗</td><td class="num">${fmtNum(kgTokens)}</td>${nc(fmtNum(nogkTokens))}</tr>
        <tr><td>工具调用次数</td><td class="num">${kgTools}</td>${nc(nogkTools)}</tr>
        <tr><td>执行步数</td><td class="num">${kgSteps}</td>${nc(nogkSteps)}</tr>
        <tr><td>运行时长</td><td class="num">${fmtDur(kgDur)}</td>${nc(fmtDur(nogkDur))}</tr>
        <tr><td>检测结果</td><td class="num">${kgOc.outcome||"N/A"}</td>${nc(nogkOc.outcome||"N/A")}</tr>
        <tr><td>验证结果</td><td class="num">${kgOc.validation||"N/A"}</td>${nc(nogkOc.validation||"N/A")}</tr>
        </table></div>`;
    }
    function _metricCards(gp0,gp1,gp2,glabel,cat){
      const isVerify=cat==="verify";
      // 从差值指标的 method 字典中提取绝对值，构造伪指标对象供 mCard 渲染
      function _absMetric(metric,key,desc){
        if(!metric) return null;
        if(metric.calculation_status!=="CALCULATED") return metric;
        const method=metric.method||{};
        const val=method[key];
        if(val==null) return {calculation_status:"NO_DATA",reason_code:"NO_DATA",n:metric.n};
        var cm=null;
        if(key.endsWith("_kg")){
          if(method.tp_kg!=null){cm={tp:method.tp_kg,fp:method.fp_kg,fn:method.fn_kg,tn:method.tn_kg};}
        }else{
          if(method.tp_n!=null){cm={tp:method.tp_n,fp:method.fp_n,fn:method.fn_n,tn:method.tn_n};}
        }
        return {estimate:val,calculation_status:"CALCULATED",n:metric.n,unit:metric.unit||"ratio",method:{},d:desc,cm:cm};
      }
      const hasNogk=r.has_nogk!==false; // 默认 true（兼容旧报告）
      const groups=[
        ["① KG vs 基线","开知识图谱条件下的漏洞判定准确性",
          [["M1",_absMetric(gp0.M1,"ba_kg","KG 条件下与基线对比的平衡准确率")],["M4",_absMetric(gp0.M4,"fnr_kg","KG 条件下与基线对比的漏报率")],["M13",_absMetric(gp0.M13,"fpr_kg","KG 条件下与基线对比的误报率")],["M14",_absMetric(gp0.M14,"precision_kg","KG 条件下与基线对比的精确率")]]],
        ...(hasNogk?[["② No-KG vs 基线","无知识图谱条件下的漏洞判定准确性",
          [["M1",_absMetric(gp0.M1,"ba_nogk","No-KG 条件下与基线对比的平衡准确率")],["M4",_absMetric(gp0.M4,"fnr_nogk","No-KG 条件下与基线对比的漏报率")],["M13",_absMetric(gp0.M13,"fpr_nogk","No-KG 条件下与基线对比的误报率")],["M14",_absMetric(gp0.M14,"precision_nogk","No-KG 条件下与基线对比的精确率")]]]]:[]),
        ["③ 作用机制","揭示知识访问/交付/记忆的介入情况"+(hasNogk&&!isVerify?"（含行为偏移）":""),
          (isVerify||!hasNogk)?[["M5",gp1.M5],["M6",gp1.M6],["M11",gp1.M11],["M12",gp1.M12]]:[["M5",gp1.M5],["M6",gp1.M6],["M7",gp1.M7],["M11",gp1.M11],["M12",gp1.M12]]],
        ...(!isVerify&&hasNogk?[["④ 成本效率","对比 KG 与 No-KG 的资源消耗",
          [["M8",gp2.M8],["M9",gp2.M9],["M10",gp2.M10]]]]:[])
      ];
      return `${groups.map(g=>`<div style="margin-bottom:14px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;padding:6px 12px;background:var(--p3);border-left:4px solid var(--acc);border-radius:0 8px 8px 0">
          <span style="font-weight:700;font-size:15px">${g[0]}</span>
          <span style="font-size:12px;color:var(--sub)">— ${g[1]}</span>
        </div>
        <div class="mcards" style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px">
          ${g[2].map(m=>mCard(m[0],m[1])).join("")}
        </div>
      </div>`).join("")}`;
    }
    const _hasNogk=r.has_nogk!==false;
    function _buildMatchTable(groupList,title,icon){
      const rows=[];let idx=1;
      let kgTP=0,kgFP=0,kgFN=0,kgTN=0,kgNA=0;
      let nogkTP=0,nogkFP=0,nogkFN=0,nogkTN=0,nogkNA=0;
      for(const g of groupList){
        const crs=Array.isArray(g.case_results)?g.case_results:[];
        for(const c of crs){
          const baseTitle=(c.vulnerability_type||c.case_id||"-").replace(/</g,"&lt;");
          const expLabel=c.expected_label||"";
          const expBadge=expLabel==="VULNERABLE"?"<span class='bdg b-FAILED' style='font-size:10px'>漏洞</span>":expLabel==="NON_VULNERABLE"?"<span class='bdg b-CREATED' style='font-size:10px'>非漏洞</span>":"";
          const kgCands=c.candidate_findings||[];
          const kgCandNote=(!c.matched&&kgCands.length)?`<div style="font-size:11px;color:var(--amber)">候选 ${kgCands.length} 条${kgCands.some(f=>f.validation_result==="FALSE_POSITIVE")?"（含判为非漏洞）":""}</div>`:"";
          const kgAc=c.ac_case_id?`（${c.ac_case_id}）`:"";
          let kgCell;
          function _chainHtml(chain){
            if(!chain||!chain.length)return "";
            var parts=chain.map(function(s){
              var sid=String(s.session_id||"").slice(0,8);
              var mark=s.has_finding?"📝":s.has_sink?"🎯":"";
              var color=s.has_finding?"var(--green)":s.has_sink?"var(--acc)":"var(--gray)";
              return "<code style='font-size:11px;color:"+color+"'>"+mark+sid+"</code>";
            });
            return "<div style='font-size:11px;margin-top:2px'>"+parts.join(" → ")+"</div>";
          }
          const _kgSessInfo=_chainHtml(c.session_chain);
          if(c.matched){
            kgCell=`<span style="color:var(--green)">✓命中</span> ${(c.finding_title||c.matched_finding_id||"-").replace(/</g,"&lt;")}`+(_kgSessInfo||kgCandNote);
          }else if(c.mined){
            kgCell=`<span style="color:var(--amber)">sink命中·挖掘无报</span>`+kgCandNote+_kgSessInfo;
          }else if(c.sink_hit){
            kgCell=`<span style="color:var(--amber)">sink命中·非挖掘</span>`+kgCandNote+_kgSessInfo;
          }else{
            kgCell=`<span style="color:var(--gray)">sink未命中</span>`;
          }
          var kgConf=c.confusion||"NA";
          var kgConfColor=kgConf==="TP"||kgConf==="TN"?"var(--green)":kgConf==="FP"||kgConf==="FN"?"var(--red)":"var(--gray)";
          var kgConfBadge=`<span style="font-size:11px;font-weight:600;color:${kgConfColor}">${CONF_LABEL[kgConf]||kgConf}</span>`;
          if(kgConf==="TP")kgTP++;else if(kgConf==="FP"&&c.sink_hit)kgFP++;else if(kgConf==="FN")kgFN++;else if(kgConf==="TN"&&c.sink_hit)kgTN++;else kgNA++;
          let nogkCell="";
          if(_hasNogk){
            const nogkCands=c.nogk_candidate_findings||[];
            const nogkCandNote=(!c.nogk_matched&&nogkCands.length)?`<div style="font-size:11px;color:var(--amber)">候选 ${nogkCands.length} 条${nogkCands.some(f=>f.validation_result==="FALSE_POSITIVE")?"（含判为非漏洞）":""}</div>`:"";
            const nogkAc=c.nogk_ac_case_id?`（${c.nogk_ac_case_id}）`:"";
            const _nogkSessInfo=_chainHtml(c.nogk_session_chain);
            if(c.nogk_matched){
              nogkCell=`<td><span style="color:var(--green)">✓命中</span> ${(c.nogk_finding_title||"-").replace(/</g,"&lt;")}${nogkAc?`<span style="font-size:12px;color:var(--acc)">${nogkAc}</span>`:""}${_nogkSessInfo||nogkCandNote}</td>`;
            }else if(c.nogk_mined){
              nogkCell=`<td><span style="color:var(--amber)">sink命中·挖掘无报</span>${nogkCandNote}${_nogkSessInfo}</td>`;
            }else if(c.nogk_sink_hit){
              nogkCell=`<td><span style="color:var(--amber)">sink命中·非挖掘</span>${nogkCandNote}${_nogkSessInfo}</td>`;
            }else{
              nogkCell=`<td><span style="color:var(--gray)">sink未命中</span></td>`;
            }
            var nogkConf=c.nogk_confusion||"NA";
            var nogkConfColor=nogkConf==="TP"||nogkConf==="TN"?"var(--green)":nogkConf==="FP"||nogkConf==="FN"?"var(--red)":"var(--gray)";
            if(nogkConf==="TP")nogkTP++;else if(nogkConf==="FP"&&c.nogk_sink_hit)nogkFP++;else if(nogkConf==="FN")nogkFN++;else if(nogkConf==="TN"&&c.nogk_sink_hit)nogkTN++;else nogkNA++;
            nogkCell=nogkCell.replace(/<\/td>$/,` ${nogkConfColor?`<span style="font-size:11px;font-weight:600;color:${nogkConfColor}">${CONF_LABEL[nogkConf]||nogkConf}</span>`:""}</td>`);
          }
          rows.push(`<tr>
            <td class="num">${idx}</td>
            <td>${baseTitle} ${expBadge}${c.case_id?`<div style="font-size:12px;color:var(--gray)">${c.case_id.replace(/</g,"&lt;")}</div>`:""}</td>
            <td>${kgCell}${kgAc?`<span style="font-size:12px;color:var(--acc)">${kgAc}</span>`:""} ${kgConfBadge}</td>
            ${nogkCell}
          </tr>`);
          idx++;
        }
      }
      if(!rows.length) return "";
      const kgDenom=kgTP+kgFP+kgFN+kgTN;
      const nogkDenom=nogkTP+nogkFP+nogkFN+nogkTN;
      const kgFprNum=kgFP+kgFN,kgFprDen=kgDenom;
      const nogkFprNum=nogkFP+nogkFN,nogkFprDen=nogkDenom;
      const kgFprStr=kgFprDen>0?(kgFprNum/kgFprDen*100).toFixed(1)+"%":"—";
      const nogkFprStr=nogkFprDen>0?(nogkFprNum/nogkFprDen*100).toFixed(1)+"%":"—";
      const summary=_hasNogk
        ? `<div style="font-size:14px;color:var(--sub);margin-bottom:12px;padding:8px 12px;background:var(--p2);border-radius:8px">KG 误报率=${kgFprStr}（分子=${kgFprNum}=假阳性${kgFP}+假阴性${kgFN} 分母=${kgFprDen}=sink命中的case数）<span style="margin-left:16px">No-KG 误报率=${nogkFprStr}（分子=${nogkFprNum}=假阳性${nogkFP}+假阴性${nogkFN} 分母=${nogkFprDen}）</span><div style="font-size:12px;margin-top:4px;color:var(--gray)">混淆矩阵：真阳性=${kgTP} 假阳性=${kgFP} 假阴性=${kgFN} 真阴性=${kgTN}${kgNA?` 未判定=${kgNA}`:""}（不含sink未命中的未判定）</div></div>`
        : `<div style="font-size:14px;color:var(--sub);margin-bottom:12px;padding:8px 12px;background:var(--p2);border-radius:8px">KG 误报率=${kgFprStr}（分子=${kgFprNum}=假阳性${kgFP}+假阴性${kgFN} 分母=${kgFprDen}=sink命中的case数）<div style="font-size:12px;margin-top:4px;color:var(--gray)">混淆矩阵：真阳性=${kgTP} 假阳性=${kgFP} 假阴性=${kgFN} 真阴性=${kgTN}${kgNA?` 未判定=${kgNA}`:""}（不含sink未命中的未判定）</div></div>`;
      return `<div class="card" style="margin-bottom:16px">
        <h3>${icon} ${title}</h3>
        ${summary}
        <table><tr><th>序号</th><th>基线</th><th>KG 结果</th>${_hasNogk?'<th>No-KG 结果</th>':''}</tr>
        ${rows.join("")}
        </table>
      </div>`;
    }
    const tabs=mg.length>1?`<div role="tablist" aria-label="报告类别" style="display:grid;grid-template-columns:repeat(${mg.length},minmax(0,1fr));gap:12px;margin:0 0 20px">${mg.map((g,i)=>{const mining=g.category!=="verify";const icon=mining?'🔎':'✅';const desc=mining?'发现与提交潜在漏洞':'验证候选漏洞是否成立';return`<button class="btn" role="tab" data-report-tab-btn aria-selected="${i===0?'true':'false'}" style="text-align:left;display:flex;gap:10px;align-items:center;padding:13px 15px;border:1px solid ${i===0?'var(--acc)':'var(--bd)'};background:${i===0?'var(--acc)':'var(--panel)'};color:${i===0?'#fff':'var(--sub)'};${i===0?'box-shadow:0 8px 20px rgba(124,58,237,.28);transform:translateY(-2px)':''}" onclick="selectReportTab(this,'report-tab-${i}')"><span style="font-size:24px">${icon}</span><span><b style="display:block;font-size:16px">${g.label}</b><small style="display:block;margin-top:3px;opacity:.82">${desc}</small></span></button>`}).join("")}</div><div style="font-size:14px;color:var(--sub);margin:-8px 0 16px;padding:8px 10px;background:var(--p2);border-radius:8px">当前选中的类别决定下方全部统计、效果指标和诊断的范围。</div>`:"";
    const panes=mg.map((g,i)=>`<div id="report-tab-${i}" data-report-tab style="display:${i===0?'block':'none'}">
      <div style="display:flex;align-items:center;gap:8px;margin:0 0 12px"><span style="font-size:18px">${g.category==='verify'?'✅':'🔎'}</span><b style="font-size:18px">当前查看：${g.label}</b><span style="font-size:13px;color:var(--sub)">以下内容仅属于此类别</span></div>
      ${_statsTable(g.task_id,g.label)}
      <div class="card" style="margin-bottom:16px"><h3>🎯 ${g.label} — 效果指标</h3>${_metricCards(g.p0||{},g.p1||{},g.p2||{},g.label,g.category)}</div>
      <div class="card" style="margin-bottom:16px">
        <h3>🧠 ${g.label} — 知识图谱与记忆介入分析</h3>
        ${Array.isArray(g.case_results)&&Array.isArray(g.per_case_kg_analysis)
          ?buildKnowledgeHtml(g)
          :mg.length===1
            ?buildKnowledgeHtml(null)
            :'<div style="font-size:14px;color:var(--sub)">该历史报告未保存按类别拆分的逐漏洞知识图谱与记忆分析；请重跑评测以生成此数据。</div>'}
      </div>
      ${_buildMatchTable([g],g.category==='verify'?"基线与 Agent 验证匹配明细":g.category==='mining'?"基线与 Agent 发现匹配明细":"基线与 Agent 发现漏洞匹配明细",g.category==='verify'?"✅":g.category==='mining'?"🔎":"📋")}
    </div>`).join("");
    return `<section style="margin-bottom:16px">${tabs}${panes}</section>`;
  })()}

  ${(()=>{
    const tu=r.llm_token_usage||{};
    if(!tu.call_count) return "";
    return `<div class="card" style="margin-bottom:16px">
      <h3>🔧 评测引擎 LLM Token 消耗</h3>
      <table><tr><th>项目</th><th>数值</th></tr>
      <tr><td>LLM 调用次数</td><td class="num">${tu.call_count||0}</td></tr>
      <tr><td>Prompt Tokens</td><td class="num">${fmtNum(tu.prompt_tokens||0)}</td></tr>
      <tr><td>Completion Tokens</td><td class="num">${fmtNum(tu.completion_tokens||0)}</td></tr>
      <tr><td>Total Tokens</td><td class="num">${fmtNum(tu.total_tokens||0)}</td></tr>
      </table>
    </div>`;
  })()}

  `;
}
