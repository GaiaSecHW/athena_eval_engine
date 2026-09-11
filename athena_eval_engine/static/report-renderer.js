/*
 * report-renderer.js — 报告渲染器
 * 由 render_static_report 内联到静态报告 HTML 中，使报告完全自包含（无外部 JS 依赖）。
 * 提取自 dashboard.html 的 renderReport 及其依赖函数。
 */
function $(i){return document.getElementById(i);}
function el(h){const d=document.createElement("div");d.innerHTML=h;return d.firstChild;}

function fmtDur(ms){
  if(ms===null||ms===undefined)return'<span class="na">NA</span>';
  var abs=Math.abs(ms);var sign=ms<0?'-':'';
  if(abs>=3600000){var h=Math.floor(abs/3600000);var m=Math.floor((abs%3600000)/60000);return sign+h+'<span class="ci">时</span> '+m+'<span class="ci">分</span>';}
  if(abs>=60000){var m2=Math.floor(abs/60000);var s=Math.floor((abs%60000)/1000);return sign+m2+'<span class="ci">分</span> '+s+'<span class="ci">秒</span>';}
  if(abs>=1000){return sign+(abs/1000).toFixed(1)+'<span class="ci">秒</span>';}
  return sign+Math.round(abs)+'<span class="ci">ms</span>';
}
function fmt(v,u){
  if(v===null||v===undefined)return'<span class="na">NA</span>';
  if(u==="ratio")return (v*100).toFixed(1)+'<span class="ci">%</span>';
  if(u==="ms")return fmtDur(v);
  if(u==="steps"||u==="tokens"){const a=Math.abs(v);let s;
    if(a>=1e9)s=(v/1e9).toFixed(2)+'B';else if(a>=1e6)s=(v/1e6).toFixed(2)+'M';else if(a>=1e3)s=(v/1e3).toFixed(1)+'K';else s=Math.round(v).toString();
    return s+'<span class="ci">'+(u==="tokens"?" tok":" steps")+'</span>';}
  return Number(v).toFixed(3);
}
function fmtNum(v){const a=Math.abs(v);
  if(a>=1e9)return(v/1e9).toFixed(2)+'B';
  if(a>=1e6)return(v/1e6).toFixed(2)+'M';
  if(a>=1e3)return(v/1e3).toFixed(1)+'K';
  return Math.round(v).toString();}
const MI={
  M1:{n:"准确率变化(ΔBA)",short:"准确率",d:"KG vs No-KG 的平衡准确率差值。正值=KG 更准，负值=更差。",u:"ratio",
     range:[{v:-1,t:"KG 更差",c:"red"},{v:0,t:"无差异",c:"amber"},{v:1,t:"KG 更准",c:"green"}],
     interp:(v)=>v==null?"无基准，无法计算":v>0.05?`KG 准确率高出 ${(v*100).toFixed(1)}pp`:v<-0.05?`KG 准确率低 ${(-v*100).toFixed(1)}pp`:"准确率无明显差异",
     formula:"BA_KG - BA_NoKG, BA=(TPR+TNR)/2, TPR=TP/(TP+FN), TNR=TN/(TN+FP)"},
  M2:{n:"救回率(IR)",short:"救回率",d:"No-KG 失败的任务里 KG 救回的比例。越高越好。",u:"ratio",
     range:[{v:0,t:"无救回",c:"red"},{v:0.3,t:"一般",c:"amber"},{v:0.7,t:"高效",c:"green"}],
     interp:(v)=>v==null?"无失败任务可分析":v>=0.7?`救回率 ${v*100}%, 高效`:v>=0.3?`救回率 ${v*100}%, 一般`:`救回率 ${v*100}%, 偏低`,
     formula:"C / (C + D), C=救回(NoKG失败->KG成功), D=持续失败"},
  M3:{n:"回归率(RR)",short:"回归率",d:"No-KG 成功的任务里 KG 反而搞坏的比例。越低越好。",u:"ratio",
     range:[{v:0,t:"无回归",c:"green"},{v:0.1,t:"少量",c:"amber"},{v:0.3,t:"严重",c:"red"}],
     interp:(v)=>v==null?"无成功任务可分析":v<0.1?`回归率 ${v*100}%, 安全`:v<0.3?`回归率 ${v*100}%, 需关注`:`回归率 ${v*100}%, 严重`,
     formula:"B / (A + B), B=回归(NoKG成功->KG失败), A=保持"},
  M4:{n:"漏报率变化(ΔFNR)",short:"漏报率",d:"KG vs No-KG 漏报率差值。负值=KG 漏报更少(好)，正值=更多。",u:"ratio",
     range:[{v:-1,t:"KG 漏报少",c:"green"},{v:0,t:"无变化",c:"amber"},{v:1,t:"KG 漏报多",c:"red"}],
     interp:(v)=>v==null?"无基准":v<0?`KG 漏报减少 ${(-v*100).toFixed(1)}pp`:v>0?`KG 漏报增加 ${(v*100).toFixed(1)}pp`:"漏报率无变化",
     formula:"FNR_KG - FNR_NoKG, FNR=FN/(FN+TP)"},
  M5:{n:"知识访问率(KAR)",short:"知识访问",d:"Agent 工具调用中知识查询所占比例（交互级）。衡量 Agent 对知识的依赖程度。",u:"ratio",
     range:[{v:0,t:"无访问",c:"red"},{v:0.05,t:"少量",c:"amber"},{v:0.15,t:"充分",c:"green"}],
     interp:(v)=>v==null?"未观测到知识访问":v>=0.15?`知识访问率 ${(v*100).toFixed(1)}%, 充分`:v>=0.05?`知识访问率 ${(v*100).toFixed(1)}%, 少量`:`知识访问率 ${(v*100).toFixed(1)}%, 极低`,
     formula:"kg_count / total_tool_calls (知识查询次数 / 总工具调用次数)"},
  M6:{n:"知识交付率(KDR)",short:"知识交付",d:"知识查询中平台有效回复的比例（交互级）。衡量知识质量。",u:"ratio",
     range:[{v:0,t:"无交付",c:"red"},{v:0.5,t:"部分",c:"amber"},{v:0.8,t:"充分",c:"green"}],
     interp:(v)=>v==null?"未观测到知识交付":v>=0.8?`知识交付率 ${v*100}%, 充分`:v>=0.5?`知识交付率 ${v*100}%, 部分`:`知识交付率 ${v*100}%, 不足`,
     formula:"successful_read_count / access_event_count (有效回复次数 / 总查询次数)"},
  M7:{n:"行为偏移(JSD)",short:"行为偏移",d:"KG vs No-KG 工具使用分布差异。0=完全相同，1=完全不同。",u:"ratio",
     range:[{v:0,t:"无差异",c:"green"},{v:0.1,t:"轻微",c:"amber"},{v:0.3,t:"显著",c:"red"}],
     interp:(v)=>v==null?"无法计算":v<0.1?`行为偏移 ${v*100}%, 轻微`:v<0.3?`行为偏移 ${v*100}%, 明显`:`行为偏移 ${v*100}%, 显著`,
     formula:"median(JSD_i), JSD_i=(0.5*KL(P||M)+0.5*KL(Q||M))/ln2, M=(P+Q)/2, P/Q=工具使用概率分布"},
  M8:{n:"Token变化(ΔToken)",short:"Token",d:"KG - No-KG 有效 token 消耗。负值=KG 更省。",u:"tokens",
     range:[{v:-1,t:"KG 更省",c:"green"},{v:0,t:"无变化",c:"amber"},{v:1,t:"KG 更耗",c:"red"}],
     interp:(v)=>v==null?"无法计算":v<0?`KG 少用 ${fmtNum(Math.abs(v))} token`:v>0?`KG 多用 ${fmtNum(v)} token`:"token 消耗无差异",
     formula:"median(KG_tokens - NoKG_tokens)"},
  M9:{n:"步数变化(ΔSteps)",short:"步数",d:"KG - No-KG 推理步数。负值=KG 更少步。",u:"steps",
     range:[{v:-1,t:"KG 更少",c:"green"},{v:0,t:"无变化",c:"amber"},{v:1,t:"KG 更多",c:"red"}],
     interp:(v)=>v==null?"无法计算":v<0?`KG 少 ${fmtNum(Math.abs(v))} 步`:v>0?`KG 多 ${fmtNum(v)} 步`:"步数无差异",
     formula:"median(KG_steps - NoKG_steps)"},
  M10:{n:"时长变化(ΔTime)",short:"时长",d:"KG - No-KG 运行时长(ms)。负值=KG 更快。",u:"ms",
     range:[{v:-1,t:"KG 更快",c:"green"},{v:0,t:"无变化",c:"amber"},{v:1,t:"KG 更慢",c:"red"}],
     interp:(v)=>v==null?"无法计算":v<0?`KG 快 ${fmtDur(-v)}`:v>0?`KG 慢 ${fmtDur(v)}`:"时长无差异",
     formula:"median(KG_duration_ms - NoKG_duration_ms)"},
  M11:{n:"记忆访问率(MAR)",short:"记忆访问",d:"Agent 工具调用中记忆读取所占比例（交互级）。衡量 Agent 对记忆的依赖程度。",u:"ratio",
     range:[{v:0,t:"无访问",c:"red"},{v:0.05,t:"少量",c:"amber"},{v:0.15,t:"充分",c:"green"}],
     interp:(v)=>v==null?"未观测到记忆访问":v>=0.15?`记忆访问率 ${(v*100).toFixed(1)}%, 充分`:v>=0.05?`记忆访问率 ${(v*100).toFixed(1)}%, 少量`:`记忆访问率 ${(v*100).toFixed(1)}%, 极低`,
     formula:"memory_read_count / total_tool_calls (记忆读取次数 / 总工具调用次数)"},
  M12:{n:"记忆交付率(MDR)",short:"记忆交付",d:"记忆查询中成功读取的比例（交互级）。衡量记忆质量。",u:"ratio",
     range:[{v:0,t:"无交付",c:"red"},{v:0.5,t:"部分",c:"amber"},{v:0.8,t:"充分",c:"green"}],
     interp:(v)=>v==null?"未观测到记忆交付":v>=0.8?`记忆交付率 ${v*100}%, 充分`:v>=0.5?`记忆交付率 ${v*100}%, 部分`:`记忆交付率 ${v*100}%, 不足`,
     formula:"successful_memory_read_count / memory_access_event_count (成功记忆读取 / 记忆读取次数)"}
};
function mInfo(id){const m=MI[id];return m?`<div style="font-size:15px;color:var(--sub);margin-top:4px;line-height:1.5">${m.d}<br><span style="color:var(--gray);font-size:14px">单位：${m.u}</span></div>`:"";}
function dc(v,u){if(v===null||v===undefined)return"";if(u==="ratio")return v>0?"dp":"dn";return v<0?"dp":"dn";}
function ci(m){if(!m||m.ci_lower===null||m.ci_lower===undefined)return"";const u=m.unit==="ratio"?"pp":(m.unit==="ms"?"s":(m.unit||""));const lo=m.unit==="ratio"?(m.ci_lower*100).toFixed(1):(m.unit==="ms"?(m.ci_lower/1000).toFixed(1):Number(m.ci_lower).toFixed(2));const hi=m.unit==="ratio"?(m.ci_upper*100).toFixed(1):(m.unit==="ms"?(m.ci_upper/1000).toFixed(1):Number(m.ci_upper).toFixed(2));return`<div class="ci">95% CI [${lo}, ${hi}] ${u}</div>`;}
function row(m,l){const mid=l.split(" ")[0];const mi=MI[mid]||{n:l,u:""};const RC={"NO_STRATUM":"基线全部为漏洞型，无对照样本","NO_VALID_DENOMINATOR":"No-KG 全部成功，无改善空间","NO_POSITIVE_GT":"无漏洞型基线","BOOTSTRAP_UNSTABLE":"样本量不足"};if(!m)return`<tr><td><b>${mi.n||l}</b><div style="font-size:14px;color:var(--sub)">${mi.d||""}</div></td><td class="na">未计算</td><td>-</td><td></td><td></td></tr>`;const c=m.calculation_status!=="CALCULATED"?`<span class="na">${m.calculation_status}<br><span style="font-size:14px">${RC[m.reason_code]||m.reason_code||""}</span></span>`:`<span class="${dc(m.estimate,m.unit)}">${fmt(m.estimate,m.unit)}</span>`;const n=m.n!=null?`<span class="ci">N=${m.n}</span>${m.median!=null?'<br><span class="ci">med '+fmt(m.median,m.unit)+'</span>':''}`:"-";const p=m.p_value!=null?`<span class="ci">p=${m.p_value<0.001?'<0.001':m.p_value.toFixed(3)}</span>`:(m.median!=null?'<span class="ci">Wilcoxon</span>':"");return`<tr><td><b>${mi.n||l}</b><div style="font-size:15px;color:var(--sub);line-height:1.5">${mi.d||""}<br><span style="color:var(--gray);font-size:14px">单位：${mi.u}</span></div></td><td class="num">${c}</td><td>${n}</td><td>${ci(m)}</td><td>${p}</td></tr>`;}

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
    const RC={"NO_STRATUM":"基线全部为漏洞型，无对照样本","NO_VALID_DENOMINATOR":mid==="M3"?"No-KG 全部失败，无回归可能":"No-KG 全部成功，无改善空间","NO_POSITIVE_GT":"无漏洞型基线","BOOTSTRAP_UNSTABLE":"样本量不足，bootstrap 不稳定","NO_VALID":"数据不足","INSUFFICIENT_DATA":"样本量不足","NO_DISCORDANT_PAIRS":"KG 与 No-KG 结果一致，无差异对","INSUFFICIENT_PAIRS":"配对数不足","ALL_ZERO_DIFFERENCES":"所有配对差异为零"};
    if(!m||m.calculation_status!=="CALCULATED"){
      const rc=m?m.reason_code||m.calculation_status:"无数据";
      const reason=RC[rc]||rc||"无数据";
      const nNote=m&&m.n!=null?` (N=${m.n})`:"";
      return `<div class="mcard na"><div class="mc-label"><span style="font-family:monospace;font-size:12px;color:var(--gray)">${mid}</span> ${mi.short||""}</div><div class="mc-val na">N/A</div><div style="font-size:13px;color:var(--sub);margin-top:4px">${reason}${nNote}</div></div>`;
    }
    const v=m.estimate;
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
    return '<div class="mcard" style="border-color:'+col+'33"><div class="mc-label"><span style="font-family:monospace;font-size:12px;color:var(--gray)">'+mid+'</span> '+(mi.short||"")+'</div><div class="mc-val" style="color:'+col+'">'+valStr+'</div><div style="font-size:12px;color:var(--sub);margin-top:4px;line-height:1.4">'+(mi.d||"")+'</div>'+rangeBar+formulaHtml+'</div>';
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
  kgData.forEach(k=>{
    (k.interactions||[]).forEach(i=>kgAll.push(i));
    const mem=k.memory||{};
    (mem.interactions||[]).forEach(i=>memAll.push(i));
  });

  // 统计辅助函数：计算主动查询、返回结果、有效返回、返回失败、知识盲区
  function _stats(arr){
    const callCount=arr.filter(function(iv){return iv.type==="CALL";}).length;
    const resultCount=arr.filter(function(iv){return iv.type==="RESULT";}).length;
    const noResponse=Math.max(0,callCount-resultCount);
    var fail=0,blind=0,success=0;
    arr.forEach(function(iv){
      if(iv.type!=="RESULT"||!iv.output)return;
      var out=(iv.output||"").toLowerCase();
      if(out.indexOf("terminated")>=0||out.indexOf("timeout")>=0||out.indexOf("error")>=0||out.indexOf("404")>=0||out.indexOf("failed")>=0||out.indexOf("exception")>=0||out.indexOf("unreachable")>=0||out.indexOf("connection refused")>=0){
        fail++;
      }else if(out.indexOf("知识库暂无此类知识")>=0||out.indexOf("no memory")>=0||out.indexOf("not found")>=0||out.indexOf("empty")>=0){
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
      if(accessRate!==null)html+="<span class='bdg' style='font-size:13px;background:var(--p3);color:var(--sub)'>访问率 "+(accessRate*100).toFixed(1)+"%</span>";
      if(deliveryRate!==null)html+="<span class='bdg' style='font-size:13px;background:var(--p3);color:var(--sub)'>交付率 "+(deliveryRate*100).toFixed(1)+"%</span>";
      html+="</div>";
    }
    return html;
  }

  const kgStats=_stats(kgAll);
  const memStats=_stats(memAll);
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

  // 基线漏洞 per-case 分析
  var caseResults=group?(group.case_results||[]):(d.case_results||[]);
  if(caseResults.length){
    kgHtml+="<div style='font-size:15px;margin-bottom:8px'>基线漏洞逐个对比：<b>"+caseResults.length+"</b> 个</div>";
    caseResults.forEach(function(c,idx){
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
      kgHtml+="<div style='background:var(--p2);border-radius:10px;padding:12px;margin-bottom:10px'>";
      kgHtml+="<div style='display:flex;gap:8px;align-items:center;margin-bottom:6px'>";
      kgHtml+="<span class='bdg b-COMPLETED' style='font-size:11px'>问题"+(idx+1)+"</span>";
      var _exp=c.expected_label||"";
      var _expBadge=_exp==="VULNERABLE"?"<span class='bdg b-FAILED' style='font-size:11px'>基线: 漏洞</span>":_exp==="NON_VULNERABLE"?"<span class='bdg b-CREATED' style='font-size:11px'>基线: 非漏洞</span>":"";
      kgHtml+=_expBadge;
      kgHtml+="<span style='font-weight:600;font-size:14px'>"+(c.vulnerability_type||c.source_function||c.source_file||"漏洞")+"</span>";
      kgHtml+="<span style='font-size:12px;color:var(--gray);font-family:monospace'>"+(c.case_id||"").slice(0,8)+"</span>";
      kgHtml+="</div>";
      // per-case 知识介入分析（仅在知识图谱已介入时显示，否则与上方"未介入"矛盾）
      var pcKa=pcAnalysis.find(function(p){return p.case_id===c.case_id;});
      // AI 分析结论放最前面
      if(pcKa&&kgActive&&(pcKa.reason||pcKa.query_summary)){
        var impColor=pcKa.impact==="POSITIVE"?"var(--green)":pcKa.impact==="NEGATIVE"?"var(--red)":"var(--amber)";
        var impText=pcKa.impact==="POSITIVE"?"正向 ✅":pcKa.impact==="NEGATIVE"?"负向 ❌":"中性 ⏳";
        var jText=pcKa.kg_judgment==="VULNERABILITY"?"漏洞(TP)":pcKa.kg_judgment==="NON_VULNERABILITY"?"非漏洞(FP)":"未找到(FN)";
        kgHtml+="<div style='background:var(--p3);border-radius:8px;padding:10px;margin-bottom:8px'>";
        kgHtml+="<div style='font-weight:600;font-size:13px;margin-bottom:4px'>📝 AI 分析结论</div>";
        kgHtml+="<div style='display:flex;gap:16px;margin-bottom:4px'><span style='font-size:13px'>判定: <b>"+jText+"</b></span><span style='font-size:13px;color:"+impColor+"'>影响: "+impText+"</span></div>";
        if(pcKa.reason)kgHtml+="<div style='font-size:12px;color:var(--txt);margin-top:4px;line-height:1.5'>"+pcKa.reason+"</div>";
        kgHtml+="</div>";
      }
      kgHtml+="<div style='display:flex;gap:16px;margin-bottom:6px'>"+confBadge("KG",conf)+confBadge("No-KG",nogkConf)+"</div>";
      // 知识与记忆交互明细
      if(pcKa&&kgActive){
        // 知识图谱交互
        var ivs=pcKa.interactions||[];
        if(ivs.length){
          kgHtml+="<details style='margin-top:6px;border-top:1px solid var(--border);padding-top:6px'>";
          kgHtml+="<summary style='font-size:12px;font-weight:600;color:var(--sub);margin-bottom:4px;cursor:pointer'>🔍 知识交互（"+ivs.length+" 条）</summary>";
          ivs.forEach(function(iv,i){
            kgHtml+="<div style='margin-bottom:6px;padding:6px;background:var(--p2);border-radius:6px'>";
            var src=iv.session_id?("session: "+String(iv.session_id).slice(0,16)+"…"):"";
            if(iv.timestamp){var ts=new Date(iv.timestamp);src+=" · "+ts.toLocaleString("zh-CN",{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"});}
            kgHtml+="<div style='font-size:11px;color:var(--gray);margin-bottom:2px'>知识"+(i+1)+"："+(iv.tool||"")+(src?" <span style='color:var(--gray);font-size:10px'>["+src+"]</span>":"")+"</div>";
            var qp=iv.command_parsed||iv.question||"";
            var op=iv.output_parsed||iv.answer||"";
            var rawQ=iv.command||iv.question||"";
            var rawA=iv.answer||"";
            if(qp){
              kgHtml+="<div style='font-size:12px;color:var(--txt);line-height:1.4'><b>查询:</b> "+qp.replace(/</g,"&lt;")+"</div>";
            }
            if(op){
              kgHtml+="<div style='font-size:12px;color:var(--sub);line-height:1.4;margin-top:2px'><b>回答:</b> "+op.replace(/</g,"&lt;")+"</div>";
            }
            if(rawQ||rawA){
              kgHtml+="<details style='margin-top:2px'><summary style='font-size:11px;color:var(--gray);cursor:pointer'>原始数据</summary>";
              if(rawQ)kgHtml+="<div style='font-size:11px;color:var(--gray);word-break:break-all'><code>"+String(rawQ).replace(/</g,"&lt;").slice(0,400)+"</code></div>";
              if(rawA)kgHtml+="<div style='font-size:11px;color:var(--gray);word-break:break-all'><code>"+String(rawA).replace(/</g,"&lt;").slice(0,600)+"</code></div>";
              kgHtml+="</details>";
            }
            kgHtml+="</div>";
          });
          kgHtml+="</details>";
        }
        // 记忆交互
        var memIvs=pcKa.memory_interactions||[];
        if(memIvs.length){
          kgHtml+="<details style='margin-top:6px;border-top:1px solid var(--border);padding-top:6px'>";
          kgHtml+="<summary style='font-size:12px;font-weight:600;color:var(--sub);margin-bottom:4px;cursor:pointer'>🧠 记忆交互（"+memIvs.length+" 条）</summary>";
          memIvs.forEach(function(iv,i){
            kgHtml+="<div style='margin-bottom:6px;padding:6px;background:var(--p2);border-radius:6px'>";
            var src=iv.session_id?("session: "+String(iv.session_id).slice(0,16)+"…"):"";
            if(iv.timestamp){var ts=new Date(iv.timestamp);src+=" · "+ts.toLocaleString("zh-CN",{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"});}
            kgHtml+="<div style='font-size:11px;color:var(--gray);margin-bottom:2px'>记忆"+(i+1)+"："+(iv.tool||"")+(src?" <span style='color:var(--gray);font-size:10px'>["+src+"]</span>":"")+"</div>";
            var qp=iv.command_parsed||iv.question||"";
            var op=iv.output_parsed||iv.answer||"";
            var rawQ=iv.command||iv.question||"";
            var rawA=iv.answer||"";
            if(qp){
              kgHtml+="<div style='font-size:12px;color:var(--txt);line-height:1.4'><b>查询:</b> "+qp.replace(/</g,"&lt;")+"</div>";
            }
            if(op){
              kgHtml+="<div style='font-size:12px;color:var(--sub);line-height:1.4;margin-top:2px'><b>回答:</b> "+op.replace(/</g,"&lt;")+"</div>";
            }
            if(rawQ||rawA){
              kgHtml+="<details style='margin-top:2px'><summary style='font-size:11px;color:var(--gray);cursor:pointer'>原始数据</summary>";
              if(rawQ)kgHtml+="<div style='font-size:11px;color:var(--gray);word-break:break-all'><code>"+String(rawQ).replace(/</g,"&lt;").slice(0,400)+"</code></div>";
              if(rawA)kgHtml+="<div style='font-size:11px;color:var(--gray);word-break:break-all'><code>"+String(rawA).replace(/</g,"&lt;").slice(0,600)+"</code></div>";
              kgHtml+="</details>";
            }
            kgHtml+="</div>";
          });
          kgHtml+="</details>";
        }
      }
      kgHtml+="</div>";
    });
  }
  return kgHtml;
  }

  // 自动生成通俗摘要
  let summaryParts=[];
  const m7v=p1.M7&&p1.M7.calculation_status==="CALCULATED"?p1.M7.estimate:null;
  const m8v=p2.M8&&p2.M8.calculation_status==="CALCULATED"?p2.M8.estimate:null;
  const m9v=p2.M9&&p2.M9.calculation_status==="CALCULATED"?p2.M9.estimate:null;
  const hasAnyKgInteraction=(d.knowledge_interactions||[]).some(k=>(k.interactions||[]).some(iv=>iv.type==="CALL"));
  const hasAnyMemInteraction=(d.knowledge_interactions||[]).some(k=>((k.memory||{}).interactions||[]).some(iv=>iv.type==="CALL"));
  const overallKgAccess=p1.M5&&p1.M5.calculation_status==="CALCULATED"?p1.M5.estimate:null;
  const overallMemAccess=p1.M11&&p1.M11.calculation_status==="CALCULATED"?p1.M11.estimate:null;
  const kgActiveSummary=(overallKgAccess!==null&&overallKgAccess>0)||hasAnyKgInteraction;
  const memActiveSummary=(overallMemAccess!==null&&overallMemAccess>0)||hasAnyMemInteraction;
  if(kgActiveSummary&&memActiveSummary)summaryParts.push("知识图谱与记忆均已介入");
  else if(kgActiveSummary)summaryParts.push("知识图谱已介入，记忆未介入");
  else if(memActiveSummary)summaryParts.push("记忆已介入，知识图谱未介入");
  else summaryParts.push("知识图谱与记忆均未介入");
  if(m8v!==null)summaryParts.push(m8v<0?"KG 模式更省 token":"KG 模式更耗 token");
  if(m9v!==null)summaryParts.push(m9v<0?"KG 步数更少":"KG 步数更多");
  if(m7v!==null)summaryParts.push(m7v<0.1?"行为几乎无变化":"行为有明显变化");
  if(rw.undetermined)summaryParts.push(`${rw.undetermined} 个任务结果待定`);

  // 评测元信息
  const evalName=d.evaluation_name||d.evaluation_id;
  const vbenchName=d.vbench_project_name||"";
  const entriesInfo=d.entries_info||[];
  const kgInfo=entriesInfo.find(e=>e.condition==="KG")||{};
  const nogkInfo=entriesInfo.find(e=>e.condition==="NOGK")||{};

  $("rep").innerHTML=`
  <div style="margin-bottom:22px">
    <h2 style="font-size:22px;margin-bottom:6px">${evalName}</h2>
    <div style="color:var(--sub);font-size:16px;margin-bottom:8px"><span class="bdg b-${d.status||""}">${d.status||"-"}</span></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px 20px;font-size:14px;color:var(--sub);background:var(--p2);border-radius:10px;padding:12px 16px">
      <div><span style="color:var(--gray)">KG 项目：</span><b>${kgInfo.project_name||"-"}</b> · <span style="color:var(--gray)">任务：</span><b>${kgInfo.task_name||"-"}</b></div>
      <div><span style="color:var(--gray)">No-KG 项目：</span><b>${nogkInfo.project_name||"-"}</b> · <span style="color:var(--gray)">任务：</span><b>${nogkInfo.task_name||"-"}</b></div>
      <div><span style="color:var(--gray)">基线来源：</span><b>${d.benchmark_source==='vuln_center'?'漏洞中心数据':(vbenchName||'无（无 GT 模式）')}</b></div>
      <div><span style="color:var(--gray)">评测 ID：</span><b style="font-family:monospace">${d.evaluation_id}</b></div>
    </div>
  </div>

  <!-- 1. AI 综合分析（合并摘要 + 漏洞对比 + 指标结论） -->
  ${(()=>{
    const nt=r.narrative||{};
    const va=r.vuln_analysis||{};
    // 总结论：优先 narrative.summary，fallback report.summary，再 fallback 规则摘要
    const topSummary=nt.summary||r.summary||summaryParts.join("；")+"。";
    // 详细分析：优先 narrative.conclusion，fallback 旧字段拼接
    let concl=nt.conclusion||"";
    if(!concl){const parts=[];if(nt.outcome_interpretation)parts.push("【准确性】"+nt.outcome_interpretation);if(nt.risk_interpretation)parts.push("【风险】"+nt.risk_interpretation);if(nt.mechanism_interpretation)parts.push("【行为/机制】"+nt.mechanism_interpretation);if(nt.cost_interpretation)parts.push("【成本】"+nt.cost_interpretation);if(nt.statistical_significance)parts.push("【统计显著性】"+nt.statistical_significance);if(nt.diagnostic_alerts)parts.push("【诊断告警】"+nt.diagnostic_alerts);concl=parts.join("\n\n");}
    return`<div class="card" style="margin-bottom:16px;background:linear-gradient(135deg,var(--p2),var(--panel))">
    <h3>📋 AI 综合分析</h3>
    <div style="font-size:18px;font-weight:600;margin-bottom:14px;line-height:1.6">${topSummary.replace(/</g,"&lt;")}</div>
    ${concl?`<div style="font-size:16px;line-height:1.8;white-space:pre-wrap;margin-bottom:10px">${concl.replace(/</g,"&lt;")}</div>`:""}
    ${nt.limitations&&nt.limitations.length?`<div style="font-size:14px;color:var(--sub);margin-top:8px;padding-top:10px;border-top:1px solid var(--bd)"><b>局限性：</b>${nt.limitations.join("；")}</div>`:""}
  </div>`})()}

  <!-- 2. 按评测类别展示详情 -->
  ${(()=>{
    const rawGroups=r.metric_groups||[];
    const mg=(rawGroups.length?rawGroups:[{task_id:"",label:"评测结果",p0,p1,p2,diagnostic_hits:h}]).slice().sort((a,b)=>{
      const order={mining:0,verify:1};return (order[a.category]??2)-(order[b.category]??2);
    });
    function _statsTable(tid,label){
      const tools=d.tool_stats||[];const res=d.resource_stats||[];const oc=d.outcome_details||[];
      const kgTool=tools.find(t=>t.task_run_id.includes("-"+tid+"-KG"))||tools.find(t=>t.task_run_id.includes("KG")&&!t.task_run_id.includes("NOGK"))||{};
      const nogkTool=tools.find(t=>t.task_run_id.includes("-"+tid+"-NOGK"))||tools.find(t=>t.task_run_id.includes("NOGK"))||{};
      const kgRes=res.find(t=>t.task_run_id.includes("-"+tid+"-KG"))||res.find(t=>t.task_run_id.includes("KG")&&!t.task_run_id.includes("NOGK"))||{};
      const nogkRes=res.find(t=>t.task_run_id.includes("-"+tid+"-NOGK"))||res.find(t=>t.task_run_id.includes("NOGK"))||{};
      const kgOc=oc.find(o=>o.task_run_id.includes("-"+tid+"-KG"))||oc.find(o=>o.task_run_id.includes("KG")&&!o.task_run_id.includes("NOGK"))||{};
      const nogkOc=oc.find(o=>o.task_run_id.includes("-"+tid+"-NOGK"))||oc.find(o=>o.task_run_id.includes("NOGK"))||{};
      const kgFound=kgTool.finding_count||0;const nogkFound=nogkTool.finding_count||0;
      const kgFP=kgTool.false_positive_count||0;const nogkFP=nogkTool.false_positive_count||0;
      const kgRecv=kgTool.analyze_received_count||(kgFound+kgFP);const nogkRecv=nogkTool.analyze_received_count||(nogkFound+nogkFP);
      const isVerify=label.includes("验证");
      const kgKi=(d.knowledge_interactions||[]).find(k=>k.task_run_id.includes("-"+tid+"-KG"))||{};
      const kgKg=(kgKi.interactions||[]).filter(iv=>iv.type==="CALL").length;
      const nogkKg=0;
      const kgMem=((kgKi.memory||{}).interactions||[]).filter(iv=>iv.type==="CALL").length;
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
      return `<div class="card" style="margin-bottom:16px">
        <h3>📊 ${label} — 漏洞检测统计</h3>
        <div style="font-size:16px;margin-bottom:12px">基准漏洞数：<b style="font-size:18px">${baseline}</b>${cr.length?`<span style="margin-left:12px;font-size:14px;color:var(--gray)">漏洞 <b>${vulnN}</b> · 非漏洞 <b>${nonVulnN}</b></span>`:""}</div>
        <table><tr><th>统计项</th><th>KG（开知识图谱与记忆）</th><th>No-KG（对照）</th></tr>
        <tr><td>${isVerify?"验证接收总数":"提交疑似漏洞数"}</td><td class="num">${kgRecv}</td><td class="num">${nogkRecv}</td></tr>
        <tr><td>${isVerify?"确认漏洞数":"Agent 确认漏洞数"}</td><td class="num">${kgFound}</td><td class="num">${nogkFound}</td></tr>
        <tr><td>误报数（非漏洞）</td><td class="num">${kgFP}</td><td class="num">${nogkFP}</td></tr>
        <tr><td>知识图谱查询次数</td><td class="num">${kgKg}</td><td class="num">${nogkKg}</td></tr>
        <tr><td>记忆查询次数</td><td class="num">${kgMem}</td><td class="num">${nogkMem}</td></tr>
        <tr><td>Token 消耗</td><td class="num">${kgTokens.toLocaleString()}</td><td class="num">${nogkTokens.toLocaleString()}</td></tr>
        <tr><td>工具调用次数</td><td class="num">${kgTools}</td><td class="num">${nogkTools}</td></tr>
        <tr><td>执行步数</td><td class="num">${kgSteps}</td><td class="num">${nogkSteps}</td></tr>
        <tr><td>运行时长</td><td class="num">${fmtDur(kgDur)}</td><td class="num">${fmtDur(nogkDur)}</td></tr>
        <tr><td>检测结果</td><td class="num">${kgOc.outcome||"N/A"}</td><td class="num">${nogkOc.outcome||"N/A"}</td></tr>
        <tr><td>验证结果</td><td class="num">${kgOc.validation||"N/A"}</td><td class="num">${nogkOc.validation||"N/A"}</td></tr>
        </table></div>`;
    }
    function _metricCards(gp0,gp1,gp2,glabel,cat){
      const isVerify=cat==="verify";
      const groups=[
        ["① 价值结果","衡量知识图谱与记忆对漏洞判定准确性的净贡献",
          [["M1",gp0.M1],["M2",gp0.M2],["M3",gp0.M3],["M4",gp0.M4]]],
        ["② 作用机制","揭示行为变化的来源（知识访问/交付/记忆"+(isVerify?"":"/行为偏移")+"）",
          isVerify?[["M5",gp1.M5],["M6",gp1.M6],["M11",gp1.M11],["M12",gp1.M12]]:[["M5",gp1.M5],["M6",gp1.M6],["M7",gp1.M7],["M11",gp1.M11],["M12",gp1.M12]]],
        ...(!isVerify?[["③ 成本效率","对比 KG 与 No-KG 的资源消耗",
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
    function _diagnostics(hits){
      return hits&&hits.length?`<div class="card" style="margin-bottom:16px"><h3>🔍 诊断发现</h3>${hits.map(x=>`<div class="diag"><span class="rid">${x.rule_id}</span> <span class="ob">${x.observed}</span><div class="ip">${x.interpretation}<br>建议：${x.suggestion}</div></div>`).join("")}</div>`:"";
    }
    const tabs=mg.length>1?`<div role="tablist" aria-label="报告类别" style="display:grid;grid-template-columns:repeat(${mg.length},minmax(0,1fr));gap:12px;margin:0 0 20px">${mg.map((g,i)=>{const mining=g.category!=="verify";const icon=mining?'🔎':'✅';const desc=mining?'发现与提交潜在漏洞':'验证候选漏洞是否成立';return`<button class="btn" role="tab" data-report-tab-btn aria-selected="${i===0?'true':'false'}" style="text-align:left;display:flex;gap:10px;align-items:center;padding:13px 15px;border:1px solid ${i===0?'var(--acc)':'var(--bd)'};background:${i===0?'var(--acc)':'var(--panel)'};color:${i===0?'#fff':'var(--sub)'};${i===0?'box-shadow:0 8px 20px rgba(124,58,237,.28);transform:translateY(-2px)':''}" onclick="selectReportTab(this,'report-tab-${i}')"><span style="font-size:24px">${icon}</span><span><b style="display:block;font-size:16px">${g.label}</b><small style="display:block;margin-top:3px;opacity:.82">${desc}</small></span></button>`}).join("")}</div><div style="font-size:14px;color:var(--sub);margin:-8px 0 16px;padding:8px 10px;background:var(--p2);border-radius:8px">当前选中的类别决定下方全部统计、效果指标和诊断的范围。</div>`:"";
    const panes=mg.map((g,i)=>`<div id="report-tab-${i}" data-report-tab style="display:${i===0?'block':'none'}">
      <div style="display:flex;align-items:center;gap:8px;margin:0 0 12px"><span style="font-size:18px">${g.category==='verify'?'✅':'🔎'}</span><b style="font-size:18px">当前查看：${g.label}</b><span style="font-size:13px;color:var(--sub)">以下内容仅属于此类别</span></div>
      ${_statsTable(g.task_id,g.label)}
      <div class="card" style="margin-bottom:16px"><h3>🎯 ${g.label} — 效果指标</h3>${_metricCards(g.p0||{},g.p1||{},g.p2||{},g.label,g.category)}</div>
      ${_diagnostics(g.diagnostic_hits||h)}
      <div class="card" style="margin-bottom:16px">
        <h3>🧠 ${g.label} — 知识图谱与记忆介入分析</h3>
        ${Array.isArray(g.case_results)&&Array.isArray(g.per_case_kg_analysis)
          ?buildKnowledgeHtml(g)
          :mg.length===1
            ?buildKnowledgeHtml(null)
            :'<div style="font-size:14px;color:var(--sub)">该历史报告未保存按类别拆分的逐漏洞知识图谱与记忆分析；请重跑评测以生成此数据。</div>'}
      </div>
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
