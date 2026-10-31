// 公共辅助函数（所有页面共享）
// URL 前缀（/eval 环境）
const _P = location.pathname;
const _INGRESS = (_P==='/eval'||_P.indexOf('/eval/')===0)?'/eval':'';
const U = (u)=>_INGRESS&&(u.indexOf("/api/")===0||u.indexOf("/reports/")===0||u.indexOf("/dts")===0||u==="/health")?_INGRESS+u:u;
const F = (u,...a)=>fetch(U(u),...a);
let activeId = null;

const DEBUG = new URLSearchParams(location.search).get("debug")==="true";

// DOM 快捷
function $(i){return document.getElementById(i);}
function el(h){const d=document.createElement("div");d.innerHTML=h;return d.firstChild;}

// HTTP
async function jget(u){const r=await F(u);if(!r.ok)throw new Error(r.status);return r.json();}
async function jpost(u,b){const r=await F(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});const d=await r.json();if(!r.ok)throw new Error(d.detail||r.status);return d;}
async function jput(u,b){const r=await F(u,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});const d=await r.json();if(!r.ok)throw new Error(d.detail||r.status);return d;}
async function jdel(u){const r=await F(u,{method:"DELETE"});const d=await r.json();if(!r.ok)throw new Error(d.detail||r.status);return d;}

// 格式化
function fmtDate(s){if(!s)return'-';const d=new Date(s+'Z');if(isNaN(d))return s;const b=new Date(d.getTime()+8*3600000);const p=n=>String(n).padStart(2,'0');return b.getUTCFullYear()+'-'+p(b.getUTCMonth()+1)+'-'+p(b.getUTCDate())+' '+p(b.getUTCHours())+':'+p(b.getUTCMinutes());}
function fmtTs(ts){if(!ts)return'';const d=new Date(ts+8*3600000);const p=n=>String(n).padStart(2,'0');return p(d.getUTCMonth()+1)+'-'+p(d.getUTCDate())+' '+p(d.getUTCHours())+':'+p(d.getUTCMinutes())+':'+p(d.getUTCSeconds());}
function fmtPct(v){if(v===null||v===undefined)return'<span class="na">NA</span>';return(v*100).toFixed(1)+'%';}

function fmtNum(v){if(v==null||isNaN(v))return'<span class="na">NA</span>';const a=Math.abs(v);
  if(a>=1e9)return(v/1e9).toFixed(2)+'B';
  if(a>=1e6)return(v/1e6).toFixed(2)+'M';
  if(a>=1e3)return(v/1e3).toFixed(1)+'K';
  return Math.round(v).toString();}
function fmt(v,u){
  if(v===null||v===undefined||isNaN(v))return'<span class="na">NA</span>';
  if(u==="ratio")return (v*100).toFixed(2)+'<span class="ci">%</span>';
  return Number(v).toFixed(3);}

// 指标卡片（报告详情页使用）
function mCard(mid,m){
  const mi=MI[mid]||{n:mid,short:mid,d:"",u:"",range:[],interp:()=>""};
  const RC={"NO_DATA":"无数据","NO_TOOL_CALLS":"无工具调用","NO_ACCESS_EVENT":"无知识访问事件","NO_VALID":"数据不足","PENDING_FPR_ANALYSIS":"等待误报率分析","NO_NEED_KNOWLEDGE":"无知识需求","NO_INITIATED_ACCESS":"未发起访问","NO_QUERY_ACCURATE_ACCESS":"无准确查询","NO_EXISTS_ACCESS":"无知识存在","NO_RETRIEVED_ACCESS":"未召回","NO_USED_ACCESS":"未使用","NO_FP_CASE":"无误报case"};
  if(!m||m.calculation_status!=="CALCULATED"){
    const rc=m?m.reason_code||m.calculation_status:"无数据";
    const reason=RC[rc]||rc||"无数据";
    return `<div class="mcard na"><div class="mc-label"><span style="font-family:monospace;font-size:12px;color:var(--gray)">${mid}</span> ${mi.short||""}</div><div class="mc-val na">N/A</div><div style="font-size:13px;color:var(--sub);margin-top:4px">${reason}</div></div>`;
  }
  const v=m.estimate;
  if(v==null||isNaN(v))return `<div class="mcard na"><div class="mc-label"><span style="font-family:monospace;font-size:12px;color:var(--gray)">${mid}</span> ${mi.short||""}</div><div class="mc-val na">N/A</div><div style="font-size:13px;color:var(--sub);margin-top:4px">estimate 缺失</div></div>`;
  const interp=mi.interp?mi.interp(v):"";
  let col="var(--gray)";
  if(mi.range){
    for(let i=mi.range.length-1;i>=0;i--){if(v>=mi.range[i].v){col=mi.range[i].c==="green"?"var(--green)":mi.range[i].c==="red"?"var(--red)":"var(--amber)";break;}}
  }
  const valStr=fmt(v,mi.u);
  let rangeBar="";
  if(mi.range&&mi.range.length>=2){
    const min=mi.range[0].v,max=mi.range[mi.range.length-1].v;
    const pct=Math.min(100,Math.max(0,((v-min)/(max-min))*100));
    rangeBar=`<div class="bar-track" style="margin-top:6px;height:4px"><div class="bar-fill" style="width:${pct}%;background:${col}"></div></div>`;
  }
  var formulaHtml=mi.d?"<div style='font-size:12px;color:var(--sub);margin-top:4px'>"+mi.d+"</div>":"";
  var nHtml=m.n!=null?'<div class="mc-n">N='+m.n+'</div>':'';
  return '<div class="mcard" style="border-color:'+col+'33"><div class="mc-label"><span style="font-family:monospace;font-size:12px;color:var(--gray)">'+mid+'</span> '+(mi.short||"")+'</div><div class="mc-val" style="color:'+col+'">'+valStr+'</div>'+rangeBar+formulaHtml+nHtml+'</div>';
}

// Agent/工具标签
function _agentLabel(a){return AGENT_LABELS[a]||a||'-';}
function _toolLabel(k){return TOOL_LABELS[k]||k||'-';}

// 评测状态徽章
function _phaseLabel(s){return EVAL_STATUS_LABELS[s]||s||'-';}
function _statusBadge(s){
  const badge=(s||'').replace('_WITH_WARNINGS','').replace('CANCEL_REQUESTED','FAILED').replace('CANCELLING','FAILED').replace('CANCELLED','FAILED');
  return `<span class="bdg b-${badge}">${_phaseLabel(s)}</span>`;
}

// 主题
function applyTheme(t){
  const v=THEMES[t];const r=document.documentElement;
  for(const[k,val]of Object.entries(v))r.style.setProperty(k,val);
  const btn=$("theme-btn");if(btn)btn.textContent=t==="dark"?"☀️":"🌙";
  localStorage.setItem("eval-theme",t);
}
function toggleTheme(){const cur=localStorage.getItem("eval-theme")||"light";applyTheme(cur==="light"?"dark":"light");}

// 生成评测 ID
function genId(){
  const d=new Date(Date.now()+8*3600000);
  const p=n=>String(n).padStart(2,"0");
  return `EV-${d.getUTCFullYear()}${p(d.getUTCMonth()+1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}-${Math.floor(Math.random()*9000+1000)}`;
}

// 页面跳转（自动加 /eval 前缀）
function go(u){location.href=_INGRESS+u;}

// DTS 标签辅助
function dtsAgentLabel(at){
  if(!at)return '-';
  return at.split(',').map(function(a){return AGENT_LABELS[a]||a;}).join(', ');
}
function dtsRespLabel(resp){
  if(!resp)return '-';
  return resp.split(',').map(function(r){return DTS_RESP_LABELS[r]||r;}).join(', ');
}
function dtsRespMatches(resp,filter){return resp&&resp.split(',').indexOf(filter)>=0;}

// 导航渲染：当前页高亮
function renderNav(currentPath){
  // 当前页路径（去掉 /eval 前缀）
  const path=currentPath||(location.pathname.replace(_INGRESS,'')||'/');
  // 主菜单
  document.querySelectorAll('header .nav-item[data-route]').forEach(b=>{
    b.classList.remove('nav-active');
    const r=b.getAttribute('data-route');
    if(!r)return;
    if(r==='home'&&(path==='/'||path===''))b.classList.add('nav-active');
    else if(r==='evals'&&(path==='/evals'||path.indexOf('/evals/')===0))b.classList.add('nav-active');
    else if(r==='dts'&&(path==='/dts'||path.indexOf('/dts/')===0))b.classList.add('nav-active');
    else if(r==='report'&&path==='/report')b.classList.add('nav-active');
  });
  // 系统按钮 debug 显示
  const sb=$("sys-btn");if(sb)sb.style.display=DEBUG?"":"none";
}

// 返回（路径映射）
function goBack(defaultPath){
  const path=location.pathname.replace(_INGRESS,'')||'/';
  if(path.indexOf('/evals/')===0){location.href=_INGRESS+'/evals';}
  else if(path.indexOf('/dts/')===0){location.href=_INGRESS+'/dts';}
  else if(path.indexOf('/dts')===0){location.href=_INGRESS+'/';}
  else if(path.indexOf('/report')===0){location.href=_INGRESS+'/';}
  else if(path.indexOf('/create')===0){location.href=_INGRESS+'/';}
  else if(path.indexOf('/system')===0){location.href=_INGRESS+'/';}
  else{location.href=_INGRESS+(defaultPath||'/');}
}

// 确认框（opts: {icon,iconBg,iconColor,title,desc,risks:[],confirmText,confirmColor,onConfirm}）
function showConfirm(opts){
  if(typeof opts==='string')opts={title:'确认',desc:opts};
  var ov=document.createElement("div");ov.className="modal-overlay";
  var risksHtml=(opts.risks||[]).map(function(r){return "<li>"+r+"</li>";}).join("");
  ov.innerHTML='<div class="modal">'
    +'<div class="modal-head"><div class="modal-icon" style="background:'+opts.iconBg+';color:'+opts.iconColor+'">'+(opts.icon||'⚠️')+'</div><h3>'+(opts.title||'确认')+'</h3></div>'
    +'<div class="modal-body"><p>'+(opts.desc||'')+'</p>'+(risksHtml?'<ul>'+risksHtml+'</ul>':'')+'</div>'
    +'<div class="modal-foot"><button class="btn g" style="font-size:15px;padding:8px 20px" onclick="this.closest(\'.modal-overlay\').remove()">取消</button>'
    +'<button class="btn" style="font-size:15px;padding:8px 20px;background:'+(opts.confirmColor||'var(--acc)')+'" id="modal-confirm">'+(opts.confirmText||'确认')+'</button></div></div>';
  document.body.appendChild(ov);
  ov.addEventListener("click",function(e){if(e.target===ov)ov.remove();});
  document.getElementById("modal-confirm").onclick=function(){ov.remove();if(opts.onConfirm)opts.onConfirm();};
  return ov;
}

// 页面加载时恢复保存的主题
(function(){
  var saved=localStorage.getItem("eval-theme");
  if(saved&&THEMES[saved]){applyTheme(saved);}
})();
