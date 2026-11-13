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

// HTML 转义：所有插入 innerHTML 的外部字段必须经过 esc()
function esc(v){
  if(v===null||v===undefined)return "";
  return String(v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

// HTTP
// 失败时把后端 detail 转成可读文本（FastAPI 校验错误 detail 是数组）
async function _httpError(r){
  var d=null;
  try{d=await r.text();if(d){try{var j=JSON.parse(d);if(j&&j.detail!==undefined)d=j.detail;}catch(_){}}}
  catch(_){}
  if(d&&typeof d==='object'){try{d=JSON.stringify(d);}catch(_){d=String(d);}}
  return d||("HTTP "+r.status);
}
async function jget(u){const r=await F(u);if(!r.ok)throw new Error(await _httpError(r));return r.json();}
async function jpost(u,b){const r=await F(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});if(!r.ok)throw new Error(await _httpError(r));return r.json();}
async function jput(u,b){const r=await F(u,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});if(!r.ok)throw new Error(await _httpError(r));return r.json();}
async function jdel(u){const r=await F(u,{method:"DELETE"});if(!r.ok)throw new Error(await _httpError(r));return r.json();}

// 分页拉取全部评测：后端 page_size 上限 100，直接传更大的值会被截断，
// 只拿首页会让「评测总数」和状态统计永久停在 100。
// 先取第 1 页拿到 total，其余页按 4 并发批量拉取，减少串行等待。
async function jgetAllEvaluations(){
  const pageSize=100,CONC=4;
  // alive=0：跳过平台任务存活校验（逐项目网络调用），列表秒回；
  // task_deleted 由列表页按可见页异步补全。
  const first=await jget(`/api/v1/evaluations?page=1&page_size=${pageSize}&alive=0`);
  let all=(first.evaluations||[]).slice();
  const total=Number(first.total||0);
  const pages=Math.max(1,Math.ceil(total/pageSize));
  for(let start=2;start<=pages;start+=CONC){
    const batch=[];
    for(let p=start;p<start+CONC&&p<=pages;p++)batch.push(p);
    const ds=await Promise.all(batch.map(p=>
      jget(`/api/v1/evaluations?page=${p}&page_size=${pageSize}&alive=0`)));
    ds.forEach(d=>{all=all.concat(d.evaluations||[]);});
  }
  return all;
}

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
function dtsRespMatches(resp,filter){
  if(!resp)return false;
  var parts=resp.split(',');
  if(filter==='other'){
    return ['knowledge','external_data_source','eval_process'].some(function(x){return parts.indexOf(x)>=0;});
  }
  return parts.indexOf(filter)>=0;
}

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

// 打开问题单详情，记录来源页以便详情页的「返回」能回到正确位置
// from: 'evals' | 'dts'（默认 dts 列表）
function goDtsFrom(dtsId, from, returnUrl){
  try{
    sessionStorage.setItem("dts-from", JSON.stringify({
      from: from||'dts',
      url: returnUrl || (from==='evals' ? location.pathname+location.search : _INGRESS+'/dts')
    }));
  }catch(e){}
  go('/dts/'+encodeURIComponent(dtsId));
}

// 读取问题单详情的来源信息
function dtsBackInfo(){
  var fallback={from:'dts', label:'问题单列表', url:_INGRESS+'/dts'};
  try{
    var raw=sessionStorage.getItem("dts-from");
    if(!raw)return fallback;
    var o=JSON.parse(raw)||{};
    if(o.from==='evals'){
      return {from:'evals', label:'评测详情', url:o.url||(_INGRESS+'/evals')};
    }
    return {from:'dts', label:'问题单列表', url:o.url||(_INGRESS+'/dts')};
  }catch(e){return fallback;}
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
  var risksHtml=(opts.risks||[]).map(function(r){return "<li>"+esc(r)+"</li>";}).join("");
  ov.innerHTML='<div class="modal">'
    +'<div class="modal-head"><div class="modal-icon" style="background:'+esc(opts.iconBg)+';color:'+esc(opts.iconColor)+'">'+esc(opts.icon||'⚠️')+'</div><h3>'+esc(opts.title||'确认')+'</h3></div>'
    +'<div class="modal-body"><p>'+esc(opts.desc||'')+'</p>'+(risksHtml?'<ul>'+risksHtml+'</ul>':'')+'</div>'
    +'<div class="modal-foot"><button class="btn g" style="font-size:15px;padding:8px 20px" onclick="this.closest(\'.modal-overlay\').remove()">取消</button>'
    +'<button class="btn" style="font-size:15px;padding:8px 20px;background:'+esc(opts.confirmColor||'var(--acc)')+'" id="modal-confirm">'+esc(opts.confirmText||'确认')+'</button></div></div>';
  document.body.appendChild(ov);
  ov.addEventListener("click",function(e){if(e.target===ov)ov.remove();});
  document.getElementById("modal-confirm").onclick=function(){ov.remove();if(opts.onConfirm)opts.onConfirm();};
  return ov;
}

// 错误提示弹框（失败必须弹出来，不能只写页面顶部的内联文字）
// opts: {title, desc, icon, iconBg, iconColor, okText}
function showAlert(opts){
  if(typeof opts==='string')opts={desc:opts};
  var ov=document.createElement("div");ov.className="modal-overlay";
  ov.innerHTML='<div class="modal">'
    +'<div class="modal-head"><div class="modal-icon" style="background:'+esc(opts.iconBg||'rgba(220,38,38,.12)')+';color:'+esc(opts.iconColor||'var(--red)')+'">'+esc(opts.icon||'✕')+'</div><h3>'+esc(opts.title||'操作失败')+'</h3></div>'
    +'<div class="modal-body"><p style="white-space:pre-wrap;word-break:break-all;line-height:1.7">'+esc(opts.desc||'')+'</p></div>'
    +'<div class="modal-foot"><button class="btn" id="modal-alert-ok" style="font-size:15px;padding:8px 20px;background:var(--acc)">'+esc(opts.okText||'知道了')+'</button></div></div>';
  document.body.appendChild(ov);
  function close(){ov.remove();}
  ov.addEventListener("click",function(e){if(e.target===ov)close();});
  var ok=ov.querySelector("#modal-alert-ok");if(ok){ok.onclick=close;ok.focus();}
  return ov;
}

// 页面加载时恢复保存的主题
(function(){
  var saved=localStorage.getItem("eval-theme");
  if(saved&&THEMES[saved]){applyTheme(saved);}
})();
