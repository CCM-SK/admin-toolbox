import { $, escapeHtml, downloadText } from '../utils.js';

export function renderRegex(app){
  app.innerHTML=`<section class="card"><h2>Regex workbench</h2><p class="small">JavaScript regular expressions only. Patterns and test text remain in your browser. Nothing is executed outside the JavaScript RegExp engine.</p>
  <div class="grid-2"><div><label for="rxPattern">Pattern</label><input id="rxPattern" class="mono" value="(\\b[A-Z][a-z]+\\b)"></div><div><label for="rxFlags">Flags</label><input id="rxFlags" class="mono" value="g" placeholder="gimuydsv"></div></div>
  <label for="rxText" style="margin-top:14px">Test text</label><textarea id="rxText" class="mono" style="min-height:240px" placeholder="Enter text to test"></textarea>
  <div class="row" style="margin-top:10px"><button class="btn primary" id="rxRun">Run</button><button class="btn" id="rxClear">Clear</button><button class="btn" id="rxExport">Export results</button></div>
  </section><section class="card" id="rxResult" hidden></section>`;

  let last=null;
  $('#rxRun').onclick=run;
  $('#rxText').oninput=()=>{ if($('#rxPattern').value && $('#rxFlags').value.includes('g')) run(); };
  $('#rxPattern').oninput=run; $('#rxFlags').oninput=run;
  $('#rxClear').onclick=()=>{$('#rxPattern').value='';$('#rxFlags').value='g';$('#rxText').value='';$('#rxResult').hidden=true;last=null;};
  $('#rxExport').onclick=()=>{if(!last)run();downloadText('regex-results.json',JSON.stringify(last,null,2),'application/json;charset=utf-8');};

  function run(){
    const pattern=$('#rxPattern').value, flags=$('#rxFlags').value, text=$('#rxText').value, out=$('#rxResult');
    if(!pattern){out.hidden=false;out.innerHTML='<p class="status warn">Enter a regular expression pattern.</p>';last=null;return;}
    let re; try{re=new RegExp(pattern,flags)}catch(e){out.hidden=false;out.innerHTML=`<p class="status danger">Invalid regular expression: ${escapeHtml(e.message)}</p>`;last=null;return;}
    const matches=[];
    if(re.global || re.sticky){let m; let guard=0; while((m=re.exec(text))!==null && guard++<10000){matches.push(toMatch(m)); if(m[0]==='') re.lastIndex++;}} else {const m=re.exec(text); if(m)matches.push(toMatch(m));}
    const replacementInput = $('#rxReplacement');
    const replacement = replacementInput ? replacementInput.value : '';
    const replaced = replacement ? text.replace(re,replacement) : null;
    last={pattern,flags,textLength:text.length,matches,replacement,replaced};
    out.hidden=false;
    const highlighted=highlight(text,matches);
    out.innerHTML=`<div class="grid"><div class="stat"><span>Matches</span><strong>${matches.length}</strong></div><div class="stat"><span>Pattern</span><strong><code>${escapeHtml('/'+pattern+'/'+flags)}</code></strong></div><div class="stat"><span>Test length</span><strong>${text.length}</strong></div></div>
      <h3>Matches</h3>${matches.length?`<div class="table-wrap"><table><thead><tr><th>#</th><th>Index</th><th>Match</th><th>Groups</th></tr></thead><tbody>${matches.map((m,i)=>`<tr><td>${i+1}</td><td>${m.index}</td><td><code>${escapeHtml(m.value)}</code></td><td><code>${escapeHtml(JSON.stringify(m.groups))}</code></td></tr>`).join('')}</tbody></table></div>`:'<p class="status ok">No matches.</p>'}
      <h3>Highlighted text</h3><pre class="mono" style="white-space:pre-wrap">${highlighted}</pre>
      <h3>Replace</h3><label for="rxReplacement">Replacement pattern</label><input id="rxReplacement" class="mono" value="${escapeAttr(replacement)}" placeholder="e.g. [$&] or $1"><div class="small">Uses JavaScript replacement syntax such as <code>$&</code>, <code>$1</code>, and <code>$$</code>.</div>${replacement?`<pre class="mono" style="white-space:pre-wrap">${escapeHtml(replaced)}</pre>`:''}`;
    $('#rxReplacement').oninput=()=>run();
  }

  function toMatch(m){return {value:m[0],index:m.index,groups:m.slice(1),namedGroups:m.groups||null};}
  function escapeAttr(v){return escapeHtml(v).replace(/\n/g,'&#10;').replace(/\r/g,'&#13;');}
  function highlight(text,matches){if(!matches.length)return escapeHtml(text); let out='',last=0; for(const m of matches){const start=m.index,end=start+m.value.length; if(start<last)continue; out+=escapeHtml(text.slice(last,start))+`<mark>${escapeHtml(text.slice(start,end))}</mark>`; last=end;} return out+escapeHtml(text.slice(last));}
}
