export const $ = (sel, root=document) => root.querySelector(sel);
export const $$ = (sel, root=document) => [...root.querySelectorAll(sel)];
export const escapeHtml = (v='') => String(v).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const formatBytes = n => { if (!Number.isFinite(n)) return '—'; const u=['B','KiB','MiB','GiB','TiB']; let i=0,x=n; while(x>=1024&&i<u.length-1){x/=1024;i++;} return `${x.toFixed(i?2:0)} ${u[i]}`; };
export const downloadText = (name,text,type='text/plain;charset=utf-8') => { const a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([text],{type})); a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href),1000); };
export const readText = file => file.text();
export const csvParse = text => { const rows=[]; let row=[], cell='', q=false; for(let i=0;i<text.length;i++){const c=text[i],n=text[i+1]; if(q){ if(c==='"'&&n==='"'){cell+='"';i++;} else if(c==='"'){q=false;} else cell+=c; } else if(c==='"'){q=true;} else if(c===','){row.push(cell);cell='';} else if(c==='\n'){row.push(cell);rows.push(row);row=[];cell='';} else if(c!=='\r'){cell+=c;} } if(cell!==''||row.length){row.push(cell);rows.push(row);} const width=Math.max(0,...rows.map(r=>r.length)); return rows.filter(r=>r.length===width&&r.some(v=>v!=='')); };
export const jsonPretty = (text) => JSON.stringify(JSON.parse(text), null, 2);
export const downloadBlob = (name, blob) => { const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(a.href),1000); };
export function dropBinder(el, onFiles){ el.addEventListener('dragover',e=>{e.preventDefault();el.classList.add('drag')}); el.addEventListener('dragleave',()=>el.classList.remove('drag')); el.addEventListener('drop',e=>{e.preventDefault();el.classList.remove('drag');onFiles([...e.dataTransfer.files])}); }
export function hex(buffer){return [...new Uint8Array(buffer)].map(b=>b.toString(16).padStart(2,'0')).join('');}
