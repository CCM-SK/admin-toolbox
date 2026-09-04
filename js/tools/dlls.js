const $ = (root, s) => root.querySelector(s);
const esc = v => String(v ?? '')
  .replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;')
  .replace(/'/g,'&#39;');

class Reader {
  constructor(buffer){ this.buffer=buffer; this.view=new DataView(buffer); this.bytes=new Uint8Array(buffer); this.size=buffer.byteLength; }
  u8(o){return this.view.getUint8(o);}
  u16(o){return this.view.getUint16(o,true);}
  u32(o){return this.view.getUint32(o,true);}
  u64(o){return this.view.getBigUint64(o,true);}
  ascii(o,n){let s='';for(let i=o;i<Math.min(this.size,o+n);i++){const b=this.u8(i);if(b===0)break;s+=String.fromCharCode(b);}return s;}
  slice(o,n){return this.bytes.slice(o,o+n);}
}

const MACHINES = {0x014c:'x86 (I386)',0x8664:'x64 (AMD64)',0xaa64:'ARM64',0x01c4:'ARM Thumb-2',0x01c0:'ARM',0x0200:'IA64'};
const SUBSYSTEMS = {2:'Windows GUI',3:'Windows CUI',9:'Windows CE GUI',10:'EFI application',16:'Xbox'};
const SEC_X=0x20000000, SEC_R=0x40000000, SEC_W=0x80000000;
const DYNAMIC_BASE=0x40, NX_COMPAT=0x100, NO_SEH=0x400, GUARD_CF=0x4000;

const align=(n,a)=>Math.ceil(n/a)*a;
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
function ipowSafe(x){return Math.min(x,Number.MAX_SAFE_INTEGER);}

async function digest(name, bytes){return new Uint8Array(await crypto.subtle.digest(name, bytes));}

function md5(bytes){
  const data=new Uint8Array(bytes), len=BigInt(data.length)*8n, padded=((data.length+9+63)>>6)<<6;
  const buf=new Uint8Array(padded);buf.set(data);buf[data.length]=0x80;
  const dv=new DataView(buf.buffer);
  dv.setUint32(padded-8,Number(len&0xffffffffn),true);dv.setUint32(padded-4,Number((len>>32n)&0xffffffffn),true);
  const s=[7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  const K=Array.from({length:64},(_,i)=>Math.floor(Math.abs(Math.sin(i+1))*2**32)>>>0);
  const rot=(x,c)=>(x<<c)|(x>>>(32-c));
  let a0=0x67452301,b0=0xefcdab89,c0=0x98badcfe,d0=0x10325476;
  for(let off=0;off<buf.length;off+=64){
    const M=new Uint32Array(16);for(let i=0;i<16;i++)M[i]=dv.getUint32(off+i*4,true);
    let A=a0,B=b0,C=c0,D=d0;
    for(let i=0;i<64;i++){
      let F,g;
      if(i<16){F=(B&C)|((~B)&D);g=i}
      else if(i<32){F=(D&B)|((~D)&C);g=(5*i+1)%16}
      else if(i<48){F=B^C^D;g=(3*i+5)%16}
      else{F=C^(B|(~D));g=(7*i)%16}
      const tmp=D,sum=(A+F+K[i]+M[g])>>>0;D=C;C=B;B=(B+rot(sum,s[i]))>>>0;A=tmp;
    }
    a0=(a0+A)>>>0;b0=(b0+B)>>>0;c0=(c0+C)>>>0;d0=(d0+D)>>>0;
  }
  const out=new Uint8Array(16),od=new DataView(out.buffer);
  [a0,b0,c0,d0].forEach((v,i)=>od.setUint32(i*4,v,true));return hex(out);
}

function rvaToOffset(pe,rva){
  for(const s of pe.sections){
    const start=s.virtualAddress, end=start+Math.max(s.virtualSize,s.sizeOfRawData);
    if(rva>=start&&rva<end)return s.pointerToRawData+(rva-start);
  }
  return null;
}
function cstr(r,o,max=8192){
  if(o==null||o<0||o>=r.size)return '';
  let s='';for(let i=o;i<Math.min(r.size,o+max);i++){const b=r.u8(i);if(b===0)break;s+=String.fromCharCode(b);}return s;
}

function parsePE(r){
  const p={valid:false,warnings:[],sections:[],dataDirectories:[],imports:[],exports:[],relocations:[],resources:[],tls:null,cli:null,dotnet:null};
  if(r.size<64||r.u16(0)!==0x5a4d){p.warnings.push('Missing DOS MZ header.');return p;}
  const nt=r.u32(0x3c);if(nt+24>r.size||r.u32(nt)!==0x4550){p.warnings.push('Missing PE signature.');return p;}
  const f=nt+4,opt=f+20,pco=f;
  p.machine=r.u16(pco);p.machineName=MACHINES[p.machine]||`Unknown (0x${p.machine.toString(16)})`;
  p.numberOfSections=r.u16(f+2);p.timestamp=r.u32(f+4);const optSize=r.u16(f+16);p.fileCharacteristics=r.u16(f+18);
  p.magic=r.u16(opt);p.is64=p.magic===0x20b;
  if(p.magic!==0x10b&&!p.is64){p.warnings.push(`Unsupported optional header: 0x${p.magic.toString(16)}`);return p;}
  p.entryPoint=r.u32(opt+16);p.imageBase=p.is64?r.u64(opt+24):BigInt(r.u32(opt+28));
  p.sectionAlignment=r.u32(opt+32);p.fileAlignment=r.u32(opt+36);p.sizeOfImage=r.u32(opt+56);p.sizeOfHeaders=r.u32(opt+60);
  p.subsystem=r.u16(opt+68);p.dllCharacteristics=r.u16(opt+70);p.checksum=r.u32(opt+64);
  const dirCount=r.u32(opt+(p.is64?108:92)), dirOff=opt+(p.is64?112:96);
  for(let i=0;i<Math.min(dirCount,16);i++)p.dataDirectories.push({index:i,rva:r.u32(dirOff+i*8),size:r.u32(dirOff+i*8+4)});
  const secOff=opt+optSize;
  for(let i=0;i<p.numberOfSections;i++){
    const o=secOff+i*40;if(o+40>r.size)break;
    p.sections.push({name:r.ascii(o,8).replace(/\0/g,''),virtualSize:r.u32(o+8),virtualAddress:r.u32(o+12),sizeOfRawData:r.u32(o+16),pointerToRawData:r.u32(o+20),characteristics:r.u32(o+36)});
  }
  p.valid=true;
  parseImports(r,p);parseExports(r,p);parseRelocs(r,p);parseTLS(r,p);parseResources(r,p);parseCLI(r,p);
  return p;
}

function dir(pe,i){const d=pe.dataDirectories[i];if(!d||!d.rva||!d.size)return null;return {...d,offset:rvaToOffset(pe,d.rva)};}

function parseImports(r,p){
  const d=dir(p,1);if(!d||d.offset==null)return;
  const step=p.is64?8:4;
  for(let n=0;n<512;n++){
    const o=d.offset+n*20;if(o+20>r.size)break;
    const oft=r.u32(o),nameRva=r.u32(o+12),ft=r.u32(o+16);if(!oft&&!nameRva&&!ft)break;
    const no=rvaToOffset(p,nameRva),dll=no==null?'?':cstr(r,no),to=rvaToOffset(p,oft||ft),functions=[];
    if(to!=null)for(let j=0;j<4096;j++){
      const x=to+j*step;if(x+step>r.size)break;const v=p.is64?r.u64(x):BigInt(r.u32(x));if(v===0n)break;
      const mask=p.is64?0x8000000000000000n:0x80000000n;
      if(v&mask)functions.push({ordinal:Number(v&0xffffn)});
      else{const h=rvaToOffset(p,Number(v&0xffffffffn));if(h!=null)functions.push({hint:r.u16(h),name:cstr(r,h+2)})}
    }
    p.imports.push({dll,functions});
  }
}

function parseExports(r,p){
  const d=dir(p,0);if(!d||d.offset==null||d.offset+40>r.size)return;
  const o=d.offset,base=r.u32(o+16),nf=r.u32(o+20),nn=r.u32(o+24),fr=r.u32(o+28),nr=r.u32(o+32),orr=r.u32(o+36);
  const fo=rvaToOffset(p,fr),no=rvaToOffset(p,nr),oo=rvaToOffset(p,orr);if(fo==null||no==null||oo==null)return;
  for(let i=0;i<nn&&i<20000;i++){const nameOff=rvaToOffset(p,r.u32(no+i*4)),ord=r.u16(oo+i*2);if(nameOff==null||ord>=nf)continue;p.exports.push({name:cstr(r,nameOff),ordinal:base+ord,rva:r.u32(fo+ord*4)})}
}

function parseRelocs(r,p){
  const d=dir(p,5);if(!d||d.offset==null)return;
  let pos=d.offset,end=Math.min(r.size,d.offset+d.size);
  while(pos+8<=end){const page=r.u32(pos),size=r.u32(pos+4);if(size<8||pos+size>end)break;const count=(size-8)/2,entries=[];for(let i=0;i<count;i++){const x=r.u16(pos+8+i*2);entries.push({type:x>>>12,offset:x&0xfff})}p.relocations.push({pageRva:page,count,entries:entries.slice(0,100)});pos+=size}
}

function parseTLS(r,p){
  const d=dir(p,9);if(!d||d.offset==null)return;
  const o=d.offset;p.tls={offset:o};
  if(p.is64&&o+40<=r.size){p.tls.start=r.u64(o).toString();p.tls.end=r.u64(o+8).toString();p.tls.index=r.u64(o+16).toString();p.tls.callbacks=r.u64(o+24).toString()}
  else if(!p.is64&&o+24<=r.size){p.tls.start=r.u32(o);p.tls.end=r.u32(o+4);p.tls.index=r.u32(o+8);p.tls.callbacks=r.u32(o+12)}
}

function parseResources(r,p){
  const d=dir(p,2);if(!d||d.offset==null)return;
  const root=d.offset,seen=new Set();
  function walk(off,path,depth){if(depth>6||off<0||off+16>r.size||seen.has(off))return;seen.add(off);
    const count=Math.min(r.u16(off+12)+r.u16(off+14),4096);
    for(let i=0;i<count;i++){const e=off+16+i*8;if(e+8>r.size)break;const nr=r.u32(e),dr=r.u32(e+4);let label;
      if(nr&0x80000000){const no=root+(nr&0x7fffffff);if(no+2>r.size)continue;const len=r.u16(no);let s='';for(let j=0;j<len;j++)s+=String.fromCharCode(r.u16(no+2+j*2));label=s}
      else label=String(nr&0xffff);
      if(dr&0x80000000)walk(root+(dr&0x7fffffff),path.concat(label),depth+1);
      else{const de=root+dr;if(de+16>r.size)continue;p.resources.push({path:path.concat(label).join('/'),rva:r.u32(de),size:r.u32(de+4)})}
    }
  }
  walk(root,[],0);
}

function parseCLI(r,p){
  const d=dir(p,14);if(!d||d.offset==null||d.offset+16>r.size)return;
  p.cli={cb:r.u32(d.offset),major:r.u16(d.offset+4),minor:r.u16(d.offset+6),metadataRva:r.u32(d.offset+8),metadataSize:r.u32(d.offset+12),flags:r.u32(d.offset+16)};
  const o=rvaToOffset(p,p.cli.metadataRva);if(o==null||o+16>r.size||r.u32(o)!==0x424a5342)return;
  const vlen=r.u32(o+12),v=new TextDecoder().decode(r.slice(o+16,vlen)).replace(/\0+$/,'').trim();let pos=align(o+16+vlen,4);if(pos+4>r.size)return;
  const streams=r.u16(pos+2);pos+=4;const map={};
  for(let i=0;i<streams;i++){if(pos+8>r.size)break;const so=r.u32(pos),sz=r.u32(pos+4);let n='',q=pos+8;while(q<r.size&&r.u8(q)!==0)n+=String.fromCharCode(r.u8(q++));pos=align(q+1,4);map[n]={offset:o+so,size:sz}}
  p.dotnet={version:v,streams:Object.fromEntries(Object.entries(map).map(([k,x])=>[k,{offset:x.offset-o,size:x.size}])),namespaces:[],types:[],methods:[],references:[]};
  // High-value string heap samples.
  if(map['#Strings']){
    const so=map['#Strings'].offset, sz=map['#Strings'].size;
    p.dotnet.getString=i=>i&&i<sz?cstr(r,so+i,Math.min(sz-i,4096)):'';
  }
  parseDotnetRows(r,p,o,map);
}

function parseDotnetRows(r,p,base,map){
  const t=map['#~']||map['#-'];if(!t)return;const o=t.offset;if(o+24>r.size)return;
  const heap=r.u8(o+6),lo=r.u32(o+8),hi=r.u32(o+12);let pos=o+24;const valid=[];
  for(let i=0;i<64;i++){const yes=i<32?((lo>>>i)&1):((hi>>>(i-32))&1);if(yes)valid.push(i)}
  const rows={};for(const i of valid){if(pos+4>r.size)return;rows[i]=r.u32(pos);pos+=4}
  p.dotnet.rowCounts=Object.fromEntries(Object.entries(rows).map(([k,v])=>[`table_${k}`,v]));
  const strIx=heap&1?4:2,blobIx=heap&4?4:2;
  // Sizes for Module, TypeRef, TypeDef, MethodDef, AssemblyRef.
  const idx=t2=>(rows[t2]||0)<65536?2:4;
  const codedMax=(tables,bits)=>Math.max(...tables.map(x=>rows[x]||0),0)<(1<<(16-bits))?2:4;
  const tdtr=codedMax([1,2,27],2);
  const sizes={
    0:2+strIx+2+2+2,
    1:tdtr+strIx,
    2:4+strIx+strIx+tdtr+idx(4)+idx(6),
    6:4+2+2+2+2+strIx+blobIx+idx(8),
    35:4+2+2+2+2+4+4+4+4+strIx+2+2
  };
  const offsets={};
  for(const i of valid){offsets[i]=pos;if(!(i in sizes))return;pos+=sizes[i]*(rows[i]||0);if(pos>r.size)return}
  const gs=p.dotnet.getString||(()=>'');

  if(offsets[2]!=null){
    const off=offsets[2],sz=sizes[2],count=rows[2]||0;
    for(let i=0;i<count;i++){const x=off+i*sz,name=strIx===2?r.u16(x+4):r.u32(x+4),ns=strIx===2?r.u16(x+4+strIx):r.u32(x+4+strIx);const n=gs(name),s=gs(ns);if(n)p.dotnet.types.push(s?`${s}.${n}`:n);if(s)p.dotnet.namespaces.push(s)}
  }
  if(offsets[6]!=null){
    const off=offsets[6],sz=sizes[6],count=rows[6]||0;
    for(let i=0;i<count;i++){const x=off+i*sz,ni=strIx===2?r.u16(x+10):r.u32(x+10),n=gs(ni);if(n)p.dotnet.methods.push(n)}
  }
  if(offsets[35]!=null){
    const off=offsets[35],sz=sizes[35],count=rows[35]||0;
    for(let i=0;i<count;i++){const x=off+i*sz;const ni=strIx===2?r.u16(x+20):r.u32(x+20);const n=gs(ni);const ver=[r.u16(x+4),r.u16(x+6),r.u16(x+8),r.u16(x+10)].join('.');if(n)p.dotnet.references.push({name:n,version:ver})}
  }
  p.dotnet.namespaces=[...new Set(p.dotnet.namespaces)].sort();
  p.dotnet.types=[...new Set(p.dotnet.types)].slice(0,10000).sort();
  p.dotnet.methods=[...new Set(p.dotnet.methods)].slice(0,10000).sort();
}

function extractStrings(r){
  const ascii=[],unicode=[];
  let s='',start=0;
  for(let i=0;i<r.size;i++){const b=r.u8(i);if(b>=0x20&&b<=0x7e){if(!s)start=i;s+=String.fromCharCode(b)}else{if(s.length>=5)ascii.push({value:s,offset:start});s=''}}
  if(s.length>=5)ascii.push({value:s,offset:start});
  s='';start=0;
  for(let i=0;i+1<r.size;i+=2){const c=r.u16(i);if(c>=0x20&&c<=0x7e){if(!s)start=i;s+=String.fromCharCode(c)}else{if(s.length>=5)unicode.push({value:s,offset:start});s=''}}
  if(s.length>=5)unicode.push({value:s,offset:start});
  return {ascii,unicode};
}

function heuristicFindings(pe,strings){
  const f=[];
  if(!pe.valid)return f;
  const dc=pe.dllCharacteristics||0;
  if(!(dc&NX_COMPAT))f.push({level:'warning',title:'NX / DEP compatibility flag absent',detail:'The PE does not advertise NX compatibility. Older binaries may legitimately lack this flag.'});
  if(dc&DYNAMIC_BASE)f.push({level:'info',title:'ASLR / Dynamic Base advertised',detail:'The PE has the Dynamic Base characteristic.'});
  if(dc&GUARD_CF)f.push({level:'info',title:'Control Flow Guard advertised',detail:'The PE has the Guard CF characteristic.'});
  if(dc&NO_SEH)f.push({level:'info',title:'No SEH characteristic',detail:'The PE advertises that it does not use structured exception handlers.'});
  for(const s of pe.sections){
    if((s.characteristics&SEC_X)&&(s.characteristics&SEC_W))f.push({level:'high',title:'Writable + executable section',detail:`Section ${s.name||'(unnamed)'} is both writable and executable.`});
    if(/upx|pack|aspack|themida|vmp/i.test(s.name))f.push({level:'warning',title:'Packer/protector-like section name',detail:`Section "${s.name}" resembles a known packer/protector naming pattern. This is not proof of packing or maliciousness.`});
  }
  const suspicious=['powershell','cmd.exe','wscript','cscript','rundll32','regsvr32','mshta','certutil','bitsadmin','schtasks','winhttp','wininet','urlmon','invoke-expression','frombase64string','downloadstring','http://','https://'];
  const hits=[...strings.ascii,...strings.unicode].filter(x=>suspicious.some(w=>x.value.toLowerCase().includes(w)));
  if(hits.length)f.push({level:'warning',title:'Interesting command/network strings',detail:`${new Set(hits.map(x=>x.value)).size} embedded string(s) contain scripting, download, URL, or command indicators.`});
  const apiText=pe.imports.flatMap(x=>x.functions.map(fn=>fn.name||'')).join(' ').toLowerCase();
  if(/virtualalloc|virtualprotect|writeprocessmemory|createremotethread|openprocess/.test(apiText))f.push({level:'warning',title:'Process/memory manipulation imports',detail:'The import table includes APIs often used for process or memory manipulation. These APIs also have legitimate uses.'});
  if(pe.imports.some(x=>/winhttp|wininet|urlmon/i.test(x.dll)))f.push({level:'warning',title:'Network-capable Windows DLL imported',detail:'One or more imported DLLs provide Windows networking functionality.'});
  return f;
}

function parseYaraRules(text){
  const rules=[],re=/rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\:[^{]+)?\s*\{([\s\S]*?)\}/gi;let m;
  while((m=re.exec(text||''))){
    const body=m[2],ss=body.match(/strings\s*:([\s\S]*?)(?:condition\s*:|$)/i)?.[1]||'',condition=body.match(/condition\s*:([\s\S]*)/i)?.[1]?.trim()||'',strings=[];
    const sr=/(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:"([^"]*)"|\{([^}]*)\})/g;let sm;
    while((sm=sr.exec(ss))){
      strings.push(sm[2]!=null?{id:sm[1],kind:'ascii',value:sm[2]}:{id:sm[1],kind:'hex',value:sm[3].replace(/\s+/g,'').toLowerCase()});
    }
    rules.push({name:m[1],strings,condition});
  }
  return rules;
}

function matchYara(rule,reader){
  const matched=[];
  for(const s of rule.strings){
    if(s.kind==='ascii'){
      const n=new TextEncoder().encode(s.value),h=reader.bytes;
      outer:for(let i=0;i+n.length<=h.length;i++){for(let j=0;j<n.length;j++)if(h[i+j]!==n[j])continue outer;matched.push(s.id);break}
    }else{
      const p=s.value.replace(/\?/g,'?').toLowerCase(),h=hex(reader.bytes);
      outer:for(let i=0;i+p.length<=h.length;i+=2){for(let j=0;j<p.length;j++)if(p[j]!=='?'&&p[j]!==h[i+j])continue outer;matched.push(s.id);break}
    }
  }
  const c=rule.condition.toLowerCase();
  let ok=false;
  if(/\bany\s+of\s+them\b/.test(c)||/\bany\s+of\s*\(/.test(c))ok=matched.length>0;
  else if(/\ball\s+of\s+them\b/.test(c)||/\ball\s+of\s*\(/.test(c))ok=matched.length===rule.strings.length;
  else if(/\btrue\b/.test(c))ok=true;
  else if(/\bor\b/.test(c))ok=rule.strings.some(s=>c.includes(s.id)&&matched.includes(s.id));
  else if(/\band\b/.test(c))ok=rule.strings.filter(s=>c.includes(s.id)).every(s=>matched.includes(s.id));
  else {const ids=rule.strings.filter(s=>c.includes(s.id)).map(s=>s.id);ok=ids.length?ids.every(x=>matched.includes(x)):matched.length>0}
  return {matched:ok,matchedStrings:[...new Set(matched)]};
}

async function doHashes(bytes){
  const [a,b]=await Promise.all([digest('SHA-256',bytes),digest('SHA-1',bytes)]);
  return {sha256:hex(a),sha1:hex(b),md5:md5(bytes)};
}

const sectionFlags=c=>`${c&SEC_X?'X':''}${c&SEC_R?'R':''}${c&SEC_W?'W':''}`||'—';
const formatUnix=t=>t?`${new Date(t*1000).toISOString()} (UTC)`:'—';

function renderData(file,pe,h,strings,findings,yara){
  const type=pe.dotnet?'.NET assembly':'Native / PE image';
  return `
  <div class="card">
    <h2>Quick view</h2>
    <div class="grid four">
      <div class="stat"><span>File</span><strong>${esc(file.name)}</strong></div>
      <div class="stat"><span>Type</span><strong>${esc(type)}</strong></div>
      <div class="stat"><span>Architecture</span><strong>${esc(pe.machineName)}</strong></div>
      <div class="stat"><span>Size</span><strong>${file.size.toLocaleString()} bytes</strong></div>
    </div>
    <div class="grid two">
      <div class="stat"><span>SHA-256</span><strong class="mono">${esc(h.sha256)}</strong></div>
      <div class="stat"><span>MD5</span><strong class="mono">${esc(h.md5)}</strong></div>
    </div>
  </div>

  <div class="card">
    <h2>Static indicators</h2>
    ${findings.length?findings.map(f=>`<div class="notice ${f.level==='high'?'bad':f.level==='warning'?'warn':'success'}"><b>${esc(f.title)}</b><br>${esc(f.detail)}</div>`).join(''):'<div class="notice success">No obvious issues were identified by the built-in heuristics.</div>'}
  </div>

  ${yara.length?`<div class="card"><h2>YARA results</h2>${yara.map(x=>`<div class="notice ${x.matched?'bad':'success'}"><b>${esc(x.name)}</b> — ${x.matched?'MATCH':'no match'}${x.matchedStrings.length?`<br>Matched: ${esc(x.matchedStrings.join(', '))}`:''}</div>`).join('')}</div>`:''}

  <div class="card"><h2>PE headers</h2><table><tbody>
    <tr><th>Machine</th><td>${esc(pe.machineName)}</td></tr>
    <tr><th>Magic</th><td>0x${pe.magic.toString(16)}</td></tr>
    <tr><th>PE timestamp</th><td>${esc(formatUnix(pe.timestamp))}</td></tr>
    <tr><th>Entry point RVA</th><td class="mono">0x${pe.entryPoint.toString(16)}</td></tr>
    <tr><th>Image base</th><td class="mono">0x${pe.imageBase.toString(16)}</td></tr>
    <tr><th>Subsystem</th><td>${esc(SUBSYSTEMS[pe.subsystem]||`0x${pe.subsystem.toString(16)}`)}</td></tr>
    <tr><th>Image size</th><td>${pe.sizeOfImage.toLocaleString()}</td></tr>
    <tr><th>DLL characteristics</th><td class="mono">0x${pe.dllCharacteristics.toString(16)}</td></tr>
  </tbody></table></div>

  <div class="card"><h2>Sections</h2><table><thead><tr><th>Name</th><th>RVA</th><th>Virtual</th><th>Raw</th><th>R/W/X</th></tr></thead><tbody>
    ${pe.sections.map(s=>`<tr><td class="mono">${esc(s.name)}</td><td class="mono">0x${s.virtualAddress.toString(16)}</td><td>${s.virtualSize.toLocaleString()}</td><td>${s.sizeOfRawData.toLocaleString()}</td><td>${sectionFlags(s.characteristics)}</td></tr>`).join('')}
  </tbody></table></div>

  <div class="card"><h2>Imports / dependencies</h2>
    ${pe.imports.length?pe.imports.map(i=>`<details class="card compact"><summary><b>${esc(i.dll)}</b> — ${i.functions.length} symbols</summary><div class="mono">${i.functions.slice(0,2000).map(x=>esc(x.name||`Ordinal #${x.ordinal}`)).join('<br>')}</div></details>`).join(''):'<div class="muted">No import directory parsed.</div>'}
  </div>

  <div class="card"><h2>Exports</h2>
    ${pe.exports.length?`<table><thead><tr><th>Name</th><th>Ordinal</th><th>RVA</th></tr></thead><tbody>${pe.exports.slice(0,10000).map(x=>`<tr><td class="mono">${esc(x.name)}</td><td>${x.ordinal}</td><td class="mono">0x${x.rva.toString(16)}</td></tr>`).join('')}</tbody></table>`:'<div class="muted">No named exports parsed.</div>'}
  </div>

  <div class="card"><h2>Resources / TLS / relocations</h2>
    <div class="grid three">
      <div class="stat"><span>Resources</span><strong>${pe.resources.length}</strong></div>
      <div class="stat"><span>Relocation blocks</span><strong>${pe.relocations.length}</strong></div>
      <div class="stat"><span>TLS</span><strong>${pe.tls?'Present':'Absent'}</strong></div>
    </div>
    ${pe.resources.length?`<ul>${pe.resources.slice(0,1000).map(x=>`<li class="mono">${esc(x.path)} — ${x.size.toLocaleString()} bytes</li>`).join('')}</ul>`:''}
    ${pe.tls?`<pre class="mono">${esc(JSON.stringify(pe.tls,null,2))}</pre>`:''}
  </div>

  ${pe.dotnet?`<div class="card"><h2>.NET metadata</h2>
    <div class="grid four">
      <div class="stat"><span>Metadata version</span><strong>${esc(pe.dotnet.version)}</strong></div>
      <div class="stat"><span>Namespaces</span><strong>${pe.dotnet.namespaces.length}</strong></div>
      <div class="stat"><span>Types</span><strong>${pe.dotnet.types.length}</strong></div>
      <div class="stat"><span>Methods</span><strong>${pe.dotnet.methods.length}</strong></div>
    </div>
    <h3>Assembly references</h3>${pe.dotnet.references.length?`<ul>${pe.dotnet.references.map(x=>`<li class="mono">${esc(x.name)} ${esc(x.version)}</li>`).join('')}</ul>`:'<div class="muted">No AssemblyRef rows parsed.</div>'}
    <h3>Namespaces</h3><div class="mono">${pe.dotnet.namespaces.map(esc).join('<br>')}</div>
    <h3>Types</h3><div class="mono">${pe.dotnet.types.slice(0,5000).map(esc).join('<br>')}</div>
    <h3>Methods</h3><div class="mono">${pe.dotnet.methods.slice(0,5000).map(esc).join('<br>')}</div>
  </div>`:''}

  <div class="card"><h2>Strings</h2>
    <div class="grid two">
      <div><h3>ASCII (${strings.ascii.length})</h3><pre class="mono" style="max-height:420px;overflow:auto">${esc(strings.ascii.slice(0,10000).map(x=>`0x${x.offset.toString(16)}  ${x.value}`).join('\n'))}</pre></div>
      <div><h3>UTF-16LE (${strings.unicode.length})</h3><pre class="mono" style="max-height:420px;overflow:auto">${esc(strings.unicode.slice(0,10000).map(x=>`0x${x.offset.toString(16)}  ${x.value}`).join('\n'))}</pre></div>
    </div>
  </div>`;
}

export function renderDllAnalyzer(app){
  app.innerHTML=`
  <section class="card">
    <div class="row between">
      <div><h2>DLL / PE Analyzer</h2><p class="small">Analyze .NET and native PE files entirely in the browser. The binary is never executed or uploaded.</p></div>
      <span class="badge ok"></span>
    </div>

    <div class="card">
      <label for="dll-file">PE file</label>
      <input id="dll-file" type="file" accept=".dll,.exe,.sys,.ocx,.cpl,.scr,.bin">
      <div class="row" style="margin-top:.75rem">
        <button class="btn primary" type="button" id="dll-analyze">Analyze</button>
        <button class="btn secondary" type="button" id="dll-clear">Clear</button>
      </div>
    </div>

    <div class="card">
      <label for="dll-yara">Optional local YARA rule files</label>
      <input id="dll-yara" type="file" accept=".yar,.yara,.rule,.txt" multiple>
      <div class="muted">Safe subset: quoted ASCII strings, hex byte patterns, and simple conditions such as <span class="mono">any of them</span>, <span class="mono">all of them</span>, <span class="mono">$a and $b</span>, <span class="mono">$a or $b</span>.</div>
    </div>

    <div id="dll-message" class="notice hidden" role="status"></div>
    <div id="dll-results"><div class="card"><h2>Quick view</h2><div class="muted">Choose a PE/DLL and click Analyze.</div></div></div>
  </section>`;

  const fileEl=$('#dll-file'),yaraEl=$('#dll-yara'),msg=$('#dll-message'),results=$('#dll-results');

  const show=(text,kind='error')=>{msg.textContent=text||'';msg.className=text?`notice ${kind}`:'notice hidden'};

  $('#dll-analyze').addEventListener('click',async()=>{
    const file=fileEl.files?.[0];if(!file){show('Choose a PE/DLL file first.');return}
    try{
      show('Reading and analyzing locally…','success');
      const buffer=await file.arrayBuffer(),reader=new Reader(buffer),pe=parsePE(reader);
      if(!pe.valid){results.innerHTML=`<div class="card"><h2>Not a supported PE file</h2><div class="notice bad">${esc(pe.warnings.join(' ')||'PE parsing failed.')}</div></div>`;return}
      const strings=extractStrings(reader),h=await doHashes(reader.bytes);
      const findings=heuristicFindings(pe,strings);
      let yara=[];
      for(const yf of [...yaraEl.files||[]]){
        const rules=parseYaraRules(await yf.text());
        yara.push(...rules.map(rule=>({name:rule.name,...matchYara(rule,reader)})));
      }
      results.innerHTML=renderData(file,pe,h,strings,findings,yara);
      show(`Analysis complete: ${file.name} — ${file.size.toLocaleString()} bytes.`,'success');
    }catch(e){results.innerHTML='<div class="card"><h2>Analysis failed</h2></div>';show(e?.message||'Could not analyze the file.')}
  });

  $('#dll-clear').addEventListener('click',()=>{
    fileEl.value='';yaraEl.value='';
    results.innerHTML='<div class="card"><h2>Quick view</h2><div class="muted">Choose a PE/DLL and click Analyze.</div></div>';show('');
  });
}