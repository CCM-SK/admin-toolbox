import { $, escapeHtml, downloadText } from '../utils.js';

const WELL_KNOWN_RIDS = new Map([
  [500,'Built-in Administrator'],[501,'Built-in Guest'],[502,'KRBTGT'],[512,'Domain Admins'],[513,'Domain Users'],[514,'Domain Guests'],
  [515,'Domain Computers'],[516,'Domain Controllers'],[517,'Cert Publishers'],[518,'Schema Admins'],[519,'Enterprise Admins'],
  [520,'Group Policy Creator Owners'],[521,'Read-only Domain Controllers'],[522,'Cloneable Domain Controllers'],[525,'Protected Users'],
  [526,'Key Admins'],[527,'Enterprise Key Admins'],[553,'RAS and IAS Servers'],[544,'Builtin Administrators'],[545,'Builtin Users'],
  [546,'Builtin Guests'],[548,'Builtin Account Operators'],[549,'Builtin Server Operators'],[550,'Builtin Print Operators'],[551,'Builtin Backup Operators']
]);

export function renderIdentity(app){
  app.innerHTML=`<section class="card"><h2>SID / GUID / identity decoder</h2><p class="small">Recognizes Windows SIDs, GUIDs, UUID byte strings, and common GUID representations. Processing is entirely local.</p>
  <label for="identityInput">Value</label><textarea id="identityInput" class="mono" style="min-height:180px" placeholder="Examples:\nS-1-5-21-1111111111-2222222222-3333333333-1107\n550e8400-e29b-41d4-a716-446655440000\n00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"></textarea>
  <div class="row" style="margin-top:10px"><button class="btn primary" id="identityDecode">Decode</button><button class="btn" id="identityClear">Clear</button><button class="btn" id="identityExport">Export result</button></div></section>
  <section class="card" id="identityResult" hidden></section>`;

  let last=null;
  $('#identityDecode').onclick=()=>{last=decode($('#identityInput').value.trim());render(last)};
  $('#identityClear').onclick=()=>{ $('#identityInput').value=''; $('#identityResult').hidden=true; last=null; $('#identityInput').focus();};
  $('#identityExport').onclick=()=>{ if(!last) last=decode($('#identityInput').value.trim()); downloadText('identity-decoder.json',JSON.stringify(last,null,2),'application/json;charset=utf-8');};

  function decode(v){
    const out={input:v, matches:[]};
    if(!v) return out;
    const sid = parseSid(v); if(sid) out.matches.push(sid);
    const guid = parseGuid(v); if(guid) out.matches.push(guid);
    const bytes = parseBytes(v);
    if(bytes && bytes.length===16){
      const standard=bytesToGuid(bytes,false), mixed=bytesToGuid(bytes,true);
      out.matches.push({type:'GUID byte string',standardGuid:standard,littleEndianGuid:mixed,rawBytes:Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join(' ')});
    }
    if(!out.matches.length) out.error='No recognized SID/GUID representation.';
    return out;
  }

  function parseSid(v){
    const m=v.match(/^S-(\d+)-([\dA-Fa-fx]+)((?:-\d+)+)$/); if(!m) return null;
    const revision=Number(m[1]); const authority=BigInt(m[2].startsWith('0x')?m[2]:m[2]); const subs=m[3].slice(1).split('-').map(Number);
    const rid=subs.at(-1); return {type:'Windows SID',revision,identifierAuthority:authority.toString(),subAuthorities:subs,relativeId:rid,wellKnownMeaning:WELL_KNOWN_RIDS.get(rid)||null,domainIdentifier:subs.length>1?subs.slice(0,-1):[]};
  }

  function parseGuid(v){
    const s=v.trim().replace(/[{}]/g,'');
    if(!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s)) return null;
    const hex=s.replaceAll('-','').toLowerCase();
    const bytes=hex.match(/../g).map(x=>parseInt(x,16));
    return {type:'GUID / UUID',canonical:s.toLowerCase(),uppercase:s.toUpperCase(),braced:`{${s.toUpperCase()}}`,hexBytes:bytes.map(b=>b.toString(16).padStart(2,'0')).join(' '),registryByteOrder:toMixedEndian(bytes).map(b=>b.toString(16).padStart(2,'0')).join(' ')};
  }

  function parseBytes(v){
    const compact=v.replace(/0x/gi,'').replace(/[\s,;:-]/g,''); if(!/^[0-9a-fA-F]+$/.test(compact)||compact.length%2) return null; const out=new Uint8Array(compact.length/2); for(let i=0;i<out.length;i++)out[i]=parseInt(compact.slice(i*2,i*2+2),16); return out;
  }
  function bytesToGuid(b,little){const x=little?toMixedEndian([...b]):[...b]; const h=x.map(z=>z.toString(16).padStart(2,'0')).join(''); return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;}
  function toMixedEndian(b){return [b[3],b[2],b[1],b[0],b[5],b[4],b[7],b[6],...b.slice(8)];}
  function render(r){
    const el=$('#identityResult'); el.hidden=false;
    if(r.error){el.innerHTML=`<p class="status warn">${escapeHtml(r.error)}</p>`;return;}
    el.innerHTML=r.matches.map(m=>`<div class="card" style="box-shadow:none;margin:0 0 12px;padding:14px"><h3>${escapeHtml(m.type)}</h3><pre class="mono">${escapeHtml(JSON.stringify(m,null,2))}</pre></div>`).join('');
  }
}
