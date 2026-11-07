// Storage adapter. Blob in production, memory in tests.
let impl=null;
function mem(){const m=new Map();return{
  async get(k){return m.has(k)?JSON.parse(m.get(k)):null;},
  async put(k,o){m.set(k,JSON.stringify(o));},
  async del(k){m.delete(k);},
  async list(p){return [...m.keys()].filter(k=>k.startsWith(p));}};}
function blob(token){
  const B=require('@vercel/blob');const T=token?{token}:{};
  return{
  async get(k){try{const r=await B.get(k,{access:'private',...T});if(!r||r.statusCode===404||!r.stream)return null;const t=await new Response(r.stream).text();return JSON.parse(t);}catch(e){if(/not.?found|404/i.test(String(e&&e.message)))return null;throw e;}},
  async put(k,o){await B.put(k,JSON.stringify(o),{access:'private',addRandomSuffix:false,allowOverwrite:true,contentType:'application/json',...T});},
  async del(k){try{await B.del(k,T);}catch(e){}},
  async list(p){const out=[];let cursor;do{const r=await B.list({prefix:p,cursor,limit:1000,...T});r.blobs.forEach(b=>out.push(b.pathname));cursor=r.hasMore?r.cursor:undefined;}while(cursor);return out;}};}

// ---- Mirror ("RAID 1"): every write goes to two independent stores ----
// A write succeeds if at least one store took it. The store that missed it gets a marker
// (sync/<id>.json) kept in the store that worked; sync() later copies the change across.
// Reads use the main store and fall back to the mirror only if the main store ERRORS
// (an outage), so a deleted account can never come back from the mirror.
const SYNC='sync/';
function mirror(A,B,onEvent){
  const ev=(e)=>{try{onEvent&&onEvent(e);}catch(x){}};
  const mk=(k,op)=>({k,op,at:new Date().toISOString()});
  const mid=(k)=>SYNC+require('crypto').createHash('sha256').update(k).digest('hex').slice(0,40)+'.json';
  const side=async(st,fn)=>{try{return {ok:true,v:await fn(st)};}catch(e){return {ok:false,e};}};
  async function mark(from,k,op){try{await from.put(mid(k),mk(k,op));}catch(e){}}
  return{
    async get(k){const a=await side(A,s=>s.get(k));if(a.ok)return a.v;ev('read-fallback');const b=await side(B,s=>s.get(k));if(b.ok)return b.v;throw a.e;},
    async put(k,o){const [a,b]=await Promise.all([side(A,s=>s.put(k,o)),side(B,s=>s.put(k,o))]);
      if(!a.ok&&!b.ok)throw a.e;
      if(!a.ok){ev('main-write-failed');await mark(B,k,'put');}
      else if(!b.ok){ev('mirror-write-failed');await mark(A,k,'put');}
    },
    async del(k){const [a,b]=await Promise.all([side(A,s=>s.del(k)),side(B,s=>s.del(k))]);
      // del swallows errors inside the adapter; verify so a failed delete is never silent
      const [ga,gb]=await Promise.all([side(A,s=>s.get(k)),side(B,s=>s.get(k))]);
      const goneA=ga.ok&&!ga.v,goneB=gb.ok&&!gb.v;
      if(goneA&&!goneB)await mark(A,k,'del');
      else if(goneB&&!goneA)await mark(B,k,'del');
      else if(!goneA&&!goneB&&!(a.ok&&b.ok&&!ga.v&&!gb.v)){if(ga.ok)await mark(A,k,'del');else if(gb.ok)await mark(B,k,'del');}
    },
    async list(p){const a=await side(A,s=>s.list(p));if(a.ok)return a.v.filter(x=>!x.startsWith(SYNC)||p.startsWith(SYNC));ev('read-fallback');const b=await side(B,s=>s.list(p));if(b.ok)return b.v;throw a.e;},
    // Copy every pending change to the store that missed it. Returns counts and the state of both stores.
    async sync(){
      const out={main:true,mirror:true,pending:0,fixed:0,failed:0};
      const ma=await side(A,s=>s.list(SYNC)),mb=await side(B,s=>s.list(SYNC));
      out.main=ma.ok;out.mirror=mb.ok;
      for(const [st,other,m] of [[A,B,ma],[B,A,mb]]){
        if(!m.ok)continue;
        for(const key of m.v){
          out.pending++;
          try{const mkr=await st.get(key);if(!mkr){continue;}
            if(mkr.op==='put'){const v=await st.get(mkr.k);if(v)await other.put(mkr.k,v);else await other.del(mkr.k);}
            else await other.del(mkr.k);
            await st.del(key);out.fixed++;
          }catch(e){out.failed++;}
        }
      }
      return out;
    },
    // Full check: do both stores answer, and how many changes are waiting?
    async health(){const t=Date.now()+'';const probe='health/probe.json';
      const a=await side(A,async s=>{await s.put(probe,{t});return (await s.get(probe)).t===t;});
      const b=await side(B,async s=>{await s.put(probe,{t});return (await s.get(probe)).t===t;});
      let pending=0;for(const [st,r] of [[A,a],[B,b]])if(r.ok){const l=await side(st,s=>s.list(SYNC));if(l.ok)pending+=l.v.length;}
      return {main:a.ok&&a.v===true,mirror:b.ok&&b.v===true,pending};}
  };
}
function build(){
  if(process.env.STORE==='memory'){
    if(process.env.MIRROR==='memory'){const a=mem(),b=mem();global.__mirrorTest={a,b};return mirror(a,b);}
    return mem();}
  const main=blob();
  const mt=process.env.BLOB_MIRROR_READ_WRITE_TOKEN||process.env.BLOB_MIRROR_TOKEN;
  return mt?mirror(main,blob(mt)):main;
}
module.exports={store(){if(!impl)impl=build();return impl;},_reset(){impl=null;},mirror,mem};
