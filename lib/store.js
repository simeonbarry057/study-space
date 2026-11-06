// Storage adapter. Blob in production, memory in tests.
let impl=null;
function mem(){const m=new Map();return{
  async get(k){return m.has(k)?JSON.parse(m.get(k)):null;},
  async put(k,o){m.set(k,JSON.stringify(o));},
  async del(k){m.delete(k);},
  async list(p){return [...m.keys()].filter(k=>k.startsWith(p));}};}
function blob(){
  const B=require('@vercel/blob');
  return{
  async get(k){try{const r=await B.get(k,{access:'private'});if(!r||r.statusCode===404||!r.stream)return null;const t=await new Response(r.stream).text();return JSON.parse(t);}catch(e){if(/not.?found|404/i.test(String(e&&e.message)))return null;throw e;}},
  async put(k,o){await B.put(k,JSON.stringify(o),{access:'private',addRandomSuffix:false,allowOverwrite:true,contentType:'application/json'});},
  async del(k){try{await B.del(k);}catch(e){}},
  async list(p){const out=[];let cursor;do{const r=await B.list({prefix:p,cursor,limit:1000});r.blobs.forEach(b=>out.push(b.pathname));cursor=r.hasMore?r.cursor:undefined;}while(cursor);return out;}};}
module.exports={store(){if(!impl)impl=process.env.STORE==='memory'?mem():blob();return impl;},_reset(){impl=null;}};
