const crypto=require('crypto');const {store}=require('./store');
const SECRET=()=>process.env.SESSION_SECRET||'';
const OWNER_EMAIL=()=>(process.env.OWNER_EMAIL||'').toLowerCase();
const hex=b=>Buffer.from(b).toString('hex');
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const b64u=s=>Buffer.from(s).toString('base64url');
function sign(p){const body=b64u(JSON.stringify(p));const mac=crypto.createHmac('sha256',SECRET()).update(body).digest('base64url');return body+'.'+mac;}
function verify(tok){if(!tok||!SECRET())return null;const [body,mac]=String(tok).split('.');if(!body||!mac)return null;const exp=crypto.createHmac('sha256',SECRET()).update(body).digest('base64url');
  const a=Buffer.from(mac),b=Buffer.from(exp);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return null;try{const p=JSON.parse(Buffer.from(body,'base64url').toString());return p.exp>Date.now()?p:null;}catch(e){return null;}}
function cookieOf(req){const c=(req.headers&&req.headers.cookie)||'';const m=c.match(/(?:^|;\s*)ss=([^;]+)/);return m?decodeURIComponent(m[1]):'';}
const setCookie=(v,age)=>'ss='+encodeURIComponent(v)+'; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age='+age;
function scrypt(pw,salt){return new Promise((res,rej)=>crypto.scrypt(pw,salt,32,{N:16384,r:8,p:1,maxmem:64*1024*1024},(e,k)=>e?rej(e):res(k)));}
const R=(status,body,headers)=>({status,body,headers:headers||{}});
const tries=new Map();
function throttle(key){const now=Date.now(),a=(tries.get(key)||[]).filter(t=>now-t<10*60*1000);a.push(now);tries.set(key,a);return a.length>12;}
const EMAIL=/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const clean=(s,n)=>String(s==null?'':s).replace(/[\u0000-\u001f<>]/g,'').trim().slice(0,n);

async function session(req){const p=verify(cookieOf(req));if(!p)return null;const u=await store().get('users/'+p.id+'.json');if(!u)return null;return{id:u.id,email:u.email,name:u.name,isOwner:u.role==='owner'};}

async function signup(req){
  const b=req.body||{};const ip=(req.headers['x-forwarded-for']||'').split(',')[0]||'x';
  if(throttle('s:'+ip))return R(429,{error:'Too many tries. Wait a few minutes.'});
  const name=clean(b.name,60),email=clean(b.email,254).toLowerCase(),pw=String(b.password||'');
  if(!name)return R(400,{error:'Enter your name.'});
  if(!EMAIL.test(email))return R(400,{error:'Enter a valid email address.'});
  if(pw.length<8||pw.length>200)return R(400,{error:'Use a password of at least 8 characters.'});
  if(!SECRET())return R(500,{error:'Server is not set up yet.'});
  const ek='emails/'+sha(email)+'.json';
  if(await store().get(ek))return R(409,{error:'That email already has an account. Sign in instead.'});
  let role='learner';
  if(email===OWNER_EMAIL()){
    const ok=process.env.OWNER_SETUP_CODE&&String(b.setup||'')===process.env.OWNER_SETUP_CODE;
    if(!ok)return R(403,{error:'This email is reserved for the site owner. Enter the owner setup code.'});
    if(await store().get('owner.json'))return R(403,{error:'The owner account already exists. Sign in.'});
    role='owner';
  }
  const id='u_'+hex(crypto.randomBytes(9)),salt=crypto.randomBytes(16);
  const hash=hex(await scrypt(pw,salt));
  await store().put('users/'+id+'.json',{id,email,name,role,salt:hex(salt),hash,at:new Date().toISOString()});
  await store().put(ek,{id});
  if(role==='owner')await store().put('owner.json',{id});
  else await store().put('docs/requests/'+id+'.json',{name,status:'pending',at:new Date().toISOString(),notifiedAt:null});
  return R(200,{ok:1},{'Set-Cookie':setCookie(sign({id,exp:Date.now()+30*864e5}),30*86400)});
}
async function login(req){
  const b=req.body||{};const email=clean(b.email,254).toLowerCase(),pw=String(b.password||'');const ip=(req.headers['x-forwarded-for']||'').split(',')[0]||'x';
  if(throttle('l:'+ip+':'+email))return R(429,{error:'Too many tries. Wait a few minutes.'});
  const bad=R(401,{error:'Email or password is not right.'});
  const ref=await store().get('emails/'+sha(email)+'.json');if(!ref)return bad;
  const u=await store().get('users/'+ref.id+'.json');if(!u)return bad;
  const h=await scrypt(pw,Buffer.from(u.salt,'hex'));const want=Buffer.from(u.hash,'hex');
  if(h.length!==want.length||!crypto.timingSafeEqual(h,want))return bad;
  return R(200,{ok:1},{'Set-Cookie':setCookie(sign({id:u.id,exp:Date.now()+30*864e5}),30*86400)});
}
const logout=()=>R(200,{ok:1},{'Set-Cookie':setCookie('',0)});
async function me(req){const s=await session(req);return R(200,s?{id:s.id,email:s.email,name:s.name,isOwner:s.isOwner,canEdit:s.isOwner}:{id:null});}

// ---- db with rules ----
const PATH=/^[A-Za-z0-9_\-]+(\/[A-Za-z0-9_\-]+){0,5}$/;
async function isAdmin(s){if(s.isOwner)return true;const d=await store().get('docs/approved/'+s.id+'.json');return !!(d&&d.role==='admin');}
function parts(p){return p.split('/');}
async function canRead(s,p,list){
  const [a,b]=parts(p);
  if(list){if(p==='approved')return isAdmin(s);if(p==='requests'||p==='alerts')return s.isOwner;return false;}
  if(a==='approved'&&b)return b===s.id||isAdmin(s);
  if(a==='requests'&&b)return b===s.id||s.isOwner;
  if(a==='alerts'&&b)return b===s.id||s.isOwner;
  if(a==='data'&&parts(p)[1]==='users'&&parts(p)[2])return parts(p)[2]===s.id;
  return false;
}
async function sanitize(s,p,op,data,prev){
  const [a,b]=parts(p);
  if(s.isOwner&&!(a==='data')){return {ok:1,data};}
  if(a==='requests'&&b===s.id&&op!=='delete'){
    if(prev&&prev.status==='denied')return null;
    const d=data||{};return {ok:1,data:{name:clean(d.name||(prev&&prev.name)||s.name,60),status:'pending',at:(prev&&prev.at)||new Date().toISOString(),notifiedAt:prev?prev.notifiedAt:null}};}
  if(a==='alerts'&&b===s.id&&op==='set'){
    const d=data||{};return {ok:1,data:{name:clean(d.name||s.name,80),at:new Date().toISOString(),count:Math.min(1e6,Math.max(1,parseInt(d.count,10)||1)),route:'admin',notifiedAt:null}};}
  if(a==='data'&&parts(p)[2]===s.id&&parts(p).length===4&&parts(p)[3]==='progress'&&op!=='delete'){
    const d=data||{};if(typeof d.json!=='string'||d.json.length>400000)return null;return {ok:1,data:{json:d.json,at:new Date().toISOString()}};}
  if(a==='data'&&parts(p)[2]===s.id&&op==='delete')return {ok:1,data:null};
  return null;
}
async function db(req){
  const s=await session(req);if(!s)return R(401,{err:'signed_out'});
  const o=req.body||{};const p=String(o.p||'').replace(/^\/+|\/+$/g,'');
  if(!PATH.test(p))return R(400,{err:'bad_path'});
  if(JSON.stringify(o.d||{}).length>450000)return R(413,{err:'too_big'});
  if(o.t==='get'){if(!(await canRead(s,p,false)))return R(403,{err:'not_granted'});const d=await store().get('docs/'+p+'.json');return R(200,d?{exists:true,data:d}:{exists:false});}
  if(o.t==='list'){if(!(await canRead(s,p,true)))return R(403,{err:'not_granted'});const keys=await store().list('docs/'+p+'/');const out=[];
    for(const k of keys){const rest=k.slice(('docs/'+p+'/').length);if(rest.includes('/')||!rest.endsWith('.json'))continue;const d=await store().get(k);if(d)out.push({id:rest.slice(0,-5),data:d});}return R(200,{docs:out});}
  if(o.t==='set'||o.t==='update'||o.t==='delete'){
    const key='docs/'+p+'.json';const prev=await store().get(key);
    const next=o.t==='update'?Object.assign({},prev||{},o.d||{}):o.d;
    const ok=await sanitize(s,p,o.t,next,prev);if(!ok)return R(403,{err:'not_granted'});
    if(o.t==='delete')await store().del(key);else await store().put(key,ok.data);
    return R(200,{ok:1});}
  return R(400,{err:'bad_op'});
}
// ---- owner email-alert feed ----
async function notify(req){
  const q=req.query||{};const tok=String(q.token||''),want=String(process.env.NOTIFY_TOKEN||'');
  const a=Buffer.from(tok),b=Buffer.from(want);if(!want||a.length!==b.length||!crypto.timingSafeEqual(a,b))return R(401,{error:'no'});
  if(q.ack){for(const it of String(q.ack).split(',')){const [c,id]=it.split(':');if(!/^(requests|alerts)$/.test(c)||!/^[A-Za-z0-9_\-]+$/.test(id||''))continue;const k='docs/'+c+'/'+id+'.json';const d=await store().get(k);if(d){d.notifiedAt=new Date().toISOString();await store().put(k,d);}}return R(200,{ok:1});}
  const out={signups:[],alerts:[]};
  for(const c of ['requests','alerts']){for(const k of await store().list('docs/'+c+'/')){const d=await store().get(k);if(!d||d.notifiedAt)continue;if(c==='requests'&&d.status!=='pending')continue;
    const id=k.split('/').pop().slice(0,-5);let email='';if(c==='requests'){const u=await store().get('users/'+id+'.json');email=u?u.email:'';}
    (c==='requests'?out.signups:out.alerts).push({id,name:d.name,email,at:d.at,count:d.count});}}
  return R(200,out);
}
module.exports={signup,login,logout,me,db,notify,session};
