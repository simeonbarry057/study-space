// Standalone server (start with: node standby/server.js): runs the whole site (pages + API) on any host that can run Node 22,
// for example Render, Railway or Fly.io. Used as the standby if Vercel is unavailable.
// It needs the same secrets as the Vercel project plus UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN.
const http=require('http'),fs=require('fs'),path=require('path'),url=require('url');
const handler=require('../api/[action].js');
const core=require('../lib/core');
const PUB=path.join(__dirname,'..','public');
const TYPES={'.html':'text/html; charset=utf-8','.json':'application/json','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.ico':'image/x-icon','.txt':'text/plain; charset=utf-8','.woff2':'font/woff2'};
function serveFile(res,file){
  fs.readFile(file,(e,buf)=>{
    if(e){res.statusCode=404;res.setHeader('Content-Type','text/plain');return res.end('Not found');}
    res.statusCode=200;res.setHeader('Content-Type',TYPES[path.extname(file)]||'application/octet-stream');
    res.setHeader('Cache-Control',path.extname(file)==='.html'||path.basename(file)==='status.json'?'no-cache':'public, max-age=3600');
    res.end(buf);});}
const server=http.createServer((req,res)=>{
  const u=url.parse(req.url,true);let p=decodeURIComponent(u.pathname||'/');
  if(p==='/healthz'){res.statusCode=200;return res.end('ok');}
  if(p.startsWith('/api/')){
    let b='',size=0,dead=false;
    req.on('data',c=>{size+=c.length;if(size>2e6&&!dead){dead=true;res.statusCode=413;res.end('{"error":"too_big"}');req.destroy();}else b+=c;});
    req.on('end',()=>{if(dead)return;
      req.query=Object.assign({},u.query,{action:p.slice(5)});
      try{req.body=b?JSON.parse(b):{};}catch(e){req.body={};}
      handler(req,res);});
    return;}
  if(p==='/')p='/index.html';
  let file=path.normalize(path.join(PUB,p));
  if(!file.startsWith(PUB)){res.statusCode=403;return res.end('Forbidden');}
  fs.stat(file,(e,st)=>{
    if(!e&&st.isFile())return serveFile(res,file);
    if(!path.extname(file))return serveFile(res,file+'.html');   // cleanUrls: /terms -> terms.html
    serveFile(res,file);});
});
// Daily job (Vercel does this with a cron entry): expiry reminders, once a day around 13:00 UTC.
let lastCron='';
setInterval(async()=>{
  const d=new Date();const day=d.toISOString().slice(0,10);
  if(d.getUTCHours()!==13||lastCron===day||!process.env.CRON_SECRET)return;
  lastCron=day;
  try{await core.cron({method:'GET',headers:{authorization:'Bearer '+process.env.CRON_SECRET},query:{}});console.log('daily job ran',day);}
  catch(e){console.error('daily job failed',e&&e.message);}
},5*60*1000).unref();
const port=process.env.PORT||3000;
if(require.main===module)server.listen(port,()=>console.log('Study Space standby listening on',port));
module.exports=server;
