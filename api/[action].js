const core=require('../lib/core');
module.exports=async(req,res)=>{
  const a=(req.query&&req.query.action)||'';
  res.setHeader('Cache-Control','no-store');
  if(req.method==='POST'&&req.headers['x-ss']!=='1'){res.statusCode=403;return res.end('{"error":"bad_request"}');}
  let out;
  try{
    if(a==='signup'&&req.method==='POST')out=await core.signup(req);
    else if(a==='login'&&req.method==='POST')out=await core.login(req);
    else if(a==='logout'&&req.method==='POST')out=core.logout(req);
    else if(a==='db'&&req.method==='POST')out=await core.db(req);
    else if(a==='changepw'&&req.method==='POST')out=await core.changepw(req);
    else if(a==='forgot'&&req.method==='POST')out=await core.forgot(req);
    else if(a==='reset'&&req.method==='POST')out=await core.reset(req);
    else if(a==='mycode'&&req.method==='POST')out=await core.mycode(req);
    else if(a==='delete_account'&&req.method==='POST')out=await core.deleteAccount(req);
    else if(a==='verifycode'&&req.method==='POST')out=await core.verifycode(req);
    else if(a==='admin_unlock'&&req.method==='POST')out=await core.adminUnlock(req);
    else if(a==='admin_newcode'&&req.method==='POST')out=await core.adminNewCode(req);
    else if(a==='feedback'&&req.method==='POST')out=await core.feedback(req);
    else if(a==='admin_restore'&&req.method==='POST')out=await core.adminRestore(req);
    else if(a==='restore_boot'&&req.method==='POST')out=await core.restoreBoot(req);
    else if(a==='admin_viewcode'&&req.method==='POST')out=await core.adminViewCode(req);
    else if(a==='cron'&&req.method==='GET')out=await core.cron(req);
    else if(a==='backup'&&req.method==='GET')out=await core.backup(req);
    else if(a==='admin_users'&&req.method==='POST')out=await core.adminUsers(req);
    else if(a==='admin_reset_link'&&req.method==='POST')out=await core.adminResetLink(req);
    else if(a==='admin_otp'&&req.method==='POST')out=await core.adminOtp(req);
    else if(a==='constitution'&&(req.method==='GET'||req.method==='POST'))out=await core.constitution(req);
    else if(a==='content'&&req.method==='GET')out=await core.content(req);
    else if(a==='me'&&req.method==='GET')out=await core.me(req);
    else if(a==='notify'&&req.method==='GET')out=await core.notify(req);
    else out={status:404,body:{error:'not_found'},headers:{}};
  }catch(e){console.error('api error',a,e&&e.message);out={status:500,body:{error:'server_error'},headers:{}};}
  Object.entries(out.headers||{}).forEach(([k,v])=>res.setHeader(k,v));
  res.statusCode=out.status;res.setHeader('Content-Type','application/json');res.end(JSON.stringify(out.body));
};
