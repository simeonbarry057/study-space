// Restore a backup (the JSON made by /api/backup) into a store.
// mode 'missing' (default): only add records that do not exist yet. mode 'all': overwrite records with the backup's copy.
// Nothing is ever deleted. The email lookup and owner pointer are rebuilt from the users.
const crypto=require('crypto');
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const UKEY=/^users\/(u_[a-f0-9]+)\.json$/;
const DKEY=/^docs\/(?!.*\.\.)[A-Za-z0-9_\-\/.]{1,200}\.json$/;
const EMAIL=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function check(b){
  if(!b||typeof b!=='object'||Array.isArray(b))return 'This is not a backup file.';
  if(!b.users||typeof b.users!=='object'||!b.docs||typeof b.docs!=='object')return 'This backup has no users or docs section.';
  const n=Object.keys(b.users).length;if(!n)return 'This backup has no users.';
  for(const [k,u] of Object.entries(b.users)){const m=UKEY.exec(k);if(!m)return 'Unexpected user key: '+String(k).slice(0,60);
    if(!u||u.id!==m[1]||!u.email||!EMAIL.test(String(u.email))||!u.hash||!u.salt)return 'User record is incomplete: '+k;}
  for(const k of Object.keys(b.docs))if(!DKEY.test(k))return 'Unexpected docs key: '+String(k).slice(0,60);
  if(b.owner&&(!b.owner.id||!b.users['users/'+b.owner.id+'.json']))return 'The owner in this backup has no matching user.';
  return null;
}
async function restoreBackup(store,b,opts){
  const mode=opts&&opts.mode==='all'?'all':'missing',dry=!!(opts&&opts.dry);
  const err=check(b);if(err)return {ok:false,error:err};
  const out={ok:true,mode,dry,users:0,docs:0,emails:0,owner:0,skipped:0,backupAt:b.at||null};
  async function put(k,v,kind){
    if(mode==='missing'&&await store.get(k)){out.skipped++;return;}
    if(!dry)await store.put(k,v);out[kind]++;}
  for(const [k,u] of Object.entries(b.users)){
    await put(k,u,'users');
    const ek='emails/'+sha(String(u.email).toLowerCase())+'.json';
    await put(ek,{id:u.id},'emails');}
  for(const [k,d] of Object.entries(b.docs))await put(k,d,'docs');
  if(b.owner)await put('owner.json',{id:b.owner.id},'owner');
  return out;
}
module.exports={restoreBackup,check};
