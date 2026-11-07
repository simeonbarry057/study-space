#!/usr/bin/env node
// Use this when you move BACK to Vercel after running on the standby.
// During a failover only Upstash receives changes, so the Vercel stores are out of date.
// This copies everything from Upstash (the source of truth) into the Vercel stores, and removes
// records that were deleted in the meantime.
//
//   UPSTASH_REDIS_REST_URL=... UPSTASH_REDIS_REST_TOKEN=... \
//   BLOB_READ_WRITE_TOKEN=... BLOB_MIRROR_READ_WRITE_TOKEN=... \
//   node scripts/resync.js          (shows what would change; nothing is written)
//   node scripts/resync.js --go     (applies it)
const {upstash,blob,HIDE}=require('../lib/store');
(async()=>{
  const go=process.argv.includes('--go');
  const uu=process.env.UPSTASH_REDIS_REST_URL,ut=process.env.UPSTASH_REDIS_REST_TOKEN;
  if(!uu||!ut){console.error('Set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN.');process.exit(2);}
  const src=upstash(uu,ut);
  const targets=[];
  if(process.env.BLOB_READ_WRITE_TOKEN)targets.push(['main store',blob(process.env.BLOB_READ_WRITE_TOKEN)]);
  if(process.env.BLOB_MIRROR_READ_WRITE_TOKEN)targets.push(['mirror store',blob(process.env.BLOB_MIRROR_READ_WRITE_TOKEN)]);
  if(!targets.length){console.error('Set BLOB_READ_WRITE_TOKEN and/or BLOB_MIRROR_READ_WRITE_TOKEN.');process.exit(2);}
  const keys=(await src.list('')).filter(k=>!HIDE.test(k));
  console.log('Upstash holds',keys.length,'records.');
  for(const [name,t] of targets){
    const have=await t.list('');const data=have.filter(k=>!HIDE.test(k));
    let put=0,same=0,del=0;
    for(const k of keys){
      const v=await src.get(k);if(v==null)continue;
      const cur=await t.get(k);
      if(cur&&JSON.stringify(cur)===JSON.stringify(v)){same++;continue;}
      put++;if(go)await t.put(k,v);
    }
    for(const k of data){if(!keys.includes(k)){del++;if(go)await t.del(k);}}
    if(go)for(const k of have.filter(k=>/^sync\d*\//.test(k)))await t.del(k);   // clear old repair markers
    console.log(name+':',put,'to write,',same,'already identical,',del,'to remove'+(go?' (done)':' (dry run, add --go to apply)'));
  }
})().catch(e=>{console.error('Failed:',e.message);process.exit(1);});
