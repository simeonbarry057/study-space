#!/usr/bin/env node
// Usage:
//   BLOB_READ_WRITE_TOKEN=... node scripts/restore.js "Study Space backup 2026-11-06 15-09.json" [--all] [--dry]
// Default only adds records that are missing. --all overwrites with the backup's copy. --dry shows what would happen.
const fs=require('fs');
const {store}=require('../lib/store');const {restoreBackup}=require('../lib/restore');
(async()=>{
  const a=process.argv.slice(2),file=a.find(x=>!x.startsWith('--'));
  if(!file){console.error('Give the path to a backup .json file.');process.exit(2);}
  if(!process.env.BLOB_READ_WRITE_TOKEN&&process.env.STORE!=='memory'){console.error('Set BLOB_READ_WRITE_TOKEN (the store to restore into) first.');process.exit(2);}
  let b;try{b=JSON.parse(fs.readFileSync(file,'utf8'));}catch(e){console.error('Could not read that file as JSON:',e.message);process.exit(2);}
  const r=await restoreBackup(store(),b,{mode:a.includes('--all')?'all':'missing',dry:a.includes('--dry')});
  if(!r.ok){console.error('Refused:',r.error);process.exit(1);}
  console.log((r.dry?'DRY RUN. Would restore':'Restored')+' ('+r.mode+' mode) from the backup made '+(r.backupAt||'(unknown time)')+':');
  console.log('  users',r.users,'| sign-in lookups',r.emails,'| docs',r.docs,'| owner',r.owner,'| left as they were',r.skipped);
})().catch(e=>{console.error('Failed:',e.message);process.exit(1);});
