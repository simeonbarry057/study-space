// Dependency-free email sending. Gmail SMTP (app password) first, Resend (owner only) as fallback.
const tls=require('tls'),net=require('net');
const b64=s=>Buffer.from(s).toString('base64');
const enc=s=>/^[\x20-\x7e]*$/.test(s)?s:'=?UTF-8?B?'+b64(s)+'?=';
function smtpSend(o){
  return new Promise((resolve,reject)=>{
    const host=o.host||'smtp.gmail.com',port=o.port||465;let done=false;
    const sock=o.secure===false?net.connect({host,port}):tls.connect({host,port,servername:host});
    const end=(e,v)=>{if(done)return;done=true;try{sock.destroy();}catch(x){}e?reject(e):resolve(v);};
    sock.setEncoding('utf8');sock.setTimeout(o.timeout||15000,()=>end(new Error('smtp timeout')));sock.on('error',end);
    const body=b64(o.text).replace(/(.{76})/g,'$1\r\n');
    const msg=['From: "'+(o.fromName||'Study Space')+'" <'+o.user+'>','To: <'+o.to+'>','Subject: '+enc(o.subject),'Date: '+new Date().toUTCString(),
      'Message-ID: <'+Date.now()+'.'+Math.random().toString(36).slice(2)+'@studyspace>','MIME-Version: 1.0','Content-Type: text/plain; charset=utf-8','Content-Transfer-Encoding: base64','',body].join('\r\n');
    const script=[[null,'220'],['EHLO studyspace','250'],['AUTH LOGIN','334'],[b64(o.user),'334'],[b64(o.pass),'235'],['MAIL FROM:<'+o.user+'>','250'],['RCPT TO:<'+o.to+'>','250'],['DATA','354'],[msg+'\r\n.','250'],['QUIT','221']];
    let i=0,buf='';
    sock.on('data',d=>{buf+=d;
      for(;;){const m=buf.match(/^(?:\d{3}-[^\n]*\n)*\d{3} [^\n]*\n/);if(!m)break;buf=buf.slice(m[0].length);
        const code=m[0].trim().split('\n').pop().slice(0,3);
        if(code!==script[i][1])return end(new Error('smtp '+code));
        i++;if(i>=script.length)return end(null,true);
        sock.write(script[i][0]+'\r\n');}});
  });
}
async function viaResend(to,subject,text){
  const key=process.env.RESEND_API_KEY;if(!key)return false;
  try{const r=await fetch('https://api.resend.com/emails',{method:'POST',headers:{'Authorization':'Bearer '+key,'Content-Type':'application/json'},
    body:JSON.stringify({from:process.env.MAIL_FROM||'Study Space <onboarding@resend.dev>',to:[to],subject,text})});return r.ok;}catch(e){return false;}
}
// Never throws. Returns true when the message was accepted.
async function sendMail(to,subject,text){
  if(global.__MAIL_SINK){global.__MAIL_SINK.push({to,subject,text});return true;}
  const user=process.env.GMAIL_USER,pass=String(process.env.GMAIL_APP_PASSWORD||'').replace(/\s+/g,'');
  if(user&&pass){
    try{return await smtpSend({user,pass,to,subject,text,host:process.env.SMTP_HOST,port:process.env.SMTP_PORT&&+process.env.SMTP_PORT,secure:process.env.SMTP_SECURE!=='0'});}
    catch(e){console.error('smtp failed',e&&e.message);}
  }
  if(String(to).toLowerCase()===String(process.env.OWNER_EMAIL||'').toLowerCase())return viaResend(to,subject,text);
  return false;
}
module.exports={sendMail,smtpSend};
