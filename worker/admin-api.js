// PickMarket Cloudflare Worker: deploy separately; never publish secrets.
const BASE = 'https://pickmarket-admin-api.leesn204.workers.dev';
const SITE = 'https://leesn204.github.io';
const REPO = 'leesn204/pickmarket';
const enc = new TextEncoder();
const b64 = b => btoa(String.fromCharCode(...b)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64 = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)), c=>c.charCodeAt(0));
const cookie = (n,v,age)=>`${n}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
const getCookie = (r,n)=>(r.headers.get('Cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(n+'='))?.slice(n.length+1);
async function key(env){const raw=Uint8Array.from(atob(env.SESSION_SECRET),c=>c.charCodeAt(0));if(raw.length<32)throw Error('Invalid session key');return crypto.subtle.importKey('raw',raw,{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);}
async function seal(v,env){const p=b64(enc.encode(JSON.stringify(v)));return p+'.'+b64(new Uint8Array(await crypto.subtle.sign('HMAC',await key(env),enc.encode(p))));}
async function unseal(v,env){try{if(!v||v.length>4096)return null;const p=v.split('.');if(p.length!==2||!await crypto.subtle.verify('HMAC',await key(env),unb64(p[1]),enc.encode(p[0])))return null;return JSON.parse(new TextDecoder().decode(unb64(p[0])));}catch{return null;}}
function json(v,status=200,extra={}){return new Response(JSON.stringify(v),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...extra}});}
function redirect(u,c=[]){const h=new Headers({Location:u,'Cache-Control':'no-store','Referrer-Policy':'no-referrer'});c.forEach(x=>h.append('Set-Cookie',x));return new Response(null,{status:302,headers:h});}
const cors={'Access-Control-Allow-Origin':SITE,'Access-Control-Allow-Credentials':'true','Vary':'Origin'};
async function github(path,env,init={}){return fetch('https://api.github.com/repos/'+REPO+'/contents/'+path,{...init,headers:{'Authorization':'Bearer '+env.GITHUB_TOKEN,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'PickMarket-Admin',...(init.headers||{})}});}
function validate(data){if(!data||!Array.isArray(data.products)||data.products.length>1000||typeof data.contact!=='string'||data.contact.length>500)return false;const ids=new Set();for(const p of data.products){if(!p||!Number.isSafeInteger(p.id)||p.id<1||ids.has(p.id)||typeof p.name!=='string'||!p.name.trim()||p.name.length>120||!Number.isFinite(p.price)||p.price<0)return false;ids.add(p.id);for(const k of ['category','middle','sub','tags','image','video','link','description'])if(p[k]!==undefined&&(typeof p[k]!=='string'||p[k].length>2000))return false;for(const k of ['image','video','link'])if(p[k]&&!(p[k].startsWith('https://')||(k!=='link'&&/^\.\/images\/[a-zA-Z0-9_.-]+$/.test(p[k]))))return false;}return true;}
export default {async fetch(request,env){
try{
const url=new URL(request.url);if(url.origin!==BASE)return json({error:'Invalid host'},400);
if(!env.GITHUB_CLIENT_ID||!env.GITHUB_CLIENT_SECRET||!env.ADMIN_GITHUB_ID||!env.SESSION_SECRET)return json({error:'Server configuration incomplete'},503);
if(url.pathname==='/health'&&request.method==='GET')return json({ok:true,service:'pickmarket-admin-api'});
if(url.pathname==='/auth/login'&&request.method==='GET'){const state=b64(crypto.getRandomValues(new Uint8Array(32)));const flow=await seal({state,exp:Date.now()+600000},env);const auth=new URL('https://github.com/login/oauth/authorize');auth.searchParams.set('client_id',env.GITHUB_CLIENT_ID);auth.searchParams.set('redirect_uri',BASE+'/auth/callback');auth.searchParams.set('state',state);return redirect(auth.toString(),[cookie('pm_oauth',flow,600)]);}
if(url.pathname==='/auth/callback'&&request.method==='GET'){const flow=await unseal(getCookie(request,'pm_oauth'),env);if(!flow||flow.exp<=Date.now()||flow.state!==url.searchParams.get('state')||!url.searchParams.get('code'))return redirect(BASE+'/?error=invalid_oauth',[cookie('pm_oauth','',0)]);const tr=await fetch('https://github.com/login/oauth/access_token',{method:'POST',headers:{Accept:'application/json','Content-Type':'application/json','User-Agent':'PickMarket-Admin'},body:JSON.stringify({client_id:env.GITHUB_CLIENT_ID,client_secret:env.GITHUB_CLIENT_SECRET,code:url.searchParams.get('code'),redirect_uri:BASE+'/auth/callback'})});if(!tr.ok)return redirect(BASE+'/?error=oauth_exchange');const td=await tr.json();if(!td.access_token)return redirect(BASE+'/?error=oauth_exchange');const ur=await fetch('https://api.github.com/user',{headers:{Authorization:'Bearer '+td.access_token,Accept:'application/vnd.github+json','User-Agent':'PickMarket-Admin'}});if(!ur.ok)return redirect(BASE+'/?error=github_user');const user=await ur.json();if(String(user.id)!==String(env.ADMIN_GITHUB_ID))return redirect(BASE+'/?error=not_admin',[cookie('pm_session','',0)]);const session=await seal({uid:String(user.id),login:user.login,exp:Date.now()+28800000},env);return redirect(BASE+'/',[cookie('pm_oauth','',0),cookie('pm_session',session,28800)]);}
const session=await unseal(getCookie(request,'pm_session'),env);const ok=!!session&&session.exp>Date.now()&&String(session.uid)===String(env.ADMIN_GITHUB_ID);
if(url.pathname==='/auth/me'&&request.method==='GET')return json(ok?{authenticated:true,login:session.login}:{authenticated:false},ok?200:401,{...cors});
if(url.pathname==='/auth/logout'&&request.method==='POST'){if(request.headers.get('Origin')!==BASE)return json({error:'Invalid origin'},403);return json({ok:true},200,{'Set-Cookie':cookie('pm_session','',0)});}
if(url.pathname==='/api/products'&&request.method==='OPTIONS'){if(request.headers.get('Origin')!==SITE)return json({error:'Invalid origin'},403);return new Response(null,{status:204,headers:{...cors,'Access-Control-Allow-Methods':'GET, PUT, OPTIONS','Access-Control-Allow-Headers':'Content-Type'}});}
if(url.pathname==='/api/products'&&(request.method==='GET'||request.method==='PUT')){
if(request.headers.get('Origin')!==SITE)return json({error:'Invalid origin'},403);
if(!ok)return json({error:'Unauthorized'},401,cors);
if(!env.GITHUB_TOKEN)return json({error:'GITHUB_TOKEN missing'},503,cors);
if(request.method==='GET'){const r=await github('products.json',env);if(!r.ok)return json({error:'GitHub read failed'},502,cors);const f=await r.json();return json({data:JSON.parse(new TextDecoder().decode(unb64(f.content.replace(/\s/g,'').replace(/\+/g,'-').replace(/\//g,'_')))),sha:f.sha},200,cors);}
if(request.headers.get('Content-Type')?.split(';')[0]!=='application/json')return json({error:'JSON required'},415,cors);
const raw=await request.text();if(raw.length>500000)return json({error:'Payload too large'},413,cors);let body;try{body=JSON.parse(raw);}catch{return json({error:'Invalid JSON'},400,cors);}
if(!validate(body.data)||!body.sha||typeof body.sha!=='string')return json({error:'Invalid data or SHA'},400,cors);
const content=btoa(unescape(encodeURIComponent(JSON.stringify(body.data,null,2)+'\n')));
const r=await github('products.json',env,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:'Update PickMarket products from authenticated admin',content,sha:body.sha,branch:'main'})});
if(!r.ok)return json({error:r.status===409?'Conflict: reload products':'GitHub write failed',status:r.status},r.status===409?409:502,cors);
const out=await r.json();return json({ok:true,sha:out.content?.sha},200,cors);
}
if(url.pathname==='/'&&request.method==='GET')return new Response('<!doctype html><html lang="ko"><meta charset="utf-8"><title>픽마켓 관리자 인증</title><body style="font:16px system-ui;margin:8vh auto;max-width:500px"><h1>픽마켓 관리자 인증</h1><p id="status">확인 중...</p><a href="/auth/login">GitHub로 로그인</a><p><a href="https://leesn204.github.io/pickmarket/admin.html">상품 관리 화면으로 이동</a></p><button id="logout">로그아웃</button><script>fetch("/auth/me").then(r=>r.json()).then(x=>document.getElementById("status").textContent=x.authenticated?"관리자 인증 완료: "+x.login:"로그인이 필요합니다.");document.getElementById("logout").onclick=async()=>{await fetch("/auth/logout",{method:"POST"});location.reload()}</script></body></html>',{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"}});
return json({error:'Not found'},404);
}catch(e){console.error('Worker error',e.message);return json({error:'Internal server error'},500);}
}};