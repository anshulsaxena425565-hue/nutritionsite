const ORIGIN_ALLOWLIST = new Set(["https://prachisayani.online", "https://www.prachisayani.online"]);
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...headers } });
const id = () => crypto.randomUUID();
const hex = (b) => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const hash = async (s) => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
const randomToken = (n = 32) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return [...b].map(x => x.toString(16).padStart(2, "0")).join(""); };
const clean = (v, n = 200) => String(v ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, n);
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 254;
const now = () => new Date().toISOString();
function cors(request) {
  const origin = request.headers.get("Origin") || "";
  const h = { "Vary": "Origin", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Credentials": "true" };
  if (ORIGIN_ALLOWLIST.has(origin)) h["Access-Control-Allow-Origin"] = origin;
  return h;
}
function cookie(name, value, maxAge) { return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`; }
async function body(request) { const len = Number(request.headers.get("Content-Length") || 0); if (len > 16000) throw new Error("too_large"); const text = await request.text(); if (text.length > 16000) throw new Error("too_large"); return JSON.parse(text || "{}"); }
async function sendOtp(env, to, code) {
  if (!env.RESEND_API_KEY || !env.MAIL_FROM) throw new Error("email_not_configured");
  const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" }, body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject: "Your secure sign-in code", text: `Your sign-in code is ${code}. It expires in 10 minutes. If you did not request this, you can ignore this email.`, html: `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px"><h2>Sign in securely</h2><p>Your one-time code is:</p><p style="font-size:32px;font-weight:700;letter-spacing:8px">${code}</p><p>This code expires in 10 minutes. Never share it with anyone.</p></div>` }) });
  if (!r.ok) throw new Error("email_send_failed");
}
async function passwordHash(password, saltHex) {
  const salt = saltHex ? Uint8Array.from(saltHex.match(/.{2}/g).map(x=>parseInt(x,16))) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},key,256);
  return hex(salt)+":"+hex(bits);
}
async function passwordMatches(password, stored) {
  if(!stored || !stored.includes(":")) return false;
  const [salt, expected] = stored.split(":");
  return expected === (await passwordHash(password,salt)).split(":")[1];
}
function validPassword(p){return typeof p==="string" && p.length>=10 && p.length<=128 && /[A-Za-z]/.test(p) && /[0-9]/.test(p);}
function createSessionCookie(raw){return cookie("pn_session",raw,7*24*60*60);}
async function establishSession(env,userId,headers){
  const raw=randomToken(32), expires=new Date(Date.now()+7*24*60*60*1000).toISOString();
  await env.DB.prepare("INSERT INTO auth_sessions(id,user_id,token_hash,expires_at,last_seen_at) VALUES(?,?,?,?,?)").bind(id(),userId,await hash(raw),expires,now()).run();
  return {...headers,"Set-Cookie":createSessionCookie(raw)};
}
async function getSession(request, env) {
  const raw = (request.headers.get("Cookie") || "").split(";").map(s => s.trim()).find(s => s.startsWith("pn_session="))?.slice("pn_session=".length);
  if (!raw) return null;
  const row = await env.DB.prepare("SELECT s.id AS session_id,s.user_id,s.expires_at,u.email,u.display_name,u.status,u.account_type FROM auth_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.status='active'").bind(await hash(raw), now()).first();
  if (!row) return null;
  const admin = await env.DB.prepare("SELECT status FROM platform_admins WHERE user_id=?").bind(row.user_id).first();
  const memberships = await env.DB.prepare("SELECT m.practice_id,m.role,m.status,p.name AS practice_name,p.slug AS practice_slug,p.status AS practice_status FROM practice_memberships m JOIN practices p ON p.id=m.practice_id WHERE m.user_id=? AND m.status='active' AND p.status='active' ORDER BY p.name").bind(row.user_id).all();
  return { ...row, is_platform_admin: admin?.status === "active", memberships: memberships.results || [] };
}
async function audit(env, actor, practiceId, action, resourceType, resourceId = null, metadata = {}) {
  await env.DB.prepare("INSERT INTO audit_logs(id,practice_id,actor_user_id,action,resource_type,resource_id,metadata_json) VALUES(?,?,?,?,?,?,?)").bind(id(), practiceId, actor, action, resourceType, resourceId, JSON.stringify(metadata)).run();
}
export default {
 async fetch(request, env) {
  const headers = cors(request);
  const origin = request.headers.get("Origin");
  if (origin && !ORIGIN_ALLOWLIST.has(origin)) return json({ success:false, message:"Origin not allowed." },403);
  if (request.method === "OPTIONS") return new Response(null,{status:204,headers});
  const url = new URL(request.url), path = url.pathname;
  try {
   if (path === "/health" && request.method === "GET") return json({ok:true,service:"prachi-nutrition-api",database:!!env.DB,authConfigured:!!(env.RESEND_API_KEY && env.MAIL_FROM),bootstrapConfigured:!!env.BOOTSTRAP_SECRET},200,headers);
   if (path === "/api/enquiry" && request.method === "POST") {
    const b = await body(request);
    if (clean(b.website,200)) return json({success:true,message:"Thank you. Your enquiry has been received."},200,headers);
    const name=clean(b.name||b.Name||b.jName,120), email=clean(b.email||b.Email||b.jEmail,254);
    if(!name||!emailOk(email)) return json({success:false,message:"Please enter a valid name and email address."},400,headers);
    const ref=id();
    await env.DB.prepare("INSERT INTO enquiries(id,name,email,phone,service,preferred_contact,goal,preferred_start,message,status,source) VALUES(?,?,?,?,?,?,?,?,?,'new',?)").bind(ref,name,email,clean(b.phone||b.jPhone,40),clean(b.service||b.service_name||b.journeyServiceName,160),clean(b.preferred_contact||b.jFormat,40),clean(b.goal||b.jGoal,1000),clean(b.preferred_start||b.jTimeline,120),clean(b.message||b.jContext,3000),"website").run();
    return json({success:true,message:"Thank you. Your enquiry has been received.",reference:ref},200,headers);
   }
   if (path === "/auth/register" && request.method === "POST") {
    const b=await body(request),name=clean(b.full_name,120),email=clean(b.email,254).toLowerCase(),phone=clean(b.mobile,24).replace(/[\\s()+.-]/g,""),password=b.password,accountType=b.account_type==="dietitian"?"dietitian":"client";
    if(name.length<2||!emailOk(email)||!/^[0-9]{7,15}$/.test(phone)||!validPassword(password))
      return json({success:false,message:"Enter your name, a valid email, mobile number and a password of at least 10 characters containing letters and numbers."},400,headers);
    const existing=await env.DB.prepare("SELECT id FROM app_users WHERE email=? COLLATE NOCASE OR phone=? LIMIT 1").bind(email,phone).first();
    if(existing)return json({success:false,message:"An account already exists for that email or mobile. Sign in instead, or use account recovery."},409,headers);
    const userId=id(),stored=await passwordHash(password);
    await env.DB.prepare("INSERT INTO app_users(id,email,display_name,phone,password_hash,status,account_type) VALUES(?,?,?,?,?,'active',?)").bind(userId,email,name,phone,stored,accountType).run();
    const sessionHeaders=await establishSession(env,userId,headers);
    await audit(env,userId,null,"auth.register","user",userId);
    return json({success:true,message:"Account created.",user:{id:userId,email,display_name:name,account_type:accountType}},201,sessionHeaders);
   }
   if (path === "/auth/login" && request.method === "POST") {
    const b=await body(request),identifier=clean(b.identifier,254).toLowerCase(),password=b.password;
    if(!identifier||typeof password!=="string"||password.length>128)return json({success:false,message:"Enter your email/mobile and password."},400,headers);
    const user=await env.DB.prepare("SELECT id,email,display_name,status,password_hash,account_type FROM app_users WHERE (email=? COLLATE NOCASE OR phone=?) LIMIT 1").bind(identifier,identifier.replace(/[\\s()+.-]/g,"")).first();
    if(!user||user.status!=="active"||!(await passwordMatches(password,user.password_hash)))return json({success:false,message:"Email/mobile or password is incorrect."},401,headers);
    const sessionHeaders=await establishSession(env,user.id,headers);
    return json({success:true,message:"Signed in.",user:{id:user.id,email:user.email,display_name:user.display_name,account_type:user.account_type||"client"}},200,sessionHeaders);
   }
   if (path === "/auth/request-code" && request.method === "POST") {
    const b=await body(request), email=clean(b.email,254).toLowerCase();
    if(!emailOk(email)) return json({success:false,message:"Enter a valid email address."},400,headers);
    const recent=await env.DB.prepare("SELECT created_at FROM auth_challenges WHERE email=? AND purpose='login' ORDER BY created_at DESC LIMIT 1").bind(email).first();
    if(recent && Date.now()-Date.parse(recent.created_at)<60000) return json({success:true,message:"If this email is eligible, a sign-in code will arrive shortly."},200,headers);
    // Do not disclose whether an account exists.
    const user=await env.DB.prepare("SELECT id,status FROM app_users WHERE email=? COLLATE NOCASE").bind(email).first();
    if(user && user.status==="active") {
      if(!env.RESEND_API_KEY||!env.MAIL_FROM) return json({success:false,message:"Secure sign-in email is not configured on the server yet."},503,headers);
      const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%1000000).padStart(6,"0"), challengeId=id(), salt=randomToken(16);
      await env.DB.prepare("INSERT INTO auth_challenges(id,email,purpose,code_hash,attempts,expires_at) VALUES(?,?, 'login', ?,0,?)").bind(challengeId,email,await hash(salt+":"+code),new Date(Date.now()+10*60*1000).toISOString()).run();
      try { await sendOtp(env,email,code); } catch { await env.DB.prepare("DELETE FROM auth_challenges WHERE id=?").bind(challengeId).run(); return json({success:false,message:"Could not send the sign-in email. Please try again later."},503,headers); }
      // Store salt with the hash to avoid storing the code itself.
      await env.DB.prepare("UPDATE auth_challenges SET code_hash=? WHERE id=?").bind(salt+":"+await hash(salt+":"+code),challengeId).run();
    }
    return json({success:true,message:"If this email is eligible, a sign-in code will arrive shortly."},200,headers);
   }
   if (path === "/auth/verify-code" && request.method === "POST") {
    const b=await body(request), email=clean(b.email,254).toLowerCase(), code=clean(b.code,6);
    if(!emailOk(email)||!/^\d{6}$/.test(code)) return json({success:false,message:"Invalid or expired code."},400,headers);
    const challenge=await env.DB.prepare("SELECT * FROM auth_challenges WHERE email=? AND purpose='login' AND consumed_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 1").bind(email,now()).first();
    if(!challenge||challenge.attempts>=5) return json({success:false,message:"Invalid or expired code."},400,headers);
    const [salt,stored]=challenge.code_hash.split(":");
    const valid=stored===await hash(salt+":"+code);
    if(!valid){await env.DB.prepare("UPDATE auth_challenges SET attempts=attempts+1 WHERE id=?").bind(challenge.id).run();return json({success:false,message:"Invalid or expired code."},400,headers);}
    const user=await env.DB.prepare("SELECT id FROM app_users WHERE email=? COLLATE NOCASE AND status='active'").bind(email).first();
    if(!user) return json({success:false,message:"Invalid or expired code."},400,headers);
    await env.DB.prepare("UPDATE auth_challenges SET consumed_at=? WHERE id=? AND consumed_at IS NULL").bind(now(),challenge.id).run();
    const raw=randomToken(32), expires=new Date(Date.now()+7*24*60*60*1000).toISOString();
    await env.DB.prepare("INSERT INTO auth_sessions(id,user_id,token_hash,expires_at,last_seen_at) VALUES(?,?,?,?,?)").bind(id(),user.id,await hash(raw),expires,now()).run();
    return json({success:true,message:"Signed in."},200,{...headers,"Set-Cookie":cookie("pn_session",raw,7*24*60*60)});
   }
   if (path === "/auth/logout" && request.method === "POST") {
    const raw=(request.headers.get("Cookie")||"").split(";").map(s=>s.trim()).find(s=>s.startsWith("pn_session="))?.slice(11);
    if(raw) await env.DB.prepare("UPDATE auth_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL").bind(now(),await hash(raw)).run();
    return json({success:true},200,{...headers,"Set-Cookie":cookie("pn_session","",0)});
   }
   if (path === "/auth/me" && request.method === "GET") {
    const s=await getSession(request,env); if(!s)return json({success:false,message:"Not signed in."},401,headers);
    return json({success:true,user:{id:s.user_id,email:s.email,display_name:s.display_name,account_type:s.account_type||"client",is_platform_admin:s.is_platform_admin,memberships:s.memberships}},200,headers);
   }
   if (path === "/admin/bootstrap" && request.method === "POST") {
    if(!env.BOOTSTRAP_SECRET) return json({success:false,message:"Bootstrap is disabled until a server secret is configured."},503,headers);
    const b=await body(request), supplied=request.headers.get("X-Bootstrap-Secret")||b.bootstrap_secret||"";
    if(supplied.length<32 || supplied!==env.BOOTSTRAP_SECRET) return json({success:false,message:"Not authorized."},403,headers);
    const email=clean(b.email,254).toLowerCase(), displayName=clean(b.display_name,120);
    if(!emailOk(email)||!displayName) return json({success:false,message:"Valid email and display name required."},400,headers);
    const existingAdmin=await env.DB.prepare("SELECT user_id FROM platform_admins LIMIT 1").first();
    if(existingAdmin) return json({success:false,message:"Bootstrap has already been used."},409,headers);
    const user=await env.DB.prepare("SELECT id FROM app_users WHERE email=? COLLATE NOCASE").bind(email).first();
    const uid=user?.id||id();
    if(!user) await env.DB.prepare("INSERT INTO app_users(id,email,display_name,status) VALUES(?,?,?,'active')").bind(uid,email,displayName).run();
    await env.DB.prepare("INSERT INTO platform_admins(user_id,status) VALUES(?,'active')").bind(uid).run();
    await audit(env,uid,null,"platform_admin.bootstrap","user",uid);
    return json({success:true,message:"Super Admin allowlisted. Sign in using email code."},201,headers);
   }
   const session=await getSession(request,env);
   if(path.startsWith("/admin/")) {
    if(!session?.is_platform_admin) return json({success:false,message:"Platform administrator access required."},session?403:401,headers);
    if(path==="/admin/practices"&&request.method==="GET") {
      const rows=await env.DB.prepare("SELECT p.id,p.name,p.slug,p.status,p.timezone,p.currency,p.created_at,u.email AS owner_email FROM practices p LEFT JOIN app_users u ON u.id=p.owner_user_id ORDER BY p.created_at DESC LIMIT 200").all();
      return json({success:true,practices:rows.results||[]},200,headers);
    }
    if(path==="/admin/practices"&&request.method==="POST") {
      const b=await body(request),name=clean(b.name,120),slug=clean(b.slug,70).toLowerCase().replace(/[^a-z0-9-]/g,"-").replace(/-+/g,"-").replace(/^-|-$/g,"");
      if(name.length<2||slug.length<2) return json({success:false,message:"Practice name and valid slug required."},400,headers);
      const pid=id();
      try { await env.DB.prepare("INSERT INTO practices(id,name,slug,status) VALUES(?,?,?,'pending')").bind(pid,name,slug).run(); await env.DB.prepare("INSERT INTO practice_settings(practice_id) VALUES(?)").bind(pid).run(); await audit(env,session.user_id,pid,"practice.created","practice",pid); }
      catch { return json({success:false,message:"Could not create practice; the slug may already be in use."},409,headers); }
      return json({success:true,practice:{id:pid,name,slug,status:"pending"}},201,headers);
    }
    const match=path.match(/^\/admin\/practices\/([a-f0-9-]+)\/status$/);
    if(match&&request.method==="POST") {
      const b=await body(request),status=clean(b.status,20);
      if(!["active","suspended","closed","pending"].includes(status))return json({success:false,message:"Invalid practice status."},400,headers);
      const result=await env.DB.prepare("UPDATE practices SET status=?,updated_at=? WHERE id=?").bind(status,now(),match[1]).run();
      if(!result.meta?.changes)return json({success:false,message:"Practice not found."},404,headers);
      await audit(env,session.user_id,match[1],"practice.status_changed","practice",match[1],{status});
      return json({success:true},200,headers);
    }
   }
   if(path==="/practice/invitations"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),practiceId=clean(b.practice_id,80),email=clean(b.email,254).toLowerCase(),role=clean(b.role,20);
    const membership=session.memberships.find(m=>m.practice_id===practiceId&&["owner","admin"].includes(m.role));
    if(!membership)return json({success:false,message:"Practice owner/admin access required."},403,headers);
    if(!emailOk(email)||!["admin","dietitian","assistant","client"].includes(role))return json({success:false,message:"Valid email and permitted role required."},400,headers);
    const existingInviteUser=await env.DB.prepare("SELECT id FROM app_users WHERE email=? COLLATE NOCASE").bind(email).first();
    if(!existingInviteUser) await env.DB.prepare("INSERT INTO app_users(id,email,display_name,status) VALUES(?,?,?,'active')").bind(id(),email,email.split("@")[0].slice(0,120)).run();
    const token=randomToken(32),inviteId=id(),expires=new Date(Date.now()+7*24*60*60*1000).toISOString();
    await env.DB.prepare("INSERT INTO practice_invitations(id,practice_id,email,role,invited_by_user_id,token_hash,expires_at) VALUES(?,?,?,?,?,?,?)").bind(inviteId,practiceId,email,role,session.user_id,await hash(token),expires).run();
    if(env.RESEND_API_KEY&&env.MAIL_FROM) {
      const acceptUrl="https://prachisayani.online/portal.html#invite="+encodeURIComponent(token);
      try { const r=await fetch("https://api.resend.com/emails",{method:"POST",headers:{Authorization:"Bearer "+env.RESEND_API_KEY,"Content-Type":"application/json"},body:JSON.stringify({from:env.MAIL_FROM,to:[email],subject:"Invitation to a nutrition practice",text:"You have been invited to join "+membership.practice_name+". Open this link to accept: "+acceptUrl,html:"<p>You have been invited to join <strong>"+membership.practice_name+"</strong>.</p><p><a href=\""+acceptUrl+"\">Accept invitation</a></p><p>This link expires in 7 days.</p>"})});if(!r.ok)throw new Error("send"); } catch { return json({success:false,message:"Invitation saved but email delivery failed; configure the Worker email secret before retrying."},503,headers); }
    } else return json({success:false,message:"Invitation saved but email delivery is not configured on the Worker."},503,headers);
    await audit(env,session.user_id,practiceId,"practice.invitation_sent","invitation",inviteId,{email,role});
    return json({success:true,message:"Invitation sent."},201,headers);
   }
   if(path==="/practice/invitations/accept"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),token=clean(b.token,128);
    if(token.length<32)return json({success:false,message:"Invalid or expired invitation."},400,headers);
    const invite=await env.DB.prepare("SELECT * FROM practice_invitations WHERE token_hash=? AND status='pending' AND expires_at>?").bind(await hash(token),now()).first();
    if(!invite||invite.email.toLowerCase()!==session.email.toLowerCase())return json({success:false,message:"Invalid or expired invitation."},400,headers);
    await env.DB.prepare("INSERT INTO practice_memberships(id,practice_id,user_id,role,status) VALUES(?,?,?,?, 'active') ON CONFLICT(practice_id,user_id) DO UPDATE SET role=excluded.role,status='active'").bind(id(),invite.practice_id,session.user_id,invite.role).run();
    if(invite.role==="dietitian") await env.DB.prepare("INSERT OR IGNORE INTO dietitian_profiles(id,practice_id,user_id) VALUES(?,?,?)").bind(id(),invite.practice_id,session.user_id).run();
    if(invite.role==="client") await env.DB.prepare("INSERT OR IGNORE INTO client_profiles(id,practice_id,user_id) VALUES(?,?,?)").bind(id(),invite.practice_id,session.user_id).run();
    await env.DB.prepare("UPDATE practice_invitations SET status='accepted',accepted_at=? WHERE id=?").bind(now(),invite.id).run();
    await audit(env,session.user_id,invite.practice_id,"practice.invitation_accepted","invitation",invite.id);
    return json({success:true,message:"Invitation accepted."},200,headers);
   }
   if(path==="/practice/members"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const practiceId=clean(url.searchParams.get("practice_id"),80);
    const membership=session.memberships.find(m=>m.practice_id===practiceId&&["owner","admin","dietitian"].includes(m.role));
    if(!membership)return json({success:false,message:"Practice membership required."},403,headers);
    const rows=await env.DB.prepare("SELECT u.id,u.email,u.display_name,m.role,m.status,m.created_at FROM practice_memberships m JOIN app_users u ON u.id=m.user_id WHERE m.practice_id=? AND m.status='active' ORDER BY m.created_at DESC LIMIT 200").bind(practiceId).all();
    return json({success:true,members:rows.results||[]},200,headers);
   }
   if(path==="/practices/public"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const rows=await env.DB.prepare("SELECT id,name,slug,timezone,currency FROM practices WHERE status='active' ORDER BY name LIMIT 200").all();
    return json({success:true,practices:rows.results||[]},200,headers);
   }
   if(path==="/dietitians/directory"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const practiceId=clean(url.searchParams.get("practice_id"),80);
    const minExp=Math.max(0,Number(url.searchParams.get("min_experience")||0));
    const maxFee=Math.max(0,Number(url.searchParams.get("max_fee")||0));
    const specialty=clean(url.searchParams.get("specialty"),80).toLowerCase();
    const language=clean(url.searchParams.get("language"),60).toLowerCase();
    const mode=clean(url.searchParams.get("mode"),30).toLowerCase();
    const gender=clean(url.searchParams.get("gender"),30).toLowerCase();
    const order=clean(url.searchParams.get("sort"),20);
    if(!practiceId)return json({success:false,message:"Select an active practice first."},400,headers);
    const practice=await env.DB.prepare("SELECT id FROM practices WHERE id=? AND status='active'").bind(practiceId).first();
    if(!practice)return json({success:false,message:"Active practice not found."},404,headers);
    const rows=await env.DB.prepare("SELECT u.id AS user_id,u.display_name,dp.credentials,dp.registration_number,dp.bio,dp.verification_status,dd.specialties_json,dd.languages_json,dd.consultation_modes_json,dd.gender,dd.fee_minor,dd.experience_years FROM dietitian_profiles dp JOIN app_users u ON u.id=dp.user_id JOIN practice_memberships m ON m.practice_id=dp.practice_id AND m.user_id=dp.user_id AND m.role='dietitian' AND m.status='active' JOIN dietitian_directory dd ON dd.practice_id=dp.practice_id AND dd.user_id=dp.user_id JOIN practices p ON p.id=dp.practice_id WHERE dp.practice_id=? AND p.status='active' AND u.status='active' AND dp.verification_status='verified' AND dd.accepting_clients=1 AND dd.experience_years>=? AND (?=0 OR dd.fee_minor<=?) AND (?='' OR lower(dd.specialties_json) LIKE ?) AND (?='' OR lower(dd.languages_json) LIKE ?) AND (?='' OR lower(dd.consultation_modes_json) LIKE ?) AND (?='' OR lower(coalesce(dd.gender,''))=?)").bind(practiceId,minExp,maxFee,maxFee,specialty,"%"+specialty+"%",language,"%"+language+"%",mode,"%"+mode+"%",gender,gender).all();
    const dietitians=(rows.results||[]).map(d=>({...d,specialties:JSON.parse(d.specialties_json||"[]"),languages:JSON.parse(d.languages_json||"[]"),consultation_modes:JSON.parse(d.consultation_modes_json||"[]")}));
    dietitians.sort((a,b)=>order==="fee_low"?a.fee_minor-b.fee_minor:order==="experience"?b.experience_years-a.experience_years:a.display_name.localeCompare(b.display_name));
    return json({success:true,dietitians},200,headers);
   }
   if(path==="/dietitian/profile"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),practiceId=clean(b.practice_id,80);
    const member=session.memberships.find(m=>m.practice_id===practiceId&&m.role==="dietitian"&&m.status==="active");
    if(!member&&!session.is_platform_admin)return json({success:false,message:"Dietitian membership required."},403,headers);
    const specialties=Array.isArray(b.specialties)?b.specialties.map(x=>clean(x,60)).filter(Boolean).slice(0,12):[];
    const languages=Array.isArray(b.languages)?b.languages.map(x=>clean(x,40)).filter(Boolean).slice(0,12):[];
    const modes=Array.isArray(b.consultation_modes)?b.consultation_modes.map(x=>clean(x,30)).filter(x=>["Online","In-person","Hybrid"].includes(x)).slice(0,3):["Online"];
    const fee=Math.max(0,Math.min(10000000,Math.round(Number(b.fee_rupees||0)*100)));
    const exp=Math.max(0,Math.min(70,Math.round(Number(b.experience_years||0))));
    const gender=clean(b.gender,30),bio=clean(b.bio,1200),credentials=clean(b.credentials,180),reg=clean(b.registration_number,100);
    await env.DB.prepare("INSERT INTO dietitian_profiles(id,practice_id,user_id,credentials,registration_number,bio) VALUES(?,?,?,?,?,?) ON CONFLICT(practice_id,user_id) DO UPDATE SET credentials=excluded.credentials,registration_number=excluded.registration_number,bio=excluded.bio").bind(id(),practiceId,session.user_id,credentials,reg,bio).run();
    await env.DB.prepare("INSERT INTO dietitian_directory(user_id,practice_id,specialties_json,languages_json,consultation_modes_json,gender,fee_minor,experience_years,accepting_clients,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id,practice_id) DO UPDATE SET specialties_json=excluded.specialties_json,languages_json=excluded.languages_json,consultation_modes_json=excluded.consultation_modes_json,gender=excluded.gender,fee_minor=excluded.fee_minor,experience_years=excluded.experience_years,accepting_clients=excluded.accepting_clients,updated_at=excluded.updated_at").bind(session.user_id,practiceId,JSON.stringify(specialties),JSON.stringify(languages),JSON.stringify(modes),gender,fee,exp,b.accepting_clients===false?0:1,now()).run();
    await audit(env,session.user_id,practiceId,"dietitian.profile_updated","dietitian_profile",session.user_id);
    return json({success:true,message:"Profile saved. It will appear in the client directory after Super Admin verification."},200,headers);
   }
   if(path==="/dietitian/requests"&&request.method==="GET") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const rows=await env.DB.prepare("SELECT r.id,r.practice_id,r.client_user_id,r.dietitian_user_id,r.message,r.status,r.created_at,p.name AS practice_name,c.display_name AS client_name,c.email AS client_email,d.display_name AS dietitian_name FROM dietitian_requests r JOIN practices p ON p.id=r.practice_id JOIN app_users c ON c.id=r.client_user_id JOIN app_users d ON d.id=r.dietitian_user_id WHERE r.client_user_id=? OR r.dietitian_user_id=? ORDER BY r.created_at DESC LIMIT 200").bind(session.user_id,session.user_id).all();
    return json({success:true,requests:rows.results||[]},200,headers);
   }
   if(path==="/dietitian/requests"&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),practiceId=clean(b.practice_id,80),dietitianId=clean(b.dietitian_user_id,80),message=clean(b.message,1000);
    const practice=await env.DB.prepare("SELECT id FROM practices WHERE id=? AND status='active'").bind(practiceId).first();
    if(!practice)return json({success:false,message:"Active practice not found."},404,headers);
    const found=await env.DB.prepare("SELECT dp.user_id FROM dietitian_profiles dp JOIN dietitian_directory dd ON dd.user_id=dp.user_id AND dd.practice_id=dp.practice_id JOIN practices p ON p.id=dp.practice_id WHERE dp.practice_id=? AND dp.user_id=? AND dp.verification_status='verified' AND dd.accepting_clients=1 AND p.status='active'").bind(practiceId,dietitianId).first();
    if(!found)return json({success:false,message:"This dietitian is not available for selection."},404,headers);
    await env.DB.prepare("INSERT INTO practice_memberships(id,practice_id,user_id,role,status) VALUES(?,?,?,'client','active') ON CONFLICT(practice_id,user_id) DO NOTHING").bind(id(),practiceId,session.user_id).run();
    await env.DB.prepare("INSERT INTO client_profiles(id,practice_id,user_id) VALUES(?,?,?) ON CONFLICT(practice_id,user_id) DO NOTHING").bind(id(),practiceId,session.user_id).run();
    const requestId=id();
    await env.DB.prepare("INSERT INTO dietitian_requests(id,practice_id,client_user_id,dietitian_user_id,message) VALUES(?,?,?,?,?) ON CONFLICT(client_user_id,practice_id,dietitian_user_id) DO UPDATE SET message=excluded.message,status='pending',updated_at=?").bind(requestId,practiceId,session.user_id,dietitianId,message,now()).run();
    await audit(env,session.user_id,practiceId,"dietitian.requested","dietitian_request",requestId);
    return json({success:true,message:"Request sent to the dietitian."},201,headers);
   }
   const requestMatch=path.match(/^\/dietitian\/requests\/([a-f0-9-]+)\/decision$/);
   if(requestMatch&&request.method==="POST") {
    if(!session)return json({success:false,message:"Sign in required."},401,headers);
    const b=await body(request),status=clean(b.status,20);
    if(!["accepted","declined"].includes(status))return json({success:false,message:"Invalid decision."},400,headers);
    const req=await env.DB.prepare("SELECT * FROM dietitian_requests WHERE id=?").bind(requestMatch[1]).first();
    if(!req||req.dietitian_user_id!==session.user_id)return json({success:false,message:"Request not found."},404,headers);
    const membership=session.memberships.find(m=>m.practice_id===req.practice_id&&m.role==="dietitian"&&m.status==="active");
    if(!membership&&!session.is_platform_admin)return json({success:false,message:"Dietitian access required."},403,headers);
    await env.DB.prepare("UPDATE dietitian_requests SET status=?,updated_at=? WHERE id=?").bind(status,now(),req.id).run();
    if(status==="accepted"){
      await env.DB.prepare("INSERT INTO client_profiles(id,practice_id,user_id,assigned_dietitian_user_id) VALUES(?,?,?,?) ON CONFLICT(practice_id,user_id) DO UPDATE SET assigned_dietitian_user_id=excluded.assigned_dietitian_user_id").bind(id(),req.practice_id,req.client_user_id,session.user_id).run();
      await env.DB.prepare("INSERT INTO conversations(id,practice_id,client_user_id,dietitian_user_id,status) VALUES(?,?,?,?,'open')").bind(id(),req.practice_id,req.client_user_id,session.user_id).run();
    }
    await audit(env,session.user_id,req.practice_id,"dietitian.request_"+status,"dietitian_request",req.id);
    return json({success:true,message:"Request "+status+"."},200,headers);
   }
   if(path==="/admin/dietitians"&&request.method==="GET") {
    if(!session?.is_platform_admin)return json({success:false,message:"Platform administrator access required."},session?403:401,headers);
    const rows=await env.DB.prepare("SELECT dp.user_id,dp.practice_id,dp.credentials,dp.registration_number,dp.bio,dp.verification_status,u.display_name,u.email,p.name AS practice_name,dd.specialties_json,dd.languages_json,dd.consultation_modes_json,dd.fee_minor,dd.experience_years,dd.accepting_clients FROM dietitian_profiles dp JOIN app_users u ON u.id=dp.user_id JOIN practices p ON p.id=dp.practice_id LEFT JOIN dietitian_directory dd ON dd.user_id=dp.user_id AND dd.practice_id=dp.practice_id ORDER BY dp.created_at DESC LIMIT 300").all();
    return json({success:true,dietitians:rows.results||[]},200,headers);
   }
   const verifyMatch=path.match(/^\/admin\/dietitians\/([a-f0-9-]+)\/verification$/);
   if(verifyMatch&&request.method==="POST") {
    if(!session?.is_platform_admin)return json({success:false,message:"Platform administrator access required."},session?403:401,headers);
    const b=await body(request),status=clean(b.status,20),practiceId=clean(b.practice_id,80);
    if(!["verified","rejected","pending","expired"].includes(status))return json({success:false,message:"Invalid verification status."},400,headers);
    await env.DB.prepare("UPDATE dietitian_profiles SET verification_status=? WHERE user_id=? AND practice_id=?").bind(status,verifyMatch[1],practiceId).run();
    await audit(env,session.user_id,practiceId,"dietitian.verification_changed","dietitian_profile",verifyMatch[1],{status});
    return json({success:true},200,headers);
   }
   return json({success:false,message:"Not found."},404,headers);
  } catch (e) {
   console.error("API request failed", { path, message: String(e?.message || e), stack: String(e?.stack || "").slice(0,1200) });
   if(e?.message==="too_large") return json({success:false,message:"Request too large."},413,headers);
   if(e instanceof SyntaxError) return json({success:false,message:"Invalid JSON."},400,headers);
   return json({success:false,message:"The service encountered an error. Please try again later."},500,headers);
  }
 }
};
