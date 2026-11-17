/* api.js -- one data-layer interface, two backends:
   - Supabase (Google login + Postgres with row-level security) when config.js has real keys
   - Demo mode (localStorage, two fake users) otherwise, so the site works before setup. */
const CFG=window.ZT_CONFIG||{};
const LIVE=!!(CFG.SUPABASE_URL&&CFG.SUPABASE_ANON_KEY&&!/YOUR_/.test(CFG.SUPABASE_URL));
const DEMO_USERS={demo1:{id:"demo1",name:"Demo User 1",email:"user1@demo.local",zone:11},demo2:{id:"demo2",name:"Demo User 2",email:"user2@demo.local",zone:12}};
const uid=()=>"d"+Math.random().toString(36).slice(2,10);

function demoApi(){
 const KEY="zt_demo_db_v1",load=()=>JSON.parse(localStorage.getItem(KEY)||'{"devices":[],"state":{},"history":[],"threat":{}}'),save=d=>localStorage.setItem(KEY,JSON.stringify(d));
 let me=null;const cur=sessionStorage.getItem("zt_demo_user");if(cur)me=DEMO_USERS[cur];
 return {mode:"demo",
  async user(){return me},
  async signIn(id){sessionStorage.setItem("zt_demo_user",id);location.reload()},
  async signOut(){sessionStorage.removeItem("zt_demo_user");location.reload()},
  async devices(){return load().devices.filter(d=>d.user_id===me.id).sort((a,b)=>a.slot-b.slot)},
  async addDevices(list){const db=load(),mine=db.devices.filter(d=>d.user_id===me.id);let slot=Math.max(0,...mine.map(d=>d.slot));
   const rows=list.map(x=>({...x,id:uid(),user_id:me.id,slot:++slot}));db.devices.push(...rows);save(db);return rows},
  async removeDevice(id){const db=load();db.devices=db.devices.filter(d=>d.id!==id);delete db.state[id];db.history=db.history.filter(h=>h.device_id!==id);save(db)},
  async states(){const db=load(),o={};db.devices.filter(d=>d.user_id===me.id).forEach(d=>{if(db.state[d.id])o[d.id]=db.state[d.id]});return o},
  async saveStates(rows){const db=load();rows.forEach(r=>db.state[r.device_id]=r);save(db)},
  async threat(){return load().threat[me.id]||0},
  async saveThreat(v){const db=load();db.threat[me.id]=v;save(db)},
  async addHistory(rows){const db=load();db.history.push(...rows.map(r=>({...r,user_id:me.id})));db.history=db.history.slice(-4000);save(db)},
  async history(id,n=300){return load().history.filter(h=>h.device_id===id&&h.user_id===me.id).slice(-n)}}}

function supaApi(){
 const sb=window.supabase.createClient(CFG.SUPABASE_URL,CFG.SUPABASE_ANON_KEY);let me=null;
 const ok=r=>{if(r.error)throw r.error;return r.data};
 return {mode:"supabase",
  async user(){const {data:{session}}=await sb.auth.getSession();if(!session)return null;
   const u=session.user,m=u.user_metadata||{};let p=ok(await sb.from("profiles").select("zone").eq("id",u.id).maybeSingle());
   if(!p){p=ok(await sb.from("profiles").insert({id:u.id,email:u.email,name:m.full_name||m.name||u.email,avatar:m.avatar_url||null}).select("zone").single())}
   me={id:u.id,name:m.full_name||m.name||u.email,email:u.email,avatar:m.avatar_url,zone:p.zone};return me},
  async signIn(){ok(await sb.auth.signInWithOAuth({provider:"google",options:{redirectTo:location.origin+location.pathname}}))},
  async signOut(){await sb.auth.signOut();location.reload()},
  async devices(){return ok(await sb.from("devices").select("*").order("slot"))},
  async addDevices(list){const cur=ok(await sb.from("devices").select("slot")),slot0=Math.max(0,...cur.map(d=>d.slot));
   return ok(await sb.from("devices").insert(list.map((x,i)=>({...x,slot:slot0+i+1}))).select())},
  async removeDevice(id){ok(await sb.from("devices").delete().eq("id",id))},
  async states(){const o={};ok(await sb.from("device_state").select("*")).forEach(r=>o[r.device_id]=r);return o},
  async saveStates(rows){if(rows.length)ok(await sb.from("device_state").upsert(rows.map(r=>({...r,updated_at:new Date().toISOString()}))))},
  async threat(){const p=ok(await sb.from("profiles").select("threat").eq("id",me.id).single());return p.threat||0},
  async saveThreat(v){ok(await sb.from("profiles").update({threat:v}).eq("id",me.id))},
  async addHistory(rows){if(rows.length)ok(await sb.from("trust_history").insert(rows))},
  async history(id,n=300){return ok(await sb.from("trust_history").select("*").eq("device_id",id).order("ts",{ascending:false}).limit(n)).reverse()}}}
window.API=LIVE?supaApi():demoApi();
