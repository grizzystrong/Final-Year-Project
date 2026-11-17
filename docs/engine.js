/* engine.js -- browser port of src/trust_engine.py + src/policy_engine.py (same four-factor logic). */
const CATALOG={
 smart_camera:{label:"Smart camera",rpm:40,pay:900,crit:.6,mfa:true,exp:"internet"},
 smart_doorbell:{label:"Smart doorbell",rpm:15,pay:600,crit:.7,mfa:true,exp:"internet"},
 smart_thermostat:{label:"Smart thermostat",rpm:4,pay:120,crit:.4,mfa:false,exp:"local"},
 smart_lock:{label:"Smart lock",rpm:2,pay:80,crit:.9,mfa:true,exp:"local"},
 baby_monitor:{label:"Baby monitor",rpm:30,pay:700,crit:.8,mfa:true,exp:"internet"},
 smart_plug:{label:"Smart plug",rpm:1,pay:40,crit:.3,mfa:false,exp:"local"},
 smart_speaker:{label:"Smart speaker",rpm:10,pay:300,crit:.5,mfa:true,exp:"internet"},
 gateway_hub:{label:"Gateway hub",rpm:60,pay:500,crit:1,mfa:true,exp:"internet"},
 smart_tv:{label:"Smart TV",rpm:8,pay:400,crit:.4,mfa:true,exp:"internet"},
 motion_sensor:{label:"Motion sensor",rpm:3,pay:60,crit:.5,mfa:false,exp:"local"}};
const SVC_RISK={telnet:.9,ftp:.6,ftp_data:.4,pop_3:.5,smtp:.35,http:.2,private:.55,other:.5,ecr_i:.6,eco_i:.5,domain_u:.1,auth:.4};
const W={identity:.18,behavior:.47,reputation:.17,context:.18};
const ACTIONS=["ALLOW","STEP_UP_VERIFICATION","RESTRICT","QUARANTINE"];
const clamp=(v,a,b)=>Math.max(a,Math.min(b,v));

function newState(dev){const prior=1-.15*dev.cert_age/365-(dev.mfa?0:.05);
 return {trust:80,identity:prior,reputation:.85,incident_weight:0,in_incident:false,baseline_rpm:null,susp:0,events:0,action:"STEP_UP_VERIFICATION",_prior:prior}}
function priorOf(dev){return 1-.15*dev.cert_age/365-(dev.mfa?0:.05)}

/* one event through the four-factor engine. `net` = {threat} is shared by the whole user fleet. */
function scoreEvent(dev,st,ev,net,hour){
 const base=CATALOG[dev.archetype],prior=priorOf(dev);
 const [ap,an,rr,pr,fl,gu,pv,svi,cat]=ev,svc=(window.ZT_EVENTS.services[svi]||"other");
 const rpm=rr*base.rpm,pay=pr*base.pay;
 // behavior / anomaly
 const aw=.3+.25*net.threat,ml=(.8-aw)*ap+aw*an;
 if(st.baseline_rpm==null)st.baseline_rpm=rpm;
 const dv=Math.min(1,Math.abs(rpm-st.baseline_rpm)/(st.baseline_rpm+5));
 const raw=clamp(ml+.2*dv,0,1),susp=.55*raw+.45*st.susp;st.susp=susp;
 if(ml<.3)st.baseline_rpm=.92*st.baseline_rpm+.08*rpm;
 const behavior=1-susp;
 // identity confidence
 const fp=Math.exp(-Math.abs(Math.log(Math.max(pay,1)/base.pay))/1.5);
 const auth=Math.min(.6,.25*fl+.2*gu+.3*pv);
 st.identity=.7*st.identity+.3*(prior*fp*(1-auth));
 // historical reputation
 st.incident_weight*=.995;st.reputation=.98*st.reputation+.02*behavior;
 const reputation=st.reputation*Math.pow(.88,st.incident_weight);
 // contextual risk (uses the user's real local hour)
 const tr=(hour>=0&&hour<5)?(base.crit>=.7?.5:.25):.05;
 const risk=.35*tr+.3*(SVC_RISK[svc]??.3)+.15*(dev.exposure==="internet"?.3:.1)+.2*net.threat;
 // fusion: weighted geometric mean, behavior weight rises with network threat
 const w={...W};w.behavior+=.1*net.threat;const z=w.identity+w.behavior+w.reputation+w.context;
 const f={identity:st.identity,behavior,reputation,context:1-risk};
 let lg=0;for(const k in f)lg+=w[k]/z*Math.log(Math.max(f[k],.02));
 const target=100*Math.exp(lg);
 const gain=target<st.trust?Math.min(.5*(1+base.crit),1):.09;
 st.trust=clamp(st.trust+gain*(target-st.trust)-1.5*net.threat,0,100);
 if(st.trust<25&&!st.in_incident){st.in_incident=true;st.incident_weight+=1}else if(st.trust>45)st.in_incident=false;
 st.events++;net.threat=.97*net.threat+.03*susp;
 return {trust:st.trust,identity:st.identity,behavior,reputation,context:1-risk,cat};
}
function decide(trust,crit,threat){
 const bump=crit*8+threat*10,allow=Math.min(97,80+bump),step=Math.min(90,55+bump*.6);
 return trust>=allow?"ALLOW":trust>=step?"STEP_UP_VERIFICATION":trust>=25?"RESTRICT":"QUARANTINE"}
