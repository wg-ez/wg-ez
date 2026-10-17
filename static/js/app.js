"use strict";
const D=document,$=(s,r)=>(r||D).querySelector(s),A=(s,r)=>[...(r||D).querySelectorAll(s)],L=addEventListener;
function T(m){const t=E("div","toast",m);let h=$("#toasts");if(MD.open){h=$(".toasts--modal",MD);if(!h){h=E("div","toasts toasts--modal");MD.append(h)}}h.append(t);setTimeout(()=>t.remove(),4e3)}
const MD=$("#modal"),MT=$(".modal__t",MD),MB=$(".modal__body",MD),OTL={},MNS=A(".menu");
const E=(t,c,...k)=>{const n=D.createElement(t);return n.className=c,n.append(...k),n};
function O(t,n){MT.textContent=t;MB.replaceChildren(n);if(!MD.open)MD.showModal();$(".field",MB)?.focus()}
MD.onclose=()=>{MB.replaceChildren();$(".toasts--modal",MD)?.remove()};
L("click",e=>MNS.forEach(m=>{if(m.open&&!m.contains(e.target))m.open=false}));
L("keydown",e=>{if(e.key==="Escape")MNS.forEach(m=>m.open=false)});
L("click",e=>{const b=e.target.closest("[data-do]");if(b){const t=b.textContent.trim(),d=b.dataset;
 if(d.do==="new"){const f=E("form","modal__f");f.id="mf";const i=E("input","field");i.name="name";i.maxLength=64;i.required=1;f.append(E("label","flabel",E("span","hud",d.n),i),E("button","btn",t));O(t,f)}
 else if(d.do==="qr"){const m=E("img","qr qr--modal");m.src=`/api/client/${d.id}/qrcode.svg`;m.alt=t;O(t,m)}
 else if(d.do==="close")MD.close()}
 else if(e.target===MD||e.target.closest(".modal__x"))MD.close()});
/* hx-confirm -> modale */
L("htmx:confirm",e=>{const d=e.detail;if(!d.question)return;e.preventDefault();const t=d.elt.textContent.trim(),k=E("div","modal__f"),c=E("button","btn btn--ghost",MD.dataset.cancel),b=E("button","btn btn--danger",t);c.type="button";c.dataset.do="close";b.type="button";b.id="mk";k.append(E("p","muted",d.question),c,b);O(t,k);$("#mk",MD).onclick=()=>{MD.close();d.issueRequest(true)}});
L("submit",async e=>{if(e.target.id!=="mf")return;e.preventDefault();const n=e.target.name.value.trim();if(!n)return;try{await(await fetch("/api/client",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:n})})).json();MD.close();location.href="/"}catch(x){T(x.message)}});
L("htmx:afterRequest",async e=>{let t;try{t=JSON.parse(e.detail.xhr.getResponseHeader("HX-Trigger"))}catch(x){}if(!t)return;if(t.toast)T(t.toast);
 if(t.hooks){const h=await(await fetch("/api/admin/hooks")).json();["preUp","postUp","preDown","postDown"].forEach(k=>{const q=$(`[name="${k}"]`);if(q)q.value=h[k]})}
 if(t.otl){try{await navigator.clipboard.writeText(location.origin+"/cnf/"+t.otl)}catch{}
 OTL[e.detail.elt.dataset.id]=Date.parse(t.exp)}
 /* jeton d'API -> modale : le clair n'est affiche qu'une fois (titre +
    etiquette + consigne + libelles du bouton Copier lus en data-t-* sur
    #token-form, donc traduits, zero texte en dur ici) ; la valeur vit en
    `dd.secret` (mono selectionnable, comme le secret TOTP de `totp_box`) et
    le bouton `.btn` copie (presse-papiers + repli `execCommand` en HTTP
    clair) avec toast `T()` ; la liste se rafraichit via refreshMe */
 if(t.showToken){const f=$("#token-form"),d=(f&&f.dataset)||{},b=E("div","modal__f"),r=E("div",""),v=E("dd","secret num",t.showToken);r.append(E("dt","",d.tToken||"token"),v);const c=E("button","btn",d.tCopy||"copy");c.type="button";c.onclick=async()=>{try{await navigator.clipboard.writeText(t.showToken)}catch(x){const a=E("textarea","","");a.value=t.showToken;D.body.append(a);a.select();try{D.execCommand("copy")}catch(y){}a.remove()}T(d.tCopied||"copied")};b.append(E("dl","kv",r),c,E("p","note",d.tWarning||""));O(d.tTitle||"",b)}});
L("htmx:responseError",e=>{let m="error";try{m=JSON.parse(e.detail.xhr.responseText).error||m}catch{}T(m)});
let DN=0;L("mousedown",()=>DN=1);L("mouseup",()=>DN=0);L("blur",()=>DN=0);
/* #grid : geler seulement pendant un clic actif, pas au survol. */
L("htmx:configRequest",e=>{const d=e.detail,g=d.elt;if(g.id=="grid"&&DN&&d.triggeringEvent?.type!="refreshGrid")e.preventDefault()});
const K=()=>{const t=Date.now();A("[data-otl]").forEach(b=>{const x=OTL[b.dataset.id];if(x>t){b.textContent=Math.ceil((x-t)/1e3)+"s";return}b.textContent=b.dataset.label;delete OTL[b.dataset.id]})};
setInterval(K,1e3);L("htmx:afterSwap",K);
