import WebSocket from 'ws';
const id=process.env.TAB;
const ws=new WebSocket(`ws://127.0.0.1:9222/devtools/page/${id}`,{perMessageDeflate:false});
const expr=`(async()=>{const r=await fetch('https://account.venmo.com/api/stories?feedType=me',{credentials:'include',headers:{'accept':'application/json'}});const t=await r.text();if(!t) return JSON.stringify({status:r.status,empty:true});try{const d=JSON.parse(t);const s=d.stories&&d.stories[0];return JSON.stringify({status:r.status,senderId:s&&s.title&&s.title.sender&&s.title.sender.id,senderName:s&&s.title&&s.title.sender&&s.title.sender.username,amount:s&&s.amount,date:s&&s.date,receiver:s&&s.title&&s.title.receiver&&s.title.receiver.username});}catch(e){return JSON.stringify({status:r.status,head:t.slice(0,150)});}})()`;
ws.on('open',()=>ws.send(JSON.stringify({id:1,method:'Runtime.evaluate',params:{expression:expr,returnByValue:true,awaitPromise:true}})));
ws.on('message',m=>{const d=JSON.parse(m);if(d.id===1){console.log(d.result?.result?.value||JSON.stringify(d.result));ws.close();process.exit(0)}});
setTimeout(()=>{console.log('timeout');process.exit(1)},20000);
