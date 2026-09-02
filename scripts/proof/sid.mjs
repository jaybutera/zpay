import WebSocket from 'ws';
const id=process.env.TAB;
const ws=new WebSocket(`ws://127.0.0.1:9222/devtools/page/${id}`,{perMessageDeflate:false});
const expr=`(async()=>{const r=await fetch('/api/stories?feedType=me',{credentials:'include'});const d=await r.json();const s=d.stories&&d.stories[0];return JSON.stringify({senderId:s&&s.title&&s.title.sender&&s.title.sender.id, senderName:s&&s.title&&s.title.sender&&s.title.sender.username, top:s&&{amount:s.amount,date:s.date,receiver:s.title&&s.title.receiver&&s.title.receiver.username}});})()`;
ws.on('open',()=>ws.send(JSON.stringify({id:1,method:'Runtime.evaluate',params:{expression:expr,returnByValue:true,awaitPromise:true}})));
ws.on('message',m=>{const d=JSON.parse(m);if(d.id===1){console.log(JSON.stringify(d.result));ws.close();process.exit(0)}});
setTimeout(()=>{console.log('timeout');process.exit(1)},20000);
