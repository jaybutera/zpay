/* Check frontend/app/qr.js against a real decoder.
 *
 * The encoder is hand-written, so "it looks like a QR code" is not evidence.
 * This renders each matrix and reads it back with jsQR, and separately
 * compares it module-for-module with the `qrcode` library's own output.
 *
 *   npm install jsqr qrcode && node frontend/app/test/qr-verify.js
 *
 * Two bugs it caught, both invisible to the eye: the fifteen format bits were
 * written least-significant first when the spec writes them most-significant
 * first, and the second copy of them overwrote the fixed dark module. Either
 * one leaves a symbol that scans as nothing while still looking correct.
 *
 * A note on the harness itself: rendering one pixel per module makes every
 * symbol undecodable regardless of whether it is right. The scale below is
 * what makes a failure here mean something.
 */
const fs=require('fs'), jsQR=require('jsqr'), QRCode=require('qrcode');
const src=fs.readFileSync(require('path').join(__dirname,'..','qr.js'),'utf8');
const ctx={TextEncoder}; new Function('globalThis',src+'\nglobalThis.__QR=QR;').call(ctx,ctx);
const QR=ctx.__QR;

// Scale up: jsQR needs more than one pixel per module to lock on.
function decode(m, scale=6){
  const n=m.length, quiet=4, total=(n+quiet*2)*scale;
  const d=new Uint8ClampedArray(total*total*4).fill(255);
  for(let r=0;r<n;r++)for(let c=0;c<n;c++){
    if(!m[r][c]) continue;
    for(let dy=0;dy<scale;dy++)for(let dx=0;dx<scale;dx++){
      const y=(r+quiet)*scale+dy, x=(c+quiet)*scale+dx, i=(y*total+x)*4;
      d[i]=d[i+1]=d[i+2]=0;
    }
  }
  const res=jsQR(d,total,total); return res?res.data:null;
}
const refMatrix=(t)=>{const q=QRCode.create(t,{errorCorrectionLevel:'M',maskPattern:0});
  const n=q.modules.size; return Array.from({length:n},(_,r)=>Array.from({length:n},(_,c)=>q.modules.get(r,c)?1:0));};

const cases=[
 'short',
 'zcash:t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx?amount=0.5',
 'zcash:t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx?amount=0.00052&label=zpay%20to%20%40jane-doe%27s%20Venmo',
 'zcash:t1KhV8ADhTGvVvBpTiEcJGnhTvBBFVFYHXx?amount=1.23456789&label=zpay%20to%20%40a-very-long-venmo-handle%27s%20Venmo',
 'zcash:t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd?amount=0.00000001',
 'a'.repeat(100), 'a'.repeat(150), 'a'.repeat(200),
];
let bad=0;
for(const t of cases){
  const mine=QR.encode(t);
  const got=decode(mine);
  // Also confirm we agree module-for-module with the reference encoder.
  let identical=null;
  try{ const ref=refMatrix(t);
    identical = ref.length===mine.length && ref.every((row,r)=>row.every((v,c)=>v===mine[r][c]));
  }catch(e){ identical='n/a'; }
  const ok = got===t;
  if(!ok) bad++;
  console.log(`${ok?'PASS':'FAIL'} len=${String(t.length).padStart(3)} size=${mine.length} refMatch=${identical}`);
  if(!ok) console.log('   got:', got);
}
console.log(bad? `\n${bad} FAILED` : '\nall decoded');
process.exit(bad?1:0);
