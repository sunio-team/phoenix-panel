// ============================================================
//  پنل ققنوس  |  Phoenix Panel  —  Sunio Team
//  GitHub  : https://github.com/sunio-team
//  Telegram: https://t.me/sunio_team
//
//  اجرا روی Cloudflare Workers:
//   1) Workers & Pages  ->  Create Worker  ->  Edit code
//   2) کل این فایل را جایگزین کد کن و Deploy بزن
//   3) (اختیاری) در Settings -> Variables این‌ها را تنظیم کن:
//        UUID      = uuid دلخواه خودت
//        PROXYIP   = آی‌پی/دامنه پروکسی برای سایت‌های پشت کلادفلر
//        CLEAN_IPS = لیست کلین آی‌پی، با کاما جدا شده
//   4) صفحه‌ی ساخت کانفیگ:  https://دامنه-ورکر/UUID
// ============================================================

import { connect } from 'cloudflare:sockets';

// ---------- تنظیمات ----------
let userID = 'a719ddaf-7560-43a0-8f4b-da87e4c50e5d'; // حتماً عوضش کن
let proxyIP = '';
let defaultCleanIPs = ['www.visa.com', 'cdnjs.cloudflare.com'];

const GITHUB = 'https://github.com/sunio-team';
const TELEGRAM = 'https://t.me/sunio_team';
const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
const HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

// ---------- ورودی اصلی ----------
export default {
  async fetch(request, env) {
    try {
      userID = env.UUID || userID;
      proxyIP = env.PROXYIP || proxyIP;
      if (env.CLEAN_IPS) {
        defaultCleanIPs = env.CLEAN_IPS.split(/[,\s]+/).filter(Boolean);
      }

      const upgrade = request.headers.get('Upgrade');
      if (upgrade && upgrade.toLowerCase() === 'websocket') {
        return await vlessOverWSHandler(request);
      }

      const url = new URL(request.url);
      const host = url.hostname;

      if (url.pathname === '/') return html(landingPage());
      if (url.pathname === `/${userID}`) return html(configPage(host));
      if (url.pathname === `/sub/${userID}`) return subscription(url, host);
      return html(landingPage(), 404);
    } catch (err) {
      return new Response(String(err), { status: 500 });
    }
  },
};

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
  });
}

// ============================================================
//  ساخت کانفیگ
// ============================================================
function buildVless(address, port, host, name, sni) {
  const tls = TLS_PORTS.includes(Number(port));
  const params = new URLSearchParams({
    encryption: 'none',
    security: tls ? 'tls' : 'none',
    type: 'ws',
    host: host,
    path: '/?ed=2048',
  });
  if (tls) {
    params.set('sni', sni || host);
    params.set('fp', 'randomized');
    params.set('alpn', 'http/1.1');
  }
  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function subscription(url, hostDefault) {
  // ?host=  دامنه‌ی ورکر (پیش‌فرض: همین دامنه‌ای که ساب را از آن می‌گیری)
  // ?sni=   اس‌ان‌آی دلخواه (پیش‌فرض: همان host)
  const host = (url.searchParams.get('host') || hostDefault).trim();
  const sni = (url.searchParams.get('sni') || '').trim() || host;
  const ips = (url.searchParams.get('ips') || '')
    .split(/[,\s]+/).filter(Boolean);
  const list = ips.length ? ips : defaultCleanIPs;
  const ports = (url.searchParams.get('ports') || '443')
    .split(/[,\s]+/).map(Number).filter((p) => p > 0 && p < 65536);

  const links = [];
  for (const ip of list) {
    for (const port of ports) {
      links.push(buildVless(ip, port, host, `Phoenix-${ip}-${port}`, sni));
    }
  }
  return new Response(btoa(links.join('\n')), {
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'profile-title': 'Phoenix Panel',
      'profile-update-interval': '6',
      'cache-control': 'no-store',
    },
  });
}

// ============================================================
//  صفحه‌ی اصلی (لندینگ)
// ============================================================
const BASE_STYLE = `
@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@500;900&display=swap');
:root{
  --orange:#f56a00; --orange-deep:#c94f00; --blue:#4127b8; --blue-glow:#7a5cff;
  --paper:#f2ff80; --red:#ff4d4d; --ink:#000;
  color-scheme: light;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  font-family:'Vazirmatn',Tahoma,'Segoe UI',sans-serif;
  background:
    radial-gradient(ellipse at 50% 38%, #ff8a1f 0%, var(--orange) 38%, var(--orange-deep) 100%);
  color:#fff; overflow-x:hidden; -webkit-tap-highlight-color:transparent;
}
#embers{position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:0}
.stroke{
  color:#fff; font-weight:900;
  -webkit-text-stroke:10px var(--ink); paint-order:stroke fill;
  text-shadow:0 6px 0 rgba(0,0,0,.35);
}
`;

function landingPage() {
  return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#f56a00">
<title>پنل ققنوس</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🔥</text></svg>">
<style>
${BASE_STYLE}
main{
  position:relative; z-index:1; min-height:100%;
  display:flex; flex-direction:column; align-items:center; justify-content:center;
  gap:clamp(18px,4vh,34px); padding:24px 16px calc(24px + env(safe-area-inset-bottom));
}
.diamond-wrap{position:relative;width:min(56vw,300px);aspect-ratio:1}
.diamond-wrap svg{width:100%;height:100%;overflow:visible}
.d-outer{fill:none;stroke:var(--blue);stroke-width:13;stroke-linejoin:miter;
  stroke-dasharray:1000;stroke-dashoffset:1000;animation:draw 1.6s ease-out .2s forwards, breathe 4s ease-in-out 1.8s infinite;
  filter:drop-shadow(0 0 14px rgba(65,39,184,.65))}
.d-mid{fill:none;stroke:var(--blue-glow);stroke-width:3;opacity:.0;
  animation:fadein .8s ease 1.4s forwards, spin 18s linear 2s infinite; transform-origin:150px 150px}
.d-core{fill:#fff;opacity:.0;animation:fadein .8s ease 1.6s forwards, pulse 2.4s ease-in-out 2.4s infinite;
  transform-origin:150px 150px;filter:drop-shadow(0 0 10px #fff)}
@keyframes draw{to{stroke-dashoffset:0}}
@keyframes fadein{to{opacity:.85}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes breathe{50%{filter:drop-shadow(0 0 26px rgba(122,92,255,.95))}}
@keyframes pulse{50%{transform:scale(1.7);opacity:.35}}

h1{font-size:clamp(56px,17vw,120px);line-height:1.15;text-align:center;letter-spacing:-1px}
.actions{display:flex;flex-direction:column;align-items:center;gap:16px;width:100%}
.btn{
  display:inline-block; min-width:min(78vw,390px); text-align:center; text-decoration:none;
  background:var(--paper); color:var(--red); font-weight:900; font-size:clamp(22px,6.4vw,34px);
  padding:14px 26px; -webkit-text-stroke:1.5px #7a0000; paint-order:stroke fill;
  box-shadow:6px 6px 0 var(--ink); transition:transform .12s ease, box-shadow .12s ease;
}
.btn:hover,.btn:focus-visible{transform:translate(-3px,-3px);box-shadow:9px 9px 0 var(--ink);outline:none}
.btn:active{transform:translate(4px,4px);box-shadow:2px 2px 0 var(--ink)}
.status{
  display:flex;align-items:center;gap:8px;font-size:15px;font-weight:500;
  background:rgba(0,0,0,.28);padding:6px 16px;border-radius:99px;backdrop-filter:blur(4px)
}
.dot{width:10px;height:10px;border-radius:50%;background:#43ff8a;box-shadow:0 0 10px #43ff8a;animation:blink 1.6s infinite}
@keyframes blink{50%{opacity:.35}}
@media (prefers-reduced-motion:reduce){*{animation:none!important}.d-outer{stroke-dashoffset:0}.d-mid,.d-core{opacity:.85}}
</style>
</head>
<body>
<canvas id="embers" aria-hidden="true"></canvas>
<main>
  <div class="diamond-wrap" aria-hidden="true">
    <svg viewBox="0 0 300 300">
      <polygon class="d-outer" points="150,10 290,150 150,290 10,150"/>
      <polygon class="d-mid" points="150,60 240,150 150,240 60,150"/>
      <polygon class="d-core" points="150,130 170,150 150,170 130,150"/>
    </svg>
  </div>
  <h1 class="stroke">پنل ققنوس</h1>
  <div class="actions">
    <a class="btn" href="${GITHUB}" target="_blank" rel="noopener">عضویت در گیت هاب</a>
    <a class="btn" href="${TELEGRAM}" target="_blank" rel="noopener">عضویت در تلگرام</a>
  </div>
  <div class="status"><span class="dot"></span> سرویس فعال است</div>
</main>
<script>
(() => {
  const c = document.getElementById('embers'), x = c.getContext('2d');
  let w, h, parts = [];
  const dpr = Math.min(devicePixelRatio || 1, 2);
  function size(){ w = c.width = innerWidth * dpr; h = c.height = innerHeight * dpr; }
  addEventListener('resize', size); size();
  const N = Math.round(Math.min(70, innerWidth / 9));
  const mk = (init) => ({
    x: Math.random() * w, y: init ? Math.random() * h : h + 10,
    r: (Math.random() * 2.6 + .8) * dpr, vy: (Math.random() * .9 + .35) * dpr,
    sw: Math.random() * 1.6 + .4, ph: Math.random() * 6.28,
    a: Math.random() * .6 + .3
  });
  for (let i = 0; i < N; i++) parts.push(mk(true));
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  (function tick(t){
    x.clearRect(0, 0, w, h);
    for (const p of parts) {
      p.y -= p.vy; p.x += Math.sin(t / 900 + p.ph) * p.sw * dpr * .35;
      if (p.y < -10) Object.assign(p, mk(false));
      const k = p.y / h;
      x.beginPath(); x.arc(p.x, p.y, p.r, 0, 6.283);
      x.fillStyle = 'rgba(255,' + Math.round(200 * k + 40) + ',60,' + (p.a * (.35 + k * .65)) + ')';
      x.shadowColor = '#ffb020'; x.shadowBlur = 12 * dpr; x.fill();
    }
    requestAnimationFrame(tick);
  })(0);
})();
</script>
</body>
</html>`;
}

// ============================================================
//  صفحه‌ی ساخت کانفیگ (فقط برای صاحب UUID)
// ============================================================
function configPage(host) {
  return `<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>ساخت کانفیگ | پنل ققنوس</title>
<style>
${BASE_STYLE}
body{padding:20px 14px calc(30px + env(safe-area-inset-bottom))}
.wrap{position:relative;z-index:1;max-width:680px;margin:0 auto;display:flex;flex-direction:column;gap:16px}
h1{font-size:clamp(38px,11vw,64px);text-align:center;-webkit-text-stroke:7px #000}
.card{background:var(--paper);color:#111;border:3px solid #000;box-shadow:6px 6px 0 #000;padding:16px;display:flex;flex-direction:column;gap:10px}
.card h2{font-size:18px;font-weight:900;color:#a30000}
label{font-size:14px;font-weight:500}
textarea,select,input{
  width:100%;font:inherit;font-size:15px;padding:10px;border:2px solid #000;background:#fff;color:#000;direction:ltr;text-align:left}
textarea{min-height:110px;resize:vertical}
.row{display:flex;gap:10px;flex-wrap:wrap}
.row>*{flex:1 1 140px}
button{
  font:inherit;font-weight:900;font-size:16px;padding:11px 16px;cursor:pointer;
  background:var(--red);color:#fff;border:3px solid #000;box-shadow:4px 4px 0 #000;
  transition:transform .1s, box-shadow .1s}
button:active{transform:translate(3px,3px);box-shadow:1px 1px 0 #000}
button.alt{background:var(--blue)}
.cfg{display:flex;flex-direction:column;gap:6px;border-top:2px dashed #000;padding-top:10px}
.cfg code{direction:ltr;text-align:left;font-size:12px;word-break:break-all;background:#fff;border:2px solid #000;padding:8px;max-height:96px;overflow:auto}
.cfg .top{display:flex;justify-content:space-between;align-items:center;gap:8px}
.cfg b{direction:ltr;font-size:14px}
.cfg button{padding:6px 12px;font-size:14px}
.hint{font-size:13px;line-height:1.9;color:#333}
.toast{position:fixed;left:50%;bottom:calc(20px + env(safe-area-inset-bottom));transform:translate(-50%,80px);background:#000;color:#fff;padding:10px 20px;transition:transform .25s;z-index:9;font-weight:500}
.toast.on{transform:translate(-50%,0)}
.links{display:flex;gap:10px;justify-content:center;flex-wrap:wrap}
.links a{color:#fff;font-weight:900;text-decoration:none;background:#000;padding:6px 16px}
</style>
</head>
<body>
<canvas id="embers" aria-hidden="true"></canvas>
<div class="wrap">
  <h1 class="stroke">پنل ققنوس</h1>

  <div class="card">
    <h2>۱) کلین آی‌پی‌ها</h2>
    <label for="ips">هر خط یک کلین آی‌پی (یا دامنه‌ی پشت کلادفلر)</label>
    <textarea id="ips" spellcheck="false" placeholder="104.16.10.20&#10;172.64.33.5&#10;www.visa.com">${defaultCleanIPs.join('\n')}</textarea>
    <div class="row">
      <div>
        <label for="ptype">نوع اتصال</label>
        <select id="ptype">
          <option value="tls">TLS (پیشنهادی)</option>
          <option value="http">بدون TLS</option>
        </select>
      </div>
      <div>
        <label for="port">پورت</label>
        <select id="port"></select>
      </div>
    </div>
    <div class="row">
      <div>
        <label for="host">Host (دامنه‌ی این ورکر)</label>
        <input id="host" value="${host}" spellcheck="false" autocapitalize="off">
      </div>
      <div>
        <label for="sni">SNI (هرچی خواستی بذار)</label>
        <input id="sni" value="${host}" spellcheck="false" autocapitalize="off">
      </div>
    </div>
    <button id="gen">ساخت کانفیگ‌ها</button>
  </div>

  <div class="card" id="out" hidden>
    <h2>۲) کانفیگ‌ها</h2>
    <div class="row">
      <button class="alt" id="copyAll">کپی همه</button>
      <button class="alt" id="copySub">کپی لینک ساب</button>
    </div>
    <div id="list"></div>
  </div>

  <div class="card">
    <h2>راهنما</h2>
    <p class="hint">
      آدرس (Address) کانفیگ = کلین آی‌پی شما.<br>
      Host باید همان دامنه‌ی ورکر باشد: <b dir="ltr">${host}</b> (خودکار پر می‌شود، روی هر هاستی آپلود کنی همان‌جا را می‌خواند).<br>
      SNI را می‌توانی به دلخواه عوض کنی. اگر با SNI دلخواه وصل نشد، آن را برگردان روی دامنه‌ی ورکر.<br>
      اگر کانفیگی وصل نشد، کلین آی‌پی دیگری امتحان کن؛ کلین آی‌پی به اینترنت و اپراتور شما بستگی دارد.
    </p>
  </div>

  <div class="links">
    <a href="${GITHUB}" target="_blank" rel="noopener">GitHub</a>
    <a href="${TELEGRAM}" target="_blank" rel="noopener">Telegram</a>
  </div>
</div>
<div class="toast" id="toast">کپی شد ✓</div>

<script>
const HOST = ${JSON.stringify(host)};
const UUID = ${JSON.stringify(userID)};
const TLS = ${JSON.stringify(TLS_PORTS)};
const HTTP = ${JSON.stringify(HTTP_PORTS)};
const $ = (id) => document.getElementById(id);
let current = [];

function fillPorts() {
  const list = $('ptype').value === 'tls' ? TLS : HTTP;
  $('port').innerHTML = list.map((p) => '<option>' + p + '</option>').join('');
}
$('ptype').onchange = fillPorts; fillPorts();

function vless(addr, port, tls) {
  const host = $('host').value.trim() || HOST;
  const sni = $('sni').value.trim() || host;
  const q = new URLSearchParams({ encryption: 'none', security: tls ? 'tls' : 'none', type: 'ws', host: host, path: '/?ed=2048' });
  if (tls) { q.set('sni', sni); q.set('fp', 'randomized'); q.set('alpn', 'http/1.1'); }
  return 'vless://' + UUID + '@' + addr + ':' + port + '?' + q + '#' + encodeURIComponent('Phoenix-' + addr + '-' + port);
}

function toast(msg) {
  const t = $('toast'); t.textContent = msg || 'کپی شد ✓'; t.classList.add('on');
  setTimeout(() => t.classList.remove('on'), 1400);
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); }
  catch { const a = document.createElement('textarea'); a.value = text; document.body.appendChild(a); a.select(); document.execCommand('copy'); a.remove(); }
  toast();
}

$('gen').onclick = () => {
  const ips = $('ips').value.split(/[\\s,]+/).map((s) => s.trim()).filter(Boolean);
  if (!ips.length) return toast('حداقل یک کلین آی‌پی وارد کن');
  const port = $('port').value, tls = $('ptype').value === 'tls';
  current = ips.map((ip) => ({ ip, link: vless(ip, port, tls) }));
  $('list').innerHTML = '';
  current.forEach((c) => {
    const d = document.createElement('div'); d.className = 'cfg';
    d.innerHTML = '<div class="top"><b></b><button>کپی</button></div><code></code>';
    d.querySelector('b').textContent = c.ip + ':' + port;
    d.querySelector('code').textContent = c.link;
    d.querySelector('button').onclick = () => copy(c.link);
    $('list').appendChild(d);
  });
  $('out').hidden = false;
  $('out').scrollIntoView({ behavior: 'smooth' });
};
$('copyAll').onclick = () => copy(current.map((c) => c.link).join('\\n'));
$('copySub').onclick = () => {
  const ips = current.map((c) => c.ip).join(',');
  const host = $('host').value.trim() || HOST;
  const sni = $('sni').value.trim() || host;
  copy(location.origin + '/sub/' + UUID + '?ips=' + encodeURIComponent(ips) + '&ports=' + $('port').value +
    '&host=' + encodeURIComponent(host) + '&sni=' + encodeURIComponent(sni));
};
</script>
<script>
(() => {
  const c = document.getElementById('embers'), x = c.getContext('2d');
  let w, h; const dpr = Math.min(devicePixelRatio || 1, 2);
  const size = () => { w = c.width = innerWidth * dpr; h = c.height = innerHeight * dpr; };
  addEventListener('resize', size); size();
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const P = Array.from({ length: 40 }, () => ({ x: Math.random() * w, y: Math.random() * h, r: (Math.random() * 2 + .6) * dpr, v: (Math.random() * .7 + .3) * dpr }));
  (function tick() {
    x.clearRect(0, 0, w, h);
    for (const p of P) {
      p.y -= p.v; if (p.y < -8) { p.y = h + 8; p.x = Math.random() * w; }
      x.beginPath(); x.arc(p.x, p.y, p.r, 0, 6.283);
      x.fillStyle = 'rgba(255,200,70,.65)'; x.shadowColor = '#ffb020'; x.shadowBlur = 10 * dpr; x.fill();
    }
    requestAnimationFrame(tick);
  })();
})();
</script>
</body>
</html>`;
}

// ============================================================
//  VLESS over WebSocket
// ============================================================
async function vlessOverWSHandler(request) {
  const pair = new WebSocketPair();
  const [client, webSocket] = Object.values(pair);
  webSocket.accept();

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

  let remoteSocketWrapper = { value: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          if (isDns && udpStreamWrite) return udpStreamWrite(chunk);

          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            hasError, message, portRemote = 443, addressRemote = '',
            rawDataIndex, vlessVersion = new Uint8Array([0, 0]), isUDP,
          } = processVlessHeader(chunk, userID);

          if (hasError) throw new Error(message);

          if (isUDP) {
            if (portRemote === 53) isDns = true;
            else throw new Error('UDP فقط برای DNS (پورت 53) پشتیبانی می‌شود');
          }

          const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isDns) {
            const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader);
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }
          handleTCPOutBound(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader);
        },
      })
    )
    .catch(() => {});

  return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote);
    tcpSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(webSocket));
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
  let cancelled = false;
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (cancelled) return;
        controller.enqueue(event.data);
      });
      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        if (cancelled) return;
        controller.close();
      });
      webSocketServer.addEventListener('error', (err) => controller.error(err));

      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    cancel() {
      if (cancelled) return;
      cancelled = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
}

function processVlessHeader(buf, uuid) {
  if (buf.byteLength < 24) return { hasError: true, message: 'invalid data' };

  const version = new Uint8Array(buf.slice(0, 1));
  if (stringifyUUID(new Uint8Array(buf.slice(1, 17))) !== uuid) {
    return { hasError: true, message: 'invalid user' };
  }

  const optLength = new Uint8Array(buf.slice(17, 18))[0];
  const command = new Uint8Array(buf.slice(18 + optLength, 19 + optLength))[0];
  let isUDP = false;
  if (command === 1) {
    // TCP
  } else if (command === 2) {
    isUDP = true;
  } else {
    return { hasError: true, message: `command ${command} not supported (01-tcp, 02-udp)` };
  }

  const portIndex = 18 + optLength + 1;
  const portRemote = new DataView(buf.slice(portIndex, portIndex + 2)).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressType = new Uint8Array(buf.slice(addressIndex, addressIndex + 1))[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = '';

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(buf.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
      break;
    case 2:
      addressLength = new Uint8Array(buf.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buf.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: {
      addressLength = 16;
      const dv = new DataView(buf.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i * 2).toString(16));
      addressValue = ipv6.join(':');
      break;
    }
    default:
      return { hasError: true, message: `invalid addressType ${addressType}` };
  }
  if (!addressValue) return { hasError: true, message: 'empty address' };

  return {
    hasError: false,
    addressRemote: addressValue,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vlessVersion: version,
    isUDP,
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry) {
  let header = vlessResponseHeader;
  let hasIncomingData = false;

  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error('webSocket is not open');
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
      })
    )
    .catch(() => safeCloseWebSocket(webSocket));

  if (!hasIncomingData && retry) retry();
}

function base64ToArrayBuffer(b64) {
  if (!b64) return { error: null };
  try {
    b64 = b64.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    return { earlyData: Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (_) {}
}

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 256).toString(16).slice(1));
function stringifyUUID(arr, offset = 0) {
  return (
    byteToHex[arr[offset]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' +
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' +
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' +
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' +
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

// DNS (UDP/53) از طریق DoH
async function handleUDPOutBound(webSocket, vlessResponseHeader) {
  let headerSent = false;
  const transform = new TransformStream({
    transform(chunk, controller) {
      for (let i = 0; i < chunk.byteLength; ) {
        const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
        controller.enqueue(new Uint8Array(chunk.slice(i + 2, i + 2 + len)));
        i += 2 + len;
      }
    },
  });

  transform.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch('https://1.1.1.1/dns-query', {
            method: 'POST',
            headers: { 'content-type': 'application/dns-message' },
            body: chunk,
          });
          const result = await resp.arrayBuffer();
          const size = result.byteLength;
          const sizeBuf = new Uint8Array([(size >> 8) & 0xff, size & 0xff]);
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            const parts = headerSent ? [sizeBuf, result] : [vlessResponseHeader, sizeBuf, result];
            webSocket.send(await new Blob(parts).arrayBuffer());
            headerSent = true;
          }
        },
      })
    )
    .catch(() => {});

  const writer = transform.writable.getWriter();
  return { write: (chunk) => writer.write(chunk) };
}
