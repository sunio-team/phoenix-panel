#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phoenix IP Scanner  -  Sunio Team
GitHub  : https://github.com/sunio-team
Telegram: https://t.me/sunio_team

Run in Termux (straight from GitHub):
    pkg install python curl -y
    curl -sL https://raw.githubusercontent.com/sunio-team/phoenix-panel/refs/heads/main/phoenix-scanner.py | python

Then open  http://127.0.0.1:8000  in your browser.
No third-party packages needed (Python standard library only).
"""

import asyncio
import base64
import ipaddress
import json
import os
import random
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = int(os.environ.get("PHOENIX_PORT", "8000"))
REPO_URL = "https://raw.githubusercontent.com/sunio-team/phoenix-panel/refs/heads/main/Clean-ips.txt"
HARD_CAP = 5000  # safety ceiling, only used when the repo list is unavailable
TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
HTTP_PORTS = {80, 8080, 8880, 2052, 2082, 2086, 2095}
DATA_DIR = os.path.join(os.path.expanduser("~"), ".phoenix_scanner")
CACHE_FILE = os.path.join(DATA_DIR, "Clean-ips.txt")
ALLOW_PRIVATE = os.environ.get("PHOENIX_ALLOW_PRIVATE") == "1"  # only for local testing

HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

_FA = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")


def fa(n):
    return str(n).translate(_FA)


# ============================================================
#  Helpers: parsing IP lists
# ============================================================
def parse_targets(text, allow_hosts):
    """Return (valid_unique_list, skipped_count)."""
    out, seen, skipped = [], set(), 0
    text = re.sub(r"#.*", "", text or "")
    for raw in re.split(r"[\s,;]+", text):
        s = raw.strip().strip("[]")
        if not s:
            continue
        try:
            ip = ipaddress.ip_address(s)
            if not ALLOW_PRIVATE and (
                ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_unspecified or ip.is_reserved
            ):
                skipped += 1
                continue
            s = str(ip)
        except ValueError:
            if not (allow_hosts and HOST_RE.match(s)):
                skipped += 1
                continue
            s = s.lower()
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out, skipped


# ============================================================
#  Repo list (Clean-ips.txt)
# ============================================================
_repo = {"ips": [], "ts": 0.0, "cached": False}
_repo_lock = threading.Lock()


def load_repo(force=False):
    with _repo_lock:
        if not force and _repo["ips"] and time.time() - _repo["ts"] < 600:
            return _repo["ips"], _repo["cached"]
        try:
            req = urllib.request.Request(REPO_URL, headers={"User-Agent": "PhoenixIPScanner/1.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                text = r.read().decode("utf-8", "ignore")
            ips, _ = parse_targets(text, allow_hosts=False)  # the file also has domains: keep IPs only
            if not ips:
                raise ValueError("empty list")
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                f.write(text)
            _repo.update(ips=ips, ts=time.time(), cached=False)
        except Exception:
            if os.path.exists(CACHE_FILE):
                with open(CACHE_FILE, encoding="utf-8") as f:
                    ips, _ = parse_targets(f.read(), allow_hosts=False)
                if not ips:
                    raise
                _repo.update(ips=ips, ts=time.time(), cached=True)
            else:
                raise
        return _repo["ips"], _repo["cached"]


# ============================================================
#  Scanner
# ============================================================
def make_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    return ctx


async def probe(target, port, sni, timeout, ctx):
    """
    Connect to target:port (TLS with the given SNI), then send a WebSocket upgrade
    with Host=SNI - exactly what a VLESS/WS config does.
      101      -> "ws"   (tunnel path works)
      other    -> "http" (reachable, but not a working Phoenix endpoint)
      no reply -> "fail"
    """
    t0 = time.perf_counter()
    writer = None
    res = {"ip": target, "status": "fail", "ms": None, "code": None, "cf": False, "err": ""}
    try:
        if port in TLS_PORTS:
            coro = asyncio.open_connection(
                target, port, ssl=ctx, server_hostname=sni, ssl_handshake_timeout=timeout
            )
        else:
            coro = asyncio.open_connection(target, port)
        reader, writer = await asyncio.wait_for(coro, timeout)
        res["ms"] = int((time.perf_counter() - t0) * 1000)

        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            "GET /?ed=2048 HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: Mozilla/5.0 (Linux; Android 13) PhoenixScanner\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n" % (sni, key)
        ).encode()
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout)
        data = await asyncio.wait_for(reader.read(4096), timeout)

        m = re.match(rb"HTTP/\d\.\d\s+(\d{3})", data)
        if not m:
            res["err"] = "no_http"
        else:
            code = int(m.group(1))
            low = data.lower()
            res["code"] = code
            res["cf"] = b"server: cloudflare" in low or b"cf-ray" in low
            if code == 101:
                res["status"] = "ws"
            elif code < 500:
                res["status"] = "http"
            else:
                res["err"] = "http%d" % code
    except asyncio.TimeoutError:
        res["err"] = "timeout"
    except ssl.SSLError:
        res["err"] = "tls"
    except ConnectionRefusedError:
        res["err"] = "refused"
    except ConnectionResetError:
        res["err"] = "reset"
    except OSError:
        res["err"] = "net"
    except Exception:
        res["err"] = "error"
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
    if res["status"] == "fail":
        res["ms"] = None
    return res


class Job:
    def __init__(self, targets, sni, port, timeout, conc):
        self.id = uuid.uuid4().hex[:10]
        self.targets = targets
        self.sni = sni
        self.port = port
        self.timeout = timeout
        self.conc = conc
        self.results = []
        self.counts = {"ws": 0, "http": 0, "fail": 0}
        self.state = "running"
        self.stop = False
        self.lock = threading.Lock()
        self.started = time.time()
        self.finished = None

    def add(self, res):
        with self.lock:
            self.results.append(res)
            self.counts[res["status"]] += 1

    def finish(self):
        with self.lock:
            self.state = "stopped" if self.stop else "done"
            self.finished = time.time()

    def snapshot(self, since):
        with self.lock:
            end = self.finished or time.time()
            return {
                "state": self.state,
                "total": len(self.targets),
                "done": len(self.results),
                "counts": dict(self.counts),
                "results": self.results[since:],
                "next": len(self.results),
                "elapsed": round(end - self.started, 1),
            }


async def run_job(job):
    ctx = make_ctx()
    sem = asyncio.Semaphore(job.conc)

    async def one(t):
        async with sem:
            if job.stop:
                return
            res = await probe(t, job.port, job.sni, job.timeout, ctx)
        job.add(res)

    await asyncio.gather(*(one(t) for t in job.targets))


JOBS = {}
JOBS_LOCK = threading.Lock()


def start_job(targets, sni, port, timeout, conc):
    with JOBS_LOCK:
        for j in JOBS.values():  # one scan at a time
            if j.state == "running":
                j.stop = True
        if len(JOBS) > 8:
            for k in list(JOBS)[:-4]:
                JOBS.pop(k, None)
        job = Job(targets, sni, port, timeout, conc)
        JOBS[job.id] = job

    def runner():
        try:
            asyncio.run(run_job(job))
        except Exception:
            pass
        finally:
            job.finish()

    threading.Thread(target=runner, daemon=True).start()
    return job


# ============================================================
#  HTTP server
# ============================================================
SNI_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


class Handler(BaseHTTPRequestHandler):
    server_version = "PhoenixScanner/1.0"

    def log_message(self, *a):
        pass

    def _host_ok(self):
        h = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        return h in ("127.0.0.1", "localhost", "::1")

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _err(self, code, key, msg):
        self._send(code, {"ok": False, "error": key, "message": msg})

    # ---------- GET ----------
    def do_GET(self):
        if not self._host_ok():
            return self._err(403, "host", "forbidden")
        path, _, query = self.path.partition("?")

        if path in ("/", "/index.html"):
            return self._send(200, INDEX_HTML, "text/html; charset=utf-8")

        if path == "/api/repo":
            try:
                ips, cached = load_repo(force="refresh=1" in query)
                return self._send(200, {"ok": True, "count": len(ips), "max": len(ips), "cached": cached})
            except Exception:
                return self._send(200, {
                    "ok": False,
                    "message": "دریافت لیست از مخزن ناموفق بود. اینترنت/فیلترشکن را چک کن یا آیپی‌ها را دستی وارد کن.",
                })

        m = re.match(r"^/api/scan/([0-9a-f]+)$", path)
        if m:
            job = JOBS.get(m.group(1))
            if not job:
                return self._err(404, "not_found", "اسکن پیدا نشد")
            since = 0
            mm = re.search(r"since=(\d+)", query)
            if mm:
                since = int(mm.group(1))
            return self._send(200, job.snapshot(since))

        return self._err(404, "not_found", "not found")

    # ---------- POST ----------
    def do_POST(self):
        if not self._host_ok():
            return self._err(403, "host", "forbidden")
        path = self.path.partition("?")[0]

        m = re.match(r"^/api/scan/([0-9a-f]+)/stop$", path)
        if m:
            job = JOBS.get(m.group(1))
            if job:
                job.stop = True
            return self._send(200, {"ok": True})

        if path == "/api/scan":
            try:
                n = min(int(self.headers.get("Content-Length") or 0), 2_000_000)
                data = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                return self._err(400, "bad_json", "درخواست نامعتبر است")

            sni = str(data.get("sni") or "").strip().lower()
            if not SNI_RE.match(sni):
                return self._err(400, "bad_sni", "SNI معتبر نیست")

            try:
                port = int(data.get("port") or 443)
                timeout = float(data.get("timeout") or 4)
                conc = int(data.get("conc") or 40)
            except Exception:
                return self._err(400, "bad_params", "پارامترها نامعتبر است")
            if port not in TLS_PORTS and port not in HTTP_PORTS:
                port = 443
            timeout = max(1.0, min(timeout, 15.0))
            conc = max(5, min(conc, 100))

            skipped = 0
            if data.get("source") == "manual":
                targets, skipped = parse_targets(str(data.get("ips") or ""), allow_hosts=True)
                if not targets:
                    return self._err(400, "empty", "هیچ آیپی معتبری وارد نشده")
                try:  # the limit is the number of IPs in the repo list
                    limit = len(load_repo()[0])
                except Exception:
                    limit = HARD_CAP
                if len(targets) > limit:
                    return self._err(400, "max_exceeded", "حداکثر %s آیپی است" % fa(limit))
            else:
                try:
                    count = int(data.get("count") or 0)
                except Exception:
                    count = 0
                if count < 1:
                    return self._err(400, "bad_count", "تعداد نامعتبر است")
                try:
                    ips, _ = load_repo()
                except Exception:
                    return self._err(502, "repo", "دریافت لیست از مخزن ناموفق بود")
                if count > len(ips):
                    return self._err(400, "max_exceeded", "حداکثر %s آیپی است" % fa(len(ips)))
                targets = random.sample(ips, count) if data.get("random", True) else ips[:count]

            job = start_job(targets, sni, port, timeout, conc)
            return self._send(200, {"ok": True, "id": job.id, "total": len(targets), "skipped": skipped})

        return self._err(404, "not_found", "not found")


# ============================================================
#  Web UI
# ============================================================
INDEX_HTML = r"""<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#f56a00">
<title>اسکنر آیپی ققنوس | Phoenix IP Scanner</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🔥</text></svg>">
<style>
@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@500;900&display=swap');
:root{
  --orange:#f56a00; --orange-deep:#c94f00; --blue:#4127b8; --blue-glow:#7a5cff;
  --paper:#f2ff80; --red:#ff4d4d; --ink:#000; --ok:#0c8a44; --warn:#b07800; --bad:#c62828;
}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth;background:#c94f00;min-height:100%}
body{
  font-family:'Vazirmatn',Tahoma,'Segoe UI',sans-serif; min-height:100vh;
  background:radial-gradient(ellipse at 50% 12%,#ff8a1f 0%,var(--orange) 40%,var(--orange-deep) 100%) fixed;
  color:#111; overflow-x:hidden; -webkit-tap-highlight-color:transparent;
  padding:18px 12px calc(40px + env(safe-area-inset-bottom));
}
#embers{position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:0}
.wrap{position:relative;z-index:1;max-width:720px;margin:0 auto;display:flex;flex-direction:column;gap:16px}

/* ---------- header ---------- */
header{display:flex;flex-direction:column;align-items:center;gap:6px;text-align:center}
.logo{width:76px;height:76px}
.logo svg{width:100%;height:100%;overflow:visible}
.lg-o{fill:none;stroke:var(--blue);stroke-width:9;stroke-dasharray:300;stroke-dashoffset:300;
  animation:draw 1.4s ease-out .1s forwards,glow 4s ease-in-out 1.6s infinite}
.lg-m{fill:none;stroke:var(--blue-glow);stroke-width:2.5;opacity:0;transform-origin:50px 50px;
  animation:fade .6s ease 1.2s forwards,spin 16s linear 1.6s infinite}
.lg-c{fill:#fff;opacity:0;transform-origin:50px 50px;animation:fade .6s ease 1.4s forwards,pulse 2.4s ease-in-out 2s infinite}
@keyframes draw{to{stroke-dashoffset:0}}
@keyframes fade{to{opacity:.9}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes glow{50%{filter:drop-shadow(0 0 10px rgba(122,92,255,.95))}}
@keyframes pulse{50%{transform:scale(1.7);opacity:.35}}
.stroke{color:#fff;font-weight:900;-webkit-text-stroke:8px #000;paint-order:stroke fill;text-shadow:0 5px 0 rgba(0,0,0,.35)}
h1{font-size:clamp(34px,10vw,58px);line-height:1.2}
.sub{color:#fff;font-weight:900;letter-spacing:3px;direction:ltr;-webkit-text-stroke:4px #000;paint-order:stroke fill;font-size:14px}

/* ---------- tabs ---------- */
.tabs{display:flex;gap:10px;flex-wrap:wrap}
.tabs button{flex:1 1 200px}
button{
  font:inherit;font-weight:900;font-size:16px;padding:12px 14px;cursor:pointer;
  background:var(--paper);color:var(--red);border:3px solid #000;box-shadow:5px 5px 0 #000;
  -webkit-text-stroke:.6px #7a0000;paint-order:stroke fill;
  transition:transform .1s,box-shadow .1s,background .15s}
button:active{transform:translate(3px,3px);box-shadow:1px 1px 0 #000}
button:disabled{opacity:.5;cursor:not-allowed}
.tabs button.on{background:var(--blue);color:#fff;-webkit-text-stroke:0}
.go{background:var(--red);color:#fff;-webkit-text-stroke:0;flex:1 1 200px}
.stop{background:#222;color:#fff;-webkit-text-stroke:0}
.blue{background:var(--blue);color:#fff;-webkit-text-stroke:0}
.small{padding:6px 12px;font-size:14px;box-shadow:3px 3px 0 #000}

/* ---------- cards ---------- */
.card{background:var(--paper);border:3px solid #000;box-shadow:6px 6px 0 #000;padding:16px;display:flex;flex-direction:column;gap:10px}
.card h2{font-size:19px;font-weight:900;color:#a30000}
.lead{font-size:14px;line-height:1.9;color:#333}
label{font-size:14px;font-weight:500}
textarea,select,input[type=number],input[type=text]{
  width:100%;font:inherit;font-size:15px;padding:10px;border:2px solid #000;background:#fff;color:#000;direction:ltr;text-align:left;border-radius:0}
textarea{min-height:110px;resize:vertical}
textarea.sni{min-height:64px}
textarea::placeholder,input::placeholder{color:#9a9a9a;direction:rtl;text-align:right;font-size:13px}
textarea:focus,input:focus,select:focus{outline:3px solid var(--blue-glow);outline-offset:0}
.row{display:flex;gap:10px;flex-wrap:wrap}
.row>*{flex:1 1 140px}
.chips{display:flex;gap:8px;flex-wrap:wrap}
.chips button{padding:5px 12px;font-size:14px;box-shadow:3px 3px 0 #000}
.seg{display:flex;gap:8px;flex-wrap:wrap}
.seg button{flex:1 1 140px;font-size:15px}
.seg button.on{background:var(--blue);color:#fff;-webkit-text-stroke:0}
.msg{font-size:13px;min-height:0;line-height:1.8}
.msg.err{color:var(--bad);font-weight:900}
.msg.ok{color:var(--ok);font-weight:500}
.msg.info{color:#444}
.check{display:flex;align-items:center;gap:8px;font-size:14px}
.check input{width:18px;height:18px;accent-color:var(--blue)}
.warnbox{background:#fff;border:2px dashed #000;padding:8px 10px;font-size:13px;line-height:1.8;color:#7a0000;font-weight:500}
details summary{cursor:pointer;font-weight:900;font-size:14px;color:#333;padding:4px 0}
details[open] summary{margin-bottom:8px}
[hidden]{display:none!important}

/* ---------- progress ---------- */
.prog{display:flex;gap:16px;align-items:center;flex-wrap:wrap;justify-content:center}
.ring{position:relative;width:150px;height:150px;flex:0 0 auto}
.ring svg{width:100%;height:100%;overflow:visible}
.ring-bg{fill:none;stroke:rgba(0,0,0,.16);stroke-width:12}
.ring-fg{fill:none;stroke:var(--blue);stroke-width:12;stroke-dasharray:100;stroke-dashoffset:100;transition:stroke-dashoffset .45s ease;
  filter:drop-shadow(0 0 6px rgba(65,39,184,.6))}
.running .ring-fg{animation:glow 2s ease-in-out infinite}
.ring-txt{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;line-height:1.3}
.ring-txt b{font-size:28px;font-weight:900;direction:ltr}
.ring-txt span{font-size:12px;color:#444;direction:ltr}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:8px;flex:1 1 200px;min-width:200px}
.stat{background:#fff;border:2px solid #000;padding:8px;text-align:center;font-size:12px;line-height:1.5}
.stat b{display:block;font-size:20px;font-weight:900;direction:ltr}
.stat.g b{color:var(--ok)} .stat.y b{color:var(--warn)} .stat.r b{color:var(--bad)} .stat.b b{color:var(--blue)}
.status-line{text-align:center;font-weight:900;font-size:15px}

/* ---------- results ---------- */
.res{display:flex;align-items:center;gap:8px;background:#fff;border:2px solid #000;border-inline-start-width:8px;padding:7px 10px;font-size:13px}
.res.ws{border-inline-start-color:var(--ok)}
.res.http{border-inline-start-color:#e0a800}
.res.fail{border-inline-start-color:var(--bad);opacity:.75}
.res .ip{direction:ltr;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:14px;flex:1;text-align:left;word-break:break-all}
.res .bd{font-size:12px;white-space:nowrap}
.res .ms{direction:ltr;font-weight:900;min-width:58px;text-align:right}
.list{display:flex;flex-direction:column;gap:6px}

/* ---------- configs ---------- */
.cfg{display:flex;flex-direction:column;gap:6px;border-top:2px dashed #000;padding-top:10px}
.cfg .top{display:flex;justify-content:space-between;align-items:center;gap:8px}
.cfg b{font-size:14px;direction:ltr;text-align:left}
.cfg code{direction:ltr;text-align:left;font-size:12px;word-break:break-all;background:#fff;border:2px solid #000;padding:8px;max-height:92px;overflow:auto}

.toast{position:fixed;left:50%;bottom:calc(20px + env(safe-area-inset-bottom));transform:translate(-50%,90px);
  background:#000;color:#fff;padding:10px 20px;transition:transform .25s;z-index:9;font-weight:500;max-width:90vw;text-align:center}
.toast.on{transform:translate(-50%,0)}
.links{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-top:6px}
.links a{color:#fff;font-weight:900;text-decoration:none;background:#000;padding:6px 16px}
@media (prefers-reduced-motion:reduce){*{animation:none!important}.lg-o{stroke-dashoffset:0}.lg-m,.lg-c{opacity:.9}}
</style>
</head>
<body>
<canvas id="embers" aria-hidden="true"></canvas>
<div class="wrap">

  <header>
    <div class="logo" aria-hidden="true">
      <svg viewBox="0 0 100 100">
        <polygon class="lg-o" points="50,4 96,50 50,96 4,50"/>
        <polygon class="lg-m" points="50,22 78,50 50,78 22,50"/>
        <polygon class="lg-c" points="50,43 57,50 50,57 43,50"/>
      </svg>
    </div>
    <h1 class="stroke">اسکنر آیپی ققنوس</h1>
    <div class="sub">PHOENIX IP SCANNER</div>
  </header>

  <nav class="tabs">
    <button data-tab="scan" class="on">اسکنر clean IP 🎰</button>
    <button data-tab="build">ساخت کانفیگ clean IP 🏗</button>
  </nav>

  <!-- ======================= SCANNER ======================= -->
  <section id="tab-scan" style="display:flex;flex-direction:column;gap:16px">

    <div class="card">
      <h2>🎰 منبع آیپی‌ها</h2>
      <div class="seg">
        <button data-src="repo" class="on">📦 از مخزن ققنوس</button>
        <button data-src="manual">✍️ وارد کردن دستی</button>
      </div>

      <div id="srcRepo" style="display:flex;flex-direction:column;gap:10px">
        <div class="row" style="align-items:center">
          <div class="msg info" id="repoInfo" style="flex:3 1 200px">⏳ در حال دریافت لیست از مخزن...</div>
          <button class="small" id="repoRefresh" style="flex:1 1 90px">🔄 بروزرسانی</button>
        </div>
        <label for="count" id="countLabel">چند آیپی اسکن شود؟</label>
        <input type="number" id="count" inputmode="numeric" min="1" value="50">
        <div class="chips" id="chips"></div>
        <div class="msg" id="countMsg"></div>
        <label class="check"><input type="checkbox" id="rand" checked> انتخاب تصادفی از لیست</label>
      </div>

      <div id="srcManual" style="display:none;flex-direction:column;gap:10px">
        <label for="manual">آیپی‌ها را وارد کنید (هر خط یک IP)</label>
        <textarea id="manual" spellcheck="false" autocapitalize="off" placeholder="104.16.10.20&#10;172.64.33.5&#10;188.114.99.29"></textarea>
        <div class="msg" id="manualMsg"></div>
      </div>
    </div>

    <div class="card">
      <h2>🔑 SNI</h2>
      <label for="sni">SNI را وارد کنید</label>
      <textarea id="sni" class="sni" rows="2" spellcheck="false" autocapitalize="off" autocomplete="off"
        placeholder="اگر از پنل ققنوس استفاده می‌کنید لینک دومی را که ساخت دریافت کردید وارد کنید"></textarea>
      <div class="msg" id="sniHint"></div>

      <details>
        <summary>⚙️ تنظیمات پیشرفته</summary>
        <div class="row">
          <div><label for="port">پورت</label>
            <select id="port">
              <option>443</option><option>2053</option><option>2083</option><option>2087</option><option>2096</option><option>8443</option>
              <option>80</option><option>8080</option><option>8880</option><option>2052</option><option>2082</option><option>2086</option><option>2095</option>
            </select></div>
          <div><label for="timeout">تایم‌اوت (ثانیه)</label>
            <input type="number" id="timeout" value="4" min="1" max="15" inputmode="numeric"></div>
          <div><label for="conc">تعداد همزمان</label>
            <input type="number" id="conc" value="40" min="5" max="100" inputmode="numeric"></div>
        </div>
      </details>

      <div class="row">
        <button class="go" id="start">🚀 شروع اسکن</button>
        <button class="stop" id="stop" hidden>⏹ توقف</button>
      </div>
      <div class="msg" id="startMsg"></div>
    </div>

    <div class="card" id="progCard" hidden>
      <h2>📡 نتیجه‌ی اسکن</h2>
      <div class="prog" id="progBox">
        <div class="ring">
          <svg viewBox="0 0 200 200">
            <polygon class="ring-bg" pathLength="100" points="100,12 188,100 100,188 12,100"/>
            <polygon class="ring-fg" id="ringFg" pathLength="100" points="100,12 188,100 100,188 12,100"/>
          </svg>
          <div class="ring-txt"><b id="pct">0%</b><span id="cnt">0 / 0</span></div>
        </div>
        <div class="stats">
          <div class="stat g"><b id="stWs">0</b>✅ سالم (WS)</div>
          <div class="stat y"><b id="stHttp">0</b>🟡 قابل‌دسترس</div>
          <div class="stat r"><b id="stFail">0</b>❌ ناموفق</div>
          <div class="stat b"><b id="stBest">—</b>⚡ سریع‌ترین</div>
        </div>
      </div>
      <div class="status-line" id="statusLine"></div>

      <label class="check"><input type="checkbox" id="showFail"> نمایش آیپی‌های ناموفق هم</label>
      <div class="list" id="list"></div>
      <button class="small" id="more" hidden>نمایش بیشتر ▼</button>

      <div class="row">
        <button class="small" id="copyOk">📋 کپی آیپی‌های سالم</button>
        <button class="small blue" id="toBuild">🏗 ارسال به ساخت کانفیگ</button>
      </div>
      <div class="lead">✅ یعنی اتصال TLS با SNI شما برقرار شد و مسیر WebSocket ورکر جواب ۱۰۱ داد، پس کانفیگ روی این آیپی کار می‌کند. 🟡 یعنی آیپی جواب داده ولی نه به‌عنوان ورکر شما (SNI را چک کن).</div>
    </div>
  </section>

  <!-- ======================= BUILDER ======================= -->
  <section id="tab-build" style="display:none;flex-direction:column;gap:16px">
    <div class="card">
      <h2>🏗 ساخت کانفیگ clean IP</h2>
      <p class="lead">این بخش جهت ایجاد کانفیگ آیپی تمیز با SNI پنل ققنوس می‌باشد.</p>

      <label for="bSni">SNI را وارد کنید</label>
      <textarea id="bSni" class="sni" rows="2" spellcheck="false" autocapitalize="off" autocomplete="off"
        placeholder="مثال: name.account.workers.dev"></textarea>
      <div class="warnbox">⚠️ دقت کنید آدرس home page نیست!<br>فقط دامنه‌ی SNI را وارد کنید (اگر لینک کامل بگذاری، دامنه‌اش جدا می‌شود).</div>
      <div class="msg" id="bSniHint"></div>

      <label for="bUuid">UUID را وارد کنید</label>
      <input type="text" id="bUuid" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
      <div class="msg" id="bUuidHint"></div>

      <label for="bIps">clean IP ها را وارد کنید 🎗</label>
      <textarea id="bIps" spellcheck="false" autocapitalize="off" placeholder="104.16.10.20&#10;172.64.33.5&#10;188.114.99.29"></textarea>
      <div class="msg" id="bIpsHint"></div>

      <label for="bName">نام سرویس</label>
      <input type="text" id="bName" placeholder="🎋 TEST">

      <div class="row">
        <div><label for="bPort">پورت</label>
          <select id="bPort">
            <option>443</option><option>2053</option><option>2083</option><option>2087</option><option>2096</option><option>8443</option>
            <option>80</option><option>8080</option><option>8880</option><option>2052</option><option>2082</option><option>2086</option><option>2095</option>
          </select></div>
      </div>

      <div class="row"><button class="go" id="build">🔥 ساخت کانفیگ‌ها</button></div>
      <div class="msg" id="buildMsg"></div>
    </div>

    <div class="card" id="outCard" hidden>
      <h2>🎋 کانفیگ‌های آماده</h2>
      <div class="row">
        <button class="small blue" id="copyAll">📋 کپی همه</button>
        <button class="small blue" id="dl">💾 دانلود فایل</button>
      </div>
      <div id="outList"></div>
    </div>
  </section>

  <div class="links">
    <a href="https://github.com/sunio-team" target="_blank" rel="noopener">GitHub</a>
    <a href="https://t.me/sunio_team" target="_blank" rel="noopener">Telegram</a>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
(() => {
'use strict';
const $ = (id) => document.getElementById(id);
const HARD = 5000;
const TLS = [443, 2053, 2083, 2087, 2096, 8443];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UUID_FIND = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const HOST_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const fa = (n) => Number(n).toLocaleString('fa-IR');

let mode = 'repo', repoCount = 0, jobId = null, since = 0, results = [], timer = null, total = 0, limit = 60;

/* ---------- small utils ---------- */
function store(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
function load(k) { try { return localStorage.getItem(k) || ''; } catch (e) { return ''; } }
function toast(msg) {
  const t = $('toast'); t.textContent = msg; t.classList.add('on');
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('on'), 1800);
}
async function copy(text, msg) {
  try { await navigator.clipboard.writeText(text); }
  catch (e) { const a = document.createElement('textarea'); a.value = text; document.body.appendChild(a); a.select(); document.execCommand('copy'); a.remove(); }
  toast(msg || 'کپی شد ✓');
}
function setMsg(id, text, cls) { const el = $(id); el.textContent = text || ''; el.className = 'msg ' + (cls || ''); }
function esc(s) { return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

function isIPv4(s) { const p = s.split('.'); return p.length === 4 && p.every((x) => /^\d{1,3}$/.test(x) && +x <= 255); }
function isIPv6(s) { return s.includes(':') && /^[0-9a-f:.]+$/i.test(s) && s.length >= 3; }
function isTarget(s) { return isIPv4(s) || isIPv6(s) || HOST_RE.test(s); }
function parseList(text) {
  const seen = new Set(), valid = []; let bad = 0;
  (text || '').replace(/#.*/g, '').split(/[\s,;]+/).forEach((raw) => {
    const s = raw.trim().replace(/^\[|\]$/g, '');
    if (!s) return;
    if (!isTarget(s)) { bad++; return; }
    const k = s.toLowerCase();
    if (!seen.has(k)) { seen.add(k); valid.push(k); }
  });
  return { valid, bad };
}
function parseSni(v) {
  v = (v || '').trim().split(/\s+/)[0] || '';
  if (!v) return { host: '', uuid: '' };
  let host = '', uuid = '';
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : 'https://' + v);
    host = u.hostname.toLowerCase();
    const m = decodeURIComponent(u.pathname).match(UUID_FIND);
    if (m) uuid = m[0].toLowerCase();
  } catch (e) { host = v.toLowerCase(); }
  return { host, uuid };
}

/* ---------- ember background ---------- */
(() => {
  const c = $('embers'), x = c.getContext('2d'); let w, h;
  const dpr = Math.min(devicePixelRatio || 1, 2);
  const size = () => { w = c.width = innerWidth * dpr; h = c.height = innerHeight * dpr; };
  addEventListener('resize', size); size();
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const mk = (init) => ({ x: Math.random() * w, y: init ? Math.random() * h : h + 10, r: (Math.random() * 2.4 + .7) * dpr, v: (Math.random() * .8 + .3) * dpr, ph: Math.random() * 6.28, a: Math.random() * .5 + .3 });
  const P = Array.from({ length: Math.min(60, Math.round(innerWidth / 9)) }, () => mk(true));
  (function tick(t) {
    x.clearRect(0, 0, w, h);
    for (const p of P) {
      p.y -= p.v; p.x += Math.sin(t / 900 + p.ph) * .5 * dpr;
      if (p.y < -10) Object.assign(p, mk(false));
      const k = p.y / h;
      x.beginPath(); x.arc(p.x, p.y, p.r, 0, 6.283);
      x.fillStyle = 'rgba(255,' + Math.round(200 * k + 40) + ',60,' + (p.a * (.35 + k * .65)) + ')';
      x.shadowColor = '#ffb020'; x.shadowBlur = 12 * dpr; x.fill();
    }
    requestAnimationFrame(tick);
  })(0);
})();

/* ---------- tabs ---------- */
document.querySelectorAll('[data-tab]').forEach((b) => b.onclick = () => showTab(b.dataset.tab));
function showTab(t) {
  document.querySelectorAll('[data-tab]').forEach((b) => b.classList.toggle('on', b.dataset.tab === t));
  $('tab-scan').style.display = t === 'scan' ? 'flex' : 'none';
  $('tab-build').style.display = t === 'build' ? 'flex' : 'none';
  scrollTo({ top: 0, behavior: 'smooth' });
}

/* ---------- source toggle ---------- */
document.querySelectorAll('[data-src]').forEach((b) => b.onclick = () => {
  mode = b.dataset.src;
  document.querySelectorAll('[data-src]').forEach((x) => x.classList.toggle('on', x === b));
  $('srcRepo').style.display = mode === 'repo' ? 'flex' : 'none';
  $('srcManual').style.display = mode === 'manual' ? 'flex' : 'none';
});

/* ---------- repo ---------- */
async function loadRepo(force) {
  setMsg('repoInfo', '⏳ در حال دریافت لیست از مخزن...', 'info');
  try {
    const r = await fetch('/api/repo' + (force ? '?refresh=1' : '')); const j = await r.json();
    if (!j.ok) { repoCount = 0; setMsg('repoInfo', '⚠️ ' + j.message, 'err'); return; }
    repoCount = j.count;
    let t = '📦 در مخزن ' + fa(j.count) + ' آیپی یکتا موجود است.';
    if (j.cached) t += ' — از حافظه‌ی ذخیره‌شده خوانده شد.';
    setMsg('repoInfo', t, 'ok');
    $('countLabel').textContent = 'چند آیپی اسکن شود؟ (حداکثر ' + fa(repoCount) + ')';
    $('count').max = repoCount; buildChips(); checkCount(); $('manual').oninput();
  } catch (e) { setMsg('repoInfo', '⚠️ ارتباط با برنامه قطع شد.', 'err'); }
}
$('repoRefresh').onclick = () => loadRepo(true);

function maxAllowed() { return repoCount || HARD; }
function buildChips() {
  const box = $('chips'); box.innerHTML = '';
  const add = (n, label) => {
    const b = document.createElement('button'); b.textContent = label || fa(n);
    b.onclick = () => { $('count').value = n; checkCount(); };
    box.appendChild(b);
  };
  [10, 50, 100, 500].forEach((n) => { if (n < repoCount) add(n); });
  if (repoCount) add(repoCount, 'همه (' + fa(repoCount) + ')');
}
function checkCount() {
  const n = parseInt($('count').value, 10);
  if (!n || n < 1) { setMsg('countMsg', ''); return true; }
  if (repoCount && n > repoCount) { setMsg('countMsg', '⚠️ حداکثر ' + fa(repoCount) + ' آیپی است', 'err'); return false; }
  setMsg('countMsg', ''); return true;
}
$('count').oninput = checkCount;

/* ---------- manual ---------- */
$('manual').oninput = () => {
  const { valid, bad } = parseList($('manual').value);
  if (!valid.length && !bad) return setMsg('manualMsg', '');
  if (valid.length > maxAllowed()) return setMsg('manualMsg', '⚠️ حداکثر ' + fa(maxAllowed()) + ' آیپی است (الان ' + fa(valid.length) + ' تا وارد کردی)', 'err');
  setMsg('manualMsg', '✅ ' + fa(valid.length) + ' آیپی معتبر' + (bad ? ' — ' + fa(bad) + ' خط نامعتبر نادیده گرفته شد' : ''), bad ? 'info' : 'ok');
};

/* ---------- SNI ---------- */
function sniHint(inputId, hintId, uuidTarget) {
  const p = parseSni($(inputId).value);
  if (!$(inputId).value.trim()) return setMsg(hintId, '');
  if (!p.host || !HOST_RE.test(p.host)) return setMsg(hintId, '⚠️ دامنه‌ی معتبر پیدا نشد', 'err');
  setMsg(hintId, '✅ SNI: ' + p.host + (p.uuid ? '  |  UUID هم شناسایی شد' : ''), 'ok');
  if (p.uuid && uuidTarget && !$(uuidTarget).value.trim()) { $(uuidTarget).value = p.uuid; store('ph_uuid', p.uuid); }
  store('ph_sni', p.host);
}
$('sni').oninput = () => { sniHint('sni', 'sniHint', 'bUuid'); };
$('bSni').oninput = () => { sniHint('bSni', 'bSniHint', 'bUuid'); };

/* ---------- scan ---------- */
async function startScan() {
  setMsg('startMsg', '');
  const p = parseSni($('sni').value);
  if (!p.host || !HOST_RE.test(p.host)) return setMsg('startMsg', '⚠️ اول SNI را وارد کن', 'err');
  const body = { sni: p.host, port: +$('port').value, timeout: +$('timeout').value || 4, conc: +$('conc').value || 40, source: mode };
  if (mode === 'repo') {
    const n = parseInt($('count').value, 10);
    if (!n || n < 1) return setMsg('startMsg', '⚠️ تعداد آیپی را وارد کن', 'err');
    if (!repoCount) return setMsg('startMsg', '⚠️ لیست مخزن دریافت نشده؛ بروزرسانی را بزن یا دستی وارد کن', 'err');
    if (n > repoCount) { checkCount(); return setMsg('startMsg', '⚠️ حداکثر ' + fa(repoCount) + ' آیپی است', 'err'); }
    body.count = n; body.random = $('rand').checked;
  } else {
    const { valid } = parseList($('manual').value);
    if (!valid.length) return setMsg('startMsg', '⚠️ حداقل یک آیپی وارد کن', 'err');
    if (valid.length > maxAllowed()) return setMsg('startMsg', '⚠️ حداکثر ' + fa(maxAllowed()) + ' آیپی است', 'err');
    body.ips = valid.join('\n');
  }
  store('ph_sni', p.host);
  $('start').disabled = true;
  try {
    const r = await fetch('/api/scan', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json();
    if (!r.ok || !j.ok) { $('start').disabled = false; return setMsg('startMsg', '⚠️ ' + (j.message || 'خطا'), 'err'); }
    jobId = j.id; total = j.total; since = 0; results = []; limit = 60;
    $('progCard').hidden = false; $('stop').hidden = false; $('progBox').classList.add('running');
    $('list').innerHTML = ''; $('statusLine').textContent = '🔎 در حال اسکن ' + fa(total) + ' آیپی...';
    updateStats({ done: 0, counts: { ws: 0, http: 0, fail: 0 } });
    $('progCard').scrollIntoView({ behavior: 'smooth' });
    clearTimeout(timer); tick();
  } catch (e) { $('start').disabled = false; setMsg('startMsg', '⚠️ ارتباط با برنامه قطع شد', 'err'); }
}
$('start').onclick = startScan;
$('stop').onclick = async () => { if (jobId) { try { await fetch('/api/scan/' + jobId + '/stop', { method: 'POST' }); } catch (e) {} } };

async function tick() {
  if (!jobId) return;
  let j;
  try { const r = await fetch('/api/scan/' + jobId + '?since=' + since); j = await r.json(); } catch (e) { timer = setTimeout(tick, 1500); return; }
  since = j.next; results.push(...j.results);
  updateStats(j); render();
  if (j.state !== 'running') {
    $('start').disabled = false; $('stop').hidden = true; $('progBox').classList.remove('running');
    const ws = j.counts.ws, ok = ws + j.counts.http;
    $('statusLine').textContent = (j.state === 'done' ? '🏁 اسکن تمام شد' : '⏹ اسکن متوقف شد') + ' — ' + fa(ws) + ' آیپی سالم، ' + fa(ok) + ' قابل‌دسترس (' + j.elapsed + ' ثانیه)';
    return;
  }
  timer = setTimeout(tick, 700);
}
function updateStats(j) {
  const pct = total ? Math.round((j.done / total) * 100) : 0;
  $('pct').textContent = pct + '%'; $('cnt').textContent = j.done + ' / ' + total;
  $('ringFg').style.strokeDashoffset = 100 - pct;
  $('stWs').textContent = j.counts.ws; $('stHttp').textContent = j.counts.http; $('stFail').textContent = j.counts.fail;
  const best = results.filter((r) => r.status !== 'fail').reduce((m, r) => Math.min(m, r.ms), Infinity);
  $('stBest').textContent = isFinite(best) ? best + 'ms' : '—';
}
const rank = { ws: 0, http: 1, fail: 2 };
function sorted() {
  const showFail = $('showFail').checked;
  return results.filter((r) => showFail || r.status !== 'fail').sort((a, b) => rank[a.status] - rank[b.status] || (a.ms ?? 1e9) - (b.ms ?? 1e9));
}
function render() {
  const s = sorted();
  $('list').innerHTML = s.slice(0, limit).map((r) => {
    const bd = r.status === 'ws' ? '✅ WS' : r.status === 'http' ? '🟡 HTTP ' + r.code : '❌ ' + esc(r.err || 'fail');
    return '<div class="res ' + r.status + '"><span class="ip">' + esc(r.ip) + '</span><span class="bd">' + bd + (r.cf ? ' ☁️' : '') + '</span><span class="ms">' + (r.ms == null ? '' : r.ms + 'ms') + '</span></div>';
  }).join('');
  $('more').hidden = s.length <= limit;
}
$('more').onclick = () => { limit += 100; render(); };
$('showFail').onchange = render;

function bestIps() {
  const ws = results.filter((r) => r.status === 'ws');
  const pool = ws.length ? ws : results.filter((r) => r.status === 'http');
  return pool.sort((a, b) => a.ms - b.ms).map((r) => r.ip);
}
$('copyOk').onclick = () => {
  const ips = bestIps(); if (!ips.length) return toast('هنوز آیپی سالمی پیدا نشده');
  copy(ips.join('\n'), fa(ips.length) + ' آیپی کپی شد ✓');
};
$('toBuild').onclick = () => {
  const ips = bestIps(); if (!ips.length) return toast('هنوز آیپی سالمی پیدا نشده');
  $('bIps').value = ips.join('\n'); $('bIps').oninput();
  const p = parseSni($('sni').value); if (p.host) { $('bSni').value = p.host; sniHint('bSni', 'bSniHint', 'bUuid'); }
  showTab('build'); toast(fa(ips.length) + ' آیپی منتقل شد ✓');
};

/* ---------- builder ---------- */
$('bUuid').oninput = () => {
  const v = $('bUuid').value.trim();
  if (!v) return setMsg('bUuidHint', '');
  if (UUID_RE.test(v)) { setMsg('bUuidHint', '✅ UUID معتبر است', 'ok'); store('ph_uuid', v.toLowerCase()); }
  else setMsg('bUuidHint', '⚠️ فرمت UUID درست نیست', 'err');
};
$('bIps').oninput = () => {
  const { valid, bad } = parseList($('bIps').value);
  if (!valid.length && !bad) return setMsg('bIpsHint', '');
  setMsg('bIpsHint', '✅ ' + fa(valid.length) + ' آیپی معتبر' + (bad ? ' — ' + fa(bad) + ' خط نامعتبر نادیده گرفته می‌شود' : ''), bad ? 'info' : 'ok');
};
$('bName').oninput = () => store('ph_name', $('bName').value);

function link(addr, port, host, uuid, name, tls) {
  const a = addr.includes(':') ? '[' + addr + ']' : addr;
  const q = new URLSearchParams({ encryption: 'none', security: tls ? 'tls' : 'none', type: 'ws', host: host, path: '/?ed=2048' });
  if (tls) { q.set('sni', host); q.set('fp', 'randomized'); q.set('alpn', 'http/1.1'); }
  return 'vless://' + uuid + '@' + a + ':' + port + '?' + q.toString() + '#' + encodeURIComponent(name);
}
let built = [];
$('build').onclick = () => {
  setMsg('buildMsg', '');
  const p = parseSni($('bSni').value);
  if (!p.host || !HOST_RE.test(p.host)) return setMsg('buildMsg', '⚠️ SNI را درست وارد کن', 'err');
  const uuid = ($('bUuid').value.trim() || p.uuid).toLowerCase();
  if (!UUID_RE.test(uuid)) return setMsg('buildMsg', '⚠️ UUID را درست وارد کن', 'err');
  $('bUuid').value = uuid;
  const { valid } = parseList($('bIps').value);
  if (!valid.length) return setMsg('buildMsg', '⚠️ حداقل یک clean IP وارد کن', 'err');
  const base = $('bName').value.trim() || 'Phoenix';
  const port = +$('bPort').value, tls = TLS.includes(port);
  built = valid.map((ip, i) => { const name = base + ' - ' + (i + 1); return { name, link: link(ip, port, p.host, uuid, name, tls) }; });
  $('outList').innerHTML = '';
  built.forEach((c) => {
    const d = document.createElement('div'); d.className = 'cfg';
    d.innerHTML = '<div class="top"><b></b><button class="small">کپی</button></div><code></code>';
    d.querySelector('b').textContent = c.name; d.querySelector('code').textContent = c.link;
    d.querySelector('button').onclick = () => copy(c.link);
    $('outList').appendChild(d);
  });
  $('outCard').hidden = false; $('outCard').scrollIntoView({ behavior: 'smooth' });
  setMsg('buildMsg', '✅ ' + fa(built.length) + ' کانفیگ ساخته شد', 'ok');
  store('ph_sni', p.host); store('ph_uuid', uuid); store('ph_name', $('bName').value);
};
$('copyAll').onclick = () => { if (built.length) copy(built.map((c) => c.link).join('\n'), fa(built.length) + ' کانفیگ کپی شد ✓'); };
$('dl').onclick = () => {
  if (!built.length) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([built.map((c) => c.link).join('\n')], { type: 'text/plain' }));
  a.download = 'phoenix-configs.txt'; document.body.appendChild(a); a.click(); a.remove();
};

/* ---------- init ---------- */
const s0 = load('ph_sni'), u0 = load('ph_uuid'), n0 = load('ph_name');
if (s0) { $('sni').value = s0; $('bSni').value = s0; sniHint('sni', 'sniHint'); sniHint('bSni', 'bSniHint'); }
if (u0) { $('bUuid').value = u0; $('bUuid').oninput(); }
if (n0) $('bName').value = n0;
loadRepo(false);
})();
</script>
</body>
</html>
"""


# ============================================================
#  Main
# ============================================================
def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    srv, port = None, PORT
    for p in range(PORT, PORT + 10):
        try:
            srv = ThreadingHTTPServer((HOST, p), Handler)
            port = p
            break
        except OSError:
            continue
    if srv is None:
        print("[X] Could not bind to %s:%d (port busy). Close the old instance and retry." % (HOST, PORT))
        sys.exit(1)
    srv.daemon_threads = True

    url = "http://%s:%d" % (HOST, port)
    print("\n\033[1;33m  Phoenix IP Scanner\033[0m  -  Sunio Team")
    print("  ------------------------------------------")
    if port != PORT:
        print("  \033[1;33m[!]\033[0m Port %d was busy, using %d instead." % (PORT, port))
    print("  Open this address in your browser:\n")
    print("      \033[1;37m%s\033[0m\n" % url)
    print("  Press Ctrl+C to stop.\n")

    if shutil.which("termux-open-url"):
        try:
            subprocess.Popen(["termux-open-url", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Bye!")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()

