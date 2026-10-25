#!/usr/bin/env python3
"""Проверка серверов через Xray: поднимаем socks-вход на каждый сервер и ходим через него
на Cloudflare trace. Успех = HTTP 200 и в ответе есть loc=XX (страна выхода).

python3 -I probe.py <xray_bin> <build.py> <out.json> <файл1> [файл2 ...]
(необязательно) GEMINI_API_KEY в окружении — тогда Gemini проверяется реальным запросом
"""
import json, os, subprocess, sys, tempfile, time, importlib.util
from concurrent.futures import ThreadPoolExecutor

xray_bin, build_py, out_json, *files = sys.argv[1:]
spec = importlib.util.spec_from_file_location("b", build_py)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

nodes, seen = [], set()
for p in files:
    for l in open(p, encoding="utf-8"):
        n = b.parse_link(l)
        if not n or n["host"] == "0.0.0.0" or n["uuid"] == "warning":
            continue
        if n["sec"] == "none":
            continue
        k = b.dedup_key(n)
        if k in seen:
            continue
        seen.add(k)
        n["key"] = "|".join(map(str, k))
        nodes.append(n)

BASE = 31000
cfg = {"log": {"loglevel": "none"}, "inbounds": [], "outbounds": [], "routing": {"rules": []}}
for i, n in enumerate(nodes):
    cfg["inbounds"].append({"tag": f"in{i}", "listen": "127.0.0.1", "port": BASE + i,
                            "protocol": "socks", "settings": {"udp": False}})
    cfg["outbounds"].append(b.xray_outbound(n, f"out{i}"))
    cfg["routing"]["rules"].append({"type": "field", "inboundTag": [f"in{i}"], "outboundTag": f"out{i}"})
cfg["outbounds"].append({"tag": "direct", "protocol": "freedom"})

d = tempfile.mkdtemp(prefix="probe-")
cpath = os.path.join(d, "c.json")
json.dump(cfg, open(cpath, "w"))
proc = subprocess.Popen([xray_bin, "run", "-c", cpath], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
time.sleep(3)
if proc.poll() is not None:
    print("xray упал:", proc.stderr.read().decode()[:800])
    sys.exit(2)


GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
BLOCK_MARKERS = ("location is not supported", "isn't currently supported", "not supported in your country",
                 "not available in your country", "isn’t currently supported")


def via(i, args, timeout=20):
    r = subprocess.run(["curl", "-sSL", "--socks5-hostname", f"127.0.0.1:{BASE + i}", "-m", "15",
                        "-w", "\n%{http_code} %{url_effective}"] + args,
                       capture_output=True, text=True, timeout=timeout)
    body, _, tail = r.stdout.rpartition("\n")
    code, _, url = tail.partition(" ")
    return code, url, body


def gemini_ok(i):
    """Открывается ли Gemini через этот сервер (смотрит Google на IP выхода сервера).
    С GEMINI_API_KEY — реальный запрос к API (надёжно). Без ключа — проверка отказа по региону."""
    try:
        if GEMINI_KEY:
            code, _, body = via(i, ["-H", "Content-Type: application/json", "-d",
                                    json.dumps({"contents": [{"parts": [{"text": "ok"}]}]}),
                                    "https://generativelanguage.googleapis.com/v1beta/models/"
                                    f"gemini-flash-latest:generateContent?key={GEMINI_KEY}"])
            low = body.lower()
            if any(m in low for m in BLOCK_MARKERS):
                return False
            return code in ("200", "429")  # 429 = лимит ключа, регион пропущен
        code, _, body = via(i, ["https://generativelanguage.googleapis.com/v1beta/models?key=invalid"])
        if any(m in body.lower() for m in BLOCK_MARKERS) or code not in ("200", "400", "401", "403"):
            return False
        code, url, body = via(i, ["https://gemini.google.com/app"])
        if any(m in body.lower() for m in BLOCK_MARKERS) or code != "200" or "google.com" not in url:
            return False
        return True
    except Exception:
        return False


def test(i):
    n = nodes[i]
    best = None
    for attempt in range(2):
        try:
            r = subprocess.run(
                ["curl", "-sS", "--socks5-hostname", f"127.0.0.1:{BASE + i}", "-m", "14",
                 "-w", "\n%{http_code} %{time_total}", "https://www.cloudflare.com/cdn-cgi/trace"],
                capture_output=True, text=True, timeout=20)
            body, _, tail = r.stdout.rpartition("\n")
            code, _, t = tail.partition(" ")
            if code == "200" and "loc=" in body:
                loc = [x[4:] for x in body.split("\n") if x.startswith("loc=")][0]
                ms = int(float(t) * 1000)
                if best is None or ms < best["ms"]:
                    best = {"ok": True, "ms": ms, "exit": loc}
                break
        except Exception:
            pass
    if best:
        best["gemini"] = gemini_ok(i) if best["exit"] not in b.NO_AI else False
    return n["key"], best or {"ok": False}


with ThreadPoolExecutor(48) as ex:
    res = dict(ex.map(test, range(len(nodes))))
proc.terminate()
json.dump(res, open(out_json, "w"), ensure_ascii=False, indent=1)
ok = sum(1 for v in res.values() if v["ok"])
gem = sum(1 for v in res.values() if v.get("gemini"))
print(f"проверено {len(res)}, работает {ok}, Gemini открывается через {gem}")
