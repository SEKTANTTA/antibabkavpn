#!/usr/bin/env python3
"""АнтиБабкаВПН — сборщик подписки.

Берёт список vless-серверов из zieng2/wl, убирает дубли, даёт понятные названия,
делит на группы (ИИ / белые списки / обычные блокировки / только РФ) и
собирает Clash Meta (mihomo) конфиги с авто-выбором лучшего сервера.

Запуск:  python3 -I build.py <файл1[,файл2=bl,...]> <папка_вывода> [--allow-insecure] [--alive probe.json]

--alive: результат probe.py; нерабочие зарубежные серверы «только для блокировок» убираются,
страна берётся по реальному выходу, внутри страны сервера идут от быстрых к медленным.
"""
import json
import sys
from urllib.parse import urlsplit, parse_qs, unquote, quote

BRAND = "АнтиБабкаВПН"

COUNTRIES = {
    "RU": "Россия", "BY": "Беларусь", "KZ": "Казахстан", "DE": "Германия",
    "NL": "Нидерланды", "FI": "Финляндия", "FR": "Франция", "GB": "Великобритания",
    "IT": "Италия", "LT": "Литва", "PL": "Польша", "SE": "Швеция",
    "CH": "Швейцария", "US": "США", "LV": "Латвия", "EE": "Эстония",
    "TR": "Турция", "ID": "Индонезия", "VN": "Вьетнам", "IN": "Индия", "KR": "Корея", "TW": "Тайвань", "BR": "Бразилия", "AU": "Австралия", "PT": "Португалия", "GR": "Греция", "CY": "Кипр", "LU": "Люксембург", "BE": "Бельгия", "IS": "Исландия", "SK": "Словакия", "SI": "Словения", "HR": "Хорватия", "AZ": "Азербайджан", "UZ": "Узбекистан", "KG": "Кыргызстан", "MX": "Мексика", "AR": "Аргентина", "ZA": "ЮАР", "BG": "Болгария", "CA": "Канада", "CZ": "Чехия", "ES": "Испания", "RO": "Румыния", "HU": "Венгрия", "MD": "Молдова", "UA": "Украина", "RS": "Сербия", "HK": "Гонконг", "JP": "Япония", "SG": "Сингапур", "AE": "ОАЭ", "IL": "Израиль", "IE": "Ирландия", "NO": "Норвегия", "DK": "Дания", "AM": "Армения", "GE": "Грузия", "AT": "Австрия",
}

# Страны, где ИИ-сервисы (ChatGPT, Claude, Gemini...) недоступны или ограничены
NO_AI = {"RU", "BY"}

AI_DOMAINS = [
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "sora.com",
    "anthropic.com", "claude.ai", "claude.com",
    "gemini.google.com", "aistudio.google.com", "ai.google.dev", "bard.google.com",
    "generativelanguage.googleapis.com", "notebooklm.google.com", "labs.google",
    "perplexity.ai", "copilot.microsoft.com", "x.ai", "grok.com",
    "midjourney.com", "huggingface.co", "poe.com", "character.ai",
    "mistral.ai", "cursor.com", "cursor.sh", "openrouter.ai", "groq.com",
    "elevenlabs.io", "runwayml.com", "suno.com", "replicate.com", "stability.ai",
    "cohere.com", "together.ai", "meta.ai", "lmarena.ai",
]

RU_DIRECT_DOMAINS = [
    "ru", "su", "xn--p1ai", "yandex.net", "yandex.com", "ya.ru", "yastatic.net",
    "vk.com", "vk.me", "userapi.com", "vkuser.net", "ok.ru", "mail.ru", "sber.ru",
    "tinkoff.ru", "gosuslugi.ru", "mos.ru", "avito.st", "ozon.ru", "wb.ru",
]

TEST_URL = "http://www.gstatic.com/generate_204"


def flag_to_code(s):
    chars = [c for c in s[:4] if 0x1F1E6 <= ord(c) <= 0x1F1FF]
    if len(chars) >= 2:
        return "".join(chr(ord(c) - 0x1F1E6 + 65) for c in chars[:2])
    return "XX"


def first(q, key, default=""):
    v = q.get(key)
    return v[0] if v else default


def parse_link(line):
    line = line.strip()
    if not line.startswith("vless://"):
        return None
    try:
        u = urlsplit(line)
        q = parse_qs(u.query, keep_blank_values=True)
        frag = unquote(u.fragment)
        if not u.hostname or not u.port or not u.username:
            return None
        return {
            "raw": line, "uuid": u.username, "host": u.hostname, "port": u.port,
            "q": q, "frag": frag, "cc": flag_to_code(frag),
            "sec": first(q, "security", "none"),
            "net": {"raw": "tcp", "tcp": "tcp"}.get(first(q, "type", "tcp"), first(q, "type", "tcp")),
        }
    except Exception:
        return None


def dedup_key(n):
    q = n["q"]
    return (n["host"], n["port"], n["uuid"], n["sec"], n["net"], first(q, "sni"),
            first(q, "pbk"), first(q, "sid"), first(q, "serviceName"),
            first(q, "path"), first(q, "host"), first(q, "mode"))


def label(n):
    sec = {"reality": "Reality", "tls": "TLS", "none": "без шифр."}.get(n["sec"], n["sec"])
    net = {"tcp": "TCP", "grpc": "gRPC", "ws": "WS", "xhttp": "XHTTP"}.get(n["net"], n["net"])
    return f"{sec}-{net}"


def purpose(n):
    wl = " · 📶 Белые списки" if n.get("wl", True) else ""
    if n["cc"] == "RU":
        return "📶 Белые списки"
    if n["cc"] in NO_AI:
        return "🌍 Блокировки" + wl
    return "🤖 ИИ · 🌍 Блокировки" + wl


def clash_proxy(n):
    q = n["q"]
    p = {
        "name": n["name"], "type": "vless", "server": n["host"], "port": n["port"],
        "uuid": n["uuid"], "udp": True, "network": n["net"],
    }
    flow = first(q, "flow").replace("-udp443", "")
    if flow:
        p["flow"] = flow
    if n["sec"] in ("tls", "reality"):
        p["tls"] = True
        p["client-fingerprint"] = first(q, "fp", "chrome")
        if first(q, "sni"):
            p["servername"] = first(q, "sni")
        if first(q, "alpn"):
            p["alpn"] = first(q, "alpn").split(",")
        p["skip-cert-verify"] = n.get("insecure", False)
    if n["sec"] == "reality":
        p["reality-opts"] = {"public-key": first(q, "pbk"), "short-id": first(q, "sid")}
    if n["net"] == "grpc":
        p["grpc-opts"] = {"grpc-service-name": first(q, "serviceName")}
    elif n["net"] == "ws":
        o = {"path": first(q, "path", "/")}
        h = first(q, "host") or first(q, "sni")
        if h:
            o["headers"] = {"Host": h}
        p["ws-opts"] = o
    elif n["net"] == "xhttp":
        o = {"path": first(q, "path", "/"), "mode": first(q, "mode", "auto")}
        h = first(q, "host") or first(q, "sni")
        if h:
            o["host"] = h
        p["xhttp-opts"] = o
    return p


def clash_ok(n):
    """В Clash берём только то, что mihomo точно умеет."""
    if n["net"] not in ("tcp", "grpc", "ws", "xhttp"):
        return False
    if n["net"] == "xhttp":
        extra = first(n["q"], "extra")
        if extra not in ("", "null"):
            return False  # сложные xhttp-настройки есть только в обычной подписке
    if n["sec"] == "reality" and not first(n["q"], "pbk"):
        return False
    return True


def header(title, desc):
    return (f"#profile-title: {title}\n#profile-update-interval: 1\n"
            f"#profile-web-page-url: https://github.com/zieng2/wl\n#description: {desc}\n")


def write_sub(path, title, desc, nodes):
    with open(path, "w", encoding="utf-8") as f:
        f.write(header(title, desc))
        for n in nodes:
            f.write(n["new_link"] + "\n")


def build_clash(mode, nodes):
    cl = [n for n in nodes if clash_ok(n)]
    proxies = [clash_proxy(n) for n in cl]
    names_all = [p["name"] for p in proxies]
    names_wl = [n["name"] for n in cl if n.get("wl", True)]
    names_ai = [n["name"] for n in cl if n["cc"] not in NO_AI]
    names_reg = [n["name"] for n in cl if n["cc"] != "RU"]
    names_ru = [n["name"] for n in cl if n["cc"] == "RU"]

    def ut(name, lst):
        return {"name": name, "type": "url-test", "proxies": lst or ["DIRECT"],
                "url": TEST_URL, "interval": 180, "tolerance": 50, "lazy": False}

    g_auto, g_ai, g_wl, g_reg, g_ru = ("🤖 АВТО (зарубежные)", "🧠 ИИ-авто",
                                       "📶 Белые списки-авто", "🌍 Обычные блокировки-авто",
                                       "🇷🇺 Только РФ-авто")
    main = f"🚀 {BRAND}"
    order = [g_reg, g_auto, g_wl, g_ai, g_ru]
    groups = [
        {"name": main, "type": "select", "proxies": order + ["🖐 Выбрать вручную", "DIRECT"]},
        ut(g_reg, names_reg), ut(g_auto, names_reg), ut(g_wl, names_wl),
        ut(g_ai, names_ai), ut(g_ru, names_ru),
        {"name": "🖐 Выбрать вручную", "type": "select", "proxies": names_all or ["DIRECT"]},
    ]
    rules = [
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    ]
    rules += [f"DOMAIN-SUFFIX,{d},{g_ai}" for d in AI_DOMAINS]
    if mode == "regular":
        rules += [f"DOMAIN-SUFFIX,{d},DIRECT" for d in RU_DIRECT_DOMAINS]
        rules.append("GEOIP,RU,DIRECT")
    rules.append(f"MATCH,{main}")
    cfg = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "warning",
        "ipv6": False,
        "dns": {"enable": True, "enhanced-mode": "fake-ip",
                "nameserver": ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"],
                "default-nameserver": ["1.1.1.1", "8.8.8.8"]},
        "proxies": proxies, "proxy-groups": groups, "rules": rules,
    }
    return cfg, len(proxies)


def strip_none(o):
    if isinstance(o, dict):
        return {k: strip_none(v) for k, v in o.items() if v is not None}
    if isinstance(o, list):
        return [strip_none(v) for v in o]
    return o


def xray_outbound(n, tag):
    q = n["q"]
    user = {"id": n["uuid"], "encryption": "none"}
    flow = first(q, "flow").replace("-udp443", "")
    if flow:
        user["flow"] = flow
    ss = {"network": n["net"], "security": n["sec"] if n["sec"] in ("tls", "reality") else "none"}
    if n["sec"] == "reality":
        ss["realitySettings"] = {
            "serverName": first(q, "sni"), "fingerprint": first(q, "fp", "chrome"),
            "publicKey": first(q, "pbk"), "shortId": first(q, "sid"),
            "spiderX": first(q, "spx", "/"),
        }
    elif n["sec"] == "tls":
        t = {"fingerprint": first(q, "fp", "chrome"), "allowInsecure": n.get("insecure", False)}
        if first(q, "sni"):
            t["serverName"] = first(q, "sni")
        if first(q, "alpn"):
            t["alpn"] = first(q, "alpn").split(",")
        ss["tlsSettings"] = t
    if n["net"] == "grpc":
        ss["grpcSettings"] = {"serviceName": first(q, "serviceName")}
    elif n["net"] == "ws":
        w = {"path": first(q, "path", "/")}
        h = first(q, "host") or first(q, "sni")
        if h:
            w["headers"] = {"Host": h}
        ss["wsSettings"] = w
    elif n["net"] == "xhttp":
        x = {"path": first(q, "path", "/"), "mode": first(q, "mode", "auto")}
        h = first(q, "host") or first(q, "sni")
        if h:
            x["host"] = h
        extra = first(q, "extra")
        if extra not in ("", "null"):
            try:
                x["extra"] = json.loads(extra)
            except ValueError:
                pass
        ss["xhttpSettings"] = x
    return strip_none({"tag": tag, "protocol": "vless",
                       "settings": {"vnext": [{"address": n["host"], "port": n["port"], "users": [user]}]},
                       "streamSettings": ss})


def xray_config(remarks, nodes, ai_routing=False):
    """Один конфиг Xray. Все узлы в одном балансировщике leastPing = авто-сервер."""
    outs = []
    for i, n in enumerate(nodes, 1):
        tag = ("node-ai-" if n["cc"] not in NO_AI else "node-ru-") + str(i)
        outs.append(xray_outbound(n, tag))
    outs += [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]
    balancers = [{"tag": "auto", "selector": ["node-"], "strategy": {"type": "leastPing"}}]
    rules = []
    if ai_routing and any(n["cc"] not in NO_AI for n in nodes):
        balancers.append({"tag": "auto-ai", "selector": ["node-ai-"], "strategy": {"type": "leastPing"}})
        rules.append({"type": "field", "domain": [f"domain:{d}" for d in AI_DOMAINS],
                      "balancerTag": "auto-ai"})
    rules.append({"type": "field", "network": "tcp,udp", "balancerTag": "auto"})
    return {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"udp": True},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
            {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http"},
        ],
        "outbounds": outs,
        "routing": {"domainStrategy": "AsIs", "balancers": balancers, "rules": rules},
        "burstObservatory": {"subjectSelector": ["node-"],
                             "pingConfig": {"destination": TEST_URL, "interval": "1m",
                                            "sampling": 3, "timeout": "5s"}},
    }


def build_xray_sub(nodes):
    """Подписка Xray JSON: сверху авто-конфиги, ниже каждый сервер отдельно."""
    ai = [n for n in nodes if n["cc"] not in NO_AI]
    reg = [n for n in nodes if n["cc"] != "RU"]
    items = [
        xray_config(f"🌍 АВТО Обычные блокировки — {BRAND}", reg),
        xray_config(f"🤖 АВТО (зарубежные, ИИ отдельно) — {BRAND}", reg, ai_routing=True),
        xray_config(f"📶 АВТО Белые списки — {BRAND}", [n for n in nodes if n.get("wl", True)]),
        xray_config(f"🧠 АВТО ИИ — {BRAND}", ai),
    ]
    items = [c for c in items if len(c["outbounds"]) > 2]
    for n in nodes:
        c = xray_config(n["name"], [n])
        c["routing"]["balancers"] = []
        c["routing"]["rules"] = [{"type": "field", "network": "tcp,udp",
                                  "outboundTag": c["outbounds"][0]["tag"]}]
        c.pop("burstObservatory")
        items.append(c)
    return items


def dump_yaml(cfg, comment):
    try:
        import yaml
        body = yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False, width=10000)
    except ImportError:
        body = json.dumps(cfg, ensure_ascii=False, indent=2)  # JSON — тоже валидный YAML
    return comment + body


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    src, out = sys.argv[1], sys.argv[2]
    allow_insecure = "--allow-insecure" in sys.argv
    import os
    os.makedirs(out, exist_ok=True)

    parsed = []
    for item in src.split(","):
        path, _, kind = item.partition("=")
        with open(path, encoding="utf-8") as f:
            for l in f:
                if not l.strip() or l.startswith("#"):
                    continue
                n = parse_link(l)
                if not n:
                    continue
                n["wl"] = kind != "bl"
                parsed.append(n)
    total_lines = len(parsed)
    # мусор: служебные заглушки, узлы без флага страны, российские узлы из списка «только блокировки»
    parsed = [n for n in parsed
              if n["host"] not in ("0.0.0.0", "127.0.0.1") and n["uuid"] != "warning"
              and n["cc"] != "XX" and (n["wl"] or n["cc"] != "RU")]
    dropped_insecure = 0
    seen, nodes = set(), []
    for n in parsed:
        if n["sec"] == "none" and not allow_insecure:
            dropped_insecure += 1
            continue
        k = dedup_key(n)
        if k in seen:
            if n["wl"]:
                for m in nodes:
                    if dedup_key(m) == k:
                        m["wl"] = True
            continue
        seen.add(k)
        n["insecure"] = allow_insecure
        nodes.append(n)

    dropped_dead = 0
    if "--alive" in sys.argv:
        alive = json.load(open(sys.argv[sys.argv.index("--alive") + 1], encoding="utf-8"))
        kept = []
        for n in nodes:
            r = alive.get("|".join(map(str, dedup_key(n))))
            n["ms"] = r["ms"] if r and r.get("ok") else 99999
            if r and r.get("ok"):
                ex = (r.get("exit") or "").upper()
                if len(ex) == 2 and ex.isalpha():
                    n["cc"] = ex
                kept.append(n)
            elif n["wl"] or n["cc"] == "RU":
                kept.append(n)  # белые-списки-серверы из-за границы не проверить честно: оставляем
            else:
                dropped_dead += 1
        nodes = kept

    # сортируем: РФ сначала (стабильнее при белых списках), потом по странам
    nodes.sort(key=lambda n: (n["cc"] == "RU", COUNTRIES.get(n["cc"], n["cc"]), n.get("ms", 0)))
    counters = {}
    for n in nodes:
        counters[n["cc"]] = counters.get(n["cc"], 0) + 1
        flag = "".join(chr(0x1F1E6 + ord(c) - 65) for c in n["cc"]) if n["cc"] != "XX" else "🌐"
        n["name"] = f"{flag} {COUNTRIES.get(n['cc'], n['cc'])} #{counters[n['cc']]} · {purpose(n)}"
        n["new_link"] = n["raw"].split("#", 1)[0] + "#" + quote(n["name"], safe="")

    ai = [n for n in nodes if n["cc"] not in NO_AI]
    reg = [n for n in nodes if n["cc"] != "RU"]
    ru = [n for n in nodes if n["cc"] == "RU"]

    write_sub(f"{out}/all.txt", f"{BRAND} — всё сразу", "Все серверы", nodes)
    write_sub(f"{out}/whitelist.txt", f"{BRAND} — белые списки", "Серверы для обхода белых списков", [n for n in nodes if n.get("wl", True)])
    write_sub(f"{out}/ai.txt", f"{BRAND} — ИИ", "Зарубежные серверы для ChatGPT, Claude, Gemini", ai)
    write_sub(f"{out}/regular.txt", f"{BRAND} — обычные блокировки", "Зарубежные серверы для YouTube, Instagram и т.д.", reg)
    write_sub(f"{out}/ru_only.txt", f"{BRAND} — только РФ", "Российские серверы", ru)

    for mode, fname, title in (("whitelist", "clash_whitelist.yaml", "белые списки"),
                               ("regular", "clash_regular.yaml", "обычные блокировки")):
        cfg, cnt = build_clash(mode, nodes)
        comment = (f"# {BRAND} — режим «{title}»\n"
                   f"# Клиент: Clash Meta / Mihomo (Clash Verge Rev, FlClash, Karing, Hiddify, Stash)\n"
                   f"# Серверов в конфиге: {cnt}. Группа «🤖 АВТО» сама выбирает самый быстрый.\n")
        with open(f"{out}/{fname}", "w", encoding="utf-8") as f:
            f.write(dump_yaml(cfg, comment))

    xray_items = build_xray_sub(nodes)
    with open(f"{out}/auto.json", "w", encoding="utf-8") as f:
        json.dump(xray_items, f, ensure_ascii=False, indent=2)

    stats = {"строк в источнике": total_lines, "конфигов в auto.json": len(xray_items), "разобрано": len(parsed),
             "убрано без шифрования": dropped_insecure, "убрано нерабочих": dropped_dead, "после дедупа": len(nodes),
             "ИИ": len(ai), "обычные блокировки": len(reg), "РФ": len(ru)}
    with open(f"{out}/stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
