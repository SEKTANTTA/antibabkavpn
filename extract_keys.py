#!/usr/bin/env python3
"""Достаёт vless-ссылки из keys.json (tiagorrg/vless-checker) в обычный текстовый список.
python3 extract_keys.py keys.json out.txt"""
import json
import sys

out = []


def walk(o):
    if isinstance(o, dict):
        for v in o.values():
            walk(v)
    elif isinstance(o, list):
        for v in o:
            walk(v)
    elif isinstance(o, str):
        out.extend(x.strip() for x in o.split("\n") if x.startswith("vless://"))


walk(json.load(open(sys.argv[1], encoding="utf-8")))
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(dict.fromkeys(out)) + "\n")
