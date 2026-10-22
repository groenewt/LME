#!/usr/bin/env python3
import os, re, sys
sys.path.insert(0, os.path.dirname(__file__))
import render_test as R

ROOT = '/home/tristan/gitters/LME'
QUADLET = os.path.join(ROOT, 'quadlet')

# map service id -> static quadlet filename
CONTAINERS = ['elasticsearch','kibana','wazuh-manager','fleet-server','fleet-distribution',
              'dashboard','log-analyzer','llama-cpp','embeddings','pgvector','logstash',
              'filebeat','metricbeat','heartbeat','apm-server','elastalert','litellm']

def directives(text):
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith('#') or s.startswith('['):
            continue
        # strip inline annotation corruption like 'Value #@@TODO...'
        out.append(s)
    return out

def norm(d):
    # collapse whitespace inside a directive value for fair compare
    return re.sub(r'\s+', ' ', d.strip())

for sid in CONTAINERS:
    static_path = os.path.join(QUADLET, f'lme-{sid}.container')
    if not os.path.exists(static_path):
        print(f"[{sid}] NO STATIC FILE")
        continue
    rendered = R.render(sid, 'default')
    stat = open(static_path).read()
    rd = set(norm(x) for x in directives(rendered))
    sd = set(norm(x) for x in directives(stat))
    only_static = sorted(sd - rd)   # in static, MISSING from render (possible drop)
    only_render = sorted(rd - sd)   # in render, not in static (added/changed)
    print(f"===== {sid} =====")
    if only_static:
        print("  MISSING FROM RENDER (present in static quadlet):")
        for x in only_static: print("    -", x)
    if only_render:
        print("  ONLY IN RENDER (not in static quadlet):")
        for x in only_render: print("    +", x)
    if not only_static and not only_render:
        print("  IDENTICAL directive set")
