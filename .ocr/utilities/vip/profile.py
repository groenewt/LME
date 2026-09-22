import sys
try:
    import yaml
except Exception:
    sys.exit(3)
ports = set()
def add(h):
    if isinstance(h, bool): return
    if isinstance(h, int): ports.add(h)
    elif isinstance(h, str) and h.strip().isdigit(): ports.add(int(h.strip()))
def walk(n):
    if isinstance(n, dict):
        if 'host' in n and str(n.get('bind')) == '0.0.0.0': add(n['host'])
        for v in n.values(): walk(v)
    elif isinstance(n, list):
        for v in n: walk(v)
try:
    with open(sys.argv[1]) as fh: walk(yaml.safe_load(fh))
except Exception:
    sys.exit(3)
for p in sorted(ports): print(p)
