import glob, os, sys
try:
    import yaml
except Exception:
    sys.exit(3)
seen, out = set(), []
for path in sorted(glob.glob(os.path.join(sys.argv[1], "*.yml"))):
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        continue
    ports = doc.get("publish_ports") or []
    # host-facing == >=1 loopback (bind 127.0.0.1), non-UDP publish_port. Mirrors
    # tailscale_service.yml's _ts_loop (bind==127.0.0.1) + _ts_lo (protocol!=udp).
    if not any(isinstance(p, dict) and p.get("bind") == "127.0.0.1"
               and p.get("protocol") != "udp" for p in ports):
        continue
    # Opt-in ONLY: mirror the publisher's `when: item.value.tailnet_service is
    # defined` gate and its NO-id-fallback naming -- a service without the key is
    # NOT fronted as a VIP, so skip it here too (never fall back to the bare id).
    name = doc.get("tailnet_service")
    if not name:
        continue
    if name and name not in seen:
        seen.add(name)
        out.append(str(name))
print("\n".join(out))
