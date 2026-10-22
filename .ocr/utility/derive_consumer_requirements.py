#!/usr/bin/env python3
"""
derive_consumer_requirements.py -- manifest-driven evidence engine for the LME
multi-machine consumer split (run-14 design lane).

Given a set of CONSUMER service ids (default: log-analyzer, dashboard), it:
  1. loads every manifests/services/*.yml,
  2. computes the transitive requires+wants closure => the full set of backend
     services a host running those consumers must reach cross-host,
  3. for each backend leg derives: published port(s)+bind, whether it terminates
     its OWN TLS, the app scheme (https / postgres / plaintext), its cert SAN
     (network_aliases), whether a consumer needs the CA to trust it, and the
     recommended tailnet front (raw-tcp passthrough vs https ingress),
  4. unions the secrets each consumer declares, and
  5. DIFFS the derived requirement set against the GAP-1..4 coverage baseline
     (routing={elasticsearch}, tls={elasticsearch}, secrets={elastic,
     litellm_master_key}) and prints the UNCOVERED set.

Output is Markdown on stdout. This is evidence, not prose: every value is read
from a manifest, nothing is hand-asserted.

READ-ONLY. Never writes to manifests/ or ansible/.
"""
import glob
import os
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("FATAL: PyYAML not available (pip install pyyaml)\n")
    sys.exit(2)

# --- GAP-1..4 coverage baseline (what the ES+litellm-centric anchoring covered) ---
BASELINE_ROUTING = {"elasticsearch"}
BASELINE_TLS = {"elasticsearch"}
BASELINE_SECRETS = {"elastic", "litellm_master_key"}

DEFAULT_CONSUMERS = ["log-analyzer", "dashboard"]
SKIP_KINDS = {"network", "volume"}


def repo_root():
    env = os.environ.get("LME_REPO_ROOT")
    if env:
        return env
    # .ocr/utility/<this file>  ->  parents[2] == repo root
    return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def load_manifests(services_dir):
    mans = {}
    for path in sorted(glob.glob(os.path.join(services_dir, "*.yml"))):
        try:
            with open(path) as fh:
                doc = yaml.safe_load(fh)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write("WARN: could not parse %s: %s\n" % (path, exc))
            continue
        if isinstance(doc, dict) and doc.get("id"):
            mans[doc["id"]] = doc
    return mans


def _deps(m, keys):
    d = (m.get("dependencies") or {})
    out = []
    for k in keys:
        out.extend(d.get(k) or [])
    return out


def closure(cid, mans, keys):
    """Transitive closure following the given dependency keys; excludes cid."""
    seen, stack = set(), [cid]
    while stack:
        x = stack.pop()
        m = mans.get(x)
        if not m:
            continue
        for dep in _deps(m, keys):
            if dep not in seen:
                seen.add(dep)
                stack.append(dep)
    return seen


def consumer_url_scheme(backend, consumers):
    """If a consumer env references this backend's alias with a URL, return the scheme."""
    aliases = list(backend.get("network_aliases") or [])
    if backend.get("name"):
        aliases.append(backend["name"])
    for c in consumers:
        for _, v in (c.get("environment") or {}).items():
            if not isinstance(v, str):
                continue
            for a in aliases:
                if a and a in v:
                    if v.startswith("https://"):
                        return "https"
                    if v.startswith("http://"):
                        return "http"
    return None


def env_refs(backend, consumers):
    """Consumers whose env actually ADDRESSES this backend (URL or *_HOST on its
    network_alias) -> proof the consumer opens a socket to it cross-host."""
    aliases = list(backend.get("network_aliases") or [])
    if backend.get("name"):
        aliases.append(backend["name"])
    hits = []
    for c in consumers:
        for k, v in (c.get("environment") or {}).items():
            if isinstance(v, str) and any(a and a in v for a in aliases):
                hits.append((c.get("id"), k))
    return hits


def serves_own_tls(m):
    env = m.get("environment") or {}
    for k, v in env.items():
        if "ssl" in str(k).lower() and str(v).strip().lower() in ("true", "1", "yes", "on"):
            return True
    ex = m.get("exec") or ""
    for tok in ("--ssl-cert-file", "--ssl-certfile", "sslCertFile", "--ssl-key-file", "ssl-keyfile"):
        if tok in ex:
            return True
    return False


def is_postgres(m):
    if str(m.get("image", "")).lower().find("pgvector") >= 0 or m.get("id") == "pgvector":
        return True
    for p in (m.get("publish_ports") or []):
        if p.get("host") == 5432:
            return True
    return "postgres" in str(m.get("exec", "")).lower()


def app_scheme(m, consumers):
    sch = consumer_url_scheme(m, consumers)
    if sch in ("https", "http"):
        return sch
    if serves_own_tls(m):
        return "https"
    if is_postgres(m):
        return "postgres-plaintext"
    return "plaintext"


def tailnet_front(scheme, own_tls):
    # own-TLS backend must pass raw bytes (--tcp) so the internal-CA leaf survives.
    if own_tls:
        return "raw-tcp (serve:tcp) -- backend terminates its own TLS"
    if scheme.startswith("postgres"):
        return "raw-tcp (serve:tcp) -- Postgres wire; tailnet WireGuard is the transport encryption"
    return "https (tailnet_ingress:https) -- terminate at tailnet"


def ports_str(m):
    out = []
    for p in (m.get("publish_ports") or []):
        out.append("%s:%s" % (p.get("host"), p.get("bind", "?")))
    return ", ".join(out) or "-"


def secrets_of(m):
    out = []
    for s in (m.get("secrets") or []):
        out.append((s.get("name"), s.get("target")))
    return out


def main():
    consumers_ids = sys.argv[1:] or DEFAULT_CONSUMERS
    root = repo_root()
    services_dir = os.path.join(root, "manifests", "services")
    mans = load_manifests(services_dir)

    missing = [c for c in consumers_ids if c not in mans]
    if missing:
        sys.stderr.write("FATAL: consumer id(s) not found in manifests: %s\n" % ", ".join(missing))
        sys.exit(1)

    consumers = [mans[c] for c in consumers_ids]

    # per-consumer hard (requires-only) and full (requires+wants) closures
    hard_cl = {c: closure(c, mans, ["requires"]) for c in consumers_ids}
    full_cl = {c: closure(c, mans, ["requires", "wants"]) for c in consumers_ids}

    # Cross-host legs are the consumer's DIRECT (depth-1) deps that (a) are a
    # container, (b) publish a port, and (c) are actually ADDRESSED by a consumer
    # env var. A transitive dep behind a remoted backend (e.g. llama-cpp behind
    # litellm) stays co-located on the producer and is NOT a consumer leg -- the
    # naive full closure over-scopes, so we do not use it for legs.
    dreq = {c: set(_deps(mans[c], ["requires"])) for c in consumers_ids}
    dwant = {c: set(_deps(mans[c], ["wants"])) for c in consumers_ids}
    candidates = set()
    for c in consumers_ids:
        candidates |= dreq[c] | dwant[c]

    legs, excluded = [], []
    for b in sorted(candidates):
        m = mans.get(b)
        if not m:
            excluded.append((b, "no manifest"))
            continue
        if m.get("kind") != "container":
            excluded.append((b, "kind=%s (not a network service)" % m.get("kind")))
            continue
        refs = env_refs(m, consumers)
        has_port = bool(m.get("publish_ports"))
        if refs and has_port:
            legs.append(b)
        else:
            why = []
            if not refs:
                why.append("no consumer env addresses it (systemd ordering only)")
            if not has_port:
                why.append("no publish_ports")
            excluded.append((b, "; ".join(why)))

    # transitive-only deps the FULL closure adds but no consumer directly reaches
    transitive_only = sorted((set().union(*full_cl.values()) if full_cl else set())
                             - set(consumers_ids) - candidates)

    def required_by(bid):
        out = []
        for c in consumers_ids:
            if bid in dreq[c]:
                out.append("%s(hard)" % c)
            elif bid in dwant[c]:
                out.append("%s(soft)" % c)
        return ", ".join(out)

    print("# Consumer cross-host requirement matrix (manifest-derived)")
    print()
    print("_Generated by `.ocr/utility/derive_consumer_requirements.py` — consumers: %s_" % ", ".join(consumers_ids))
    print()

    print("## Consumers (the UI hosts)")
    print()
    print("| id | dep model | needs_ca | inbound port:bind |")
    print("|----|-----------|----------|-------------------|")
    for c in consumers_ids:
        m = mans[c]
        d = m.get("dependencies") or {}
        model = []
        if d.get("requires"):
            model.append("requires%s" % d["requires"])
        if d.get("wants"):
            model.append("wants%s" % d["wants"])
        needs_ca = (m.get("certs") or {}).get("needs_ca", False)
        print("| %s | %s | %s | %s |" % (c, "; ".join(model) or "-", needs_ca, ports_str(m)))
    print()

    print("## Backend legs — direct, env-addressed deps the host must reach (kind=container)")
    print()
    print("| id | port:bind | own_TLS | app_scheme | SAN (network_aliases) | tailnet_front | required_by |")
    print("|----|-----------|---------|-----------|-----------------------|---------------|-------------|")
    tls_needed = set()
    for b in legs:
        m = mans[b]
        own = serves_own_tls(m)
        sch = app_scheme(m, consumers)
        san = ", ".join(m.get("network_aliases") or []) or "-"
        front = tailnet_front(sch, own)
        if own:
            tls_needed.add(b)
        print("| %s | %s | %s | %s | %s | %s | %s |" % (
            b, ports_str(m), own, sch, san, front, required_by(b)))
    print()

    print("## NOT consumer-crossing legs (scoping guard — why the closure over-counts)")
    print()
    print("| dep | why it is NOT a cross-host leg |")
    print("|-----|--------------------------------|")
    for b, why in excluded:
        print("| %s | %s |" % (b, why))
    for b in transitive_only:
        km = mans.get(b, {}).get("kind", "?")
        print("| %s | transitive-only (kind=%s): reached by a remoted backend, not by the consumer — stays co-located on the producer |" % (b, km))
    print()

    # union of secrets across consumers (what the host must hold cross-host)
    sec_needed = {}
    for c in consumers:
        for name, target in secrets_of(c):
            sec_needed.setdefault(name, {"targets": set(), "by": set()})
            sec_needed[name]["targets"].add(target)
            sec_needed[name]["by"].add(c.get("id"))

    print("## Secrets the consumer host must hold (union across consumers)")
    print()
    print("| secret | env target(s) | needed_by |")
    print("|--------|---------------|-----------|")
    for name in sorted(sec_needed):
        info = sec_needed[name]
        print("| %s | %s | %s |" % (
            name, ", ".join(sorted(t for t in info["targets"] if t)), ", ".join(sorted(info["by"]))))
    print()

    # --- coverage diff against the GAP-1..4 baseline ---
    routing_needed = set(legs)
    secrets_needed = set(sec_needed.keys())

    unc_routing = routing_needed - BASELINE_ROUTING
    unc_tls = tls_needed - BASELINE_TLS
    unc_secrets = secrets_needed - BASELINE_SECRETS

    print("## GAP-1..4 baseline coverage DIFF (the under-scoping, in evidence)")
    print()
    print("Baseline covered by the anchored GAP-1..4: routing=%s · tls=%s · secrets=%s" % (
        sorted(BASELINE_ROUTING), sorted(BASELINE_TLS), sorted(BASELINE_SECRETS)))
    print()
    print("- **UNCOVERED routing** (backend legs with no tailnet marker designed): `%s`" % sorted(unc_routing))
    print("- **UNCOVERED TLS** (own-TLS internal-CA legs needing CA/SAN trust, minus ES): `%s`" % sorted(unc_tls))
    print("- **UNCOVERED secrets** (needed cross-host, not in GAP-4 set): `%s`" % sorted(unc_secrets))
    print()
    print("_Note: litellm routing/TLS is separately banked as the ts.net-terminated `svc:lme-litellm`"
          " VIP (public-CA, no ca.crt distribution); pgvector serves plaintext Postgres (no own-TLS),"
          " so its cross-host confidentiality rides the tailnet WireGuard, not app TLS._")


if __name__ == "__main__":
    main()
