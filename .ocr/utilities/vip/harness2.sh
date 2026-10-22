#!/bin/bash
set -uo pipefail
BASH_SOURCE=("/home/tristan/gitters/LME/scripts/wipe_lme.sh")
_wipe_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
LME_MANIFESTS_DIR="${LME_MANIFESTS_DIR:-${_wipe_script_dir}/../manifests}"

# LME_SVC_NAMES  -- host-facing (loopback-VIP) services; SCOPES the reset in 4b and
#                   is cleared there. Derived to match the publisher exactly.
# LME_MANIFEST_NAMES -- EVERY service manifest's VIP name; used ONLY by the 6d
#                   residue cross-check (never to reset), so a derivation miss cannot
#                   silently orphan a VIP.
LME_SVC_NAMES=()
LME_MANIFEST_NAMES=()

# Top-level VIP name of a manifest: `tailnet_service` if set, else `id`. Anchored at
# column 0 (top-level key) and stripped of any inline `# comment`, so e.g.
# `id: elasticsearch  # logical key` yields exactly `elasticsearch`. Format-immune
# (a top-level scalar, not the nested publish_ports list).
_wipe_manifest_name() {
  local _n
  _n=$(sed -nE 's/^tailnet_service:[[:space:]]*([^[:space:]#]+).*/\1/p' "$1" | head -n1)
  [ -n "$_n" ] || _n=$(sed -nE 's/^id:[[:space:]]*([^[:space:]#]+).*/\1/p' "$1" | head -n1)
  printf '%s' "$_n"
}

if [ -d "${LME_MANIFESTS_DIR}/services" ]; then
  # Same PyYAML-on-PATH convention the rest of the repo uses to read manifests.
  export PATH="$PATH:/nix/var/nix/profiles/default/bin"

  # --- Host-facing set (LME_SVC_NAMES) -------------------------------------------
  # PRIMARY: a real YAML parse. ATOMIC -- any unreadable/malformed manifest aborts
  # the whole derivation (non-zero exit) so we fall back rather than emit a partial
  # (silently incomplete) set. Reproduces the publisher's host-facing filter.
  _svc_out=""
  # stderr suppressed: a malformed manifest makes this exit non-zero and we DEGRADE
  # to the fallback below (quiet by design -- a stray parse traceback mid-teardown
  # would read like a wipe error; the fallback + 6d cross-check still guard it).
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1 \
     && _svc_out=$(python3 - "${LME_MANIFESTS_DIR}/services" 2>/dev/null <<'PY'
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
    name = doc.get("tailnet_service") or doc.get("id")
    if name and name not in seen:
        seen.add(name)
        out.append(str(name))
print("\n".join(out))
PY
     ); then
    mapfile -t LME_SVC_NAMES < <(printf '%s\n' "$_svc_out" | grep -v '^[[:space:]]*$' || true)
  else
    # FALLBACK (no PyYAML): scope to the top-level `publish_ports:` block and test for
    # a loopback bind INSIDE it. Format-agnostic (flow AND block) and inclusive-safe
    # (an over-match only clears an svc that was never advertised -- a no-op). The
    # block scope replaces the old flow-anchor's job of not false-positiving a stray
    # 127.0.0.1 comment elsewhere in the file.
    for _mf in "${LME_MANIFESTS_DIR}"/services/*.yml; do
      [ -e "$_mf" ] || continue
      # In-block == after the top-level `publish_ports:` key and before the next
      # top-level MAPPING key. A leading `-` is a list-item marker, NOT a block end
      # (block-style entries can sit at column 0, e.g. `- host: 9200`), so the end
      # pattern excludes `-` as well as spaces and `#`.
      awk '/^publish_ports:/{inb=1;next} inb && /^[^[:space:]#-]/{inb=0} inb' "$_mf" \
        | grep -q '127\.0\.0\.1' || continue
      _svc=$(_wipe_manifest_name "$_mf")
      [ -n "$_svc" ] && LME_SVC_NAMES+=("$_svc")
    done
  fi

  # --- Full manifest-name set (LME_MANIFEST_NAMES) -------------------------------
  # EVERY manifest's top-level VIP name -- the weaker, format-immune predicate the 6d
  # residue check uses so an advertised svc:<name> the host-facing derivation MISSED
  # is still recognised as LME-owned and fails closed. NEVER used to reset: a generic
  # id (network/lme) could collide with a co-tenant, and here a collision only prints
  # a residue FAILURE, never a destructive reset.
  for _mf in "${LME_MANIFESTS_DIR}"/services/*.yml; do
    [ -e "$_mf" ] || continue
    _mn=$(_wipe_manifest_name "$_mf")
    [ -n "$_mn" ] && LME_MANIFEST_NAMES+=("$_mn")
  done
fi
echo "SVC(${#LME_SVC_NAMES[@]}): ${LME_SVC_NAMES[*]:-<empty>}"
echo "MAN(${#LME_MANIFEST_NAMES[@]})"
