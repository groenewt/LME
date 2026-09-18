#!/bin/bash
# Fully uninstall LME from THIS host: stop/disable units, remove containers,
# volumes, secrets, images, unit files, /opt/lme, /etc/lme, and tailscale serve
# ingress state -- then SELF-VERIFY the host is clean and FAIL if any residue
# remains. Safe to run before a fresh install (a host with nothing installed
# verifies clean and exits 0).
#
# SCOPE: single-node, host-local teardown only. Multi-node / inventory-wide
# teardown (iterating an Ansible inventory to wipe every cluster member) is NOT
# implemented here -- follow-up if cluster-wide wipe is needed. This script only
# touches the machine it runs on.
#
# WHY NOT `set -e`: the previous version set `set -e` but suffixed every op with
# `|| true`, so `-e` was inert and the script printed "Wipe complete" / exited 0
# even on a dirty host. Teardown is DELIBERATELY tolerant (a unit that was never
# loaded, an already-absent path, etc. are expected and non-fatal). Correctness
# is enforced by the strict SELF-VERIFY block at the very end -- that is the
# authoritative gate and the only thing that decides the exit code. `set -u`
# catches unset-var bugs; `pipefail` keeps piped probes honest; `-e` is
# intentionally omitted so an expected no-op cannot abort the teardown.
set -uo pipefail

PODMAN="sudo -i podman"

# --------------------------------------------------------------------------
# LME-OWNED tailscale serve identity (Finding A). The teardown must reset ONLY
# serve/Service entries LME itself created and must NEVER touch a co-tenant's
# serves on a shared node -- e.g. the operator's own svc:windows11 /
# svc:vncserverwindow. BOTH the reset (step 4) and the residue self-verify
# (step 6d) read THESE arrays, so "what LME owns" is defined in exactly one place
# and the two lists cannot drift apart (the drift is how this bug came back).
#
#   * Node-scoped ingress serves (ansible/roles/podman/tasks/tailscale_ingress.yml):
#     apm-server :8200 (https), litellm :4000 (https) and logstash beats :5044
#     (raw --tcp). These are the ONLY node-scoped serves LME publishes.
#   * VIP Services (tailscale_service.yml): svc:<name> for each enabled host-facing
#     LME service. That leg DERIVES the name from each manifest (its optional
#     `tailnet_service`, else its `id`) and publishes one only for a service that
#     declares a loopback (bind:127.0.0.1) publish_port. Matched by EXACT name, so a
#     non-LME svc:<name> is never reset or counted as residue.
LME_SERVE_HTTPS_PORTS=(8200 4000)            # node-scoped HTTPS ingress fronts
LME_SERVE_TCP_PORTS=(5044)                   # node-scoped raw-TCP ingress front
LME_SERVE_NODE_PORTS=(8200 4000 5044)        # every node-scoped LME serve port

# svc:<name> VIPs LME may publish. DERIVED at runtime from the SAME source the
# publisher (ansible/roles/podman/tasks/tailscale_service.yml) reads -- never a
# hand-maintained list. A hardcoded copy DRIFTS from the manifests, and it did:
# embeddings / fleet-distribution / pgvector / wazuh-manager were published as VIPs
# but absent from the old static list, so teardown orphaned them yet reported clean.
# We reproduce the publisher's derivation straight from manifests/services/*.yml:
# svc name = the manifest's `tailnet_service` (else its `id`); "host-facing" = it
# declares at least one loopback (bind:127.0.0.1) publish_port. The set therefore
# contains ONLY LME service ids by construction -- a co-tenant's svc:<name>
# (svc:windows11 / svc:vncserverwindow / svc:webui) can never appear in it and is
# never cleared. Teardown is deliberately inclusive of every service that COULD
# carry a loopback VIP under any profile (we do NOT re-apply the per-profile enable
# gate): clearing an svc that was never advertised is a safe no-op, whereas missing
# one leaves an orphaned VIP -- the exact bug this fixes. BOTH the reset (step 4b)
# and the residue self-verify (step 6d) read this one array, so the two can never
# drift from each other, and now neither can drift from the manifests.
#
# LME_MANIFESTS_DIR mirrors the ansible `lme_manifests_dir` var; it defaults to the
# manifests tree beside this script's repo checkout (scripts/ and manifests/ are
# siblings at the repo root, and wipe_lme.sh is always invoked from that checkout).
_wipe_script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
LME_MANIFESTS_DIR="${LME_MANIFESTS_DIR:-${_wipe_script_dir}/../manifests}"
LME_SVC_NAMES=()
if [ -d "${LME_MANIFESTS_DIR}/services" ]; then
  for _mf in "${LME_MANIFESTS_DIR}"/services/*.yml; do
    [ -e "$_mf" ] || continue
    # host-facing == advertises at least one loopback publish_port. Match the
    # flow-style publish_ports entry ( `- {host: N, ..., bind: 127.0.0.1}` ) so a
    # stray comment that merely mentions 127.0.0.1 cannot false-positive a service
    # that publishes nothing on loopback.
    grep -qE '^[[:space:]]*-[[:space:]]*\{.*bind:[[:space:]]*127\.0\.0\.1' "$_mf" || continue
    # svc name = top-level `tailnet_service` if the manifest sets one, else its
    # top-level `id`. Anchored at column 0 (top-level key) and stripped of any
    # inline `# comment` so e.g. `id: elasticsearch  # logical key` yields exactly
    # `elasticsearch`.
    _svc=$(sed -nE 's/^tailnet_service:[[:space:]]*([^[:space:]#]+).*/\1/p' "$_mf" | head -n1)
    [ -n "$_svc" ] || _svc=$(sed -nE 's/^id:[[:space:]]*([^[:space:]#]+).*/\1/p' "$_mf" | head -n1)
    [ -n "$_svc" ] && LME_SVC_NAMES+=("$_svc")
  done
fi

# --------------------------------------------------------------------------
# 1. Stop AND disable every lme unit -- enumerated robustly (cwd-independent).
#    We DO NOT use a bare shell glob (`systemctl stop lme*`); from the repo
#    root that expands against directory names and stops almost nothing. The
#    'lme*' pattern below is QUOTED and matched by systemd itself, not the
#    shell, so it works from any working directory. We union three sources:
#      - loaded units          (systemctl list-units)
#      - installed unit files  (systemctl list-unit-files, catches .path/.timer)
#      - an explicit safety net (the .path watchers + their services, the
#        network-generated service, and the hand-written lme.service)
# --------------------------------------------------------------------------
if command -v systemctl >/dev/null 2>&1; then
  mapfile -t LME_UNITS < <(
    {
      systemctl list-units --all --plain --no-legend 'lme*' 2>/dev/null | awk '{print $1}'
      systemctl list-unit-files --no-legend 'lme*' 2>/dev/null | awk '{print $1}'
      printf '%s\n' \
        lme-llm-keys.path      lme-llm-keys.service \
        lme-llama-model.path   lme-llama-model.service \
        lme.service            lme-network.service    lme.network
    } | sort -u
  )

  if [ "${#LME_UNITS[@]}" -gt 0 ]; then
    echo "Stopping ${#LME_UNITS[@]} lme unit(s) (path watchers first, then services)..."
    # Stop .path watchers before their .service so a watcher cannot re-trigger
    # a service we are tearing down. Stopping everything covers both.
    for u in "${LME_UNITS[@]}"; do
      sudo systemctl stop "$u" 2>/dev/null || true
    done
    echo "Disabling lme unit(s) (removes .wants symlinks)..."
    for u in "${LME_UNITS[@]}"; do
      sudo systemctl disable "$u" 2>/dev/null || true
    done
  fi
fi

# --------------------------------------------------------------------------
# 2. Stop/remove all containers, then remove volumes, secrets, images.
#    (Keep the aggressive `rm -a` steps: LME secrets are NOT lme-prefixed --
#    they are named elastic/wazuh/wazuh_api/kibana_system/pgvector/llm-keys
#    plus per-user names -- so they can only be cleared wholesale.)
# --------------------------------------------------------------------------
echo "Stopping and removing all containers..."
$PODMAN stop -a 2>/dev/null || true
$PODMAN rm -af 2>/dev/null || true

echo "Removing volumes, secrets, and images..."
$PODMAN volume rm -a 2>/dev/null || true
$PODMAN secret rm -a 2>/dev/null || true
$PODMAN image prune -af 2>/dev/null || true

# --------------------------------------------------------------------------
# 3. Remove quadlet/systemd unit files AND both config trees.
# --------------------------------------------------------------------------
echo "Removing LME quadlet and systemd unit files..."
sudo rm -f /etc/containers/systemd/lme-*.container
sudo rm -f /etc/containers/systemd/lme-*.volume
sudo rm -f /etc/containers/systemd/lme-*.network
sudo rm -f /etc/containers/systemd/lme.network
sudo rm -f /etc/containers/systemd/lme.service
sudo rm -f /etc/containers/networks/lme.json
sudo rm -f /etc/systemd/system/lme-*.service
sudo rm -f /etc/systemd/system/lme-*.path
sudo rm -f /etc/systemd/system/lme-*.timer
sudo rm -f /etc/systemd/system/lme.service
# Enable symlinks under */.wants are removed by the `systemctl disable` loop in
# step 1; any that survive are caught by the list-unit-files probe in 6a.

echo "Removing /opt/lme and /etc/lme..."
sudo rm -rf /opt/lme
# /etc/lme holds the Ansible vault, pass.sh (0700) and version file -- the old
# script never removed it, so secrets survived a "full" wipe. Remove it.
sudo rm -rf /etc/lme

# 3b. Remove the ANSIBLE_VAULT_PASSWORD_FILE export that setup_passwords.yml
#     appends to /root/.profile AND /root/.bashrc. It points at /etc/lme/pass.sh
#     (just deleted). Left behind, the NEXT fresh install inherits it from the
#     shell env and ansible-playbook aborts at STARTUP -- "The vault password file
#     /etc/lme/pass.sh was not found" -- before the base role can recreate it. So a
#     wipe that skipped this silently broke every teardown->reinstall on the host.
echo "Removing ANSIBLE_VAULT_PASSWORD_FILE export from root shell profiles..."
for _rc in /root/.profile /root/.bashrc; do
  [ -f "$_rc" ] && sudo sed -i '/export ANSIBLE_VAULT_PASSWORD_FILE=/d' "$_rc" 2>/dev/null || true
done

# --------------------------------------------------------------------------
# 4. Reset ONLY LME-owned tailscale serve/ingress state (Finding A). A blanket
#    `tailscale serve reset` would also wipe a co-tenant's serve/Service config on
#    a shared node, so LME removes its specific node-scoped ports and its own
#    svc:<name> VIPs by exact identity. A blanket reset is used ONLY as a last
#    resort, and only on a host that has NO non-LME serve config to protect.
#    Guarded on the binary being present.
# --------------------------------------------------------------------------
if command -v tailscale >/dev/null 2>&1; then
  echo "Resetting LME-owned tailscale serve/ingress config (co-tenant serves left intact)..."

  # 4a. Remove LME node-scoped serve handlers by EXACT port. `--https/--tcp <port>
  #     off` targets just that handler; it never touches svc:* Services or a non-LME
  #     node handler bound to a different port.
  for _p in "${LME_SERVE_HTTPS_PORTS[@]}"; do
    sudo tailscale serve --https="$_p" off 2>/dev/null || true
  done
  for _p in "${LME_SERVE_TCP_PORTS[@]}"; do
    sudo tailscale serve --tcp="$_p" off 2>/dev/null || true
  done

  # 4b. Remove ONLY LME-owned Tailscale Service VIPs. Enumerate what is actually
  #     advertised, intersect with the LME name set, and clear JUST those. We never
  #     iterate-and-reset every svc:* (that is exactly what used to destroy the
  #     operator's svc:windows11). `clear` removes all handlers for the service; the
  #     older per-service `reset` spelling is a fallback for builds without `clear`.
  if _present_svcs=$(sudo tailscale serve status 2>/dev/null \
                     | grep -oE 'svc:[A-Za-z0-9._-]+' | sort -u); then
    for _svc in $_present_svcs; do
      _name=${_svc#svc:}
      for _lme in "${LME_SVC_NAMES[@]}"; do
        if [ "$_name" = "$_lme" ]; then
          # `clear` arg form varies (svc:<name> vs bare <name>); try both, then the
          # older per-service `reset` spelling, so a scoped removal actually lands.
          sudo tailscale serve clear "$_svc" 2>/dev/null \
            || sudo tailscale serve clear "$_name" 2>/dev/null \
            || sudo tailscale serve --service="$_svc" reset 2>/dev/null || true
          break
        fi
      done
    done
  fi

  # 4c. Last-resort blanket reset, ONLY on a host with nothing else to lose. If LME
  #     node serves survived 4a (e.g. a tailscale build whose serve has no `... off`
  #     target) AND the node advertises NO non-LME serve entry at all, a blanket
  #     reset is provably harmless and keeps the B2 teardown gate passable. If ANY
  #     non-LME entry is present we NEVER reset -- surviving LME node residue is left
  #     to the fail-closed self-verify (6d) rather than risk a co-tenant's config.
  if _serve_now=$(sudo tailscale serve status 2>/dev/null); then
    _lme_node_left=""
    for _p in "${LME_SERVE_NODE_PORTS[@]}"; do
      printf '%s\n' "$_serve_now" | grep -qE "127\.0\.0\.1:${_p}([^0-9]|$)" \
        && _lme_node_left="yes"
    done
    # Foreign = any svc:<name> still present (LME-owned ones were just cleared in 4b,
    # so a remainder is a co-tenant's) OR a node backend on a port LME does not own.
    _foreign=""
    printf '%s\n' "$_serve_now" | grep -qE 'svc:[A-Za-z0-9._-]+' && _foreign="yes"
    while IFS= read -r _bport; do
      _own=""
      for _p in "${LME_SERVE_NODE_PORTS[@]}"; do [ "$_bport" = "$_p" ] && _own="yes"; done
      [ -z "$_own" ] && _foreign="yes"
    done < <(printf '%s\n' "$_serve_now" | grep -oE '127\.0\.0\.1:[0-9]+' \
             | grep -oE '[0-9]+$' | sort -u)

    if [ -n "$_lme_node_left" ] && [ -z "$_foreign" ]; then
      echo "  LME node serves survived scoped '... off' and no co-tenant serve is present; blanket reset (safe on a dedicated host)."
      sudo tailscale serve reset 2>/dev/null || true
    fi
  fi

  # 4d. Revert the EGRESS leg's client preference (Finding C). tailscale_egress.yml
  #     runs `tailscale set --accept-routes=true` (daemon pref RouteAll:true) so LME
  #     can reach services behind tailnet subnet routers; a wipe that leaves it on
  #     keeps the host pulling every advertised subnet route after LME is gone. Revert
  #     it. `tailscale set` is idempotent (a no-op when already false), so we run it
  #     unconditionally rather than add a `debug prefs` read (another failure surface)
  #     just to gate it. NOTE: unlike the serve clears above -- which are scoped to
  #     LME's EXACT svc/port identities -- RouteAll is a HOST-GLOBAL pref, not
  #     LME-scoped; reverting it is correct for LME's own egress teardown but would
  #     also drop a co-tenant's accept-routes on a shared node. The optional exit-node
  #     (operator opt-in) is deliberately NOT touched.
  echo "Reverting tailnet egress accept-routes (RouteAll -> false)..."
  sudo tailscale set --accept-routes=false 2>/dev/null || true
fi

# --------------------------------------------------------------------------
# 5. Reload systemd (drops now-source-less generated units) and clear failures.
# --------------------------------------------------------------------------
echo "Reloading systemd and clearing failed states..."
sudo systemctl daemon-reload 2>/dev/null || true
sudo systemctl reset-failed 2>/dev/null || true

# `sudo -i podman` runs with HOME=/root, so podman reads
# /root/.config/containers/{storage,containers}.conf -- written by setup_passwords.yml
# as user_storage_conf (the RELOCATED graphroot) and user_secrets_conf (the shell-
# driver secrets config pointing at /etc/lme/vault, just deleted). The old
# `rm -rf ~/.config/containers` (un-sudo'd) targeted the INVOKING user's home, which
# on this rootful install is the WRONG store -- so the load-bearing root config
# survived a "full" wipe and the next install inherited a stale graphroot pointer.
echo "Cleaning up rootful container config (/root/.config/containers)..."
sudo rm -rf /root/.config/containers
sudo rm -f /etc/containers/storage.conf

# --------------------------------------------------------------------------
# 6. SELF-VERIFY -- the authoritative gate. Assert NONE of the residue classes
#    remain. Anything found is printed and forces exit 1. Only a verifiably
#    clean host prints success and exits 0.
#
#    FAIL-CLOSED probing: a tool that is ABSENT means that residue class cannot
#    exist -> skip it. A tool that is PRESENT but whose query ERRORS is
#    INDETERMINATE -> we cannot prove clean -> treat as residue. We never print
#    success on an unqueryable probe.
# --------------------------------------------------------------------------
RESIDUE=()

echo "Verifying host is clean..."

# --- 6a. systemd units (loaded units + installed unit files) ---------------
# `--plain --no-legend` columns: $1=UNIT $2=LOAD. Count a loaded unit as
# residue ONLY when LOAD == "loaded"; `not-found` stubs left mid-teardown are
# not residue and must not false-fail a clean wipe. list-unit-files is a second,
# independent probe for any lingering unit FILE or dangling .wants symlink.
if command -v systemctl >/dev/null 2>&1; then
  loaded_units=$(systemctl list-units --all --plain --no-legend 'lme*' 2>/dev/null \
                 | awk '$2 == "loaded" {print $1}')
  if [ -n "$loaded_units" ]; then
    RESIDUE+=("loaded systemd unit(s) still present:"$'\n'"$loaded_units")
  fi
  unit_files=$(systemctl list-unit-files --no-legend 'lme*' 2>/dev/null | awk '{print $1}')
  if [ -n "$unit_files" ]; then
    RESIDUE+=("installed unit file(s) still present:"$'\n'"$unit_files")
  fi
fi

# --- 6b. podman containers / volumes / secrets -----------------------------
# NOTE the template-field asymmetry: containers use {{.Names}} (plural),
# volumes and secrets use {{.Name}} (singular). Each probe's exit status is
# checked: a failed query is indeterminate -> residue (never silent-clean).
if $PODMAN --version >/dev/null 2>&1; then
  if names=$($PODMAN ps -a --format '{{.Names}}' 2>/dev/null); then
    lme_containers=$(printf '%s\n' "$names" | grep -i '^lme' || true)
    [ -n "$lme_containers" ] && RESIDUE+=("lme container(s) still present:"$'\n'"$lme_containers")
  else
    RESIDUE+=("podman container query failed -- cannot verify clean (indeterminate)")
  fi

  if vols=$($PODMAN volume ls --format '{{.Name}}' 2>/dev/null); then
    lme_volumes=$(printf '%s\n' "$vols" | grep -i '^lme' || true)
    [ -n "$lme_volumes" ] && RESIDUE+=("lme volume(s) still present:"$'\n'"$lme_volumes")
  else
    RESIDUE+=("podman volume query failed -- cannot verify clean (indeterminate)")
  fi

  # Secrets are not lme-prefixed and `secret rm -a` above removes them all, so
  # ANY remaining secret means the wipe did not complete -> residue.
  if secs=$($PODMAN secret ls --format '{{.Name}}' 2>/dev/null); then
    leftover_secrets=$(printf '%s\n' "$secs" | grep -v '^[[:space:]]*$' || true)
    [ -n "$leftover_secrets" ] && RESIDUE+=("podman secret(s) still present:"$'\n'"$leftover_secrets")
  else
    RESIDUE+=("podman secret query failed -- cannot verify clean (indeterminate)")
  fi
fi

# --- 6c. filesystem residue ------------------------------------------------
[ -e /opt/lme ] && RESIDUE+=("/opt/lme still exists")
[ -e /etc/lme ] && RESIDUE+=("/etc/lme still exists")
# SF-8: the rootful podman config `sudo -i podman` actually reads. The dir holds
# storage.conf (relocated graphroot) AND containers.conf (shell-secrets driver);
# one dir assertion covers both. storage.conf is named so the check is self-evident.
[ -e /root/.config/containers ] && RESIDUE+=("/root/.config/containers still exists (rootful storage.conf/containers.conf residue)")

# Unit-file residue in the quadlet dir. `nullglob` so an empty match does NOT
# leave the literal pattern (which would false-fail a clean host).
shopt -s nullglob
quadlet_leftover=(/etc/containers/systemd/lme*)
shopt -u nullglob
if [ "${#quadlet_leftover[@]}" -gt 0 ]; then
  RESIDUE+=("quadlet file(s) still present:"$'\n'"$(printf '%s\n' "${quadlet_leftover[@]}")")
fi

# --- 6d. tailscale serve config (LME-owned ONLY -- Finding A) ---------------
# Count ONLY LME-owned serve config as residue. A co-tenant's serve/Service on a
# shared node (svc:windows11, svc:vncserverwindow, or a node backend on a non-LME
# port) is deliberately NOT asserted -- it is not ours to remove and must never
# fail our wipe. LME-owned residue still fails closed (any survivor -> exit 1), so
# the B2 teardown contract is preserved. Present-but-unqueryable (tailscaled down)
# is indeterminate -> residue, because serve config persists and returns on restart.
if command -v tailscale >/dev/null 2>&1; then
  # Fail-closed: tailscale is present but we derived NO LME svc names (manifests tree
  # missing/unreadable, or empty). We then cannot have cleared any VIP in 4b nor can
  # we recognise one as residue below -- an empty set would silently report clean with
  # orphaned VIPs still advertised, the very failure this finding fixes. Treat an
  # underivable set as INDETERMINATE residue, matching 6d's "present but unqueryable"
  # rule. (When tailscale is absent this is skipped, so a non-tailscale wipe is
  # unaffected.)
  if [ "${#LME_SVC_NAMES[@]}" -eq 0 ]; then
    RESIDUE+=("cannot derive the LME svc set from ${LME_MANIFESTS_DIR}/services -- tailnet VIP teardown unverifiable (indeterminate)")
  fi
  if serve_status=$(sudo tailscale serve status 2>/dev/null); then
    lme_serve_residue=""
    # LME-owned svc:<name> VIPs (exact-name match; foreign svc:* ignored).
    while IFS= read -r _svc; do
      _name=${_svc#svc:}
      for _lme in "${LME_SVC_NAMES[@]}"; do
        [ "$_name" = "$_lme" ] && lme_serve_residue+="${_svc}"$'\n'
      done
    done < <(printf '%s\n' "$serve_status" | grep -oE 'svc:[A-Za-z0-9._-]+' | sort -u)
    # LME node-scoped serves (ingress ports). Anchored so :50441 cannot match :5044.
    for _p in "${LME_SERVE_NODE_PORTS[@]}"; do
      printf '%s\n' "$serve_status" | grep -qE "127\.0\.0\.1:${_p}([^0-9]|$)" \
        && lme_serve_residue+="127.0.0.1:${_p} (LME node serve)"$'\n'
    done
    lme_serve_residue=$(printf '%s' "$lme_serve_residue" | grep -v '^[[:space:]]*$' || true)
    [ -n "$lme_serve_residue" ] \
      && RESIDUE+=("LME tailscale serve config still present:"$'\n'"$lme_serve_residue")
  else
    RESIDUE+=("tailscale serve status query failed -- cannot verify clean (indeterminate)")
  fi
fi

# --- 6f. shell-profile residue --------------------------------------------
# The ANSIBLE_VAULT_PASSWORD_FILE export setup_passwords.yml injects into
# /root/.profile + /root/.bashrc. If it survives, the next fresh install's
# ansible-playbook aborts at startup pointing at the now-deleted pass.sh.
for _rc in /root/.profile /root/.bashrc; do
  if [ -f "$_rc" ] && grep -q 'ANSIBLE_VAULT_PASSWORD_FILE' "$_rc" 2>/dev/null; then
    RESIDUE+=("ANSIBLE_VAULT_PASSWORD_FILE export still present in $_rc")
  fi
done

# --- 6e. verdict -----------------------------------------------------------
if [ "${#RESIDUE[@]}" -gt 0 ]; then
  echo ""
  echo "WIPE FAILED: host is NOT clean. Residue found:"
  for r in "${RESIDUE[@]}"; do
    echo "  - ${r//$'\n'/$'\n'    }"
  done
  echo ""
  echo "Re-run after resolving the above, or investigate manually. Exiting non-zero."
  exit 1
fi

echo "Wipe complete and verified clean. Ready for fresh install."
exit 0
