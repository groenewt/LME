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
# 4. Reset tailscale serve/ingress so host-facing proxy state does not persist
#    across teardown. Guarded on the binary being present.
# --------------------------------------------------------------------------
if command -v tailscale >/dev/null 2>&1; then
  echo "Resetting tailscale serve/ingress config..."
  sudo tailscale serve reset 2>/dev/null || true
  # Best-effort clear of any Tailscale Service-scoped serves. The repo uses
  # node-scoped serve only (tailscale_ingress.yml), so this is purely defensive
  # for `--service=` setups -- no version detection, just reset whatever shows.
  if svc_names=$(sudo tailscale serve status 2>/dev/null \
                 | grep -oE 'svc:[A-Za-z0-9._-]+' | sort -u); then
    for svc in $svc_names; do
      sudo tailscale serve --service="$svc" reset 2>/dev/null || true
    done
  fi
fi

# --------------------------------------------------------------------------
# 5. Reload systemd (drops now-source-less generated units) and clear failures.
# --------------------------------------------------------------------------
echo "Reloading systemd and clearing failed states..."
sudo systemctl daemon-reload 2>/dev/null || true
sudo systemctl reset-failed 2>/dev/null || true

echo "Cleaning up container config..."
rm -rf ~/.config/containers
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

# Unit-file residue in the quadlet dir. `nullglob` so an empty match does NOT
# leave the literal pattern (which would false-fail a clean host).
shopt -s nullglob
quadlet_leftover=(/etc/containers/systemd/lme*)
shopt -u nullglob
if [ "${#quadlet_leftover[@]}" -gt 0 ]; then
  RESIDUE+=("quadlet file(s) still present:"$'\n'"$(printf '%s\n' "${quadlet_leftover[@]}")")
fi

# --- 6d. tailscale serve config -------------------------------------------
# Positive-match actual serve config lines (version-independent); do NOT
# negative-match the "No serve config" banner. Present-but-unqueryable
# (tailscaled down) is indeterminate -> residue, because the serve config
# persists in state and returns when tailscaled restarts.
if command -v tailscale >/dev/null 2>&1; then
  if serve_status=$(sudo tailscale serve status 2>/dev/null); then
    serve_cfg=$(printf '%s\n' "$serve_status" | grep -E '127\.0\.0\.1:|proxy|tcp://|svc:' || true)
    [ -n "$serve_cfg" ] && RESIDUE+=("tailscale serve config still present:"$'\n'"$serve_cfg")
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
