#!/bin/bash
# Fully uninstall LME: stop services, remove containers, volumes, secrets, images,
# unit files and config. Safe to run before a fresh install, from ANY directory.
#
# Hardening notes (cwd-independent, "fit all": single-node + cluster child/master,
# online + offline, LLM-on + LLM-off):
#   - Never rely on shell globbing to name systemd units. Bare `lme*` (unquoted)
#     glob-expands against the CURRENT DIRECTORY (e.g. run from ~/LME it becomes
#     `lme-dashboard lme-log-analyzer`), so the ~19 real lme units are never
#     stopped -> podman rm fails on running containers -> quadlet regenerates
#     elasticsearch/embeddings/llama-cpp. We enumerate real units from systemd.
#   - Stop AND disable BEFORE removing unit files (disable needs the files present,
#     otherwise it leaves a dangling default.target.wants/lme.service symlink).
#   - Order: stop -> disable -> daemon-reload -> remove unit files (+ .backup) ->
#     podman rm containers -> volume/secret rm -> rm -rf /opt/lme /etc/lme ->
#     daemon-reload + reset-failed -> self-verify.
#   - A self-verifying tail re-probes with GLOB-FREE checks and exits non-zero if
#     anything LME survives, so the script cannot report success on a partial wipe.

# NOTE: intentionally no `set -e` / no `set -o pipefail`. Individual teardown
# steps are best-effort (a unit already gone must not abort the run), but the
# real removals below are unconditional and the verify tail is the gate.

echo "==> Enumerating and stopping all LME systemd units (cwd-independent)..."
# Glob-free: list ALL loaded units, filter to lme[-._] with grep (not a shell glob).
# --plain strips the leading status dot so awk $1 is the real unit name.
lme_loaded_units() {
    systemctl list-units --all --plain --no-legend 2>/dev/null \
        | awk '{print $1}' | grep -E '^lme[-._]' || true
}
lme_unit_files() {
    systemctl list-unit-files --plain --no-legend 2>/dev/null \
        | awk '{print $1}' | grep -E '^lme[-._]' || true
}

# Stop the orchestrator (bare `lme.service`, no dash -> not matched by lme[-._])
# and every enumerated lme unit. Quoted patterns are also passed straight to
# systemctl (it matches loaded units itself; the shell never expands them).
sudo systemctl stop 'lme.service' 'lme-*' 2>/dev/null || true
while read -r u; do
    [ -n "$u" ] && sudo systemctl stop "$u" 2>/dev/null || true
done < <(lme_loaded_units)

echo "==> Disabling LME units (while unit files still exist) to clear enable symlinks..."
sudo systemctl disable 'lme.service' 2>/dev/null || true
while read -r u; do
    [ -n "$u" ] && sudo systemctl disable "$u" 2>/dev/null || true
done < <(lme_unit_files)
# Also disable any enabled generated quadlet services still loaded.
while read -r u; do
    [ -n "$u" ] && sudo systemctl disable "$u" 2>/dev/null || true
done < <(lme_loaded_units)

echo "==> Reloading systemd (forget disabled units before removing files)..."
sudo systemctl daemon-reload

echo "==> Removing LME quadlet + systemd unit files (incl. .backup, drop-ins, network)..."
# find, not a suffix whitelist: catches lme-*.container, .container.backup*, .volume,
# .network, lme.service, any lme-*.container.d/ drop-in dir, and future suffixes.
sudo find /etc/containers/systemd -maxdepth 1 -name 'lme*' -exec rm -rf {} + 2>/dev/null || true
sudo find /etc/containers/networks -maxdepth 1 -name 'lme*.json' -exec rm -f {} + 2>/dev/null || true
# Persistent sidecar units live in /etc/systemd/system (lme-llm-keys.{service,path},
# lme-llama-model.{service,path}, and on child nodes an inactive lme-litellm@*).
sudo find /etc/systemd/system -maxdepth 1 -name 'lme*' ! -type d -exec rm -f {} + 2>/dev/null || true
# Sweep dangling enable symlinks in every *.target.wants dir (don't guess which target).
sudo find /etc/systemd/system -name 'lme*' -type l -delete 2>/dev/null || true

echo "==> Reloading systemd after unit-file removal..."
sudo systemctl daemon-reload

echo "==> Stopping and removing all containers..."
sudo -i podman stop -a 2>/dev/null || true
sudo -i podman rm -af 2>/dev/null || true

echo "==> Removing volumes..."
sudo -i podman volume rm -a 2>/dev/null || true

echo "==> Removing podman secrets (file-driver secrets survive a blanket -a on some"
echo "    podman builds, so remove known LME secrets by name AND enumerate the rest)..."
sudo -i podman secret rm -a 2>/dev/null || true
# Known LME secrets (file-driver: llm-keys, pgvector; shell-driver: the rest).
for s in llm-keys pgvector elastic wazuh wazuh_api kibana_system; do
    sudo -i podman secret rm "$s" 2>/dev/null || true
done
# Enumerate anything still present (e.g. the dynamic per-user secret) and remove it.
while read -r s; do
    [ -n "$s" ] && sudo -i podman secret rm "$s" 2>/dev/null || true
done < <(sudo -i podman secret ls --noheading --format '{{.Name}}' 2>/dev/null | grep -E '^[A-Za-z0-9._-]+$')

echo "==> Pruning images..."
sudo -i podman image prune -af 2>/dev/null || true

echo "==> Removing /opt/lme and /etc/lme (vault + pass.sh)..."
sudo rm -rf /opt/lme
sudo rm -rf /etc/lme

echo "==> Cleaning up container config..."
rm -rf ~/.config/containers
sudo rm -f /etc/containers/storage.conf

echo "==> Final systemd daemon-reload + reset-failed..."
sudo systemctl daemon-reload
sudo systemctl reset-failed 2>/dev/null || true

echo "==> Verifying no LME residue survived (glob-free probes)..."
fail=0
report() { echo "  RESIDUE: $1"; fail=1; }

# Systemd units / unit files (glob-free; catches not-found/dangling too).
if systemctl list-units --all --plain --no-legend 2>/dev/null | awk '{print $1}' | grep -qE '^lme[-._]'; then
    report "lme systemd units still loaded:"
    systemctl list-units --all --plain --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^lme[-._]' | sed 's/^/    /'
fi
if systemctl list-unit-files --plain --no-legend 2>/dev/null | awk '{print $1}' | grep -qE '^lme[-._]'; then
    report "lme unit files still present:"
    systemctl list-unit-files --plain --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^lme[-._]' | sed 's/^/    /'
fi
# On-disk unit files / quadlets / dangling symlinks.
leftover_files=$(sudo find /etc/systemd/system /etc/containers/systemd /etc/containers/networks -name 'lme*' 2>/dev/null)
if [ -n "$leftover_files" ]; then
    report "lme files under /etc/systemd|/etc/containers:"
    echo "$leftover_files" | sed 's/^/    /'
fi
# Containers (volumes are lme_* underscore -> match lme[-_]).
if sudo -i podman ps -a --format '{{.Names}}' 2>/dev/null | grep -qE 'lme[-_]'; then
    report "lme containers still present:"
    sudo -i podman ps -a --format '{{.Names}}' 2>/dev/null | grep -E 'lme[-_]' | sed 's/^/    /'
fi
if sudo -i podman volume ls --format '{{.Name}}' 2>/dev/null | grep -qE 'lme[-_]'; then
    report "lme volumes still present:"
    sudo -i podman volume ls --format '{{.Name}}' 2>/dev/null | grep -E 'lme[-_]' | sed 's/^/    /'
fi
# Secrets (known LME secret names do NOT contain 'lme', so match them explicitly).
if sudo -i podman secret ls --format '{{.Name}}' 2>/dev/null | grep -qE '^(llm-keys|pgvector|elastic|wazuh|wazuh_api|kibana_system)$'; then
    report "lme podman secrets still present:"
    sudo -i podman secret ls --format '{{.Name}}' 2>/dev/null | grep -E '(llm-keys|pgvector|elastic|wazuh|kibana)' | sed 's/^/    /'
fi
# Directories.
[ -e /opt/lme ] && report "/opt/lme still present"
[ -e /etc/lme ] && report "/etc/lme still present"

if [ "$fail" -ne 0 ]; then
    echo "Wipe INCOMPLETE: LME residue survived (see RESIDUE lines above)." >&2
    exit 1
fi

echo "Wipe complete and verified: no LME units, containers, volumes, secrets, or config remain."
echo "Ready for fresh install."
