#!/bin/bash
cd /home/vmuser/LME
echo "=== running tree's own scripts/wipe_lme.sh ==="
sudo bash scripts/wipe_lme.sh
rc=$?
echo "WIPE rc=$rc"
echo "=== POST-WIPE CLEAN VERIFICATION ==="
echo "-- podman containers (expect none) --"; sudo -i podman ps -a --format '{{.Names}} {{.Status}}' 2>/dev/null | sed '/^$/d' || true
c=$(sudo -i podman ps -a --format '{{.Names}}' 2>/dev/null | sed '/^$/d' | wc -l); echo "container count=$c"
echo "-- podman images (expect none) --"; sudo -i podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | sed '/^$/d' || true
img=$(sudo -i podman images --format '{{.ID}}' 2>/dev/null | sed '/^$/d' | wc -l); echo "image count=$img"
echo "-- lme_* volumes (expect none) --"; vol=$(sudo -i podman volume ls --format '{{.Name}}' 2>/dev/null | grep -c '^lme_' || true); echo "lme volume count=$vol"
echo "-- lme systemd units (expect none) --"; sudo systemctl daemon-reload; u=$(systemctl list-unit-files 'lme*' --no-legend 2>/dev/null | wc -l); echo "lme unit-files=$u"; systemctl list-unit-files 'lme*' --no-legend 2>/dev/null | head
echo "-- /opt/lme /opt/lme-storage (expect gone/empty) --"; ls -ld /opt/lme /opt/lme-storage 2>&1 | head
echo "-- failed units --"; fu=$(systemctl --failed --no-legend 2>/dev/null | grep -c lme || true); echo "failed lme units=$fu"
echo "=== CLEAN SUMMARY: containers=$c images=$img lme_vols=$vol lme_units=$u ==="
