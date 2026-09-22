#!/bin/bash
LME_MANIFESTS_DIR="/home/tristan/gitters/LME/manifests"
LME_SVC_NAMES=()
if [ -d "${LME_MANIFESTS_DIR}/services" ]; then
  for _mf in "${LME_MANIFESTS_DIR}"/services/*.yml; do
    [ -e "$_mf" ] || continue
    grep -qE '^[[:space:]]*-[[:space:]]*\{.*bind:[[:space:]]*127\.0\.0\.1' "$_mf" || continue
    _svc=$(sed -nE 's/^tailnet_service:[[:space:]]*([^[:space:]#]+).*/\1/p' "$_mf" | head -n1)
    [ -n "$_svc" ] || _svc=$(sed -nE 's/^id:[[:space:]]*([^[:space:]#]+).*/\1/p' "$_mf" | head -n1)
    [ -n "$_svc" ] && LME_SVC_NAMES+=("$_svc")
  done
fi
printf '%s\n' "${LME_SVC_NAMES[@]}" | sort | tr '\n' ' '
echo ""
echo "COUNT=${#LME_SVC_NAMES[@]}"
