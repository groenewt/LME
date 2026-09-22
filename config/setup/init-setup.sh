#!/bin/bash
set -euo pipefail

if [[ -z "${ELASTIC_PASSWORD:-}" || -z "${KIBANA_PASSWORD:-}" ]]; then
  echo "ERROR: ELASTIC_PASSWORD and/or KIBANA_PASSWORD are missing."
  exit 1
fi
#echo $ELASTIC_PASSWORD
#echo $KIBANA_PASSWORD

CONFIG_DIR="/usr/share/elasticsearch/config"
CERTS_DIR="${CONFIG_DIR}/certs"
DATA_DIR="/usr/share/elasticsearch/data"
INSTANCES_PATH="${CONFIG_DIR}/setup/instances.yml"

if [ ! -f "${CERTS_DIR}/ca.zip" ]; then
  echo "Creating CA..."
  elasticsearch-certutil ca --silent --pem --out "${CERTS_DIR}/ca.zip"
  unzip -o "${CERTS_DIR}/ca.zip" -d "${CERTS_DIR}"
fi

if [ ! -f "${CERTS_DIR}/certs.zip" ]; then
  echo "Creating certificates..."
  elasticsearch-certutil cert --silent --pem --in "${INSTANCES_PATH}" --out "${CERTS_DIR}/certs.zip" --ca-cert "${CERTS_DIR}/ca/ca.crt" --ca-key "${CERTS_DIR}/ca/ca.key"
  unzip -o "${CERTS_DIR}/certs.zip" -d "${CERTS_DIR}"

  # Build chain PEMs (leaf cert + public CA cert) for every service declared in
  # instances.yml (elasticsearch included). The service list is DERIVED from
  # instances.yml -- which is itself rendered from the manifest tree
  # (manifests/services/*.yml) -- so there is NO hardcoded service list here. A new
  # cert consumer appears the moment its manifest declares a certs block; nothing
  # in this script needs to change.
  while read -r svc; do
    if [ -d "${CERTS_DIR}/${svc}" ] && [ -f "${CERTS_DIR}/${svc}/${svc}.crt" ]; then
      cat "${CERTS_DIR}/${svc}/${svc}.crt" "${CERTS_DIR}/ca/ca.crt" > "${CERTS_DIR}/${svc}/${svc}.chain.pem"
      echo "Created chain PEM for ${svc}"
    fi
  done < <(awk '/^  - name: /{ n=$3; gsub(/"/,"",n); print n }' "${INSTANCES_PATH}")

  echo "Setting file permissions... data"
  chown -R elasticsearch:elasticsearch "${DATA_DIR}"
fi

# --- Cert OWNERSHIP + PERMISSION hardening: runs on EVERY setup pass (fresh + upgrade) ---
# This block previously lived INSIDE the `if [ ! -f certs.zip ]` fresh-install guard
# above. An in-place upgrade keeps certs.zip, so the guard skipped the block and left an
# already-installed host's `ca/ca.key` WORLD-READABLE (0644) — the CA-signing-key MITM
# vector was closed for fresh installs but never for the installed base (the population
# most likely to have it). Hoisted out of the guard so the tightening self-heals existing
# hosts on the next setup/upgrade pass. Idempotent: re-applying fixed modes/owner to the
# same files is safe to repeat, and the top-up loop below only (re)mints missing certs.
#
# WORKSPACE ownership stays HERE, in the setup-certs container, because this script runs
# as userns-root and can freely chown/chmod every file in the lme_certs workspace (all in
# its own userns). The shared-workspace cert consumers -- Elasticsearch (mounts lme_certs
# directly) and the LLM pack (mount lme_certs:,idmap) -- read their leaf as the container's
# `elasticsearch` uid, so the workspace is owned by that uid.
#
# B4 CA-KEY CARVE-OUT: `ca/ca.key` is chowned OFF the `elasticsearch` service uid to
# userns-root and kept 0600, so the Elasticsearch SERVICE process (which runs as
# `elasticsearch`, not root) cannot read the CA signing key even though it mounts the whole
# workspace. This is the ownership half of the CA-MITM fix; the mode half is 0600. The CA
# key is published to NOTHING and mounted into NOTHING else. NOTE: host-subuid ownership of
# the PUBLISHED per-service bundles (/opt/lme/certs/<svc>) is applied separately by the
# ansible cert publisher (real host root) -- those live OUTSIDE this workspace, so this
# block never fights the ansible layer over the same files.
if [ -d "${CERTS_DIR}" ]; then
  echo "Setting cert ownership + permissions..."
  chown -R elasticsearch:elasticsearch "${CERTS_DIR}"
  find "${CERTS_DIR}" -type d -exec chmod 755 {} \;
  # Public material (certs, chains) world-readable; private keys group-only; CA key owner-only.
  find "${CERTS_DIR}" -type f -name '*.key' -exec chmod 640 {} \;
  find "${CERTS_DIR}" -type f -not -name '*.key' -not -name '*.zip' -exec chmod 644 {} \;
  # Zip bundles contain the CA and every service key; keep them owner-only (they double as idempotence sentinels).
  find "${CERTS_DIR}" -maxdepth 1 -type f -name '*.zip' -exec chmod 600 {} \;
  # CA private key: OFF the elasticsearch service uid (owner -> userns-root) AND 0600.
  if [ -f "${CERTS_DIR}/ca/ca.key" ]; then
    chown 0:0 "${CERTS_DIR}/ca/ca.key"
    chmod 600 "${CERTS_DIR}/ca/ca.key"
  fi
fi

# Idempotent top-up: mint certs for instances.yml entries whose cert dir is missing.
# Same derived service list (from instances.yml -> manifests): no hardcoded names.
TOPUP_TMP="$(mktemp -d)"
trap 'rm -rf "${TOPUP_TMP}"' EXIT

while read -r svc; do
  # Skip services already minted, unless a re-mint is forced (e.g. after a SAN / instances.yml edit).
  # Set LME_FORCE_CERT_REMINT=true (or 1) in /opt/lme/lme-environment.env to re-mint on an installed host.
  if [ -f "${CERTS_DIR}/${svc}/${svc}.crt" ]; then
    if [ "${LME_FORCE_CERT_REMINT:-}" = "true" ] || [ "${LME_FORCE_CERT_REMINT:-}" = "1" ]; then
      echo "Force re-mint requested (LME_FORCE_CERT_REMINT): re-minting cert for ${svc}"
    else
      continue
    fi
  fi
  echo "Top-up: generating missing cert for ${svc}"
  awk -v name="${svc}" '
    /^instances:/ { print; next }
    /^  - name: / { inblock = ($0 ~ "- name: \"" name "\"") }
    inblock { print }
  ' "${INSTANCES_PATH}" > "${TOPUP_TMP}/${svc}.yml"
  elasticsearch-certutil cert --silent --pem \
    --in "${TOPUP_TMP}/${svc}.yml" \
    --out "${TOPUP_TMP}/${svc}.zip" \
    --ca-cert "${CERTS_DIR}/ca/ca.crt" --ca-key "${CERTS_DIR}/ca/ca.key"
  unzip -o "${TOPUP_TMP}/${svc}.zip" -d "${CERTS_DIR}"
  cat "${CERTS_DIR}/${svc}/${svc}.crt" "${CERTS_DIR}/ca/ca.crt" > "${CERTS_DIR}/${svc}/${svc}.chain.pem"
  # Newly minted leaves are owned by userns-root; hand them to the workspace uid so the
  # shared-workspace consumers (ES / idmap LLM pack) can read them (host-subuid ownership
  # of the PUBLISHED bundle is applied separately, on the host, by the ansible publisher).
  chown -R elasticsearch:elasticsearch "${CERTS_DIR}/${svc}"
  chmod 755 "${CERTS_DIR}/${svc}"
  # Public material world-readable; private key group-only (matches the top-level discipline above).
  find "${CERTS_DIR}/${svc}" -type f -name '*.key' -exec chmod 640 {} \;
  find "${CERTS_DIR}/${svc}" -type f -not -name '*.key' -exec chmod 644 {} \;
done < <(awk '/^  - name: /{ n=$3; gsub(/"/,"",n); print n }' "${INSTANCES_PATH}")
