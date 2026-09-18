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
  cat "${CERTS_DIR}/elasticsearch/elasticsearch.crt" "${CERTS_DIR}/ca/ca.crt" > "${CERTS_DIR}/elasticsearch/elasticsearch.chain.pem"

  # Generate chain PEM files for all services that need them
  for svc in litellm dashboard log-analyzer embeddings llama-cpp kibana fleet-server wazuh-manager logstash curator fleet-distribution; do
    if [ -d "${CERTS_DIR}/${svc}" ] && [ -f "${CERTS_DIR}/${svc}/${svc}.crt" ]; then
      cat "${CERTS_DIR}/${svc}/${svc}.crt" "${CERTS_DIR}/ca/ca.crt" > "${CERTS_DIR}/${svc}/${svc}.chain.pem"
      echo "Created chain PEM for ${svc}"
    fi
  done

  echo "Setting file permissions... certs"
  chown -R elasticsearch:elasticsearch "${CERTS_DIR}"
  find "${CERTS_DIR}" -type d -exec chmod 755 {} \;
  # Public material (certs, chains) world-readable; private keys group-only; CA key owner-only.
  find "${CERTS_DIR}" -type f -name '*.key' -exec chmod 640 {} \;
  find "${CERTS_DIR}" -type f -not -name '*.key' -not -name '*.zip' -exec chmod 644 {} \;
  # Zip bundles contain the CA and every service key; keep them owner-only (they double as idempotence sentinels).
  find "${CERTS_DIR}" -maxdepth 1 -type f -name '*.zip' -exec chmod 600 {} \;
  if [ -f "${CERTS_DIR}/ca/ca.key" ]; then
    chmod 600 "${CERTS_DIR}/ca/ca.key"
  fi

  echo "Setting file permissions... data"
  chown -R elasticsearch:elasticsearch "${DATA_DIR}"
fi

# Idempotent top-up: mint certs for instances.yml entries whose cert dir is missing
TOPUP_TMP="$(mktemp -d)"
trap 'rm -rf "${TOPUP_TMP}"' EXIT

for svc in $(awk '/^  - name: /{ n=$3; gsub(/"/,"",n); print n }' "${INSTANCES_PATH}"); do
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
  chown -R elasticsearch:elasticsearch "${CERTS_DIR}/${svc}"
  chmod 755 "${CERTS_DIR}/${svc}"
  # Public material world-readable; private key group-only (matches the top-level discipline above).
  find "${CERTS_DIR}/${svc}" -type f -name '*.key' -exec chmod 640 {} \;
  find "${CERTS_DIR}/${svc}" -type f -not -name '*.key' -exec chmod 644 {} \;
done

