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

  # Generate chain PEM files for all services that need them.
  # Source of truth is instances.yml (same list the idempotent top-up loop below
  # derives), so new services (e.g. apm-server) are covered without hand-editing a
  # hardcoded list. Keep this awk selector in sync with the top-up loop.
  for svc in $(awk '/^  - name: /{ n=$3; gsub(/"/,"",n); print n }' "${INSTANCES_PATH}"); do
    if [ -d "${CERTS_DIR}/${svc}" ] && [ -f "${CERTS_DIR}/${svc}/${svc}.crt" ]; then
      cat "${CERTS_DIR}/${svc}/${svc}.crt" "${CERTS_DIR}/ca/ca.crt" > "${CERTS_DIR}/${svc}/${svc}.chain.pem"
      echo "Created chain PEM for ${svc}"
    fi
  done

  echo "Setting file permissions... certs"
  chown -R elasticsearch:elasticsearch "${CERTS_DIR}"
  find "${CERTS_DIR}" -type d -exec chmod 755 {} \;
  find "${CERTS_DIR}" -type f -exec chmod 644 {} \;
  # Private keys must not be world-readable (shared lme_certs volume / local users)
  find "${CERTS_DIR}" -type f \( -name '*.key' -o -name '*-key.pem' \) -exec chmod 600 {} \;

  echo "Setting file permissions... data"
  chown -R elasticsearch:elasticsearch "${DATA_DIR}"
fi

# Idempotent top-up: mint certs for instances.yml entries whose cert dir is missing
TOPUP_TMP="$(mktemp -d)"
trap 'rm -rf "${TOPUP_TMP}"' EXIT

for svc in $(awk '/^  - name: /{ n=$3; gsub(/"/,"",n); print n }' "${INSTANCES_PATH}"); do
  if [ -f "${CERTS_DIR}/${svc}/${svc}.crt" ]; then
    # Cert already exists; do not re-mint. But an older run (hardcoded bulk list)
    # may have skipped this service's chain, so create it if missing. Chain files
    # are public certs only -- no private key is touched here.
    if [ ! -f "${CERTS_DIR}/${svc}/${svc}.chain.pem" ]; then
      cat "${CERTS_DIR}/${svc}/${svc}.crt" "${CERTS_DIR}/ca/ca.crt" > "${CERTS_DIR}/${svc}/${svc}.chain.pem"
      chown elasticsearch:elasticsearch "${CERTS_DIR}/${svc}/${svc}.chain.pem"
      chmod 644 "${CERTS_DIR}/${svc}/${svc}.chain.pem"
      echo "Top-up: created missing chain PEM for ${svc}"
    fi
    continue
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
  chmod 644 "${CERTS_DIR}/${svc}"/*
  # Private keys must not be world-readable (shared lme_certs volume / local users)
  find "${CERTS_DIR}/${svc}" -type f \( -name '*.key' -o -name '*-key.pem' \) -exec chmod 600 {} \;
done

