#!/bin/bash
HAS_SUDO_ACCESS="true"; SCRIPT_DIR="/home/tristan/gitters/LME"; OFFLINE_MODE=false
EFFECTIVE_INSTALL_LLM=true; EFFECTIVE_INSTALL_ELASTIC_SERVICES=false
GRAPH_ROOT="$1"; GRAPH_ROOT_SET="$2"; EFFECTIVE_PROFILE="$3"
if [ "$GRAPH_ROOT_SET" = "true" ]; then
    EFFECTIVE_GLOBAL_OVERRIDE=',"lme_global_override":{"storage":{"graphroot":"'"${GRAPH_ROOT}"'"}}'
else
    EFFECTIVE_GLOBAL_OVERRIDE=""
fi
# EXACT copy of the install.sh payload tail:
PAYLOAD='{"has_sudo_access":"'"${HAS_SUDO_ACCESS}"'","clone_dir":"'"${SCRIPT_DIR}"'","offline_mode":'"${OFFLINE_MODE}"',"install_llm":'"${EFFECTIVE_INSTALL_LLM}"',"install_elastic_services":'"${EFFECTIVE_INSTALL_ELASTIC_SERVICES}"',"storage_graphroot":"'"${GRAPH_ROOT}"'","lme_profile":"'"${EFFECTIVE_PROFILE}"'"'"${EFFECTIVE_GLOBAL_OVERRIDE}"'}'
printf '%s\n' "$PAYLOAD" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("VALID JSON; keys:", sorted(d.keys())); print("  lme_profile =", d["lme_profile"]); print("  has lme_global_override:", "lme_global_override" in d, "->", d.get("lme_global_override"))'
