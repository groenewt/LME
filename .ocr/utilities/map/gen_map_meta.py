#!/usr/bin/env python3
"""Generate the complete-map JSON payload for `ocr state complete-map --file`.
Joins the finalized section homing (path -> section, role) against
`git diff main...HEAD --numstat`. Deterministic; safe to re-run."""
import json, subprocess, sys

SECTIONS = {
 1: ("OS-Family SELinux Gating",
     "Split the RHEL-only SELinux setup into an OS-family dispatcher so Debian/AppArmor hosts stop building/loading RHEL container-selinux policy; gate podman SELinux policy on selinux_policy_managed (RedHat AND tooling present). RedHat half is unverified on real iron (no RedHat node in tailnet)."),
 2: ("Debian 13 Base Enablement",
     "Make the base role work on Debian 13 (trixie): version-specific var lookup, common-package install, and drop software-properties-common (removed in Debian 13)."),
 3: ("apt-based Nix on Debian 13",
     "Install Nix from apt (nix-bin) on Debian 13 instead of the official installer; dispatched from the nix role."),
 4: ("Optional Elastic-Services Pack (--elastic-services)",
     "New opt-in, online-only pack (apm-server, filebeat, heartbeat, logstash, metricbeat): flag -> var -> role -> quadlet -> config wiring plus cert instances. No offline bundle."),
 5: ("LLM Stack (LiteLLM + pgvector + llama.cpp)",
     "Connect LiteLLM to pgvector for persistent UI/key management; template the litellm quadlet with DATABASE_URL; log-analyzer/dashboard app wiring. Locus of the R2 DATABASE_URL blocker."),
 6: ("Wazuh / Kibana / Dashboards",
     "Supporting adjustments to Wazuh readiness, Kibana, dashboards, and the wazuh-manager quadlet reference."),
 7: ("Upgrade / Backup / Offline / Scripts / Docs",
     "New upgrade playbook, backup role touch, offline-prep and quadlet-linking scripts, and colocated docs."),
}

# path -> (section_number, role)
HOMING = {
 # Section 1
 "ansible/roles/base/tasks/selinux_setup.yml": (1, "Gutted monolith -> OS-family SELinux dispatcher"),
 "ansible/roles/base/tasks/selinux_common.yml": (1, "OS-neutral SELinux fallback tasks (new)"),
 "ansible/roles/base/tasks/selinux_debian.yml": (1, "Debian SELinux path / skip semantics (new)"),
 "ansible/roles/base/tasks/selinux_redhat.yml": (1, "RHEL SELinux policy build/load, moved here (new, +138)"),
 "ansible/roles/base/tasks/redhat.yml": (1, "Removed inline SELinux block (now dispatched)"),
 "ansible/roles/podman/tasks/main.yml": (1, "selinux_policy_managed gate + apt-nix presence detection"),
 # Section 2
 "ansible/roles/base/tasks/main.yml": (2, "OS/version var lookup via with_first_found"),
 "ansible/roles/base/tasks/debian.yml": (2, "Install common_packages on Debian"),
 "ansible/roles/base/tasks/debian_13.yml": (2, "Debian-13-specific base steps (new)"),
 "ansible/roles/base/vars/debian_13.yml": (2, "Debian 13 package vars (new)"),
 "ansible/roles/base/defaults/main.yml": (2, "Drop software-properties-common"),
 "ansible/roles/base/tasks/setup_passwords.yml": (2, "Base password setup tweak"),
 # Section 3
 "ansible/roles/nix/tasks/main.yml": (3, "Nix role dispatch entry"),
 "ansible/roles/nix/tasks/debian.yml": (3, "Dispatch to Debian-13 nix path"),
 "ansible/roles/nix/tasks/debian-13.yml": (3, "apt-based Nix install for Debian 13 (new, +60)"),
 # Section 4
 "install.sh": (4, "Adds --elastic-services flag + effective-var computation"),
 "ansible/site.yml": (4, "Adds install_elastic_services default var"),
 "ansible/roles/podman/tasks/elastic_services_setup.yml": (4, "Deploy optional Elastic-services pack (new, +96)"),
 "ansible/roles/podman/tasks/container_setup.yml": (4, "Pull/tag elastic-services images + containers.txt filter fix"),
 "config/apm-server.yml": (4, "APM server beat config (new)"),
 "config/filebeat.yml": (4, "Filebeat config (new)"),
 "config/heartbeat.yml": (4, "Heartbeat config (new, +91)"),
 "config/metricbeat.yml": (4, "Metricbeat config (new)"),
 "config/logstash/logstash.yml": (4, "Logstash settings (new)"),
 "config/containers-elastic-services.txt": (4, "Elastic-services image list (new)"),
 "config/setup/init-setup.sh": (4, "Cert bootstrap incl. beats (cert-0600 blocker locus)"),
 "config/setup/instances.yml": (4, "Cert SAN instances for beats"),
 "quadlet-optional/elastic-services/lme-apm-server.container": (4, "APM server quadlet unit (new)"),
 "quadlet-optional/elastic-services/lme-filebeat.container": (4, "Filebeat quadlet unit (new)"),
 "quadlet-optional/elastic-services/lme-filebeatdata.volume": (4, "Filebeat data volume (new)"),
 "quadlet-optional/elastic-services/lme-heartbeat.container": (4, "Heartbeat quadlet unit (new)"),
 "quadlet-optional/elastic-services/lme-logstash.container": (4, "Logstash quadlet unit (new)"),
 "quadlet-optional/elastic-services/lme-metricbeat.container": (4, "Metricbeat quadlet unit (new)"),
 # Section 5
 "ansible/templates/lme-litellm.container.j2": (5, "LiteLLM quadlet template w/ DATABASE_URL (new; R2 locus)"),
 "ansible/roles/podman/tasks/llama_cpp_setup.yml": (5, "llama.cpp + LiteLLM DB bootstrap (new)"),
 "ansible/roles/podman/tasks/quadlet_setup.yml": (5, "Render LiteLLM quadlet from template (install_llm)"),
 "lme-dashboard/app.py": (5, "Dashboard app: pgvector UI wiring"),
 "lme-log-analyzer/app_simple.py": (5, "Point LITELLM_MODEL at registered model"),
 "quadlet/lme-log-analyzer.container": (5, "Log-analyzer quadlet image ref bump"),
 # Section 6
 "ansible/roles/wazuh/tasks/main.yml": (6, "Wazuh readiness / rc-gate"),
 "ansible/roles/kibana/tasks/main.yml": (6, "Kibana task tweak"),
 "ansible/roles/dashboards/tasks/main.yml": (6, "Dashboard deploy adjustments"),
 "quadlet/lme-wazuh-manager.container": (6, "Wazuh-manager quadlet ref bump"),
 # Section 7
 "ansible/upgrade_lme.yml": (7, "New upgrade playbook (+42)"),
 "ansible/roles/backup_lme/tasks/main.yml": (7, "Backup role addition"),
 "scripts/prepare_offline.sh": (7, "Offline bundle prep"),
 "scripts/link_latest_podman_quadlet.sh": (7, "Quadlet linking helper"),
 "scripts/upgrade/version_upgrade.md": (7, "Upgrade doc"),
 "ansible/README.md": (7, "Ansible role/ops README"),
 "ansible/BACKUP_README.md": (7, "Backup README"),
 "ansible/UPGRADE_README.md": (7, "Upgrade README"),
 "testing/v2/development/OFFLINE_INSTALL.md": (7, "Offline install doc"),
}

DEPENDENCIES = [
 (4,1,"Elastic-services runs after OS/SELinux base"),
 (5,1,"LLM stack runs after OS/SELinux base"),
 (2,3,"Debian base precedes apt-Nix install"),
 (3,1,"apt-Nix presence feeds podman SELinux/nix gate"),
 (4,3,"Container pulls need Nix-provided podman"),
 (5,3,"LLM containers need Nix-provided podman"),
 (4,2,"Elastic-services depends on Debian base packages"),
 (6,1,"Wazuh/Kibana run after OS/SELinux base"),
 (7,4,"Offline prep excludes online-only elastic-services"),
]

def numstat():
    out = subprocess.check_output(["git","diff","main...HEAD","--numstat"], cwd="/home/tristan/gitters/LME", text=True)
    d = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3: continue
        a,dele,path = parts
        d[path] = (0 if a=="-" else int(a), 0 if dele=="-" else int(dele))
    return d

def main():
    ns = numstat()
    # integrity check
    missing_home = [p for p in ns if p not in HOMING]
    missing_diff = [p for p in HOMING if p not in ns]
    if missing_home or missing_diff:
        print("HOMING MISMATCH", file=sys.stderr)
        print("in diff not homed:", missing_home, file=sys.stderr)
        print("homed not in diff:", missing_diff, file=sys.stderr)
        sys.exit(1)
    sections = []
    for num in sorted(SECTIONS):
        title, desc = SECTIONS[num]
        files = []
        for path,(snum,role) in HOMING.items():
            if snum != num: continue
            add,dele = ns[path]
            files.append({"file_path":path,"role":role,"lines_added":add,"lines_deleted":dele})
        files.sort(key=lambda f: f["file_path"])
        sections.append({"section_number":num,"title":title,"description":desc,"files":files})
    deps = [{"from_section":a,"from_title":SECTIONS[a][0],"to_section":b,"to_title":SECTIONS[b][0],"relationship":r}
            for (a,b,r) in DEPENDENCIES]
    payload = {"schema_version":1,"sections":sections,"dependencies":deps}
    total = sum(len(s["files"]) for s in sections)
    print(json.dumps(payload, indent=2))
    print(f"\n# section files total = {total} (expect 52)", file=sys.stderr)

if __name__ == "__main__":
    main()
