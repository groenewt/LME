import json, subprocess, collections, sys

J="/home/tristan/.claude/projects/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/subagents/workflows/wf_47338c8d-3d3/journal.jsonl"
RUN=".ocr/sessions/2026-09-18-fix-debian-13-selinux-apt/map/runs/run-4"
SECT="/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad/sections.json"

rows=[json.loads(l) for l in open(J) if l.strip()]
results=[r for r in rows if r.get("type")=="result"]
verify=[]; flow=[]
for r in results:
    v=r["result"]; key=r.get("key","")
    if isinstance(v,dict) and "finding_id" in v: verify.append(v)
    elif isinstance(v,dict) and "section" in v: v["_key"]=key; flow.append(v)

sections=json.load(open(SECT))
# per-file numstat
num={}
for l in subprocess.check_output(["git","diff","main...HEAD","--numstat"],text=True).splitlines():
    p=l.split("\t")
    if len(p)==3:
        a,d,f=p; num[f]=(0 if a=='-' else int(a), 0 if d=='-' else int(d))

SEVRANK={"critical":0,"high":1,"medium":2,"low":3,"info":4}
verify.sort(key=lambda x: SEVRANK.get(x.get("severity","low"),5))

# flow by section
flowby=collections.defaultdict(list)
for f in flow: flowby[f["section"]].append(f)

# ---- build map.md ----
out=[]
w=out.append
w("# Code Review Map — run-4\n")
w("**Branch**: `fix/debian-13-selinux-apt` vs `main`  •  **Files**: 124  •  **Fleet**: 47 agents (35 flow + 12 evidence-anchored verifiers)  •  **Anchored on**: live graph deploy evidence\n")

# Exec summary
crit=[v for v in verify if v["severity"] in ("critical","high")]
w("## Executive Summary\n")
w("This changeset replaces LME's static quadlet tree with a **manifest→resolver→render** pipeline "
  "(`manifests/*` → `filter_plugins/lme_manifests.py` → `load_manifests`/`render_units` → `templates/units/*.j2`), "
  "adds a tailscale 3-leg overlay, an SF-8 co-residency budget preflight, a per-install LiteLLM secret, "
  "SELinux/Debian-13 base work, and a versioned e2e deploy-gate harness. Hypothesis: the refactor is structurally sound "
  "and the round-5 blockers (B0 render, LiteLLM key) are closed — but the fleet + live-graph evidence surface a "
  f"**cross-cutting network-exposure posture problem**: {len(crit)} critical/high findings, led by every host-published "
  "port defaulting to `0.0.0.0` with the loopback fix applied to only one service, and two unauthenticated web UIs "
  "with mutating endpoints. The gate that declared this 'healthy' only probes ES for a 401.\n")

# Questions
w("## Questions & Clarifications\n")
for q in [
 "Is LAN exposure of ES:9200 / Postgres:5432 intended for any supported profile, or should default be loopback-closed with an explicit `expose_lan` opt-in?",
 "Should the `--tailscale` flag *couple* to loopback binding (serve-on ⇒ ports off 0.0.0.0), or is 0.0.0.0+serve intentional?",
 "Dashboard/log-analyzer: is inbound auth planned (per-install secret, mirroring litellm_master_key), or is loopback+tailscale the only intended control?",
 "RedHat/SELinux path: operator confirms the Debian no-op is acceptable and stays in the PR (RRH gave us systemd) — recorded as non-blocking.",
 "deb13-on-QEMU: genericcloud image fails kernel/initrd handoff on this host; is UEFI-non-secure-boot acceptable, or is bare-metal Debian-13 (graph/trixie) sufficient distro coverage?",
]: w(f"- {q}")
w("")

# Critical review focus = verify findings
w("## Critical Review Focus (evidence-anchored)\n")
w("| # | Finding | Verdict | Sev | Where |")
w("|---|---------|---------|-----|-------|")
for i,v in enumerate(verify,1):
    aff=", ".join(f"`{a}`" for a in (v.get("affected") or [])[:3])
    w(f"| {i} | **{v['title']}** | {v['verdict']} | {v['severity'].upper()} | {aff} |")
w("")
for i,v in enumerate(verify,1):
    w(f"### F{i} · {v['finding_id']} — {v['severity'].upper()} · {v['verdict']}")
    w(f"**{v['title']}**\n")
    w(f"- **Evidence**: {v['evidence'][:900]}")
    w(f"- **Recommendation**: {v.get('recommendation','')[:500]}")
    w("")

# Manual verification
w("## Manual Verification (what the gate must add)\n")
for m in [
 "`ss -ltnp` on the deploy host: assert ES:9200, Postgres:5432, dashboard:8502, log-analyzer:8501 are NOT on a non-loopback address (wire `conftest.py` deny-set into the gate).",
 "Unauth probe: `curl` dashboard `/api/rules/kibana/toggle` + log-analyzer from a non-loopback IP → must be refused.",
 "End-to-end ingest: write→refresh→read a doc through ES and confirm it surfaces in Kibana (data-flow, not just ES-up).",
 "Fleet: server enrolled/healthy; Wazuh→indexer index present; LLM chain (litellm→llama-cpp→embeddings→pgvector) serves a completion.",
 "Post-install teardown: `wipe_lme.sh` after a REAL install removes all 11 containers+volumes (pristine wipe only proved exit-0-on-empty).",
]: w(f"- {m}")
w("")

# File review sections
w("## File Review\n")
secnames=sorted(sections.keys())
for sn in secnames:
    files=sections[sn]["files"]
    fl=flowby.get(sn,[])
    role=" ".join(f.get("role_summary","") for f in fl)[:400] or "(section)"
    w(f"### {sn}  ({len(files)} files)")
    w(f"_{role}_\n")
    # review focus union
    rf=[]
    for f in fl: rf += f.get("review_focus",[])
    for x in rf[:6]: w(f"- 🔎 {x}")
    # concerns
    cc=[]
    for f in fl:
        for c in f.get("concerns",[]) or []:
            cc.append(c)
    cc=[c for c in cc if c.get("severity") in ("critical","high","medium")]
    for c in cc[:6]:
        w(f"- ⚠️ **{c.get('severity','').upper()}** {c.get('file','')}: {c.get('issue','')[:160]}")
    w("")
    w("| Done | File | +/− |")
    w("|:----:|------|-----|")
    for f in files:
        a,d=num.get(f,(0,0))
        w(f"| ☐ | `{f}` | +{a}/-{d} |")
    w("")

# File index
w("## File Index\n")
allf=sorted(f for s in sections.values() for f in s["files"])
sec_of={f:sn for sn in sections for f in sections[sn]["files"]}
for f in allf: w(f"- `{f}` — {sec_of[f]}")
w("")

mapmd="\n".join(out)
open(f"{RUN}/map.md","w").write(mapmd)

# ---- complete-map JSON ----
cm={"schema_version":1,"sections":[],"dependencies":[]}
for idx,sn in enumerate(secnames,1):
    files=sections[sn]["files"]
    cm["sections"].append({
        "section_number":idx,"title":sn,
        "description":(" ".join(f.get("role_summary","") for f in flowby.get(sn,[]))[:200] or sn),
        "files":[{"file_path":f,"role":"changed","lines_added":num.get(f,(0,0))[0],"lines_deleted":num.get(f,(0,0))[1]} for f in files],
    })
idx_of={sn:i for i,sn in enumerate(secnames,1)}
for frm,to,rel in [
 ("S13-tests+gate-harness","S04-render+load pipeline","tests + gate exercise the render pipeline"),
 ("S04-render+load pipeline","S03-unit-templates(render)","render pipeline drives unit templates"),
 ("S03-unit-templates(render)","S02-service-manifests","templates render service manifests"),
 ("S01-manifest-core+resolver","S02-service-manifests","resolver consumes service manifests"),
 ("S12-install/wipe/offline scripts","S04-render+load pipeline","install.sh invokes render pipeline"),
 ("S05-tailscale(ingress/egress/svc)","S01-manifest-core+resolver","tailscale overlay is a profile"),
]:
    if frm in idx_of and to in idx_of:
        cm["dependencies"].append({"from_section":idx_of[frm],"from_title":frm,"to_section":idx_of[to],"to_title":to,"relationship":rel})
json.dump(cm, open(f"{RUN}/complete-map.json","w"), indent=1)

# ---- compact digest for context ----
dg=[]
dg.append("VERIFY FINDINGS (sev-sorted):")
for v in verify:
    dg.append(f"  [{v['severity'].upper():8}] {v['verdict']:9} {v['finding_id']:22} — {v['title'][:90]}")
dg.append("\nFLOW CONCERNS (high/critical only):")
for f in flow:
    for c in f.get("concerns",[]) or []:
        if c.get("severity") in ("critical","high"):
            dg.append(f"  [{c.get('severity','').upper():8}] {f['section']:30} {c.get('file','')}: {c.get('issue','')[:110]}")
digest="\n".join(dg)
open("/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad/run4-digest.txt","w").write(digest)

# completeness check
mapped=mapmd.count("| `")
print(f"map.md written: {len(mapmd)} chars, files-in-tables≈{mapped} (expected ≥124)")
print(f"verify={len(verify)} flow={len(flow)} sections={len(secnames)}")
print("---- DIGEST ----")
print(digest)
