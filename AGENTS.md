<!-- OCR:START -->
## Open Code Review Instructions

These instructions are for AI assistants handling code review in this project.

Always open `.ocr/skills/SKILL.md` when the request:
- Asks for code review, PR review, or feedback on changes
- Mentions "review my code" or similar phrases
- Wants multi-perspective analysis of code quality
- Asks to map, organize, or navigate a large changeset

Use `.ocr/skills/SKILL.md` to learn:
- How to run the 8-phase review workflow
- How to generate a Code Review Map for large changesets
- Available reviewer personas and their focus areas
- Session management and output format

Keep this managed block so `ocr init` can refresh the instructions.
<!-- OCR:END -->

## Recorded operator rulings

The universal representation/YAML-value-sourcing rule in `../AGENTS.md` and `../operator-rulings.yaml` applies to every file here, including current HEAD, generic code, tests, and OCR/evidence. The architecture rules below add ownership constraints; they do not exempt structural literals, private defaults, or existing managed instruction blocks.

Authority: [manifest-reconciliation directive](.ocr/sessions/2026-09-22-fix-debian-13-selinux-apt/requirements-src/2026-09-22-manifest-reconciliation.md), [DISSOLVE decision, 2026-09-22](.ocr/index/areas/session-22-codex-worktree.md#4-the-hinge-and-the-dissolve-decision), and [approved implementation contract](.ocr/sessions/2026-09-22-fix-debian-13-selinux-apt/requirements-src/2026-09-22-observability-implementation.md). These define required behavior, not proof that the current checkout or deployment satisfies it. Resolve conflicts using the latest explicit operator instruction; keep historical evidence attached to its reviewed revision.

### One configuration authority

- **DISSOLVE is settled:** move parallel `lme_lab` selector/topology resolution and deployment orchestration into the existing loader, `ansible/roles/podman/filter_plugins/lme_manifests.py`, and `ansible/site.yml`. Do not retain the rejected engine behind installer selectors or rewrite the acceptance doctrine to legitimize it. Retain independently verified portable mechanisms as consumers of resolved configuration.
- Keep the path **inventory + service manifests + profile overlays → existing loader/filters → generic templates → Ansible reconciliation → `testing/e2e/deploy_gate.sh`**. Ansible emits one validated, versioned resolved configuration; helpers must not reload manifests, invent defaults, or perform another merge.
- Inventory owns machines, placement, connections, paths, and host overrides; service manifests own runtime owners, images, commands, resources, dependencies, credentials, and trust references. Generic tasks, filters, templates, installers, and gates must not hardcode `graph`/`trixie`/`silmaril`, source counts, placement, or deployment-specific ports. Declare each route once for publication, clients, authorization, and acceptance.
- Preserve **base → profile → operator override LAST**, including host-vars overrides and the legacy Elasticsearch shim (`ansible/roles/podman/tasks/load_manifests.yml`). Preserve default-off/single-host rendering and existing collector selection when new selectors are omitted. `--profile`, `--database-profile`, `--telemetry-profile`, and `--telemetry-destinations` must use the existing deployment path.

### Reconciliation and activation

- An unchanged apply preserves credentials, certificates, VM identities, data, monitors, subscriptions, and healthy processes. A changed configuration is a revision of the same deployment; restart only affected consumers. Resume interrupted operations from verified state, not remembered status.
- Removing a destination affects **new admissions only**. Preserve outstanding payloads, adapters, credentials, checkpoints, and recovery metadata until delivery obligations finish. Never automatically purge unverified records. Changing database profiles on initialized storage requires an explicit migration; `shared-ha` is not a fallback for failed `dual-owned-ha` admission.
- Derive required secrets from enabled services and their actual runtime owners; retain B3 and the manifest-driven consumer activation path. A GAP-5 shipping receipt does not close a downstream credential dependency. Exercise secret-bearing failure paths with synthetic canaries before real credentials; diagnostics contain allowlisted metadata, never raw registered secret results. Actual clients must verify both TLS chain and endpoint identity without insecure fallback.
- Rootless means owner-specific Podman storage, Quadlets, and systemd **user** managers; setting `User=` on a system Quadlet is insufficient. Malcolm's pinned Docker runtime and narrowly declared privileged helpers are exceptions. Verify routes and credential readability from the consuming owner/container namespace.

### Acceptance and review

- Derive expected services, collectors, destinations, and tests from the resolved manifest **before activation**. Runtime discovery cannot shrink that matrix. A required missing, skipped, stale, or unexecuted check is failed/blocked; optional inapplicability needs a manifest-derived reason. Record `required`, `applicable`, `executed`, `status`, and `evidence` separately.
- Collection requires a fresh attributable source occurrence and retrieved content at every selected destination; ports, HTTP acknowledgements, Fleet check-in, and healthy processes are insufficient. A stopped collector must fail acceptance even with healthy destinations. Prove Malcolm host-log readback separately from guest-scoped network analysis.
- Keep all three telemetry profiles × both database profiles and `multinode × tailscale` in acceptance scope. No silent profile substitution or reduced coverage. The 90-second target measures surviving clients' database reconnection with safe quorum/fencing; the 300-second replay target uses the declared backlog/load envelope. Neither proves whole-application HA or universal full-spool recovery.
- Architecture acceptance must rename hosts, relocate services, vary source rosters and declared values, repeat apply on the same deployment, and interrupt/resume through the **real loader/templates/Ansible path**. Tests of a parallel engine or fresh deployments alone cannot establish compliance.
- Campaign workflow is **MAIN → bounded coordinators → actual `.ocr`-configured Cursor/OpenCode CLI workers**. Resolve executable/model/trust bindings from current `.ocr` configuration; do not substitute silently. Native subagent critiques do not count as those CLI executions. Mapping uses 8 flow analysts + 6 requirements mappers; review uses 4 principal + 4 quality + 2 security + 2 testing reviewers with discourse.
- Preserve separate reproduction, patch, regression, integration, and independent-review evidence, bound to source/configuration digests and actual command output. Never manufacture a review receipt or reuse an earlier approval for a later diff. The recorded DISSOLVE follow-up re-review requires operator approval; source export is limited to the approved sanitized packet, not arbitrary workspace content.
