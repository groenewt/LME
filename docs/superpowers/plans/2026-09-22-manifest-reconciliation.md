# Reconcile the implementation, manifest architecture, and OCR workflow

  ## 1. Re-establish the requirements and account for every existing change

  The objective remains the full observability deployment in your final attached plan and four rebuttals. Manifest/template ownership, idempotency, composability, and the prescribed worker hierarchy are acceptance
  requirements. The three machines are one inventory on which to demonstrate that system.

  First, build one reconciliation register from the original .ocr lineage, your messages, the rebuttals, and the final plan. Each requirement records its authority, implementation owner, affected components,
  required tests, and current evidence. Conflicts are resolved using your latest explicit instructions; historical evidence remains attached to its original source revision.

  Every existing change receives an explicit disposition:

• Proposed Plan


  # Reconcile the implementation, manifest architecture, and OCR workflow

  ## 1. Re-establish the requirements and account for every existing change

  The objective remains the full observability deployment in your final attached plan and four rebuttals. Manifest/template ownership, idempotency, composability, and the prescribed worker hierarchy are acceptance
  requirements. The three machines are one inventory on which to demonstrate that system.

  First, build one reconciliation register from the original .ocr lineage, your messages, the rebuttals, and the final plan. Each requirement records its authority, implementation owner, affected components,
  required tests, and current evidence. Conflicts are resolved using your latest explicit instructions; historical evidence remains attached to its original source revision.

  Every existing change receives an explicit disposition:

   Disposition                          Treatment
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Retain after verification            Portable mechanisms such as durable delivery, strict TLS, canonical readback, secret redaction, and scoped fencing—provided their current code passes independent review.
  ───────────────────────────────────  ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   Refactor into the existing engine    Service configuration, owners, resource budgets, routes, collectors, credentials, lifecycle declarations, and acceptance expectations.
  ───────────────────────────────────  ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   Remove from the execution path       The parallel manifest loader, topology compiler, renderer, generated deployment orchestration, and hostname-specific dispatch.
  ───────────────────────────────────  ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   Preserve as incomplete evidence      Unfinished queue-drain logic, unqualified images, failed retirement attempts, prior reviews, and tests that validate only the rejected architecture.

  No blanket reset or deletion of your work. Passing old tests will not transfer acceptance to the revised implementation.

  Before further host mutation, reconcile actual external state: graph’s preservation and interrupted retirement, installed packages, created accounts, image directories, Tailscale policy changes, and issued
  credentials. Record exact ownership and recovery information. Do not recreate, revoke, or remove resources based solely on remembered status.

  ## 2. Restore the workflow you specified

  The execution hierarchy will be:

  MAIN → bounded domain coordinators → actual .ocr-configured Cursor/OpenCode workers.

  MAIN owns shared manifest contracts, integration, conflict resolution, deployment authorization within your existing scope, and the release verdict. Coordinators own these bounded areas:

  - Manifest composition, inventory, runtime ownership, and lifecycle.
  - Secrets, certificates, identity, and connectivity.
  - PostgreSQL ownership, replication, fencing, migrations, and restore.
  - Collection, HertzBeat exports, Malcolm integration, and interfaces.
  - Independent acceptance and evidence reconciliation.

  Coordinators will invoke the actual CLIs for their assigned implementation and review work. Native subagents organizing work will not be counted as those CLI executions.

  The current configured bindings are OpenCode openai/gpt-5.6-sol and Cursor cursor-grok-4.6-xhigh. Executable availability, model availability, and scoped workspace trust must be verified when invoked. No silent
  model substitution.

  Each worker receipt records executable/version, role, model, exact task/input, source digest, writable scope, output/diff, exit status, and executed tests. Coordinators review returned patches before MAIN
  integrates shared changes.

  The sequence includes the previously requested research fanout—including gippidy and the sibling integrations—before regenerating the map. Use the configured 8 flow analysts + 6 requirements mappers, followed by 4
  principal + 4 quality + 2 security + 2 testing reviewers, with discourse.

  The previous external critiques remain architecture-packet evidence only. Any additional source export must use a prepared, sanitized packet within its approved disclosure scope; the existing exact-packet approval
  will not be misrepresented as approval for arbitrary workspace export.

  ## 3. Make the existing manifest engine the sole authority

  The supported path remains:

  Inventory + service manifests + profile overlays → existing manifest loader and derivation filters → generic templates → Ansible reconciliation → existing deployment gate.

  The rejected framework will not remain an alternative backend.

  Configuration ownership

  - Inventory declares machines, placement, connections, storage locations, and host-specific overrides.
  - Service manifests declare runtime owners, images, commands, arguments, ports, dependencies, resources, configuration templates, credentials, and trust references.
  - Profile overlays select and configure those same service definitions.
  - Generic code implements validation, derivation, rendering, and execution. It does not choose graph, trixie, silmaril, fixed source counts, service placement, or deployment-specific port values.
  - Routes have one declaration, consumed by publication, client configuration, authorization, and acceptance. Malcolm’s UI cannot be independently declared in three factories.

  Extend the existing loader and lme_manifests.py; remove their dependency on the rejected topology resolver. Preserve existing merge semantics and operator overrides. Add database, telemetry, and runtime overlays
  using the established overlay structure, with explicit composition order and validation.

  Public entry points

  Keep the existing installer and these independent selectors:

  - --profile
  - --database-profile
  - --telemetry-profile
  - --telemetry-destinations

  They must reach the existing deployment path. Remove the current behavior that redirects these selections into a separate Python deployment framework. Omitted telemetry selectors preserve existing behavior.

  Ansible emits one validated, versioned resolved configuration for execution and evidence. Helpers consume that configuration; they cannot reload manifests, invent defaults, or run a second merge process.

  Runtime and lifecycle

  Extend generic rendering for actual per-owner user Quadlets, system services, timers, and narrowly scoped privileged helpers. Malcolm’s pinned Docker runtime remains the declared exception. Owners, paths, resource
  limits, and helper permissions come from resolved declarations.

  QEMU helpers perform lifecycle operations on declared resources. Exact UUIDs, disk identities, generations, and observed state remain protected operational records—not another desired-configuration language.

  Idempotency and updates

  Separate deployment identity from configuration revision. A changed configuration creates an auditable revision of the same deployment rather than requiring a new run to evade reconciliation.

  An unchanged apply must preserve credentials, certificates, VM identities, data, monitors, subscriptions, and healthy service processes. Changes restart only affected consumers. Interrupted operations resume from
  verified state.

  Removing a destination changes new admissions only. Existing delivery obligations retain the adapters, credentials, payloads, and recovery metadata needed to finish. Database-profile changes on initialized storage
  require an explicit migration; they are never treated as ordinary reapplication.

  ## 4. Prove architectural compliance before deploying again

  The first acceptance barrier tests the architecture through the real loader, templates, and Ansible path:

  - Rename inventory hosts without modifying executable code.
  - Relocate HertzBeat, UI, AI, and destination services through inventory changes.
  - Add or remove collector sources without editing fixed rosters or expected counts, while preserving required HA membership.
  - Override declared ports, owners, paths, resources, and endpoint identities.
  - Exercise all three telemetry selections × both database profiles, plus existing deployment/connectivity cases, including multinode × Tailscale.
  - Apply the same configuration twice and verify stable native identities, unchanged configuration files, and no unnecessary restart or credential regeneration.
  - Change configuration on the existing deployment, verify the intended delta, and preserve unrelated resources.
  - Interrupt provisioning, rendering, credential rotation, and reconciliation; resume without duplication or loss.
  - Omit required dependencies and verify rejection before mutation.

  Tests must challenge the implementation’s assumptions. Literal six-source fixtures, two identical GET requests, and fresh deployments alone cannot establish composability or idempotency.

  Acceptance expectations come from approved profile requirements and the resolved manifest before activation. Running-service discovery cannot shrink the expected matrix. Missing required services or collectors
  fail; they cannot disappear into “not applicable.”

  ## 5. Reintegrate and qualify the complete requested system

  Once the architectural barrier passes, proceed through the original deployment requirements:

  1. Security remediation: reproduce and close R1, consumer credential dependencies, strict TLS, consumer-profile activation, route composition, and gate false passes. Re-run synthetic secret failure tests before
     real credentials traverse changed paths.

  2. Resource admission and bootstrap: use the final inventory allocations—graph 13 GiB, trixie 12 GiB, silmaril 48 GiB—with AI on silmaril. Verify actual capacity, rootless ownership, storage, namespace-specific
     access, and exclusions.

  3. Database foundations: establish the two PostgreSQL 17/Patroni ownership domains, shared etcd, fencing, schema-only initialization, selected logical exchange, strict durability, and isolated restore.
     Independently qualify the shared-HA alternative.

  4. Collection and interfaces: activate declared OTel, HertzBeat SSH/SQL/REST/JMX, Wazuh, Tailscale telemetry/certificates, durable exports, Elastic views, Malcolm host/network evidence, browser authentication, and
     AI provenance.

  5. Functional and failure acceptance: require real source records at every selected destination within 120 seconds; advancing metrics across three intervals; genuine lifecycle and security events; usable
     interfaces; destination exclusion; TLS/authentication negatives; collector stoppage; sink failures; replay, quota, restart, failover, restore, and guest-reboot tests.

  6. Repeat and review: prove same-deployment reconciliation separately from fresh-overlay deployment. Complete current-source provider work and the configured review/discourse round. Bind results to the exact
     source, resolved configuration, artifacts, and runtime observations.

  The original 90-second database-recovery and 300-second declared-backlog replay targets remain. Full-capacity spool tests remain separate. No reduced collection coverage, silent profile substitution, or weaker
  durability target will be used to obtain a pass.

  Direct Windows inspection and collection remain excluded; your later authorization permits tailnet-wide control-plane metadata reads. Preserve unresolved records and recovery evidence before scoped cleanup. No
  physical-host shutdown, blanket wipe, commit, or push is introduced.

  Completion requires both a composable, idempotent deployment mechanism and the fully verified operational outcome. Neither can substitute for the other.
