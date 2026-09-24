# -*- coding: utf-8 -*-
# LME manifest render filters (work-group G1 -- "manifest spine").
#
# This is the ONLY place the userns / cert-owner derivation ARITHMETIC lives.
# The two seed constants it operates on (subuid_base, slot_size) are NOT
# hardcoded here -- they are read from `lme_global` (manifests/global.yml).
# Everything else in the render path (templates, task files) is literal-free and
# defers to these filters, so there is a single provable source of truth for:
#   * userns id-mapping bases            (render_userns / userns_base)
#   * per-consumer cert key owner uids   (cert_owner)
#   * logical service name -> systemd .service unit name  (svc_unit)
#   * PublishPort= value assembly        (render_port)
#   * Volume= value assembly incl. cert:<svc> host-tree expansion (render_volume)
#   * enable/skip decision from profile flags  (is_enabled)
#   * Elasticsearch JVM heap opts + derived cgroup memory caps (jvm_opts / mem_derive)
#   * per-service MemoryMax resolution + SF-8 co-residency budget (service_memory_max / memory_budget)
#
# THE derivation fact (stored as index/step in global.yml, derived everywhere else):
#   userns_base(svc) = subuid_base + slot(svc) * slot_size
#   cert key owner   = userns_base(svc) + in_container_uid
# e.g. subuid_base=165536, slot_size=3048:
#   elasticsearch slot 0 -> 165536 ; + in_container_uid 1000 -> 166536
#   kibana        slot 1 -> 168584 ; + 1000 -> 169584
#   a consumer with no numbered slot falls back to subuid_base (165536), which is
#   exactly the observed `lme_backups` volume owner (165536 = 165536 + 0 + 0).

from __future__ import absolute_import, division, print_function
import hashlib
import json
import re

__metaclass__ = type


def _slot_base(slot, lme_global):
    """subuid_base + slot*slot_size. Unknown/None slot -> subuid_base (no remap).

    This is the single implementation of the base-address arithmetic. `slot` is a
    logical key into lme_global.slots; a name absent from that map (e.g. a beat
    that runs without its own id-mapping) resolves to the raw subuid_base, which
    matches the observed `lme_backups`/host-side owner of 165536.
    """
    base = int(lme_global['subuid_base'])
    step = int(lme_global['slot_size'])
    slots = lme_global.get('slots', {})
    if slot is not None and slot in slots:
        return base + int(slots[slot]) * step
    return base


def userns_base(slot, lme_global):
    """Public: derived id-mapping base for a slot (or subuid_base if unslotted)."""
    return _slot_base(slot, lme_global)


def render_userns(userns, lme_global):
    """Render the value of a quadlet `UserNS=` directive from a userns directive.

    Supported modes (structural only -- no service names or numbers baked in):
      * {mode: auto, slot: <name>}      -> auto:uidmapping=0:BASE:SIZE,gidmapping=0:BASE:SIZE
      * {mode: share_with, service: X}  -> container:lme-X   (share X's namespace)
      * {mode: auto_unpinned}           -> auto
    where BASE = subuid_base + slot*slot_size and SIZE = slot_size.
    """
    cfg = lme_global['userns']
    mode = userns.get('mode', cfg['default_mode'])
    if mode == 'share_with':
        return cfg['share_ref'].format(name=userns['service'])
    if mode == 'auto_unpinned':
        return cfg['unpinned_value']
    # mode == auto (pinned id-mapping)
    base = _slot_base(userns.get('slot'), lme_global)
    size = int(lme_global['slot_size'])
    return cfg['auto_format'].format(base=base, size=size)


def cert_owner(certs, lme_global):
    """Host uid that must own a consumer's published cert bundle (B4).

    Two declarative id-mapping regimes, both expressed in the manifest (never
    guessed by the publisher):
      * pinned userns (UserNS=auto:uidmapping=0:BASE:SIZE): the container's
        in_container_uid maps to host BASE+in_container_uid, so
        owner = userns_base(slot) + in_container_uid.
      * host userns (certs.host_userns: true -- no UserNS= remap, e.g. a beat that
        must read the host journal as real host root/uid): the container uid IS the
        host uid, so owner = in_container_uid (base 0, NO subuid offset). This is
        the honest owner; a root host-userns consumer owns its bundle as uid 0.
    Consumed by the cert-publishing step (init-setup.sh / G5) to chown
    /opt/lme/certs/<svc>; NOT emitted into any .container file, so it never affects
    unit fidelity.
    """
    base = 0 if certs.get('host_userns') else _slot_base(certs.get('slot'), lme_global)
    in_uid = certs.get('in_container_uid',
                       lme_global.get('certs', {}).get('default_in_container_uid', 0))
    return base + int(in_uid)


def svc_unit(logical, kind='container'):
    """Logical service name -> the systemd unit name quadlet generates for it.

    Quadlet naming rules (verified against the current units):
      * the umbrella target      -> lme.service           (logical 'lme' / kind target)
      * lme.network              -> lme-network.service    (kind network / logical 'network')
      * lme-<x>.volume           -> lme-<x>-volume.service (kind volume)
      * lme-<x>.container        -> lme-<x>.service        (kind container, the default)
    """
    if logical == 'lme' or kind == 'target':
        return 'lme.service'
    if kind == 'network' or logical == 'network':
        return 'lme-network.service'
    if kind == 'volume':
        return 'lme-%s-volume.service' % logical
    return 'lme-%s.service' % logical


def unit_refs(items, kinds=None):
    """Space-joined list of svc_unit()s for Requires=/After=/Wants=/PartOf=.

    `kinds` maps logical name -> kind (built from lme_services at load time); a
    name missing from it defaults to 'container', except the always-special
    'lme' (target) and 'network' which svc_unit resolves on its own.
    """
    kinds = kinds or {}
    return ' '.join(svc_unit(it, kinds.get(it, 'container')) for it in (items or []))


def wanted_by(items, kinds=None):
    """Value for [Install] WantedBy=. Raw systemd targets/units pass through
    verbatim (default.target, multi-user.target); bare logical names resolve via
    svc_unit (so 'lme' -> lme.service)."""
    kinds = kinds or {}
    out = []
    for it in (items or []):
        if it.endswith('.target') or it.endswith('.service') or it.endswith('.path'):
            out.append(it)
        else:
            out.append(svc_unit(it, kinds.get(it, 'container')))
    return ' '.join(out)


def _requires_partition(requires, host_services):
    """Partition a service's hard `requires:` list against the local host roster.

    GAP-3 host-scoping. When a consumer (e.g. dashboard) is scoped onto a host
    that does NOT run every unit it hard-requires (its elasticsearch / litellm /
    pgvector / embeddings targets live on the producer host), those cross-host ids
    must NOT stay in Requires=: a hard Requires= on a unit that will never exist on
    THIS host makes the consumer fail to start. They are RELAXED to Wants= (soft --
    a no-op when the target is absent). Ids whose target IS in the roster stay in
    Requires= (KEEP). This realises the design's rule "either INCLUDE or RELAX --
    never hand-drop a unit": every input id lands in exactly one output list.

    Returns (keep, relax) with input order preserved within each list, so the two
    are a stable partition of the input and unit_refs() renders them deterministically.

    BACKWARD-COMPAT (the single most important property, mirrored by the render-site
    `when:` clause): host_services FALSY -- undefined resolves to None via the
    template's `| default(None)`, and the empty list is the explicit full-host roster
    -- means NO host scoping, so keep == the full input list and relax == []. Then
    container.j2 renders exactly today's Requires= and adds nothing to Wants=:
    byte-identical to pre-GAP-3. (None and [] MUST behave identically here because the
    render-site clause treats `[]` as "render everything" too -- see gap3-contract.md
    HAZARD-1; a filter that scoped on [] would disagree with the clause and brick
    every existing full-host run.)
    """
    reqs = list(requires or [])
    if not host_services:
        return reqs, []
    roster = set(host_services)
    keep = [r for r in reqs if r in roster]
    relax = [r for r in reqs if r not in roster]
    return keep, relax


def requires_keep(requires, host_services=None):
    """GAP-3: the `requires:` ids to KEEP as a hard Requires= on this host -- those
    whose target unit IS in the host roster. host_services None/empty -> the full
    input list (backward-compat identity). Composes BEFORE unit_refs, which does not
    prune (it maps every id to a unit ref), so the pruning must happen here:
      Requires = service.dependencies.requires | requires_keep(lme_host_services) | unit_refs(kinds)
    """
    keep, _relax = _requires_partition(requires, host_services)
    return keep


def requires_relax(requires, host_services=None):
    """GAP-3: the `requires:` ids to RELAX to a soft Wants= on this host -- those
    whose target unit is NOT in the host roster (it runs on another host).
    host_services None/empty -> [] (nothing relaxed; backward-compat identity). Fed
    into Wants= alongside the service's own declared wants:
      Wants = (wants | default([]) + requires | requires_relax(lme_host_services)) | unit_refs(kinds)
    Relax applies ONLY to `requires` (the hard gate). `after`/`partof`/`binds_to` are
    left untouched: After= on an absent unit is a harmless ordering no-op, and PartOf=
    targets the always-listed `lme` umbrella (infra floor -- see gap3-contract.md).
    """
    _keep, relax = _requires_partition(requires, host_services)
    return relax


def render_port(p):
    """{host, container, bind?, protocol?} -> a PublishPort= value.
      {host:9200,container:9200}                       -> 9200:9200
      {host:5044,container:5044,bind:127.0.0.1}        -> 127.0.0.1:5044:5044
      {host:514, container:514, protocol:udp}          -> 514:514/udp
    """
    s = ''
    if p.get('bind'):
        s += '%s:' % p['bind']
    s += '%s:%s' % (p['host'], p['container'])
    if p.get('protocol'):
        s += '/%s' % p['protocol']
    return s


def render_volume(vol, lme_global):
    """{source, dest, options[]} -> a Volume= value.

    source is one of:
      * a named podman volume        (e.g. lme_certs, lme_esdata01)  -> verbatim
      * an absolute host path        (e.g. /opt/lme/config/x.yml)    -> verbatim
      * 'cert:<svc>'                 -> expands to <certs.host_tree>/<svc>  (B4:
        the per-service published bundle, NOT the shared workspace volume)
    """
    src = vol['source']
    if src.startswith('cert:'):
        svc = src.split(':', 1)[1]
        src = '%s/%s' % (lme_global['certs']['host_tree'], svc)
    s = '%s:%s' % (src, vol['dest'])
    opts = vol.get('options') or []
    if opts:
        s += ':%s' % ','.join(opts)
    return s


def podman_args(network_aliases=None, extra=None):
    """Assemble the PodmanArgs= value: one --network-alias per alias, then any
    verbatim extra tokens (health flags, --entrypoint, --requires, --cap-add...)."""
    parts = []
    for a in (network_aliases or []):
        parts.append('--network-alias %s' % a)
    for e in (extra or []):
        parts.append(e)
    return ' '.join(parts)


# The 'always' sentinel is a no-op (an always-on unit), NOT a flag lookup.
ALWAYS = 'always'

# Canonical enable-flag names. This MIRRORS the flags dict that load_manifests.yml
# assembles for is_enabled() to consult (ansible/roles/podman/tasks/load_manifests.yml:77-82
# -- install_llm / install_elastic_services / offline_mode), which is the single
# constructor of lme_enable_flags. The 'always' sentinel is deliberately NOT a
# member (it means "always render", not a variable). Kept inline with this
# citation for the same reason the B3 secret guard hardcodes its known-set inline
# (container_setup.yml:190-209): the resolver has no ansible runtime to read the
# task var from. An enabled_when token that is neither 'always' nor one of these
# is a typo (e.g. 'install_lmm'); is_enabled() rejects it LOUDLY rather than
# silently evaluating it False and dropping the unit from the render.
#
# SINGLE SOURCE OF TRUTH: this frozenset MUST equal the set of
# manifests/global.yml lme_config_registry fields marked `enable_flag: true`. The
# pure filter cannot read that manifest at call time (no ansible runtime) and is
# consulted by callers that legitimately pass a PARTIAL/empty flags dict (see the
# many `is_enabled(..., lme_enable_flags | default({}))` call sites), so the typo
# guard must key off this STATIC set, not the passed dict. The equality with the
# registry is enforced DECLARATIVELY (a loader-test case compares the registry's
# enable_flag keys to the `lme_known_enable_flags` filter) -- drift fails the suite.
# Do NOT add a member without declaring the field (enable_flag: true) in the
# registry, and vice versa.
KNOWN_ENABLE_FLAGS = frozenset((
    'install_llm',
    'install_elastic_services',
    'install_otel',
    'install_legacy_beats',
    'offline_mode',
))


def is_enabled(enabled_when, flags=None, context=None):
    """True iff every flag in enabled_when is truthy in `flags`. The sentinel
    'always' is a no-op (an always-on unit), NOT a variable lookup -- so
    enabled_when:[always] renders, and an empty/omitted list also renders.

    Fail-closed on typos (symmetric with the B3 secret guard, which validates the
    enabled-secret set against a known set before creating anything): every
    non-sentinel token MUST be a known enable flag (KNOWN_ENABLE_FLAGS, mirroring
    load_manifests.yml). A misspelled flag -- e.g. enabled_when:[install_lmm] --
    would otherwise resolve False and SILENTLY drop the service from the render
    with no error; instead it raises ValueError (this file's error idiom; the
    resolver is imported with no ansible runtime, so AnsibleFilterError is not
    available) naming the offending token, and `context` (the service id) when a
    caller supplies it. A KNOWN flag merely ABSENT from `flags` is NOT an error:
    an unset gate is off, so it evaluates False (the [install_llm] + {} -> False
    contract). Validation runs over the WHOLE list first, so an earlier
    False-evaluating gate can never short-circuit past a later typo."""
    flags = flags or {}
    if not enabled_when:
        return True
    # Pass 1: validate every token before evaluating any gate, so a legitimately
    # unmet gate earlier in the list cannot mask a misspelled flag later in it.
    for f in enabled_when:
        if f == ALWAYS:
            continue
        if f not in KNOWN_ENABLE_FLAGS:
            where = ' for service %r' % (context,) if context else ''
            raise ValueError(
                'lme: unknown enabled_when flag %r%s -- not the %r sentinel and '
                'not a known enable flag %s. Fix the typo, or declare the flag '
                '(enable_flag: true) in manifests/global.yml lme_config_registry.'
                % (f, where, ALWAYS, sorted(KNOWN_ENABLE_FLAGS)))
    # Pass 2: AND over the (now validated) gates. An absent flag is OFF (False),
    # matching the docstring's [install_llm] + {} -> False contract. There is NO
    # per-flag hidden default here: the DECLARED default lives in the registry
    # (install_legacy_beats default: true, etc.) and reaches lme_enable_flags
    # through the resolver, so is_enabled() never re-invents a default. (Removed
    # RC-OPEN-4: `flags.get(f, f == 'install_legacy_beats')` asymmetrically
    # defaulted one flag True, contradicting this docstring.)
    for f in enabled_when:
        if f == ALWAYS:
            continue
        value = flags.get(f, False)
        if type(value) is not bool:
            if isinstance(value, str) and value.lower() in ('true', 'false'):
                value = value.lower() == 'true'
            else:
                raise ValueError('lme: enable flag %s must be true or false' % f)
        if not value:
            return False
    return True


def _split_size(value):
    """'4g' -> (4.0, 'g'). Bare number -> (n, '')."""
    m = re.match(r'^\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]*)\s*$', str(value))
    if not m:
        raise ValueError('lme: cannot parse size %r' % (value,))
    return float(m.group(1)), m.group(2)


def jvm_opts(resources):
    """Elasticsearch ES_JAVA_OPTS *value*, FULLY QUOTED (the quotes are
    load-bearing: the value contains spaces and systemd Environment= would
    otherwise split it -- the exact logstash whitespace trap). B1: -Xms/-Xmx are
    always assembled from resources.heap, so heap is a single knob.

      {heap:4g, jvm_base:'-Des.entitlements.enabled=false'}
        -> "-Des.entitlements.enabled=false -Xms4g -Xmx4g"
    """
    heap = resources['heap']
    parts = []
    base = resources.get('jvm_base')
    if base:
        parts.append(base)
    parts.append('-Xms%s' % heap)
    parts.append('-Xmx%s' % heap)
    return '"%s"' % ' '.join(parts)


def mem_derive(heap, factor):
    """Derive a systemd MemoryHigh=/MemoryMax= value from the heap and a factor.
    Unit is normalised to uppercase for systemd (4g -> 6G at 1.5, 8G at 2.0),
    matching the caps the current template emits for single-node."""
    num, unit = _split_size(heap)
    val = num * float(factor)
    if val == int(val):
        val = int(val)
    return '%s%s' % (val, unit.upper())


def _to_bytes(value):
    """systemd size string ('6G', '512M', '8g', bare number) -> integer bytes.
    Binary units (1G = 1024^3) to match systemd's MemoryMax= interpretation."""
    num, unit = _split_size(value)
    factors = {'': 1, 'b': 1, 'k': 1024, 'm': 1024 ** 2,
               'g': 1024 ** 3, 't': 1024 ** 4}
    key = unit[0].lower() if unit else ''
    if key not in factors:
        raise ValueError('lme: unknown size unit %r in %r' % (unit, value))
    return int(num * factors[key])


def service_memory_max(resources):
    """The MemoryMax a service's `resources` block resolves to, as a systemd size
    string (or None when the service declares no cap). Mirrors container.j2's two
    declaration forms EXACTLY so the summed budget matches what is rendered:
      * JVM service     (resources.heap set): heap * memory_max_factor (default 2),
        via mem_derive -- the same value the template emits.
      * non-JVM service (no heap): resources.memory_max, declared verbatim.
    """
    if not resources:
        return None
    if resources.get('heap') is not None:
        return mem_derive(resources['heap'], resources.get('memory_max_factor', 2))
    if resources.get('memory_max') is not None:
        return resources['memory_max']
    return None


def memory_budget(services, flags=None, lme_global=None, host_services=None):
    """SF-8 co-residency budget. Sum the MemoryMax of every ENABLED container
    service that declares a cap, and compare against the host budget declared in
    lme_global.budget (host_ram_gb minus reserve_gb).

    Args:
      services: the lme_services map (id -> resolved manifest dict).
      flags:    the same enable-flags dict is_enabled() consults (install_llm /
                install_elastic_services / offline_mode). Unenabled services are
                excluded from the sum -- so the budget reflects THIS install's set.
      lme_global: supplies lme_global.budget {host_ram_gb, reserve_gb}.
      host_services: OPTIONAL GAP-3 host roster (list of service ids). When
                supplied and non-empty, only services whose id is in the roster
                enter the sum -- so a host scoped to a couple of consumers is not
                charged co-residency for the whole stack it does not run. Checked
                AFTER is_enabled() so is_enabled()'s fail-loud typo guard still
                fires for every manifest, scoped-in or not. host_services
                None/empty -> no host filtering -> byte-identical to the pre-GAP-3
                budget (the render-site `when:` clause treats `[]` as full-host too).

    Returns a fact dict a preflight task can consume:
      {total_bytes, total_gb, host_ram_gb, reserve_gb, usable_gb,
       over_budget, oversized, capped, uncapped}
      * capped   : id -> its MemoryMax (the services that entered the sum).
      * uncapped : enabled container services with NO cap (e.g. fleet-server,
                   logstash) -- EXCLUDED from the sum and surfaced so the total
                   is not mistaken for the whole stack's real footprint.
      * over_budget: total_gb > usable_gb (usable = host_ram_gb - reserve_gb).
                   This is an OVER-COMMIT signal, NOT a fit/OOM prediction:
                   MemoryMax is a per-service systemd KILL CEILING, not a
                   reservation, and services rarely reach their ceilings at once.
                   Empirically the default+llm stack (23G of ceilings: ES 8 +
                   kibana 5 + llm 10) runs on a 14G host. So over_budget is
                   ADVISORY -- a preflight should WARN (loud) on it, NOT hard-fail,
                   else it false-blocks a profile the deploy pipeline proves good.
      * oversized: enabled services whose OWN MemoryMax exceeds usable RAM. That
                   IS a deterministic OOM-kill (e.g. kibana 5G on a 4G host), so
                   it is the real hard gate -- a preflight asserts `oversized == []`
                   and only WARNS on over_budget (see container_setup.yml SF-8).
    """
    flags = flags or {}
    lme_global = lme_global or {}
    budget = lme_global.get('budget', {})
    host_ram_gb = float(budget.get('host_ram_gb', 0))
    reserve_gb = float(budget.get('reserve_gb', 0))
    total_bytes = 0
    capped = {}
    uncapped = []
    for sid, svc in (services or {}).items():
        if svc.get('kind') != 'container':
            continue
        if not is_enabled(svc.get('enabled_when'), flags, context=sid):
            continue
        # GAP-3 host-scoping (optional): with a roster, budget only what THIS host
        # runs. AFTER is_enabled so a scoped-OUT service with a misspelled
        # enabled_when is still caught loudly (never a silently narrowed guard).
        # host_services None/empty -> no filtering -> byte-identical to pre-GAP-3.
        if host_services and sid not in host_services:
            continue
        cap = service_memory_max(svc.get('resources'))
        if cap is None:
            uncapped.append(sid)
            continue
        total_bytes += _to_bytes(cap)
        capped[sid] = cap
    total_gb = total_bytes / float(1024 ** 3)
    usable_gb = host_ram_gb - reserve_gb
    usable_bytes = usable_gb * (1024 ** 3)
    oversized = sorted([sid for sid, cap in capped.items()
                        if usable_gb > 0 and _to_bytes(cap) > usable_bytes])
    return {
        'total_bytes': total_bytes,
        'total_gb': round(total_gb, 3),
        'host_ram_gb': host_ram_gb,
        'reserve_gb': reserve_gb,
        'usable_gb': usable_gb,
        'over_budget': bool(usable_gb > 0 and total_gb > usable_gb),
        'oversized': oversized,
        'capped': capped,
        'uncapped': sorted(uncapped),
    }


def strict_enable_bool(value):
    if type(value) is bool:
        return value
    if isinstance(value, str) and value.lower() in ('true', 'false'):
        return value.lower() == 'true'
    raise ValueError('lme: enable flag must be true or false')


_SELECTION_ORIGINS = ('extra_var', 'inventory')  # caller-VERIFIABLE finer sources
_COMBINED_OPERATOR = 'operator'                   # honest native-selected label (A5)
_OBSERVED_ORIGINS = ('observation', 'build')      # inferred/derived: NOT defaultable
_SUPPORTED_TYPES = ('bool', 'str', 'int', 'list', 'dict', 'map')  # the only declarable field types


def _require_registry_shape(registry):
    """Structural gate for BOTH resolve and validate (C1-VALIDATE-CALL / A1). A
    malformed or empty registry RAISES, so a reversed Jinja pipe (`resolved |
    lme_validate_config(registry)` -> registry bound to `resolved`, resolved bound to
    `registry`) can never pass silently -- it hits "no fields" here and fails closed.
    Also validates the precedence COMPOSITION (A2): every tier has a declared channel,
    no duplicate tier, `default` is last, and no observation/build field is defaultable
    (an inferred value is not an explicit choice). Every field MUST declare a SUPPORTED
    type -- this runs BEFORE any value is inspected, so a nullable field declaring an
    unsupported type can no longer slip a null past validation via the None short-circuit
    in _coerce_declared / _canonical_ok (C1-UNKNOWN-NULLABLE-TYPE). Returns (fields,
    precedence, channels)."""
    if not isinstance(registry, dict):
        raise ValueError('lme: config registry must be a mapping')
    fields = registry.get('fields')
    if not isinstance(fields, dict) or not fields:
        raise ValueError('lme: config registry has no fields (malformed or reversed registry argument)')
    precedence = registry.get('precedence')
    if not isinstance(precedence, list) or not precedence:
        raise ValueError('lme: config registry has no precedence list')
    if len(precedence) != len(set(precedence)):
        raise ValueError('lme: config registry precedence has a duplicate tier %r' % (precedence,))
    channels = registry.get('channels') or {}
    for tier in precedence:
        if tier not in channels:
            raise ValueError('lme: precedence tier %r has no declared channel' % (tier,))
    if precedence[-1] != 'default':
        raise ValueError("lme: config registry precedence must end with the 'default' tier")
    for key, field in fields.items():
        if not isinstance(field, dict):
            raise ValueError('lme: field %r declaration is not a mapping' % (key,))
        if field.get('type') not in _SUPPORTED_TYPES:
            raise ValueError(
                'lme: field %r declares unsupported/absent type %r (supported: %r) -- schema '
                'checked before any value, so a nullable unsupported-type field cannot pass'
                % (key, field.get('type'), list(_SUPPORTED_TYPES)))
        if field.get('origin') in _OBSERVED_ORIGINS and 'default' in field:
            raise ValueError(
                'lme: field %r declares origin %r (inferred/derived) and therefore MUST NOT '
                'carry a default -- an inferred value is not an explicit choice' % (key, field.get('origin')))
        # OBSERVATION-ONLY shape (C1-OBSERVATION-ORIGIN-DOES-NOT-RESTRICT-CHANNEL). A field that
        # may be filled ONLY by the observation channel must be self-consistent: it declares
        # origin: observation (so it carries no default and its honest origin is `observation`)
        # AND upgrade_fallback: true (the observation channel's requires_field -- without it the
        # observation tier could never fill the field, making observation_only a dead declaration).
        if field.get('observation_only'):
            if field.get('origin') != 'observation':
                raise ValueError(
                    'lme: field %r is observation_only but does not declare origin: observation '
                    '-- an observation-only field must be honestly labelled observed' % (key,))
            if not field.get('upgrade_fallback'):
                raise ValueError(
                    'lme: field %r is observation_only but does not declare upgrade_fallback: true '
                    '-- the observation channel (requires_field: upgrade_fallback) could otherwise '
                    'never fill it' % (key,))
    return fields, precedence, channels


def _coerce_declared(value, field):
    """RESOLVE-time normalization to the declared type, preserving an explicit
    False / 0 / '' / [] / {} as a real selection. Value-pure: the type token comes
    from the registry field. Distinct from _canonical_ok (validate-time), which
    REJECTS rather than coerces.

      * null:      kept only if the field is nullable, else a loud error.
      * bool:      via strict_enable_bool (rejects non-bool, non-'true'/'false').
      * str:       kept (stringified only if a non-str slipped through).
      * int:       int, or a numeric string; a bool is NOT an int.
      * list/dict: must already be that collection (empty allowed; merge semantics
                   -- e.g. atomic replace vs deep merge -- are the caller/loader's,
                   declared per field via `merge:`)."""
    if value is None:
        if field.get('nullable'):
            return None
        raise ValueError('lme: config value is null but field is not nullable')
    t = field.get('type')
    if t == 'bool':
        return strict_enable_bool(value)
    if t == 'str':
        return value if isinstance(value, str) else str(value)
    if t == 'int':
        if isinstance(value, bool):
            raise ValueError('lme: int field got a bool %r' % (value,))
        if isinstance(value, int):
            return value
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            raise ValueError('lme: int field value %r is not an integer' % (value,))
    if t == 'list':
        if not isinstance(value, list):
            raise ValueError('lme: list field value %r is not a list' % (value,))
        return value
    if t in ('dict', 'map'):
        if not isinstance(value, dict):
            raise ValueError('lme: %s field value %r is not a mapping' % (t, value))
        return value
    raise ValueError('lme: unknown declared config type %r' % (t,))


def _canonical_ok(value, field):
    """VALIDATE-time predicate (C1-CANONICAL-VALIDATION / A3): True iff `value` is
    ALREADY the exact declared type -- NO coercion. This is what makes validation
    reject a bool field still holding the string 'false', a str field holding an
    arbitrary object, etc., rather than silently coercing them."""
    if value is None:
        return bool(field.get('nullable'))
    t = field.get('type')
    if t == 'bool':
        return isinstance(value, bool)
    if t == 'str':
        return isinstance(value, str)
    if t == 'int':
        return isinstance(value, int) and not isinstance(value, bool)
    if t == 'list':
        return isinstance(value, list)
    if t in ('dict', 'map'):
        return isinstance(value, dict)
    return False


def _channel_value(tier, channels, field, key, selections, profile_vars, observations):
    """(has_value, value) for `key` at precedence `tier`, per the tier's DECLARED
    channel source. Membership (not truthiness) decides presence, so an explicit
    False / 0 / '' / [] / {} counts as present."""
    src = (channels.get(tier) or {}).get('source')
    if src == 'selections':
        if key in selections:
            return True, selections[key]
    elif src == 'profile_vars':
        if key in profile_vars:
            return True, profile_vars[key]
    elif src == 'observations':
        req = (channels.get(tier) or {}).get('requires_field')
        if (not req or field.get(req)) and key in observations:
            return True, observations[key]
    elif src == 'field_default':
        if 'default' in field:
            return True, field['default']
    else:
        raise ValueError('lme: precedence tier %r has unknown channel source %r' % (tier, src))
    return False, None


def _honest_origin(tier, channels, key, origins, vocab):
    """A5: never emit a false attribution. For a caller channel (provenance:caller,
    i.e. the operator tiers) a caller-VERIFIED finer origin (extra_var|inventory) is
    preserved IF supplied and declared; otherwise the honest combined label
    `operator` is recorded. A caller label that lies about the tier (e.g. `default`
    for a selected value) is DISCARDED, not propagated. For profile/observation/
    default the origin IS the tier name."""
    if (channels.get(tier) or {}).get('provenance') == 'caller':
        claimed = origins.get(key)
        if claimed in _SELECTION_ORIGINS and claimed in vocab:
            return claimed
        return _COMBINED_OPERATOR
    if tier in vocab:
        return tier
    raise ValueError('lme: tier %r is not in the declared origin vocabulary' % (tier,))


def lme_resolve_config(registry, profile_vars=None, selections=None,
                       observations=None, origins=None):
    """Resolve every declared config field by ITERATING registry.precedence (so the
    declaration is EFFECTIVE, C1-DECLARED-PRECEDENCE / A2) into one dict, with NO
    snapshot and NO self-capture: reads ONLY its explicit arguments and returns
    NAMESPACED outputs, so a caller materialising lme_resolved.* / lme_enable_flags
    never feeds an output back in.

    Precedence tiers + their sources are DECLARED in registry.channels; the default
    order is extra_var > inventory > profile > observation(only where
    field.upgrade_fallback) > default. Membership (not truthiness) selects a tier, so
    an explicit False/0/''/[]/{} at a higher tier is honoured and an observation can
    never overwrite it. A REQUIRED field with no value at any tier raises (fail-closed,
    pre-mutation); an OPTIONAL field with no value is ABSENT from `resolved`.

    Returns {resolved, origins, enable_flags}. Origins are honest (A5): a
    natively-selected value with no caller-verified finer source is labelled
    `operator`, never falsely extra_var/inventory."""
    fields, precedence, channels = _require_registry_shape(registry)
    profile_vars = profile_vars or {}
    selections = selections or {}
    observations = observations or {}
    origins = origins or {}
    vocab = set(registry.get('origin_vocabulary') or (list(precedence) + [_COMBINED_OPERATOR]))

    # Managed-key assert (symmetric with is_enabled()'s typo guard): a profile var,
    # selection or observation naming no declared field is an authoring error --
    # adding a field must be a registry change, not a silent ungoverned key.
    for label, src in (('profile', profile_vars), ('selection', selections), ('observation', observations)):
        unknown = [k for k in src if k not in fields]
        if unknown:
            raise ValueError(
                'lme: %s names undeclared config key(s) %r; declare them in '
                'manifests/global.yml lme_config_registry.fields' % (label, sorted(unknown)))

    # OBSERVATION-ONLY CHANNEL ENFORCEMENT (C1-OBSERVATION-ORIGIN-DOES-NOT-RESTRICT-CHANNEL). A
    # field declared observation_only may be filled ONLY by the observation channel -- an
    # origin=observation LABEL alone is insufficient. Reject it appearing in an operator
    # selection (extra_var/inventory) or a profile overlay; only a verified read-only
    # observation may supply it. (The observation channel itself still gates on upgrade_fallback,
    # and _honest_origin labels the value `observation`.) The `default` channel cannot reach it
    # either, because origin: observation forbids a declared default (registry-shape gate).
    obs_only = set(k for k, f in fields.items() if f.get('observation_only'))
    bad_channel = sorted(k for k in obs_only if k in selections or k in profile_vars)
    if bad_channel:
        raise ValueError(
            'lme: observation-only field(s) %r were supplied via an operator selection '
            '(extra_var/inventory) or a profile overlay -- an observation-only value may come '
            'ONLY from the observation channel (a verified read-only observation), never from '
            '-e / inventory / profile / default' % bad_channel)

    resolved = {}
    out_origins = {}
    for key, field in fields.items():
        found = False
        for tier in precedence:
            has, value = _channel_value(tier, channels, field, key, selections, profile_vars, observations)
            if has:
                out_origins[key] = _honest_origin(tier, channels, key, origins, vocab)
                resolved[key] = _coerce_declared(value, field)
                found = True
                break
        if not found and field.get('required'):
            raise ValueError(
                'lme: required config field %r has no value from any tier '
                '(declared precedence %r)' % (key, precedence))

    enable_flags = {k: resolved[k] for k, f in fields.items()
                    if f.get('enable_flag') and k in resolved}
    return {'resolved': resolved, 'origins': out_origins, 'enable_flags': enable_flags}


def lme_validate_config(registry, resolved):
    """Validate an ALREADY-CANONICAL resolved dict against the registry
    (C1-CANONICAL-VALIDATION / A3), registry-FIRST so the Jinja pipe is
    `registry | lme_validate_config(resolved)`. Distinct from resolve-time
    normalization: this REJECTS (never coerces) -- a bool field still holding
    'false', a str holding a non-string, an int holding a bool, an undeclared key in
    the resolved set, a missing required field, or a malformed/reversed registry all
    RAISE. Returns the dict unchanged on success. The registry-shape gate makes the
    reversed-pipe fail closed by construction rather than only by argument order."""
    fields, _precedence, _channels = _require_registry_shape(registry)
    # Reject a non-mapping resolved input INDEPENDENTLY of whether any field is required
    # (C1-OPTIONAL-NONMAPPING): silently coercing [] / None / a scalar to {} let a
    # registry with only optional fields "validate" a bogus input as if it were empty.
    if not isinstance(resolved, dict):
        raise ValueError(
            'lme: resolved config must be a mapping, got %r' % (type(resolved).__name__,))
    undeclared = [k for k in resolved if k not in fields]
    if undeclared:
        raise ValueError('lme: resolved config has undeclared key(s) %r' % (sorted(undeclared),))
    for key, field in fields.items():
        if key not in resolved:
            if field.get('required'):
                raise ValueError('lme: required config field %r missing from resolved set' % (key,))
            continue
        if not _canonical_ok(resolved[key], field):
            raise ValueError(
                'lme: resolved field %r value %r is not canonical for declared type %r '
                '(nullable=%r)' % (key, resolved[key], field.get('type'), bool(field.get('nullable'))))
    return resolved


def lme_config_revision(payload):
    """Content-addressed revision id (sha256 hex) for a resolved config.

    The id is a pure function of the resolution INPUTS (payload = inputs-by-tier,
    the ordered profile chain, observations, resolved values + origins, and any
    source/runner digests the caller folds in). Because it is content-addressed --
    NOT HEAD+timestamp -- it is IDENTICAL across the several loader includes in one
    playbook run (same inputs -> same id), which is what lets the early gate, the
    rendered-membership check and the credential gate all assert one revision
    (codex-0200). A timestamp, if recorded at all, is METADATA and is NOT part of
    the payload. OUTPUT-ONLY: the id is never fed back as a resolution input.

    Value-pure: canonical JSON (sorted keys, no whitespace) then sha256."""
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _strip_resource_ids(status):
    """Return required_material_status with the identity-derived, volatile `resource_ids`
    removed from every node/service entry. resource_ids are content-addressed over the
    STABLE deployment_identity (lme_material_resource_id), so leaving them in the revision
    payload would churn the revision on an identity change -- which the three-identity
    binding forbids (identity keys storage/fence, NOT the config revision). Everything else
    in status (status/evidence/enabled) is config-derived and STAYS, so an
    undeclared->declared_none transition still flips the revision."""
    if not isinstance(status, dict):
        return status
    out = {}
    for node, svcs in status.items():
        if not isinstance(svcs, dict):
            out[node] = svcs
            continue
        out[node] = {}
        for sid, entry in svcs.items():
            if isinstance(entry, dict):
                out[node][sid] = {k: v for k, v in entry.items() if k != 'resource_ids'}
            else:
                out[node][sid] = entry
    return out


def _revision_payload(resolved, registry, profile_identities,
                      services=None, global_manifest=None, host_rendered=None):
    """Assemble the canonical revision payload from the COMPLETE composed desired/effective
    state (codex-0645 C1-COMPLETE-RESOLVED-REVISION). Value-pure: the exclude set is READ from
    the registry (`exclude_from_revision`), never hardcoded. Included: the declared config
    fields (minus excluded), the ordered profile identities, and -- when supplied by the
    post-projection loader call -- the composed lme_services + lme_global + the per-host
    rendered-service roster + the required_material / datastore / membership projections. So a
    service/material/endpoint/override change flips the revision (the config-only resolve.yml
    call omits them and keeps the pre-projection revision for resolve-only callers).

    EXCLUDED from the payload (deliberate): the STABLE deployment_identity (both the resolved
    field, via exclude_from_revision, AND the `deployment_identity` projection key) and the
    identity-derived required_material_status.resource_ids -- an identity change must NOT churn
    the config revision, only the per-run evidence identity."""
    resolved = resolved or {}
    fields = (registry or {}).get('fields') or {}
    excluded = set(k for k, f in fields.items()
                   if isinstance(f, dict) and f.get('exclude_from_revision'))
    # Declared flat config fields present in resolved, minus the excluded identity fields.
    config = {k: resolved[k] for k in fields if k in resolved and k not in excluded}
    payload = {
        'schema_version': (registry or {}).get('schema_version', 1),
        'ordered_profiles': profile_identities,
        'config': config,
    }
    # Projections (present only in the post-projection loader call). deployment_identity is
    # deliberately NOT copied in (identity is excluded); resource_ids are stripped from status.
    if 'required_material' in resolved:
        payload['required_material'] = resolved['required_material']
    if 'required_material_status' in resolved:
        payload['required_material_status'] = _strip_resource_ids(
            resolved['required_material_status'])
    if 'hosts' in resolved:
        payload['hosts'] = resolved['hosts']
    if 'database' in resolved:
        payload['database'] = resolved['database']
    # SEED-06 (codex-232517): the effective remote-harness policy section is part of the execution revision.
    rh_key = ((registry or {}).get('remote_harness_schema') or {}).get('policy_key')
    if rh_key and rh_key in resolved:
        payload[rh_key] = resolved[rh_key]
    # Composed artifacts that actually render (so an -e lme_service_overrides / lme_global_override
    # that changes the rendered units is not invisible to the revision).
    if services is not None:
        payload['services'] = services
    if global_manifest is not None:
        payload['global'] = global_manifest
    if host_rendered is not None:
        payload['host_rendered_services'] = sorted(host_rendered)
    return payload


def lme_bind_revision(resolved, registry, profile_identities,
                     services=None, global_manifest=None, host_rendered=None):
    """The single untamperable revision binder (C1-REVISION-INTERMEDIATE-EXTRAVAR-PIN +
    C1-COMPLETE-RESOLVED-REVISION). Assembles the canonical payload INSIDE this value-pure
    filter (so there is NO named revision-only Ansible `vars:` intermediate an extra-var can
    pin -- the resolve.yml/load_manifests.yml call sites pass broad facts + an INLINE profile
    identity literal, and a read-back assert re-runs this same call to reject any pinned fact)
    and returns the content-addressed sha256. OUTPUT-ONLY."""
    return lme_config_revision(_revision_payload(
        resolved, registry, profile_identities, services, global_manifest, host_rendered))


def lme_known_enable_flags(_ignored=None):
    """The static KNOWN_ENABLE_FLAGS set is_enabled() guards against, as a sorted
    list, so a DECLARATIVE case can assert it equals the registry's enable_flag keys
    (drift enforcement without a hand-authored Python test / a 4th roster). Takes an
    ignored arg so it can be used as a Jinja filter (`'' | lme_known_enable_flags`)."""
    return sorted(KNOWN_ENABLE_FLAGS)


_MATERIAL_SUPPORTED_FIELD_TYPES = ('str', 'bool', 'int')  # record-field declared types


def _require_material_catalog_schema(catalog_schema):
    """Structural gate for the material_catalog SCHEMA. Returns
    (definition_fields, kind_vocab, distributable_kinds)."""
    if not isinstance(catalog_schema, dict):
        raise ValueError('lme: material_catalog_schema must be a mapping')
    definition = catalog_schema.get('definition')
    if not isinstance(definition, dict) or not definition:
        raise ValueError('lme: material_catalog_schema.definition has no fields')
    kind_decl = definition.get('kind')
    if not isinstance(kind_decl, dict) or not isinstance(kind_decl.get('vocab'), list) \
            or not kind_decl['vocab']:
        raise ValueError('lme: material_catalog_schema.definition.kind needs a non-empty vocab')
    distributable = catalog_schema.get('distributable_kinds')
    if not isinstance(distributable, list):
        raise ValueError('lme: material_catalog_schema.distributable_kinds must be a list')
    bad = [k for k in distributable if k not in kind_decl['vocab']]
    if bad:
        raise ValueError('lme: distributable_kinds %r are not in the kind vocab %r'
                         % (sorted(bad), sorted(kind_decl['vocab'])))
    return definition, set(kind_decl['vocab']), set(distributable)


def lme_validate_material_catalog(catalog, catalog_schema, context=None):
    """Validate the shared `lme_global.material_catalog` against
    `lme_global.material_catalog_schema` (C1-MATERIAL-CATALOG-DEFINITION-VALIDATION). A
    null/empty definition, an absent/unknown `kind` or an absent/empty `payload_validity`
    now FAIL -- previously bare catalog membership passed and a private-key definition was
    indistinguishable from a public one. Value-pure: the required fields, kind vocab and
    distributable set are READ from the schema. Returns the catalog on success."""
    where = ' (catalog %r)' % (context,) if context else ''
    definition, kind_vocab, _distributable = _require_material_catalog_schema(catalog_schema)
    if not isinstance(catalog, dict):
        raise ValueError('lme: material_catalog%s must be a mapping' % where)
    for name, defn in catalog.items():
        dwhere = '%s definition %r' % (where, name)
        if not isinstance(defn, dict) or not defn:
            raise ValueError('lme: material_catalog%s is null/empty -- a definition MUST '
                             'declare kind + payload_validity' % dwhere)
        for fname, fdecl in definition.items():
            present = fname in defn
            if not present:
                if fdecl.get('required'):
                    raise ValueError('lme: material_catalog%s missing required field %r'
                                     % (dwhere, fname))
                continue
            val = defn[fname]
            ftype = fdecl.get('type')
            if ftype == 'str' and (not isinstance(val, str) or not val):
                raise ValueError('lme: material_catalog%s field %r must be a non-empty '
                                 'string, got %r' % (dwhere, fname, val))
            # A4: a declared bool/int catalog field must be that exact type, never a list.
            if ftype == 'bool' and not isinstance(val, bool):
                raise ValueError('lme: material_catalog%s field %r must be a boolean, got %r'
                                 % (dwhere, fname, val))
            if ftype == 'int' and (isinstance(val, bool) or not isinstance(val, int)):
                raise ValueError('lme: material_catalog%s field %r must be an integer, got %r'
                                 % (dwhere, fname, val))
            vocab = fdecl.get('vocab')
            if vocab and val not in vocab:
                raise ValueError('lme: material_catalog%s field %r value %r not in vocab %r'
                                 % (dwhere, fname, val, sorted(vocab)))
        undeclared = [k for k in defn if k not in definition]
        if undeclared:
            raise ValueError('lme: material_catalog%s has undeclared field(s) %r'
                             % (dwhere, sorted(undeclared)))
    return catalog


def _require_material_schema(schema):
    """Structural gate for the material_requirements SCHEMA itself
    (C1-MATERIAL-SCHEMA-VALIDATION): an empty record, an unsupported field type, an
    incomplete/ill-typed empty_semantics policy, an absent id/mode pattern or an
    under-declared placement_forms are REJECTED before any obligation is inspected.
    Returns a normalized bundle the obligation loop consumes."""
    if not isinstance(schema, dict):
        raise ValueError('lme: material_requirements_schema must be a mapping')
    record = schema.get('record')
    if not isinstance(record, dict) or not record:
        raise ValueError('lme: material_requirements_schema.record is empty/absent')
    for fname, fdecl in record.items():
        if not isinstance(fdecl, dict):
            raise ValueError('lme: material_requirements_schema.record.%s is not a mapping' % fname)
        if fdecl.get('type') not in _MATERIAL_SUPPORTED_FIELD_TYPES:
            raise ValueError(
                'lme: material_requirements_schema.record.%s declares unsupported/absent '
                'type %r (supported: %r)' % (fname, fdecl.get('type'),
                                             list(_MATERIAL_SUPPORTED_FIELD_TYPES)))
        if 'vocab' in fdecl and (not isinstance(fdecl['vocab'], list) or not fdecl['vocab']):
            raise ValueError('lme: material_requirements_schema.record.%s vocab must be a '
                             'non-empty list' % fname)
    id_pat = schema.get('obligation_id_pattern')
    mode_pat = schema.get('mode_pattern')
    if not isinstance(id_pat, str) or not isinstance(mode_pat, str):
        raise ValueError('lme: material_requirements_schema needs str obligation_id_pattern '
                         '+ mode_pattern')
    placement_decl = record.get('placement_class', {})
    placement_vocab = placement_decl.get('vocab') if isinstance(placement_decl, dict) else None
    if not placement_vocab:
        raise ValueError('lme: material_requirements_schema.record.placement_class needs a vocab')
    forms = schema.get('placement_forms')
    if not isinstance(forms, dict):
        raise ValueError('lme: material_requirements_schema.placement_forms must be a mapping')
    for pc in placement_vocab:
        form = forms.get(pc)
        if not isinstance(form, dict) or not isinstance(form.get('requires'), list) \
                or not isinstance(form.get('forbids'), list):
            raise ValueError('lme: placement_forms.%s must declare requires[] + forbids[]' % pc)
    pcv = schema.get('profile_condition_vocab')
    if not isinstance(pcv, list) or not pcv:
        raise ValueError('lme: material_requirements_schema.profile_condition_vocab must be a '
                         'non-empty list')
    # trust_ref_namespaces: the DECLARED set of namespaces a colon-form trust_ref
    # (`<ns>:<name>`) may use (C1-MATERIAL-REFERENCE-INPUT-AND-EMPTY-POLICY / A3). Read from
    # the schema, not hardcoded (filter-plugin literal ban); an ABSENT/empty list means NO
    # colon namespace is declared, so EVERY colon-form trust_ref is unresolved and REJECTED
    # (previously the `:` form silently bypassed reference closure).
    trust_ns = schema.get('trust_ref_namespaces')
    trust_ns = [] if trust_ns is None else trust_ns
    if not isinstance(trust_ns, list) or any(not isinstance(n, str) or not n for n in trust_ns):
        raise ValueError('lme: material_requirements_schema.trust_ref_namespaces must be a list '
                         'of non-empty namespace strings')
    # empty_semantics: ALL three keys REQUIRED, each boolean true. A non-bool, an omitted
    # key, or a value that DISABLES a required failure is an unsupported policy -> reject
    # (C1-MATERIAL-REFERENCE-INPUT-AND-EMPTY-POLICY -- never silently honored/ignored).
    required_policy = ('declared_none_passes', 'missing_field_fails', 'empty_contradicting_refs_invalid')
    empty_sem = schema.get('empty_semantics')
    if not isinstance(empty_sem, dict):
        raise ValueError('lme: material_requirements_schema.empty_semantics must be a mapping')
    unknown = [k for k in empty_sem if k not in required_policy]
    if unknown:
        raise ValueError('lme: empty_semantics has unsupported key(s) %r' % sorted(unknown))
    for k in required_policy:
        if k not in empty_sem:
            raise ValueError('lme: empty_semantics is missing required policy %r' % k)
        if empty_sem[k] is not True:
            raise ValueError('lme: empty_semantics.%s=%r is an unsupported policy -- it would '
                             'DISABLE a required failure; only `true` is supported'
                             % (k, empty_sem[k]))
    return {
        'record': record,
        'id_re': re.compile(id_pat),
        'mode_re': re.compile(mode_pat),
        'placement_vocab': set(placement_vocab),
        'forms': forms,
        'profile_condition_vocab': set(pcv),
        'trust_ref_namespaces': set(trust_ns),
        'vocabs': {k: set(f['vocab']) for k, f in record.items() if f.get('vocab')},
        'base_required': [k for k, f in record.items() if f.get('required')],
        'form_fields': set(('destination', 'owner_role', 'mode')),
    }


def lme_validate_material_requirements(catalog, obligations, schema, catalog_schema,
                                       referenced_ids=None, context=None,
                                       producer_registry=None, custody_registry=None):
    """Validate ONE service's declared `material_requirements` against the shared
    `lme_global.material_catalog`, the record schema
    (`lme_config_registry.material_requirements_schema`) and the catalog schema. Value-pure:
    every field name, required flag, vocabulary, placement-form rule and pattern is READ
    from the schemas, never hardcoded here (the filter-plugin literal ban). This is the
    SCHEMA_REQUIRED_MATERIAL enforcer (codex-0430 decision 1+2). It validates the
    DECLARATION shape + reference resolution; the deploy-time "obligation produced but
    malformed" checks are the consumer's (C materializer / D completeness).

    `obligations` (the service's material_requirements value):
      * None  -> the field is ABSENT. A SELECTED service omitting it is INCOMPLETE and
                 RAISES (missing != implicitly-empty; codex-0430 decision 2). The
                 projection emitter does NOT call this for an undeclared service (it marks
                 status:undeclared instead) until missing_field is armed swarm-wide.
      * {}    -> explicit declared-none. PASSES iff nothing references an obligation.
      * map   -> each obligation id -> a typed record validated against schema.record.

    `catalog_schema` supplies the kind vocab + distributable set: an obligation's
    material_ref MUST resolve to a definition of a DISTRIBUTABLE kind, so a catalog NAME
    alone cannot authorize private-material distribution
    (C1-MATERIAL-CATALOG-DEFINITION-VALIDATION).

    `referenced_ids` is the list/set/tuple of obligation ids OTHER declarations point at;
    every one MUST resolve to a declared obligation. An UNRESOLVED reference is a
    PRE-GENERATION CONFIG error (a missing/invalid declaration), NOT proof the payload was
    not produced (codex-0515 stage_and_evidence_corrections). Returns the validated
    obligations map on success."""
    where = ' for service %r' % (context,) if context else ''
    S = _require_material_schema(schema)
    _def, _kind_vocab, distributable = _require_material_catalog_schema(catalog_schema)
    catalog = catalog or {}
    empty_sem = schema['empty_semantics']

    # referenced_ids input type: only None / list / tuple / set of ids -- a bare string
    # (-> set of chars) or a mapping (-> set of keys) is malformed
    # (C1-MATERIAL-REFERENCE-INPUT-AND-EMPTY-POLICY).
    if referenced_ids is None:
        refs = set()
    elif isinstance(referenced_ids, (list, tuple, set)):
        bad = [r for r in referenced_ids if not isinstance(r, str) or not r]
        if bad:
            raise ValueError('lme: referenced_ids%s contains non-string/empty id(s) %r'
                             % (where, bad))
        refs = set(referenced_ids)
    else:
        raise ValueError('lme: referenced_ids%s must be a list/tuple/set of ids, got %r'
                         % (where, type(referenced_ids).__name__))

    # --- the three empty-list cases (codex-0430 decision 2) ---------------------
    if obligations is None:
        if empty_sem['missing_field_fails']:
            raise ValueError(
                'lme: material_requirements is MISSING%s -- a selected service must '
                'declare the field (explicit {} for declared-none); omission is '
                'INCOMPLETE, never implicitly empty' % where)
        return {}
    if not isinstance(obligations, dict):
        raise ValueError('lme: material_requirements%s must be a mapping, got %r'
                         % (where, type(obligations).__name__))
    if not obligations:
        if refs and empty_sem['empty_contradicting_refs_invalid']:
            raise ValueError(
                'lme: material_requirements%s is declared-none ({}) but obligation '
                'reference(s) %r point at it -- an empty declaration contradicting '
                'cred/trust/mount refs is INVALID' % (where, sorted(refs)))
        return {}

    # --- typed record validation ----------------------------------------------
    for oid, rec in obligations.items():
        rwhere = '%s obligation %r' % (where, oid)
        # obligation id (map key): stable service-local name, never an int/empty.
        if not isinstance(oid, str) or not S['id_re'].match(oid):
            raise ValueError('lme: material_requirements%s id must match %r (a stable '
                             'service-local name, never an integer/empty)'
                             % (rwhere, schema['obligation_id_pattern']))
        if not isinstance(rec, dict):
            raise ValueError('lme: material_requirements%s is not a mapping' % rwhere)
        undeclared = [k for k in rec if k not in S['record']]
        if undeclared:
            raise ValueError('lme: material_requirements%s has undeclared field(s) %r'
                             % (rwhere, sorted(undeclared)))
        # base-required fields present + (for str) nonempty.
        for fname in S['base_required']:
            if fname not in rec:
                raise ValueError('lme: material_requirements%s missing required field %r'
                                 % (rwhere, fname))
        # typed + vocab + nonempty per declared field (C1-MATERIAL-* A3/A4).
        for fname, fdecl in S['record'].items():
            if fname not in rec:
                continue
            val = rec[fname]
            ftype = fdecl.get('type')
            if ftype == 'str':
                if not isinstance(val, str):
                    raise ValueError('lme: material_requirements%s field %r must be a '
                                     'string, got %r' % (rwhere, fname, val))
                # A3: a PRESENT str field must be non-empty -- required OR optional. An empty
                # optional producer_ref/custody_ref/consumer/trust_ref is not a value; omit the
                # field instead of declaring it empty (an empty ref silently resolved to nothing).
                if not val:
                    raise ValueError('lme: material_requirements%s field %r is present but '
                                     'empty -- omit an optional field rather than declaring it '
                                     'empty (an empty reference resolves to nothing)'
                                     % (rwhere, fname))
            elif ftype == 'bool':
                # A4: a declared bool field must be a real bool, never a list/int/str.
                if not isinstance(val, bool):
                    raise ValueError('lme: material_requirements%s field %r must be a boolean, '
                                     'got %r' % (rwhere, fname, val))
            elif ftype == 'int':
                # A4: a declared int field must be an int and NOT a bool (bool is an int subclass)
                # and NOT a list.
                if isinstance(val, bool) or not isinstance(val, int):
                    raise ValueError('lme: material_requirements%s field %r must be an integer, '
                                     'got %r' % (rwhere, fname, val))
            if fname in S['vocabs'] and val not in S['vocabs'][fname]:
                raise ValueError('lme: material_requirements%s field %r value %r not in '
                                 'declared vocab %r' % (rwhere, fname, val,
                                                        sorted(S['vocabs'][fname])))
        # placement-FORM conditional requires/forbids (C1-MATERIAL-CANONICAL-REFERENCE-SHAPE).
        pc = rec['placement_class']
        form = S['forms'][pc]
        for fname in form['requires']:
            if fname not in rec or not (isinstance(rec[fname], str) and rec[fname]):
                raise ValueError('lme: material_requirements%s placement_class %r requires '
                                 'a non-empty %r' % (rwhere, pc, fname))
        for fname in form['forbids']:
            if fname in rec:
                raise ValueError('lme: material_requirements%s placement_class %r must NOT '
                                 'declare %r (env-backed forms fabricate no file path/mode)'
                                 % (rwhere, pc, fname))
        # profile_condition semantic closure.
        if rec['profile_condition'] not in S['profile_condition_vocab']:
            raise ValueError('lme: material_requirements%s profile_condition %r not in the '
                             'declared vocab %r' % (rwhere, rec['profile_condition'],
                                                    sorted(S['profile_condition_vocab'])))
        # mode (when a file-backed form declared it): complete anchored octal.
        mode = rec.get('mode')
        if isinstance(mode, str) and not S['mode_re'].match(mode):
            raise ValueError('lme: material_requirements%s mode %r is not a complete octal '
                             'string (e.g. "0600"); trailing/leading junk rejected'
                             % (rwhere, mode))
        # material_ref -> a catalog definition of a DISTRIBUTABLE kind. A catalog NAME
        # alone (or a private_key kind) cannot authorize distribution.
        mref = rec['material_ref']
        if mref not in catalog:
            raise ValueError('lme: material_requirements%s material_ref %r resolves to no '
                             'lme_global.material_catalog definition' % (rwhere, mref))
        kind = (catalog[mref] or {}).get('kind')
        if kind not in distributable:
            raise ValueError('lme: material_requirements%s material_ref %r has kind %r which '
                             'is NOT distributable %r -- a catalog reference cannot authorize '
                             'distributing private material' % (rwhere, mref, kind,
                                                                sorted(distributable)))
        # trust_ref closure (A3). A BARE name must resolve to a catalog definition or a sibling
        # obligation. A COLON-FORM `<ns>:<name>` must use a namespace DECLARED in the schema's
        # trust_ref_namespaces -- an undeclared namespace (the default, since none are declared
        # yet) is UNRESOLVED and REJECTED (previously the `:` form silently bypassed closure).
        # The producer/custody registries C/D still owe will declare their namespaces here.
        tref = rec.get('trust_ref')
        if isinstance(tref, str) and tref:
            if ':' in tref:
                ns = tref.split(':', 1)[0]
                if ns not in S['trust_ref_namespaces']:
                    raise ValueError(
                        'lme: material_requirements%s trust_ref %r uses namespace %r which is '
                        'not in the declared trust_ref_namespaces %r -- a colon-form reference '
                        'to an undeclared namespace is unresolved'
                        % (rwhere, tref, ns, sorted(S['trust_ref_namespaces'])))
            elif tref not in catalog and tref not in obligations:
                raise ValueError('lme: material_requirements%s trust_ref %r resolves to no '
                                 'catalog definition or sibling obligation' % (rwhere, tref))
        # producer_ref / custody_ref closure (fix_3). SHAPE is validated above (present ->
        # non-empty str). CLOSURE arms when the registries are SUPPLIED: the live loader path
        # passes lme_global.{producer_registry,custody_registry}, so a present producer_ref
        # MUST resolve to a producer_registry entry and a present custody_ref to a
        # custody_registry entry. When a registry is NOT supplied the field stays shape-only
        # -- the schema's DECLARED pre-arm contract ("producer_ref/custody_ref resolve against
        # canonical producer/custody declarations ... reference closure arms when those
        # declarations land"). No service declares material_requirements today (0/29), so this
        # changes nothing on the current live path; it arms the reference for the names this
        # fold introduces (certs_role / certs_workspace / certs_bundle_publish).
        pref = rec.get('producer_ref')
        if isinstance(pref, str) and pref and producer_registry is not None:
            if pref not in producer_registry:
                raise ValueError('lme: material_requirements%s producer_ref %r resolves to no '
                                 'producer_registry entry' % (rwhere, pref))
            # MEMBERSHIP (codex-1625 additional_partial_validation): existence of the producer
            # is not enough -- the named producer MUST actually produce the material this
            # obligation requires, exactly like the leaf-key producer-membership check. A
            # producer_ref pointing at a real producer that does NOT list material_ref is a
            # broken production relationship, not a valid reference.
            _pref_produces = (producer_registry[pref] or {}).get('produces_materials') or []
            if mref not in _pref_produces:
                raise ValueError('lme: material_requirements%s producer_ref %r does not produce '
                                 'material_ref %r (produces %r) -- producer existence is not a '
                                 'production relationship' % (rwhere, pref, mref,
                                                              sorted(_pref_produces)))
        cref = rec.get('custody_ref')
        if isinstance(cref, str) and cref and custody_registry is not None:
            if cref not in custody_registry:
                raise ValueError('lme: material_requirements%s custody_ref %r resolves to no '
                                 'custody_registry entry' % (rwhere, cref))
            # C-CORR-ES-CUSTODY-CHANNEL: the consuming service MUST be a declared consumer of
            # the custody channel it references (elasticsearch -> certs_workspace; kibana /
            # fleet-server -> certs_bundle_publish). context is the service id. This stops an
            # obligation being GREEN on the WRONG channel (e.g. ES on the published bundle).
            consumers = (custody_registry[cref] or {}).get('consumers') or []
            if context is not None and context not in consumers:
                raise ValueError('lme: material_requirements%s custody_ref %r does not list '
                                 'consumer %r (declared consumers %r) -- wrong custody channel'
                                 % (rwhere, cref, context, sorted(consumers)))

    # --- reference resolution: every referenced obligation id must resolve ------
    unresolved = sorted(r for r in refs if r not in obligations)
    if unresolved:
        raise ValueError(
            'lme: material_requirement_ref(s) %r%s resolve to no declared obligation -- an '
            'UNRESOLVED reference is a pre-generation configuration error (fail before '
            'mutation), distinct from a valid declared production yielding an absent payload'
            % (unresolved, where))
    return obligations


def lme_type_aware_equal(a, b, context=None):
    """Value-pure structural TYPE-AWARE equality (fix_3, C1-REGISTRY-TYPE-EQUALITY-BYPASS /
    C1-TYPED-EQUALITY-MAPPING-KEYS codex-1625). Ordinary Jinja/Python == conflates 1 with True
    and 0 with False (bool is an int subclass, and a Python dict collapses {True: x}/{1: x} and
    {1: x}/{1.0: x} at the KEY level too), so a plain == would treat type substitutions as equal.
    This DELEGATES to the single existing type-aware comparator `_leaf_equal`, which requires the
    same canonical kind (bool distinguished from int, int from float) at EVERY leaf AND pairs
    mapping keys TYPE-AWARELY ({True: x} != {1: x}, {1: x} != {1.0: x}). The earlier fix_3 v5
    copy used set(keys)/b[k] and so reopened the key-level conflation this function exists to
    close; it is removed in favour of the one engine (no second partially type-aware helper).
    Used by the loader for scalar deployment_identity agreement; returns True only on exact
    structural + type identity."""
    return _leaf_equal(a, b)


def _require_material_provision_schema(provision_schema):
    """Structural gate for lme_global.material_provision_schema (fix_3). Returns the five
    record sub-schemas + the compiled mode regex. Value-pure -- every required list / vocab
    / pattern is READ from the schema, never hardcoded."""
    if not isinstance(provision_schema, dict):
        raise ValueError('lme: material_provision_schema must be a mapping')
    parts = {}
    for key in ('producer_record', 'custody_record', 'leaf_key_provision_record',
                'custody_hop_record', 'ca_key_rule_record'):
        part = provision_schema.get(key)
        if not isinstance(part, dict) or not isinstance(part.get('required'), list) \
                or not part['required']:
            raise ValueError('lme: material_provision_schema.%s needs a non-empty '
                             'required list' % key)
        parts[key] = part
    mode_pat = provision_schema.get('mode_pattern')
    if not isinstance(mode_pat, str) or not mode_pat:
        raise ValueError('lme: material_provision_schema.mode_pattern must be a non-empty '
                         'string')
    parts['mode_re'] = re.compile(mode_pat)
    # leaf_mode_forbidden_mask (C1-COMPOSED-MATERIAL-DECLARATIONS-REJECTED codex-1625): the
    # octal permission bits a delivered private-key leaf mode may NEVER grant, DECLARED as data
    # (an octal string in the schema, never a bitmask literal in Python). This is the ABSOLUTE
    # restrictiveness ceiling that replaces the removed whole-registry equality gate for the one
    # security field that is a free-form string (mode) rather than an is-True/is-False bool: an
    # override may legitimately recompose placement/owner/consumer, but it can never widen a
    # private key past this mask (e.g. grant world read or group write).
    mask = provision_schema.get('leaf_mode_forbidden_mask')
    if not isinstance(mask, str) or not mode_pat or not parts['mode_re'].match(mask):
        raise ValueError('lme: material_provision_schema.leaf_mode_forbidden_mask must be a '
                         'complete octal string (e.g. "0027") matching mode_pattern')
    parts['mode_forbidden_bits'] = int(mask, 8)
    parts['mode_forbidden_mask'] = mask
    # custody_mode_key_kinds (fix_3 v6.2, codex-1812 C1-CUSTODY-MODE-KIND-CLOSURE): the DECLARED
    # classification of every custody channel mode KEY to a material_catalog KIND. This is policy
    # (it lives in the schema, which the loader admits only from the declared source), not
    # composed data: the private-material ceiling for a custody mode is chosen by this declared
    # class, never by whether the mode key happens to also name a catalog id. Its values are
    # checked against the catalog kind vocab by the caller (which holds the catalog schema).
    mkk = provision_schema.get('custody_mode_key_kinds')
    if not isinstance(mkk, dict) or not mkk:
        raise ValueError('lme: material_provision_schema.custody_mode_key_kinds must be a '
                         'non-empty mapping of custody mode key -> material kind')
    for mk, mkind in mkk.items():
        if not isinstance(mk, str) or not mk or not isinstance(mkind, str) or not mkind:
            raise ValueError('lme: material_provision_schema.custody_mode_key_kinds entry '
                             '%r: %r must map a non-empty string key to a non-empty kind string'
                             % (mk, mkind))
    parts['mode_key_kinds'] = mkk
    return parts


def _prov_required(entry, required, where):
    """Every required field present and not None; a declared list/mapping field non-empty."""
    if not isinstance(entry, dict) or not entry:
        raise ValueError('lme: %s must be a non-empty mapping' % where)
    for f in required:
        if f not in entry or entry[f] is None:
            raise ValueError('lme: %s missing required field %r' % (where, f))
        if isinstance(entry[f], (list, dict)) and not entry[f]:
            raise ValueError('lme: %s field %r is empty' % (where, f))


def _prov_vocab(part, vocab_key, value, where):
    """Membership against a schema-declared vocab. The vocab itself MUST be declared
    (value-purity): an absent vocab is a schema error, not a silent pass."""
    vocab = part.get(vocab_key)
    if not isinstance(vocab, list) or not vocab:
        raise ValueError('lme: material_provision_schema %r vocab is absent/empty' % vocab_key)
    if value not in vocab:
        raise ValueError('lme: %s value %r not in %s %r'
                         % (where, value, vocab_key, sorted(vocab)))


def lme_validate_material_registries(catalog, catalog_schema, producer_registry,
                                     custody_registry, material_provision,
                                     provision_schema, context=None):
    """Validate the fix_3 producer/custody registries + the private-key material provision
    (lme_global.{producer_registry,custody_registry,material_provision}) against
    lme_global.material_provision_schema, with reference closure onto the shared
    material_catalog. THIS is the machine validation that makes private-key production /
    custody / placement CONSUMED in the single engine (codex C_TLS.follow_up: a descriptive
    registry with no enforcement is NOT provision); it is invoked on the loader path
    (load_manifests.yml A2 block), fail-closed pre-mutation. Value-pure: no host, uid or
    secret byte is read; every required list, vocab and pattern is READ from the schema.
    Returns material_provision on success.

    Enforced:
      * producer_registry: each entry carries producer_record.required; id matches id_pattern;
        host_scope + reference_form in vocab; every produces_materials id resolves to a catalog
        def.
      * custody_registry: each entry carries custody_record.required; desired_host_scope in the
        desired vocab (which OMITS every_host, so an all-host desired custody scope is rejected
        for the channel); observed_host_scope + reference_form in vocab; drift is a boolean AND
        drift == (observed != desired); consumers a non-empty list; every modes value a complete
        octal; every modes KEY classified by the declared custody_mode_key_kinds (unknown /
        aliased keys rejected; a key naming a catalog id must carry that material's kind) and
        ceilinged by leaf_mode_forbidden_mask when its declared class is non-distributable;
        non_publication ids resolve to catalog defs.
      * leaf-to-channel kind closure: every channel a leaf key is delivered through must declare
        a custody mode classified as that material's kind.
      * leaf_key_provision: each entry carries leaf_key_provision_record.required; material
        resolves to a catalog def of a NON-distributable (private_key) kind -- a leaf key can
        never be a distributable obligation; producer -> producer_registry; every channel ->
        custody_registry; delivery_mode + lifecycle in vocab; mode a complete octal;
        host_scope in the leaf vocab, which DELIBERATELY omits every_host so an all-host
        DESIRED custody scope for a private key is REJECTED (today's all-host replication is
        observed behavior, never the target).
      * ca_key_rule: carries ca_key_rule_record.required; material -> a private_key catalog
        def; non_publication true; distributable false; carve_out carries carve_out_required;
        conformance in vocab. It is a SEPARATE rule and MUST NOT appear in leaf_key_provision.
    """
    where = ' (%s)' % context if context else ''
    P = _require_material_provision_schema(provision_schema)
    _def, _kv, distributable = _require_material_catalog_schema(catalog_schema)
    # Every declared custody mode-key class must be a real catalog KIND (closure of the policy
    # map itself: a typo'd class can neither silently exempt nor silently ceiling a key).
    _bad_classes = sorted(set(P['mode_key_kinds'].values()) - set(_kv))
    if _bad_classes:
        raise ValueError('lme: material_provision_schema.custody_mode_key_kinds classes %r are '
                         'not in the material_catalog kind vocab %r'
                         % (_bad_classes, sorted(_kv)))
    catalog = catalog or {}
    if not isinstance(producer_registry, dict) or not producer_registry:
        raise ValueError('lme: producer_registry%s must be a non-empty mapping' % where)
    if not isinstance(custody_registry, dict) or not custody_registry:
        raise ValueError('lme: custody_registry%s must be a non-empty mapping' % where)
    if not isinstance(material_provision, dict) or not material_provision:
        raise ValueError('lme: material_provision%s must be a non-empty mapping' % where)

    # --- producer_registry ------------------------------------------------------
    prod_rec = P['producer_record']
    for pid, entry in producer_registry.items():
        pwhere = 'producer_registry.%s' % pid
        _prov_required(entry, prod_rec['required'], pwhere)
        idpat = prod_rec.get('id_pattern')
        if isinstance(idpat, str) and idpat and not re.match(idpat, str(pid)):
            raise ValueError('lme: %s id %r does not match id_pattern %r'
                             % (pwhere, pid, idpat))
        # map-key / record-id coherence: the mapping KEY is the record identity, so a record
        # whose own id field names a DIFFERENT producer is incoherent -- reference existence
        # alone is insufficient (codex still_required map-key/record-id coherence).
        if entry.get('id') != pid:
            raise ValueError('lme: %s.id %r does not equal its registry key %r -- the map key '
                             'IS the record identity' % (pwhere, entry.get('id'), pid))
        _prov_vocab(prod_rec, 'host_scope_vocab', entry['host_scope'], pwhere)
        _prov_vocab(prod_rec, 'reference_form_vocab', entry['reference_form'], pwhere)
        mats = entry['produces_materials']
        if not isinstance(mats, list):
            raise ValueError('lme: %s.produces_materials must be a list' % pwhere)
        for mid in mats:
            if mid not in catalog:
                raise ValueError('lme: %s produces_materials %r resolves to no '
                                 'material_catalog definition' % (pwhere, mid))

    # --- custody_registry -------------------------------------------------------
    # non_publication_materials: the material ids declared NEVER-published across every custody
    # channel (union) PLUS the ca_key_rule material (added after ca_key_rule is validated). A
    # leaf provision -- a publish-to-channel contract -- may NEVER reference a member of this
    # set, checked by REFERENCED MATERIAL IDENTITY (not the leaf map KEY), which closes the
    # renamed/aliased-leaf bypass (C1-CA-ALIAS-PROVISION-BYPASS).
    non_publication_materials = set()
    # channel id -> the set of DECLARED mode-key classes its modes cover (v6.2 kind closure);
    # the leaf loop requires every delivery channel to classify the delivered material's kind.
    channel_mode_kinds = {}
    cust_rec = P['custody_record']
    for cid, entry in custody_registry.items():
        cwhere = 'custody_registry.%s' % cid
        _prov_required(entry, cust_rec['required'], cwhere)
        if entry.get('id') != cid:
            raise ValueError('lme: %s.id %r does not equal its registry key %r -- the map key '
                             'IS the record identity' % (cwhere, entry.get('id'), cid))
        # desired_host_scope vocab OMITS every_host -> an all-host DESIRED custody scope is
        # rejected for the channel itself (not only the leaf provision); today's all-host
        # replication is recorded as observed_host_scope + drift, never blessed as desired.
        _prov_vocab(cust_rec, 'desired_host_scope_vocab', entry['desired_host_scope'], cwhere)
        _prov_vocab(cust_rec, 'observed_host_scope_vocab', entry['observed_host_scope'], cwhere)
        _prov_vocab(cust_rec, 'reference_form_vocab', entry['reference_form'], cwhere)
        if not isinstance(entry['consumers'], list) or not entry['consumers']:
            raise ValueError('lme: %s.consumers must be a non-empty list' % cwhere)
        if not isinstance(entry['drift'], bool):
            raise ValueError('lme: %s.drift must be a boolean' % cwhere)
        # drift MUST equal (observed != desired): a mislabelled channel (drift:false while
        # observed diverges) cannot silently bless the divergence.
        if entry['drift'] != (entry['observed_host_scope'] != entry['desired_host_scope']):
            raise ValueError('lme: %s.drift %r disagrees with observed_host_scope %r != '
                             'desired_host_scope %r' % (cwhere, entry['drift'],
                             entry['observed_host_scope'], entry['desired_host_scope']))
        if not isinstance(entry['modes'], dict) or not entry['modes']:
            raise ValueError('lme: %s.modes must be a non-empty mapping' % cwhere)
        for mk, mv in entry['modes'].items():
            if not isinstance(mv, str) or not P['mode_re'].match(mv):
                raise ValueError('lme: %s.modes[%r] %r is not a complete octal string'
                                 % (cwhere, mk, mv))
            # MODE-KEY KIND CLOSURE (fix_3 v6.2, codex-1812 C1-CUSTODY-MODE-KIND-CLOSURE). v6.1
            # ceilinged a custody mode ONLY when its key was also a catalog id, so the real
            # private-key channel key (a generic class key, not a catalog id) escaped the ceiling
            # and could be widened to a world-readable mode. Now EVERY mode key must be classified
            # by the DECLARED schema map custody_mode_key_kinds (policy, declared-source only):
            #   * an unclassified / unknown / aliased key is REJECTED (no silent exemption);
            #   * a key that is ALSO a catalog id must carry that material's own catalog kind as
            #     its declared class (an alias cannot relabel a private key as a certificate);
            #   * the ceiling is chosen by the DECLARED class: a non-distributable class is under
            #     leaf_mode_forbidden_mask, a distributable class is not.
            # No mode key or material identity is named in Python -- all of it is read from YAML.
            mclass = P['mode_key_kinds'].get(mk)
            if mclass is None:
                raise ValueError('lme: %s.modes[%r] is not classified by '
                                 'material_provision_schema.custody_mode_key_kinds %r -- an '
                                 'unknown or aliased custody mode key cannot escape the '
                                 'private-material ceiling'
                                 % (cwhere, mk, sorted(P['mode_key_kinds'])))
            if mk in catalog and (catalog[mk] or {}).get('kind') != mclass:
                raise ValueError('lme: %s.modes[%r] is declared class %r but material_catalog '
                                 '%r has kind %r -- a custody mode key naming a catalog material '
                                 'must carry that material\'s own kind'
                                 % (cwhere, mk, mclass, mk, (catalog[mk] or {}).get('kind')))
            if mclass not in distributable and int(mv, 8) & P['mode_forbidden_bits']:
                raise ValueError('lme: %s.modes[%r] %r grants bits forbidden for the '
                                 'non-distributable class %r by '
                                 'material_provision_schema.leaf_mode_forbidden_mask %r'
                                 % (cwhere, mk, mv, mclass, P['mode_forbidden_mask']))
            channel_mode_kinds.setdefault(cid, set()).add(mclass)
        for npid in (entry.get('non_publication') or []):
            if npid not in catalog:
                raise ValueError('lme: %s.non_publication %r resolves to no material_catalog '
                                 'definition' % (cwhere, npid))
            non_publication_materials.add(npid)

    # --- material_provision.ca_key_rule (validated BEFORE the leaf loop so its material joins
    #     non_publication_materials; the renamed-leaf case is then caught by identity in the
    #     leaf loop, and the explicit KEY-form control is retained after it) ---------
    ca_rec = P['ca_key_rule_record']
    ca = material_provision.get('ca_key_rule')
    _prov_required(ca, ca_rec['required'], 'ca_key_rule')
    ca_mid = ca['material']
    if ca_mid not in catalog:
        raise ValueError('lme: ca_key_rule material %r resolves to no material_catalog '
                         'definition' % ca_mid)
    if (catalog[ca_mid] or {}).get('kind') in distributable:
        raise ValueError('lme: ca_key_rule material %r must be a NON-distributable private '
                         'key' % ca_mid)
    if ca['non_publication'] is not True:
        raise ValueError('lme: ca_key_rule.non_publication must be true')
    if ca['distributable'] is not False:
        raise ValueError('lme: ca_key_rule.distributable must be false')
    carve = ca['carve_out']
    if not isinstance(carve, dict):
        raise ValueError('lme: ca_key_rule.carve_out must be a mapping')
    for f in (ca_rec.get('carve_out_required') or []):
        if f not in carve or carve[f] is None:
            raise ValueError('lme: ca_key_rule.carve_out missing required field %r' % f)
    # The CA private key carve-out mode is under the SAME restrictiveness ceiling as a leaf key
    # (codex-1625 + v6.1 self-found bypass): an override can never widen the CA key past
    # leaf_mode_forbidden_mask. A NON-string or non-octal carve mode (e.g. an unquoted 0666 that
    # YAML loads as the int 438, or "0644 " with trailing space) previously SKIPPED the ceiling
    # silently -- it now RAISES, exactly like the leaf mode check.
    _carve_mode = carve.get('mode')
    if not isinstance(_carve_mode, str) or not P['mode_re'].match(_carve_mode):
        raise ValueError('lme: ca_key_rule.carve_out.mode %r is not a complete octal string -- a '
                         'non-string or trailing-junk carve mode cannot skip the restrictiveness '
                         'ceiling' % (_carve_mode,))
    if int(_carve_mode, 8) & P['mode_forbidden_bits']:
        raise ValueError('lme: ca_key_rule.carve_out.mode %r grants bits forbidden by '
                         'material_provision_schema.leaf_mode_forbidden_mask %r -- the CA '
                         'private key mode cannot be widened by an override'
                         % (_carve_mode, P['mode_forbidden_mask']))
    # carve_out.owner: the CA private key MUST stay userns-root (the 0:0 CA-MITM ownership fix).
    # The required owner is DECLARED in the ca_key_rule_record schema, which the loader sources
    # from _lme_global_file.lme_global (byte-bound to the on-disk manifest by resolve.yml:72-73),
    # so an override cannot reach it to both change the owner and relax the schema (codex-1710
    # C1-COMPOSED-SCHEMA-WEAKENS-ITS-OWN-SECURITY-POLICY). Nothing validated owner before.
    _req_owner = ca_rec.get('carve_out_owner')
    if _req_owner is not None and carve.get('owner') != _req_owner:
        raise ValueError('lme: ca_key_rule.carve_out.owner %r must be the declared CA-key owner %r '
                         '(userns-root; an override cannot re-own the CA private key)'
                         % (carve.get('owner'), _req_owner))
    _prov_vocab(ca_rec, 'observed_host_scope_vocab', ca['observed_host_scope'], 'ca_key_rule')
    _prov_vocab(ca_rec, 'conformance_vocab', ca['conformance'], 'ca_key_rule')
    non_publication_materials.add(ca_mid)

    # --- material_provision.leaf_key_provision ----------------------------------
    leaf_rec = P['leaf_key_provision_record']
    hop_rec = P['custody_hop_record']
    leaves = material_provision.get('leaf_key_provision')
    if not isinstance(leaves, dict) or not leaves:
        raise ValueError('lme: material_provision.leaf_key_provision%s must be a non-empty '
                         'mapping' % where)
    leaf_material_owner = {}   # material id -> the ONE leaf key that delivers it
    for lid, entry in leaves.items():
        lwhere = 'leaf_key_provision.%s' % lid
        _prov_required(entry, leaf_rec['required'], lwhere)
        # material -> a catalog def of a NON-distributable (private_key) kind.
        mid = entry['material']
        if mid not in catalog:
            raise ValueError('lme: %s material %r resolves to no material_catalog '
                             'definition' % (lwhere, mid))
        kind = (catalog[mid] or {}).get('kind')
        if kind in distributable:
            raise ValueError('lme: %s material %r has kind %r which IS distributable -- a '
                             'leaf-key PROVISION must reference a NON-distributable private '
                             'key, never a distributable material' % (lwhere, mid, kind))
        # NON-PUBLICATION BY REFERENCED MATERIAL IDENTITY (C1-CA-ALIAS-PROVISION-BYPASS). A
        # material declared non-publication (the ca_key_rule material or any custody
        # non_publication id) may NEVER be delivered as a leaf key -- checked on
        # entry['material'], NOT the leaf map KEY, so a renamed/aliased leaf entry
        # ({sneaky_alias: {material: ca_key, ...}}) is rejected exactly like a leaf keyed
        # ca_key. This is the identity enforcement the prior KEY-only check missed.
        if mid in non_publication_materials:
            raise ValueError('lme: %s material %r is declared NON-PUBLICATION (ca_key_rule / '
                             'custody non_publication) and must NEVER be delivered as a leaf '
                             'key -- a renamed leaf entry cannot bypass non-publication by '
                             'referenced material identity' % (lwhere, mid))
        # a private key is delivered by AT MOST ONE leaf (no double-custody of one key).
        if mid in leaf_material_owner:
            raise ValueError('lme: %s material %r is already delivered by leaf %r -- a private '
                             'key is delivered by at most one leaf_key_provision entry'
                             % (lwhere, mid, leaf_material_owner[mid]))
        leaf_material_owner[mid] = lid
        # producer -> producer_registry AND producer MEMBERSHIP: the declared producer must
        # actually PRODUCE this material (reference existence alone is insufficient; codex
        # still_required producer material membership).
        producer = entry['producer']
        if producer not in producer_registry:
            raise ValueError('lme: %s producer %r resolves to no producer_registry entry'
                             % (lwhere, producer))
        prod_mats = producer_registry[producer].get('produces_materials') or []
        if mid not in prod_mats:
            raise ValueError('lme: %s material %r is not in producer %r produces_materials %r '
                             '-- the declared producer must actually produce the material it '
                             'delivers' % (lwhere, mid, producer, sorted(prod_mats)))
        # channels: every channel resolves to a custody_registry entry (closure).
        if not isinstance(entry['channels'], list) or not entry['channels']:
            raise ValueError('lme: %s.channels must be a non-empty list' % lwhere)
        for ch in entry['channels']:
            if ch not in custody_registry:
                raise ValueError('lme: %s channel %r resolves to no custody_registry entry'
                                 % (lwhere, ch))
            # KIND-TO-CHANNEL-MODE RELATIONSHIP (v6.2): a channel that carries this private key
            # must declare a mode for the key's kind (via a classified mode key), so the
            # private-material ceiling above actually governs the mode the key lands with on
            # that channel -- a channel with no classified mode for the kind cannot carry it.
            if kind not in channel_mode_kinds.get(ch, set()):
                raise ValueError('lme: %s channel %r declares no custody mode classified as the '
                                 'delivered material kind %r (classes %r) -- the channel mode '
                                 'for this private material is unclassified'
                                 % (lwhere, ch, kind, sorted(channel_mode_kinds.get(ch, set()))))
        # TYPED ORDERED custody hops + residual locations (codex still_required: a channels
        # list + a transits_controller boolean is NOT a typed custody-hop model). Each hop is
        # an ordered {channel, order, residual_copy, host_scope, transits_controller} record;
        # the ordered hop channel sequence MUST equal the channels closure list, order is a
        # dense 1..N, residual_copy/transits_controller are real booleans, host_scope is in
        # the declared vocab. This carries WHERE each residual copy lands (host_scope) and
        # WHETHER it persists (residual_copy), per hop -- not a single opaque boolean.
        hops = entry['custody_hops']
        if not isinstance(hops, list) or not hops:
            raise ValueError('lme: %s.custody_hops must be a non-empty ordered list' % lwhere)
        hop_channels = []
        for i, hop in enumerate(hops):
            hwhere = '%s.custody_hops[%d]' % (lwhere, i)
            _prov_required(hop, hop_rec['required'], hwhere)
            if hop['channel'] not in custody_registry:
                raise ValueError('lme: %s channel %r resolves to no custody_registry entry'
                                 % (hwhere, hop['channel']))
            if (not isinstance(hop['order'], int) or isinstance(hop['order'], bool)
                    or hop['order'] != i + 1):
                raise ValueError('lme: %s.order %r must be the dense 1-based INTEGER hop '
                                 'position %d (a bool or a float such as 1.0 is rejected: '
                                 'the declared type is a non-boolean int)'
                                 % (hwhere, hop['order'], i + 1))
            if not isinstance(hop['residual_copy'], bool):
                raise ValueError('lme: %s.residual_copy must be a boolean' % hwhere)
            if not isinstance(hop['transits_controller'], bool):
                raise ValueError('lme: %s.transits_controller must be a boolean' % hwhere)
            _prov_vocab(hop_rec, 'host_scope_vocab', hop['host_scope'], hwhere)
            hop_channels.append(hop['channel'])
        if hop_channels != list(entry['channels']):
            raise ValueError('lme: %s.custody_hops channel order %r must equal the channels '
                             'closure list %r' % (lwhere, hop_channels, list(entry['channels'])))
        # terminal_channel: the LAST delivery hop, DECLARED as data (no channels[-1] literal in
        # Python). It must be the last hop's channel, and the leaf CONSUMER must be a declared
        # consumer of it -- consumer / terminal-channel coherence (codex still_required). This
        # stops a leaf delivered GREEN on the wrong terminal channel.
        term = entry['terminal_channel']
        if term != hop_channels[-1]:
            raise ValueError('lme: %s.terminal_channel %r must be the last custody hop channel '
                             '%r' % (lwhere, term, hop_channels[-1]))
        term_consumers = (custody_registry[term] or {}).get('consumers') or []
        if entry['consumer'] not in term_consumers:
            raise ValueError('lme: %s consumer %r is not a declared consumer of its terminal '
                             'channel %r (consumers %r) -- wrong terminal custody channel'
                             % (lwhere, entry['consumer'], term, sorted(term_consumers)))
        _prov_vocab(leaf_rec, 'delivery_mode_vocab', entry['delivery_mode'], lwhere)
        _prov_vocab(leaf_rec, 'lifecycle_vocab', entry['lifecycle'], lwhere)
        # host_scope vocab DELIBERATELY omits every_host: an all-host DESIRED custody scope
        # for a private key is rejected (today's all-host replication is observed, never the
        # target). This is the machine enforcement of desired-vs-observed separation.
        _prov_vocab(leaf_rec, 'host_scope_vocab', entry['host_scope'], lwhere)
        mode = entry['mode']
        if not isinstance(mode, str) or not P['mode_re'].match(mode):
            raise ValueError('lme: %s mode %r is not a complete octal string' % (lwhere, mode))
        # RESTRICTIVENESS CEILING (codex-1625 C1-COMPOSED-MATERIAL-DECLARATIONS-REJECTED). A
        # delivered private key must not grant any bit the schema forbids (world r/w/x, group
        # write). This is the absolute invariant that keeps an lme_global_override / profile
        # overlay from WIDENING a leaf mode once the whole-registry equality gate is removed.
        if int(mode, 8) & P['mode_forbidden_bits']:
            raise ValueError('lme: %s mode %r grants permission bits forbidden for a delivered '
                             'private key by material_provision_schema.leaf_mode_forbidden_mask '
                             '%r -- an override may recompose placement/owner/consumer but may '
                             'never widen a private-key mode' % (lwhere, mode,
                                                                 P['mode_forbidden_mask']))

    # --- CA/leaf separation (retained explicit KEY-form control) + PARTITION ------
    # The identity check above already rejects any leaf REFERENCING ca_mid; retain the
    # explicit key-form control (a leaf literally KEYED as the ca material) for clarity.
    if ca_mid in leaves:
        raise ValueError('lme: ca_key_rule material %r must NOT also be a leaf_key_provision '
                         'entry -- the CA-key rule is SEPARATE from every leaf delivery '
                         'contract (codex private_key_correction)' % ca_mid)
    # PARTITION over PRODUCER RELATIONS (codex still_required): every NON-distributable
    # (private-key) material a producer produces must be classified EXACTLY ONCE -- either
    # delivered by a leaf (published to a channel) or declared non_publication -- never both,
    # never neither. A produced private key that is neither is an unaccounted key; one that is
    # both is a contradiction. This binds production to custody by material identity.
    for pid, entry in producer_registry.items():
        for mid in (entry.get('produces_materials') or []):
            if (catalog[mid] or {}).get('kind') in distributable:
                continue
            in_leaf = mid in leaf_material_owner
            in_np = mid in non_publication_materials
            if in_leaf and in_np:
                raise ValueError('lme: producer %r private key %r is BOTH a leaf delivery and '
                                 'non_publication -- a private key cannot be both published to '
                                 'a channel and non-publication' % (pid, mid))
            if not in_leaf and not in_np:
                raise ValueError('lme: producer %r produces private key %r but it is neither '
                                 'delivered by a leaf_key_provision entry nor declared '
                                 'non_publication -- every produced private key must be '
                                 'classified exactly once' % (pid, mid))
    return material_provision


# ===========================================================================
# RESOLVED PROJECTIONS (C1 part C/D). These derive read-only projections of the
# validated declarations onto the canonical lme_resolved.* paths (codex-0430):
#   lme_resolved.required_material.<node>.<svc>.<obligation>
#   lme_resolved.hosts.<node>.resolved_services.<svc>.datastore_clients
#   lme_resolved.database.{domains,etcd_groups}.<id>.members
#   lme_resolved.deployment_identity
# They are value-pure: config VALUES come from the manifests passed in; these
# functions compute STRUCTURE only, never read a secret byte, and are the single
# producer feeding lme_resolved (lme_runtime_inventory is a read-only view of it).
# ===========================================================================

_DEPLOYMENT_ID_RE = re.compile(r'\A[A-Za-z0-9_-]+\Z')


def lme_validate_deployment_identity(value, context=None):
    """DEPLOYMENT-IDENTITY-NOW-REQUIRED (codex-0430 dec 5; codex-0445). A STABLE
    operator/inventory string: [A-Za-z0-9_-]+, never minted or derived from
    run_id/config/hostname/directory. Missing/ill-shaped REJECTS before mutation. The
    HARD 'required for a persistent-resource/DB profile' gate arms with the DB selectors;
    this validates the shape wherever it is supplied. Returns the value unchanged."""
    where = ' (%s)' % context if context else ''
    if not isinstance(value, str) or not _DEPLOYMENT_ID_RE.match(value):
        raise ValueError(
            'lme: deployment_identity%s must be a stable [A-Za-z0-9_-]+ operator/inventory '
            'string, never derived from run_id/config/hostname, got %r' % (where, value))
    return value


def lme_validated_deployment_identity(resolved):
    """Return the VALIDATED stable deployment_identity from a resolved config dict, or None
    when the optional field is unset. Lets load_manifests.yml derive the identity INLINE in
    the projection compose + its read-back (no pinnable `_lme_deployment_identity` set_fact
    that both reuse), so an `-e _lme_deployment_identity=<forged>` cannot bypass
    lme_validate_deployment_identity (the shape gate still runs on the resolved value).
    Value-pure."""
    resolved = resolved or {}
    val = resolved.get('lme_deployment_identity')
    if val is None:
        return None
    return lme_validate_deployment_identity(val)


def lme_material_resource_id(deployment_identity, node, svc, obligation_id):
    """Stable resource id for a material obligation: content-addressed over the DEPLOYMENT
    identity + node + service + obligation id (codex-0430: tied to deployment/declared
    resource identity, NEVER run_id/evidence run). Returns None when deployment_identity is
    absent -- the id cannot be stably bound without it, so the obligation is emitted with a
    null resource_id (a consumer that needs to bind storage/ownership must reject until
    deployment_identity is declared)."""
    if not deployment_identity:
        return None
    payload = [str(deployment_identity), str(node), str(svc), str(obligation_id)]
    return hashlib.sha256(
        json.dumps(payload, separators=(',', ':')).encode('utf-8')).hexdigest()[:32]


def _material_evidence(svc):
    """Structural evidence that a service BEARS material (so an undeclared/declared-none
    service can be flagged). Reads manifest STRUCTURE only -- never a secret value."""
    ev = []
    if svc.get('secrets'):
        ev.append('secrets')
    if svc.get('certs'):
        ev.append('certs')
    if any(isinstance(v, dict) and str(v.get('source', '')).startswith('cert:')
           for v in (svc.get('volumes') or [])):
        ev.append('cert_mount')
    return sorted(set(ev))


def _selected_container_services(services, enable_flags, host_services):
    """Iterate (sid, svc) for the SELECTED container services on this host -- same three
    predicates as load_manifests GAP-5 (is_enabled -> host-scope). is_enabled runs FIRST so
    a scoped-out service with a misspelled enabled_when is still caught loudly."""
    for sid, svc in (services or {}).items():
        if not isinstance(svc, dict) or svc.get('kind') != 'container':
            continue
        if not is_enabled(svc.get('enabled_when'), enable_flags or {}, context=sid):
            continue
        if host_services and sid not in host_services:
            continue
        yield sid, svc


def lme_project_required_material(services, node, catalog, schema, catalog_schema,
                                  enable_flags=None, host_services=None,
                                  deployment_identity=None, producer_registry=None,
                                  custody_registry=None):
    """Emit lme_resolved.required_material.<node>.<svc>.<obligation> from each SELECTED
    container service's declared material_requirements, validated against the catalog +
    schema. Returns:
      {'required_material': {node: {svc: {obligation_id: validated_record}}},
       'required_material_status': {node: {svc: {status, evidence, enabled, resource_ids?}}}}
    status is 'declared' | 'declared_none' | 'undeclared'. A DECLARED service is validated.
    A declared-none ({}) service that still bears material EVIDENCE FAILS (codex-0430: an
    empty declaration cannot erase a secrets/cert obligation). An UNDECLARED service is NOT
    failed (missing_field is not armed swarm-wide) -- it is surfaced with its structural
    evidence (visible debt), never hidden as empty. Consumers MUST read
    required_material_status to distinguish 'no material' from 'not yet declared'."""
    material = {}
    status = {}
    for sid, svc in _selected_container_services(services, enable_flags, host_services):
        evidence = _material_evidence(svc)
        if 'material_requirements' not in svc:
            status.setdefault(node, {})[sid] = {
                'status': 'undeclared', 'evidence': evidence, 'enabled': True}
            continue
        obl = svc['material_requirements']
        if obl == {} and evidence:
            raise ValueError(
                'lme: service %r declares material_requirements: {} (declared-none) but bears '
                'material evidence %r -- an empty declaration cannot erase a secrets/cert '
                'obligation (codex-0430)' % (sid, evidence))
        refs = []
        for _bid, binding in (svc.get('datastore_clients') or {}).items():
            refs.extend((binding or {}).get('material_requirement_refs') or [])
        validated = lme_validate_material_requirements(
            catalog, obl, schema, catalog_schema,
            referenced_ids=(refs or None), context=sid,
            producer_registry=producer_registry, custody_registry=custody_registry)
        if validated:
            material.setdefault(node, {})[sid] = validated
        status.setdefault(node, {})[sid] = {
            'status': ('declared_none' if not validated else 'declared'),
            'evidence': evidence, 'enabled': True,
            'resource_ids': {oid: lme_material_resource_id(deployment_identity, node, sid, oid)
                             for oid in validated}}
    return {'required_material': material, 'required_material_status': status}


def lme_project_datastore_clients(services, node, enable_flags=None, host_services=None):
    """Emit lme_resolved.hosts.<node>.resolved_services.<svc>.datastore_clients from each
    selected service's declared datastore_clients (codex-0430 decision 3). Validates the
    binding shape (domain_ref/database_ref/principal_ref/endpoint_ref required;
    material_requirement_refs a list). Returns
    {'hosts': {node: {'resolved_services': {svc: {'datastore_clients': {...}}}}}}."""
    required = ('domain_ref', 'database_ref', 'principal_ref', 'endpoint_ref')
    out = {}
    for sid, svc in _selected_container_services(services, enable_flags, host_services):
        clients = svc.get('datastore_clients')
        if clients is None:
            continue
        if not isinstance(clients, dict):
            raise ValueError('lme: datastore_clients for %r must be a mapping' % sid)
        for bid, binding in clients.items():
            if not isinstance(binding, dict):
                raise ValueError('lme: datastore_clients %r.%r must be a mapping' % (sid, bid))
            for f in required:
                if not binding.get(f):
                    raise ValueError('lme: datastore_clients %r.%r missing %r' % (sid, bid, f))
            mrefs = binding.get('material_requirement_refs')
            if mrefs is not None and not isinstance(mrefs, list):
                raise ValueError('lme: datastore_clients %r.%r material_requirement_refs '
                                 'must be a list' % (sid, bid))
        out.setdefault(node, {}).setdefault('resolved_services', {})[sid] = {
            'datastore_clients': clients}
    return {'hosts': out}


def lme_project_database_membership(membership):
    """Emit lme_resolved.database.{domains,etcd_groups}.<id>.members from
    lme_database_membership (codex-0430 decision 4). Validates each group's members is a
    NON-EMPTY list of UNIQUE non-empty node-id strings (empty/dup rejected). Returns
    {'database': {...}} ({} when absent). Membership vs the actual inventory + the selected
    profile's HA constraints (wrong-runtime / insufficient-HA / an extra collector host not
    joining a domain) is the DB-profile consumer's check (D); this validates the shape."""
    if not membership:
        return {'database': {}}
    if not isinstance(membership, dict):
        raise ValueError('lme: lme_database_membership must be a mapping')
    out = {}
    for group_kind in ('domains', 'etcd_groups'):
        groups = membership.get(group_kind)
        if groups is None:
            continue
        if not isinstance(groups, dict):
            raise ValueError('lme: lme_database_membership.%s must be a mapping' % group_kind)
        proj = {}
        for gid, gval in groups.items():
            if not isinstance(gval, dict) or 'members' not in gval:
                raise ValueError('lme: %s.%r must declare a members list' % (group_kind, gid))
            members = gval['members']
            if not isinstance(members, list) or not members:
                raise ValueError('lme: %s.%r.members must be a non-empty list' % (group_kind, gid))
            if any(not isinstance(m, str) or not m for m in members):
                raise ValueError('lme: %s.%r.members must be non-empty node-id strings'
                                 % (group_kind, gid))
            if len(set(members)) != len(members):
                raise ValueError('lme: %s.%r.members has duplicate node ids' % (group_kind, gid))
            proj[gid] = {'members': list(members)}
        out[group_kind] = proj
    return {'database': out}


def lme_selection_conflicts(operator_selections, caller_selections, registry=None):
    """C1-CONFLICTING-INPUT-PRECEDENCE: the sorted keys present in BOTH the pristine
    operator capture (native extra-var/inventory precedence already resolved this winner)
    AND a caller-normalized lme_inputs.selections, with DIFFERING values. A lower-tier
    namespaced selection may not silently override the operator's native selection; where
    the two disagree provenance cannot be established, so the resolver REJECTS (rather than
    combining one over the other and recreating consumer disagreement). Agreeing keys are
    NOT conflicts. Value-pure.

    C1-CONFLICT-GATE-BOOLEAN-REPRESENTATION-REGRESSION (codex-0645 HIGH): compare by the
    DECLARED FIELD TYPE, not raw bytes. A representation difference is NOT a disagreement --
    an `-e install_llm=false` (string 'false') or a JSON-typed CLI false and a namespaced
    bool false all denote the SAME selection, so they must NOT be flagged as a conflict;
    only a genuine value disagreement (true vs false) is. When a `registry` is supplied both
    sides are canonicalized through _coerce_declared (the resolver's own coercion) before
    comparison. A key absent from the registry falls back to a RAW compare. A value that will
    NOT canonicalize to the declared type (e.g. an int 0 for a bool field) is NOT compared
    raw -- Python 0 == False would launder the malformed input into the caller's clean value
    with NO conflict -- it is surfaced as a CONFLICT (fail-closed) so admission REJECTS the
    invalid declared-type input (C1-CONFLICT-COERCION-FAILURE-RAW-EQUALITY). A valid
    equivalent representation (string 'false' vs bool false) still canonicalizes and agrees,
    so it is NOT a conflict."""
    op = operator_selections or {}
    caller = caller_selections or {}
    fields = (registry or {}).get('fields') if isinstance(registry, dict) else None
    fields = fields if isinstance(fields, dict) else {}
    out = []
    for k in op:
        if k not in caller:
            continue
        ov, cv = op[k], caller[k]
        field = fields.get(k)
        if isinstance(field, dict):
            try:
                ov = _coerce_declared(op[k], field)
                cv = _coerce_declared(caller[k], field)
            except (ValueError, TypeError):
                # C1-CONFLICT-COERCION-FAILURE-RAW-EQUALITY: an operator (or caller) value
                # that will NOT canonicalize to the DECLARED type (e.g. an int 0 for a bool
                # field) cannot be proven equal to the other side. The prior raw fallback
                # (ov, cv = op[k], caller[k]) was fail-OPEN, not fail-closed: Python 0 ==
                # False (and '' == 0, etc.) let a malformed declared-type input be laundered
                # into the caller's clean value with NO conflict raised, so combine() then
                # replaced it and the resolver's typed validation only ever saw a valid bool.
                # Surface it as a CONFLICT so admission REJECTS the invalid declared-type
                # input at the pristine-selection gate; a VALID equivalent representation
                # (string 'false' for a bool) still canonicalizes above and agrees.
                out.append(k)
                continue
        if ov != cv:
            out.append(k)
    return sorted(out)


def lme_resolve_from_admitted(registry, profile_vars=None, operator_selections=None,
                              caller_inputs=None):
    """Compose the effective resolver inputs from the PRISTINE admitted operator capture
    (`operator_selections`) + the caller-normalized lme_inputs (`caller_inputs`), then
    resolve -- in ONE value-pure call with NO overridable intermediate task fact
    (C1-DERIVED-EFFECTIVE-INPUTS-PIN). Previously resolve.yml composed a NAMED
    `_lme_eff_inputs` set_fact that both the resolver and its read-back guard read; an
    `-e _lme_eff_inputs={selections:{},...}` outranked the set_fact and DISCARDED the
    admitted selection, while the guard recomputed from that SAME pinned object and agreed
    (an internally-consistent discard). Folding the composition HERE and calling this
    filter inline (an expression, not a variable, so extra-vars cannot pin it) makes that
    intermediate a dead name: the derivation is faithful to the admitted declarations +
    operator inputs. Replicates resolve.yml's compose exactly: caller selections combine
    over the operator capture per key (a genuine disagreement was already rejected by the
    conflict gate); observations come only from the caller; each operator key carries the
    honest `operator` origin and a caller-verified finer origin combines on top. Returns
    {resolved, origins, enable_flags}."""
    op = dict(operator_selections or {})
    caller = caller_inputs if isinstance(caller_inputs, dict) else {}
    caller_sel = caller.get('selections') or {}
    caller_obs = caller.get('observations') or {}
    caller_orig = caller.get('origins') or {}
    selections = dict(op)
    selections.update(caller_sel)
    origins = {k: _COMBINED_OPERATOR for k in op}
    origins.update(caller_orig)
    return lme_resolve_config(registry, profile_vars or {}, selections, caller_obs, origins)


def lme_split_brain_keys(registry, bare_scope, resolved):
    """POST-BRIDGE split-brain invariant (C1-DERIVED-EFFECTIVE-INPUTS-PIN closure). After
    resolve.yml materialises the bare-name compat facts, this returns every registry key
    whose BARE value in scope disagrees with the canonical `resolved` value -- compared by
    the DECLARED TYPE, so a valid equivalent representation (the string 'false' for a bool)
    is NOT a disagreement. Such a key is a split-brain: a value the resolution DISCARDED
    while a higher-precedence bare input kept it.

    Why this catches EVERY pin hop in one place: a bare-name fact is written by set_fact
    (Ansible var precedence 19), which is OVERWRITTEN by role/include params and extra-vars
    (20-22). So a bare != resolved key can ONLY arise from a higher-precedence operator
    input that the resolution dropped -- exactly the discarded-declaration condition,
    whether the pin landed on `_lme_eff_inputs`, `_lme_operator_selections`,
    `_lme_sel_keys`/`_lme_reg_keys`, or any future derived intermediate. Inventory/play/role
    -default values (<=15) are overwritten by the bridge, so they can never false-trip it.

    A declared OPTIONAL absent from `resolved` is allowed IFF its bare value equals the
    field's declared `bridge_absent` (the sanctioned 'unset' compat value the loader resets
    it to); a bare key present in scope but absent from `resolved` with no `bridge_absent`
    sanction is itself a dropped selection. Value-pure; returns the sorted offending keys
    (empty == consistent)."""
    fields, _precedence, _channels = _require_registry_shape(registry)
    bare_scope = bare_scope or {}
    resolved = resolved or {}
    out = []
    for key, field in fields.items():
        if key not in bare_scope:
            continue
        bv = bare_scope[key]
        if key in resolved:
            try:
                if _coerce_declared(bv, field) != _coerce_declared(resolved[key], field):
                    out.append(key)
            except (ValueError, TypeError):
                # the bare value is not even a valid declared-type representation of the
                # resolved value -> a discarded/laundered declaration (fail-closed).
                out.append(key)
        elif 'bridge_absent' in field:
            if bv != field['bridge_absent']:
                out.append(key)
        else:
            # present in the bare scope, absent from resolved, no sanctioned 'unset' value:
            # a selection was admitted into scope and then dropped from resolution.
            out.append(key)
    return sorted(out)


def lme_observation_only_keys(registry):
    """codex-1045 decision B: the sorted registry keys DECLARED observation_only, selected
    GENERICALLY by the property (never by a field name). resolve.yml excludes these from the
    compatibility bare-name bridge, so an observation_only value lives ONLY in lme_resolved and
    NO bare alias is ever manufactured -- a repeated load without the observation leaves no stale
    alias to trip the split-brain invariant, and no bridge_absent sentinel is needed. The
    split-brain guard is NOT silenced for the class (an unexpected bare fact in scope is still
    caught) and operator/inventory/profile injection is still rejected by the observation-only
    channel guard. Value-pure."""
    fields, _precedence, _channels = _require_registry_shape(registry)
    return sorted(k for k, f in fields.items() if isinstance(f, dict) and f.get('observation_only'))


def lme_validate_dependency_closure(services, context=None):
    """C1-COMPLETE-CONFIGURATION-VALIDATION (dependency half): every id in a service's
    dependencies (requires/after/wants/partof/binds_to) MUST resolve to a DECLARED manifest
    service id. An unknown name (a typo like 'elasticsarch') is rejected BEFORE activation,
    rather than silently relaxed to a Wants= on an absent unit. Validates against the FULL
    manifest set (a legitimate cross-host requires is relaxed to Wants by GAP-3 host-scoping
    -- that is separate and stays valid; only names that resolve to NO manifest fail).
    Returns the services map unchanged on success."""
    services = services or {}
    known = set(services.keys())
    rel_kinds = ('requires', 'after', 'wants', 'partof', 'binds_to')
    for sid, svc in services.items():
        deps = (svc or {}).get('dependencies') or {}
        for rel in rel_kinds:
            for dep in (deps.get(rel) or []):
                if dep not in known:
                    raise ValueError(
                        'lme: service %r dependencies.%s names %r which resolves to no '
                        'declared manifest service id (known: %r)'
                        % (sid, rel, dep, sorted(known)))
    return services


def _deep_combine(base, over):
    """Mirror Ansible's `combine(recursive=True)`: keys in `over` win; where BOTH sides are
    dicts, merge recursively; otherwise `over` replaces `base` wholesale. Pure; returns a new
    object and never mutates its inputs. A non-dict `base` (or `over`) is replaced by `over`."""
    if not isinstance(base, dict) or not isinstance(over, dict):
        return over
    out = dict(base)
    for k, v in over.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_combine(out[k], v)
        else:
            out[k] = v
    return out


def _normalize_list_join(value):
    """GENERIC `list_join` normalizer (declared by name in legacy_service_override_projection):
    normalise a multi-host value to a trimmed, comma-joined bare string, replicating
    load_manifests.yml's former _lme_es_seed_join / _lme_es_masters_join Jinja EXACTLY: a STRING
    is bracket-stripped, comma-split, trimmed, empties dropped (the Jinja `select`), and joined;
    a LIST is str-cast, trimmed and joined with NO empty-drop (matching the Jinja list branch);
    None/absent -> ''. Value-pure; carries no deployment-specific literal."""
    if value is None:
        return ''
    if isinstance(value, str):
        stripped = value.replace('[', '').replace(']', '')
        parts = [p.strip() for p in stripped.split(',')]
        return ','.join(p for p in parts if p)  # Jinja `select` drops empties (string branch)
    return ','.join(str(p).strip() for p in value)  # list branch: no empty-drop (Jinja parity)


# --- generic legacy service-override projection consumer ---------------------------------
# C1-LEGACY-CONFIGURATION-MOVED-INTO-ENGINE (codex-1100): the service id, env keys, source
# wiring and single-node master default are DECLARED in manifests/global.yml
# (legacy_service_override_projection). This file evaluates only a small CLOSED, GENERIC vocab
# of gates + normalizers; no deployment-specific literal lives here.

_ABSENT = object()  # an es-context source that was NEVER defined -- distinct from an explicit null

_NORMALIZERS = {
    'list_join': _normalize_list_join,   # legacy multi-host value -> trimmed CSV string
}


def _projection_source(es_ctx, name):
    """Return the es-context value for `name`, or the _ABSENT sentinel when the key is not
    present. An EXPLICIT null is PRESENT (returns None), distinct from absence -- so a declared
    default_when_absent fires ONLY on true absence and a supplied null is preserved
    (C1-LEGACY-EXPLICIT-NULL-CONFLATED-WITH-ABSENCE, codex-1100)."""
    if not isinstance(es_ctx, dict) or name not in es_ctx:
        return _ABSENT
    return es_ctx[name]


def _projection_entry_value(entry, es_ctx):
    """Evaluate ONE declared projection environment entry against the es context. Returns
    (emit, value); emit False means the key is not written. Pure -- the gate/normalizer vocab
    is fixed and generic, every deployment specific comes from `entry`. An unknown gate or
    normalizer, or a malformed entry, RAISES (fail-closed, never a silent drop)."""
    if not isinstance(entry, dict):
        raise ValueError('lme: legacy_service_override_projection entry must be a mapping, got %r' % (entry,))
    key = entry.get('key')
    if not isinstance(key, str) or not key:
        raise ValueError('lme: legacy_service_override_projection entry needs a non-empty string key, got %r' % (key,))
    norm_name = entry.get('normalize')
    if norm_name is not None and norm_name not in _NORMALIZERS:
        raise ValueError('lme: legacy_service_override_projection key %r declares unknown normalize %r (known %r)'
                         % (key, norm_name, sorted(_NORMALIZERS)))
    normalize = _NORMALIZERS[norm_name] if norm_name is not None else (lambda v: v)
    gate = entry.get('emit_when')
    src = _projection_source(es_ctx, entry.get('source'))

    if gate == 'present':
        if src is _ABSENT or src is None:
            return (False, None)
        return (True, normalize(src))
    if gate == 'truthy_not_omit':
        if src is _ABSENT or not src or '__omit_place_holder__' in str(src):
            return (False, None)
        return (True, normalize(src))
    if gate == 'nonempty':
        if src is _ABSENT:
            return (False, None)
        val = normalize(src)
        if not isinstance(val, str) or len(val) == 0:
            return (False, None)
        return (True, val)
    if gate == 'flag':
        flag_on = bool(es_ctx.get(entry.get('flag_source'))) if isinstance(es_ctx, dict) else False
        if not flag_on:
            return (False, None)
        # branch active: default_when_absent ONLY on true absence; an EXPLICIT null is
        # preserved (null-env-skip drops the key at render), a present value is normalized.
        if src is _ABSENT:
            return (True, entry.get('default_when_absent'))
        if src is None:
            return (True, None)
        return (True, normalize(src))
    raise ValueError('lme: legacy_service_override_projection key %r declares unknown emit_when %r' % (key, gate))


def lme_effective_service_overrides(operator_overrides, es_ctx=None, projection=None):
    """C1-SERVICE-OVERRIDE-INTERMEDIATE-DISCARDS-DECLARATION (codex-1015 HIGH). The SINGLE
    value-pure source of the effective service-override map: the legacy shim BASE (built by
    CONSUMING the declared `legacy_service_override_projection` -- codex-1100 architecture fix,
    no embedded service id / env key / master default here) with the operator's
    `lme_service_overrides` combined OVER it (operator wins LAST, recursive). Folded HERE and
    called INLINE by load_manifests.yml's build loop AND its faithful-application invariant, so
    NO pinnable task fact remains between the admitted declarations (es context +
    lme_service_overrides + the byte-bound projection) and the composed lme_services.

    C1-MALFORMED-OVERRIDE-SILENT-DISCARD (codex-1100): a None operator declaration is legitimate
    ABSENCE (no overrides); a NONMAPPING shape (a scalar `lme_service_overrides=7`, a list) is a
    MALFORMED declaration and is REJECTED before composition -- never silently coerced to {} --
    and each per-service value must itself be a mapping (the offending id is named).

    es_ctx carries the admitted legacy inputs, PRESENCE-PRESERVING (a key present with a null
    value is distinct from an absent key). The projection is byte-bound (resolve.yml binds the
    whole global.yml), so it cannot be pinned. Inert per service unless its declared gate_source
    is present. Value-pure."""
    if operator_overrides is None:
        operator_overrides = {}
    elif not isinstance(operator_overrides, dict):
        raise ValueError('lme: lme_service_overrides must be a mapping of service-id -> override, '
                         'got %r (%s)' % (operator_overrides, type(operator_overrides).__name__))
    for sid, ov in operator_overrides.items():
        if not isinstance(ov, dict):
            raise ValueError('lme: lme_service_overrides[%r] must be a mapping, got %r (%s)'
                             % (sid, ov, type(ov).__name__))
    ctx = es_ctx if isinstance(es_ctx, dict) else {}
    projection = projection if isinstance(projection, dict) else {}
    legacy = {}
    for svc, spec in projection.items():
        if not isinstance(spec, dict):
            raise ValueError('lme: legacy_service_override_projection[%r] must be a mapping' % (svc,))
        gate_source = spec.get('gate_source')
        if gate_source is not None:
            gv = _projection_source(ctx, gate_source)
            if gv is _ABSENT or gv is None:
                continue  # projection inert for this service (no legacy inputs present)
        env = {}
        for entry in (spec.get('environment') or []):
            emit, value = _projection_entry_value(entry, ctx)
            if emit:
                env[entry['key']] = value
        if env:
            legacy = _deep_combine(legacy, {svc: {'environment': env}})
    return _deep_combine(legacy, operator_overrides)


_OVERRIDE_LEAF_MISSING = object()


def _canonical_kind(v):
    """A comparison kind that does NOT conflate bool with int (Python True == 1) and keeps the
    container/scalar distinction. isinstance-based (checking bool BEFORE int), so a data-tagged
    str/int/dict subclass (Ansible 2.19 tagging) still compares as its base kind -- codex-1100
    warns an exact `type(a) is type(b)` would false-reject ordinary overrides."""
    if isinstance(v, bool):
        return 'bool'
    if isinstance(v, int):
        return 'int'
    if isinstance(v, float):
        return 'float'
    if isinstance(v, str):
        return 'str'
    if isinstance(v, dict):
        return 'dict'
    if isinstance(v, (list, tuple)):
        return 'list'
    if v is None:
        return 'none'
    return 'other'


def _leaf_equal(a, b):
    """C1-LIST-MAPPING-LEAF-BOOL-INT-CONFLATION (codex-1300; was codex-1100 #3): RECURSIVE
    structural TYPE-AWARE equality at EVERY supported container depth (dict, list, and any
    nesting). Two leaves must share a canonical kind AND be equal, so `0` != `false`, `[0]` !=
    `[false]`, `{e: false}` != `{e: 0}`, and `[{e: true}]` != `[{e: 1}]` at ANY depth. Lists
    compare element-by-element; dicts compare by TYPE-AWARE key pairing then recurse on each value.

    The dict branch is what v3 lacked: v3 recursed lists but a MAPPING element inside a list (and a
    dict leaf generally) fell through to Python `==`, which conflates False/0 and True/1 (and
    1/1.0) inside a mapping. Key pairing is TYPE-AWARE on purpose -- a plain `set(a)==set(b)` /
    `b[k]` lookup would reopen the SAME conflation at the KEY level, because a Python dict collapses
    {True: x} and {1: x} (and {1: x} vs {1.0: x}) to a single key. A valid normalized
    representation is NOT weakened: an ordinary str override (incl. an Ansible 2.19 data-tagged str
    subclass, isinstance-based kind) still compares equal to the composed str. Value-pure."""
    ka, kb = _canonical_kind(a), _canonical_kind(b)
    if ka != kb:
        return False
    if ka == 'list':
        if len(a) != len(b):
            return False
        return all(_leaf_equal(x, y) for x, y in zip(a, b))
    if ka == 'dict':
        if len(a) != len(b):
            return False
        # TYPE-AWARE key pairing: index b by (canonical_kind, key) so a bool key can never match an
        # int key. Python's True==1 / False==0 / 1==1.0 key-collapse would otherwise defeat the very
        # bool/int distinction this function exists to enforce.
        b_by_typed_key = {(_canonical_kind(k), k): v for k, v in b.items()}
        for k, av in a.items():
            bv = b_by_typed_key.get((_canonical_kind(k), k), _OVERRIDE_LEAF_MISSING)
            if bv is _OVERRIDE_LEAF_MISSING or not _leaf_equal(av, bv):
                return False
        return True
    return a == b


def _override_leaf_missing(ov, sv, path, out):
    """Walk the override subtree `ov`; append to `out` each `path` where a leaf of `ov` is not
    present-and-TYPED-equal (_leaf_equal) in the composed subtree `sv`. Dict keys are paired
    TYPE-AWARELY (a bool key does not match an int key -- the same key-collapse hazard fixed in
    _leaf_equal), so a missing typed key becomes a locator and FAILS CLOSED. List/scalar leaves are
    compared by the now-fully-recursive _leaf_equal, so a mapping element inside a list is compared
    type-awarely at every depth."""
    if isinstance(ov, dict):
        if not isinstance(sv, dict):
            out.append(path or '.')
            return
        sv_by_typed_key = {(_canonical_kind(k), k): v for k, v in sv.items()}
        for k in ov:
            child = sv_by_typed_key.get((_canonical_kind(k), k), _OVERRIDE_LEAF_MISSING)
            child_path = (path + '.' + str(k)) if path else str(k)
            if child is _OVERRIDE_LEAF_MISSING:
                out.append(child_path)
            else:
                _override_leaf_missing(ov[k], child, child_path, out)
    elif not _leaf_equal(ov, sv):
        out.append(path or '.')


def lme_service_overrides_applied(services, effective_overrides):
    """C1-SERVICE-OVERRIDE-INTERMEDIATE-DISCARDS-DECLARATION invariant (faithful-application
    half). Return the sorted 'service_id.path' locators where a leaf of the EFFECTIVE
    service-override map (legacy shim + operator lme_service_overrides, recomputed inline via
    lme_effective_service_overrides -- NOT read from a pinnable intermediate) is NOT reflected in
    the composed `services`. Empty == every admitted override was faithfully applied. A pin that
    discarded an override leaves the declared leaf missing/different -> non-empty -> the loader
    fails closed pre-mutation, so the revision can no longer silently equal a no-override control.

    C1-OVERRIDE-MISSING-SERVICE-SKIP (codex-1100): an override id ABSENT from `services` is NO
    LONGER skipped -- it is a discarded declaration (the admission + coverage gates guarantee
    every declared service is composed, so an absent id can only mean a pinned/suppressed
    projection) and yields an explicit locator. Leaf comparison is TYPED (0 != false). Value-pure."""
    services = services if isinstance(services, dict) else {}
    effective_overrides = effective_overrides if isinstance(effective_overrides, dict) else {}
    out = []
    for sid, ov in effective_overrides.items():
        if sid not in services:
            out.append('%s (absent from composed services)' % (sid,))
            continue
        _override_leaf_missing(ov, services[sid], str(sid), out)
    return sorted(out)


def lme_service_typed_inputs(services, registry):
    """MULTINODE-217-TEMPLATED-PORT-TYPE (codex choice a). `services` = {service id: service entry or partial
    override entry}. Returns a copy in which ONLY the integer fields registry.service_input_types declares
    (<list field>.item_int_fields) are normalized: an int (not a bool) within [min, max] is kept; a string matching
    canonical_regex within [min, max] becomes that int; anything else (bool, float, null, another string, out of
    range) raises. Absent leaves stay absent; every other field is returned as given (no recursive coercion).
    Value-pure; applied at the lme_services build and to the faithful-application re-derivation only."""
    decl = (registry or {}).get('service_input_types') if isinstance(registry, dict) else None
    if not isinstance(decl, dict) or not decl:
        raise ValueError('lme: registry service_input_types must declare the integer service input fields')
    for lf, d in decl.items():
        if not isinstance(d, dict) or set(d) != {'item_int_fields', 'canonical_regex', 'min', 'max'} \
                or not isinstance(d['item_int_fields'], list) or not d['item_int_fields'] \
                or any(not isinstance(f, str) for f in d['item_int_fields']) or not isinstance(d['canonical_regex'], str) \
                or any(isinstance(d[b], bool) or not isinstance(d[b], int) for b in ('min', 'max')) or d['min'] > d['max']:
            raise ValueError('lme: registry service_input_types.%s must be {item_int_fields, canonical_regex, min, max}; got %r' % (lf, d))
    if not isinstance(services, dict):
        raise ValueError('lme: service_input_types applies to a {service id: entry} mapping; got %r' % (type(services).__name__,))

    def one(v, where, d):
        if isinstance(v, bool) or not (isinstance(v, int) or isinstance(v, str)):
            raise ValueError('lme: %s = %r (%s) is not a declared integer input (int or canonical decimal string, %d..%d)' % (
                where, v, type(v).__name__, d['min'], d['max']))
        if isinstance(v, str):
            if not re.match(d['canonical_regex'] + r'\Z', v):
                raise ValueError('lme: %s = %r (str) is not a canonical decimal (%s)' % (where, v, d['canonical_regex']))
            v = int(v)
        else:
            v = int(v)
        if not d['min'] <= v <= d['max']:
            raise ValueError('lme: %s = %r is outside the declared range %d..%d' % (where, v, d['min'], d['max']))
        return v

    out = {}
    for sid, svc in services.items():
        if not isinstance(svc, dict):
            out[sid] = svc
            continue
        new = dict(svc)
        for lf, d in decl.items():
            if lf not in svc:
                continue
            items = svc[lf]
            if not isinstance(items, list):
                raise ValueError('lme: %s.%s must be a list; got %r' % (sid, lf, type(items).__name__))
            typed = []
            for i, it in enumerate(items):
                if not isinstance(it, dict):
                    raise ValueError('lme: %s.%s[%d] must be a mapping; got %r' % (sid, lf, i, it))
                it = dict(it)
                for f in d['item_int_fields']:
                    if f in it:
                        it[f] = one(it[f], '%s.%s[%d].%s' % (sid, lf, i, f), d)
                typed.append(it)
            new[lf] = typed
        out[sid] = new
    return out


def lme_unknown_service_override_ids(operator_overrides, declared_universe):
    """codex-1045 admission / C1-OVERRIDE-MISSING-SERVICE-SKIP (codex-1100): the sorted OPERATOR
    override service ids that are NOT in the COMPLETE ADMITTED catalog `declared_universe` (every
    declared service-manifest id, enumerated BEFORE activation + host filtering). A declared-but-
    disabled or off-host id is IN the universe and stays a valid override target; a misspelled /
    removed / renamed-away id is not, so it is rejected before mutation. Validates the OPERATOR
    keys, not the effective/shim map (the shim only ever targets declared ids). Value-pure."""
    ov = operator_overrides if isinstance(operator_overrides, dict) else {}
    universe = set(declared_universe or [])
    return sorted(str(sid) for sid in ov if sid not in universe)


def lme_service_override_shape_errors(operator_overrides):
    """codex-1100 #2 C1-MALFORMED-OVERRIDE-SILENT-DISCARD (admission half). Return the sorted
    shape violations of the OPERATOR lme_service_overrides, evaluated at ADMISSION -- BEFORE any
    composition. `None` is legitimate absence -> []. A nonmapping top-level value (scalar/list), or
    ANY per-service value that is not a mapping, is a MALFORMED declaration named here so the loader
    rejects it at admission and NEVER silently coerces it to {}; the defensive `isinstance ... else {}`
    coercions in the downstream override helpers are thereby unreachable for a nonmapping once this
    gate has run. Kept distinct in message + stage from the composition fold's 'must be a mapping'
    raise so the two gates are separable by a classifier. Value-pure."""
    if operator_overrides is None:
        return []
    if not isinstance(operator_overrides, dict):
        return ['<top-level> is not a mapping (got %s)' % type(operator_overrides).__name__]
    return sorted('%s is not a mapping (got %s)' % (sid, type(ov).__name__)
                  for sid, ov in operator_overrides.items() if not isinstance(ov, dict))


def lme_service_coverage_gap(declared_universe, services):
    """codex-1100 C1-OVERRIDE-MISSING-SERVICE-SKIP (coverage half): the sorted SYMMETRIC
    difference between the declared universe (a NON-pinnable inline enumeration of the service
    manifests) and the composed `services` (lme_services) keys. A pinned or suppressed projection
    -- `-e lme_services={}`, an `-e _lme_service_files=<subset>` (drops a declared service) or a
    `<superset>` (composes an undeclared one) -- makes composed coverage diverge from the
    declaration, so a NON-empty result fails closed BEFORE activation, INDEPENDENTLY of the
    pinnable projection. A symmetric difference (not a one-way subset) catches BOTH the missing
    and the extra case. Value-pure."""
    universe = set(declared_universe or [])
    composed = set((services or {}).keys()) if isinstance(services, dict) else set()
    return sorted(str(x) for x in (universe ^ composed))


# Prerequisite hunk (byte-identical to the helper introduced by stack commit ea67f95 REV-ACCEL-MODEL): its
# SEED-06 consumer is _rh_validate (policy_sha256). The later accelerator join keeps ONE definition.
def _digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')).hexdigest()


def _rh_kind(v):
    if isinstance(v, bool):
        return 'bool'
    if isinstance(v, int):
        return 'int'
    if isinstance(v, str):
        return 'str'
    if isinstance(v, float):
        return 'float'
    if isinstance(v, dict):
        return 'mapping'
    if isinstance(v, (list, tuple)):
        return 'list'
    return 'null' if v is None else type(v).__name__


def _rh_get(tree, dotted):
    cur = tree
    for k in dotted.split('.'):
        if not isinstance(cur, dict) or k not in cur:
            return False, None
        cur = cur[k]
    return True, cur


def _rh_leaves(x, prefix):
    if isinstance(x, dict) and x:
        out = []
        for k in sorted(x):
            if not isinstance(k, str) or not k or '.' in k:
                raise ValueError('lme: remote_harness override key %r under %r must be a non-empty string without "."' % (k, '.'.join(prefix)))
            out.extend(_rh_leaves(x[k], prefix + [k]))
        return out
    return [(prefix, x)]


def _rh_prefix(path, pattern):
    return len(path) >= len(pattern) and all(p == '*' or p == q for p, q in zip(pattern, path))


def _rh_expand(tree, pattern):
    """Concrete dotted paths in tree matching pattern ('*' = every key of a mapping)."""
    found = [([], tree)]
    for seg in pattern.split('.'):
        nxt = []
        for path, node in found:
            if not isinstance(node, dict):
                continue
            for k in (sorted(node) if seg == '*' else [seg]):
                if k in node:
                    nxt.append((path + [k], node[k]))
        found = nxt
    return found


def _rh_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


# C1-BOOTSTRAP-CONTRACT-VALUE-ADMISSION (codex 191117 / 191017): the closed check vocabulary of registry
# remote_harness_schema.contract_admission. Generic: every contract, path, enum, pattern and reference is registry
# DATA; this code names no contract, tool, env name or deployment value.
_RH_CA_KINDS = frozenset(('keys', 'has_keys', 'enum', 'pattern', 'key_pattern', 'positive_int', 'strings', 'within',
                          'ere', 'ere_compose', 'umask_yields', 'not_in'))
_RH_CA_MODS = {'each': frozenset(('enum', 'pattern', 'strings', 'positive_int')),
               'having': frozenset(('within',)), 'sed_delimited': frozenset(('ere',))}
_RH_CA_ERE_BANNED = ('\\', '\n', '|', '[:', '(?', '*?', '+?', '??', '}?')


def _rh_ca_same(a, b):
    """Type-exact equality (True != 1; tagged strings compare as str)."""
    return _rh_kind(a) == _rh_kind(b) and a == b


def _rh_ca_members(x):
    if isinstance(x, (dict, list)):
        return list(x)
    return [x]


def _rh_ca_ere(v, form, sed):
    """None when v is an admitted portable ERE of the declared form, else the reason."""
    if not isinstance(v, str) or not v:
        return 'must be a non-empty string'
    bad = [t for t in _RH_CA_ERE_BANNED + (('/',) if sed else ()) if t in v]
    if bad:
        return 'contains %r (portable ERE: no backslash, newline, alternation, class name, extension or lazy quantifier%s)' % (
            bad, '; sed-delimited: no /' if sed else '')
    body = v
    if form == 'anchored':
        if len(v) < 2 or not v.startswith('^') or not v.endswith('$'):
            return "must be anchored: exactly a leading '^' and a trailing '$'"
        body = v[1:-1]
    if '^' in body or '$' in body:
        return "must carry no other '^' or '$' (%s)" % ('an anchored ERE is anchored once' if form == 'anchored' else 'a fragment is composed inside ^...$')
    try:
        re.compile(v)
    except re.error as e:
        return 'does not compile: %s' % (e,)
    return None


def _rh_ca_registry(ca, schema):
    """The registry declaration contract_admission, shape-checked (fail-closed: admission can never be disabled or
    weakened by a malformed or missing registry entry). Returns ({pattern name: compiled}, contracts)."""
    if not isinstance(ca, dict) or set(ca) != {'patterns', 'contracts'} or not isinstance(ca['patterns'], dict) \
            or not isinstance(ca['contracts'], dict) or not ca['contracts']:
        raise ValueError('lme: registry remote_harness_schema.contract_admission must declare {patterns, contracts} (bootstrap contract admission is fail-closed); got %r' % (ca,))
    pats = {}
    for n in sorted(ca['patterns']):
        p = ca['patterns'][n]
        try:
            pats[n] = re.compile(p) if isinstance(p, str) and p else None
        except re.error:
            pats[n] = None
        if pats[n] is None:
            raise ValueError('lme: registry contract_admission.patterns.%s must be a compilable regex; got %r' % (n, p))
    strs = lambda a: isinstance(a, list) and bool(a) and all(isinstance(x, str) and x for x in a)
    for cname in sorted(ca['contracts']):
        c = ca['contracts'][cname]
        if not isinstance(c, dict) or not {'root', 'checks'} <= set(c) or set(c) - {'root', 'checks', 'when_present'} \
                or not isinstance(c['root'], str) or not c['root'] or not isinstance(c['checks'], list) or not c['checks'] \
                or ('when_present' in c and (not isinstance(c['when_present'], str) or not c['when_present'])):
            raise ValueError('lme: registry contract_admission.contracts.%s must be {root, checks[, when_present]}; got %r' % (cname, c))
        for i, chk in enumerate(c['checks']):
            locs = [k for k in ('path', 'at') if isinstance(chk, dict) and k in chk]
            kinds = [k for k in chk if k in _RH_CA_KINDS] if isinstance(chk, dict) else []
            mods = [k for k in chk if k in _RH_CA_MODS] if isinstance(chk, dict) else []
            if not isinstance(chk, dict) or len(locs) != 1 or not isinstance(chk[locs[0]], str) \
                    or (locs[0] == 'at' and not chk['at']) or len(kinds) != 1 or set(chk) - set(locs) - set(kinds) - set(mods):
                raise ValueError('lme: registry contract_admission.contracts.%s.checks[%d] must carry exactly one of path/at, exactly one check kind of %s and only the modifiers %s; got %r' % (
                    cname, i, sorted(_RH_CA_KINDS), sorted(_RH_CA_MODS), chk))
            kind, arg = kinds[0], chk[kinds[0]]
            ok = {'keys': strs(arg), 'has_keys': strs(arg), 'within': strs(arg), 'ere_compose': strs(arg),
                  'enum': isinstance(arg, list) and bool(arg),
                  'pattern': isinstance(arg, str) and arg in pats, 'key_pattern': isinstance(arg, str) and arg in pats,
                  'positive_int': arg is True,
                  'strings': isinstance(arg, dict) and not set(arg) - {'nonempty', 'distinct'} and all(isinstance(x, bool) for x in arg.values()),
                  'ere': arg in ('fragment', 'anchored'),
                  'umask_yields': isinstance(arg, str) and bool(arg),
                  'not_in': strs(arg) and all(isinstance(schema.get(n), list) for n in arg)}[kind]
            for m in mods:
                ok = ok and kind in _RH_CA_MODS[m] and (
                    isinstance(chk[m], dict) and set(chk[m]) == {'field', 'contains'} and all(isinstance(x, str) and x for x in chk[m].values())
                    if m == 'having' else isinstance(chk[m], bool))
            if not ok:
                raise ValueError('lme: registry contract_admission.contracts.%s.checks[%d] %s argument/modifiers are malformed; got %r' % (cname, i, kind, chk))
    return pats, ca['contracts']


def _rh_ca_check(kind, arg, s, chk, pol, pats, schema, root):
    """One admission check of subject s; None when admitted, else the reason."""
    if kind in ('keys', 'has_keys'):
        if not isinstance(s, dict):
            return 'must be a mapping'
        miss, extra = sorted(set(arg) - set(s)), sorted(set(s) - set(arg))
        if miss or (kind == 'keys' and extra):
            return 'key set must be %s %s (missing %s%s)' % ('exactly' if kind == 'keys' else 'at least', sorted(arg), miss,
                                                             ', undeclared %s' % (extra,) if kind == 'keys' else '')
        return None
    if kind == 'enum':
        return None if any(_rh_ca_same(s, e) for e in arg) else 'must be one of %r' % (arg,)
    if kind == 'pattern':
        return None if isinstance(s, str) and pats[arg].fullmatch(s) else 'must fully match patterns.%s %r' % (arg, pats[arg].pattern)
    if kind == 'key_pattern':
        if not isinstance(s, dict):
            return 'must be a mapping'
        bad = sorted(str(k) for k in s if not isinstance(k, str) or not pats[arg].fullmatch(k))
        return 'keys %s must fully match patterns.%s %r' % (bad, arg, pats[arg].pattern) if bad else None
    if kind == 'positive_int':
        return None if _rh_int(s) and s >= 1 else 'must be an integer >= 1'
    if kind == 'strings':
        if not isinstance(s, list) or any(not isinstance(x, str) for x in s):
            return 'must be a list of strings'
        if arg.get('nonempty') and not s:
            return 'must be non-empty'
        if arg.get('distinct') and len(set(s)) != len(s):
            return 'must hold distinct entries'
        return None
    if kind == 'within':
        allowed, hv = [], chk.get('having')
        for ref in arg:
            nodes = _rh_expand(pol, ref)
            if not nodes:
                return 'references %s, which the policy does not declare (missing dependency)' % (ref,)
            for _p, node in nodes:
                if isinstance(node, dict):
                    allowed.extend(k for k in node if hv is None or (
                        isinstance(node[k], dict) and isinstance(node[k].get(hv['field']), list) and hv['contains'] in node[k][hv['field']]))
                elif isinstance(node, list):
                    allowed.extend(node)
                else:
                    allowed.append(node)
        miss = [m for m in _rh_ca_members(s) if isinstance(m, (dict, list)) or not any(_rh_ca_same(m, a) for a in allowed)]
        return 'names %r outside %s%s (missing dependency)' % (miss, arg, ' with %s containing %r' % (hv['field'], hv['contains']) if hv else '') if miss else None
    if kind == 'ere':
        return _rh_ca_ere(s, arg, chk.get('sed_delimited', False))
    if kind == 'ere_compose':
        parts = [_rh_get(s, p) if isinstance(s, dict) else (False, None) for p in arg]
        if any(not f or not isinstance(v, str) for f, v in parts):
            return 'must declare %s as strings' % (arg,)
        try:
            re.compile('^' + ''.join(v for _f, v in parts) + '$')
        except re.error as e:
            return 'the composed ^%s$ does not compile: %s' % ('+'.join(arg), e)
        return None
    if kind == 'umask_yields':
        fm, mode = _rh_get(pol, root + '.' + arg)
        octal = re.compile('^0?[0-7]{3}$')
        if not (isinstance(s, str) and octal.match(s) and fm and isinstance(mode, str) and octal.match(mode)):
            return 'and %s must both be octal modes' % (arg,)
        return None if (0o666 & ~int(s, 8)) == int(mode, 8) else '0666 & ~%s = %04o, not the declared %s %s' % (s, 0o666 & ~int(s, 8), arg, mode)
    if kind == 'not_in':
        hit = [n for n in arg if s in schema[n]]
        return 'is a registry %s name (a route/loader OUTPUT, never an external input)' % (hit,) if hit else None
    return 'unknown check kind'


def _rh_admit_contracts(pol, schema, key):
    """C1-BOOTSTRAP-CONTRACT-VALUE-ADMISSION: shape, enum and reference admission of every registry-declared
    controller.bootstrap contract on the COMPOSED policy, at resolve, before any mutation. Raises on the first
    refusal (named by the policy path, the contract and the check kind)."""
    pats, contracts = _rh_ca_registry(schema.get('contract_admission'), schema)
    for cname in sorted(contracts):
        c = contracts[cname]
        if 'when_present' in c and not _rh_get(pol, c['when_present'])[0]:
            continue
        fr, rv = _rh_get(pol, c['root'])
        if not fr or not isinstance(rv, dict):
            raise ValueError('lme: %s.%s must be a declared mapping (contract_admission.%s); got %r' % (key, c['root'], cname, rv if fr else '<absent>'))
        for chk in c['checks']:
            kind = [k for k in chk if k in _RH_CA_KINDS][0]
            dotted = chk['at'] if 'at' in chk else '.'.join(p for p in (c['root'], chk['path']) if p)
            found, v = _rh_get(pol, dotted)
            why = 'is not declared' if not found else None
            if why is None:
                subjects = (list(v.values()) if isinstance(v, dict) else v if isinstance(v, list) else None) if chk.get('each') else [v]
                if subjects is None:
                    why = 'must be a list or mapping (each)'
                for sub in subjects or []:
                    why = why or _rh_ca_check(kind, chk[kind], sub, chk, pol, pats, schema, c['root'])
            if why:
                raise ValueError('lme: %s.%s fails contract_admission.%s (%s): %s; got %r' % (key, dotted, cname, kind, why, v))


def _rh_validate(composed, declared, override, schema):
    key = schema['policy_key']
    ov = (override or {}).get(key) if isinstance(override, dict) else None
    if not isinstance(declared, dict) or key not in declared:
        if ov is not None:
            raise ValueError('lme: lme_global_override.%s supplied but no %s policy is declared (global/profile)' % (key, key))
        return None, []
    decl, pol = declared[key], (composed or {}).get(key)
    if not isinstance(decl, dict) or not isinstance(pol, dict):
        raise ValueError('lme: %s must be a mapping (declared %s, composed %s)' % (key, _rh_kind(decl), _rh_kind(pol)))
    ver = pol.get('schema_version')
    if not _rh_int(ver) or ver != schema['policy_schema_version']:
        raise ValueError('lme: %s.schema_version %r != %r' % (key, ver, schema['policy_schema_version']))
    for retired in schema['retired_policy_paths']:
        if _rh_get(pol, retired)[0]:
            raise ValueError('lme: %s.%s is retired (registry remote_harness_schema owns it); remove it from the declaration' % (key, retired))
    # -- override: deny-by-default tunable paths, declared-leaf types, path+identity together --
    tunables = [t.split('.') for t in schema['tunable_paths']]
    overridden = []
    if ov is not None:
        if not isinstance(ov, dict):
            raise ValueError('lme: lme_global_override.%s must be a mapping, got %s' % (key, _rh_kind(ov)))
        for path, val in _rh_leaves(ov, []):
            dotted = '.'.join(path)
            if not any(_rh_prefix(path, t) for t in tunables):
                raise ValueError('lme: lme_global_override.%s.%s is not a tunable path (registry remote_harness_schema.tunable_paths %s); the declared value is pinned' % (key, dotted, schema['tunable_paths']))
            found, dval = _rh_get(decl, dotted)
            if found and _rh_kind(dval) != _rh_kind(val):
                raise ValueError('lme: lme_global_override.%s.%s is %s; the declared leaf is %s' % (key, dotted, _rh_kind(val), _rh_kind(dval)))
            if not found and not any(_rh_prefix(path, e.split('.')) for e in schema['extensible_paths']):
                raise ValueError('lme: lme_global_override.%s.%s names no declared leaf (only %s accept new keys); an override may only retune a declaration' % (key, dotted, schema['extensible_paths']))
            overridden.append(dotted)
        for pattern, sibling in sorted(schema['path_requires'].items()):
            pat = pattern.split('.')
            for path, _v in _rh_leaves(ov, []):
                if len(path) == len(pat) and _rh_prefix(path, pat):
                    if not _rh_get(ov, '.'.join(path[:-1] + [sibling]))[0]:
                        raise ValueError('lme: lme_global_override.%s.%s changes an executable location without its %s; selecting an admitted executable elsewhere requires its declared identity in the same override' % (key, '.'.join(path), sibling))
        # C1-EXPLICIT-IDENTITY-OVERRIDE (codex 022716): an override that touches an executable identity must carry
        # the COMPLETE identity itself ({kind, <value_field>} of a declared kind). A partial one ({} or only kind)
        # would inherit the declared digest through the recursive merge and pass the merged-identity check below.
        ei0 = schema['executable_identity']
        fo, ov_entries = _rh_get(ov, ei0['entries'])
        if fo and isinstance(ov_entries, dict):
            for tool in sorted(ov_entries):
                if not isinstance(ov_entries[tool], dict) or ei0['field'] not in ov_entries[tool]:
                    continue
                oid = ov_entries[tool][ei0['field']]
                okind = oid.get('kind') if isinstance(oid, dict) else None
                ospec = ei0['kinds'].get(okind) if isinstance(okind, str) else None
                oval = oid.get(ospec['value_field']) if ospec else None
                if ospec is None or set(oid) != {'kind', ospec['value_field']} or not isinstance(oval, str) \
                        or not re.match(ospec['value_pattern'], oval):
                    raise ValueError('lme: lme_global_override.%s.%s.%s.%s must be a COMPLETE identity {kind: <one of %s>, <value>} in the override itself; got %r (a partial identity would inherit the declared digest)' % (key, ei0['entries'], tool, ei0['field'], sorted(ei0['kinds']), oid))
    # -- composed-policy checks (declaration AND override) --
    for pattern in schema['path_leaves']:
        for path, v in _rh_expand(pol, pattern):
            segs = v.split('/')[1:] if isinstance(v, str) else []
            if not isinstance(v, str) or not v.startswith('/') or v == '/' or any(x in ('', '.', '..') for x in segs):
                raise ValueError('lme: %s.%s %r must be an absolute normalized path' % (key, '.'.join(path), v))
    ei = schema['executable_identity']
    fe, entries = _rh_get(pol, ei['entries'])
    if not fe or not isinstance(entries, dict):
        raise ValueError('lme: %s.%s must be a mapping of executables' % (key, ei['entries']))
    for tool in sorted(entries):
        ident = (entries[tool] or {}).get(ei['field']) if isinstance(entries[tool], dict) else None
        kind = ident.get('kind') if isinstance(ident, dict) else None
        spec = ei['kinds'].get(kind) if isinstance(kind, str) else None
        val = ident.get(spec['value_field']) if spec else None
        if spec is None or not isinstance(val, str) or not re.match(spec['value_pattern'], val) \
                or set(ident) != {'kind', spec['value_field']}:
            raise ValueError('lme: %s.%s.%s.%s must be {kind: <one of %s>, <value>} (executable identity); got %r' % (key, ei['entries'], tool, ei['field'], sorted(ei['kinds']), ident))
    # C1-BOOTSTRAP-CONTRACT-VALUE-ADMISSION (codex 191117): the registry-declared bootstrap contracts and their
    # references (executables, env names, sub_roots keys, ERE/format fields) on the composed policy, before any mutation.
    _rh_admit_contracts(pol, schema, key)
    for dotted in schema['positive_int_paths']:
        f, v = _rh_get(pol, dotted)
        if not f or not _rh_int(v) or v < 1:
            raise ValueError('lme: %s.%s %r must be an integer >= 1' % (key, dotted, v))
    for bnd in schema['bounds']:
        (fv, v), (fm, m) = _rh_get(pol, bnd['path']), _rh_get(pol, bnd['max'])
        if not (fv and fm and _rh_int(v) and _rh_int(m)) or v > m * bnd['scale']:
            raise ValueError('lme: %s.%s %r exceeds %s.%s %r x %r' % (key, bnd['path'], v, key, bnd['max'], m, bnd['scale']))
    pm = schema['package_mapping']
    ff, fams = _rh_get(pol, pm['families'])
    fr, req = _rh_get(pol, pm['required'])
    if not ff or not isinstance(fams, dict) or not fams or any(not isinstance(m, dict) for m in fams.values()):
        raise ValueError('lme: %s.%s must map each os family to a package mapping' % (key, pm['families']))
    def _pkg_check(names, where):
        if not isinstance(names, list):
            raise ValueError('lme: %s.%s must be a list' % (key, where))
        for fam in sorted(fams):
            miss = sorted(n for n in names if n not in fams[fam])
            if miss:
                raise ValueError('lme: %s.%s names %s with no %s.%s.%s mapping' % (key, where, miss, key, pm['families'], fam))
    _pkg_check(req if fr else None, pm['required'])
    ad = schema['adapter']
    (fs, sel), (fm, members) = _rh_get(pol, ad['selector']), _rh_get(pol, ad['members'])
    if not fs or not isinstance(sel, str) or not fm or not isinstance(members, dict) or sel not in members:
        raise ValueError('lme: %s.%s %r must name a key of the composed %s.%s %s' % (key, ad['selector'], sel, key, ad['members'], sorted(members) if isinstance(members, dict) else members))
    adecl = members[sel]
    if not isinstance(adecl, dict) or adecl.get(ad['status_field']) in ad['refused_statuses']:
        raise ValueError('lme: %s.%s %r is %s (%s)' % (key, ad['selector'], sel, (adecl or {}).get(ad['status_field']) if isinstance(adecl, dict) else adecl, ad['refused_statuses']))
    for tl in ad['tool_lists']:
        f, tools = _rh_get(adecl, tl)
        if f:
            if not isinstance(tools, list) or any(t not in entries for t in tools):
                raise ValueError('lme: %s adapter %s.%s %r names executables outside %s.%s' % (key, sel, tl, tools, key, ei['entries']))
    for pl in ad['package_lists']:
        f, pk = _rh_get(adecl, pl)
        if f:
            _pkg_check(pk, '%s.%s.%s' % (ad['members'], sel, pl))
    # CANONICAL-TOOL-OVERRIDES (codex-tick144): an adapter's executables are NAMED here (keys of
    # executable_identity.entries) and never re-declared; their location and identity DERIVE from the same
    # effective entries, so one admitted override reaches every consumer. A declared copy is refused.
    derived = {}
    for tm in ad['tool_maps']:
        f, tmap = _rh_get(adecl, tm)
        if not f:
            continue
        if not isinstance(tmap, dict) or any(not isinstance(v, dict) for v in tmap.values()):
            raise ValueError('lme: %s adapter %s.%s must map executable names to mappings' % (key, sel, tm))
        outside = sorted(t for t in tmap if t not in entries)
        if outside:
            raise ValueError('lme: %s adapter %s.%s names executables outside %s.%s: %s (missing dependency)' % (key, sel, tm, key, ei['entries'], outside))
        for t in sorted(tmap):
            dup = sorted(k for k in tmap[t] if k in ad['derived_tool_fields'])
            if dup:
                raise ValueError('lme: %s adapter %s.%s.%s declares %s; these DERIVE from %s.%s.%s (one source; a copy would diverge from an admitted override)' % (key, sel, tm, t, dup, key, ei['entries'], t))
        derived[tm] = {t: dict(tmap[t], **{k: entries[t][k] for k in ad['derived_tool_fields']}) for t in sorted(tmap)}
    fi, inv = _rh_get(pol, schema['inventory_var_path'])
    for name, want in sorted(schema['inventory_vars'].items()):
        got = inv.get(name) if fi and isinstance(inv, dict) else None
        if got != want:
            raise ValueError('lme: %s.%s.%s is %r; the registry declares %r' % (key, schema['inventory_var_path'], name, got, want))
    # PER-HOST-SCOPE-CONTRACT (codex 023332): the registry rule host_scope names the leaves that may differ between
    # scopes of one deployment (every scoped field of every executable), derived from the declaration, never listed.
    # C1-ARTIFACT-REUSE-INPUT-COVERAGE (codex 035141): the reuse key digests EVERY input the declared shared
    # artifacts' templates consume (_rh_shared_inputs), not selected executable paths.
    hs = schema['host_scope']
    if hs['tool_map'] != ei['entries']:
        raise ValueError('lme: registry host_scope.tool_map %r must be executable_identity.entries %r' % (hs['tool_map'], ei['entries']))
    scoped = []
    for t in sorted(entries):
        req = entries[t].get(hs['consumer_field'])
        if '.' in t or not isinstance(req, list) or not req or any(not isinstance(r, str) for r in req):
            raise ValueError('lme: %s.%s.%s.%s must be a non-empty list of consumer names (host scope derives from it); got %r' % (key, ei['entries'], t, hs['consumer_field'], req))
        scoped.extend('%s.%s.%s' % (ei['entries'], t, fld) for fld in hs['scoped_fields'] if fld in entries[t])
    shared_inputs = _rh_shared_inputs(pol, hs, scoped, key)
    section = {'schema_version': schema['projection_schema_version'], 'policy': pol, 'policy_sha256': _digest(pol),
               'adapter': {'name': sel, 'tools': derived},
               'host_scoped_paths': scoped,
               'scope_invariant_sha256': _digest({'policy': _rh_without(pol, scoped), 'host_scoped_paths': scoped}),
               'shared_artifact_inputs_sha256': _digest(shared_inputs)}
    return section, sorted(overridden)


_RH_ARTIFACT_KEYS = frozenset(('templates', 'inputs', 'checkout_inputs', 'consumers', 'not_embedded_fields'))


def _rh_artifact_decl(hs):
    """The registry declaration host_scope.shared_artifacts, shape-checked (fail-closed)."""
    arts = hs.get('shared_artifacts')
    if not isinstance(arts, dict) or not arts:
        raise ValueError('lme: registry host_scope.shared_artifacts must declare every shared rendered artifact; got %r' % (arts,))
    for a in sorted(arts):
        d = arts[a]
        if not isinstance(d, dict) or set(d) != _RH_ARTIFACT_KEYS:
            raise ValueError('lme: registry host_scope.shared_artifacts.%s must carry exactly %s' % (a, sorted(_RH_ARTIFACT_KEYS)))
        tpl, ins, cins, cons, ne = (d[k] for k in ('templates', 'inputs', 'checkout_inputs', 'consumers', 'not_embedded_fields'))
        if not isinstance(tpl, list) or not tpl or len(set(tpl)) != len(tpl) or any(
                not isinstance(p, str) or not p or p.startswith('/') or '..' in p.split('/') for p in tpl):
            raise ValueError('lme: shared_artifacts.%s.templates must be distinct repository-relative paths, entry first; got %r' % (a, tpl))
        for n, m in (('inputs', ins), ('checkout_inputs', cins)):
            if not isinstance(m, dict) or any(not isinstance(k, str) or not isinstance(v, str) or not v for k, v in m.items()):
                raise ValueError('lme: shared_artifacts.%s.%s must map template variables to policy paths; got %r' % (a, n, m))
        if not ins or set(ins) & set(cins):
            raise ValueError('lme: shared_artifacts.%s.inputs must be non-empty and disjoint from checkout_inputs' % (a,))
        if not isinstance(cons, list) or not cons or any(not isinstance(c, str) for c in cons):
            raise ValueError('lme: shared_artifacts.%s.consumers must be a non-empty list of consumer names; got %r' % (a, cons))
        if not isinstance(ne, list) or any(f not in hs['scoped_fields'] for f in ne):
            raise ValueError('lme: shared_artifacts.%s.not_embedded_fields must name scoped_fields %r only; got %r' % (a, hs['scoped_fields'], ne))
    return arts


def _rh_shared_inputs(pol, hs, scoped, key):
    """C1-ARTIFACT-REUSE-INPUT-COVERAGE (codex 035141). {artifact: {template variable: the policy subtree it
    receives}} for every declared shared artifact, minus the host-scoped leaves whose field the templates never read
    (not_embedded_fields; proved against the templates by _rh_prove_artifact_templates). Every declared input path
    must exist, and every executable a declared consumer runs must reach the templates through an input (a
    consumed input missing from the declaration refuses). Value-pure; derived from the declaration only."""
    tm = hs['tool_map']
    _, entries = _rh_get(pol, tm)
    out = {}
    for a, d in sorted(_rh_artifact_decl(hs).items()):
        stripped = _rh_without(pol, [p for p in scoped if p.rsplit('.', 1)[1] in d['not_embedded_fields']])
        vals = {}
        for var, path in sorted(d['inputs'].items()):
            f, v = _rh_get(stripped, path)
            if not f:
                raise ValueError('lme: shared artifact %s input %s names %s.%s, which the policy does not declare' % (a, var, key, path))
            vals[var] = v
        for var, path in sorted(d['checkout_inputs'].items()):
            if not _rh_get(pol, path)[0]:
                raise ValueError('lme: shared artifact %s checkout input %s names %s.%s, which the policy does not declare' % (a, var, key, path))
        for t in sorted(entries if isinstance(entries, dict) else {}):
            if not set(entries[t].get(hs['consumer_field']) or []) & set(d['consumers']):
                continue
            for fld in hs['scoped_fields']:
                leaf = '%s.%s.%s' % (tm, t, fld)
                if fld in entries[t] and fld not in d['not_embedded_fields'] and not any(
                        leaf == p or leaf.startswith(p + '.') for p in d['inputs'].values()):
                    raise ValueError('lme: shared artifact %s runs %s but no declared input covers %s.%s (a consumed input missing from the declaration)' % (a, t, key, leaf))
        out[a] = vals
    return out


def _rh_prove_artifact_templates(hs, sources):
    """C1-ARTIFACT-REUSE-INPUT-COVERAGE: prove the shared_artifacts declaration against the ACTUAL template sources
    (the loader reads them; artifact_sources = {repository-relative path: content}). The entry template's free
    variables must EQUAL inputs + checkout_inputs (anything else it consumes is missing from the declaration); it
    and every other template import only declared templates, never with context, and never include/extend (a
    context-carrying load could read undeclared variables); non-entry templates have no free variables; a
    not_embedded field name is never an attribute, item or string constant of any template. Raises otherwise."""
    import jinja2
    from jinja2 import meta, nodes
    arts = _rh_artifact_decl(hs)
    want = sorted(set(p for d in arts.values() for p in d['templates']))
    if not isinstance(sources, dict) or sorted(sources) != want or any(not isinstance(v, str) for v in sources.values()):
        raise ValueError('lme: remote-harness scope artifact_sources must carry exactly the declared templates %r; got %r' % (
            want, sorted(sources) if isinstance(sources, dict) else sources))
    env = jinja2.Environment(extensions=['jinja2.ext.do', 'jinja2.ext.loopcontrols'])
    for a, d in sorted(arts.items()):
        base = d['templates'][0].rsplit('/', 1)[0] if '/' in d['templates'][0] else ''
        for i, path in enumerate(d['templates']):
            try:
                ast = env.parse(sources[path])
            except jinja2.TemplateSyntaxError as e:
                raise ValueError('lme: shared artifact %s template %s does not parse: %s' % (a, path, e))
            free = set(meta.find_undeclared_variables(ast))
            declared = set(d['inputs']) | set(d['checkout_inputs'])
            if i == 0 and free != declared:
                raise ValueError('lme: shared artifact %s entry template %s consumes %s; the declaration names %s (undeclared: %s; unconsumed: %s)' % (
                    a, path, sorted(free), sorted(declared), sorted(free - declared), sorted(declared - free)))
            if i > 0 and free:
                raise ValueError('lme: shared artifact %s template %s reads variables %s outside its macro parameters' % (a, path, sorted(free)))
            if list(ast.find_all((nodes.Include, nodes.Extends))):
                raise ValueError('lme: shared artifact %s template %s includes/extends (context-carrying; undeclared inputs)' % (a, path))
            for imp in ast.find_all((nodes.Import, nodes.FromImport)):
                tgt = imp.template.value if isinstance(imp.template, nodes.Const) else None
                if imp.with_context or not isinstance(tgt, str) or ((base + '/' if base else '') + tgt) not in d['templates']:
                    raise ValueError('lme: shared artifact %s template %s imports %r (only declared templates, without context)' % (a, path, tgt))
            names = set(n.attr for n in ast.find_all(nodes.Getattr)) | set(
                n.value for n in ast.find_all(nodes.Const) if isinstance(n.value, str))
            hit = sorted(set(d['not_embedded_fields']) & names)
            if hit:
                raise ValueError('lme: shared artifact %s template %s reads %s, declared not_embedded (the reuse key would omit an embedded input)' % (a, path, hit))
    return True


_RH_ENDPOINT_KEY = ('address', 'port', 'proxy_jump', 'owner')
_RH_FORM_TESTS = frozenset(('undefined', 'equals_empty', 'equals_mode_args', 'match_form_regex'))


def _rh_endpoint_vars(pol, hs, key):
    """C1-EFFECTIVE-ENDPOINT-BINDING (codex 035141): the ONE declared connection rule (registry host_scope.endpoint
    names where it lives in the policy: rule_path = ssh_auth.composition {address, port, proxy_jump}, owner_var_path =
    inventory.owner_var, owner_rule_path = inventory.owner {var, absent}) -- the same rule the route's endpoint key
    and B consume. Returns the inventory variable name per endpoint role and the rule (with the declared owner rule
    as 'owner_rule'); refuses a rule this resolver cannot apply exactly as declared."""
    ep = hs.get('endpoint')
    if not isinstance(ep, dict) or set(ep) != {'rule_path', 'owner_var_path', 'owner_rule_path', 'auth_path'}:
        raise ValueError('lme: registry host_scope.endpoint must be {rule_path, owner_var_path, owner_rule_path, auth_path}; got %r' % (ep,))
    f, rule = _rh_get(pol, ep['rule_path'])
    fo, owner_var = _rh_get(pol, ep['owner_var_path'])
    fr, owner_rule = _rh_get(pol, ep['owner_rule_path'])
    fa, auth = _rh_get(pol, ep['auth_path'])
    if not f or not isinstance(rule, dict) or any(not isinstance(rule.get(r), dict) or not isinstance(rule[r].get('var'), str) or not rule[r]['var']
                                                  for r in ('address', 'port', 'proxy_jump', 'inventory_forms')):
        raise ValueError('lme: %s.%s must declare address, port, proxy_jump and inventory_forms, each with its inventory var (the endpoint rule)' % (key, ep['rule_path']))
    if rule.get('endpoint_key') != list(_RH_ENDPOINT_KEY):
        raise ValueError('lme: %s.%s.endpoint_key must be %r (the components this resolver binds); got %r' % (key, ep['rule_path'], list(_RH_ENDPOINT_KEY), rule.get('endpoint_key')))
    if not fo or not isinstance(owner_var, str) or not owner_var:
        raise ValueError('lme: %s.%s must name the owner inventory variable' % (key, ep['owner_var_path']))
    # OWNER-ABSENT RULE (route r3h): the owner component's absent value is DECLARED by the policy, never a resolver
    # default. One rule, one place: owner.var must be the same variable owner_var names.
    if not fr or not isinstance(owner_rule, dict) or set(owner_rule) != {'var', 'absent'} \
            or not isinstance(owner_rule['var'], str) or not owner_rule['var'] or not isinstance(owner_rule['absent'], str):
        raise ValueError('lme: %s.%s must be the owner rule {var: <non-empty string>, absent: <string>}; got %r' % (
            key, ep['owner_rule_path'], owner_rule if fr else '<absent>'))
    if owner_rule['var'] != owner_var:
        raise ValueError('lme: %s.%s.var %r must equal %s %r (one owner rule, one place)' % (
            key, ep['owner_rule_path'], owner_rule['var'], ep['owner_var_path'], owner_var))
    if not fa or not isinstance(auth, dict) or not isinstance(auth.get('mode_var'), str) or not auth['mode_var'] \
            or not isinstance(auth.get('modes'), dict) or any(not isinstance(m, dict) or not isinstance(m.get('ssh_common_args'), str) for m in auth['modes'].values()):
        raise ValueError('lme: %s.%s must declare mode_var and modes, each mode with its ssh_common_args' % (key, ep['auth_path']))
    fm = rule['inventory_forms']
    acc = fm.get('accepted')
    if fm.get('other') != 'refuse' or not isinstance(acc, list) or not acc or any(
            not isinstance(a, dict) or set(a) != {'form', 'test', 'proxy_jump'} or a['test'] not in _RH_FORM_TESTS
            or a['proxy_jump'] not in ('', 'form_regex_capture_1')
            or (a['proxy_jump'] == 'form_regex_capture_1') != (a['test'] == 'match_form_regex') for a in acc):
        raise ValueError('lme: %s.%s.inventory_forms must be {var, accepted: [{form, test in %s, proxy_jump in [\'\', form_regex_capture_1]}], other: refuse}; got %r' % (
            key, ep['rule_path'], sorted(_RH_FORM_TESTS), fm))
    if fm['var'] != rule['proxy_jump']['var']:
        raise ValueError('lme: %s.%s.inventory_forms.var must be the proxy_jump var %r' % (key, ep['rule_path'], rule['proxy_jump']['var']))
    ad, pt, pj = rule['address'], rule['port'], rule['proxy_jump']
    if ad.get('absent') != 'inventory_hostname' or ad.get('normalize') != 'lower':
        raise ValueError('lme: %s.%s.address must be {var, absent: inventory_hostname, normalize: lower}; got %r' % (key, ep['rule_path'], ad))
    if pt.get('absent') != 'delegate_ssh_config' or not isinstance(pt.get('absent_key'), str) or not pt['absent_key'] \
            or not isinstance(pt.get('explicit_regex'), str) or isinstance(pt.get('explicit_max'), bool) or not isinstance(pt.get('explicit_max'), int):
        raise ValueError('lme: %s.%s.port must be {var, absent: delegate_ssh_config, absent_key, explicit_regex, explicit_max}; got %r' % (key, ep['rule_path'], pt))
    if not isinstance(pj.get('form_regex'), str) or re.compile(pj['form_regex']).groups != 1:
        raise ValueError('lme: %s.%s.proxy_jump.form_regex must capture exactly the jump; got %r' % (key, ep['rule_path'], pj.get('form_regex')))
    return ({'address': ad['var'], 'port': pt['var'], 'proxy_jump': fm['var'], 'owner': owner_var, 'mode': auth['mode_var']},
            dict(rule, modes=auth['modes'], owner_rule=owner_rule))


def _rh_endpoint(raw, rule, host, key):
    """One target's effective declared endpoint in the route's key order [address, port_key, proxy_jump, owner]:
    address = the address var, absent -> the inventory id, lower-cased; port_key = an explicit port as its canonical
    decimal (explicit_regex, <= explicit_max; bool/float/null refuse), absent -> absent_key (DELEGATED to the owner's
    ssh configuration, never a guessed number); proxy_jump = per the declared inventory_forms (see below); owner =
    the owner var, absent -> the DECLARED owner rule's absent value (inventory.owner.absent, validated by
    _rh_endpoint_vars; not a resolver default). A value the declared rule refuses is refused here too (same rule, one
    place). C1-ENDPOINT-EXPLICIT-NULL (codex 063540): a role is ABSENT only when its key is missing from raw (see
    lme_rh_connection_values); the absent rules above apply to absence only. A SUPPLIED null is a value, and no
    declared field rule accepts it: address (non-empty string), port (explicit_regex decimal), common args (no
    accepted inventory form holds for null) and owner (string) each refuse it."""
    if 'address' in raw:
        a = raw['address']
        if not isinstance(a, str) or not a:
            raise ValueError('lme: %s endpoint of %r: address %s was supplied as %r (%s); a supplied address must be a non-empty string (only an ABSENT address falls back to the inventory id)' % (
                key, host, rule['address']['var'], a, type(a).__name__))
    else:
        a = host
    pt = rule['port']
    if 'port' not in raw:
        pk = pt['absent_key']
    elif raw['port'] is None:
        raise ValueError('lme: %s endpoint of %r: port %s was supplied as null; a supplied port must be an explicit port by the declared rule (%s, <= %d) -- only an ABSENT port delegates to ssh_config' % (
            key, host, pt['var'], pt['explicit_regex'], pt['explicit_max']))
    else:
        p = raw['port']
        s = str(p) if (isinstance(p, int) and not isinstance(p, bool)) or isinstance(p, str) else None
        if s is None or not re.match(pt['explicit_regex'] + r'\Z', s) or int(s) > pt['explicit_max']:
            raise ValueError('lme: %s endpoint of %r: port %r (%s) is not an explicit port by the declared rule (%s, <= %d)' % (
                key, host, p, type(p).__name__, pt['explicit_regex'], pt['explicit_max']))
        pk = s
    # The route value: the FIRST declared accepted inventory form (composition.inventory_forms, in order) whose test
    # holds; equals_mode_args compares with the HOST's declared mode (mode_var) args -- admission (admit_transport.yml)
    # requires that mode to equal the run's selected mode, so under admission they are the same args. No accepted
    # form -> refuse (other: refuse). An absent or unknown host mode matches no equals_mode_args form.
    # The `undefined` test holds for an ABSENT var only; a supplied null matches no accepted form and refuses.
    jp = 'proxy_jump' in raw
    j = raw.get('proxy_jump')
    mode = rule['modes'].get(raw.get('mode')) if isinstance(raw.get('mode'), str) else None
    jump = None
    for form in rule['inventory_forms']['accepted']:
        t = form['test']
        m = re.match(rule['proxy_jump']['form_regex'] + r'\Z', j) if t == 'match_form_regex' and isinstance(j, str) else None
        if (t == 'undefined' and not jp) or (t == 'equals_empty' and j == '') \
                or (t == 'equals_mode_args' and mode is not None and isinstance(j, str) and j == mode['ssh_common_args']) or m:
            jump = m.group(1) if form['proxy_jump'] == 'form_regex_capture_1' else ''
            break
    if jump is None:
        raise ValueError('lme: %s endpoint of %r: %s %r is none of the declared accepted inventory forms %r (host mode %r)' % (
            key, host, rule['inventory_forms']['var'], j if jp else '<absent>', [f['form'] for f in rule['inventory_forms']['accepted']], raw.get('mode')))
    # Owner: ABSENT -> the declared owner rule's absent value (a separate, declared policy); a SUPPLIED value (null
    # included) must be a string.
    o = raw['owner'] if 'owner' in raw else rule['owner_rule']['absent']
    if not isinstance(o, str):
        raise ValueError('lme: %s endpoint of %r: a supplied owner must be a string; got %r (%s)' % (key, host, o, type(o).__name__))
    comp = {'address': a.lower(), 'port': pk, 'proxy_jump': jump, 'owner': o}
    return [comp[c] for c in rule['endpoint_key']]


def lme_rh_connection_values(hostvars, ids, composed, schema):
    """C1-EFFECTIVE-ENDPOINT-BINDING: a SELECTION (no derivation) of the inventory values the declared endpoint rule
    names, for each host id: {vars: {role: var name}, values: {id: {role: value}}}; {} when no remote-harness
    policy is declared. The scope projection derives each target's endpoint from them (_rh_endpoint).
    C1-ENDPOINT-EXPLICIT-NULL (codex 063540): PRESENCE is kept separate from the value -- a role whose var the host
    does not define is OMITTED from values[id]; a defined var is carried as supplied, a null included, so a supplied
    null never shares the binding of an absent input."""
    key = schema['policy_key']
    pol = composed.get(key) if isinstance(composed, dict) else None
    if not isinstance(pol, dict):
        return {}
    names = _rh_endpoint_vars(pol, schema['host_scope'], key)[0]
    values = {}
    for h in ids:
        hv = hostvars[h]
        values[h] = dict((role, hv[v]) for role, v in sorted(names.items()) if v in hv)
    return {'vars': names, 'values': values}


def _rh_without(tree, dotted_paths):
    """A copy of tree with the named leaves removed (value-pure; the input is not mutated)."""
    drop = [p.split('.') for p in dotted_paths]

    def walk(node, at):
        if not isinstance(node, dict):
            return node
        return {k: walk(v, at + [k]) for k, v in node.items() if (at + [k]) not in drop}
    return walk(tree, [])


_RH_SCOPE_ENTRY = ('policy', 'policy_sha256', 'adapter', 'host_scoped_paths', 'scope_invariant_sha256',
                   'shared_artifact_inputs_sha256')


def _rh_scoped(section, composed, declared, override, schema, scope):
    """PER-HOST-SCOPE-CONTRACT (codex-r3f-scope-binding-and-join-023332). Every host resolves the FULL intended
    policy of EVERY scope of the deployment -- the controller (registry host_scope.controller_id) and each member
    of the policy's declared target group -- each composed by the loader's ONE composition (global | profile |
    that scope's own lme_global_override; the caller composes, this function never merges) and validated by the
    same projection. Each scope carries its identity and scope_sha256 = digest(scope, binding, policy_sha256),
    binding = the deployment (profile, controller, target group, members), the source edition (global/profile
    bytes) and the operation. scope_invariant_sha256 is an ADDITIONAL compatibility digest only; exact identity
    is scope_sha256 / policy_sha256 of the scope a consumer serves."""
    hs, key = schema['host_scope'], schema['policy_key']
    need = ('self', 'groups', 'composed', 'overrides', 'edition', 'artifact_sources', 'connections')
    if not isinstance(scope, dict) or any(k not in scope for k in need):
        raise ValueError('lme: remote-harness scope context must carry %s; got %r' % (list(need), sorted(scope) if isinstance(scope, dict) else scope))
    _rh_prove_artifact_templates(hs, scope['artifact_sources'])
    ed = scope['edition']
    if not isinstance(ed, dict) or set(ed) != {'profile', 'global_sha256', 'profile_sha256'} or not isinstance(ed['profile'], str) \
            or any(not isinstance(ed[k], str) or not re.match('^[0-9a-f]{64}$', ed[k]) for k in ('global_sha256', 'profile_sha256')):
        raise ValueError('lme: remote-harness scope edition must be {profile, global_sha256, profile_sha256}; got %r' % (ed,))
    pol = section['policy']
    ftg, tg = _rh_get(pol, hs['target_group_path'])
    fop, op = _rh_get(pol, hs['operation_path'])
    if not ftg or not isinstance(tg, str) or not tg or not fop or not isinstance(op, str) or not op:
        raise ValueError('lme: %s.%s and %s.%s must be non-empty strings (scope binding)' % (key, hs['target_group_path'], key, hs['operation_path']))
    cid = hs['controller_id']
    groups = scope['groups'] if isinstance(scope['groups'], dict) else {}
    members = groups.get(tg) or []
    if not isinstance(members, list) or any(not isinstance(m, str) for m in members) or cid in members:
        raise ValueError('lme: inventory group %s must list target identities other than the controller %r; got %r' % (tg, cid, members))
    targets = sorted(set(members))
    me = scope['self']
    if me != cid and me not in targets:
        raise ValueError('lme: host %r is neither the declared controller %r nor a member of %s; it has no %s scope' % (me, cid, tg, key))
    comp, ovs = scope['composed'], scope['overrides']
    for i in [cid] + targets:
        if not isinstance(comp, dict) or i not in comp or not isinstance(ovs, dict) or i not in ovs:
            raise ValueError('lme: remote-harness scope context lacks the composition of scope %r' % (i,))
    # This host's own composition/override ARE its scope entry's (type-aware): a context that disagrees is refused.
    if not _leaf_equal(comp[me], composed) or not _leaf_equal(ovs[me], override if override is not None else {}):
        raise ValueError('lme: the scope context for %r disagrees with this host\'s own composition/override' % (me,))
    # C1-EFFECTIVE-ENDPOINT-BINDING (codex 035141): every target's effective declared endpoint (the ONE declared
    # connection rule; same key order and rules as the route) is part of the deployment binding, so a changed
    # address / explicit port / ProxyJump route / owner under the same inventory id moves every scope identity.
    names, rule = _rh_endpoint_vars(pol, hs, key)
    conn = scope['connections']
    if not isinstance(conn, dict) or conn.get('vars') != names or not isinstance(conn.get('values'), dict) \
            or any(not isinstance(conn['values'].get(t), dict) for t in targets):
        raise ValueError('lme: remote-harness scope connections must carry the declared endpoint vars %r and every target\'s values' % (names,))
    endpoints = dict((t, _rh_endpoint(conn['values'][t], rule, t, key)) for t in targets)
    binding = {'deployment': {'profile': ed['profile'], 'controller': cid, 'target_group': tg, 'targets': targets,
                              'endpoints': endpoints},
               'source_edition': {'global_sha256': ed['global_sha256'], 'profile_sha256': ed['profile_sha256']},
               'operation': op}

    def entry(i):
        sec = section if i == me else _rh_validate(comp[i], declared, ovs[i], schema)[0]
        if _rh_get(sec['policy'], hs['target_group_path'])[1] != tg or _rh_get(sec['policy'], hs['operation_path'])[1] != op:
            raise ValueError('lme: scope %r resolves another target group/operation than the deployment binding' % (i,))
        ident = {'kind': 'controller' if i == cid else 'target', 'id': i}
        out = dict(ident, **{k: sec[k] for k in _RH_SCOPE_ENTRY})
        out['scope_sha256'] = _digest({'scope': ident, 'binding': binding, 'policy_sha256': sec['policy_sha256']})
        return out
    scopes = {'controller': entry(cid), 'targets': {t: entry(t) for t in targets}}
    mine = scopes['controller'] if me == cid else scopes['targets'][me]
    return dict(section, scope={'kind': mine['kind'], 'id': me}, binding=binding, scope_sha256=mine['scope_sha256'],
                scopes=scopes, scopes_sha256=_digest(scopes))


def lme_project_remote_harness(composed, declared, override, schema, scope=None):
    """SEED-06 (codex-tick121-223811, codex-232517): the typed lme_resolved.<policy_key> section
    {schema_version, policy, policy_sha256}, or None when no policy is declared.

    composed = lme_global as composed (global | profile | operator override LAST); declared = the same
    composition WITHOUT the operator override; override = lme_global_override; schema =
    lme_config_registry.remote_harness_schema. MERGES NOTHING. Validates, deny-by-default: override leaves only
    under declared tunable paths with the declared leaf type; an executable location override only together with
    its identity; absolute normalized executable paths; a well-formed identity of a declared kind for every
    executable; positive integers and resource bounds inside the declared envelope; package mappings for every
    required and adapter package in every os family; an admitted adapter whose executables are declared;
    registry inventory variable names; retired profile paths absent; adapter tool maps name declared
    executables only and carry no derived field (path/identity): section.adapter.tools.<map>.<tool> is
    DERIVED from the effective executable entry (codex-tick144 CANONICAL-TOOL-OVERRIDES). The section is
    revision-bound; override
    provenance is NOT in it (lme_remote_harness_overridden_paths is the unhashed audit view).

    Every section also carries host_scoped_paths / scope_invariant_sha256 (an ADDITIONAL compatibility digest)
    and shared_artifact_inputs_sha256. With scope (the loader's inline scope context), the section is bound to
    this host's scope and carries every scope's full intended policy (PER-HOST-SCOPE-CONTRACT, _rh_scoped)."""
    section = _rh_validate(composed, declared, override, schema)[0]
    if section is None or scope is None:
        return section
    return _rh_scoped(section, composed, declared, override, schema, scope)


_RH_BASE_KEYS = frozenset(('schema_version', 'policy', 'policy_sha256', 'adapter', 'host_scoped_paths',
                           'scope_invariant_sha256', 'shared_artifact_inputs_sha256'))
_RH_SCOPED_KEYS = frozenset(('scope', 'binding', 'scope_sha256', 'scopes', 'scopes_sha256'))


def _rh_verify_entry(where, sec, keys, schema):
    if not isinstance(sec, dict) or set(sec) != set(keys):
        raise ValueError('lme: published %s must carry exactly %s; got %r' % (where, sorted(keys), sorted(sec) if isinstance(sec, dict) else sec))
    if sec['policy_sha256'] != _digest(sec['policy']):
        raise ValueError('lme: published %s.policy_sha256 is not the digest of its actual policy content' % (where,))
    hsp = sec['host_scoped_paths']
    if not isinstance(hsp, list) or any(not isinstance(p, str) for p in hsp):
        raise ValueError('lme: published %s.host_scoped_paths must be a list of dotted paths' % (where,))
    if sec['scope_invariant_sha256'] != _digest({'policy': _rh_without(sec['policy'], hsp), 'host_scoped_paths': hsp}):
        raise ValueError('lme: published %s.scope_invariant_sha256 is not the digest of its actual content' % (where,))
    # C1-ARTIFACT-REUSE-INPUT-COVERAGE: the reuse key re-derives from the entry's own policy + the registry declaration.
    if sec['shared_artifact_inputs_sha256'] != _digest(_rh_shared_inputs(sec['policy'], schema['host_scope'], hsp, schema['policy_key'])):
        raise ValueError('lme: published %s.shared_artifact_inputs_sha256 is not the digest of its declared artifact inputs' % (where,))


def lme_verify_resolved(resolved, registry):
    """C1-TYPED-OUTPUT-REVISION (codex 022716). Validates the ACTUAL published lme_resolved -- not a recompute
    it merely compares equal to. Registry fields present in it must be canonical for their declared type
    (lme_validate_config: rejects, never coerces -- 3.0 is not an int, 1 is not a bool). The remote-harness
    section must carry the exact key set of its projection, schema_version must be the declared int (a float
    or bool 3 refuses), and every digest (policy_sha256, scope_invariant_sha256, and when scoped scope_sha256
    per scope + scopes_sha256) must be re-derivable from the section's OWN content, so a pre-supplied section
    whose content changed type/value while keeping an old digest refuses. Returns True; raises otherwise."""
    if not isinstance(resolved, dict):
        raise ValueError('lme: published lme_resolved must be a mapping; got %r' % (type(resolved).__name__,))
    fields = registry.get('fields') if isinstance(registry, dict) else None
    if not isinstance(fields, dict):
        raise ValueError('lme: registry fields missing (cannot validate the published lme_resolved)')
    lme_validate_config(registry, {k: v for k, v in resolved.items() if k in fields})
    schema = registry.get('remote_harness_schema') or {}
    outs = schema.get('resolver_outputs')
    if outs is not None and (not isinstance(outs, list) or any(not isinstance(n, str) for n in outs)
                             or 'lme_resolved' not in outs or any(n in fields for n in outs)):
        raise ValueError('lme: registry resolver_outputs must list loader OUTPUT names (incl. lme_resolved), none a '
                         'declared config field (a declared input must stay usable); got %r' % (outs,))
    key = schema.get('policy_key')
    if not key or key not in resolved:
        return True
    sec = resolved[key]
    scoped = isinstance(sec, dict) and 'scope' in sec
    _rh_verify_entry(key, sec, _RH_BASE_KEYS | (_RH_SCOPED_KEYS if scoped else frozenset()), schema)
    want = schema['projection_schema_version']
    if not _leaf_equal(sec['schema_version'], want):
        raise ValueError('lme: published %s.schema_version is %r (%s); the registry declares %r (%s)' % (
            key, sec['schema_version'], type(sec['schema_version']).__name__, want, type(want).__name__))
    if not scoped:
        return True
    scopes, binding = sec['scopes'], sec['binding']
    # C1-EFFECTIVE-ENDPOINT-BINDING: the bound endpoints are exactly the bound targets' [address, port_key, proxy_jump, owner].
    dep = binding.get('deployment') if isinstance(binding, dict) else None
    eps = dep.get('endpoints') if isinstance(dep, dict) else None
    if not isinstance(eps, dict) or sorted(eps) != sorted(dep.get('targets') or []) or any(
            not isinstance(v, list) or len(v) != 4 or any(not isinstance(x, str) for x in v) for v in eps.values()):
        raise ValueError('lme: published %s.binding.deployment.endpoints must map every bound target to its [address, port_key, proxy_jump, owner] strings' % (key,))
    if not isinstance(scopes, dict) or set(scopes) != {'controller', 'targets'} or not isinstance(scopes['targets'], dict):
        raise ValueError('lme: published %s.scopes must be {controller, targets}' % (key,))
    entries = [('controller', scopes['controller'])] + [('targets.' + t, scopes['targets'][t]) for t in sorted(scopes['targets'])]
    for where, ent in entries:
        _rh_verify_entry('%s.scopes.%s' % (key, where), ent, set(_RH_SCOPE_ENTRY) | {'kind', 'id', 'scope_sha256'}, schema)
        ident = {'kind': ent['kind'], 'id': ent['id']}
        if ent['scope_sha256'] != _digest({'scope': ident, 'binding': binding, 'policy_sha256': ent['policy_sha256']}):
            raise ValueError('lme: published %s.scopes.%s.scope_sha256 is not bound to its scope/binding/policy' % (key, where))
    if sec['scopes_sha256'] != _digest(scopes):
        raise ValueError('lme: published %s.scopes_sha256 is not the digest of its actual scopes' % (key,))
    me = sec['scope']
    mine = scopes['controller'] if isinstance(me, dict) and me.get('kind') == 'controller' else \
        scopes['targets'].get(me.get('id')) if isinstance(me, dict) else None
    if not isinstance(mine, dict) or not _leaf_equal({'kind': mine['kind'], 'id': mine['id']}, me) \
            or not _leaf_equal({k: mine[k] for k in _RH_SCOPE_ENTRY}, {k: sec[k] for k in _RH_SCOPE_ENTRY}) \
            or sec['scope_sha256'] != mine['scope_sha256']:
        raise ValueError('lme: published %s is not its own scope entry %r of scopes' % (key, me))
    return True


def lme_remote_harness_overridden_paths(composed, declared, override, schema):
    """Audit view (not revision-bound): sorted dotted leaf paths the operator override set; same validation."""
    return _rh_validate(composed, declared, override, schema)[1]


class FilterModule(object):
    def filters(self):
        return {
            'strict_enable_bool': strict_enable_bool,
            'lme_service_typed_inputs': lme_service_typed_inputs,
            'lme_project_remote_harness': lme_project_remote_harness,
            'lme_remote_harness_overridden_paths': lme_remote_harness_overridden_paths,
            'lme_verify_resolved': lme_verify_resolved,
            'lme_rh_connection_values': lme_rh_connection_values,
            'lme_resolve_config': lme_resolve_config,
            'lme_validate_config': lme_validate_config,
            'lme_config_revision': lme_config_revision,
            'lme_bind_revision': lme_bind_revision,
            'lme_known_enable_flags': lme_known_enable_flags,
            'lme_validate_material_requirements': lme_validate_material_requirements,
            'lme_validate_material_catalog': lme_validate_material_catalog,
            'lme_validate_material_registries': lme_validate_material_registries,
            'lme_type_aware_equal': lme_type_aware_equal,
            'lme_validate_deployment_identity': lme_validate_deployment_identity,
            'lme_validated_deployment_identity': lme_validated_deployment_identity,
            'lme_material_resource_id': lme_material_resource_id,
            'lme_project_required_material': lme_project_required_material,
            'lme_project_datastore_clients': lme_project_datastore_clients,
            'lme_project_database_membership': lme_project_database_membership,
            'lme_validate_dependency_closure': lme_validate_dependency_closure,
            'lme_selection_conflicts': lme_selection_conflicts,
            'lme_resolve_from_admitted': lme_resolve_from_admitted,
            'lme_split_brain_keys': lme_split_brain_keys,
            'lme_observation_only_keys': lme_observation_only_keys,
            'lme_effective_service_overrides': lme_effective_service_overrides,
            'lme_service_overrides_applied': lme_service_overrides_applied,
            'lme_unknown_service_override_ids': lme_unknown_service_override_ids,
            'lme_service_override_shape_errors': lme_service_override_shape_errors,
            'lme_service_coverage_gap': lme_service_coverage_gap,
            'render_userns': render_userns,
            'userns_base': userns_base,
            'cert_owner': cert_owner,
            'svc_unit': svc_unit,
            'unit_refs': unit_refs,
            'wanted_by': wanted_by,
            'requires_keep': requires_keep,
            'requires_relax': requires_relax,
            'render_port': render_port,
            'render_volume': render_volume,
            'podman_args': podman_args,
            'is_enabled': is_enabled,
            'jvm_opts': jvm_opts,
            'mem_derive': mem_derive,
            'service_memory_max': service_memory_max,
            'memory_budget': memory_budget,
        }
