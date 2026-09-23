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
            if fdecl.get('type') == 'str' and (not isinstance(val, str) or not val):
                raise ValueError('lme: material_catalog%s field %r must be a non-empty '
                                 'string, got %r' % (dwhere, fname, val))
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
        'vocabs': {k: set(f['vocab']) for k, f in record.items() if f.get('vocab')},
        'base_required': [k for k, f in record.items() if f.get('required')],
        'form_fields': set(('destination', 'owner_role', 'mode')),
    }


def lme_validate_material_requirements(catalog, obligations, schema, catalog_schema,
                                       referenced_ids=None, context=None):
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
        # typed + vocab + nonempty per declared field.
        for fname, fdecl in S['record'].items():
            if fname not in rec:
                continue
            val = rec[fname]
            if fdecl.get('type') == 'str':
                if not isinstance(val, str):
                    raise ValueError('lme: material_requirements%s field %r must be a '
                                     'string, got %r' % (rwhere, fname, val))
                if fdecl.get('required') and not val:
                    raise ValueError('lme: material_requirements%s required field %r is '
                                     'empty' % (rwhere, fname))
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
        # trust_ref, when it NAMES a catalog def, must resolve; producer/custody references
        # are shape-validated now (nonempty str), their closure arms when C/D declare the
        # producer/custody registries (C1-MATERIAL-LIFECYCLE-AND-RETENTION -- reported owed).
        tref = rec.get('trust_ref')
        if isinstance(tref, str) and tref and ':' not in tref and tref not in catalog \
                and tref not in obligations:
            raise ValueError('lme: material_requirements%s trust_ref %r resolves to no '
                             'catalog definition or sibling obligation' % (rwhere, tref))

    # --- reference resolution: every referenced obligation id must resolve ------
    unresolved = sorted(r for r in refs if r not in obligations)
    if unresolved:
        raise ValueError(
            'lme: material_requirement_ref(s) %r%s resolve to no declared obligation -- an '
            'UNRESOLVED reference is a pre-generation configuration error (fail before '
            'mutation), distinct from a valid declared production yielding an absent payload'
            % (unresolved, where))
    return obligations


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
                                  deployment_identity=None):
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
            referenced_ids=(refs or None), context=sid)
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
    comparison. A key absent from the registry, or a value that will not coerce, falls back
    to a RAW compare -- fail-closed: an uncanonicalizable disagreement still surfaces as a
    conflict, and the malformed value is caught by the resolver's typed validation anyway."""
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
                ov, cv = op[k], caller[k]  # raw fallback (fail-closed)
        if ov != cv:
            out.append(k)
    return sorted(out)


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


class FilterModule(object):
    def filters(self):
        return {
            'strict_enable_bool': strict_enable_bool,
            'lme_resolve_config': lme_resolve_config,
            'lme_validate_config': lme_validate_config,
            'lme_config_revision': lme_config_revision,
            'lme_bind_revision': lme_bind_revision,
            'lme_known_enable_flags': lme_known_enable_flags,
            'lme_validate_material_requirements': lme_validate_material_requirements,
            'lme_validate_material_catalog': lme_validate_material_catalog,
            'lme_validate_deployment_identity': lme_validate_deployment_identity,
            'lme_material_resource_id': lme_material_resource_id,
            'lme_project_required_material': lme_project_required_material,
            'lme_project_datastore_clients': lme_project_datastore_clients,
            'lme_project_database_membership': lme_project_database_membership,
            'lme_validate_dependency_closure': lme_validate_dependency_closure,
            'lme_selection_conflicts': lme_selection_conflicts,
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
