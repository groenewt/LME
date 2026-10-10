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
import copy
import hashlib
import json
import math
import re
from collections.abc import Mapping

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

    Value-pure: canonical JSON (sorted keys, no whitespace) then sha256 -- the ONE canonical digest _digest
    (C1-RECIPE-PUB-02, OW-L1-JSON-DEFAULT-STR-01): an unsupported value refuses, an admitted payload keeps its bytes."""
    return _digest(payload)


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
    if services is not None and 'resolved_record' in registry:
        declaration = registry['resolved_record']
        projections = declaration['projection_keys']
        if not isinstance(projections, list) or not projections or any(
                not isinstance(key, str) or not key or key not in resolved or key in payload
                for key in projections) or len(projections) != len(set(projections)):
            raise ValueError(declaration['diagnostics']['revision'])
        for key in projections:
            payload[key] = resolved[key]
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


def _material_local_state(catalog, catalog_kinds, distributable, producers, provision,
                          schema, leaf_owners, non_publication, components):
    """Admit the existing local-state ownership route before producer partitioning.

    This is declaration validation only. It neither selects a database profile nor
    creates, transports, projects or reads a persistent record.
    """
    policy = schema['local_state_admission']
    constants, kinds = policy['constants'], policy['types']

    def fail(reason, detail):
        raise ValueError(policy['errors'][reason].format(detail=detail))

    recs = {section: schema[key] for section, key in policy['sections'].items()}
    present = [name for name in recs if name in provision]
    if present and set(present) != set(recs):
        fail('sections', present)
    for name, rec in recs.items():
        if (not isinstance(rec, dict) or not isinstance(rec['required'], list)
                or not rec['required'] or len(set(rec['required'])) != len(rec['required'])
                or not isinstance(rec['empty_allowed'], list)
                or not set(rec['empty_allowed']) <= set(rec['required'])
                or len(set(rec['empty_allowed'])) != len(rec['empty_allowed'])
                or _canonical_kind(rec['empty_section_admitted']) != kinds['boolean']):
            fail('schema', name)
        if name in provision and (not isinstance(provision[name], dict)
                or (not provision[name] and rec['empty_section_admitted'] is not constants['enabled'])):
            fail('sections', name)

    local_kinds = recs[policy['records_section']]['material_kinds']
    if (not isinstance(local_kinds, list) or not local_kinds
            or len(set(local_kinds)) != len(local_kinds)
            or not set(local_kinds) <= set(catalog_kinds)
            or set(local_kinds) & set(distributable)):
        fail('schema', policy['details']['schema'])

    custody = schema['local_state_custody']
    vocab, classes = custody['vocab'], custody['classes']
    root = custody['root_owner']
    if (not isinstance(root, dict) or set(root) != set(policy['root_owner_fields'])
            or root['name'] not in vocab['owner']
            or _canonical_kind(root['uid']) != kinds['integer']
            or root['uid'] < constants['zero']):
        fail('schema', policy['details']['schema'])
    stat_policy = custody['stat_flag_policy']
    if (not isinstance(stat_policy, dict)
            or set(stat_policy) != set(policy['stat_policy_fields'])
            or any(not isinstance(stat_policy[field], str) or not stat_policy[field]
                   for field in policy['stat_text_fields'])
            or any(stat_policy[field] not in vocab[field] for field in policy['stat_vocab_fields'])):
        fail('schema', policy['details']['schema'])
    mode_re = re.compile(schema['mode_pattern'])
    if not isinstance(classes, dict) or not classes:
        fail('schema', policy['details']['schema'])
    for name, cls in classes.items():
        if (not isinstance(cls, dict) or set(cls) != set(custody['class_keys'])
                or any(not any(_leaf_equal(cls[field], value) for value in vocab[field])
                       for field in policy['class_vocab_fields'])
                or not isinstance(cls['forbid_mode_bits'], str)
                or not mode_re.fullmatch(cls['forbid_mode_bits'])
                or int(cls['forbid_mode_bits'], constants['mode_radix']) == constants['zero']
                or not isinstance(cls['forbid_stat_flags'], list) or not cls['forbid_stat_flags']
                or any(not isinstance(flag, str) or not flag for flag in cls['forbid_stat_flags'])
                or (not _leaf_equal(cls['parent_class'], constants['absent'])
                    and cls['parent_class'] not in classes)):
            fail('schema', name)

    if (not isinstance(components, dict) or not isinstance(components['selected_by'], dict)
            or not components['selected_by'] or not isinstance(components['selectors'], list)
            or not components['selectors']
            or any(selector not in components['selectors']
                   for selector in components['selected_by'].values())):
        fail('schema', policy['details']['components'])

    owners = dict(policy['empty']['mapping'])
    for section in present:
        rec = recs[section]
        placeholder_re = re.compile(rec['placeholder_pattern'])
        if (placeholder_re.groups != constants['one']
                or not isinstance(rec['placeholders'], list)
                or len(set(rec['placeholders'])) != len(rec['placeholders'])
                or rec['object_type'] not in vocab['object_type']):
            fail('schema', section)
        for identity, entry in provision[section].items():
            if (not isinstance(entry, dict) or set(entry) != set(rec['required'])
                    or any(_canonical_kind(entry[field]) != policy['entry_types'][field]
                           for field in rec['required'])
                    or any(not entry[field] for field in rec['required']
                           if field not in rec['empty_allowed'])):
                fail('entry', identity)
            for field, vocabulary in policy['placement_vocab_fields'].items():
                if entry[field] not in rec[vocabulary]:
                    fail('entry', identity)
            cls = (classes[entry['custody_class']] if entry['custody_class'] in classes
                   else constants['absent'])
            mode = entry['mode']
            if (_leaf_equal(cls, constants['absent']) or cls['object_type'] != rec['object_type']
                    or cls['owner'] != entry['owner_role'] or not mode_re.fullmatch(mode)
                    or int(mode, constants['mode_radix'])
                       & int(cls['forbid_mode_bits'], constants['mode_radix'])):
                fail('custody', identity)
            per, destination = entry['per'], entry['destination']
            if (any(not isinstance(value, str) or value not in rec['placeholders'] for value in per)
                    or len(set(per)) != len(per)
                    or set(placeholder_re.findall(destination)) != set(per)
                    or any(delimiter in placeholder_re.sub(policy['empty']['text'], destination)
                           for delimiter in policy['placeholder_delimiters'])):
                fail('entry', identity)
            consumers = entry['consumers']
            if (any(not isinstance(value, str) or not value for value in consumers)
                    or len(set(consumers)) != len(consumers)
                    or any(value not in components['selected_by'] for value in consumers)):
                fail('consumer', identity)
            if section == policy['records_section']:
                material, producer = entry['material'], entry['producer']
                if (material not in catalog or catalog[material]['kind'] not in local_kinds
                        or material in owners or material in leaf_owners or material in non_publication
                        or producer not in producers or material not in producers[producer]['produces_materials']
                        or producers[producer]['host_scope'] != entry['host_scope']):
                    fail('producer', identity)
                for field, vocabulary in policy['record_vocab_fields'].items():
                    if entry[field] not in rec[vocabulary]:
                        fail('entry', identity)
                owners[material] = producer
    return owners


def lme_validate_material_registries(catalog, catalog_schema, producer_registry,
                                     custody_registry, material_provision,
                                     provision_schema, context=None, *, component_registry):
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

    local_material_owner = _material_local_state(
        catalog, _kv, distributable, producer_registry, material_provision,
        provision_schema, leaf_material_owner, non_publication_materials, component_registry)
    local_policy = provision_schema['local_state_admission']

    # --- CA/leaf separation (retained explicit KEY-form control) + PARTITION ------
    # The identity check above already rejects any leaf REFERENCING ca_mid; retain the
    # explicit key-form control (a leaf literally KEYED as the ca material) for clarity.
    if ca_mid in leaves:
        raise ValueError('lme: ca_key_rule material %r must NOT also be a leaf_key_provision '
                         'entry -- the CA-key rule is SEPARATE from every leaf delivery '
                         'contract (codex private_key_correction)' % ca_mid)
    # Partition every non-distributable produced material across the declared ownership
    # routes. Local-state kinds require their validated local record and producer binding;
    # they cannot use a private-key or non-publication route instead.
    for pid, entry in producer_registry.items():
        for mid in (entry.get('produces_materials') or []):
            if (catalog[mid] or {}).get('kind') in distributable:
                continue
            homes = {
                local_policy['routes']['leaf']: mid in leaf_material_owner,
                local_policy['routes']['non_publication']: mid in non_publication_materials,
                local_policy['routes']['local']: mid in local_material_owner}
            local_kinds = provision_schema['local_state_provision_record']['material_kinds']
            if (sum(homes.values()) != local_policy['constants']['one']
                    or (catalog[mid]['kind'] in local_kinds and mid not in local_material_owner)
                    or (mid in local_material_owner and local_material_owner[mid] != pid)):
                raise ValueError(local_policy['errors']['partition'].format(detail=(pid, mid, homes)))
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
# C1-RECIPE-PUB-02 (OW-L1-JSON-DEFAULT-STR-01 closed; codex-tick884 Q290_2 b): THE canonical digest -- policy, scope,
# reuse-key and structural digests, every select_tree digest and lme_config_revision. The payload is admitted first
# (_rh_canonical_admit) and json gets no default hook, so it serializes an admitted payload natively (the old bytes,
# since json called the old hook only for unsupported values); any other value refuses instead of becoming its str().
_RH_CANONICAL_SCALARS = (str, bool, int)


def _rh_canonical_admit(v, at):
    """C1-RECIPE-PUB-02 (codex-tick884 Q290_2 b): admit v for _digest, recursively: null, str, bool, int, a finite
    float, a list of admitted values, or a dict whose keys are all str and whose values are admitted (a subclass of an
    admitted type serializes as that type). Anything else -- tuple, set, bytes, date or datetime, a non-dict Mapping, an
    undefined or any other object --, a non-str key or a nonfinite float raises ValueError naming the path and the
    type, never the value."""
    where = '.'.join(at) if at else '<root>'
    if v is None or isinstance(v, _RH_CANONICAL_SCALARS):
        return
    if isinstance(v, float):
        if not math.isfinite(v):
            raise ValueError('lme: canonical digest refuses a nonfinite number at %s' % (where,))
        return
    if isinstance(v, list):
        for i, x in enumerate(v):
            _rh_canonical_admit(x, at + ['[%d]' % (i,)])
        return
    if isinstance(v, dict):
        bad = sorted(type(k).__name__ for k in v if not isinstance(k, str))
        if bad:
            raise ValueError('lme: canonical digest refuses non-string mapping keys (%s) at %s' % (', '.join(bad), where))
        for k in v:
            _rh_canonical_admit(v[k], at + [k])
        return
    raise ValueError('lme: canonical digest refuses an unsupported %s at %s (admitted: null, str, bool, int, finite float, list, string-keyed mapping)' % (type(v).__name__, where))


def _digest(obj):
    _rh_canonical_admit(obj, [])
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')).hexdigest()


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


# F05-S4 RENDER-CONTEXT-02 (render-interface-02; Codex578 OD-S06-STRUCT-SOURCE-TYPE; Codex580 J-S07-KIND-ADMISSION):
# the SEVEN supported kind words bool / int / str / float / mapping / list / null -- exactly the words of _rh_kind's
# DECLARED branches, taken by applying it to one representative of each branch (never respelled). Its unbounded
# type(v).__name__ fallback (an unsupported value) is NEVER a member: a registry-declared result kind
# (published_views.<view>.rendered.source_kinds) or a struct_kind_tests key outside these seven refuses.
_RH_KIND_WORDS = frozenset(_rh_kind(x) for x in (False, 0, '', 0.0, {}, [], None))


def _rh_get(tree, dotted):
    cur = tree
    for k in dotted.split('.'):
        if not isinstance(cur, dict) or k not in cur:
            return False, None
        cur = cur[k]
    return True, cur


# F05-S3 (codex-tick522 / codex-tick530 / codex-tick534): the DOCUMENT CHANNEL, the projection DEPENDENCY ORDER and the
# entry-generation projection kinds. Every literal below is a registry KEY of the declaration it reads (the kind's own
# contract, documented beside the declaration in global.yml); every value is read through a registry pointer.
_RH_DOC_CHANNEL_KEYS = frozenset(('at', 'when', 'fact', 'read', 'encoding', 'digest_algorithm', 'rel_pattern', 'admission',
                                  'refusal', 'message', 'parse'))
# F-LIS12-DUPKEY (codex-tick710 C1-DK-DIAGNOSTIC-KEY-DISCLOSURE; OD-DK-DECL-01; codex-tick712): document_channel.parse.
# Its registry keys, and the ONLY fields each declared position / diagnostic text may name (sorted): the admitted
# document identity (rel), the declared encoding, an exception class name (error) and position metadata. No field
# carries a key, a value, source text or an exception message.
_RH_DOC_PARSE_KEYS = frozenset(('tags', 'bases', 'positions', 'diagnostics'))
_RH_DOC_PARSE_TAG_KEYS = frozenset(('merge', 'value'))
_RH_DOC_PARSE_TAG_FIELDS = frozenset(('tag', 'plain'))
_RH_DOC_PARSE_BASES = frozenset(('authored', 'aliased'))
_RH_DOC_PARSE_POSITIONS = {'marked': ('column', 'line'), 'unmarked': ()}
_RH_DOC_PARSE_DIAGNOSTICS = {
    'duplicate_key': ('basis', 'column', 'first_basis', 'first_column', 'first_line', 'line', 'rel'),
    'duplicate_merge': ('basis', 'column', 'first_basis', 'first_column', 'first_line', 'line', 'rel'),
    'unconstructable': ('error', 'rel', 'where'),
    'unencodable': ('encoding', 'error', 'rel'),
    'unparsable': ('error', 'rel', 'where')}
# C1 s10 L10-01 (records-c1-framework-27; codex-tick821 item 5): + declaration / partial, the presence names of the
# reader inputs (_rh_sa_decl, rh_src_partial) declared WITH the document-admission contract.
_RH_DOC_ADMISSION_KEYS = frozenset(('declaration', 'fact', 'members', 'observed', 'partial'))
_RH_DOC_FACT_KEYS = frozenset(('rel', 'text'))
_RH_DOC_PRIMARY_KEYS = frozenset(('rel_from', 'root'))
_RH_DOC_DEPENDENT_KEYS = frozenset(('document', 'rel_at'))


def _rh_patterns(schema):
    """contract_admission.patterns, admitted fail-closed (_rh_ca_registry): ({name: compiled}, {name: text})."""
    if not isinstance(schema, dict) or 'contract_admission' not in schema:
        raise ValueError('lme: registry remote_harness_schema.contract_admission is absent (the patterns are declared there); got %r' % (
            sorted(schema) if isinstance(schema, dict) else schema,))
    ca = schema['contract_admission']
    return _rh_ca_registry(ca, schema)[0], ca['patterns']


def _rh_contract_active(pol, schema, view, where):
    """The ONE activity rule (codex-tick530 OI-08): the published view `view` must be a declaration_contract; active
    exactly when the policy declares its when_declared path. No absence-derived skip: callers refuse an inactive
    policy that carries a gated node."""
    views = _rh_published_view_decl(schema)
    if view not in views or views[view]['kind'] != 'declaration_contract':
        raise ValueError('lme: registry %s names published view %r, which is not a declared declaration_contract view (%s)' % (
            where, view, sorted(n for n in views if views[n]['kind'] == 'declaration_contract')))
    return _rh_get(pol, views[view]['when_declared'])[0]


def _rh_document_channel(schema):
    """LR-01: registry remote_harness_schema.document_channel, admitted at every use. Exact keys; at / read / encoding /
    digest_algorithm are policy paths; `when` names a declaration_contract view; fact and admission.fact are reserved
    resolver outputs (var_name, listed in resolver_outputs); rel_pattern names a contract_admission pattern (the ONE
    relative-path grammar, F05S2-RELATIVE-PATH-GRAMMAR); admission.members / admission.observed are policy paths whose
    values name the admission record's members container and observed-digest field (S3-SEAM-01, OD-S3-02 a);
    admission.partial / admission.declaration are the presence names of the reader inputs (var_name, distinct from
    both facts; records-c1-framework-27 L10), distinct from each other and each a reserved output (records-c1-framework-29
    L11-05); refusal matches patterns.refusal_code."""
    pats, ptext = _rh_patterns(schema)
    for k in ('document_channel', 'resolver_outputs'):
        if k not in schema:
            raise ValueError('lme: registry remote_harness_schema.%s is absent (F05-S3 document channel, S3-SEAM-01)' % (k,))
    ch = schema['document_channel']
    outs = schema['resolver_outputs']
    if not isinstance(ch, dict) or set(ch) != _RH_DOC_CHANNEL_KEYS \
            or any(not isinstance(ch[k], str) or not ch[k] for k in _RH_DOC_CHANNEL_KEYS - {'admission', 'parse'}) \
            or not isinstance(ch['admission'], dict) or set(ch['admission']) != _RH_DOC_ADMISSION_KEYS \
            or any(not isinstance(v, str) or not v for v in ch['admission'].values()):
        raise ValueError('lme: registry remote_harness_schema.document_channel must carry exactly %s (admission exactly %s) with non-empty string values; got %r' % (
            sorted(_RH_DOC_CHANNEL_KEYS), sorted(_RH_DOC_ADMISSION_KEYS), ch))
    for f in (ch['fact'], ch['admission']['fact']):
        if 'var_name' not in pats or not pats['var_name'].fullmatch(f) or not isinstance(outs, list) or f not in outs:
            raise ValueError('lme: registry remote_harness_schema.document_channel fact %r must be a var_name listed in resolver_outputs (a reserved resolver output); got resolver_outputs %r' % (f, outs))
    # C1 s10 L10-02 (records-c1-framework-27): admission.partial / admission.declaration name reader INPUTS (presence
    # names tested by membership in vars), so resolver_outputs membership is NOT required; each is a var_name distinct
    # from both facts.
    for k in ('partial', 'declaration'):
        f = ch['admission'][k]
        if 'var_name' not in pats or not pats['var_name'].fullmatch(f) or f in (ch['fact'], ch['admission']['fact']):
            raise ValueError('lme: registry remote_harness_schema.document_channel.admission.%s %r must be a var_name distinct from document_channel.fact %r and admission.fact %r' % (k, f, ch['fact'], ch['admission']['fact']))
    # C1 s11 L11-05 (records-c1-framework-29; codex-tick823 OPEN-NOTE-L10-DISTINCT): the two reader-input roles name
    # DIFFERENT inputs (different structures), and each is a reserved output, so its first-entry protection
    # (refuse_pinned_outputs.yml) and its producer follow the declared name: presence, value and protection move together.
    if ch['admission']['partial'] == ch['admission']['declaration']:
        raise ValueError('lme: registry remote_harness_schema.document_channel.admission.partial and admission.declaration must name distinct reader inputs; both are %r' % (ch['admission']['partial'],))
    if 'reserved_outputs' not in schema or not isinstance(schema['reserved_outputs'], list):
        raise ValueError('lme: registry remote_harness_schema.reserved_outputs must be a list (document_channel.admission input names are first-entry protected through it); got %r' % (
            _rh_kind(schema['reserved_outputs']) if 'reserved_outputs' in schema else '<absent>',))
    miss = [k for k in ('partial', 'declaration') if ch['admission'][k] not in schema['reserved_outputs']]
    if miss:
        raise ValueError('lme: registry remote_harness_schema.document_channel.admission %s %r must each be listed in remote_harness_schema.reserved_outputs (first-entry protected)' % (
            miss, [ch['admission'][k] for k in miss]))
    # C1 records-c1-framework-30-r2 (codex-tick826 FW30-PUBLICATION-ROLE-COLLISION; the registry ingress applies the same
    # rule, R2-03): each reader-input publication name is disjoint from every declared pre-view name (every value of every
    # entry of contract_admission.early_names: the internal binding and working facts bound before any view). The other
    # publication role is excluded above (L11-05). This code names no early name and no entry key.
    if 'contract_admission' not in schema or not isinstance(schema['contract_admission'], dict) \
            or 'early_names' not in schema['contract_admission'] or not isinstance(schema['contract_admission']['early_names'], dict) \
            or any(not isinstance(e, dict) or any(not isinstance(v, str) for v in e.values()) for e in schema['contract_admission']['early_names'].values()):
        raise ValueError('lme: registry remote_harness_schema.contract_admission.early_names must be a mapping of entry mappings with string values (document_channel.admission names are checked against it)')
    early = [v for e in schema['contract_admission']['early_names'].values() for v in e.values()]
    hit = [k for k in ('partial', 'declaration') if ch['admission'][k] in early]
    if hit:
        raise ValueError('lme: registry remote_harness_schema.document_channel.admission %s %r must not be declared pre-view names (contract_admission.early_names: internal binding and working facts)' % (
            hit, [ch['admission'][k] for k in hit]))
    if ch['rel_pattern'] not in pats:
        raise ValueError('lme: registry remote_harness_schema.document_channel.rel_pattern %r must name a declared contract_admission.patterns entry' % (ch['rel_pattern'],))
    if 'refusal_code' not in pats:
        raise ValueError('lme: registry remote_harness_schema.contract_admission.patterns declares no refusal_code; document_channel.refusal %r cannot be admitted' % (ch['refusal'],))
    if not pats['refusal_code'].fullmatch(ch['refusal']):
        raise ValueError('lme: registry remote_harness_schema.document_channel.refusal %r must fully match patterns.refusal_code %r' % (ch['refusal'], ptext['refusal_code']))
    _rh_doc_parse_decl(ch['parse'])
    _rh_contract_active({}, schema, ch['when'], 'remote_harness_schema.document_channel.when')
    return ch


def _rh_doc_parse_decl(p):
    """F-LIS12-DUPKEY (codex-tick710 C1-DK-DIAGNOSTIC-KEY-DISCLOSURE; OD-DK-DECL-01; codex-tick712 C1-DK-TAG-ROLE-BINDING):
    registry remote_harness_schema.document_channel.parse, admitted with the channel at every use. tags: the merge and
    value keys ({tag, plain}); after the shape check each role is bound to THIS parser's resolver AND role semantics
    (_rh_yaml_roles_bound), so a refusal precedes every document read; bases: the words for where a reported key
    position comes from; positions / diagnostics: str.format texts naming EXACTLY the fields of
    _RH_DOC_PARSE_POSITIONS / _RH_DOC_PARSE_DIAGNOSTICS, each once, plain names only (no attribute, index, conversion or
    format spec), so no text can reach anything but the supplied metadata. The node supplies words, never a choice: no
    declared value disables the duplicate refusal."""
    import string

    def fields(text):
        try:
            parts = list(string.Formatter().parse(text))
        except ValueError:
            return None
        if any(f is not None and (spec or conv is not None) for _lit, f, spec, conv in parts):
            return None
        return tuple(sorted(f for _lit, f, _spec, _conv in parts if f is not None))

    def texts(node, want):
        return isinstance(node, dict) and set(node) == set(want) and all(
            isinstance(node[k], str) and node[k] and fields(node[k]) == tuple(want[k]) for k in want)
    if not isinstance(p, dict) or set(p) != _RH_DOC_PARSE_KEYS or not isinstance(p['tags'], dict) \
            or set(p['tags']) != _RH_DOC_PARSE_TAG_KEYS \
            or any(not isinstance(t, dict) or set(t) != _RH_DOC_PARSE_TAG_FIELDS
                   or any(not isinstance(x, str) or not x for x in t.values()) for t in p['tags'].values()) \
            or not texts(p['bases'], dict((b, ()) for b in _RH_DOC_PARSE_BASES)) \
            or not texts(p['positions'], _RH_DOC_PARSE_POSITIONS) or not texts(p['diagnostics'], _RH_DOC_PARSE_DIAGNOSTICS):
        raise ValueError('lme: registry remote_harness_schema.document_channel.parse must carry exactly %s: tags exactly %s, each exactly %s of non-empty strings; bases exactly %s with no format field; positions %s and diagnostics %s as non-empty texts whose str.format fields are exactly those named, each once (no attribute, index, conversion or format spec); got %r' % (
            sorted(_RH_DOC_PARSE_KEYS), sorted(_RH_DOC_PARSE_TAG_KEYS), sorted(_RH_DOC_PARSE_TAG_FIELDS), sorted(_RH_DOC_PARSE_BASES),
            _RH_DOC_PARSE_POSITIONS, _RH_DOC_PARSE_DIAGNOSTICS, p))
    _rh_yaml_roles_bound(p['tags'])


def _rh_doc_refuse(ch, key, path, detail, value):
    raise ValueError('lme: %s (registry remote_harness_schema.document_channel; %s): %s.%s %s; got %r' % (
        ch['refusal'], ch['message'], key, path, detail, value))


def _rh_documents(pol, schema, key, documents, admission):
    """The complete admission (every declared name carried): see _rh_documents_admit."""
    active, out, _order, _next = _rh_documents_admit(pol, schema, key, documents, admission, False)
    return active, out


def _rh_documents_admit(pol, schema, key, documents, admission, partial):
    """LR-03 / LR-04 / LD01 (S3-SEAM-07, OD-S3-02 a): admit the retained document reads BEFORE any parse.
    inactive (document_channel.when): the node at document_channel.at must be ABSENT, `documents` must be an empty
      mapping and `admission` must be None (no inert declaration, no read, no admission authority).
    active: `documents` carries exactly the declared names, each exactly {rel, text}; for EVERY name n the expected
      rel(n) is re-derived here (rel_from: the policy value; rel_at: the value under the PARENT document's root, read
      from the parent's already digest-verified parse) and must full-match the channel's rel_pattern; documents[n].rel
      must EQUAL rel(n) (a coherent swap of two names refuses) and digest(text.encode(encoding)) must EQUAL
      admission[<members>][rel(n)][<observed>] (a swapped or forged text refuses) -- both BEFORE n is parsed.
      The document relation is ONE level (OI-05): a {document, rel_at} entry must name a {rel_from, root} entry.
    Exact bytes: no strip or normalisation (body_domain.read is admitted {lstrip: false, rstrip: false} by contract
    body_domain); the digested bytes and the parsed value come from the SAME text.
    partial (the resolve.yml reader, LR-14): `documents` carries exactly the FIRST k names of the admission order
      (each admitted exactly as above; the empty prefix only here) and the rels of the next LEVEL are derived and
      full-matched -- from the policy or from the already digest-verified, strictly parsed parents -- BEFORE the reader
      constructs, stats, Git-admits or reads a path; `admission` is the one-key reading-stage partial admission.
    Returns (active, {name: {rel, sha256, root}}, admission order, [(next name, next rel)] of the next level | None)."""
    import yaml
    ch = _rh_document_channel(schema)
    pats, ptext = _rh_patterns(schema)
    relp = pats[ch['rel_pattern']]
    active = _rh_contract_active(pol, schema, ch['when'], 'remote_harness_schema.document_channel.when')
    fn, node = _rh_get(pol, ch['at'])
    if not isinstance(documents, dict):
        _rh_doc_refuse(ch, key, ch['at'], 'is read through resolver output %s, which must be a mapping' % (ch['fact'],), _rh_kind(documents))
    if not active:
        if fn:
            _rh_doc_refuse(ch, key, ch['at'], 'is declared while published view %s is inactive (no inert declaration)' % (ch['when'],), node)
        if documents:
            _rh_doc_refuse(ch, key, ch['at'], 'is inactive but resolver output %s carries documents (nothing is read while inactive)' % (ch['fact'],), sorted(documents))
        if admission is not None:
            _rh_doc_refuse(ch, key, ch['at'], 'is inactive but resolver output %s is not null (no admission authority while inactive)' % (ch['admission']['fact'],), _rh_kind(admission))
        return False, {}, [], None
    if not fn or not isinstance(node, dict) or not node:
        _rh_doc_refuse(ch, key, ch['at'], 'must be a declared non-empty mapping while published view %s is active' % (ch['when'],), node if fn else '<absent>')
    (fe, enc), (fa, alg) = _rh_get(pol, ch['encoding']), _rh_get(pol, ch['digest_algorithm'])
    if not fe or not isinstance(enc, str) or not enc or not fa or not isinstance(alg, str) or alg not in hashlib.algorithms_available:
        _rh_doc_refuse(ch, key, '%s / %s' % (ch['encoding'], ch['digest_algorithm']), 'must name a declared encoding and an available digest algorithm', [enc if fe else '<absent>', alg if fa else '<absent>'])
    try:
        ''.encode(enc)
    except LookupError:
        _rh_doc_refuse(ch, key, ch['encoding'], 'is not a known encoding', enc)
    am = ch['admission']
    (fm, mk), (fo, ok) = _rh_get(pol, am['members']), _rh_get(pol, am['observed'])
    if not fm or not isinstance(mk, str) or not mk or not fo or not isinstance(ok, str) or not ok:
        _rh_doc_refuse(ch, key, '%s / %s' % (am['members'], am['observed']), 'must name the admission record members container and observed-digest field', [mk if fm else '<absent>', ok if fo else '<absent>'])
    # records-staged-reader-01 (codex-tick740 single_engine_document_reader; codex-tick747; codex-tick750): admission
    # authority BY STAGE. partial (the resolve.yml reader): `admission` is exactly ONE key -- the reading-stage word
    # resolve.yml takes from the declared admission_stages.words, never the members key -- whose value is the record
    # (the executable_closure members plus the rels the reader Git-admitted); the empty prefix is valid only here.
    # complete (_rh_validate, the projection): `admission` is the completed receipt itself. A receipt offered to the
    # partial reader (more than one key) and a partial admission offered to the projection (no members key) refuse.
    pk = next(iter(admission)) if partial and isinstance(admission, dict) and admission else None
    rec = admission[pk] if pk is not None and pk != mk and set(admission) == {pk} else (None if partial else admission)
    if not isinstance(rec, dict) or mk not in rec or not isinstance(rec[mk], dict):
        _rh_doc_refuse(ch, key, ch['at'], 'is active; resolver output %s must be the protected source-admission record carrying a %r mapping (the reader passes rh_src_admission; a caller-supplied record is no authority)' % (am['fact'], mk),
                       sorted(admission) if isinstance(admission, dict) else _rh_kind(admission))
    adm = rec[mk]
    prim = sorted(n for n in node if isinstance(node[n], dict) and set(node[n]) == _RH_DOC_PRIMARY_KEYS)
    dep = sorted(n for n in node if isinstance(node[n], dict) and set(node[n]) == _RH_DOC_DEPENDENT_KEYS)
    bad = sorted(n for n in node if n not in prim and n not in dep
                 or any(not isinstance(v, str) or not v for v in node[n].values()))
    if bad:
        _rh_doc_refuse(ch, key, ch['at'], 'entries %s must be exactly %s or %s of non-empty strings' % (bad, sorted(_RH_DOC_PRIMARY_KEYS), sorted(_RH_DOC_DEPENDENT_KEYS)), dict((n, node[n]) for n in bad))
    deeper = sorted(n for n in dep if node[n]['document'] not in prim)
    if deeper:
        _rh_doc_refuse(ch, key, ch['at'], 'entries %s name a document that is not a %s entry: the document relation is ONE level (a deeper, self or cyclic relation refuses, OI-05)' % (deeper, sorted(_RH_DOC_PRIMARY_KEYS)),
                       dict((n, node[n]['document']) for n in deeper))
    order = prim + dep
    carried = order[:len(documents)] if partial else order
    if sorted(documents) != sorted(carried):
        _rh_doc_refuse(ch, key, ch['at'], 'declares the documents %s (admission order %s); resolver output %s must carry exactly %s' % (
            sorted(node), order, ch['fact'], 'a prefix of that order' if partial else 'those names'), sorted(documents))
    out, seen = {}, {}

    def rel_of(n):
        # full-match BEFORE any path is constructed (OD-S3-01 a): the reader receives only this admitted rel
        e = node[n]
        if n in prim:
            fr, rel = _rh_get(pol, e['rel_from'])
            src = '%s.%s' % (key, e['rel_from'])
        else:
            fr, rel = _rh_get(out[e['document']]['root'], e['rel_at'])
            src = 'document %s (%s) root %s' % (e['document'], out[e['document']]['rel'], e['rel_at'])
        if not fr or not isinstance(rel, str) or not relp.fullmatch(rel):
            # codex-tick712 OBS-DK2-01: a dependent rel is a VALUE of the parent document; a value that fails the pattern is
            # not an admitted identity, so only its kind is shown. A primary rel is the policy value (a declaration).
            _rh_doc_refuse(ch, key, '%s.%s' % (ch['at'], n), 'resolves through %s to no repository-relative path fully matching patterns.%s %r' % (src, ch['rel_pattern'], ptext[ch['rel_pattern']]), (rel if n in prim else _rh_kind(rel)) if fr else '<absent>')
        if rel in seen:
            _rh_doc_refuse(ch, key, '%s.%s' % (ch['at'], n), 'resolves to rel %r, already document %s (a document rel is declared once)' % (rel, seen[rel]), rel)
        return rel
    for n in carried:
        e = node[n]
        rel = rel_of(n)
        d = documents[n]
        if not isinstance(d, dict) or set(d) != _RH_DOC_FACT_KEYS or not isinstance(d['rel'], str) or not isinstance(d['text'], str):
            _rh_doc_refuse(ch, key, '%s.%s' % (ch['at'], n), 'is carried by resolver output %s.%s, which must be exactly %s of strings' % (ch['fact'], n, sorted(_RH_DOC_FACT_KEYS)),
                           sorted(d) if isinstance(d, dict) else _rh_kind(d))
        if d['rel'] != rel:
            _rh_doc_refuse(ch, key, '%s.%s' % (ch['at'], n), 'is declared at rel %r; resolver output %s.%s.rel names another file (name-to-rel binding, LD01; nothing is parsed)' % (rel, ch['fact'], n), d['rel'])
        # codex-tick712 OBS-DK2-02: the exception text names the offending character; only its class is kept, and the
        # refusal is raised after the handler (no exception context; records-dupkey-03 exception_chain).
        raw, unenc = b'', ''
        try:
            raw = d['text'].encode(enc)
        except UnicodeError as exc:
            unenc = type(exc).__name__
        if unenc:
            _rh_doc_refuse(ch, key, '%s.%s' % (ch['at'], n), ch['parse']['diagnostics']['unencodable'].format(rel=rel, encoding=enc, error=unenc), rel)
        sha = hashlib.new(alg, raw).hexdigest()
        if rel not in adm or not isinstance(adm[rel], dict) or ok not in adm[rel]:
            _rh_doc_refuse(ch, key, '%s.%s' % (ch['at'], n), 'rel %r is not admitted by resolver output %s[%r] (no %r digest; the source admission precedes every read)' % (rel, am['fact'], mk, ok), sorted(adm))
        if adm[rel][ok] != sha:
            _rh_doc_refuse(ch, key, '%s.%s' % (ch['at'], n), 'text of %r digests to %s; the admitted %s is %r (exact bytes are compared BEFORE any parse)' % (rel, sha, ok, adm[rel][ok]), sha)
        # F-LIS12-DUPKEY (codex-tick702 mechanism 2; codex-tick710; codex-tick712 C1-DK-CONSTRUCTOR-DIAGNOSTICS): the SAME
        # text whose bytes were digested above is parsed; a mapping repeating a key refuses. The parse never raises for the
        # text: every failure comes back as metadata (role, class name, positions) and the declared document_channel.parse
        # text is raised HERE, outside any exception handler, so the refusal has no exception context or cause.
        dp = ch['parse']
        parsed, failure = _rh_yaml_load_unique(d['text'], dp['tags'])
        if failure:
            _rh_doc_refuse(ch, key, '%s.%s' % (ch['at'], n), _rh_doc_parse_text(dp, rel, failure), rel)
        if n in prim:
            if not isinstance(parsed, dict) or e['root'] not in parsed or not isinstance(parsed[e['root']], dict):
                # codex-tick710 (same class as C1-DK-DIAGNOSTIC-KEY-DISCLOSURE): the parsed KEYS are not echoed; a top-level key
                # may be an aliased credential scalar. Only the kind of the parsed value is shown.
                _rh_doc_refuse(ch, key, '%s.%s.root' % (ch['at'], n), 'names %r; the admitted %r must be a mapping carrying it as a mapping (its keys are not shown)' % (e['root'], rel), _rh_kind(parsed))
            root = parsed[e['root']]
        else:
            if not isinstance(parsed, dict):
                _rh_doc_refuse(ch, key, '%s.%s' % (ch['at'], n), 'admitted %r must parse to a mapping' % (rel,), _rh_kind(parsed))
            root = parsed
        out[n] = {'rel': rel, 'sha256': sha, 'root': root}
        seen[rel] = n
    # records-staged-reader-01 (codex-tick740 / 747; supersedes records-dkjoin-02 C1-DKJ2-LM-723, NOT applied): the next
    # LEVEL of the ONE-level relation (OI-05 above) as [(name, rel)] -- the uncarried primaries, else the uncarried
    # dependents, whose parents are then all carried, digest-checked and strictly parsed above. Each rel is derived and
    # full-matched by rel_of BEFORE the reader builds a path and is unique against every carried and earlier level rel.
    # A derived rel is not yet a member: resolve.yml stats it, Git-admits it and adds it to the partial admission
    # before it reads; the membership and admitted-digest refusals above then run on the carried text before its
    # strict parse. Empty once every name is carried.
    nxt = list()
    for nn in order[len(carried):len(prim) if len(carried) < len(prim) else len(order)]:
        nr = rel_of(nn)
        seen[nr] = nn
        nxt.append((nn, nr))
    return True, out, order, nxt


class _RhDuplicateKey(Exception):
    """F-LIS12-DUPKEY (codex-tick702 mechanism 2; codex-tick710 C1-DK-DIAGNOSTIC-KEY-DISCLOSURE): one mapping of one
    admitted document repeats a key. Carries ONLY metadata: role (a document_channel.parse.diagnostics key), and for the
    repeated key node and the first one a (line, column, basis) triple -- 1-based position of the node definition and
    a document_channel.parse.bases key. Never the key, a value or source text: not in its attributes, not in its
    exception arguments. It never leaves _rh_yaml_load_unique."""

    def __init__(self, role, here, first):
        Exception.__init__(self, role, here, first)
        self.role = role
        (self.line, self.column, self.basis), (self.first_line, self.first_column, self.first_basis) = here, first


def _rh_yaml_unique_loader(tags):
    """F-LIS12-DUPKEY: the ONE loader class of the document-channel parse, used both by the role binding
    (_rh_yaml_roles_bound) and by the parse (_rh_yaml_load_unique), so the semantics bound are the semantics used.
    yaml.SafeLoader unchanged except:
    - construct_object records, before delegating, that construction has begun and the 1-based (line, column) of the
      node DEFINITION being entered (two ints; never the node, its tag or its text);
    - construct_document first judges the COMPOSED node structure, every mapping at every depth, before anything is
      constructed (SafeConstructor flattens merge keys IN PLACE, so a check during construction could not tell authored
      keys from merged ones): key identity = the constructed scalar key under Python equality, i.e. exactly what the
      resulting dict would collapse (1, 1.0 and true collide; '1' and 1 do not); the value key (bound to the parser's
      value semantics) is judged by its text, as flatten_mapping retags it to a string; pairs arriving through a merge
      are not authored in that mapping, an authored key overriding a merged one keeps YAML merge semantics, two merge
      keys in one mapping refuse; a node reached by more than one edge (an alias) reports basis aliased at its anchor
      definition, the repeated occurrence is not located; a non-scalar key keeps SafeConstructor's own refusal.
    The class is local: no global loader, constructor, resolver or PyYAML state is modified."""
    import yaml
    merge_tag, value_tag = tags['merge']['tag'], tags['value']['tag']

    class _UniqueKeyLoader(yaml.SafeLoader):
        lme_constructing = False
        lme_at = ()

        def construct_object(self, node, deep=False):
            self.lme_constructing = True
            if node.start_mark is not None:
                self.lme_at = (node.start_mark.line + 1, node.start_mark.column + 1)
            return yaml.SafeLoader.construct_object(self, node, deep)

        def construct_document(self, node):
            # pass 1: every parent-to-child edge; a node reached by more than one edge was reused through an alias
            edges, stack, visited = [], [node], set()
            while stack:
                cur = stack.pop()
                if id(cur) in visited:
                    continue
                visited.add(id(cur))
                if isinstance(cur, yaml.MappingNode):
                    kids = [x for pair in cur.value for x in pair]
                elif isinstance(cur, yaml.SequenceNode):
                    kids = list(cur.value)
                else:
                    continue
                edges.extend(id(x) for x in kids)
                stack.extend(kids)
            once, aliased = set(), set()
            for i in edges:
                if i in once:
                    aliased.add(i)
                once.add(i)
            # pass 2: every mapping, its keys judged before construction
            stack, visited = [node], set()
            while stack:
                cur = stack.pop()
                if id(cur) in visited:
                    continue
                visited.add(id(cur))
                if isinstance(cur, yaml.SequenceNode):
                    stack.extend(cur.value)
                if not isinstance(cur, yaml.MappingNode):
                    continue
                seen, merges = {}, []
                for kn, vn in cur.value:
                    stack.extend((kn, vn))
                    here = (kn.start_mark.line + 1, kn.start_mark.column + 1, 'aliased' if id(kn) in aliased else 'authored')
                    if kn.tag == merge_tag:
                        if merges:
                            raise _RhDuplicateKey('duplicate_merge', here, merges[0])
                        merges.append(here)
                    elif isinstance(kn, yaml.ScalarNode):
                        k = kn.value if kn.tag == value_tag else self.construct_object(kn)
                        if k in seen:
                            raise _RhDuplicateKey('duplicate_key', here, seen[k])
                        seen[k] = here
            return yaml.SafeLoader.construct_document(self, node)

    return _UniqueKeyLoader


def _rh_yaml_roles_bound(tags):
    """F-LIS12-DUPKEY (codex-tick712 C1-DK-TAG-ROLE-BINDING; codex-tick713): bind the declared merge / value roles
    (document_channel.parse.tags, shape already admitted) to THIS parser's semantics, not to whatever tag the resolver
    happens to give a declared spelling. Runs at every channel admission on a probe instance of the parse loader class
    over the EMPTY text, so a refusal precedes every document read, compose and construction:
    - resolver: each declared plain spelling, as a plain key, resolves to its declared tag;
    - merge: flatten_mapping, given a synthetic mapping whose only key carries the declared merge tag and whose value
      is a one-pair mapping, removes that key and splices in exactly that pair (only the merge tag does);
    - value: construct_scalar, given a synthetic mapping whose only key carries the declared value tag, returns that
      pair's value text (only the value tag does; any other tag raises ConstructorError, kept local).
    So {plain: 'true', tag: 'tag:yaml.org,2002:bool'} as the value role resolves but has no value semantics: refused.
    A swapped pair (merge / value tags exchanged) is refused on both roles. The synthetic scalars are the role NAMES;
    the refusal names only declaration words. Every handler here assigns a local; the refusal raises after."""
    import yaml
    probe = _rh_yaml_unique_loader(tags)('')
    unbound = set()
    try:
        for role in sorted(tags):
            if probe.resolve(yaml.ScalarNode, tags[role]['plain'], (True, False)) != tags[role]['tag']:
                unbound.add(role)
        mtag = probe.resolve(yaml.MappingNode, None, (True, False))
        word = dict((r, yaml.ScalarNode(probe.resolve(yaml.ScalarNode, r, (True, False)), r)) for r in sorted(tags))
        pair = (word['merge'], word['value'])
        merged = yaml.MappingNode(mtag, [(yaml.ScalarNode(tags['merge']['tag'], tags['merge']['plain']), yaml.MappingNode(mtag, [pair]))])
        probe.flatten_mapping(merged)
        if merged.value != [pair]:
            unbound.add('merge')
        holder = yaml.MappingNode(mtag, [(yaml.ScalarNode(tags['value']['tag'], tags['value']['plain']), word['value'])])
        try:
            got = probe.construct_scalar(holder)
        except yaml.YAMLError:
            got = holder
        if got != word['value'].value:
            unbound.add('value')
    finally:
        probe.dispose()
    if unbound:
        raise ValueError('lme: registry remote_harness_schema.document_channel.parse.tags %s must each name the tag this YAML parser resolves from the declared plain spelling AND that carries the role semantics of this parser (merge: spliced by flatten_mapping; value: read by construct_scalar); a spelling / tag pair that only resolves is not the role (no configurable duplicate bypass); got %r' % (
            sorted(unbound), dict((r, tags[r]) for r in sorted(unbound))))


def _rh_yaml_load_unique(text, tags):
    """F-LIS12-DUPKEY (codex-tick702 mechanism 2; codex-tick710; codex-tick712 C1-DK-CONSTRUCTOR-DIAGNOSTICS): parse ONE
    admitted document text exactly as yaml.safe_load does (SafeLoader resolver, tags, constructors and merge handling;
    yaml.load = Loader(text), get_single_data(), dispose()), with the duplicate judgement of _rh_yaml_unique_loader.
    tags is the admitted, role-bound document_channel.parse.tags. Returns (parsed, ()) or (None, failure); it raises
    nothing for the text. failure, metadata only:
    - (role, (line, column, basis), (first_line, first_column, first_basis)) for duplicate_key / duplicate_merge;
    - ('unparsable', class name, position) when reading / scanning / parsing / composing fails, position the
      parser problem mark or () when the exception has none (a ReaderError has none);
    - ('unconstructable', class name, position) when any exception is raised once construction has begun: a
      ConstructorError, or a native exception of a scalar constructor (bool KeyError, int / float ValueError or
      IndexError, timestamp AttributeError or ValueError, and any other Exception subclass), position the problem
      mark when there is one, else the definition of the node construction last entered.
    Only the class NAME and integer positions leave a handler; the exception (its args, message and traceback, which
    holds the walk locals with constructed keys) is released when the handler ends. Not converted: BaseException
    subclasses that are not Exception (KeyboardInterrupt, SystemExit, GeneratorExit)."""
    import yaml
    loader, parsed, failure = (), None, ()
    try:
        loader = _rh_yaml_unique_loader(tags)(text)
        parsed = loader.get_single_data()
    except _RhDuplicateKey as dup:
        failure = (dup.role, (dup.line, dup.column, dup.basis), (dup.first_line, dup.first_column, dup.first_basis))
    except Exception as exc:
        mark = exc.problem_mark if isinstance(exc, yaml.MarkedYAMLError) else ()
        built = bool(loader) and loader.lme_constructing
        at = (mark.line + 1, mark.column + 1) if mark else (loader.lme_at if built else ())
        failure = ('unconstructable' if built else 'unparsable', type(exc).__name__, at)
    finally:
        if loader:
            loader.dispose()
    return (None, failure) if failure else (parsed, ())


def _rh_doc_parse_text(dp, rel, failure):
    """F-LIS12-DUPKEY: the declared document_channel.parse diagnostic for one _rh_yaml_load_unique failure, filled with
    the admitted rel and the failure's class name / position / basis metadata only. The role literals are
    document_channel.parse.diagnostics keys (registry keys, the convention of :2476-2477)."""
    role = failure[0]
    if role in ('duplicate_key', 'duplicate_merge'):
        (line, column, basis), (first_line, first_column, first_basis) = failure[1], failure[2]
        return dp['diagnostics'][role].format(rel=rel, line=line, column=column, basis=dp['bases'][basis],
                                              first_line=first_line, first_column=first_column, first_basis=dp['bases'][first_basis])
    at = failure[2]
    where = dp['positions']['marked'].format(line=at[0], column=at[1]) if at else dp['positions']['unmarked'].format()
    return dp['diagnostics'][role].format(rel=rel, error=failure[1], where=where)


def _rh_projection_order(projs):
    """F05S2-PROJECTION-DEPENDENCY-ORDER: every policy_projections entry declares `after` (a list of OTHER projection
    names it reads, [] for none); the projections apply in topological order, ties broken by name. An unknown, self
    or duplicated name, or a cycle, refuses. No name special-case and no reliance on lexical order."""
    for name in sorted(projs):
        if not isinstance(projs[name], dict) or 'after' not in projs[name]:
            raise ValueError('lme: registry policy_projections.%s declares no after (every projection states its order; [] is explicit); got %r' % (name, projs[name]))
        aft = projs[name]['after']
        if not isinstance(aft, list) or any(not isinstance(a, str) or a == name or a not in projs for a in aft) or len(set(aft)) != len(aft):
            raise ValueError('lme: registry policy_projections.%s.after must be a list of distinct OTHER projection names %s; got %r' % (name, sorted(projs), aft))
    order, done = [], set()
    while len(order) < len(projs):
        ready = sorted(n for n in projs if n not in done and set(projs[n]['after']) <= done)
        if not ready:
            raise ValueError('lme: registry policy_projections.*.after is cyclic among %s' % (sorted(set(projs) - done),))
        order.append(ready[0])
        done.add(ready[0])
    return order


def _rh_doc_root(name, pj, docs, key):
    """The admitted root of the document a projection reads (`document` names a document_channel entry)."""
    if pj['document'] not in docs:
        raise ValueError('lme: registry policy_projections.%s.document %r names no admitted document_channel entry (%s, remote_harness_schema.document_channel.at); admitted %s' % (
            name, pj['document'], key, sorted(docs)))
    return docs[pj['document']]['root']


def _rh_doc_value(root, path, label, field, docname):
    """label = the registry declaration that reads it (policy_projections.<name> | published_views.<name>)."""
    f, v = _rh_get(root, path)
    if not f:
        raise ValueError('lme: registry %s.%s: document %s path %s is absent' % (label, field, docname, path))
    return v


def _rh_eg_generated(label, pj, root, pol, key, relp):
    """The ONE generated selection (B identity): members whose <identity.marker_key> equals the value at
    <identity.marker_from>; output rel = identity.output_rel_parts mapped through the struct role words member_dir ->
    member directory, member_file -> member file, joined by the policy value at identity.separator_from.
    F05-S4 ROSTER-NONPLAYBOOK (Codex546 generated_outputs; OPEN-A / OD-BRR-14 / U-SEAM01): identity.rendered_from is the
    B pointer of the SECOND generated marker word -- a generated output that is RENDERED (by a declared render, e.g.
    the genesis entry and its producer) and NOT entry-constructed: no head, no plays, no importer guard closure. Both
    selections come from this ONE function (one identity, one output-rel law; a rel is unique across both); the
    rendered word must differ from the entry word. label = the registry declaration that reads it.
    Returns ({output rel: (dir, file, member)} entry-constructed, members, sep, {output rel: (dir, file, member)} rendered)."""
    ident = _rh_doc_value(root, pj['identity'], label, 'identity', pj['document'])
    members = _rh_doc_value(root, pj['members'], label, 'members', pj['document'])
    if not isinstance(ident, dict) or set(ident) != {'marker_key', 'marker_from', 'rendered_from', 'separator_from', 'output_rel_parts'} \
            or not isinstance(ident['output_rel_parts'], list) or not ident['output_rel_parts'] \
            or any(p not in ('member_dir', 'member_file') for p in ident['output_rel_parts']):
        raise ValueError('lme: registry %s.identity: document %s %s must be {marker_key, marker_from, rendered_from, separator_from, output_rel_parts ⊆ [member_dir, member_file]}; got %r' % (label, pj['document'], pj['identity'], ident))
    marker = _rh_doc_value(root, ident['marker_from'], label, 'identity.marker_from', pj['document'])
    rmarker = _rh_doc_value(root, ident['rendered_from'], label, 'identity.rendered_from', pj['document'])
    fs, sep = _rh_get(pol, ident['separator_from'])
    if not isinstance(marker, str) or not marker or not isinstance(rmarker, str) or not rmarker or rmarker == marker \
            or not fs or not isinstance(sep, str) or not sep:
        raise ValueError('lme: registry %s: markers (%s / %s, distinct) and separator (%s.%s) must be non-empty strings; got %r / %r / %r' % (
            label, ident['marker_from'], ident['rendered_from'], key, ident['separator_from'], marker, rmarker, sep if fs else '<absent>'))
    if not isinstance(members, dict) or not members or any(not isinstance(m, dict) or not m for m in members.values()):
        raise ValueError('lme: registry %s: document %s %s must map member directories to non-empty member mappings; got %r' % (label, pj['document'], pj['members'], members))
    gen, rendered = {}, {}
    for d in sorted(members):
        for f in sorted(members[d]):
            ent = members[d][f]
            if not isinstance(ent, dict) or ident['marker_key'] not in ent:
                raise ValueError('lme: registry %s: document %s %s.%s.%s carries no %r (the generated marker)' % (label, pj['document'], pj['members'], d, f, ident['marker_key']))
            if ent[ident['marker_key']] not in (marker, rmarker):
                continue
            rel = sep.join(d if p == 'member_dir' else f for p in ident['output_rel_parts'])
            if not relp.fullmatch(rel) or rel in gen or rel in rendered:
                raise ValueError('lme: registry %s: generated member %r is not a unique repository-relative path' % (label, rel))
            if ent[ident['marker_key']] == rmarker and set(ent) != {ident['marker_key']}:
                raise ValueError('lme: registry %s: document %s %s.%s.%s is a rendered output (%s) and must carry exactly {%s} (no entry construction: no head, no plays); got %r' % (
                    label, pj['document'], pj['members'], d, f, ident['rendered_from'], ident['marker_key'], sorted(ent)))
            (gen if ent[ident['marker_key']] == marker else rendered)[rel] = (d, f, ent)
    return gen, members, sep, rendered


def _rh_pj_entry_importers(name, pj, out, root, active, docs, schema, key, relp, ptext):
    """S3-SEAM-06 / OD-S2-01 a / OD-S2-07 / OD-S3-03 a: {<executable rel>: sorted closure}.
    RUNNER PART (every resolve): each <runners>.<r> declares <runner_key> (the playbook rel) and <requires_key> (the
      REQUIRED declared dependency list; [] is an explicit statement): importers[playbook] = sorted(requires).
      Each runner also declares <runner_transport.key>, its ingress transport word, equal to the word of its
      declared launch purpose (C1 s11 L11-03; records-c1-framework-28).
    DISPATCH ADMISSION (every resolve): <dispatch> = {mode[, authored]}; mode is one of the words of the policy
      mapping <dispatch_modes> {generation, declared, none} (F05-S4 SC-MM-20 b: declared ONCE in the policy, read by
      the loader and the seed alike; the registry field is the pointer); mode generation <=> published view `when` active; declared: inactive only, authored REQUIRED; generation:
      authored OPTIONAL (codex-tick543 OD-BRR-08: declared authored closures alongside the generated entries; an
      authored key that is also a generated / B / runner key is conflicting ownership and refuses as a repeated
      importer key); none: inactive only, no authored entry (run-local runners only). A present authored is a
      non-empty mapping {playbook rel: [closure items]}.
    B PART (active only): every <members> entry and every <entries> key under the declaration directory; closure =
      the guard members (relativity repository | entry_dir) + for an <entries> key its <closure>.members items (entry
      relativity) + every <route_includes> rel (repository). A closure rel must not be its own key; an entry_closure
      rel must not restate a guard member, a route_includes rel or a <common> member (declared once).
    CLOSURE ITEMS (requires, authored and entry_closure lists; codex-tick543 OD-BRR-03 / OD-BRR-09): a rel string, or a
      ONE-key typed reference whose key is a value of the registry field reference_keys:
        {<reference_keys.value>: <dotted policy path>}: every segment fully matches patterns.<segment_pattern>, the path
          is declared in the policy being projected and is not under a leaf another projection writes unless that
          projection is listed in `after`, and its value fully matches the rel pattern; the value is
          REPOSITORY-relative (never joined to an entry directory). Resolved BEFORE every restated / common check.
        {<reference_keys.closure>: <importer key>}: the referenced importer key AND its complete closure join this
          closure; expansion is deterministic (sorted) and recursive; an unknown key (a B key while the generation
          view is inactive included), a self reference or a cycle refuses; a rel the composition already supplies
          must not be restated by a rel item (declared once).
    Every key and closure member full-matches the rel pattern; a key declared twice refuses."""
    runners, common = _rh_get(out, pj['runners']), _rh_get(out, pj['common'])
    if not runners[0] or not isinstance(runners[1], dict) or not runners[1]:
        raise ValueError('lme: %s.%s must be a declared non-empty mapping of runners (policy_projections.%s)' % (key, pj['runners'], name))
    if not common[0] or not isinstance(common[1], list) or any(not isinstance(c, str) or not relp.fullmatch(c) for c in common[1]):
        raise ValueError('lme: %s.%s must be a list of repository-relative paths (policy_projections.%s); got %r' % (key, pj['common'], name, common[1] if common[0] else '<absent>'))
    common = set(common[1])
    refk = pj['reference_keys']
    if not isinstance(refk, dict) or set(refk) != {'value', 'closure'} or any(not isinstance(v, str) or not v for v in refk.values()) \
            or refk['value'] == refk['closure']:
        raise ValueError('lme: registry policy_projections.%s.reference_keys must map exactly value / closure to distinct non-empty item keys; got %r' % (name, refk))
    if pj['segment_pattern'] not in _rh_patterns(schema)[0]:
        raise ValueError('lme: registry policy_projections.%s.segment_pattern %r must name a declared contract_admission.patterns entry' % (name, pj['segment_pattern']))
    segp = _rh_patterns(schema)[0][pj['segment_pattern']]
    # MR03-RENDERED-SOURCE-BOOTSTRAP (DEP-MR03-LOADER-01; codex-tick606 / codex-tick610): RENDERED DISPATCH. A rendered
    # output is never an importer key (ROSTER-NONPLAYBOOK, below); its ONE dispatch owner is its render declaration: each
    # rendered_dispatch.outputs policy node carries <output_field> (the rendered playbook rel) and <requires_key> (its
    # closure items). Admitted here on every resolve against the ONE rendered-output authority: the entry_generation view
    # naming this projection as its importers (rendered.outputs / output_fields.output / when_present).
    rd = pj['rendered_dispatch']
    if not isinstance(rd, dict) or set(rd) != {'outputs', 'output_field', 'requires_key', 'to'} or not isinstance(rd['outputs'], list) or not rd['outputs'] \
            or len(set(map(repr, rd['outputs']))) != len(rd['outputs']) \
            or any(not isinstance(x, str) or not x or not all(segp.fullmatch(s) for s in x.split('.')) for x in rd['outputs']) \
            or any(not isinstance(rd[f], str) or not segp.fullmatch(rd[f]) for f in ('output_field', 'requires_key', 'to')) or rd['to'] == pj['to']:
        raise ValueError('lme: registry policy_projections.%s.rendered_dispatch must be exactly {outputs: [distinct dotted policy paths, segments fully matching patterns.%s], output_field, requires_key, to: <one segment, not %r>}; got %r' % (
            name, pj['segment_pattern'], pj['to'], rd))
    if 'published_views' not in schema or not isinstance(schema['published_views'], dict):
        raise ValueError('lme: registry remote_harness_schema.published_views must be a mapping (policy_projections.%s.rendered_dispatch authority); got %r' % (name, sorted(schema)))
    owners = sorted(n for n, w in schema['published_views'].items() if isinstance(w, dict) and 'kind' in w and w['kind'] == 'entry_generation' and 'importers' in w and w['importers'] == name)
    vr = schema['published_views'][owners[0]]['rendered'] if len(owners) == 1 and 'rendered' in schema['published_views'][owners[0]] else None   # absent -> refused below
    if not isinstance(vr, dict) or any(f not in vr for f in ('outputs', 'output_fields', 'when_present')) or not isinstance(vr['outputs'], list) \
            or not isinstance(vr['output_fields'], dict) or 'output' not in vr['output_fields'] or not isinstance(vr['when_present'], str) \
            or any(x not in vr['outputs'] for x in rd['outputs']) or rd['output_field'] != vr['output_fields']['output']:
        raise ValueError('lme: registry policy_projections.%s.rendered_dispatch must be owned by EXACTLY ONE published_views entry_generation view naming it as importers (found %s) whose rendered.outputs (the ONE rendered-output authority) include every node %r and whose rendered.output_fields.output equals output_field %r; got %r' % (
            name, owners, rd['outputs'], rd['output_field'], vr))
    imp, comp, expl, src = {}, {}, {}, {}
    # value_of must not read a leaf another projection writes unless that projection is in `after` (applied before
    # this one by _rh_projection_order); otherwise the value would depend on the name tie-break (no lexical reliance)
    projs = schema['policy_projections']
    unordered = []
    for n in sorted(projs):
        if n in pj['after']:
            continue
        o = projs[n]
        if o['kind'] == 'lookup_merge':
            fsel, sel = _rh_get(out, '%s.%s' % (o['at'], o['from']))
            unordered += [('%s.%s.%s' % (o['at'], o['to'], r), n) for r in (sorted(sel) if fsel and isinstance(sel, dict) else [])]
        else:
            unordered.append(('%s.%s' % (o['at'], o['to']), n))
            unordered += [('%s.%s' % (o['at'], s), n) for s in _rh_pj_secondary(n, o)]   # MR03: secondary destinations

    # MR03 J-MR03-COMMON-POLICY-LITERALS (codex-tick612): every policy path listed at <common_refs> SELECTS a common
    # member: its value in the policy being projected (the RESOLVED, override-LAST policy) is a <common> element (a
    # membership relation, no filename literal). A relocation that moves the selection without its members_rel entry
    # refuses here, before any consumer hashes, reads or renders the selected path; a coherent relocation passes.
    fcr, crefs = _rh_get(out, pj['common_refs'])
    if not fcr or not isinstance(crefs, list) or not crefs or len(set(map(repr, crefs))) != len(crefs):
        raise ValueError('lme: %s.%s must be a non-empty list of distinct policy paths (policy_projections.%s.common_refs); got %r' % (
            key, pj['common_refs'], name, crefs if fcr else '<absent>'))
    for i, cp in enumerate(crefs):
        hit = sorted(n for d, n in unordered if isinstance(cp, str) and (cp == d or cp.startswith(d + '.')))
        fv, cv = _rh_get(out, cp) if isinstance(cp, str) and cp and all(segp.fullmatch(s) for s in cp.split('.')) else (False, None)
        if hit or not fv or not isinstance(cv, str) or cv not in common:
            raise ValueError('lme: %s.%s[%d] (policy_projections.%s.common_refs): policy path %r must be declared (not a leaf RESOLVED by %s) and select a %s.%s member; resolved value %r (relocate the selected file and its %s entry together)' % (
                key, pj['common_refs'], i, name, cp, hit, key, pj['common'], cv if fv else '<absent>', pj['common']))

    def items(lst, where, joiner):
        """-> (rels, closure refs): rel strings (joined by `joiner` when given) and resolved value references."""
        rels, refs = [], []
        for i, x in enumerate(lst):
            if isinstance(x, str):
                rels.append(joiner(x) if joiner is not None else x)
                continue
            rk = next(iter(x)) if isinstance(x, dict) and len(x) == 1 else None
            if rk == refk['value']:
                p = x[rk]
                hit = sorted(n for d, n in unordered if isinstance(p, str) and (p == d or p.startswith(d + '.')))
                if hit:
                    raise ValueError('lme: %s[%d] (policy_projections.%s): {%s: %r} reads a leaf RESOLVED by policy_projections %s, which is not listed in its after %r (declare the order; no lexical reliance)' % (
                        where, i, name, rk, p, hit, pj['after']))
                fv, v = _rh_get(out, p) if isinstance(p, str) and p and all(segp.fullmatch(s) for s in p.split('.')) else (False, None)
                if not fv or not isinstance(v, str) or not relp.fullmatch(v):
                    raise ValueError('lme: %s[%d] (policy_projections.%s): {%s: %r} must name a declared %s path (segments fully matching patterns.%s) whose value fully matches patterns.%s %r; got %r' % (
                        where, i, name, rk, p, key, pj['segment_pattern'], pj['rel_pattern'], ptext[pj['rel_pattern']], v if fv else '<absent or malformed path>'))
                rels.append(v)
            elif rk == refk['closure'] and isinstance(x[rk], str) and relp.fullmatch(x[rk]):
                refs.append(x[rk])
            else:
                raise ValueError('lme: %s[%d] (policy_projections.%s): a closure item is a rel string, {%s: <policy path>} or {%s: <importer key>}; got %r' % (
                    where, i, name, refk['value'], refk['closure'], x))
        return rels, refs

    def add(k, deps, refs, where, explicit):
        bad = sorted(repr(x) for x in [k] + list(deps) if not isinstance(x, str) or not relp.fullmatch(x))
        if bad or k in imp or k in deps or k in refs or len(set(refs)) != len(refs):
            raise ValueError('lme: %s (policy_projections.%s): executable %r closure must be distinct repository-relative paths fully matching patterns.%s %r, not repeat an importer key (one owner per key) and not contain or compose itself; bad %r, repeated %r, composed %r' % (
                where, name, k, pj['rel_pattern'], ptext[pj['rel_pattern']], bad, k in imp, refs))
        imp[k] = sorted(set(deps))
        comp[k] = sorted(refs)
        expl[k] = set(explicit)
        src[k] = where

    def common_restated(rels, where):
        restated = sorted(set(rels) & common)
        if restated:
            raise ValueError('lme: %s restates %s.%s members %s (declared once; policy_projections.%s)' % (where, key, pj['common'], restated, name))

    def composed():
        full = {}
        for k0 in sorted(imp):
            stack = [(k0, False)]
            path = []
            while stack:
                k, done = stack.pop()
                if done:
                    path.pop()
                    acc = set(imp[k])
                    for r in comp[k]:
                        acc |= {r} | set(full[r])
                    dup = sorted(expl[k] & set(x for r in comp[k] for x in [r] + full[r]))
                    if dup:
                        raise ValueError('lme: %s (policy_projections.%s): importer %r restates %s, already supplied by its composed closures %s (declared once)' % (src[k], name, k, dup, comp[k]))
                    full[k] = sorted(acc)
                    continue
                if k in full:
                    continue
                path.append(k)
                stack.append((k, True))
                for r in reversed(comp[k]):
                    if r not in imp:
                        raise ValueError('lme: %s (policy_projections.%s): importer %r composes %r, which is no importer key (a B entry composes only while published view %s is active); importers %s' % (
                            src[k], name, k, r, pj['when'], sorted(imp)))
                    if r in path:
                        raise ValueError('lme: %s (policy_projections.%s): importer %r composes %r: closure composition is cyclic (%s)' % (src[k], name, k, r, path + [r]))
                    if r not in full:
                        stack.append((r, False))
        return full
    # C1 s11 L11-02 (records-c1-framework-28; codex-tick822 B-E1): the RUNNER TRANSPORT pointers. key: the runner
    # field naming its declared ingress transport; words: the policy mapping launcher -> transport word; launcher:
    # the words key of the run-local launcher; purposes: the record-free launch rows keyed by playbook rel;
    # purpose_transport: the row field holding that purpose's transport word.
    rt = pj['runner_transport']
    if not isinstance(rt, dict) or set(rt) != {'key', 'words', 'launcher', 'purposes', 'purpose_transport'} \
            or any(not isinstance(rt[f], str) or not rt[f] or not all(segp.fullmatch(s) for s in rt[f].split('.')) for f in rt):
        raise ValueError('lme: registry policy_projections.%s.runner_transport must be exactly {key, words, launcher, purposes, purpose_transport} of dotted names whose segments fully match patterns.%s; got %r' % (
            name, pj['segment_pattern'], rt))
    fw, tw = _rh_get(out, rt['words'])
    fp, tp = _rh_get(out, rt['purposes'])
    if not fw or not isinstance(tw, dict) or not tw or any(not isinstance(v, str) or not v for v in tw.values()) \
            or len(set(tw.values())) != len(tw) or rt['launcher'] not in tw or not fp or not isinstance(tp, dict):
        raise ValueError('lme: %s.%s must be a non-empty mapping of distinct non-empty transport words holding launcher %r, and %s.%s a mapping (policy_projections.%s.runner_transport); got %r / %r' % (
            key, rt['words'], rt['launcher'], key, rt['purposes'], name, tw if fw else '<absent>', tp if fp else '<absent>'))
    for r in sorted(runners[1]):
        rr = runners[1][r]
        if not isinstance(rr, dict) or pj['runner_key'] not in rr or pj['requires_key'] not in rr or not isinstance(rr[pj['requires_key']], list) \
                or len(set(map(repr, rr[pj['requires_key']]))) != len(rr[pj['requires_key']]):
            raise ValueError('lme: %s.%s.%s must declare %s and %s (a list of distinct closure items; [] is explicit) (policy_projections.%s); got %r' % (
                key, pj['runners'], r, pj['runner_key'], pj['requires_key'], name, rr))
        where = '%s.%s.%s.%s' % (key, pj['runners'], r, pj['requires_key'])
        rels, refs = items(rr[pj['requires_key']], where, None)
        common_restated(rels, where)
        add(rr[pj['runner_key']], rels, refs, where, rels)
        # C1 s11 L11-03 (records-c1-framework-28): the runner's declared transport word equals the word of its
        # declared launch purpose: a record-free launch row's transport when its playbook is such a row, otherwise
        # the run-local launcher's word. No inference from supplied variables.
        want, why = tw[rt['launcher']], 'the %s launcher' % (rt['launcher'],)
        if rr[pj['runner_key']] in tp:
            pr = tp[rr[pj['runner_key']]]
            if not isinstance(pr, dict) or rt['purpose_transport'] not in pr:
                raise ValueError('lme: %s.%s[%r] must carry %s (policy_projections.%s.runner_transport); got %r' % (
                    key, rt['purposes'], rr[pj['runner_key']], rt['purpose_transport'], name, pr))
            want, why = pr[rt['purpose_transport']], 'its record-free launch row'
        if rt['key'] not in rr or not isinstance(rr[rt['key']], str) or rr[rt['key']] != want:
            raise ValueError('lme: %s.%s.%s.%s %r does not match the declared launch purpose of %r (expected %r: %s) (policy_projections.%s)' % (
                key, pj['runners'], r, rt['key'], rr[rt['key']] if rt['key'] in rr else '<absent>', rr[pj['runner_key']], want, why, name))
    fd, da = _rh_get(out, pj['dispatch'])
    fm, modes = _rh_get(out, pj['dispatch_modes'])
    if not fm or not isinstance(modes, dict) or set(modes) != {'generation', 'declared', 'none'} or len(set(modes.values())) != 3 \
            or any(not isinstance(v, str) or not v for v in modes.values()):
        raise ValueError('lme: %s.%s (registry policy_projections.%s.dispatch_modes; SC-MM-20: the ONE home of the dispatch mode words) must map exactly generation/declared/none to distinct non-empty words; got %r' % (
            key, pj['dispatch_modes'], name, modes if fm else '<absent>'))
    mode = da['mode'] if fd and isinstance(da, dict) and 'mode' in da else None   # absent -> refused below
    want = [{'mode', 'authored'}] if mode == modes['declared'] else [{'mode'}, {'mode', 'authored'}] if mode == modes['generation'] else [{'mode'}]
    if not fd or not isinstance(da, dict) or mode not in modes.values() or set(da) not in want:
        raise ValueError('lme: %s.%s must be {mode: one of %s} + authored (required when mode is %r, optional when %r, refused when %r) (policy_projections.%s; OD-S2-04, OD-BRR-08); got %r' % (
            key, pj['dispatch'], sorted(modes.values()), modes['declared'], modes['generation'], modes['none'], name, da if fd else '<absent>'))
    if (mode == modes['generation']) != active:
        raise ValueError('lme: %s.%s.mode %r contradicts published view %s (active %r): mode %r exactly while the generation contract is active (policy_projections.%s)' % (
            key, pj['dispatch'], mode, pj['when'], active, modes['generation'], name))
    if 'authored' in da:
        au = da['authored']
        if not isinstance(au, dict) or not au or any(not isinstance(v, list) for v in au.values()):
            raise ValueError('lme: %s.%s.authored must be a non-empty mapping {playbook rel: [closure items]} (policy_projections.%s); got %r' % (key, pj['dispatch'], name, au))
        for k in sorted(au):
            where = '%s.%s.authored.%s' % (key, pj['dispatch'], k)
            rels, refs = items(au[k], where, None)
            common_restated(rels, where)
            add(k, rels, refs, where, rels)
    if not active:
        return composed(), {}   # MR03: no rendered dispatch row while the generation contract is inactive
    rel_doc = docs[pj['document']]['rel']
    lab = 'policy_projections.%s' % (name,)
    gen, members, sep, rendered = _rh_eg_generated(lab, pj, root, out, key, relp)
    guard = _rh_doc_value(root, pj['guard'], lab, 'guard', pj['document'])
    relv = _rh_doc_value(root, pj['relativity_from'], lab, 'relativity_from', pj['document'])
    entries = _rh_doc_value(root, pj['entries'], lab, 'entries', pj['document'])
    eclos = _rh_doc_value(root, pj['closure'], lab, 'closure', pj['document'])
    rincs = _rh_doc_value(root, pj['route_includes'], lab, 'route_includes', pj['document'])
    words = ('repository', 'entry_dir')
    psm = guard['protected_set_members'] if isinstance(guard, dict) and 'protected_set_members' in guard else None   # absent -> refused below
    if not isinstance(psm, list) or not psm or any(not isinstance(m, str) or m not in guard or not isinstance(guard[m], str) for m in psm) \
            or not isinstance(relv, dict) or sorted(relv) != sorted(psm) or any(v not in words for v in relv.values()):
        raise ValueError('lme: policy_projections.%s: document %s %s.protected_set_members must name string members and %s must map exactly those to %s; got %r / %r' % (
            name, pj['document'], pj['guard'], pj['relativity_from'], list(words), psm, relv))
    if not isinstance(entries, dict) or not entries or not isinstance(eclos, dict) or set(eclos) != {'relativity', 'members'} \
            or eclos['relativity'] not in words or not isinstance(eclos['members'], dict) or sorted(eclos['members']) != sorted(entries) \
            or any(not isinstance(v, list) for v in eclos['members'].values()):
        raise ValueError('lme: policy_projections.%s: document %s %s must be {relativity: one of %s, members: {<each %s key>: [rels]}} (BR-08, OD-S2-07); got %r' % (
            name, pj['document'], pj['closure'], list(words), pj['entries'], eclos))
    if not isinstance(rincs, list) or any(not isinstance(x, dict) or 'rel' not in x or not isinstance(x['rel'], str) for x in rincs):
        raise ValueError('lme: policy_projections.%s: document %s %s must be a list of {rel, ...} entries; got %r' % (name, pj['document'], pj['route_includes'], rincs))
    rinc = sorted(x['rel'] for x in rincs)
    ddir = rel_doc.rsplit(sep, 1)[0] if sep in rel_doc else ''
    if not ddir:
        raise ValueError('lme: policy_projections.%s: declaration rel %r has no directory under separator %r' % (name, rel_doc, sep))

    def join(base, rel, word):
        return rel if word == 'repository' else base + sep + rel

    # F05-S4 ROSTER-NONPLAYBOOK: a RENDERED member (identity.rendered_from) is no B-guarded entry: it is not an importer
    # key and carries no guard closure (its dispatch, if any, is its render owner's declaration).
    keyed = [(d + sep + f, d, None) for d in sorted(members) for f in sorted(members[d]) if (d + sep + f) not in rendered] \
        + [(ddir + sep + e, ddir, e) for e in sorted(entries)]
    # ... and its ONE owner is its render declaration: a runner or authored importer key naming a rendered rel refuses
    # (conflicting ownership, OD-BRR-08 -- formerly refused as a repeated B key, so it never passes silently)
    owned = sorted(k for k in imp if k in rendered)
    if owned:
        raise ValueError('lme: policy_projections.%s: %s.%s / %s.%s.authored key(s) %s are rendered outputs of document %s (%s): a rendered output is never a runner or authored importer key (one owner per key)' % (
            name, key, pj['runners'], key, pj['dispatch'], owned, pj['document'], rel_doc))
    for k, edir, ent in keyed:
        gclos = [join(edir, guard[m], relv[m]) for m in psm]
        deps, refs, extra = list(gclos), [], []
        if ent is not None:
            where = 'document %s %s.members.%s' % (pj['document'], pj['closure'], ent)
            extra, refs = items(eclos['members'][ent], where, lambda x, edir=edir: join(edir, x, eclos['relativity']))
            restated = sorted(set(extra) & (set(gclos) | set(rinc) | common))
            if restated:
                raise ValueError('lme: policy_projections.%s: %s restates %s (a guard member, a %s rel or a %s.%s member is declared once)' % (
                    name, where, restated, pj['route_includes'], key, pj['common']))
            deps = deps + extra + rinc
        add(k, deps, refs, '%s (%s)' % (where, rel_doc) if ent is not None else 'document %s (%s)' % (pj['document'], rel_doc), extra)
    full = composed()
    # MR03-RENDERED-SOURCE-BOOTSTRAP (DEP-MR03-LOADER-01): one rendered dispatch row per rendered_dispatch.outputs node,
    # published only while the rendered kind is active (its authority's when_present; inactive: {} -- omitted as the
    # rendered roster rows are). <output_field> must be a B rendered member of this document (never an importer key:
    # `owned` above). <requires_key> is admitted EXACTLY as runner requires (codex-tick612 F2): DISTINCT RAW items, then
    # items + common_restated, then the RESOLVED rels deduplicated (a literal and a {value_of} naming the same rel are
    # one member); a closure_of item composes an importer key under the composed() declared-once rule; [] is explicit.
    # codex-tick612 F4: the rendered root must not appear ANYWHERE in its completed expanded closure (direct or through
    # a composed importer that itself names it).
    rrows = {}
    for ro in (rd['outputs'] if _rh_get(out, vr['when_present'])[0] else []):
        fo, onode = _rh_get(out, ro)
        rrel = onode[rd['output_field']] if fo and isinstance(onode, dict) and rd['output_field'] in onode else None   # absent -> refused below
        rreq = onode[rd['requires_key']] if fo and isinstance(onode, dict) and rd['requires_key'] in onode else None   # absent -> refused below
        if not isinstance(rrel, str) or not relp.fullmatch(rrel) or rrel not in rendered or rrel in full or rrel in rrows \
                or not isinstance(rreq, list) or len(set(map(repr, rreq))) != len(rreq):
            raise ValueError('lme: %s.%s (policy_projections.%s.rendered_dispatch): %s must be a rendered output of document %s (%s; rendered %s), dispatched once and never an importer key, and %s a list of distinct closure items ([] is explicit); got %r / %r' % (
                key, ro, name, rd['output_field'], pj['document'], rel_doc, sorted(rendered), rd['requires_key'], rrel, rreq))
        where = '%s.%s.%s' % (key, ro, rd['requires_key'])
        rels, refs = items(rreq, where, None)
        common_restated(rels, where)
        badr = sorted(repr(x) for x in rels if not relp.fullmatch(x))
        unknown = sorted(r for r in refs if r not in full)
        dup = sorted(set(rels) & set(x for r in refs if r in full for x in [r] + full[r]))
        clos = sorted(set(rels) | set(x for r in refs if r in full for x in [r] + full[r]))
        if badr or unknown or dup or rrel in clos or len(set(refs)) != len(refs):
            raise ValueError('lme: %s (policy_projections.%s.rendered_dispatch): rendered playbook %r closure must be repository-relative paths fully matching patterns.%s %r, compose only importer keys, restate nothing its composed closures supply (declared once) and never contain the rendered playbook itself, directly or in its expanded closure; bad %r, unknown %r, restated %r, self %r' % (
                where, name, rrel, pj['rel_pattern'], ptext[pj['rel_pattern']], badr, unknown, dup, rrel in clos))
        rrows[rrel] = clos
    return full, rrows


def _rh_pj_entry_bodies(name, pj, out, root, docs, key, relp, ptext, resolved, schema):
    """{<importer rel>: {<generated entry rel>: [[body, sha256], ...]}} (F05-S4 transitive obligations): for every
    importer, each generated member in {importer} + its composed closure, keyed by its generated-entry identity (output
    rel), with that member's declared plays in declared order; bodies.from and
    bodies.sha256_from (BR-04) are leaves of one plays list. Every body full-matches the rel pattern and is declared
    once; every sha fully matches the value at digest_pattern; every key is an importer of projection <importers>
    (which must be in `after`)."""
    if pj['importers'] not in pj['after'] or pj['importers'] not in resolved:
        raise ValueError('lme: registry policy_projections.%s.importers %r must name a projection listed in its after %r' % (name, pj['importers'], pj['after']))
    # MR03 (DEP-MR03-LOADER-01): <importers> must be the entry_importers projection whose rendered dispatch rows are published
    ipj = schema['policy_projections'][pj['importers']]
    if ipj['kind'] != 'entry_importers' or not _rh_get(out, '%s.%s' % (ipj['at'], ipj['rendered_dispatch']['to']))[0] \
            or not isinstance(_rh_get(out, '%s.%s' % (ipj['at'], ipj['rendered_dispatch']['to']))[1], dict):
        raise ValueError('lme: registry policy_projections.%s.importers %r must name the entry_importers projection whose rendered_dispatch rows are published (MR03)' % (name, pj['importers']))
    lab = 'policy_projections.%s' % (name,)
    gen, _m, _s, _r = _rh_eg_generated(lab, pj, root, out, key, relp)
    bod = _rh_doc_value(root, pj['bodies'], lab, 'bodies', pj['document'])
    dpat = _rh_doc_value(root, pj['digest_pattern'], lab, 'digest_pattern', pj['document'])
    if not isinstance(bod, dict) or not {'from', 'sha256_from'} <= set(bod) or any(not isinstance(bod[k], str) or bod[k].count('.') != 1 for k in ('from', 'sha256_from')) \
            or bod['from'].split('.')[0] != bod['sha256_from'].split('.')[0] or not isinstance(dpat, str):
        raise ValueError('lme: policy_projections.%s: document %s %s must declare from and sha256_from as leaves of ONE list (<list>.<leaf>), and %s a pattern; got %r / %r' % (
            name, pj['document'], pj['bodies'], pj['digest_pattern'], bod, dpat))
    lst, bl, sl = bod['from'].split('.')[0], bod['from'].split('.')[1], bod['sha256_from'].split('.')[1]
    res, seen = {}, {}
    for k in sorted(gen):
        if k not in resolved[pj['importers']]:
            raise ValueError('lme: policy_projections.%s: generated member %r is not an importer of projection %s' % (name, k, pj['importers']))
        plays = gen[k][2][lst] if isinstance(gen[k][2], dict) and lst in gen[k][2] else None   # absent -> refused below
        if not isinstance(plays, list) or not plays:
            raise ValueError('lme: policy_projections.%s: generated member %r declares no %s' % (name, k, lst))
        rows = []
        for i, p in enumerate(plays):
            b, s = (p[bl], p[sl]) if isinstance(p, dict) and bl in p and sl in p else (None, None)   # absent -> refused below
            if not isinstance(b, str) or not relp.fullmatch(b) or not isinstance(s, str) or not re.fullmatch(dpat, s) or b in seen:
                raise ValueError('lme: policy_projections.%s: generated member %r %s[%d] must carry %s (a repository-relative path fully matching patterns.%s %r, declared once) and %s (fully matching %r); got %r (already %r)' % (
                    name, k, lst, i, bl, pj['rel_pattern'], ptext[pj['rel_pattern']], sl, dpat, p, seen[b] if isinstance(b, str) and b in seen else '<not seen>'))
            seen[b] = k
            rows.append([b, s])
        res[k] = rows
    # F05-S4 F05-S3-COMPOSED-BODY-ADMISSION (codex-tick548 HIGH, codex-tick549 scope): ONE authoritative transitive
    # obligation projection. An importer whose composed closure contains a generated member (closure_of, direct or
    # transitive: the importers projection already carries every composed member key) inherits that member as an
    # OBLIGATION: its generated-entry identity (the B output rel, the same key entry_outputs publishes) AND its pinned
    # body pairs, so a launch of the composing importer verifies every generated entry and admits every body digest it
    # can reach BEFORE execution. Shape: {<importer rel>: {<generated entry rel>: [[body, sha256], ...]}} over the
    # generated members in {<importer>} + importers[<importer>]; plays in declared order. Deterministic: a wrapper
    # reached by several composition paths is one key with its one value (the generated identity is unique, refused
    # in _rh_eg_generated; a body is declared once across all members, refused above), so no conflict can arise.
    # F05-S4 CORRECTIONS (codex-tick558 F05-S4-EMPTY-IMPORTER-ROW): EVERY admitted importer of projection <importers>
    # (runner, authored dispatch closure or B member: the established declaration contract) is published, with the
    # empty obligation mapping {} when its closure reaches no generated member; an unknown importer stays absent, so
    # the consumer's refusal of a stage playbook without a row is kept (no consumer-side fallback).
    imps = resolved[pj['importers']]
    oblig = {}
    for k in sorted(imps):
        ms = sorted(m for m in res if m == k or m in imps[k])
        oblig[k] = dict((m, [list(r) for r in res[m]]) for m in ms)
    # MR03 (DEP-MR03-LOADER-01): the SAME transitive obligation rule over each rendered dispatch row of projection
    # <importers> (written before this projection: `after`); an EMPTY mapping is a valid row
    rimps = _rh_get(out, '%s.%s' % (ipj['at'], ipj['rendered_dispatch']['to']))[1]
    roblig = {}
    for k in sorted(rimps):
        ms = sorted(m for m in res if m == k or m in rimps[k])
        roblig[k] = dict((m, [list(r) for r in res[m]]) for m in ms)
    return oblig, roblig


def _rh_pj_document_kind(name, pj, out, node, schema, key, docs, active, pats, ptext, resolved):
    """The F05-S3 projection kinds (registry_pattern, document_parse, document_rels, entry_importers, entry_bodies, entry_outputs,
    document_value, document_ere). Returns (applied, value). A document-reading kind applies only while its `when` view is active
    (entry_importers: its B part only)."""
    relp = pats[pj['rel_pattern']] if 'rel_pattern' in pj else None
    if 'rel_pattern' in pj and pj['rel_pattern'] not in pats:
        raise ValueError('lme: registry policy_projections.%s.rel_pattern %r must name a declared contract_admission.patterns entry' % (name, pj['rel_pattern']))
    if pj['kind'] == 'registry_pattern':
        if pj['pattern'] not in pats:
            raise ValueError('lme: registry policy_projections.%s.pattern %r must name a declared contract_admission.patterns entry' % (name, pj['pattern']))
        # F05-S4 F05-GEN3-01: the projected grammar crosses into the shell consumer, so only a declared path grammar
        # {pattern, refused_components} (admitted by _rh_path_grammar) projects; a plain Python regex refuses.
        if not isinstance(pats[pj['pattern']], _RhPathGrammar):
            raise ValueError('lme: registry policy_projections.%s.pattern %r must name a contract_admission.patterns path grammar {pattern, refused_components} (a registry_pattern projection reaches the shell consumer); got %r' % (
                name, pj['pattern'], ptext[pj['pattern']]))
        # F05-S4 CORRECTIONS (codex-tick558 S4-D04, codex-tick560): the projected form {pattern, refused_components,
        # separator, terminator} (= contract_admission.path_law.*; the shell consumer reads them with the grammar)
        return True, copy.deepcopy(pats[pj['pattern']].pattern)
    if pj['kind'] == 'document_parse':
        # C1-SR922 (codex 922 OBS_SR919B_R0_PROJECTION_DROPS; restores records-dk03-launch-01 C1-DKL-LM-01 :206-224 byte form):
        # the admitted document_channel.parse (exact shape and parser role binding at _rh_document_channel), projected
        # into the resolved source_admission so the seed renders it into the launch record context. Ungated: the
        # first-entry guard parses on every phase. No authored copy (an authored `to` refuses in the caller).
        return True, copy.deepcopy(_rh_document_channel(schema)['parse'])
    on = _rh_contract_active(out, schema, pj['when'], 'policy_projections.%s.when' % (name,))
    if on != active:
        raise ValueError('lme: registry policy_projections.%s.when %r and document_channel.when disagree on activity (one activity rule)' % (name, pj['when']))
    if pj['kind'] == 'entry_importers':
        # MR03 (DEP-MR03-LOADER-01): the secondary destination rendered_dispatch.to (guarded by the caller, S-GUARD)
        full, rrows = _rh_pj_entry_importers(name, pj, out, _rh_doc_root(name, pj, docs, key) if active else None, active, docs, schema, key, relp, ptext)
        node[pj['rendered_dispatch']['to']] = rrows
        return True, full
    if not active:
        return False, None
    if pj['kind'] == 'document_rels':
        return True, dict((n, docs[n]['rel']) for n in sorted(docs))
    root = _rh_doc_root(name, pj, docs, key)
    if pj['kind'] == 'entry_bodies':
        # MR03 (DEP-MR03-LOADER-01): the secondary destination rendered_to (guarded by the caller, S-GUARD)
        oblig, roblig = _rh_pj_entry_bodies(name, pj, out, root, docs, key, relp, ptext, resolved, schema)
        node[pj['rendered_to']] = roblig
        return True, oblig
    if pj['kind'] == 'entry_outputs':
        return True, sorted(_rh_eg_generated('policy_projections.%s' % (name,), pj, root, out, key, relp)[0])
    v = _rh_doc_value(root, pj['value_at'], 'policy_projections.%s' % (name,), 'value_at', pj['document'])
    if pj['kind'] == 'document_ere':
        # C1-SR922 (codex 922 OBS_SR919B_R0_PROJECTION_DROPS; codex-tick626 OD-LI-03 UNIFY, s11 engine form): one authority
        # for a grammar both engines read; admitted inside the bounded ERE subset of the declared form by the SAME
        # admission as the `ere` contract kind (_rh_ca_ere; its forms are the `ere` arg check's), never re-spelled.
        why = _rh_ca_ere(v, pj['ere'], False) if pj['ere'] in ('fragment', 'anchored') else 'names no declared ERE form (fragment, anchored)'
        if why:
            raise ValueError('lme: policy_projections.%s: document %s %s must be an ERE of form %r inside the bounded subset: %s; got %r' % (
                name, pj['document'], pj['value_at'], pj['ere'], why, v))
        return True, v
    if not isinstance(v, str) or not relp.fullmatch(v):
        raise ValueError('lme: policy_projections.%s: document %s %s must be a repository-relative path fully matching patterns.%s %r; got %r' % (
            name, pj['document'], pj['value_at'], pj['rel_pattern'], ptext[pj['rel_pattern']], v))
    return True, v


_RH_DOC_KIND_SHAPES = {
    'registry_pattern': frozenset(('kind', 'after', 'at', 'to', 'pattern', 'segment_pattern')),
    'document_parse': frozenset(('kind', 'after', 'at', 'to', 'segment_pattern')),   # records-dk03-launch-01 C1-DKL-LM-02; C1-SR922
    'document_rels': frozenset(('kind', 'after', 'when', 'at', 'to', 'segment_pattern')),
    'entry_importers': frozenset(('kind', 'after', 'when', 'document', 'at', 'to', 'members', 'entries', 'closure', 'route_includes',
                                  'identity', 'guard', 'relativity_from', 'runners', 'runner_key', 'requires_key', 'common',
                                  'dispatch', 'dispatch_modes', 'reference_keys', 'rel_pattern', 'segment_pattern',
                                  'rendered_dispatch', 'common_refs', 'runner_transport')),   # MR03-GL-01; MR03-F05-GL-01; C1 s11 L11-01
    'entry_bodies': frozenset(('kind', 'after', 'when', 'document', 'at', 'to', 'members', 'identity', 'bodies', 'importers',
                               'digest_pattern', 'rel_pattern', 'segment_pattern', 'rendered_to')),   # MR03-GL-02
    'entry_outputs': frozenset(('kind', 'after', 'when', 'document', 'at', 'to', 'members', 'identity', 'rel_pattern', 'segment_pattern')),
    'document_value': frozenset(('kind', 'after', 'when', 'document', 'at', 'to', 'value_at', 'rel_pattern', 'segment_pattern')),
    # codex-tick626 OD-LI-03 UNIFY; C1-SR922: a document GRAMMAR (an ERE of the declared form `ere`), projected verbatim
    'document_ere': frozenset(('kind', 'after', 'when', 'document', 'at', 'to', 'value_at', 'ere', 'segment_pattern')),
}
# non-string fields of the projection shapes (every other field is a non-empty string)
_RH_PJ_NONSTRING = frozenset(('parts', 'fields', 'after', 'reference_keys', 'rendered_dispatch', 'runner_transport', 'address', 'outputs', 'leaves'))   # C1-RECIPE-PUB-01: + select_tree


def _rh_pj_secondary(name, pj):
    """MR03 (DEP-MR03-LOADER-01; codex-tick610 / codex-tick612): the SECONDARY publication destinations (one segment
    each under `at`) a document-kind projection writes beside its primary `to`: entry_importers rendered_dispatch.to,
    entry_bodies rendered_to. The ONE list read by the projection guard, the publication, lme_verify_resolved and
    excluded_paths. Every other projection has none."""
    out = []
    if 'rendered_to' in pj:
        out.append(pj['rendered_to'])
    if 'rendered_dispatch' in pj:
        rd = pj['rendered_dispatch']
        if not isinstance(rd, dict) or 'to' not in rd:
            raise ValueError('lme: registry policy_projections.%s.rendered_dispatch must be a mapping carrying to; got %r' % (name, rd))
        out.append(rd['to'])
    if any(not isinstance(s, str) or not s for s in out):
        raise ValueError('lme: registry policy_projections.%s secondary destinations must be non-empty strings; got %r' % (name, out))
    return out
# F05-S4 (codex-tick546 inactive_profiles; MAIN ruling 1): the kinds that MAY declare `when`
_RH_PJ_GATED = frozenset(('lookup_merge', 'sorted_values'))


def _rh_pj_shape_view(name, pj):
    """F05-S4 (codex-tick546 inactive_profiles, MAIN ruling 1): a lookup_merge or sorted_values projection MAY declare
    `when` (a declaration_contract published view: the ONE activity rule); without it the kind keeps its existing
    unconditional semantics. Returns the declaration without `when` for the exact-shape check (every other kind is
    returned unchanged: the document kinds carry `when` in their shape). A non-string or empty `when` refuses."""
    if not isinstance(pj, dict) or 'when' not in pj or 'kind' not in pj or not isinstance(pj['kind'], str) or pj['kind'] not in _RH_PJ_GATED:
        return pj
    if not isinstance(pj['when'], str) or not pj['when']:
        raise ValueError('lme: registry policy_projections.%s.when must name a declaration_contract published view; got %r' % (name, pj['when']))
    return dict((k, v) for k, v in pj.items() if k != 'when')


def _rh_pj_select_tree(name, pj, out, key, pats):
    """C1-RECIPE-PUB-01 (OW-H11-C1-01-PUB; codex-tick883 SR290_09) and C1-RECIPE-PUB-02 (OW-H11-C1-01-PUB-02; codex-tick884
    Q290_2 a, b): the ONE derivation of a select_tree projection, read by _rh_project_policy and re-run by
    lme_verify_resolved (no second resolver, no merge). roles = a policy mapping {role: address}; an address is exactly
    {<address.node>: <policy path>, <address.label>: <policy path of a non-empty string>} (that node, named by that
    declared word; never inferred) or {<address.entries>: <policy path of a mapping>, <address.selector>: <policy path of
    a non-empty string naming one of its keys>}; every path is read from `out`, the resolved copy of the override-LAST
    composition. Each role yields exactly {<outputs.tree>: the declared `leaves` of the selected node, deep-copied and
    nested by segment (the declared content projection), <outputs.selected>: the label or selector value,
    <outputs.digest>: _digest of that tree alone, computed before it is added}. No fallback: an absent, malformed or
    unknown address, label, selector, entry or leaf refuses."""
    fr, roles = _rh_get(out, pj['roles'])
    ad, ow, lv = pj['address'], pj['outputs'], pj['leaves']
    if not fr or not isinstance(roles, dict) or not roles or not isinstance(ad, dict) or set(ad) != {'node', 'label', 'entries', 'selector'} \
            or not isinstance(ow, dict) or set(ow) != {'tree', 'selected', 'digest'} or not isinstance(lv, list) or not lv \
            or any(not isinstance(x, str) or not x for x in list(ad.values()) + list(ow.values()) + lv) \
            or len(set(ad.values())) != 4 or len(set(ow.values())) != 3 or len(set(lv)) != len(lv) \
            or any(y.startswith(x + '.') for x in lv for y in lv):
        raise ValueError('lme: policy_projections.%s needs a declared non-empty mapping %s.%s, address {node, label, entries, selector} and outputs {tree, selected, digest} of distinct non-empty strings, and leaves of distinct, non-nested dotted paths; got %r / %r / %r / %r' % (
            name, key, pj['roles'], roles if fr else '<absent>', ad, ow, lv))
    if pj['segment_pattern'] not in pats:
        raise ValueError('lme: policy_projections.%s.segment_pattern %r must name a declared contract_admission.patterns entry' % (name, pj['segment_pattern']))
    badseg = sorted(repr(s) for s in [pj['to']] + list(roles) + list(ow.values()) + [p for x in lv for p in x.split('.')]
                    if not isinstance(s, str) or not pats[pj['segment_pattern']].fullmatch(s))
    if badseg:
        raise ValueError('lme: policy_projections.%s generated path segments %s do not fully match patterns.%s (a segment is one metadata path step)' % (name, badseg, pj['segment_pattern']))
    rec = {}
    for role in sorted(roles):
        a = roles[role]
        if isinstance(a, dict) and set(a) == {ad['node'], ad['label']} and isinstance(a[ad['node']], str) and isinstance(a[ad['label']], str):
            (fsrc, src), (fs, sel) = _rh_get(out, a[ad['node']]), _rh_get(out, a[ad['label']])
            if not fs or not isinstance(sel, str) or not sel:
                raise ValueError('lme: %s.%s.%s: %s.%s must be a declared non-empty string naming the recipe at %s.%s (policy_projections.%s); got %s' % (
                    key, pj['roles'], role, key, a[ad['label']], key, a[ad['node']], name, _rh_kind(sel) if fs else '<absent>'))
        elif isinstance(a, dict) and set(a) == {ad['entries'], ad['selector']} and isinstance(a[ad['entries']], str) and isinstance(a[ad['selector']], str):
            (fe, ents), (fs, sel) = _rh_get(out, a[ad['entries']]), _rh_get(out, a[ad['selector']])
            if not fe or not isinstance(ents, dict) or not fs or not isinstance(sel, str) or not sel or sel not in ents:
                raise ValueError('lme: %s.%s.%s: %s.%s must be a non-empty string naming a key of the mapping %s.%s (policy_projections.%s); got %r of %r' % (
                    key, pj['roles'], role, key, a[ad['selector']], key, a[ad['entries']], name, sel if fs else '<absent>', sorted(repr(k) for k in ents) if fe and isinstance(ents, dict) else '<absent>'))
            fsrc, src = True, ents[sel]
        else:
            raise ValueError('lme: %s.%s.%s must be exactly {%s: <path>, %s: <path>} or {%s: <path>, %s: <path>} (policy_projections.%s); got %r' % (
                key, pj['roles'], role, ad['node'], ad['label'], ad['entries'], ad['selector'], name, a))
        if not fsrc or not isinstance(src, dict):
            raise ValueError('lme: %s.%s.%s selects no mapping (policy_projections.%s); got %r' % (key, pj['roles'], role, name, _rh_kind(src) if fsrc else '<absent>'))
        tree = {}
        for p in sorted(lv):
            fl, v = _rh_get(src, p)
            if not fl:
                raise ValueError('lme: %s.%s.%s: the selected node carries no %s (policy_projections.%s.leaves)' % (key, pj['roles'], role, p, name))
            cur, segs = tree, p.split('.')
            for s in segs[:-1]:
                if s not in cur:
                    cur[s] = {}
                cur = cur[s]
            cur[segs[-1]] = copy.deepcopy(v)
        rec[role] = {ow['tree']: tree, ow['selected']: sel, ow['digest']: _digest(tree)}
    return rec


def _rh_project_policy(pol, schema, key, active, docs):
    """The registry-declared RESOLVED projections (remote_harness_schema.policy_projections) and partitions
    (policy_partitions), applied to a COPY of the admitted composed policy after contract admission and before any
    digest, so consumers read one resolved node and the composed input is never mutated (a second validation of the
    same composition sees the authored node). No fallback: an absent or malformed declaration, node or reference refuses.
    Projection kinds (each names at = a declared policy mapping, from = its authored selector key, to = the resolved key):
      path_list (LI-MAIN-1, B-OD-09 b): parts = ordered [{key, in}]; the authored node must not carry `to`;
        to = [<policy node at in>[<at.from.key>] ...], each a non-empty string.
      lookup_merge (LI-03, B-OD-10 a): source = a mapping read from source_root (policy: the resolved policy copy;
        registry: the admitted remote_harness_schema; C1 s08 LH-2, FW22-BOOT-OWNER); for every role of at.from, at.to[role] =
        source[at.from[role]] (a non-empty string); an authored at.to key that is also a role of at.from refuses
        (no second authority). A registry source names no projection, so it adds no after edge.
      select_record (L-11, codex-tick498 R2N-L11-NONROLE-REUSE): roles = a policy mapping {role: <source key>};
        source = a policy mapping; fields_from = a policy mapping {field role: <output name>}; fields = {field role:
        <dotted sub-path of source[<key>]>} with the same field roles; at.to = {role: {<output name>: <value>}}, each a
        non-empty string; the composed policy (declaration AND override) must not carry at.to (one authority). A leaf
        whose sub-path starts with a registry host_scope.scoped_fields member is HOST-SCOPED: it is returned for
        host_scoped_paths (scope_invariant_sha256 strips it like its source) and its output name may not be any
        shared artifact's not_embedded_fields name (_rh_shared_inputs strips by that last segment; it would silently
        drop an embedded input from the reuse key). segment_pattern names a registry contract_admission.patterns entry
        that `to`, every role key and every output name must fully match BEFORE any value or host_scoped_paths entry
        is built (a dotted name would be one literal key but address a different metadata path; codex-tick500
        L11-PROJECTED-PATH-SEGMENTS).
      sorted_values (LI-07, codex-tick507 LI-07-RENDER-STAGE-INPUTS): source = a non-empty policy mapping whose
        values are distinct strings each fully matching contract_admission.patterns[segment_pattern]; at.to =
        sorted(those values); the composed policy (declaration AND override) must not carry at.to (one authority).
      select_tree (C1-RECIPE-PUB-01, OW-H11-C1-01-PUB; codex-tick883 SR290_09; C1-RECIPE-PUB-02, codex-tick884 Q290_2):
        roles = a policy mapping {role: address}; at.to = {role: {<outputs.tree>: the declared `leaves` of the addressed
        node, <outputs.selected>: the label or selector value, <outputs.digest>: _digest of that tree}} (_rh_pj_select_tree,
        also the readback derivation); the composed policy must not carry at.to.
    Partitions (LI-03 resolved ownership map): universe = a policy list; parts = [{values_of | keys_of | value_of: path}];
    the parts are pairwise disjoint and their union equals the universe, both read on the RESOLVED copy.
    F05-S3: every projection declares `after` and they apply in that dependency order (_rh_projection_order); the
    document kinds (_RH_DOC_KIND_SHAPES) read the ADMITTED documents `docs` (_rh_documents; `active` = the one
    activity rule evaluated on the admitted policy BEFORE any projection) and never accept an authored `to`.
    F05-S4 (MAIN ruling 1, codex-tick546 inactive_profiles): a lookup_merge / sorted_values projection MAY declare
    `when` (_rh_pj_shape_view); gated, it applies exactly while that view is active (agreeing with `active`); while
    inactive nothing is projected and nothing refuses here (a declared `at` stays under its own contracts).
    Returns (resolved copy, sorted host-scoped projected leaves)."""
    projs, parts_decl = schema.get('policy_projections'), schema.get('policy_partitions')
    if not isinstance(projs, dict) or not isinstance(parts_decl, dict):
        raise ValueError('lme: registry remote_harness_schema.policy_projections and policy_partitions must be mappings; got %r / %r' % (projs, parts_decl))
    out = copy.deepcopy(pol)
    # C1 s08 LH-2: every lookup_merge declares source_root (policy | registry; required, no implicit value).
    shapes = {'path_list': {'kind', 'after', 'at', 'from', 'to', 'parts'}, 'lookup_merge': {'kind', 'after', 'at', 'from', 'to', 'source', 'source_root'},
              'select_record': {'kind', 'after', 'at', 'to', 'roles', 'source', 'fields_from', 'fields', 'segment_pattern'},
              'sorted_values': {'kind', 'after', 'at', 'to', 'source', 'segment_pattern'},
              'select_tree': {'kind', 'after', 'at', 'to', 'roles', 'address', 'outputs', 'leaves', 'segment_pattern'}}
    shapes.update((k, set(v)) for k, v in _RH_DOC_KIND_SHAPES.items())
    hs = schema['host_scope']
    ne_names = set(f for d in _rh_artifact_decl(hs).values() for f in d['not_embedded_fields'])
    pscoped = []
    for name in sorted(projs):
        pj = _rh_pj_shape_view(name, projs[name])
        if not isinstance(pj, dict) or pj.get('kind') not in shapes or set(pj) != shapes[pj['kind']] \
                or any(not isinstance(pj[k], str) or not pj[k] for k in shapes[pj['kind']] - _RH_PJ_NONSTRING):
            raise ValueError('lme: registry policy_projections.%s must be one of %s; got %r' % (name, {k: sorted(v) for k, v in shapes.items()}, pj))
        if pj['kind'] == 'lookup_merge' and pj['source_root'] not in ('policy', 'registry'):
            raise ValueError('lme: registry policy_projections.%s.source_root must be policy or registry; got %r' % (name, pj['source_root']))
    pats, ptext = _rh_patterns(schema)
    resolved = {}
    for name in _rh_projection_order(projs):
        pj = projs[name]
        if pj['kind'] in _RH_PJ_GATED and 'when' in pj:
            # F05-S4 MAIN ruling 1 (codex-tick546 inactive_profiles / OD-BRR-07): gated by the ONE activity rule. Active:
            # the projection applies as before (an absent `at` refuses below). Inactive: nothing is projected, no view is
            # fabricated and nothing refuses here -- a declared `at` stays subject to its own when_present contracts
            # (genesis_inventory_kinds exact key sets refuse an authored projection leaf), never to this projection.
            on = _rh_contract_active(out, schema, pj['when'], 'policy_projections.%s.when' % (name,))
            if on != active:
                raise ValueError('lme: registry policy_projections.%s.when %r and document_channel.when disagree on activity (one activity rule)' % (name, pj['when']))
            if not on:
                continue
        fn_, node = _rh_get(out, pj['at'])
        if not fn_ or not isinstance(node, dict):
            raise ValueError('lme: %s.%s must be a declared mapping (policy_projections.%s); got %r' % (key, pj['at'], name, node if fn_ else '<absent>'))
        if pj['kind'] in _RH_DOC_KIND_SHAPES:
            if pj['to'] in node:
                raise ValueError('lme: %s.%s declares %s; it is RESOLVED (policy_projections.%s; one authority -- neither the declaration nor an override may supply it)' % (key, pj['at'], pj['to'], name))
            if pj['segment_pattern'] not in pats or not pats[pj['segment_pattern']].fullmatch(pj['to']):
                raise ValueError('lme: policy_projections.%s.to %r does not fully match a declared patterns.%s (a segment is one metadata path step)' % (name, pj['to'], pj['segment_pattern']))
            # MR03 (codex-tick610 / codex-tick612 F3): each SECONDARY destination carries the primary `to` protections above,
            # checked here -- before any activity skip -- so a declaration- or override-supplied secondary leaf refuses
            # whether or not the projection then publishes it (inactive: honest absence / {} is kept by the kind)
            sec = _rh_pj_secondary(name, pj)
            for s in sec:
                if s in node or s == pj['to'] or sec.count(s) != 1 or not pats[pj['segment_pattern']].fullmatch(s):
                    raise ValueError('lme: %s.%s declares %s, or it is not one segment fully matching patterns.%s distinct from %r; it is RESOLVED (policy_projections.%s secondary destination; one authority -- neither the declaration nor an override may supply it)' % (
                        key, pj['at'], s, pj['segment_pattern'], pj['to'], name))
            applied, val = _rh_pj_document_kind(name, pj, out, node, schema, key, docs, active, pats, ptext, resolved)
            if applied:
                node[pj['to']] = val
                resolved[name] = val
            continue
        if pj['kind'] == 'sorted_values':
            if pj['to'] in node:
                raise ValueError('lme: %s.%s declares %s; it is RESOLVED from %s (policy_projections.%s; one authority -- neither the declaration nor an override may supply it)' % (key, pj['at'], pj['to'], pj['source'], name))
            seg = (schema.get('contract_admission') or {}).get('patterns', {}).get(pj['segment_pattern'])
            if not isinstance(seg, str) or not seg:
                raise ValueError('lme: policy_projections.%s.segment_pattern %r must name a declared contract_admission.patterns entry' % (name, pj['segment_pattern']))
            if not re.fullmatch(seg, pj['to']):
                raise ValueError('lme: policy_projections.%s.to %r does not fully match patterns.%s %r (a segment is one metadata path step; codex F05-SORTED-VALUES-DESTINATION-SEGMENT)' % (name, pj['to'], pj['segment_pattern'], seg))
            fsrc, src = _rh_get(out, pj['source'])
            if not fsrc or not isinstance(src, dict) or not src:
                raise ValueError('lme: %s.%s must be a declared non-empty mapping (policy_projections.%s); got %r' % (key, pj['source'], name, src if fsrc else '<absent>'))
            vals = list(src.values())
            bad = sorted(repr(v) for v in vals if not isinstance(v, str) or not re.fullmatch(seg, v))
            if bad or len(set(vals)) != len(vals):
                raise ValueError('lme: %s.%s values must be distinct strings fully matching patterns.%s %r (policy_projections.%s); got bad %r / duplicated %r' % (
                    key, pj['source'], pj['segment_pattern'], seg, name, bad, sorted(v for v in set(vals) if vals.count(v) > 1) if not bad else []))
            node[pj['to']] = sorted(vals)
            continue
        if pj['kind'] == 'select_record':
            if pj['to'] in node:
                raise ValueError('lme: %s.%s declares %s; it is RESOLVED (policy_projections.%s; one authority -- neither the declaration nor an override may supply it)' % (key, pj['at'], pj['to'], name))
            (fr, roles), (fsrc, src), (ff, fmap) = _rh_get(out, pj['roles']), _rh_get(out, pj['source']), _rh_get(out, pj['fields_from'])
            subs = pj['fields']
            seg = (schema.get('contract_admission') or {}).get('patterns', {}).get(pj['segment_pattern'])
            if not isinstance(seg, str) or not seg:
                raise ValueError('lme: policy_projections.%s.segment_pattern %r must name a declared contract_admission.patterns entry' % (name, pj['segment_pattern']))
            if not fr or not isinstance(roles, dict) or not roles or not fsrc or not isinstance(src, dict) or not ff or not isinstance(fmap, dict) \
                    or not isinstance(subs, dict) or sorted(subs) != sorted(fmap) or any(not isinstance(v, str) or not v for v in list(subs.values()) + list(fmap.values())):
                raise ValueError('lme: policy_projections.%s needs declared mappings %s.%s / %s.%s / %s.%s and fields keyed exactly like %s.%s; got %r / %r / %r / %r' % (
                    name, key, pj['roles'], key, pj['source'], key, pj['fields_from'], key, pj['fields_from'], roles, sorted(src) if isinstance(src, dict) else src, fmap, subs))
            badseg = sorted(s for s in [pj['to']] + list(roles) + list(fmap.values())
                            if not isinstance(s, str) or not re.fullmatch(seg, s))
            if badseg:
                raise ValueError('lme: policy_projections.%s generated path segments %r do not fully match patterns.%s %r (a segment is one metadata path step)' % (name, badseg, pj['segment_pattern'], seg))
            rec = {}
            for role in sorted(roles):
                ent = src.get(roles[role]) if isinstance(roles[role], str) else None
                rec[role] = {}
                for fr_ in sorted(subs):
                    fv, v = _rh_get(ent, subs[fr_]) if isinstance(ent, dict) else (False, None)
                    if not fv or not isinstance(v, str) or not v:
                        raise ValueError('lme: %s.%s.%s (role %s, field %s) does not resolve to a non-empty string (policy_projections.%s)' % (key, pj['source'], '%s.%s' % (roles[role], subs[fr_]), role, fr_, name))
                    rec[role][fmap[fr_]] = v
                    if subs[fr_].split('.')[0] in hs['scoped_fields']:
                        if fmap[fr_] in ne_names:
                            raise ValueError('lme: policy_projections.%s output name %r is a shared-artifact not_embedded_fields name; the host-scoped projected leaf would be stripped from every reuse key' % (name, fmap[fr_]))
                        pscoped.append('%s.%s.%s.%s' % (pj['at'], pj['to'], role, fmap[fr_]))
            node[pj['to']] = rec
            continue
        if pj['kind'] == 'select_tree':
            # C1-RECIPE-PUB-01 (OW-H11-C1-01-PUB): the ONE derivation, on the resolved copy of the override-LAST composition
            if pj['to'] in node:
                raise ValueError('lme: %s.%s declares %s; it is RESOLVED (policy_projections.%s; one authority -- neither the declaration nor an override may supply it)' % (key, pj['at'], pj['to'], name))
            node[pj['to']] = _rh_pj_select_tree(name, pj, out, key, pats)
            continue
        sel = node.get(pj['from'])
        if pj['kind'] == 'path_list':
            if not isinstance(pj['parts'], list) or not pj['parts'] or any(not isinstance(p, dict) or set(p) != {'key', 'in'} for p in pj['parts']):
                raise ValueError('lme: registry policy_projections.%s.parts must be a non-empty list of {key, in}; got %r' % (name, pj['parts']))
            if pj['to'] in node:
                raise ValueError('lme: %s.%s declares %s; it is RESOLVED from %s (policy_projections.%s; one authority)' % (key, pj['at'], pj['to'], pj['from'], name))
            if not isinstance(sel, dict) or sorted(sel) != sorted(p['key'] for p in pj['parts']):
                raise ValueError('lme: %s.%s.%s must name exactly %s (policy_projections.%s); got %r' % (key, pj['at'], pj['from'], [p['key'] for p in pj['parts']], name, sel))
            res = []
            for p in pj['parts']:
                fi, src = _rh_get(out, p['in'])
                v = src.get(sel[p['key']]) if fi and isinstance(src, dict) and isinstance(sel[p['key']], str) else None
                if not isinstance(v, str) or not v:
                    raise ValueError('lme: %s.%s.%s.%s %r does not resolve to a non-empty string in %s.%s (policy_projections.%s)' % (key, pj['at'], pj['from'], p['key'], sel[p['key']], key, p['in'], name))
                res.append(v)
            node[pj['to']] = res
        else:
            # C1 s08 LH-2 (records-c1-framework-22 FW22-BOOT-OWNER / FW22-HOSTS-SEED; codex-tick818 :33-55): the source is
            # read by the existing _rh_get from the resolved policy copy (source_root policy) or from the admitted registry
            # (source_root registry; admitted by the shape check above). Every other line below is unchanged.
            fs_, src = _rh_get(out if pj['source_root'] == 'policy' else schema, pj['source'])
            tgt = node.get(pj['to'])
            if not isinstance(sel, dict) or not sel or not fs_ or not isinstance(src, dict) or not isinstance(tgt, dict):
                raise ValueError('lme: %s.%s.%s / .%s and %s.%s must be declared mappings (policy_projections.%s); got %r / %r / %r' % (
                    key, pj['at'], pj['from'], pj['to'], key, pj['source'], name, sel, tgt, src if fs_ else '<absent>'))
            dup = sorted(set(tgt) & set(sel))
            if dup:
                raise ValueError('lme: %s.%s.%s authors %s; they are RESOLVED from %s.%s through %s (policy_projections.%s; one authority)' % (key, pj['at'], pj['to'], dup, key, pj['source'], pj['from'], name))
            for role in sorted(sel):
                v = src.get(sel[role]) if isinstance(sel[role], str) else None
                if not isinstance(v, str) or not v:
                    raise ValueError('lme: %s.%s.%s.%s %r does not name a non-empty string in %s.%s (policy_projections.%s)' % (key, pj['at'], pj['from'], role, sel[role], key, pj['source'], name))
                tgt[role] = v
    for name in sorted(parts_decl):
        pt = parts_decl[name]
        if not isinstance(pt, dict) or set(pt) != {'universe', 'parts'} or not isinstance(pt['parts'], list) or not pt['parts'] \
                or any(not isinstance(p, dict) or len(p) != 1 or next(iter(p)) not in ('values_of', 'keys_of', 'value_of') for p in pt['parts']):
            raise ValueError('lme: registry policy_partitions.%s must be {universe, parts: [{values_of | keys_of | value_of: <path>}, ...]}; got %r' % (name, pt))
        fu, uni = _rh_get(out, pt['universe'])
        if not fu or not isinstance(uni, list) or any(not isinstance(u, str) for u in uni) or len(set(uni)) != len(uni):
            raise ValueError('lme: %s.%s must be a list of distinct strings (policy_partitions.%s); got %r' % (key, pt['universe'], name, uni if fu else '<absent>'))
        seen, got = {}, []
        for p in pt['parts']:
            how, path = next(iter(p.items()))
            fp, v = _rh_get(out, path)
            if not fp or (how == 'value_of' and not isinstance(v, str)) or (how != 'value_of' and not isinstance(v, dict)):
                raise ValueError('lme: %s.%s must be declared (%s; policy_partitions.%s); got %r' % (key, path, how, name, v if fp else '<absent>'))
            for m in ([v] if how == 'value_of' else list(v.values()) if how == 'values_of' else list(v)):
                if m in seen:
                    raise ValueError('lme: %s policy_partitions.%s: %r is owned by both %s and %s (collision)' % (key, name, m, seen[m], path))
                seen[m] = path
                got.append(m)
        if sorted(got) != sorted(uni):
            raise ValueError('lme: %s policy_partitions.%s: the parts cover %s, the universe %s.%s is %s (unowned: %s; outside: %s)' % (
                key, name, sorted(got), key, pt['universe'], sorted(uni), sorted(set(uni) - set(got)), sorted(set(got) - set(uni))))
    return out, sorted(pscoped)


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
                          'ere', 'ere_compose', 'umask_yields', 'not_in', 'rejects',
                          'matches_ere', 'distinct_from', 'placeholder_words', 'equals_registry', 'equals_registry_set',
                          'records', 'rel_disjoint', 'int_range', 'key_set', 'int_gt_sum', 'disjoint_from',
                          'mode_regex_domain', 'values_distinct', 'includes', 'not_within'))
# GRAPH-SHARED-CONTRACT (codex-tick304): `within` joins each (a role -> executable-name mapping: every VALUE is one
# scalar member, e.g. guest.tools.<role> names a controller.bootstrap.os_tools key the guest consumer requires).
_RH_CA_EACH = frozenset(('enum', 'pattern', 'strings', 'positive_int', 'has_keys', 'placeholder_words', 'int_range',
                         'within'))
_RH_CA_MODS = {'each': _RH_CA_EACH, 'where': _RH_CA_EACH,
               'having': frozenset(('within',)), 'sed_delimited': frozenset(('ere',)), 'subject': frozenset(('within', 'not_within')),
               'key_at': frozenset(('within',)), 'placeholders': frozenset(('within',)),
               # codex-tick626 LI-OPTIONAL-RULE-EMPTY-EXPANSION: the kinds an optional key_set member row may carry
               'optional': frozenset(('strings', 'keys', 'within', 'pattern', 'enum')),
               # C1 CURRENT correction (codex-tick860 (b)): the kinds an explicitly empty-mapping wildcard row may carry
               'empty_mapping': frozenset(('keys', 'within')),
               # C1 s08 LH-3 (records-c1-framework-22 LH-3; codex-tick818 :43): the kinds a `registry` (subject in the admitted
               # registry) check may carry
               'registry': frozenset(('keys', 'has_keys', 'pattern', 'enum', 'not_in', 'distinct_from', 'values_distinct'))}
# C1-CONTRACT-SCALAR-SHAPE (codex 193253): the declared shape of a `within` value (REQUIRED on every within check):
# scalar = one non-empty string; list = a non-empty list of strings; keys = a non-empty mapping (its keys checked).
_RH_CA_SUBJECTS = ('scalar', 'list', 'keys')
_RH_CA_ERE_BANNED = ('\\', '\n', '|', '[:', '(?', '*?', '+?', '??', '}?')


def _rh_ca_same(a, b):
    """Type-exact equality (True != 1; tagged strings compare as str)."""
    return _rh_kind(a) == _rh_kind(b) and a == b


def _rh_ca_members(x):
    if isinstance(x, (dict, list)):
        return list(x)
    return [x]


def _rh_ca_placeholders(w):
    """The placeholder names of one argv word exactly as controller_seed.j2 launch_word splits it (every '{' opens a
    name closed by the next '}'); None when a placeholder is unterminated (a launch_word render error)."""
    names = []
    for p in w.split('{')[1:]:
        kv = p.split('}', 1)
        if len(kv) != 2:
            return None
        names.append(kv[0])
    return names


def _rh_ca_words(s, arg, pats):
    """placeholder_words: None when every placeholder of the word list s renders under the declared vocabulary."""
    if not isinstance(s, list) or any(not isinstance(w, str) for w in s):
        return 'must be a list of strings (argv words)'
    known, whole, refused = (arg.get(k, []) for k in ('known', 'whole_word', 'refused'))
    for w in s:
        names = _rh_ca_placeholders(w)
        if names is None:
            return 'word %r has an unterminated placeholder' % (w,)
        for n in names:
            if n in whole:
                if w != '{' + n + '}':
                    return 'word %r carries {%s}, admitted only as a whole word' % (w, n)
            elif n in refused:
                return 'word %r names {%s}, a fixed launcher value the launcher would also count as a positional mode parameter' % (w, n)
            elif n not in known and not ('params' in arg and pats[arg['params']].fullmatch(n)):
                return 'word %r names an undeclared placeholder {%s} (known %s, whole-word %s%s)' % (
                    w, n, known, whole, ', parameters fully matching patterns.%s' % (arg['params'],) if 'params' in arg else ', no parameters')
    return None


def _rh_ca_ere(v, form, sed):
    """None when v is inside the admitted BOUNDED ERE subset of the declared form, else the reason. This is a
    conservative subset (Python re compiles it + a substring blacklist), NOT a complete portable-ERE grammar check;
    bracket negation ('[^...]') is refused by the '^' substring rule and is unsupported by design (codex 193337)."""
    if not isinstance(v, str) or not v:
        return 'must be a non-empty string'
    bad = [t for t in _RH_CA_ERE_BANNED + (('/',) if sed else ()) if t in v]
    if bad:
        return 'contains %r (bounded ERE subset: no backslash, newline, alternation, class name, extension or lazy quantifier%s)' % (
            bad, '; sed-delimited: no /' if sed else '')
    body = v
    if form == 'anchored':
        if len(v) < 2 or not v.startswith('^') or not v.endswith('$'):
            return "must be anchored: exactly a leading '^' and a trailing '$'"
        body = v[1:-1]
    if '^' in body or '$' in body:
        return "must carry no other '^' or '$' (%s; bracket negation is unsupported)" % ('an anchored ERE is anchored once' if form == 'anchored' else 'a fragment is composed inside ^...$')
    try:
        re.compile(v)
    except re.error as e:
        return 'does not compile: %s' % (e,)
    return None


class _RhPathGrammar(object):
    """A declared path grammar (contract_admission.patterns.<n> = {pattern, refused_components}) under the registry
    path law (contract_admission.path_law): a path is admitted iff it fully matches `pattern` AND none of its
    path_law.separator-split components is a refused component (refused_components includes every path_law.traversal
    component, so the traversal invariant holds by construction for every pattern). `pattern` fully matches the
    declared ERE subset patterns.<path_law.syntax>, which Python re.fullmatch and POSIX `grep -E -x` decide identically,
    so the loader and the shell consumer validate the ONE declaration with the same two steps (no second spelling).
    .pattern is the projected form {pattern, refused_components, separator, terminator} (codex-tick558 S4-D04,
    codex-tick560: the consumer reads the separator and the line terminator with the grammar, no format literal); a
    value holding the terminator is refused here as the shell refuses it before grep. fullmatch / pattern mirror a
    compiled regex for every pats[...] reader."""
    __slots__ = ('pattern', '_rx', '_refused', '_sep', '_term')

    def __init__(self, decl, rx, sep, term):
        self.pattern = {'pattern': decl['pattern'], 'refused_components': list(decl['refused_components']), 'separator': sep, 'terminator': term}
        self._rx = rx
        self._refused = frozenset(decl['refused_components'])
        self._sep = sep
        self._term = term

    def fullmatch(self, s):
        return isinstance(s, str) and self._term not in s and self._rx.fullmatch(s) is not None and not (self._refused & set(s.split(self._sep)))


def _rh_path_law(ca, plain):
    """contract_admission.path_law (codex-tick558 S4-D04 / F05-S4-PATH-LAW-FLOOR, codex-tick560), admitted fail-closed:
    exactly {separator, terminator, traversal, syntax, consumers}; separator and terminator distinct one-character
    strings; traversal a non-empty list of distinct non-empty components holding neither; syntax the name of a declared
    plain (string) patterns entry; and (codex-tick564 F05-GROUP-PATH-READER-COMPATIBILITY) every separator / terminator /
    traversal value bound by at least one declared reader (consumers.<reader> = {law field: [supported value, ...]}) and
    in EVERY binding reader's supported list, so an unsupported law refuses here, before any projection.
    Returns (separator, terminator, traversal, compiled syntax)."""
    law = ca['path_law']
    where = 'registry remote_harness_schema.contract_admission.path_law'
    if not isinstance(law, dict) or set(law) != {'separator', 'terminator', 'traversal', 'syntax', 'consumers'}:
        raise ValueError('lme: %s must declare exactly {separator, terminator, traversal, syntax, consumers}; got %r' % (where, law))
    sep, term, trav, syn = law['separator'], law['terminator'], law['traversal'], law['syntax']
    if not isinstance(sep, str) or len(sep) != 1 or not isinstance(term, str) or len(term) != 1 or sep == term:
        raise ValueError('lme: %s.separator / .terminator must be distinct one-character strings; got %r / %r' % (where, sep, term))
    if not isinstance(trav, list) or not trav or any(not isinstance(x, str) or not x or sep in x or term in x for x in trav) or len(set(trav)) != len(trav):
        raise ValueError('lme: %s.traversal must be a non-empty list of distinct non-empty components without the separator %r or the terminator %r; got %r' % (where, sep, term, trav))
    if not isinstance(syn, str) or syn not in plain:
        raise ValueError('lme: %s.syntax must name a declared contract_admission.patterns regex (a string entry); got %r (declared %s)' % (where, syn, sorted(plain)))
    # F05-S4 GROUPS CORRECTIONS (codex-tick564 F05-GROUP-PATH-READER-COMPATIBILITY): the law binds to its declared
    # readers (POSIX pathname resolution, grep -E -x per-line records); the supported values live in YAML only.
    rdr, bound = law['consumers'], ('separator', 'terminator', 'traversal')
    if not isinstance(rdr, dict) or not rdr or any(not isinstance(c, str) or not isinstance(rdr[c], dict) or not rdr[c] or not set(rdr[c]) <= set(bound)
                                                   or any(not isinstance(s, list) or not s for s in rdr[c].values()) for c in rdr):
        raise ValueError('lme: %s.consumers must be a non-empty mapping {reader: {law field among %s: [supported value, ...]}}; got %r' % (where, list(bound), rdr))
    unbound = [f for f in bound if not any(f in rdr[c] for c in rdr)]
    if unbound:
        raise ValueError('lme: %s.%s must be bound by at least one declared reader in %s.consumers (an unbound law value is an unchecked reader contract); got readers %r' % (
            where, unbound, where, rdr))
    unsupported = sorted((c, f) for c in rdr for f in rdr[c] if law[f] not in rdr[c][f])
    if unsupported:
        raise ValueError('lme: %s: %s; the declared value(s) %r are not supported by the reader(s) that consume them (supported %r); an unsupported path law refuses before projection' % (
            where, ', '.join('%s.%s is outside %s.consumers.%s.%s' % (where, f, where, c, f) for c, f in unsupported),
            dict((f, law[f]) for c, f in unsupported), dict(('%s.%s' % (c, f), rdr[c][f]) for c, f in unsupported)))
    return sep, term, trav, plain[syn]


def _rh_path_grammar(n, p, law):
    """contract_admission.patterns.<n> declared as a path grammar, admitted fail-closed under the path law
    (_rh_path_law): exactly {pattern, refused_components}; pattern ASCII, inside the bounded ERE subset (_rh_ca_ere
    'anchored': anchoring, banned tokens, Python compiles) AND fully matching patterns.<path_law.syntax> (the PRECISE
    positive subset both engines decide identically; a quantifier never follows a quantifier, so possessive / lazy /
    stacked forms refuse); refused_components distinct non-empty components without the separator that include EVERY
    path_law.traversal component (no finite sample probe: the component check is the invariant). A refused component
    beyond the traversal law must be one `pattern` alone admits (else that entry is vacuous); a traversal component is
    exempt from that test because it may arise only INSIDE a path (e.g. X/../X under ^[.X](/[.X]+)*$)."""
    sep, term, trav, syn = law
    where = 'registry contract_admission.patterns.%s' % (n,)
    if set(p) != {'pattern', 'refused_components'}:
        raise ValueError('lme: %s (a path grammar) must declare exactly {pattern, refused_components}; got %r' % (where, sorted(p)))
    pt, rc = p['pattern'], p['refused_components']
    why = _rh_ca_ere(pt, 'anchored', False) if isinstance(pt, str) and pt.isascii() else 'must be a non-empty ASCII string'
    if not why and not syn.fullmatch(pt):
        why = 'is outside the declared path ERE subset (patterns per contract_admission.path_law.syntax %r: literals, flat groups, bracket literals / same-class ranges, at most one quantifier per unit)' % (syn.pattern,)
    if why:
        raise ValueError('lme: %s.pattern %s (the ONE path grammar is validated by Python re.fullmatch AND POSIX grep -E -x; only the declared bounded ERE subset is decided identically); got %r' % (where, why, pt))
    rx = re.compile(pt)
    if not isinstance(rc, list) or not rc or len(set(x for x in rc if isinstance(x, str))) != len(rc) \
            or any(not isinstance(x, str) or not x or sep in x or term in x or (x not in trav and not rx.fullmatch(x)) for x in rc):
        raise ValueError('lme: %s.refused_components must be a non-empty list of distinct single components (no %r; a component beyond contract_admission.path_law.traversal must be one %s.pattern alone admits); got %r' % (
            where, sep, where, rc))
    missing = [x for x in trav if x not in rc]
    if missing:
        raise ValueError('lme: %s.refused_components must include every contract_admission.path_law.traversal component %r (the traversal invariant of every path grammar); missing %r, declared %r' % (
            where, trav, missing, p))
    return _RhPathGrammar(p, rx, sep, term)


def _rh_ca_registry(ca, schema):
    """The registry declaration contract_admission, shape-checked (fail-closed: admission can never be disabled or
    weakened by a malformed or missing registry entry). Returns ({pattern name: compiled}, contracts, required_values)."""
    if not isinstance(ca, dict) or set(ca) != {'path_law', 'patterns', 'contracts', 'required_values', 'bootstrap_input_refusal', 'bootstrap_identity_task', 'cold_inputs', 'carrier_state', 'member_rel_grammar', 'vocabulary', 'early_names'} \
            or not isinstance(ca['patterns'], dict) or not isinstance(ca['contracts'], dict) or not ca['contracts'] \
            or not isinstance(ca['required_values'], dict) or not ca['required_values']:
        raise ValueError('lme: registry remote_harness_schema.contract_admission must declare {path_law, patterns, contracts, required_values, bootstrap_input_refusal, bootstrap_identity_task, cold_inputs, carrier_state, member_rel_grammar, vocabulary, early_names} (bootstrap contract admission is fail-closed); got %r' % (ca,))
    # C1 s08 LH-4 (codex-tick818 :33-53; records-c1-framework-23 A3-FW23-LH34; FW19 :69 governs over FW22 LH4 :132): early_names
    # is the eleventh member. Structural admission before use only: a non-empty mapping of non-empty string keys to
    # mappings. Its required-member roster, entry keys, var pattern and identity are DECLARED contract rows carrying
    # `registry: true` (LH-3), evaluated by the one check engine at resolve (a missing required early name fails there);
    # this code names no early name and no entry key.
    en = ca['early_names']
    if not isinstance(en, dict) or not en or any(not isinstance(k, str) or not k or not isinstance(e, dict) for k, e in en.items()):
        raise ValueError('lme: registry remote_harness_schema.contract_admission.early_names must be a non-empty mapping of names to entry mappings; got %r' % (en,))
    # codex-tick637 boot_shape: the ONE literal of the bootstrap-input refusal codes, a named mapping of two distinct
    # non-empty strings (their code grammar is admitted where they are used: contract bootstrap_refusal_statuses)
    bir = ca['bootstrap_input_refusal']
    if not isinstance(bir, dict) or sorted(bir) != ['bytes', 'input'] or any(not isinstance(v, str) or not v for v in bir.values()) \
            or bir['bytes'] == bir['input']:
        raise ValueError('lme: registry remote_harness_schema.contract_admission.bootstrap_input_refusal must map exactly {input, bytes} to two distinct non-empty codes; got %r' % (bir,))
    pats = {}
    # plain regex entries first; then every path grammar under the ONE path law (whose syntax is a plain entry)
    for n in sorted(n for n in ca['patterns'] if not isinstance(ca['patterns'][n], dict)):
        p = ca['patterns'][n]
        try:
            pats[n] = re.compile(p) if isinstance(p, str) and p else None
        except re.error:
            pats[n] = None
        if pats[n] is None:
            raise ValueError('lme: registry contract_admission.patterns.%s must be a compilable regex; got %r' % (n, p))
    law = _rh_path_law(ca, dict(pats))
    for n in sorted(n for n in ca['patterns'] if isinstance(ca['patterns'][n], dict)):
        pats[n] = _rh_path_grammar(n, ca['patterns'][n], law)
    strs = lambda a: isinstance(a, list) and bool(a) and all(isinstance(x, str) and x for x in a)
    # records-contract-set-kind-01 (codex-tick755 OPEN-S17-RF-MEMBER-GRAMMAR-CONSUMER / OPEN-S18-LATE-BINDING-KIND): the shared
    # consumer vocabulary (role -> word mappings) and the member rel grammar, admitted fail-closed. Every literal below is a
    # registry KEY of the declaration it reads; every value is registry data. Shapes and references only: the in-play
    # consumer type-checks the same nodes before use (pre-import); this is the late (resolve) admission.
    voc, mg = ca['vocabulary'], ca['member_rel_grammar']
    words = lambda m: isinstance(m, dict) and bool(m) and all(isinstance(k, str) and k and isinstance(w, str) and w for k, w in m.items())
    if not isinstance(voc, dict) or set(voc) != {'tests', 'attributes', 'projections', 'filters', 'probes'} \
            or not all(words(voc[r]) for r in ('tests', 'attributes', 'projections', 'filters')) \
            or set(voc['projections']) != {'keys', 'members'} or voc['projections']['keys'] == voc['projections']['members'] \
            or not isinstance(voc['probes'], dict) or set(voc['probes']) != set(voc['filters']) \
            or not all(isinstance(p, dict) and set(p) == {'input', 'output'} and isinstance(p['input'], list) and p['input']
                       and isinstance(p['output'], list) and len(p['output']) == len(p['input']) for p in voc['probes'].values()):
        raise ValueError('lme: registry remote_harness_schema.contract_admission.vocabulary must be {tests, attributes, projections, filters, probes}: the first four non-empty mappings of role -> non-empty word, projections exactly {keys, members} with distinct words, probes exactly one {input, output} pair of equal-length non-empty lists per filters role; got %r' % (voc,))
    frc, rel_pat = _rh_get(schema, 'document_channel.rel_pattern')
    if not isinstance(mg, dict) or set(mg) != {'pattern', 'grammar_fields', 'law_fields', 'entry_rel', 'macros_rel', 'macro', 'output'} \
            or not isinstance(mg['pattern'], str) or mg['pattern'] not in pats or not isinstance(pats[mg['pattern']], _RhPathGrammar) \
            or not frc or not _rh_ca_same(rel_pat, mg['pattern']) \
            or not strs(mg['grammar_fields']) or sorted(mg['grammar_fields']) != sorted(ca['patterns'][mg['pattern']]) \
            or not strs(mg['law_fields']) or len(set(mg['law_fields'])) != len(mg['law_fields']) or set(mg['law_fields']) - set(ca['path_law']) \
            or not pats[mg['pattern']].fullmatch(mg['entry_rel']) or not pats[mg['pattern']].fullmatch(mg['macros_rel']) \
            or not isinstance(mg['macro'], str) or not mg['macro'] \
            or not words(mg['output']) or set(mg['output']) != {'form', 'refused'} or mg['output']['form'] == mg['output']['refused']:
        raise ValueError('lme: registry remote_harness_schema.contract_admission.member_rel_grammar must be {pattern (a declared path grammar, equal to document_channel.rel_pattern), grammar_fields (exactly its fields), law_fields (distinct path_law fields), entry_rel / macros_rel (rels that grammar admits), macro, output {form, refused} (distinct words)}; got %r' % (mg,))
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
            # MR03 S13 (F-E4-01): not_within takes within's argument (a non-empty list of policy references)
            ok = {'keys': strs(arg), 'has_keys': strs(arg), 'within': strs(arg), 'not_within': strs(arg), 'ere_compose': strs(arg),
                  'enum': isinstance(arg, list) and bool(arg),
                  'pattern': isinstance(arg, str) and arg in pats, 'key_pattern': isinstance(arg, str) and arg in pats,
                  'positive_int': arg is True,
                  'strings': isinstance(arg, dict) and not set(arg) - {'nonempty', 'distinct'} and all(isinstance(x, bool) for x in arg.values()),
                  'ere': arg in ('fragment', 'anchored'),
                  'umask_yields': isinstance(arg, str) and bool(arg),
                  'not_in': strs(arg) and all(isinstance(schema.get(n), list) for n in arg),
                  'rejects': isinstance(arg, list) and bool(arg) and all(isinstance(x, str) for x in arg),
                  'matches_ere': isinstance(arg, str) and bool(arg),
                  'distinct_from': strs(arg),
                  # OS-TOOL CONSUMER PARTITION (codex-tick328-329): a list subject shares NO member with any referenced
                  # (root-relative) list; shapes checked, an absent reference is a missing dependency
                  'disjoint_from': strs(arg),
                  # C1-PREREQ-MODE-DOMAIN (codex-tick328 schema findings, HIGH): a configurable MODE regex is admitted
                  # by its whole permission domain -- forbidden_bits is one octal mask (e.g. '0022': group/other write)
                  'mode_regex_domain': isinstance(arg, dict) and set(arg) == {'forbidden_bits'} and isinstance(arg['forbidden_bits'], str)
                  and 3 <= len(arg['forbidden_bits']) <= 4 and all(c in '01234567' for c in arg['forbidden_bits'])
                  and int(arg['forbidden_bits'], 8) != 0,
                  # C1-GUEST-RUN-FILE-ALIASES / refusal codes (codex-tick328): every VALUE of a mapping is a non-empty
                  # scalar and no two are equal (type-exact); `includes`: a list holds every declared member
                  'values_distinct': arg is True,
                  'includes': strs(arg),
                  'placeholder_words': isinstance(arg, dict) and 'known' in arg and not set(arg) - {'known', 'whole_word', 'params', 'refused'}
                  and all(isinstance(arg[k], list) and all(isinstance(x, str) and x for x in arg[k]) for k in ('known', 'whole_word', 'refused') if k in arg)
                  and ('params' not in arg or (isinstance(arg['params'], str) and arg['params'] in pats)),
                  'equals_registry': isinstance(arg, dict) and 'path' in arg and not set(arg) - {'path', 'index'}
                  and isinstance(arg['path'], str) and bool(arg['path']) and ('index' not in arg or (_rh_int(arg['index']) and arg['index'] >= 0)),
                  # records-contract-set-kind-01 (codex-tick755 OPEN-S18-LATE-BINDING-KIND option ii): exact SET equality with a
                  # registry string collection; projection is a declared vocabulary.projections word (members / keys)
                  'equals_registry_set': isinstance(arg, dict) and set(arg) == {'path', 'projection'} and isinstance(arg['path'], str)
                  and bool(arg['path']) and arg['projection'] in ca['vocabulary']['projections'].values(),
                  'records': isinstance(arg, dict) and set(arg) == {'fields'} and isinstance(arg['fields'], dict) and bool(arg['fields'])
                  and all(isinstance(k, str) and k and isinstance(p, str) and p in pats for k, p in arg['fields'].items()),
                  'rel_disjoint': isinstance(arg, dict) and 'field' in arg and not set(arg) - {'field', 'from', 'from_under', 'ref_pattern'}
                  and isinstance(arg['field'], str) and bool(arg['field']) and ('from' not in arg or strs(arg['from']))
                  # UV-REFERENCE-NORMALIZATION (codex 001124): references are compared only after they fully match a
                  # DECLARED pattern, so ref_pattern is required whenever the check has references
                  and (('from' not in arg and 'from_under' not in arg and 'ref_pattern' not in arg)
                       or (isinstance(arg.get('ref_pattern'), str) and arg['ref_pattern'] in pats))
                  and ('from_under' not in arg or (isinstance(arg['from_under'], dict) and set(arg['from_under']) == {'base', 'paths'}
                                                   and isinstance(arg['from_under']['base'], str) and bool(arg['from_under']['base'])
                                                   and strs(arg['from_under']['paths']))),
                  # GRAPH-SHARED-CONTRACT (codex-tick304): a type-exact integer range; min REQUIRED, max optional
                  'int_range': isinstance(arg, dict) and 'min' in arg and not set(arg) - {'min', 'max'}
                  and all(_rh_int(arg[k]) for k in arg) and ('max' not in arg or arg['max'] >= arg['min']),
                  # GRAPH-SHARED-CONTRACT (codex-tick304): an EXACT key set with declared optional members (a section
                  # whose per-host member exists on target scopes only); required and optional are disjoint
                  'key_set': isinstance(arg, dict) and set(arg) == {'required', 'optional'} and strs(arg['required'])
                  and strs(arg['optional']) and not set(arg['required']) & set(arg['optional']),
                  # GUEST-LEASE-BOUND (RS a51cc226 B1.lifecycle_leaves): a BOUNDED linear cross-leaf constraint: the
                  # integer subject strictly exceeds sum(times * <root-relative integer leaf>); times a positive int
                  'int_gt_sum': isinstance(arg, list) and bool(arg) and all(
                      isinstance(t, dict) and set(t) == {'path', 'times'} and isinstance(t['path'], str) and bool(t['path'])
                      and _rh_int(t['times']) and t['times'] >= 1 for t in arg)}[kind]
            for m in mods:
                v = chk[m]
                ok = ok and kind in _RH_CA_MODS[m] and {
                    'having': lambda: isinstance(v, dict) and set(v) == {'field', 'contains'} and all(isinstance(x, str) and x for x in v.values()),
                    'where': lambda: isinstance(v, dict) and set(v) == {'field', 'equals_at'} and all(isinstance(x, str) and x for x in v.values())
                    and chk.get('each') is True,
                    'subject': lambda: v in _RH_CA_SUBJECTS,
                    'key_at': lambda: isinstance(v, str) and bool(v),
                    'placeholders': lambda: isinstance(v, list) and all(isinstance(x, str) and x for x in v),
                    # codex-tick626: `optional` is exactly true, and only on a location with a '*' segment
                    'optional': lambda: v is True and '*' in chk[locs[0]].split('.'),
                    # C1 CURRENT correction (codex-tick860 (b)): `empty_mapping` is exactly true, on a location with exactly one '*'
                    # C1 records-c1-d4-g2-l2-01 CX-D4-04: never together with `registry` (the empty-holder test reads the policy)
                    'empty_mapping': lambda: v is True and chk[locs[0]].split('.').count('*') == 1 and 'registry' not in chk,
                    # C1 s08 LH-3 (codex-tick818 :43-45): `registry` is exactly true, and only on an `at` location (the kind
                    # set is _RH_CA_MODS['registry']); any other value, type or location refuses here, at registry admission
                    'registry': lambda: v is True and locs[0] == 'at'}.get(m, lambda: isinstance(v, bool))()
            if kind in ('within', 'not_within') and 'subject' not in chk:
                ok = False    # C1-CONTRACT-SCALAR-SHAPE: a membership check must declare its value's shape
            if not ok:
                raise ValueError('lme: registry contract_admission.contracts.%s.checks[%d] %s argument/modifiers are malformed; got %r' % (cname, i, kind, chk))
    # C1-ACT-REQUIRED-COMPONENT (codex 193337): each required runtime value names the policy leaf holding its variable
    # name (var_at) and a declared pattern its value must fully match independently of any configurable pattern.
    for rname in sorted(ca['required_values']):
        r = ca['required_values'][rname]
        if not isinstance(r, dict) or not {'var_at', 'pattern'} <= set(r) or set(r) - {'var_at', 'pattern', 'when_present'} \
                or not isinstance(r['var_at'], str) or not r['var_at'] or not isinstance(r['pattern'], str) or r['pattern'] not in pats \
                or ('when_present' in r and (not isinstance(r['when_present'], str) or not r['when_present'])):
            raise ValueError('lme: registry contract_admission.required_values.%s must be {var_at, pattern (a declared patterns name)[, when_present]}; got %r' % (rname, r))
    # GRAPH-SHARED-CONTRACT (codex-tick304): reserved OUTPUT name FAMILIES (a consumer's prefixed task vars) are declared
    # patterns; not_in [reserved_outputs] and the declared target inputs refuse a name matching one (fail-closed shape).
    rop = schema.get('reserved_output_patterns', [])
    if not isinstance(rop, list) or any(not isinstance(n, str) or n not in pats for n in rop):
        raise ValueError('lme: registry remote_harness_schema.reserved_output_patterns must be a list of contract_admission.patterns names; got %r' % (rop,))
    # MR03 S12E2 (codex-tick655 OD-S11-COLD-E-FAMILY; codex-tick656): the ONE exact PUBLIC cold-input set. required is a
    # non-empty mapping, both_or_neither exactly one pair, disjoint; every name a var_name of type string with exactly one
    # decision leaf (grammar_at or equals_at: a dotted policy path). No public name is a reserved / resolver output or
    # matches a reserved_output_patterns family (a broad prefix family can never reject one).
    ci = ca['cold_inputs']
    if not isinstance(ci, dict) or set(ci) != {'required', 'both_or_neither'} or not isinstance(ci['required'], dict) \
            or not ci['required'] or not isinstance(ci['both_or_neither'], dict) or len(ci['both_or_neither']) != 2 \
            or set(ci['required']) & set(ci['both_or_neither']):
        raise ValueError('lme: registry contract_admission.cold_inputs must be {required: <non-empty mapping>, both_or_neither: <exactly two>}, disjoint; got %r' % (ci,))
    if 'var_name' not in pats:
        raise ValueError('lme: registry contract_admission.patterns.var_name is required to admit contract_admission.cold_inputs')
    # seat ruling (codex697 presence form; supersedes the E02 :202 spelling): reserved_outputs and resolver_outputs are
    # each read by KEY PRESENCE. An absent key declares no names; a present one must be a list of strings (null or
    # another type refuses).
    ci_reserved = set()
    for rk in ('reserved_outputs', 'resolver_outputs'):
        if rk in schema:
            if not isinstance(schema[rk], list) or any(not isinstance(n, str) for n in schema[rk]):
                raise ValueError('lme: registry remote_harness_schema.%s must be a list of output names; got %r' % (rk, schema[rk]))
            ci_reserved |= set(schema[rk])
    for grp in ('required', 'both_or_neither'):
        for v in sorted(ci[grp], key=str):
            spec = ci[grp][v]
            ok = isinstance(v, str) and bool(pats['var_name'].fullmatch(v)) and isinstance(spec, dict) \
                and set(spec) in ({'type', 'grammar_at'}, {'type', 'equals_at'}) and spec['type'] == 'string' \
                and all(isinstance(spec[k], str) and spec[k] and all(s for s in spec[k].split('.')) for k in spec if k != 'type')
            if not ok:
                raise ValueError('lme: registry contract_admission.cold_inputs.%s.%s must be {type: string, grammar_at | equals_at: <dotted policy path>} under a var_name; got %r' % (grp, v, spec))
            if v in ci_reserved or any(pats[p].fullmatch(v) for p in rop):
                raise ValueError('lme: registry contract_admission.cold_inputs.%s.%s is a reserved / resolver OUTPUT name or matches a reserved_output_patterns family, never a public input' % (grp, v))
    # MR03 S14 (codex-tick675 OD-ALS02-INCLUDE-REL-01): the ONE pre-parse declaration identity task rel, exactly {rel}
    # under the ONE relative-path grammar (it is an include target before any declaration is readable).
    bit = ca['bootstrap_identity_task']
    if not isinstance(bit, dict) or sorted(bit) != ['rel'] or not isinstance(bit['rel'], str) or 'rel_path' not in pats \
            or not pats['rel_path'].fullmatch(bit['rel']):
        raise ValueError('lme: registry remote_harness_schema.contract_admission.bootstrap_identity_task must be exactly {rel: <a patterns.rel_path relative path>}; got %r' % (bit,))
    return pats, ca['contracts'], ca['required_values']


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
    if kind == 'int_range':
        # type-exact: a bool, a float or a decimal string is never an integer here (no coercion)
        lim = '[%d, %s]' % (arg['min'], arg['max'] if 'max' in arg else 'unbounded')
        if not _rh_int(s):
            return 'must be an integer in %s (type-exact; a %s is not)' % (lim, _rh_kind(s))
        return None if s >= arg['min'] and ('max' not in arg or s <= arg['max']) else 'must be an integer in %s' % (lim,)
    if kind == 'int_gt_sum':
        # type-exact on the subject and every term (a bool / float / string never counts); an absent or non-integer
        # term is a missing dependency, never vacuous
        if not _rh_int(s):
            return 'must be an integer (type-exact; a %s is not)' % (_rh_kind(s),)
        total, parts = 0, []
        for t in arg:
            ft, v = _rh_get(pol, root + '.' + t['path'])
            if not ft or not _rh_int(v):
                return 'requires %s declared as an integer (missing dependency)' % (t['path'],)
            total += t['times'] * v
            parts.append('%d*%s' % (t['times'], t['path']))
        return None if s > total else 'must exceed %s = %d' % (' + '.join(parts), total)
    if kind == 'key_set':
        if not isinstance(s, dict):
            return 'must be a mapping'
        miss = sorted(set(arg['required']) - set(s))
        extra = sorted(str(k) for k in set(s) - set(arg['required']) - set(arg['optional']))
        if miss or extra:
            return 'key set must be exactly %s plus optionally %s (missing %s, undeclared %s)' % (
                sorted(arg['required']), sorted(arg['optional']), miss, extra)
        return None
    if kind == 'strings':
        if not isinstance(s, list) or any(not isinstance(x, str) for x in s):
            return 'must be a list of strings'
        if arg.get('nonempty') and not s:
            return 'must be non-empty'
        if arg.get('distinct') and len(set(s)) != len(s):
            return 'must hold distinct entries'
        return None
    if kind in ('within', 'not_within'):
        # C1-CONTRACT-SCALAR-SHAPE (codex 193253): the value must have its DECLARED shape before membership is judged;
        # an empty or differently shaped value never passes vacuously (e.g. {} / [] / [getent] for a scalar key).
        shape = chk['subject']
        if shape == 'scalar' and not (isinstance(s, str) and s):
            return 'must be a non-empty string (subject: scalar; a %s is not a key)' % (_rh_kind(s),)
        if shape == 'list' and not (isinstance(s, list) and s and all(isinstance(x, str) and x for x in s)):
            return 'must be a non-empty list of non-empty strings (subject: list); got a %s' % (_rh_kind(s),)
        if shape == 'keys' and not (isinstance(s, dict) and s and all(isinstance(x, str) and x for x in s)):
            return 'must be a non-empty mapping with string keys (subject: keys); got a %s' % (_rh_kind(s),)
        allowed, hv, excl = [], chk.get('having'), chk.get('placeholders')
        if 'key_at' in chk:
            fk, sel = _rh_get(pol, chk['key_at'])
            if not fk or not isinstance(sel, str) or not sel:
                return 'selects its reference entry by %s, which the policy does not declare as a string (missing dependency)' % (chk['key_at'],)
        for ref in arg:
            nodes = _rh_expand(pol, ref)
            if not nodes:
                return 'references %s, which the policy does not declare (missing dependency)' % (ref,)
            for _p, node in nodes:
                if 'key_at' in chk:
                    if not isinstance(node, dict) or sel not in node:
                        return 'references %s.%s (key_at %s), which the policy does not declare (missing dependency)' % (ref, sel, chk['key_at'])
                    node = node[sel]
                if excl is not None:
                    for w in (node if isinstance(node, list) else [node]):
                        allowed.extend(n for n in (_rh_ca_placeholders(w) or [] if isinstance(w, str) else []) if n not in excl)
                elif isinstance(node, dict):
                    allowed.extend(k for k in node if hv is None or (
                        isinstance(node[k], dict) and isinstance(node[k].get(hv['field']), list) and hv['contains'] in node[k][hv['field']]))
                elif isinstance(node, list):
                    allowed.extend(node)
                else:
                    allowed.append(node)
        if kind == 'not_within':
            # MR03 S13 (F-E4-01 / OD-GL-DISJ-01; codex665 minimal generic check): the complement of within over the SAME
            # declared-shape check and the SAME reference walk above (an absent reference refuses as a missing dependency,
            # never vacuous): no member of the subject may equal (type-exact) a member of a referenced node. No consumer-
            # specific rule; having / key_at / placeholders never reach here (_RH_CA_MODS admits them for within only).
            hit = [m for m in _rh_ca_members(s) if any(_rh_ca_same(m, a) for a in allowed)]
            return 'names %r inside %s (the subject must share no member with them)' % (hit, arg) if hit else None
        miss = [m for m in _rh_ca_members(s) if isinstance(m, (dict, list)) or not any(_rh_ca_same(m, a) for a in allowed)]
        return 'names %r outside %s%s%s%s (missing dependency)' % (
            miss, arg, ' with %s containing %r' % (hv['field'], hv['contains']) if hv else '',
            ' at the entry keyed by %s (%r)' % (chk['key_at'], sel) if 'key_at' in chk else '',
            ' (placeholder names, excluding %s)' % (excl,) if excl is not None else '') if miss else None
    if kind == 'matches_ere':
        fe, frag = _rh_get(pol, root + '.' + arg)
        if not fe or not isinstance(frag, str) or not frag:
            return 'requires %s declared as an ERE fragment (missing dependency)' % (arg,)
        try:
            rx = re.compile('^' + frag + '$')
        except re.error as e:
            return 'cannot be judged: ^%s$ does not compile: %s' % (arg, e)
        return None if isinstance(s, str) and rx.fullmatch(s) else 'must fully match ^<%s>$ %r' % (arg, rx.pattern)
    if kind == 'distinct_from':
        for p in arg:
            fd, other = _rh_get(pol, root + '.' + p)
            if not fd:
                return 'requires %s declared (missing dependency)' % (p,)
            if _rh_ca_same(s, other):
                return 'equals %s (%r); it must be distinct from %s' % (p, other, arg)
        return None
    if kind == 'disjoint_from':
        if not isinstance(s, list) or any(not isinstance(x, str) or not x for x in s):
            return 'must be a list of non-empty strings'
        for p in arg:
            fd, other = _rh_get(pol, root + '.' + p)
            if not fd or not isinstance(other, list) or any(not isinstance(x, str) or not x for x in other):
                return 'requires %s declared as a list of non-empty strings (missing dependency); got %r' % (p, other if fd else '<absent>')
            both = sorted(set(s) & set(other))
            if both:
                return 'shares %r with %s; the sets must be disjoint' % (both, p)
        return None
    if kind == 'mode_regex_domain':
        # STRUCTURAL permission domain (C1-PREREQ-MODE-DOMAIN): every octal mode string of width 1..4 (the stat %a
        # and the zero-padded forms, 4680 strings) that the regex ADMITS (re.search: a superset of an anchored full
        # match, so an unanchored consumer is covered too) must carry none of forbidden_bits; and it must admit at
        # least one mode. Never judged by examples: 0712 / 0752 refuse because their bits do, not because listed.
        if not isinstance(s, str) or not s:
            return 'must be a non-empty regex string'
        try:
            rx = re.compile(s)
        except re.error as e:
            return 'does not compile: %s' % (e,)
        forbid, ok_n, bad = int(arg['forbidden_bits'], 8), 0, []
        for width in (1, 2, 3, 4):
            for v in range(8 ** width):
                m = format(v, '0%do' % width)
                if rx.search(m):
                    if v & forbid:
                        bad.append(m)
                    else:
                        ok_n += 1
        if bad:
            return 'admits %d mode string(s) carrying forbidden permission bits %s, e.g. %r' % (len(bad), arg['forbidden_bits'], bad[:12])
        return None if ok_n else 'admits no mode at all (an empty permission domain)'
    if kind == 'values_distinct':
        if not isinstance(s, dict) or not s:
            return 'must be a non-empty mapping'
        seen = {}
        for k in sorted(s, key=str):
            v = s[k]
            if isinstance(v, (dict, list)) or v is None or v == '':
                return 'value of %s must be a non-empty scalar; got %r' % (k, v)
            for k0, v0 in seen.items():
                if _rh_ca_same(v, v0):
                    return 'values of %s and %s are equal (%r); every value must be distinct' % (k0, k, v)
            seen[k] = v
        return None
    if kind == 'includes':
        if not isinstance(s, list):
            return 'must be a list; got a %s' % (_rh_kind(s),)
        miss = [m for m in arg if not any(_rh_ca_same(m, x) for x in s)]
        return 'must include %s (missing %s)' % (arg, miss) if miss else None
    if kind == 'placeholder_words':
        return _rh_ca_words(s, arg, pats)
    if kind == 'equals_registry':
        # one literal, owned by the registry (remote_harness_schema): the policy value must equal it; a registry
        # path that is absent (or an index outside its list) refuses, never admits vacuously. C1-EQUALS-REGISTRY-
        # NESTED-TYPES (codex 203817): SCALARS ONLY (str / int / bool, compared type-exact by _rh_ca_same); a
        # container (or any other kind) on either side refuses, since _rh_ca_same is type-exact at the top level only
        where = arg['path'] + ('[%d]' % arg['index'] if 'index' in arg else '')
        fg, want = _rh_get(schema, arg['path'])
        if fg and 'index' in arg:
            fg, want = (True, want[arg['index']]) if isinstance(want, list) and arg['index'] < len(want) else (False, None)
        if not fg:
            return 'requires registry %s declared (missing dependency)' % (where,)
        if _rh_kind(want) not in ('str', 'int', 'bool'):
            return 'compares scalars only (str, int, bool): registry %s is a %s' % (where, _rh_kind(want))
        if _rh_kind(s) not in ('str', 'int', 'bool'):
            return 'must be a scalar (str, int, bool) to equal registry %s; got a %s' % (where, _rh_kind(s))
        return None if _rh_ca_same(s, want) else 'must equal registry %s (%r)' % (where, want)
    if kind == 'equals_registry_set':
        # records-contract-set-kind-01 (codex-tick755 OPEN-S18-LATE-BINDING-KIND option ii): EXACT SET equality of a policy
        # string collection with a registry string collection: the members of a registry list, or the keys of a registry
        # mapping when the declared projection is the vocabulary.projections keys word. Both sides must be lists of strings
        # (type-exact) without a duplicate, checked BEFORE the set conversion; order is not significant; an empty set
        # equals only an empty set; an absent or differently typed reference refuses (missing dependency).
        fg, want = _rh_get(schema, arg['path'])
        if not fg:
            return 'requires registry %s declared (missing dependency)' % (arg['path'],)
        if arg['projection'] == schema['contract_admission']['vocabulary']['projections']['keys']:
            if not isinstance(want, dict):
                return 'projects the keys of registry %s, which is a %s, not a mapping (missing dependency)' % (arg['path'], _rh_kind(want))
            want = list(want)
        elif not isinstance(want, list):
            return 'compares the members of registry %s, which is a %s, not a list (missing dependency)' % (arg['path'], _rh_kind(want))
        for side, xs in (('registry %s' % (arg['path'],), want), ('the value', s)):
            if not isinstance(xs, list) or any(_rh_kind(x) != 'str' for x in xs):
                return '%s must be a list of strings; got %r' % (side, xs)
            if len(set(xs)) != len(xs):
                return '%s holds a duplicate member; got %r' % (side, xs)
        miss, extra = sorted(set(want) - set(s)), sorted(set(s) - set(want))
        return 'must equal the set of registry %s (missing %s, undeclared %s)' % (arg['path'], miss, extra) if miss or extra else None
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
        if 'reserved_outputs' in arg and isinstance(s, str):
            hit += ['reserved_output_patterns.%s' % (p,) for p in schema.get('reserved_output_patterns', []) if pats[p].fullmatch(s)]
        return 'is a registry %s name (a route/loader OUTPUT, never an external input)' % (hit,) if hit else None
    if kind == 'rejects':
        if not isinstance(s, str) or not s:
            return 'must be a non-empty regex string'
        try:
            rx = re.compile(s)
        except re.error as e:
            return 'does not compile: %s' % (e,)
        hit = [p for p in arg if rx.fullmatch(p)]
        return 'admits the refused probe values %r (a configurable pattern may never admit them)' % (hit,) if hit else None
    if kind == 'records':
        # C1-UV-ADDED-FILES (codex-d649-runtime-refusal-repair-20260924-235616): a LIST (possibly empty -- the strictest
        # declaration) of mappings, each with EXACTLY the declared field names, each field a string fully matching its
        # declared pattern. A missing value never reaches here (_rh_admit_contracts: 'is not declared').
        if not isinstance(s, list):
            return 'must be a list of {%s} mappings; got a %s' % (', '.join(sorted(arg['fields'])), _rh_kind(s))
        for i, e in enumerate(s):
            if not isinstance(e, dict) or set(e) != set(arg['fields']):
                return 'entry %d must be a mapping with exactly the keys %s; got %r' % (i, sorted(arg['fields']), e)
            for f in sorted(arg['fields']):
                p = pats[arg['fields'][f]]
                if not isinstance(e[f], str) or not p.fullmatch(e[f]):
                    return 'entry %d %s %r must fully match patterns.%s %r' % (i, f, e[f], arg['fields'][f], p.pattern)
        return None
    if kind == 'rel_disjoint':
        # C1-UV-ADDED-FILES: the <field> relative paths of a record list are pairwise distinct and never nested, and
        # overlap (equal / ancestor / descendant, compared BY COMPONENT: a == b or one is the other + '/' + more) no
        # member of the `from` nodes (relative paths in the same base) and no `from_under` path rebased onto `base`
        # (it must lie strictly under base + '/'). Every shape and reference is checked here (fail-closed, never
        # vacuous): a malformed subject refuses, an absent or malformed reference is a missing dependency.
        f = arg['field']
        if not isinstance(s, list) or any(not isinstance(e, dict) or not isinstance(e.get(f), str) or not e[f] for e in s):
            return 'must be a list of mappings each carrying a non-empty string %s' % (f,)
        rels = [e[f] for e in s]
        nested = lambda a, b: a == b or b.startswith(a + '/') or a.startswith(b + '/')
        how = lambda a, b: 'equal to' if a == b else 'an ancestor of' if b.startswith(a + '/') else 'a descendant of'
        for i in range(len(rels)):
            for j in range(i + 1, len(rels)):
                if nested(rels[i], rels[j]):
                    return '%s %r is %s %s %r (entries must be distinct and never nested)' % (f, rels[i], how(rels[i], rels[j]), f, rels[j])
        # UV-REFERENCE-NORMALIZATION (codex 001124): EVERY reference (the from_under base, each from_under path, each
        # member of each from list) must fully match the declared ref_pattern BEFORE any rebasing or comparison --
        # checked even when the subject list is empty; an unnormalized reference (x/../BUILD, bin/../bin/python3.13)
        # REFUSES, it is never normalized away (a normalized copy could differ from what the consumer reads).
        rn = arg.get('ref_pattern')
        norm = lambda x: isinstance(x, str) and bool(pats[rn].fullmatch(x))
        others = []   # from_under first, then from (the first overlap found is reported)
        if 'from_under' in arg:
            b = arg['from_under']['base']
            fb, base = _rh_get(pol, root + '.' + b)
            if not fb or not norm(base):
                return 'requires %s declared as a normalized relative path (patterns.%s) (missing dependency); got %r' % (b, rn, base if fb else '<absent>')
            for p in arg['from_under']['paths']:
                fp, node = _rh_get(pol, root + '.' + p)
                if not fp or not norm(node) or not node.startswith(base + '/'):
                    return 'requires %s declared as a normalized relative path (patterns.%s) strictly under %s %r (missing dependency); got %r' % (
                        p, rn, b, base, node if fp else '<absent>')
                others.append((p + ' (under ' + b + ')', node[len(base) + 1:]))
        for p in arg.get('from', []):
            fo, node = _rh_get(pol, root + '.' + p)
            if not fo or not isinstance(node, list) or not all(norm(x) for x in node):
                return 'requires %s declared as a list of normalized relative paths (patterns.%s) (missing dependency); got %r' % (
                    p, rn, node if fo else '<absent>')
            others.extend((p, x) for x in node)
        for r in rels:
            for p, o in others:
                if nested(r, o):
                    return '%s %r is %s %s %r' % (f, r, how(r, o), p, o)
        return None
    return 'unknown check kind'


def _rh_admit_contracts(pol, schema, key):
    """C1-BOOTSTRAP-CONTRACT-VALUE-ADMISSION: shape, enum and reference admission of every registry-declared
    controller.bootstrap contract on the COMPOSED policy, at resolve, before any mutation. Raises on the first
    refusal (named by the policy path, the contract and the check kind)."""
    pats, contracts, required = _rh_ca_registry(schema.get('contract_admission'), schema)
    for rname in sorted(required):
        r = required[rname]
        if 'when_present' in r and not _rh_get(pol, r['when_present'])[0]:
            continue
        fv, var = _rh_get(pol, r['var_at'])
        if not fv or not isinstance(var, str) or not var:
            raise ValueError('lme: %s.%s fails contract_admission.required_values.%s: must declare the variable name of the required value; got %r' % (
                key, r['var_at'], rname, var if fv else '<absent>'))
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
            # C1 s08 LH-3 (codex-tick818 :43-45; records-c1-framework-22 LH-3): a `registry` check (admitted exactly true, on
            # an `at` location, for the declared registry kinds) resolves its SUBJECT in the admitted registry; every other
            # check resolves it in the policy. Both the plain and the '*' branch use this one tree. Comparands keep their
            # existing sources (_rh_ca_check below still receives pol and schema) and the contract root stays a policy mapping.
            subj_tree = schema if 'registry' in chk else pol
            if '*' in dotted.split('.'):
                # a '*' segment: every expanded node is a subject; expanding to nothing refuses (never vacuous). codex-tick626
                # LI-OPTIONAL-RULE-EMPTY-EXPANSION: an `optional` row (a key_set optional member) checks every PRESENT member;
                # none present is admitted ONLY while the expansion up to its LAST '*' (the owner rows' subjects) is non-empty,
                # so the owner stays never-vacuous and a present malformed member still refuses
                vals = [n for _p, n in _rh_expand(subj_tree, dotted)]
                found, v = bool(vals) or (chk.get('optional') is True and bool(_rh_expand(subj_tree, dotted[:dotted.rindex('*') + 1]))), vals
                if not found and chk.get('empty_mapping') is True:
                    # C1 CURRENT correction (codex-tick860 (b)): an empty expansion is admitted ONLY when the node holding the
                    # row's '*' is present, a mapping, and empty; a missing, null or list holder refuses (is not declared), and
                    # a non-empty holder whose members do not reach the row still refuses (never vacuous otherwise).
                    segs = dotted.split('.')
                    fh, holder = _rh_get(pol, '.'.join(segs[:segs.index('*')]))
                    found = fh and isinstance(holder, dict) and not holder
            else:
                found, v = _rh_get(subj_tree, dotted)
                vals = [v]
            why = 'is not declared' if not found else None
            for val in (vals if why is None else []):
                subjects = (list(val.values()) if isinstance(val, dict) else val if isinstance(val, list) else None) if chk.get('each') else [val]
                if subjects is None:
                    why = why or 'must be a list or mapping (each)'
                elif 'where' in chk:
                    fw, want = _rh_get(pol, chk['where']['equals_at'])
                    if not fw:
                        why = why or 'selects entries by %s, which the policy does not declare (missing dependency)' % (chk['where']['equals_at'],)
                    subjects = [x for x in subjects if isinstance(x, dict) and chk['where']['field'] in x and _rh_ca_same(x[chk['where']['field']], want)]
                    if not subjects:
                        why = why or 'selects no entry whose %s equals %s (%r); the selection must not be empty' % (chk['where']['field'], chk['where']['equals_at'], want)
                for sub in subjects or []:
                    why = why or _rh_ca_check(kind, chk[kind], sub, chk, pol, pats, schema, c['root'])
            if why:
                raise ValueError('lme: %s.%s fails contract_admission.%s (%s): %s; got %r' % (key, dotted, cname, kind, why, v))


def _rh_validate(composed, declared, override, schema, *, documents, admission):
    """F05-S3 LR-02: `documents` (the resolve.yml reader fact) and `admission` (the protected source-admission record or
    None) are REQUIRED keyword arguments -- a call without them is a TypeError, never an implied empty mapping.
    Returns (section, sorted overridden paths, (active, admitted documents))."""
    key = schema['policy_key']
    ov = (override or {}).get(key) if isinstance(override, dict) else None
    if not isinstance(declared, dict) or key not in declared:
        if ov is not None:
            raise ValueError('lme: lme_global_override.%s supplied but no %s policy is declared (global/profile)' % (key, key))
        if documents != {} or admission is not None:
            raise ValueError('lme: no %s policy is declared; the document reader outputs must be an empty mapping and null; got %r / %r' % (
                key, sorted(documents) if isinstance(documents, dict) else _rh_kind(documents), _rh_kind(admission)))
        return None, [], (False, {})
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
    # GRAPH-SHARED-CONTRACT (codex-tick304): per-host INSTANCE values (a guest allocation) come ONLY from that host's
    # override; a global/profile declaration would be a default for every scope, so it refuses (registry override_only_paths).
    oop = schema.get('override_only_paths', [])
    if not isinstance(oop, list) or any(not isinstance(p, str) or not p for p in oop):
        raise ValueError('lme: registry remote_harness_schema.override_only_paths must be a list of policy paths; got %r' % (oop,))
    for p in oop:
        if _rh_get(decl, p)[0]:
            raise ValueError('lme: %s.%s is declared in global/profile; it is a per-host instance value that only that host\'s lme_global_override.%s.%s may supply (no default)' % (key, p, key, p))
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
    # GRAPH-SHARED-CONTRACT (codex-tick304): the declared target-input roles are admitted on every composition, scoped or not.
    _rh_target_inputs(pol, schema, key)
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
    # GRAPH-SHARED-CONTRACT (codex-tick304): further DECLARED logical package lists (e.g. the target prerequisite's
    # hypervisor packages) need a mapping in EVERY os family, like packages.required; absent list = not declared.
    rl = pm.get('required_lists', [])
    if not isinstance(rl, list) or any(not isinstance(p, str) or not p for p in rl):
        raise ValueError('lme: registry package_mapping.required_lists must be a list of policy paths; got %r' % (rl,))
    for p in rl:
        fl, names = _rh_get(pol, p)
        if fl:
            if not isinstance(names, list) or not names or any(not isinstance(n, str) or not n for n in names):
                raise ValueError('lme: %s.%s must be a non-empty list of logical package names; got %r' % (key, p, names))
            _pkg_check(names, p)
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
    # LI-MAIN-1 / LI-03 / L-11: the declared resolved projections, after every composed-policy check above, before every
    # digest below; host-scoped projected leaves join host_scoped_paths (derived, never listed).
    # F05-S3 (LR-03 / LR-04 / LD01): the declared documents are admitted against the protected admission record on the
    # ADMITTED composed policy, BEFORE any projection reads them (trust before parse; one activity rule).
    docs = _rh_documents(pol, schema, key, documents, admission)
    pol, pscoped = _rh_project_policy(pol, schema, key, docs[0], docs[1])
    scoped = scoped + pscoped
    shared_inputs = _rh_shared_inputs(pol, hs, scoped, key)
    section = {'schema_version': schema['projection_schema_version'], 'policy': pol, 'policy_sha256': _digest(pol),
               'adapter': {'name': sel, 'tools': derived},
               'host_scoped_paths': scoped,
               'scope_invariant_sha256': _digest({'policy': _rh_without(pol, scoped), 'host_scoped_paths': scoped}),
               'shared_artifact_inputs_sha256': _digest(shared_inputs)}
    # C1-RECIPE-PUB-02 (codex-tick884 Q290_2 c; codex-tick886 Q_R2_PROV_02; SR-292-04): the per-role generation bindings of
    # this scope (= class), after every digest above and outside the policy (a class key inside it would digest itself).
    section[_rh_gb_decl(schema)['to']] = _rh_generation_bindings(pol, section, schema, key, admission)
    section[_rh_tr_decl(schema)['to']] = _rh_toolchain_renderers(pol, schema, key)
    return section, sorted(overridden), docs


# F05-S4 RENDER-CONTEXT-02 (genesis J-FIN-F05-01): + entry_count, the number of LEADING entry templates (required).
_RH_ARTIFACT_KEYS = frozenset(('templates', 'inputs', 'checkout_inputs', 'consumers', 'not_embedded_fields', 'entry_count'))
# INSTALLED-SET-FRAGMENT (codex-tick313 R2 (a)): the ONE optional artifact key. when_present names a policy path; a
# scope whose resolved policy does not declare it neither binds the artifact's inputs nor its declared-reference
# import (an OPTIONAL fragment, composable per profile). The template proof itself stays policy-free and total.
_RH_ARTIFACT_OPTIONAL = frozenset(('when_present',))


def _rh_artifact_active(d, pol):
    """True when the artifact applies to this scope policy (no when_present, or its path is declared there)."""
    return 'when_present' not in d or _rh_get(pol, d['when_present'])[0]


def _rh_artifact_decl(hs):
    """The registry declaration host_scope.shared_artifacts, shape-checked (fail-closed)."""
    arts = hs.get('shared_artifacts')
    if not isinstance(arts, dict) or not arts:
        raise ValueError('lme: registry host_scope.shared_artifacts must declare every shared rendered artifact; got %r' % (arts,))
    for a in sorted(arts):
        d = arts[a]
        if not isinstance(d, dict) or set(d) - _RH_ARTIFACT_OPTIONAL != _RH_ARTIFACT_KEYS:
            raise ValueError('lme: registry host_scope.shared_artifacts.%s must carry exactly %s plus optionally %s' % (
                a, sorted(_RH_ARTIFACT_KEYS), sorted(_RH_ARTIFACT_OPTIONAL)))
        if 'when_present' in d and (not isinstance(d['when_present'], str) or not d['when_present']
                                    or '' in d['when_present'].split('.')):
            raise ValueError('lme: registry host_scope.shared_artifacts.%s.when_present must be a dotted policy path; got %r' % (a, d['when_present']))
        tpl, ins, cins, cons, ne = (d[k] for k in ('templates', 'inputs', 'checkout_inputs', 'consumers', 'not_embedded_fields'))
        if not isinstance(tpl, list) or not tpl or len(set(tpl)) != len(tpl) or any(
                not isinstance(p, str) or not p or p.startswith('/') or '..' in p.split('/') for p in tpl):
            raise ValueError('lme: shared_artifacts.%s.templates must be distinct repository-relative paths, entry first; got %r' % (a, tpl))
        # F05-S4 RENDER-CONTEXT-02 (J-FIN-F05-01): the leading entry_count templates are entries (each one's free
        # variables EQUAL inputs + checkout_inputs); an integer (never a bool) in [1, len(templates)]; no default.
        if not _rh_int(d['entry_count']) or not 1 <= d['entry_count'] <= len(tpl):
            raise ValueError('lme: registry host_scope.shared_artifacts.%s.entry_count must be an integer in [1, %d] (the leading entry templates of %r); got %r' % (
                a, len(tpl), tpl, d['entry_count']))
        for n, m in (('inputs', ins), ('checkout_inputs', cins)):
            if not isinstance(m, dict) or any(not isinstance(k, str) or not isinstance(v, str) or not v for k, v in m.items()):
                raise ValueError('lme: shared_artifacts.%s.%s must map template variables to policy paths; got %r' % (a, n, m))
        if not ins or set(ins) & set(cins):
            raise ValueError('lme: shared_artifacts.%s.inputs must be non-empty and disjoint from checkout_inputs' % (a,))
        # consumers = the executed-tool required_by labels whose tools the artifact serves; [] is the truthful value
        # for a pure metadata export that no executed tool consumes (codex 214135; its input proof is unchanged).
        if not isinstance(cons, list) or any(not isinstance(c, str) for c in cons):
            raise ValueError('lme: shared_artifacts.%s.consumers must be a list of consumer names ([] for a pure metadata export); got %r' % (a, cons))
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
        if not _rh_artifact_active(d, pol):
            continue
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


# C1-RECIPE-PUB-02 (OW-H11-C1-01-PUB-02; codex-tick884 Q290_2 b, c; codex-tick886 Q_R2_PROV_02; SR-292-04): the keys of
# the registry remote_harness_schema.generation_binding declaration, the semantic roles of one published binding and
# the two applicability roles. Every output word is the registry's.
_RH_GB_KEYS = frozenset(('to', 'projection', 'class_key_from', 'payload_role', 'lock_field_from', 'roles_from',
                         'lock_algorithm', 'fields', 'applicability',
                         # SR-300-09/10 HOLE-RT3-PROV-FIELD-MAP (C1 r12): the R3 provenance attestation map
                         'provenance_block', 'provenance_fields', 'not_attested'))
_RH_GB_FIELDS = frozenset(('role', 'leg', 'recipe_sha256', 'class_key', 'lock_rel', 'lock_sha256', 'bundle_provenance'))
_RH_GB_APPLICABILITY = frozenset(('applies', 'not_applicable'))


def _rh_gb_decl(schema):
    """C1-RECIPE-PUB-02: registry remote_harness_schema.generation_binding, admitted at every use. to: the section and
    scope-entry key carrying the bindings (a var_name; no section, scope or published view key); projection: a declared
    select_tree projection; class_key_from, payload_role, lock_field_from, roles_from, lock_algorithm: policy paths;
    fields: exactly the _RH_GB_FIELDS roles mapped to distinct var_name words; applicability: exactly applies and
    not_applicable mapped to distinct var_name words."""
    pats = _rh_patterns(schema)[0]
    if 'generation_binding' not in schema or 'var_name' not in pats:
        raise ValueError('lme: registry remote_harness_schema.generation_binding and contract_admission.patterns.var_name must be declared (C1-RECIPE-PUB-02)')
    gb, views, projs = schema['generation_binding'], _rh_published_view_decl(schema), schema['policy_projections']
    if not isinstance(gb, dict) or set(gb) != _RH_GB_KEYS \
            or any(not isinstance(gb[k], str) or not gb[k] for k in sorted(_RH_GB_KEYS - {'fields', 'applicability', 'provenance_fields', 'not_attested'})) \
            or not isinstance(gb['fields'], dict) or set(gb['fields']) != _RH_GB_FIELDS \
            or not isinstance(gb['applicability'], dict) or set(gb['applicability']) != _RH_GB_APPLICABILITY:
        raise ValueError('lme: registry remote_harness_schema.generation_binding must carry exactly %s of non-empty strings, fields exactly %s and applicability exactly %s; got %r' % (
            sorted(_RH_GB_KEYS), sorted(_RH_GB_FIELDS), sorted(_RH_GB_APPLICABILITY), gb))
    # SR-300-09/10 HOLE-RT3-PROV-FIELD-MAP (C1 r12): provenance_block is a var_name; provenance_fields maps distinct
    # var_name block keys to distinct fields roles; not_attested lists the remaining roles; together exactly
    # _RH_GB_FIELDS, disjoint (lme_source_binding ties the block keys and its role enum to the record schema and policy).
    pf, na = gb['provenance_fields'], gb['not_attested']
    if not isinstance(pf, dict) or not pf or not isinstance(na, list) \
            or any(not isinstance(k, str) or not pats['var_name'].fullmatch(k) for k in pf) \
            or any(not isinstance(v, str) or v not in _RH_GB_FIELDS for v in list(pf.values()) + na) \
            or len(set(pf.values())) != len(pf) or len(set(na)) != len(na) \
            or set(pf.values()) & set(na) or set(pf.values()) | set(na) != _RH_GB_FIELDS \
            or not pats['var_name'].fullmatch(gb['provenance_block']):
        raise ValueError('lme: registry remote_harness_schema.generation_binding (HOLE-RT3-PROV-FIELD-MAP): provenance_block must be a var_name, provenance_fields map distinct var_name block keys to distinct fields roles and not_attested list the other roles, together exactly %s and disjoint; got %r / %r / %r' % (
            sorted(_RH_GB_FIELDS), gb['provenance_block'], pf, na))
    words = [gb['to']] + list(gb['fields'].values()) + list(gb['applicability'].values())
    if any(not isinstance(w, str) or not pats['var_name'].fullmatch(w) for w in words) \
            or len(set(gb['fields'].values())) != len(_RH_GB_FIELDS) or len(set(gb['applicability'].values())) != len(_RH_GB_APPLICABILITY) \
            or gb['to'] in _RH_BASE_KEYS | _RH_SCOPED_KEYS | set(_RH_SCOPE_ENTRY) | {'kind', 'id'} or gb['to'] in views \
            or not isinstance(projs, dict) or gb['projection'] not in projs or not isinstance(projs[gb['projection']], dict) \
            or 'kind' not in projs[gb['projection']] or projs[gb['projection']]['kind'] != 'select_tree':
        raise ValueError('lme: registry remote_harness_schema.generation_binding: to and every field / applicability word must be a distinct var_name, to no section, scope or published view key, and projection a declared select_tree projection; got %r' % (gb,))
    return gb


def _rh_tr_decl(schema):
    """The declared complete-renderer view is outside policy, alongside generation bindings.

    It consumes the existing selected recipe projection; it never selects a recipe address
    or reads declarations. The destination and content names belong to the registry.
    """
    d = schema.get('toolchain_rendering')
    pats = _rh_patterns(schema)[0]
    if not isinstance(d, dict) or set(d) != {'to', 'base', 'projection', 'output'} \
            or any(not isinstance(v, str) or not v for v in d.values()):
        raise ValueError(schema['toolchain_rendering_errors']['shape'])
    if 'var_name' not in pats or any(not pats['var_name'].fullmatch(d[k]) for k in ('to', 'output')) \
            or any(not pats['var_name'].fullmatch(x) for x in d['base'].split('.')):
        raise ValueError(schema['toolchain_rendering_errors']['names'])
    taken = _RH_BASE_KEYS | _RH_SCOPED_KEYS | set(_RH_SCOPE_ENTRY) | {'kind', 'id'} \
        | set(_rh_published_view_decl(schema)) | {_rh_gb_decl(schema)['to']}
    projs = schema['policy_projections']
    if d['to'] in taken or d['projection'] not in projs or projs[d['projection']]['kind'] != 'select_tree':
        raise ValueError(schema['toolchain_rendering_errors']['destination'])
    if d['projection'] != schema['generation_binding']['projection']:
        raise ValueError(schema['toolchain_rendering_errors']['projection'])
    return d


def _rh_toolchain_renderers(pol, schema, key):
    """Materialize complete renderer inputs from one fully resolved policy.

    Copy the declared common base, then replace exactly the recipe projection's admitted
    leaves with their already published values. This is a loader projection, not another
    desired-state merge: no defaults, selection, file I/O or consumer-side reconstruction.
    The view stays outside policy, so it cannot contain itself. Both publication and
    verification invoke this same function.
    """
    d = _rh_tr_decl(schema)
    pj = schema['policy_projections'][d['projection']]
    fb, base = _rh_get(pol, d['base'])
    fp, published = _rh_get(pol, pj['at'] + '.' + pj['to'])
    if not fb or not isinstance(base, dict) or not fp or not isinstance(published, dict) or not published:
        raise ValueError(schema['toolchain_rendering_errors']['inputs'] % (key,))
    expected = _rh_pj_select_tree(d['projection'], pj, pol, key, _rh_patterns(schema)[0])
    if not _leaf_equal(published, expected):
        raise ValueError(schema['toolchain_rendering_errors']['selected'] % (key,))
    out = {}
    for role in sorted(published):
        ctl = copy.deepcopy(base)
        tree = published[role][pj['outputs']['tree']]
        for path in pj['leaves']:
            found, value = _rh_get(tree, path)
            if not found:
                raise ValueError(schema['toolchain_rendering_errors']['leaf'] % (key, role, path))
            parent, parts = ctl, path.split('.')
            for part in parts[:-1]:
                if part not in parent or not isinstance(parent[part], dict):
                    raise ValueError(schema['toolchain_rendering_errors']['base_path'] % (key, path))
                parent = parent[part]
            if parts[-1] not in parent:
                raise ValueError(schema['toolchain_rendering_errors']['base_leaf'] % (key, path))
            parent[parts[-1]] = copy.deepcopy(value)
        out[role] = {d['output']: ctl}
    return out


def _rh_generation_bindings(pol, sec, schema, key, admission):
    """C1-RECIPE-PUB-02 (codex-tick884 Q290_2 b, c; codex-tick883 Q290_1; codex-tick886 Q_R2_PROV_02; SR-292-04):
    {role: binding} for every role the projection published in pol (one scope's resolved policy = one class), each
    exactly the declared fields: role; leg and recipe_sha256 as the projection published them; class_key = sec[<the
    value at class_key_from>] (the serving scope's own class identity, bootstrap.bundle.per_class.key_field -- the
    engine-derived key PUB-01 names, never a receipt claim); lock_rel = the role recipe's <value at lock_field_from>
    (lock_capture.input_binding.field); lock_sha256 = the observed digest the protected source-admission record holds
    for lock_rel (the admitted lock bytes, read through document_channel.admission; lock_algorithm must equal the
    channel digest algorithm); bundle_provenance = applicability.applies exactly for the role at payload_role, else
    applicability.not_applicable (declared, so absence never switches a check off). Outside the policy and after its
    digests. No fallback: no admission record, an unadmitted lock, an unknown role or a differing algorithm refuses."""
    gb, ch = _rh_gb_decl(schema), _rh_document_channel(schema)
    pj = schema['policy_projections'][gb['projection']]
    ow, am = pj['outputs'], ch['admission']
    paths = {'published': '%s.%s' % (pj['at'], pj['to']), 'class_key_from': gb['class_key_from'], 'payload_role': gb['payload_role'],
             'lock_field_from': gb['lock_field_from'], 'roles_from': gb['roles_from'], 'lock_algorithm': gb['lock_algorithm'],
             'admission_algorithm': ch['digest_algorithm'], 'members': am['members'], 'observed': am['observed']}
    got = dict((n, _rh_get(pol, p)) for n, p in sorted(paths.items()))
    absent = sorted(paths[n] for n in got if not got[n][0])
    if absent:
        raise ValueError('lme: %s generation bindings (C1-RECIPE-PUB-02): the resolved policy declares no %s' % (key, absent))
    pub, kf, prole, lf, roles = (got[n][1] for n in ('published', 'class_key_from', 'payload_role', 'lock_field_from', 'roles_from'))
    lalg, aalg, mk, ok = (got[n][1] for n in ('lock_algorithm', 'admission_algorithm', 'members', 'observed'))
    if not isinstance(pub, dict) or not isinstance(roles, list) or any(not isinstance(r, str) for r in roles) or sorted(pub) != sorted(roles) \
            or len(set(roles)) != len(roles) or not isinstance(prole, str) or prole not in roles or not isinstance(lf, str) or not lf \
            or not isinstance(kf, str) or kf not in sec or not isinstance(sec[kf], str) or not sec[kf] \
            or not isinstance(lalg, str) or lalg != aalg or not isinstance(mk, str) or not isinstance(ok, str):
        raise ValueError('lme: %s generation bindings (C1-RECIPE-PUB-02): %s must publish exactly the roles at %s, %s must name one of them, %s a section class key, and %s must equal %s; got roles %r / %r, payload role %r, class key field %r, algorithms %r / %r' % (
            key, paths['published'], gb['roles_from'], gb['payload_role'], gb['class_key_from'], gb['lock_algorithm'], ch['digest_algorithm'],
            sorted(pub) if isinstance(pub, dict) else _rh_kind(pub), roles, prole, kf, lalg, aalg))
    if not isinstance(admission, dict) or mk not in admission or not isinstance(admission[mk], dict):
        raise ValueError('lme: %s generation bindings (C1-RECIPE-PUB-02): lock_sha256 is read only from the protected source-admission record (%s), which is absent or carries no %r mapping; nothing stands in for it' % (
            key, am['fact'], mk))
    adm, f, ap, out = admission[mk], gb['fields'], gb['applicability'], {}
    for role in sorted(pub):
        ent = pub[role]
        if not isinstance(ent, dict) or set(ent) != set(ow.values()) or not isinstance(ent[ow['tree']], dict) or lf not in ent[ow['tree']]:
            raise ValueError('lme: %s.%s.%s must carry exactly %s with %s in its %s (C1-RECIPE-PUB-02)' % (key, paths['published'], role, sorted(ow.values()), lf, ow['tree']))
        rel = ent[ow['tree']][lf]
        if not isinstance(rel, str) or rel not in adm or not isinstance(adm[rel], dict) or ok not in adm[rel] or not isinstance(adm[rel][ok], str) or not adm[rel][ok]:
            raise ValueError('lme: %s generation bindings.%s: lock %r is no admitted source member with an observed digest (%s.%s.<rel>.%s); lock_sha256 has no source' % (
                key, role, rel, am['fact'], mk, ok))
        out[role] = {f['role']: role, f['leg']: ent[ow['selected']], f['recipe_sha256']: ent[ow['digest']], f['class_key']: sec[kf],
                     f['lock_rel']: rel, f['lock_sha256']: adm[rel][ok],
                     f['bundle_provenance']: ap['applies'] if role == prole else ap['not_applicable']}
    return out


def _rh_safe_rel(p):
    """A normalized, relative repository path: non-empty, not absolute, no '.' / '..' / empty component."""
    import posixpath
    return isinstance(p, str) and bool(p) and not p.startswith('/') and posixpath.normpath(p) == p \
        and not ({'.', '..'} & set(p.split('/')))


_RH_IMPORT_FILTERS = ('relpath', 'dirname')
# SOFT-FRAME (codex 220953): the COMPILER-ONLY known capabilities beyond Jinja's builtin tests -- names the templates
# may reference, never executed by the proof (inert). `match`: the Ansible test plugin the canonical macros use
# (controller_seed.j2 `is match(...)` and reject('match', ...)); the pinned cores define it in
# ansible/plugins/test/core.py (see the edition evidence in the C1 hand-back). No other plugin name is admitted.
_RH_KNOWN_TESTS = ('match',)
# filters whose positional argument NAMES another capability: select / reject / selectattr / rejectattr name a TEST,
# map names a FILTER; {filter: (argument index, 'test' | 'filter')}
_RH_NAMED_CAPABILITY_ARGS = {'select': (0, 'test'), 'reject': (0, 'test'), 'selectattr': (1, 'test'),
                             'rejectattr': (1, 'test'), 'map': (0, 'filter')}


def _rh_inert_filter(name):
    """IMPORT-STATIC-FILTER-KNOWLEDGE (codex 214135): a PARSE-ONLY stand-in so the static analysis
    (meta.find_undeclared_variables compiles the AST; plain Jinja refuses an unknown filter there) knows the two
    filters of the declared-reference import. The proof never renders; a call is a defect and raises."""
    def inert(*args, **kwargs):
        raise ValueError('lme: %s is a parse-only stand-in of the artifact template proof (never rendered)' % (name,))
    return inert


def _rh_declared_import(a, path, i, imp, d, nodes, tree):
    """C1-DECLARED-REFERENCE-IMPORT (codex 213721; codex 214135). The ONE admitted non-literal import target, an
    explicitly bounded AST (no evaluation, no calls, no lookups, no ambient context):
        {% import <ref A> | relpath(<ref B> | dirname) as <name> %}
    Import(template=Filter(relpath, node=<ref A>, args=[Filter(dirname, node=<ref B>, args=[])]), with_context=False),
    every Filter without kwargs / *args / **kwargs; each <ref> a Getattr chain of constant attribute names rooted at
    Name(<a declared INPUT of this artifact>, load) -- no Getitem, no Call, no other filter or node. Only in the entry
    template; never with context. IMPORT-LEXICAL-BINDING: the template may not bind a referenced root anywhere
    (set / block set / for / with target, macro or call-block parameter, import-as / from-import alias), since the
    references are resolved against the DECLARED binding, not a template-local value (free-variable equality alone
    does not prove the importer still reads the declared input). POLICY-FREE (the shape only); runs BEFORE the
    free-variable analysis. Returns the proved reference record; the VALUES are bound per scope by
    _rh_bind_declared_import. Raises otherwise."""
    at = 'lme: shared artifact %s template %s declared import' % (a, path)
    shape = ('%s must be exactly `<declared input>.<attr>... | relpath(<declared input>.<attr>... | dirname)`: attribute'
             ' references only, filters relpath / dirname only, no call, item access, other filter or argument' % at)
    if i != 0:
        raise ValueError('%s is admitted in the entry template only (non-entry templates read no variables)' % (at,))
    if type(imp) is not nodes.Import:
        raise ValueError(shape + ' (got a from-import)')
    if imp.with_context:
        raise ValueError('%s carries context (only declared templates, without context)' % (at,))

    def plain(f, name, nargs):
        return type(f) is nodes.Filter and f.name == name and len(f.args) == nargs and not f.kwargs \
            and f.dyn_args is None and f.dyn_kwargs is None

    t = imp.template
    if not plain(t, 'relpath', 1) or not plain(t.args[0], 'dirname', 0):
        got = type(t).__name__
        if type(t) is nodes.Filter:
            got = 'filter %s over %s' % (t.name, ('filter ' + str(t.args[0].name)) if (t.args and type(t.args[0]) is nodes.Filter)
                                          else (type(t.args[0]).__name__ if t.args else 'no argument'))
        raise ValueError(shape + ' (got %s)' % (got,))

    def ref(n, role):
        chain = []
        while type(n) is nodes.Getattr and isinstance(n.attr, str):
            chain.append(n.attr)
            n = n.node
        if type(n) is not nodes.Name or n.ctx != 'load' or not chain:
            raise ValueError(shape + ' (%s reference is a %s)' % (role, type(n).__name__))
        if n.name not in d['inputs']:
            raise ValueError('%s %s reference root %r is not a declared input of this artifact %r (undeclared variable)' % (
                at, role, n.name, sorted(d['inputs'])))
        return n.name, tuple(reversed(chain))

    refs = {'target': ref(t.node, 'target'), 'entry-path': ref(t.args[0].node, 'entry-path')}
    bound = set(n.name for n in tree.find_all(nodes.Name) if n.ctx in ('store', 'param'))
    for m in tree.find_all((nodes.Import, nodes.FromImport)):
        if type(m) is nodes.Import:
            bound.add(m.target)
        else:
            bound.update(x[1] if isinstance(x, tuple) else x for x in m.names)
    # C1-IMPORT-MACRO-NAME-SHADOW (codex 221058): a macro declaration binds its NAME (a plain string, not a Name node;
    # jinja2 idtracking visit_Macro stores node.name), so `{% macro <root>() %}` shadows the root like any binder.
    # The string-named binders are exactly Macro.name, Import.target and FromImport names / aliases (idtracking).
    bound.update(m.name for m in tree.find_all(nodes.Macro))
    rebound = sorted(set(r[0] for r in refs.values()) & set(n for n in bound if isinstance(n, str)))
    if rebound:
        raise ValueError('%s: the template binds referenced input root(s) %s locally (set / for / with / macro or call parameter /'
                         ' import alias): a template-local value would replace the declared binding (lexical binding)' % (at, rebound))
    return {'artifact': a, 'template': path, 'refs': refs}


def _rh_bind_declared_import(rec, d, label, pol):
    """C1-DECLARED-REFERENCE-IMPORT, the VALUE binding (codex 213721; IMPORT-PER-SCOPE-BINDING + IMPORT-LOADER-LAYOUT,
    codex 214135), against ONE already-resolved scope policy `pol` (the caller passes EVERY scope's; no merge here).
    Each reference resolves through the artifact's declared input binding (the same subtree _rh_shared_inputs binds
    into that scope's shared_artifact_inputs_sha256) to a normalized relative repository path. The entry-path
    reference must equal the artifact's entry template; the target must lie strictly inside the entry's directory
    and be a declared NON-entry template (a member of artifact_sources, parsed and proved). LOADER LAYOUT: the render
    resolves relpath(target, dirname(entry)) against the entry's directory (the template's own search path);
    jinja2's loader refuses a '..' piece and drops '.' / empty pieces, so only a normalized path with no '..' is
    admitted and entry_dir + '/' + relpath is then exactly the declared target: what the proof binds is what the
    loader opens. Any other layout refuses here, at resolve, before any render; there is no fixed-path fallback."""
    at = 'lme: shared artifact %s template %s declared import' % (rec['artifact'], rec['template'])
    where = ' [scope %s]' % (label,)
    vals = {}
    for role in ('target', 'entry-path'):
        root, attrs = rec['refs'][role]
        dotted = d['inputs'][root] + '.' + '.'.join(attrs)
        f, v = _rh_get(pol, dotted)
        if not f or not isinstance(v, str) or not v:
            raise ValueError('%s %s reference %s names %s, which the resolved policy does not declare as a non-empty string (missing target)%s' % (
                at, role, root + '.' + '.'.join(attrs), dotted, where))
        if not _rh_safe_rel(v):
            raise ValueError('%s %s reference %s = %r is not a normalized relative repository path (unsafe path)%s' % (at, role, dotted, v, where))
        vals[role] = v
    tgt, entry = vals['target'], vals['entry-path']
    if entry != d['templates'][0]:
        raise ValueError('%s entry-path reference = %r is not this artifact\'s entry template %r%s' % (at, entry, d['templates'][0], where))
    start = entry.rsplit('/', 1)[0] if '/' in entry else ''
    if not start or not tgt.startswith(start + '/'):
        raise ValueError('%s target %r lies outside the entry directory %r: relpath would carry \'..\', which the template loader refuses (unsafe path)%s' % (
            at, tgt, start, where))
    if tgt not in d['templates'][d['entry_count']:]:
        raise ValueError('%s resolves to %r (relpath %r), which is not a declared non-entry template of this artifact %r (mismatch)%s' % (
            at, tgt, tgt[len(start) + 1:], d['templates'][d['entry_count']:], where))
    return tgt[len(start) + 1:]


def _rh_prove_artifact_templates(hs, sources):
    """C1-ARTIFACT-REUSE-INPUT-COVERAGE: prove the shared_artifacts declaration against the ACTUAL template sources
    (the loader reads them; artifact_sources = {repository-relative path: content}). The entry template's free
    variables must EQUAL inputs + checkout_inputs (anything else it consumes is missing from the declaration); it
    and every other template import only declared templates, never with context, and never include/extend (a
    context-carrying load could read undeclared variables); non-entry templates have no free variables; a
    not_embedded field name is never an attribute, item or string constant of any template. Raises otherwise.
    A literal (Const) import keeps exactly this proof. The entry template may instead import through the ONE
    declared-reference form (_rh_declared_import; codex 213721 / 214135): its SHAPE is proved here, before the
    free-variable analysis; relpath / dirname are known to that analysis as parse-only stand-ins and admitted in
    that proved operand ONLY. Returns the proved reference records; the caller binds their VALUES against every
    scope policy (_rh_bind_declared_import) -- a record left unbound is never admitted."""
    import jinja2
    from jinja2 import meta, nodes
    arts = _rh_artifact_decl(hs)
    want = sorted(set(p for d in arts.values() for p in d['templates']))
    if not isinstance(sources, dict) or sorted(sources) != want or any(not isinstance(v, str) for v in sources.values()):
        raise ValueError('lme: remote-harness scope artifact_sources must carry exactly the declared templates %r; got %r' % (
            want, sorted(sources) if isinstance(sources, dict) else sources))
    env = jinja2.Environment(extensions=['jinja2.ext.do', 'jinja2.ext.loopcontrols'])
    builtin_filters = frozenset(env.filters)
    known_tests = frozenset(env.tests) | frozenset(_RH_KNOWN_TESTS)
    env.filters.update((n, _rh_inert_filter(n)) for n in _RH_IMPORT_FILTERS)
    env.tests.update((n, _rh_inert_filter(n)) for n in _RH_KNOWN_TESTS)
    found = []
    for a, d in sorted(arts.items()):
        base = d['templates'][0].rsplit('/', 1)[0] if '/' in d['templates'][0] else ''
        for i, path in enumerate(d['templates']):
            try:
                ast = env.parse(sources[path])
            except jinja2.TemplateSyntaxError as e:
                raise ValueError('lme: shared artifact %s template %s does not parse: %s' % (a, path, e))
            admitted = set()
            for imp in ast.find_all((nodes.Import, nodes.FromImport)):
                if not isinstance(imp.template, nodes.Const):
                    found.append(_rh_declared_import(a, path, i, imp, d, nodes, ast))
                    admitted.update((id(imp.template), id(imp.template.args[0])))
            filters = list(ast.find_all(nodes.Filter))
            stray = sorted(set(f.name for f in filters if f.name in _RH_IMPORT_FILTERS and id(f) not in admitted))
            if stray:
                raise ValueError('lme: shared artifact %s template %s uses filter(s) %s outside the declared import operand (the static proof admits them there only)' % (a, path, stray))
            # SOFT-FRAME (codex 220953): every filter and test NAME is checked explicitly, in EVERY frame -- the
            # compile inside find_undeclared_variables refuses an unknown name only in hard frames (an if test / body
            # and a condexpr are soft: jinja2 compiler.py _filter_test_common), so it is not relied on here.
            unknown = sorted(set(f.name for f in filters if f.name not in builtin_filters and f.name not in _RH_IMPORT_FILTERS))
            if unknown:
                raise ValueError('lme: shared artifact %s template %s uses filter(s) %s the static proof does not know (Jinja builtin filters only, in every frame; relpath / dirname in the declared import operand only)' % (a, path, unknown))
            tests = set(t.name for t in ast.find_all(nodes.Test))
            for f in filters:
                if f.name not in _RH_NAMED_CAPABILITY_ARGS:
                    continue
                pos, what = _RH_NAMED_CAPABILITY_ARGS[f.name]
                arg = f.args[pos] if len(f.args) > pos else None
                if f.dyn_args is not None or (arg is not None and (type(arg) is not nodes.Const or not isinstance(arg.value, str))):
                    raise ValueError('lme: shared artifact %s template %s passes a non-literal %s name to %s (the static proof admits literal names only)' % (a, path, what, f.name))
                if arg is not None and what == 'test':
                    tests.add(arg.value)
                elif arg is not None and arg.value in _RH_NAMED_CAPABILITY_ARGS:
                    # C1-NESTED-CAPABILITY-DISPATCH (codex 222326): map forwards its remaining arguments to
                    # environment.call_filter (jinja2 filters.py prepare_map), so a higher-order named-dispatch filter
                    # named through map would dispatch an inner name this check never sees -- refused, not chased.
                    raise ValueError('lme: shared artifact %s template %s composes higher-order filter %r through map; unsupported (the static proof checks one named dispatch per filter)' % (a, path, arg.value))
                elif arg is not None and arg.value not in builtin_filters:
                    raise ValueError('lme: shared artifact %s template %s names filter %r through map (Jinja builtin filters only)' % (a, path, arg.value))
            unknown = sorted(tests - known_tests)
            if unknown:
                raise ValueError('lme: shared artifact %s template %s uses test(s) %s the static proof does not know (Jinja builtin tests plus the declared known capability %s, in every frame)' % (a, path, unknown, list(_RH_KNOWN_TESTS)))
            try:
                free = set(meta.find_undeclared_variables(ast))
            except jinja2.TemplateError as e:
                raise ValueError('lme: shared artifact %s template %s does not analyze statically (plain Jinja plus the declared-import stand-ins): %s' % (a, path, e))
            declared = set(d['inputs']) | set(d['checkout_inputs'])
            # F05-S4 RENDER-CONTEXT-02 (J-FIN-F05-01): every one of the leading entry_count templates is an entry
            if i < d['entry_count'] and free != declared:
                raise ValueError('lme: shared artifact %s entry template %s consumes %s; the declaration names %s (undeclared: %s; unconsumed: %s)' % (
                    a, path, sorted(free), sorted(declared), sorted(free - declared), sorted(declared - free)))
            if i >= d['entry_count'] and free:
                raise ValueError('lme: shared artifact %s template %s reads variables %s outside its macro parameters' % (a, path, sorted(free)))
            if list(ast.find_all((nodes.Include, nodes.Extends))):
                raise ValueError('lme: shared artifact %s template %s includes/extends (context-carrying; undeclared inputs)' % (a, path))
            for imp in ast.find_all((nodes.Import, nodes.FromImport)):
                if not isinstance(imp.template, nodes.Const):
                    continue  # the declared-reference form, shape-proved above; its values bind per scope
                tgt = imp.template.value if isinstance(imp.template, nodes.Const) else None
                if imp.with_context or not isinstance(tgt, str) or ((base + '/' if base else '') + tgt) not in d['templates']:
                    raise ValueError('lme: shared artifact %s template %s imports %r (only declared templates, without context)' % (a, path, tgt))
            names = set(n.attr for n in ast.find_all(nodes.Getattr)) | set(
                n.value for n in ast.find_all(nodes.Const) if isinstance(n.value, str))
            hit = sorted(set(d['not_embedded_fields']) & names)
            if hit:
                raise ValueError('lme: shared artifact %s template %s reads %s, declared not_embedded (the reuse key would omit an embedded input)' % (a, path, hit))
    return found


_RH_ENDPOINT_KEY = ('address', 'port', 'proxy_jump', 'owner')
# H-FORM-1 / H-FORM-VOCAB (route r4j, codex-tick445/455/462): the ONE shared inventory-form interpreter. Its
# vocabulary (entry keys, refuse token, tests, outcomes, result keys, cause tokens) is the DECLARED node
# controller.bootstrap.ssh_auth.composition.form_semantics (registry host_scope.endpoint.semantics_path). The only
# code-side names are the primitive implementation table (name -> its declared parameter set) and the cause-emission
# roles; neither is an exemption: both are joined by SET EQUALITY to the registry (host_scope.endpoint.form_primitives,
# .form_cause_roles) on every resolve, and the cause roles to the key set of form_semantics.causes, so neither side can
# add, drop or rename one alone (drift refuses).
_RH_FORM_PRIMITIVES = {'key_absent': frozenset(), 'equals_literal': frozenset(('literal',)),
                       'equals_selected_mode_field': frozenset(('field',)),
                       'full_match_capture': frozenset(('regex', 'groups', 'group'))}
_RH_FORM_CAUSE_ROLES = frozenset(('rule_invalid', 'source_not_mapping', 'no_accepted_form'))
_RH_FORM_SEMANTICS_KEYS = frozenset(('entry_keys', 'refuse_token', 'tests', 'outcomes', 'result', 'causes'))
_RH_FORM_RESULT_ROLES = frozenset(('admitted', 'jump', 'cause'))


def _rh_form_admit(fs, rule, primitives, cause_roles, where):
    """PHASE 1 (r4j declaration_admission): admit the form vocabulary as a DECLARATION before the interpreter is ever
    invoked. primitives / cause_roles are the registry lists (the loader) or the code tables (the filter adapter, which
    runs on a projection the loader already joined). A malformed or missing vocabulary RAISES (a declaration refusal);
    it never becomes a typed interpreter result. Returns the admitted form_semantics."""
    nes = lambda x: isinstance(x, str) and bool(x)
    if not isinstance(primitives, list) or not all(nes(p) for p in primitives) or set(primitives) != set(_RH_FORM_PRIMITIVES) \
            or len(set(primitives)) != len(primitives):
        raise ValueError('lme: %s: form_primitives %r must be exactly the interpreter primitive table %s (set equality, no duplicates)' % (
            where, primitives, sorted(_RH_FORM_PRIMITIVES)))
    if not isinstance(cause_roles, list) or not all(nes(c) for c in cause_roles) or set(cause_roles) != _RH_FORM_CAUSE_ROLES \
            or len(set(cause_roles)) != len(cause_roles):
        raise ValueError('lme: %s: form_cause_roles %r must be exactly the interpreter cause roles %s (set equality, no duplicates)' % (
            where, cause_roles, sorted(_RH_FORM_CAUSE_ROLES)))
    if not isinstance(fs, dict) or set(fs) != _RH_FORM_SEMANTICS_KEYS:
        raise ValueError('lme: %s.form_semantics must be exactly %s; got %r' % (where, sorted(_RH_FORM_SEMANTICS_KEYS), fs))
    ek, tests, outs, res, causes = fs['entry_keys'], fs['tests'], fs['outcomes'], fs['result'], fs['causes']
    if not isinstance(ek, list) or not ek or not all(nes(k) for k in ek) or len(set(ek)) != len(ek) or not nes(fs['refuse_token']):
        raise ValueError('lme: %s.form_semantics.entry_keys must be distinct non-empty strings and refuse_token a non-empty string; got %r / %r' % (
            where, ek, fs['refuse_token']))
    if not isinstance(tests, dict) or not tests:
        raise ValueError('lme: %s.form_semantics.tests must be a non-empty mapping; got %r' % (where, tests))
    for t in sorted(tests, key=str):
        d = tests[t]
        p = d.get('primitive') if isinstance(d, dict) else None
        if not nes(t) or p not in primitives or set(d) != {'primitive'} | _RH_FORM_PRIMITIVES[p]:
            raise ValueError('lme: %s.form_semantics.tests.%s must be {primitive in %s, exactly that primitive\'s parameters}; got %r' % (
                where, t, sorted(primitives), d))
        if 'literal' in d and not isinstance(d['literal'], str) or 'field' in d and not nes(d['field']) \
                or 'regex' in d and not nes(d['regex']) \
                or 'groups' in d and not (_rh_int(d['groups']) and d['groups'] >= 1 and _rh_int(d['group']) and 1 <= d['group'] <= d['groups']):
            raise ValueError('lme: %s.form_semantics.tests.%s has a mistyped parameter (literal string; field / regex non-empty string; 1 <= group <= groups integers); got %r' % (
                where, t, d))
    if not isinstance(outs, dict) or not outs or any(
            not nes(o) or not isinstance(outs[o], dict) or not isinstance(outs[o].get('value'), str)
            or not (set(outs[o]) == {'value', 'jump'} and isinstance(outs[o]['jump'], str)
                    or set(outs[o]) == {'value', 'test'} and outs[o]['test'] in tests and 'regex' in tests[outs[o]['test']])
            for o in outs) or len(set(outs[o]['value'] for o in outs)) != len(outs):
        raise ValueError('lme: %s.form_semantics.outcomes must map each outcome to {value, jump} (a fixed jump) or {value, test} (the capture of a capture test), values distinct; got %r' % (
            where, outs))
    if not isinstance(res, dict) or set(res) != _RH_FORM_RESULT_ROLES or not all(nes(v) for v in res.values()) or len(set(res.values())) != len(res):
        raise ValueError('lme: %s.form_semantics.result must map exactly %s to distinct non-empty keys; got %r' % (
            where, sorted(_RH_FORM_RESULT_ROLES), res))
    if not isinstance(causes, dict) or set(causes) != set(cause_roles) or not all(nes(v) for v in causes.values()) \
            or len(set(causes.values())) != len(causes):
        raise ValueError('lme: %s.form_semantics.causes must map exactly the cause roles %s to distinct non-empty tokens; got %r' % (
            where, sorted(cause_roles), causes))
    return fs


def _rh_form_invalid(fs, rule, auth):
    """PHASE 2: the WHOLE declared rule under the ADMITTED vocabulary (every entry, whatever its position; independent
    of the mode argument). None when valid, else the reason."""
    if not isinstance(rule, dict) or not isinstance(rule.get('inventory_forms'), dict) or not isinstance(rule.get('proxy_jump'), dict):
        return 'the rule must carry inventory_forms and proxy_jump mappings'
    fm = rule['inventory_forms']
    acc, tests, outs = fm.get('accepted'), fs['tests'], fs['outcomes']
    by_value = dict((o['value'], o) for o in outs.values())
    if fm.get('other') != fs['refuse_token']:
        return 'inventory_forms.other must be the declared refuse token %r; got %r' % (fs['refuse_token'], fm.get('other'))
    if not isinstance(acc, list) or not acc:
        return 'inventory_forms.accepted must be a non-empty list'
    for i, a in enumerate(acc):
        if not isinstance(a, dict) or set(a) != set(fs['entry_keys']):
            return 'inventory_forms.accepted[%d] must carry exactly the declared entry keys %s; got %r' % (i, fs['entry_keys'], a)
        if a.get('test') not in tests or a.get('proxy_jump') not in by_value:
            return 'inventory_forms.accepted[%d] test must be a declared test %s and proxy_jump a declared outcome value %s; got %r' % (
                i, sorted(tests), sorted(by_value), a)
        o = by_value[a['proxy_jump']]
        if any((a['test'] == p['test']) != (a['proxy_jump'] == p['value']) for p in outs.values() if 'test' in p):
            return 'inventory_forms.accepted[%d] breaks the declared outcome pairing (a capture outcome iff its capture test); got %r' % (i, a)
        if 'test' in o and o['test'] != a['test']:
            return 'inventory_forms.accepted[%d] pairs capture outcome %r with test %r' % (i, a['proxy_jump'], a['test'])
    if fm.get('var') != rule['proxy_jump'].get('var') or not isinstance(fm.get('var'), str) or not fm['var']:
        return 'inventory_forms.var must be the proxy_jump var %r' % (rule['proxy_jump'].get('var'),)
    for t in sorted(tests):
        d = tests[t]
        if 'regex' in d:
            f, rx = _rh_get(rule, d['regex'])
            try:
                ok = f and isinstance(rx, str) and re.compile(rx).groups == d['groups']
            except re.error:
                ok = False
            if not ok:
                return 'test %s regex %s must be a compilable string with exactly %d group(s); got %r' % (t, d['regex'], d['groups'], rx if f else '<absent>')
        if 'field' in d:
            modes = auth.get('modes') if isinstance(auth, dict) else None
            if not isinstance(modes, dict) or not modes or any(not isinstance(m, dict) or not isinstance(m.get(d['field']), str) for m in modes.values()):
                return 'auth modes must be a mapping, each mode with a string %s (test %s)' % (d['field'], t)
    return None


def _rh_form_classify(fs, rule, auth, source, mode):
    """The pure core (both adapters): (admitted, jump, cause role). Validation first (rule_invalid), then the source
    (source_not_mapping: collections.abc.Mapping, so Ansible HostVarsVars qualifies), then the FIRST accepted form in
    declared order whose test holds. The proxy role is ABSENT iff the var is not a key; a supplied null is a value no
    test admits. mode is classification context only: ONLY a string key of auth.modes enables a selected-mode test; any
    other value just leaves that test false (never a refusal, never a mode cause). Capture is anchored at end of string
    (re.match + \\Z, the loader law); no normalization -- the jump is the exact input substring."""
    if _rh_form_invalid(fs, rule, auth) is not None:
        return False, None, 'rule_invalid'
    if not isinstance(source, Mapping):
        return False, None, 'source_not_mapping'
    var = rule['inventory_forms']['var']
    present = var in source
    j = source[var] if present else None
    sel = auth['modes'][mode] if isinstance(mode, str) and mode in auth['modes'] else None
    by_value = dict((o['value'], o) for o in fs['outcomes'].values())
    for a in rule['inventory_forms']['accepted']:
        d = fs['tests'][a['test']]
        p, m = d['primitive'], None
        if p == 'key_absent':
            hold = not present
        elif p == 'equals_literal':
            hold = present and isinstance(j, str) and j == d['literal']
        elif p == 'equals_selected_mode_field':
            hold = present and sel is not None and isinstance(j, str) and j == sel[d['field']]
        else:
            m = re.match(_rh_get(rule, d['regex'])[1] + r'\Z', j) if present and isinstance(j, str) else None
            hold = m is not None
        if hold:
            o = by_value[a['proxy_jump']]
            return True, (o['jump'] if 'jump' in o else m.group(d['group'])), None
    return False, None, 'no_accepted_form'


def lme_rh_proxy_outcome(source, rule, auth, mode=None):
    """H-FORM-1 typed adapter (Ansible filter): <source mapping> | lme_rh_proxy_outcome(<composition>, <ssh_auth>, <mode>).
    Admits the vocabulary at rule.form_semantics (the declared node; the loader's resolve joined it to the registry
    before publishing this projection) and RAISES the declaration refusal when it is not admitted. For an admitted
    vocabulary it never raises on malformed source / form / rule: it returns the mapping keyed by the DECLARED result
    keys {admitted: bool, jump: the exact jump | null, cause: null | the declared cause token}. It says nothing about
    whether mode is admitted (mode admission stays at its declared boundaries)."""
    fs = _rh_form_admit(rule.get('form_semantics') if isinstance(rule, dict) else None, rule,
                        sorted(_RH_FORM_PRIMITIVES), sorted(_RH_FORM_CAUSE_ROLES), 'lme_rh_proxy_outcome rule')
    ok, jump, cause = _rh_form_classify(fs, rule, auth, source, mode)
    r = fs['result']
    return {r['admitted']: ok, r['jump']: jump, r['cause']: None if cause is None else fs['causes'][cause]}


def _rh_endpoint_vars(pol, hs, key):
    """C1-EFFECTIVE-ENDPOINT-BINDING (codex 035141): the ONE declared connection rule (registry host_scope.endpoint
    names where it lives in the policy: rule_path = ssh_auth.composition {address, port, proxy_jump}, owner_var_path =
    inventory.owner_var, owner_rule_path = inventory.owner {var, absent}) -- the same rule the route's endpoint key
    and B consume. Returns the inventory variable name per endpoint role and the rule (with the declared owner rule
    as 'owner_rule'); refuses a rule this resolver cannot apply exactly as declared."""
    ep = hs.get('endpoint')
    if not isinstance(ep, dict) or set(ep) != {'rule_path', 'owner_var_path', 'owner_rule_path', 'auth_path',
                                                'semantics_path', 'form_primitives', 'form_cause_roles'}:
        raise ValueError('lme: registry host_scope.endpoint must be {rule_path, owner_var_path, owner_rule_path, auth_path, semantics_path, form_primitives, form_cause_roles}; got %r' % (ep,))
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
            or not isinstance(auth.get('modes'), dict) or not auth['modes'] or any(not isinstance(m, dict) for m in auth['modes'].values()):
        raise ValueError('lme: %s.%s must declare mode_var and modes (a non-empty mapping of mode mappings)' % (key, ep['auth_path']))
    # H-FORM-1 PHASE 1 (declaration admission) then PHASE 2 (whole-rule validation): the vocabulary is read through the
    # registry semantics_path and joined to the registry form_primitives / form_cause_roles; it must be the rule's own
    # form_semantics member (the node the filter adapter reads from the same composition), so both adapters admit ONE
    # node. A malformed vocabulary or rule refuses here, before any interpreter call and before publication.
    fsm, fs = _rh_get(pol, ep['semantics_path']) if isinstance(ep['semantics_path'], str) else (False, None)
    if not fsm or fs is not rule.get('form_semantics'):
        raise ValueError('lme: registry host_scope.endpoint.semantics_path %r must name the form_semantics member of the rule at %s; got %s' % (
            ep['semantics_path'], ep['rule_path'], 'a different node' if fsm else '<absent>'))
    _rh_form_admit(fs, rule, ep['form_primitives'], ep['form_cause_roles'], '%s.%s' % (key, ep['rule_path']))
    why = _rh_form_invalid(fs, rule, auth)
    if why is not None:
        raise ValueError('lme: %s.%s: %s' % (key, ep['rule_path'], why))
    ad, pt = rule['address'], rule['port']
    if ad.get('absent') != 'inventory_hostname' or ad.get('normalize') != 'lower':
        raise ValueError('lme: %s.%s.address must be {var, absent: inventory_hostname, normalize: lower}; got %r' % (key, ep['rule_path'], ad))
    if pt.get('absent') != 'delegate_ssh_config' or not isinstance(pt.get('absent_key'), str) or not pt['absent_key'] \
            or not isinstance(pt.get('explicit_regex'), str) or isinstance(pt.get('explicit_max'), bool) or not isinstance(pt.get('explicit_max'), int):
        raise ValueError('lme: %s.%s.port must be {var, absent: delegate_ssh_config, absent_key, explicit_regex, explicit_max}; got %r' % (key, ep['rule_path'], pt))
    return ({'address': ad['var'], 'port': pt['var'], 'proxy_jump': rule['inventory_forms']['var'], 'owner': owner_var, 'mode': auth['mode_var']},
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
    # H-FORM-1 RAISING ADAPTER: the same admitted vocabulary and pure core as lme_rh_proxy_outcome (validated by
    # _rh_endpoint_vars); the source is the selected endpoint values with the proxy role under the inventory var.
    jp = 'proxy_jump' in raw
    j = raw.get('proxy_jump')
    ok, jump, cause = _rh_form_classify(rule['form_semantics'], rule, {'modes': rule['modes']},
                                        {rule['inventory_forms']['var']: j} if jp else {}, raw.get('mode'))
    if not ok:
        raise ValueError('lme: %s endpoint of %r: %s %r is none of the declared accepted inventory forms %r (host mode %r)' % (
            key, host, rule['inventory_forms']['var'], j if jp else '<absent>', [f['form'] for f in rule['inventory_forms']['accepted']], raw.get('mode')))
    # Owner: ABSENT -> the declared owner rule's absent value (a separate, declared policy); a SUPPLIED value (null
    # included) must be a string.
    o = raw['owner'] if 'owner' in raw else rule['owner_rule']['absent']
    if not isinstance(o, str):
        raise ValueError('lme: %s endpoint of %r: a supplied owner must be a string; got %r (%s)' % (key, host, o, type(o).__name__))
    comp = {'address': a.lower(), 'port': pk, 'proxy_jump': jump, 'owner': o}
    return [comp[c] for c in rule['endpoint_key']]


_RH_INPUT_TYPES = ('string', 'bool', 'string_list')


def _rh_target_inputs(pol, schema, key):
    """GRAPH-SHARED-CONTRACT (codex-tick304) DECLARED TARGET INPUTS. The per-target INVENTORY values the deployment's
    consumers read (owner account, toolchain root, bundle dir, the owner key REFERENCE, observation host inputs, ...)
    are each named ONCE in the policy, at registry host_scope.target_inputs.decl_path, as
    {<role>: {var, type, required[, pattern]}}. The loader SELECTS them (lme_rh_connection_values), types them against
    the registry patterns and binds every target's values into binding.deployment.target_inputs (part of every
    scope_sha256), so a consumer reads the bound value, never a raw host var. A key or credential is only ever a PATH
    reference (a string; the loader never reads it). Presence is kept separate from the value (as for endpoints): an
    absent var omits the role (a required role refuses); a supplied null is a value no type admits. Returns
    {role: spec}; {} (inert) when the registry names no decl_path or the policy declares none."""
    hs = schema['host_scope']
    if 'target_inputs' not in hs:
        return {}
    ti = hs['target_inputs']
    if not isinstance(ti, dict) or set(ti) != {'decl_path'} or not isinstance(ti['decl_path'], str) or not ti['decl_path']:
        raise ValueError('lme: registry host_scope.target_inputs must be {decl_path: <policy path>}; got %r' % (ti,))
    f, decl = _rh_get(pol, ti['decl_path'])
    if not f:
        return {}
    pats = _rh_ca_registry(schema.get('contract_admission'), schema)[0]
    if 'var_name' not in pats:
        raise ValueError('lme: registry contract_admission.patterns.var_name is required to admit %s.%s' % (key, ti['decl_path']))
    if not isinstance(decl, dict) or not decl:
        raise ValueError('lme: %s.%s must be a non-empty mapping of input roles; got %r' % (key, ti['decl_path'], decl))
    reserved = set(schema.get('reserved_outputs') or []) | set(schema.get('resolver_outputs') or [])
    seen = {}
    for role in sorted(decl, key=str):
        spec, where = decl[role], '%s.%s.%s' % (key, ti['decl_path'], role)
        if not isinstance(role, str) or not pats['var_name'].fullmatch(role):
            raise ValueError('lme: %s: an input role must fully match patterns.var_name' % (where,))
        ok = isinstance(spec, dict) and {'var', 'type', 'required'} <= set(spec) and not set(spec) - {'var', 'type', 'required', 'pattern'} \
            and isinstance(spec['var'], str) and bool(pats['var_name'].fullmatch(spec['var'])) \
            and isinstance(spec['type'], str) and spec['type'] in _RH_INPUT_TYPES and isinstance(spec['required'], bool) \
            and ('pattern' in spec) == (spec['type'] != 'bool') \
            and ('pattern' not in spec or (isinstance(spec['pattern'], str) and spec['pattern'] in pats))
        if not ok:
            raise ValueError('lme: %s must be {var: <patterns.var_name>, type: <one of %s>, required: <bool>, pattern: <a declared '
                             'contract_admission.patterns name; string / string_list only>}; got %r' % (where, list(_RH_INPUT_TYPES), spec))
        if spec['var'] in reserved or any(pats[p].fullmatch(spec['var']) for p in schema.get('reserved_output_patterns', [])):
            raise ValueError('lme: %s.var %r is a reserved / resolver OUTPUT name, never an input' % (where, spec['var']))
        if spec['var'] in seen:
            raise ValueError('lme: %s.var %r is already read by role %s (one role per inventory variable)' % (where, spec['var'], seen[spec['var']]))
        seen[spec['var']] = role
    return decl


def _rh_bind_target_inputs(decl, conn, targets, schema, key):
    """The typed {target: {role: value}} of the declared target inputs (see _rh_target_inputs); refuses a connection
    context that does not carry exactly the declared vars and every target's values, a missing required role, and a
    value of another type (type-exact: 'true' is not a bool, 8 is not a string)."""
    pats = _rh_ca_registry(schema.get('contract_admission'), schema)[0]
    names = dict((r, decl[r]['var']) for r in sorted(decl))
    inp = conn.get('inputs') if isinstance(conn, dict) else None
    if not isinstance(inp, dict) or inp.get('vars') != names or not isinstance(inp.get('values'), dict) \
            or any(not isinstance(inp['values'].get(t), dict) for t in targets):
        raise ValueError('lme: remote-harness scope connections must carry the declared target inputs %r and every target\'s values' % (names,))
    out = {}
    for t in targets:
        raw, row = inp['values'][t], {}
        for role in sorted(decl):
            spec = decl[role]
            if role not in raw:
                if spec['required']:
                    raise ValueError('lme: %s target %r lacks the required input %s (inventory var %s); there is no default' % (key, t, role, spec['var']))
                continue
            v, p = raw[role], pats.get(spec.get('pattern'))
            if spec['type'] == 'bool':
                good, want = isinstance(v, bool), 'a bool (type-exact)'
            elif spec['type'] == 'string':
                good, want = isinstance(v, str) and bool(p.fullmatch(v)), 'a string fully matching patterns.%s' % (spec['pattern'],)
            else:
                good = isinstance(v, list) and bool(v) and all(isinstance(x, str) and p.fullmatch(x) for x in v) and len(set(v)) == len(v)
                want = 'a non-empty list of distinct strings, each fully matching patterns.%s' % (spec['pattern'],)
            if not good:
                raise ValueError('lme: %s target %r input %s (inventory var %s) must be %s; got %r (%s)' % (key, t, role, spec['var'], want, v, _rh_kind(v)))
            row[role] = v
        out[t] = row
    return out


def _rh_distinct_across_targets(hs, scopes, targets, key):
    """GRAPH-SHARED-CONTRACT (codex-tick304): registry host_scope.distinct_across_targets names policy paths whose
    value, wherever a target scope declares it, must differ between the targets of one deployment (e.g. a guest's
    run_id and hostname: two hypervisors declaring the same one would collide in the lifecycle record and the
    inventory binding). Scalars only (str / int), compared type-exactly; absent on a scope = not declared there."""
    dat = hs.get('distinct_across_targets')
    if dat is None:
        return
    if not isinstance(dat, list) or any(not isinstance(p, str) or not p for p in dat):
        raise ValueError('lme: registry host_scope.distinct_across_targets must be a list of policy paths; got %r' % (dat,))
    for p in dat:
        seen = {}
        for t in targets:
            f, v = _rh_get(scopes['targets'][t]['policy'], p)
            if not f:
                continue
            if isinstance(v, bool) or not isinstance(v, (str, int)):
                raise ValueError('lme: %s.%s of target %r must be a string or integer to be compared across targets; got %r' % (key, p, t, v))
            k = (_rh_kind(v), v)
            if k in seen:
                raise ValueError('lme: %s.%s %r is declared by targets %r and %r; it must be distinct across the targets of one deployment' % (key, p, v, seen[k], t))
            seen[k] = t


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
    out = {'vars': names, 'values': values}
    # GRAPH-SHARED-CONTRACT (codex-tick304): the DECLARED target inputs, selected the same way (presence kept apart
    # from the value); carried only when the policy declares them, so an undeclared context is unchanged.
    tin = _rh_target_inputs(pol, schema, key)
    if tin:
        ivars = dict((r, tin[r]['var']) for r in sorted(tin))
        out['inputs'] = {'vars': ivars, 'values': dict(
            (h, dict((r, hostvars[h][v]) for r, v in sorted(ivars.items()) if v in hostvars[h])) for h in ids)}
    return out


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


def _rh_scoped(section, composed, declared, override, schema, scope, *, documents, admission):
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
    imports = _rh_prove_artifact_templates(hs, scope['artifact_sources'])
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
    # GRAPH-SHARED-CONTRACT (codex-tick304): every target's DECLARED inventory inputs, typed, join the deployment
    # binding (so every scope_sha256), exactly when the policy declares them; a context carrying undeclared inputs refuses.
    tin = _rh_target_inputs(pol, schema, key)
    if tin:
        binding['deployment']['target_inputs'] = _rh_bind_target_inputs(tin, conn, targets, schema, key)
    elif 'inputs' in conn:
        raise ValueError('lme: remote-harness scope connections carry target inputs the policy does not declare')

    def entry(i):
        # F05-S3 LR-02: every scope is validated with the SAME retained documents and admission record: the documents
        # are the ONE admitted source checkout's bytes (not per-host data), so a sibling scope whose policy names
        # another document rel refuses in _rh_documents (rel binding) instead of reading anything.
        sec = section if i == me else _rh_validate(comp[i], declared, ovs[i], schema, documents=documents, admission=admission)[0]
        if _rh_get(sec['policy'], hs['target_group_path'])[1] != tg or _rh_get(sec['policy'], hs['operation_path'])[1] != op:
            raise ValueError('lme: scope %r resolves another target group/operation than the deployment binding' % (i,))
        ident = {'kind': 'controller' if i == cid else 'target', 'id': i}
        out = dict(ident, **{k: sec[k] for k in _RH_SCOPE_ENTRY + (_rh_gb_decl(schema)['to'], _rh_tr_decl(schema)['to'])})   # C1-RECIPE-PUB-02: + the class generation bindings
        out['scope_sha256'] = _digest({'scope': ident, 'binding': binding, 'policy_sha256': sec['policy_sha256']})
        return out
    scopes = {'controller': entry(cid), 'targets': {t: entry(t) for t in targets}}
    _rh_distinct_across_targets(hs, scopes, targets, key)
    # IMPORT-PER-SCOPE-BINDING (codex 214135): every declared-reference import binds against EVERY already-resolved
    # scope policy (the ONE composition per scope, derived above; nothing merged here), so a scope whose declared
    # target differs is proved on its own values, not on this host's.
    arts = _rh_artifact_decl(hs)
    for label, spol in [('controller ' + cid, scopes['controller']['policy'])] + [
            ('target ' + t, scopes['targets'][t]['policy']) for t in targets]:
        for rec in imports:
            if _rh_artifact_active(arts[rec['artifact']], spol):
                _rh_bind_declared_import(rec, arts[rec['artifact']], label, spol)
    mine =scopes['controller'] if me == cid else scopes['targets'][me]
    return dict(section, scope={'kind': mine['kind'], 'id': me}, binding=binding, scope_sha256=mine['scope_sha256'],
                scopes=scopes, scopes_sha256=_digest(scopes))


def lme_project_remote_harness(composed, declared, override, schema, scope=None, *, documents, admission):
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
    section, _ov, docs = _rh_validate(composed, declared, override, schema, documents=documents, admission=admission)
    if section is None:
        return section
    # F05 (codex-tick507 R2-F05-ACTUAL-CONSUMER): the registry-declared published views ride at the TOP level only
    # (_rh_scoped copies _RH_SCOPE_ENTRY into scopes); outside every policy/scope digest, inside lme_resolved_revision.
    # F05-S3: the document-gated views read the SAME admitted documents (docs) the projections read.
    section = dict(section, **_rh_published_views(section['policy'], schema, schema['policy_key'], docs))
    if scope is None:
        return section
    return _rh_scoped(section, composed, declared, override, schema, scope, documents=documents, admission=admission)


def _rh_published_view_decl(schema):
    """F05-G2 LV-2: remote_harness_schema.published_views admitted at every use. Each name is a
    contract_admission.patterns.var_name, collides with no section/scope key, and carries exactly its kind's keys:
      policy_node {kind, from}: the view is a deep copy of the policy node at `from` (absent refuses; no empty view).
      declaration_contract {kind, when_declared, fields, refusal, message}: fields = exactly {active, refusal,
        message} -> distinct var_name output names; refusal matches patterns.refusal_code; message non-empty.
      document_binding {kind, when} (F05-S3 P6): {name: {rel, sha256}} of the admitted documents.
      entry_generation {_RH_EG_VIEW_KEYS} (F05-S3 P5, LR-12): see _rh_eg_view.
    A `when` names a declaration_contract view; the gated view is published exactly while it is active (LR-10).
    Returns the admitted mapping."""
    views = schema.get('published_views')
    pats = (schema.get('contract_admission') or {}).get('patterns') or {}
    vn, rc = pats.get('var_name'), pats.get('refusal_code')
    if not isinstance(views, dict) or not isinstance(vn, str) or not isinstance(rc, str):
        raise ValueError('lme: registry remote_harness_schema.published_views must be a mapping and contract_admission.patterns must declare var_name and refusal_code; got %r' % (views,))
    shapes = {'policy_node': {'kind', 'from'}, 'declaration_contract': {'kind', 'when_declared', 'fields', 'refusal', 'message'},
              'document_binding': {'kind', 'when'}, 'entry_generation': set(_RH_EG_VIEW_KEYS)}
    taken = _RH_BASE_KEYS | _RH_SCOPED_KEYS | set(_RH_SCOPE_ENTRY) | {'kind', 'id'}
    for name in sorted(views):
        v = views[name]
        if not isinstance(name, str) or not re.fullmatch(vn, name) or name in taken:
            raise ValueError('lme: registry published_views name %r must fully match patterns.var_name and not be a section or scope key %s' % (name, sorted(taken)))
        if not isinstance(v, dict) or v.get('kind') not in shapes or set(v) != shapes[v['kind']] \
                or any(not isinstance(v[k], str) or not v[k] for k in shapes[v['kind']] - {'fields'} - _RH_EG_VIEW_NONSTRING):
            raise ValueError('lme: registry published_views.%s must be one of %s with non-empty string values; got %r' % (name, {k: sorted(x) for k, x in shapes.items()}, v))
        # F05-S3 LR-10: a gated view names a declaration_contract view (admitted after the loop: order-free)
        if 'when' in v and (v['when'] not in views or not isinstance(views[v['when']], dict) or 'kind' not in views[v['when']]
                                 or views[v['when']]['kind'] != 'declaration_contract'):
            raise ValueError('lme: registry published_views.%s.when %r must name a declared declaration_contract view' % (name, v['when']))
        if v['kind'] == 'declaration_contract':
            f = v['fields']
            if not isinstance(f, dict) or set(f) != {'active', 'refusal', 'message'} \
                    or any(not isinstance(x, str) or not re.fullmatch(vn, x) for x in f.values()) or len(set(f.values())) != 3:
                raise ValueError('lme: registry published_views.%s.fields must map exactly active/refusal/message to distinct var_name strings; got %r' % (name, f))
            if not re.fullmatch(rc, v['refusal']):
                raise ValueError('lme: registry published_views.%s.refusal %r must fully match patterns.refusal_code %r' % (name, v['refusal'], rc))
    # F05-S4 RENDER-CONTEXT-03 (Codex585 RC02-INACTIVE-ARTIFACT-ENTRY-COUNT): the ONE entry_count cross-reference,
    # admitted HERE -- registry-only, at every use, before any view is gated on policy activity -- so it holds when
    # the whole generation contract is inactive too. More than one entry template is admitted ONLY on a shared
    # artifact the registry already names as an entry_generation view's rendered.render_artifact; every other
    # shared artifact keeps exactly one entry. (The active rendered-output equality stays in _rh_eg_view.)
    rarts = set()
    for name in sorted(views):
        v = views[name]
        if v['kind'] != 'entry_generation':
            continue
        rd = v['rendered']
        if not isinstance(rd, dict) or 'render_artifact' not in rd or not isinstance(rd['render_artifact'], str) or not rd['render_artifact']:
            raise ValueError('lme: registry published_views.%s.rendered.render_artifact must name a shared artifact (non-empty string); got %r' % (name, rd))
        rarts.add(rd['render_artifact'])
    if 'host_scope' not in schema:
        raise ValueError('lme: registry remote_harness_schema.host_scope must be declared (shared_artifacts entry_count admission); got %r' % (sorted(schema),))
    arts = _rh_artifact_decl(schema['host_scope'])
    multi = sorted(a for a, d in arts.items() if d['entry_count'] != 1 and a not in rarts)
    if multi:
        raise ValueError('lme: registry host_scope.shared_artifacts.%s.entry_count must be 1: several entry templates are admitted only on a declared published_views.<entry_generation view>.rendered.render_artifact %s; got %r' % (
            multi[0], sorted(rarts), dict((a, arts[a]['entry_count']) for a in multi)))
    return views


def _rh_published_views(policy, schema, key, docs):
    """F05-G2 LV-3: the published views, a pure function of the resolved policy, the registry and (F05-S3) the
    admitted documents docs = (active, {name: {rel, sha256, root}}) from _rh_documents. A view with `when` is
    published exactly while that declaration_contract view is active (LR-10); inactive it is ABSENT (no manufactured
    inactive state; the consumer's own typed assert refuses)."""
    views = _rh_published_view_decl(schema)
    res = {}
    for name, v in sorted(views.items()):
        if 'when' in v:
            on = _rh_get(policy, views[v['when']]['when_declared'])[0]
            if on != docs[0]:
                raise ValueError('lme: published_views.%s.when %r and the admitted documents disagree on activity (one activity rule)' % (name, v['when']))
            if not on:
                continue
        if v['kind'] == 'policy_node':
            fv, node = _rh_get(policy, v['from'])
            if not fv:
                raise ValueError('lme: %s.%s is absent; published view %s has no empty form (published_views.%s)' % (key, v['from'], name, name))
            res[name] = copy.deepcopy(node)
        elif v['kind'] == 'declaration_contract':
            res[name] = {v['fields']['active']: _rh_get(policy, v['when_declared'])[0] is True,
                         v['fields']['refusal']: v['refusal'], v['fields']['message']: v['message']}
        elif v['kind'] == 'document_binding':
            res[name] = dict((n, {'rel': d['rel'], 'sha256': d['sha256']}) for n, d in sorted(docs[1].items()))
        else:
            res[name] = _rh_eg_view(name, v, views[v['when']], policy, schema, key, docs[1])
    return res


# F05-S3 LR-12 / STRUCT-ROLE / L-ADO-01..06 / LD05 (OD-S3-05 a + dynamic references): the entry_generation view
# declaration keys. Pointers only: B paths relative to the `document` root (b_paths, members, select, identity), policy
# paths absolute; record_codes / record_code_refs are the ONE generator-consumer contract.
_RH_EG_VIEW_KEYS = ('kind', 'when', 'schema_version', 'document', 'roster_document', 'names_family', 'derived_row_keys',
                    'members', 'select', 'identity', 'b_paths', 'template_vars', 'template_var_roles', 'declaration_rel',
                    'never_generated', 'importers', 'bodies', 'context', 'context_root', 'policy_path_separator', 'interface',
                    'render_artifact', 'record_codes', 'record_code_refs', 'record_code_pattern', 'adoption_checks',
                    'row_id_key', 'row_template_key', 'rendered')
_RH_EG_VIEW_NONSTRING = frozenset(('schema_version', 'derived_row_keys', 'b_paths', 'template_var_roles', 'never_generated',
                                   'interface', 'record_codes', 'record_code_refs', 'adoption_checks', 'rendered'))
# F05-S4 ROSTER-NONPLAYBOOK (Codex546 generated_outputs; OPEN-A / OD-BRR-14 / U-SEAM01): the rendered-output row kind's
# registry declaration (policy pointers; output_fields maps the two row roles onto the leaf names of every outputs node).
# F05-S4 RENDER-CONTEXT (render-interface-01): + struct_sources / context_binding (policy paths) and source_facts (the
# registry key of the fact universe a struct source must name exactly).
_RH_EG_RENDERED_KEYS = frozenset(('when_present', 'render_artifact', 'context_kind', 'context_kinds', 'struct_roles', 'outputs', 'output_fields',
                                  'struct_sources', 'context_binding', 'source_facts',
                                  # F05-S4 RENDER-CONTEXT-02: the declared entry shape and the permitted kinds
                                  'source_entry_fields', 'source_kinds', 'kind_tests', 'kind_test_names'))
_RH_EG_B_PATHS = frozenset(('roster_key', 'roster_member_key', 'roster_member_keys', 'roster_source_keys', 'retire_key',
                            'retire_row_keys', 'records', 'pending_roles', 'record_refusals', 'record_texts', 'adoption_rel',
                            'blob_id_regex', 'edition_regex', 'ownership', 'struct_roles', 'identity_refusal', 'identity_text',
                            'adoption', 'adoption_baseline', 'adoption_authored'))
_RH_EG_ADOPTION_CHECKS = frozenset(('retention_root', 'dispatch_closure', 'common', 'excludes', 'exclude_forms', 'adoption_keys'))
_RH_EG_STRUCT_WORDS = ('declaration_rel', 'member_dir', 'member_file')
_RH_EG_EXCLUDE_WORDS = ('component', 'prefix', 'suffix')


def _rh_eg_view(name, v, contract, policy, schema, key, docs):
    """LR-12: the entry-generation view (spec.yml P5 fields, codex-tick522 corrections, L-ADO-01..06, LD05). Any absent
    or malformed input refuses with the contract view's refusal (RH-ENTRY-DECLARATION-MISSING) naming the registry,
    policy/document path and value; the roster identity law refuses with B's identity code and text."""
    def bad(where, detail, value):
        raise ValueError('lme: %s (published_views.%s; %s): %s %s; got %r' % (contract['refusal'], name, contract['message'], where, detail, value))
    pats, ptext = _rh_patterns(schema)
    if not _rh_int(v['schema_version']) or not isinstance(v['derived_row_keys'], list) or not v['derived_row_keys'] \
            or any(not isinstance(x, str) or not x for x in v['derived_row_keys']) \
            or not isinstance(v['b_paths'], dict) or set(v['b_paths']) != _RH_EG_B_PATHS or any(not isinstance(x, str) or not x for x in v['b_paths'].values()) \
            or not isinstance(v['template_var_roles'], dict) or set(v['template_var_roles']) != {'context', 'struct', 'decl'} \
            or not isinstance(v['never_generated'], list) or not isinstance(v['interface'], dict) or set(v['interface']) != {'base', 'files'} \
            or not isinstance(v['record_codes'], list) or not v['record_codes'] or len(set(v['record_codes'])) != len(v['record_codes']) \
            or not isinstance(v['record_code_refs'], list) or any(not isinstance(r, dict) or len(r) != 1 or next(iter(r)) not in ('values_of', 'items_of') for r in v['record_code_refs']) \
            or not isinstance(v['adoption_checks'], dict) or set(v['adoption_checks']) != _RH_EG_ADOPTION_CHECKS \
            or v['names_family'] not in pats or v['record_code_pattern'] not in pats or 'rel_path' not in pats:
        bad('registry remote_harness_schema.published_views.%s' % (name,), 'must carry exactly %s with typed values (b_paths exactly %s, adoption_checks exactly %s)' % (
            list(_RH_EG_VIEW_KEYS), sorted(_RH_EG_B_PATHS), sorted(_RH_EG_ADOPTION_CHECKS)), sorted(v))
    rd = v['rendered']
    if not isinstance(rd, dict) or set(rd) != _RH_EG_RENDERED_KEYS \
            or any(not isinstance(rd[k], str) or not rd[k] for k in _RH_EG_RENDERED_KEYS - {'outputs', 'output_fields', 'source_entry_fields', 'source_kinds', 'kind_test_names'}) \
            or not isinstance(rd['source_entry_fields'], dict) or set(rd['source_entry_fields']) != {'fact', 'path', 'kind'} \
            or any(not isinstance(x, str) or not x for x in rd['source_entry_fields'].values()) or len(set(rd['source_entry_fields'].values())) != 3 \
            or not isinstance(rd['source_kinds'], list) or not rd['source_kinds'] or len(set(x for x in rd['source_kinds'] if isinstance(x, str))) != len(rd['source_kinds']) \
            or any(x not in _RH_KIND_WORDS for x in rd['source_kinds']) \
            or not isinstance(rd['kind_test_names'], list) or not rd['kind_test_names'] or any(not isinstance(x, str) or not x for x in rd['kind_test_names']) \
            or len(set(rd['kind_test_names'])) != len(rd['kind_test_names']) \
            or not isinstance(rd['outputs'], list) or not rd['outputs'] or any(not isinstance(x, str) or not x for x in rd['outputs']) \
            or len(set(rd['outputs'])) != len(rd['outputs']) \
            or not isinstance(rd['output_fields'], dict) or set(rd['output_fields']) != {'output', 'template'} \
            or any(not isinstance(x, str) or not x for x in rd['output_fields'].values()) or len(set(rd['output_fields'].values())) != 2:
        bad('registry remote_harness_schema.published_views.%s.rendered' % (name,),
            'must carry exactly %s (policy path strings; outputs a non-empty distinct list of policy paths; output_fields exactly {output, template} -> two distinct leaf names; source_entry_fields exactly {fact, path, kind} -> three distinct entry key names; source_kinds a non-empty distinct list of the supported kind words %s; kind_test_names a non-empty distinct list of test names)' % (
                sorted(_RH_EG_RENDERED_KEYS), sorted(_RH_KIND_WORDS)), rd)
    relp = pats['rel_path']
    for dn in (v['document'], v['roster_document']):
        if dn not in docs:
            bad('published_views.%s document %r' % (name, dn), 'names no admitted document', sorted(docs))
    root, rroot = docs[v['document']]['root'], docs[v['roster_document']]['root']
    B = v['b_paths']

    def b(field, want=None):
        f, x = _rh_get(root, B[field])
        if not f or (want is not None and not isinstance(x, want)):
            bad('document %s %s' % (v['document'], B[field]), 'must be a declared %s' % (want.__name__ if want else 'value'), x if f else '<absent>')
        return x

    def p(path, want=None):
        f, x = _rh_get(policy, path)
        if not f or (want is not None and not isinstance(x, want)):
            bad('%s.%s' % (key, path), 'must be a declared %s' % (want.__name__ if want else 'value'), x if f else '<absent>')
        return x
    projs = schema['policy_projections']
    for pn in (v['importers'], v['bodies']):
        if pn not in projs:
            bad('published_views.%s' % (name,), 'names projection %r, which is not declared' % (pn,), sorted(projs))
    importers = p('%s.%s' % (projs[v['importers']]['at'], projs[v['importers']]['to']), dict)
    bodies = p('%s.%s' % (projs[v['bodies']]['at'], projs[v['bodies']]['to']), dict)
    # MR03 (DEP-MR03-LOADER-01): the rendered dispatch rows / their obligation rows (same projections, second destinations)
    rimps = p('%s.%s' % (projs[v['importers']]['at'], projs[v['importers']]['rendered_dispatch']['to']), dict)
    robls = p('%s.%s' % (projs[v['bodies']]['at'], projs[v['bodies']]['rendered_to']), dict)
    pseparator = p(v['policy_path_separator'], str)
    gen, _members, sep, rendered = _rh_eg_generated('published_views.%s' % (name,), {'identity': v['identity'], 'members': v['members'], 'document': v['document']}, root, policy, key, relp)
    # ---- STRUCT-ROLE (codex-tick522): struct_roles and bound.struct keys are BOTH the select VALUES of the struct.roles keys
    sroles, select = b('struct_roles', dict), _rh_get(root, v['select'])[1]
    if sorted(sroles.values()) != sorted(_RH_EG_STRUCT_WORDS) or not isinstance(select, dict) \
            or any(r not in select or not isinstance(select[r], str) or not select[r] for r in sroles) \
            or len(set(select[r] for r in sroles)) != len(sroles):
        bad('document %s %s / %s' % (v['document'], B['struct_roles'], v['select']), 'must map struct roles onto %s and select a distinct field name for every struct role' % (list(_RH_EG_STRUCT_WORDS),), [sroles, select])
    role_of = dict((w, r) for r, w in sroles.items())
    struct_roles = sorted(select[r] for r in sroles)
    # ---- roster (identity law) ----
    skeys, mkey, mkeys = b('roster_source_keys', list), b('roster_member_key', str), b('roster_member_keys', list)
    if sorted(mkeys) != sorted([role_of['member_dir'], role_of['member_file']]) or mkey not in skeys:
        bad('document %s %s / %s' % (v['document'], B['roster_member_keys'], B['roster_member_key']), 'must be the struct roles of member_dir/member_file and a source key', [mkeys, mkey])
    rows = _rh_get(rroot, b('roster_key', str))[1]
    retire_rows, rr_keys = _rh_get(rroot, b('retire_key', str))[1], b('retire_row_keys', list)
    if not isinstance(rroot, dict) or not isinstance(rows, list) or not isinstance(retire_rows, list) \
            or any(not isinstance(r, dict) or sorted(r) != sorted(rr_keys) for r in retire_rows):
        bad('document %s (%s)' % (v['roster_document'], docs[v['roster_document']]['rel']), 'must carry a row list and a retire list of exactly %s rows' % (sorted(rr_keys),), sorted(rroot) if isinstance(rroot, dict) else type(rroot).__name__)
    tv = p(v['template_vars'], dict)
    tvr = v['template_var_roles']
    if any(tvr[r] not in tv or not isinstance(tv[tvr[r]], str) for r in tvr):
        bad('%s.%s' % (key, v['template_vars']), 'must name a template variable for every role %s' % (sorted(tvr.values()),), tv)
    tvc, tvs, tvd = tv[tvr['context']], tv[tvr['struct']], tv[tvr['decl']]
    cfields = p(v['context'], dict)
    cpaths = dict((f, pseparator.join([v['context_root']] + list(kp))) for f, kp in sorted(cfields.items()))
    decl_rel = p(v['declaration_rel'], str)
    if decl_rel != docs[v['document']]['rel']:
        bad('%s.%s' % (key, v['declaration_rel']), 'must be the admitted %s document rel %r' % (v['document'], docs[v['document']]['rel']), decl_rel)
    arts = _rh_artifact_decl(schema['host_scope'])
    if v['render_artifact'] not in arts:
        bad('host_scope.shared_artifacts.%s' % (v['render_artifact'],), 'is not declared (the render closure is SEQUENCED on C1-S9-SHARED-MACRO-REACH + C1-S9-MANDATORY-CAPABILITY, OD-S2-06)', sorted(arts))
    closure = list(arts[v['render_artifact']]['templates'])
    # F05-S4 RENDER-CONTEXT-02/-03 (J-FIN-F05-01; Codex585): entry_count > 1 only on a declared rendered.render_artifact
    # is admitted UNCONDITIONALLY in _rh_published_view_decl (before this view is gated); the leading entries of this
    # view's render_artifact must equal the declared rendered output templates (checked below while active).
    # ---- F05-S4 ROSTER-NONPLAYBOOK (Codex546 generated_outputs; OPEN-A / OD-BRR-14 / U-SEAM01): the RENDERED row kind.
    # A row whose member is a rendered member (identity.rendered_from) is the same B roster row shape; its kind is its
    # member's marker (declared once, in B entry_sets). Active exactly while rendered.when_present is declared in the
    # policy (OD-BRR-07: no fabricated inactive view): its render closure is shared artifact rendered.render_artifact,
    # its context kind (policy rendered.context_kind) is a key of rendered.context_kinds, its struct binding is the
    # policy mapping rendered.struct_roles, and the PRODUCER declaration rendered.outputs (policy nodes, each carrying
    # the output_fields leaves) is the ONE authority of {output rel: template rel}: the rendered rows must equal it in
    # both directions (no second spelling passes silently). Inactive: rendered rows stay identity-checked (B roster law)
    # and are OMITTED from the published roster.
    ron = _rh_get(policy, rd['when_present'])[0]
    rclosure, rpairs, rstruct, rsrc, rbind = [], {}, {}, {}, {}
    if ron:
        rkind, rkinds = p(rd['context_kind'], str), p(rd['context_kinds'], dict)
        if rkind not in rkinds:
            bad('%s.%s' % (key, rd['context_kind']), 'must be a key of %s.%s %s' % (key, rd['context_kinds'], sorted(rkinds)), rkind)
        rstruct = p(rd['struct_roles'], dict)
        if not rstruct or any(not isinstance(x, str) or not x for x in rstruct.values()) or len(set(rstruct.values())) != len(rstruct):
            bad('%s.%s' % (key, rd['struct_roles']), 'must map struct roles to distinct non-empty names', rstruct)
        # F05-S4 RENDER-CONTEXT (render-interface-01 s1): the ONE runtime role -> source binding. Keys EXACTLY the
        # struct_roles keys; each source exactly {fact, path}: fact an EXACT member of the registry list named by
        # rendered.source_facts, path a list of non-empty keys walked inside it ([] = the fact itself). No default.
        found, facts = _rh_get(schema, rd['source_facts'])
        if not found or not isinstance(facts, list) or not facts:
            bad('registry remote_harness_schema.%s (published_views.%s.rendered.source_facts)' % (rd['source_facts'], name), 'must be a declared non-empty list of fact names', facts if found else '<absent>')
        # F05-S4 RENDER-CONTEXT-02 (render-interface-02 s1): each entry carries EXACTLY the declared entry keys
        # (rendered.source_entry_fields values, now incl. the kind key); the kind is one of rendered.source_kinds (a
        # subset of the seven supported kind words, admitted above); no default.
        sef = rd['source_entry_fields']
        fk, pk, kk = sef['fact'], sef['path'], sef['kind']
        rsrc = p(rd['struct_sources'], dict)
        if set(rsrc) != set(rstruct) or any(not isinstance(s, dict) or set(s) != set(sef.values()) or not isinstance(s[fk], str) or s[fk] not in facts
                                             or not isinstance(s[pk], list) or any(not isinstance(x, str) or not x for x in s[pk])
                                             or not isinstance(s[kk], str) or s[kk] not in rd['source_kinds'] for s in rsrc.values()):
            bad('%s.%s' % (key, rd['struct_sources']), 'must map EXACTLY the %s.%s roles %s to entries of exactly %s (%s a registry %s member, %s a list of non-empty keys, %s one of the permitted kinds %s)' % (
                key, rd['struct_roles'], sorted(rstruct), sorted(sef.values()), fk, rd['source_facts'], pk, kk, rd['source_kinds']), rsrc)
        # parent successor-07 J-S07-PROFILE-KEY-ADMISSION / Codex580 J-S07-KIND-ADMISSION: the ONE kind -> {test,
        # excludes} map the generator applies, admitted before render (no default): keys among the seven supported kind
        # words and covering every permitted kind; each value exactly {test, excludes}; test one of the registry's
        # CLOSED rendered.kind_test_names (parent successor-08 J-S07-KIND-RANGE; each of which must be a Jinja builtin
        # test, the generator's render engine); no two kinds share a test (ambiguous); excludes a distinct list from the
        # same closed set, each the test of ANOTHER declared kind (an unknown or self exclusion refuses).
        import jinja2
        jtests = frozenset(jinja2.Environment().tests)
        tnames = rd['kind_test_names']
        if any(x not in jtests for x in tnames):
            bad('registry remote_harness_schema.published_views.%s.rendered.kind_test_names' % (name,), 'must name only Jinja builtin tests %s' % (sorted(jtests),), tnames)
        ktests = p(rd['kind_tests'], dict)
        kt_ok = all(isinstance(k, str) and k in _RH_KIND_WORDS for k in ktests) and set(rd['source_kinds']) <= set(ktests) \
            and all(isinstance(t, dict) and set(t) == {'test', 'excludes'} and isinstance(t['test'], str) and t['test'] in tnames
                    and isinstance(t['excludes'], list) and all(isinstance(x, str) and x in tnames for x in t['excludes'])
                    and len(set(t['excludes'])) == len(t['excludes']) for t in ktests.values())
        if kt_ok:
            kt_tests = [t['test'] for t in ktests.values()]
            kt_ok = len(set(kt_tests)) == len(kt_tests) and all(x in kt_tests and x != t['test'] for t in ktests.values() for x in t['excludes'])
        if not kt_ok:
            bad('%s.%s' % (key, rd['kind_tests']), 'must map supported kind words %s (covering every permitted kind %s) to exactly {test, excludes}: test one of the declared kind_test_names %s, distinct across kinds; excludes a distinct list of the tests of OTHER declared kinds from the same set' % (
                sorted(_RH_KIND_WORDS), rd['source_kinds'], tnames), ktests)
        # context_binding exactly {key, value}: value = the render-contract key it carries (the leaf of the struct_roles
        # policy path); key = the nested context key the templates read, never an early context field name.
        rbind = p(rd['context_binding'], dict)
        if set(rbind) != {'key', 'value'} or rbind['value'] != rd['struct_roles'].split(pseparator)[-1] \
                or not isinstance(rbind['key'], str) or not rbind['key'] or rbind['key'] in cfields:
            bad('%s.%s' % (key, rd['context_binding']), 'must be exactly {key, value} with value %r (the %s leaf) and key a non-empty name outside the early context fields %s' % (
                rd['struct_roles'].split(pseparator)[-1], rd['struct_roles'], sorted(cfields)), rbind)
        of, tf = rd['output_fields']['output'], rd['output_fields']['template']
        for o in rd['outputs']:
            node = p(o, dict)
            if any(f not in node or not isinstance(node[f], str) or not relp.fullmatch(node[f]) for f in (of, tf)) or node[of] in rpairs:
                bad('%s.%s' % (key, o), 'must carry %s and %s, repository-relative paths, the output declared once across %s' % (of, tf, rd['outputs']),
                    [node[f] if f in node else '<absent>' for f in (of, tf)])
            rpairs[node[of]] = node[tf]
        if rd['render_artifact'] not in arts:
            bad('host_scope.shared_artifacts.%s' % (rd['render_artifact'],), 'is not declared (the rendered-output render closure is SEQUENCED on GEN2-J-RENDER)', sorted(arts))
        rclosure = list(arts[rd['render_artifact']]['templates'])
        if sorted(rpairs) != sorted(rendered):
            raise ValueError('lme: %s (document %s %s / %s.%s): %s; the rendered members %s must equal the declared rendered outputs %s' % (
                b('identity_refusal', str), v['document'], v['members'], key, rd['outputs'], b('identity_text', str), sorted(rendered), sorted(rpairs)))
        # F05-S4 RENDER-CONTEXT-02 (J-FIN-F05-01): the render artifact's leading entry_count templates (each proved:
        # free variables EQUAL its declared inputs, incl. lme_entry_binding) are EXACTLY the declared rendered output
        # templates -- every declared rendered root an entry, nothing else (its macros stay non-entry, free-variable-free)
        rentries = rclosure[:arts[rd['render_artifact']]['entry_count']]
        if sorted(rentries) != sorted(set(rpairs.values())):
            bad('host_scope.shared_artifacts.%s.entry_count / %s.%s' % (rd['render_artifact'], key, rd['outputs']),
                'the leading entry templates must be exactly the declared rendered output templates %s' % (sorted(set(rpairs.values())),), rentries)
    # the consumer's row identity / template fields (generate_entries :243, :250) are declared once in the registry
    # view and must be roster source keys (no second literal of a B value; a renamed B key refuses typed)
    if len(v['derived_row_keys']) != 5 or set(v['derived_row_keys']) & set(skeys) \
            or v['row_id_key'] not in skeys or v['row_template_key'] not in skeys or len({v['row_id_key'], v['row_template_key'], mkey}) != 3:
        bad('registry published_views.%s.derived_row_keys / row_id_key / row_template_key' % (name,),
            'must name the five derived row fields [output_rel, inputs, bound, checkout_inputs, bound_checkout] (in that order) disjoint from the source keys %s, and two distinct non-member source keys' % (skeys,),
            [v['derived_row_keys'], v['row_id_key'], v['row_template_key']])
    out_k, in_k, bound_k, cin_k, bcin_k = v['derived_row_keys']
    seen_ids, seen_g, roster = [], {}, []
    ident_code, ident_text = b('identity_refusal', str), b('identity_text', str)
    parts = _rh_get(root, v['identity'])[1]['output_rel_parts']
    for i, r in enumerate(rows):
        m = r[mkey] if isinstance(r, dict) and mkey in r else None
        if not isinstance(r, dict) or sorted(r) != sorted(skeys) or not isinstance(m, dict) or sorted(m) != sorted(mkeys) \
                or any(not isinstance(x, str) or not x for x in m.values()):
            raise ValueError('lme: %s (document %s %s[%d]): %s; got %r' % (ident_code, v['roster_document'], B['roster_key'], i, ident_text, r))
        orel = sep.join(m[role_of['member_dir']] if w == 'member_dir' else m[role_of['member_file']] for w in parts)
        if (orel not in gen and orel not in rendered) or orel in seen_g:
            raise ValueError('lme: %s (document %s %s[%d]): %s; got %r (generated %s, rendered %s)' % (ident_code, v['roster_document'], B['roster_key'], i, ident_text, orel, sorted(gen), sorted(rendered)))
        if r[v['row_id_key']] in seen_ids:
            bad('document %s %s[%d]' % (v['roster_document'], B['roster_key'], i), 'must carry a unique %s' % (v['row_id_key'],), r[v['row_id_key']])
        seen_g[orel] = i
        seen_ids.append(r[v['row_id_key']])
        if orel in rendered:
            # F05-S4 ROSTER-NONPLAYBOOK: inactive -> identity-checked above, omitted from the published roster
            if not ron:
                continue
            if r[v['row_template_key']] not in rclosure or rpairs[orel] != r[v['row_template_key']]:
                bad('document %s %s[%d] / %s.%s' % (v['roster_document'], B['roster_key'], i, key, rd['outputs']),
                    'a rendered row must carry the declared %s of its output (%r) and it must be in the rendered render closure %s' % (v['row_template_key'], rpairs[orel], rclosure),
                    r[v['row_template_key']])
            row = copy.deepcopy(r)
            # F05-S4 RENDER-CONTEXT (render-interface-01 s2, decision (a) NESTED): context = the early context + ONE
            # nested key context_binding.key -> struct_roles; struct = struct_sources (entry rows unchanged)
            row.update({out_k: orel,
                        in_k: {tvc: sorted(list(cpaths.values()) + [rd['context_binding'], rd['struct_roles']]), tvs: [rd['struct_sources']]},
                        bound_k: {tvc: dict([(f, p(cpaths[f])) for f in sorted(cpaths)] + [(rbind['key'], copy.deepcopy(rstruct))]), tvs: copy.deepcopy(rsrc)},
                        cin_k: {tvd: decl_rel},
                        bcin_k: {tvd: decl_rel}})
            roster.append(row)
            continue
        if r[v['row_template_key']] not in closure:
            bad('document %s %s[%d]' % (v['roster_document'], B['roster_key'], i),
                'must carry a %s in the render closure %s' % (v['row_template_key'], closure), r[v['row_template_key']])
        sval = {'declaration_rel': decl_rel, 'member_dir': m[role_of['member_dir']], 'member_file': m[role_of['member_file']]}
        row = copy.deepcopy(r)
        row.update({out_k: orel,
                    in_k: {tvc: sorted(cpaths.values()), tvs: [v['declaration_rel']]},
                    bound_k: {tvc: dict((f, p(cpaths[f])) for f in sorted(cpaths)),
                              tvs: dict((select[rk], sval[sroles[rk]]) for rk in sorted(sroles))},
                    cin_k: {tvd: decl_rel},
                    bcin_k: {tvd: decl_rel}})
        roster.append(row)
    unref = sorted((set(gen) | set(rendered)) - set(seen_g))
    if unref:
        raise ValueError('lme: %s (document %s %s): %s; unreferenced generated members %s' % (ident_code, v['roster_document'], B['roster_key'], ident_text, unref))
    # ---- retire_roles (OD-S2-05): pending_roles restricted to retire_row_keys ----
    pend = b('pending_roles', dict)
    retire_roles = dict((role, f) for role, f in sorted(pend.items()) if f in rr_keys)
    if sorted(retire_roles.values()) != sorted(rr_keys):
        bad('document %s %s' % (v['document'], B['pending_roles']), 'must cover exactly the retire row keys %s' % (sorted(rr_keys),), pend)
    # ---- LD05 (OD-S3-05 a + dynamic references): every consumed code, direct or through a declared selector ----
    records, refusals, texts = b('records', dict), b('record_refusals', dict), b('record_texts', dict)
    need = [(c, 'record_codes') for c in v['record_codes']]
    for ref in v['record_code_refs']:
        how, path = next(iter(ref.items()))
        f, sel = _rh_get(records, path)
        if not f or (how == 'values_of' and not isinstance(sel, dict)) or (how == 'items_of' and not isinstance(sel, list)):
            bad('document %s %s.%s' % (v['document'], B['records'], path), 'is an admitted dynamic code selector (record_code_refs %s) and must be declared' % (how,), sel if f else '<absent>')
        need += [(c, '%s %s' % (how, path)) for c in (sel.values() if how == 'values_of' else sel)]
    cpat = pats[v['record_code_pattern']]
    for c, via in need:
        if not isinstance(c, str) or c not in refusals or not isinstance(refusals[c], str) or not cpat.fullmatch(refusals[c]) \
                or c not in texts or not isinstance(texts[c], str) or not texts[c].strip():
            bad('registry remote_harness_schema.published_views.%s.record_code_refs/record_codes: document %s %s.%s / %s.%s' % (name, v['document'], B['record_refusals'], c, B['record_texts'], c),
                'is absent or not a code fully matching patterns.%s with a non-empty text (generator-consumed custody key, reached through %s)' % (v['record_code_pattern'], via),
                [_rh_get(refusals, c)[1] if isinstance(c, str) else c, _rh_get(texts, c)[1] if isinstance(c, str) else c])
    # ---- adoption (L-ADO-01..05) ----
    ac = v['adoption_checks']
    adoption = b('adoption', dict)
    if not isinstance(ac['adoption_keys'], list) or sorted(adoption) != sorted(ac['adoption_keys']):
        bad('document %s %s' % (v['document'], B['adoption']), 'must carry exactly %s' % (ac['adoption_keys'],), sorted(adoption))
    base, authored = b('adoption_baseline'), b('adoption_authored', dict)
    erx, brx = b('edition_regex', str), b('blob_id_regex', str)
    if not (base is None or (isinstance(base, str) and re.fullmatch(erx, base))) \
            or any(not isinstance(k, str) or not relp.fullmatch(k) or not isinstance(x, str) or not re.fullmatch(brx, x) for k, x in authored.items()):
        bad('document %s %s / %s' % (v['document'], B['adoption_baseline'], B['adoption_authored']), 'must be null or a commit (%s) and {output rel: blob id (%s)}' % (erx, brx), [base, authored])
    adoption_rel, retention = b('adoption_rel', str), p(ac['retention_root'], str)
    excludes, forms = _rh_get(root, ac['excludes'])[1], ac['exclude_forms']
    if not isinstance(excludes, list) or not isinstance(forms, dict) or any(x not in _RH_EG_EXCLUDE_WORDS for x in forms.values()) \
            or any(not isinstance(e, dict) or len(e) != 1 or next(iter(e)) not in forms for e in excludes):
        bad('document %s %s' % (v['document'], ac['excludes']), 'must be a list of single-key excludes of the declared forms %s' % (forms,), excludes)

    def excluded(rel):
        parts = rel.split(sep)
        for e in excludes:
            k, x = next(iter(e.items()))
            if (forms[k] == 'component' and x in parts) or (forms[k] == 'prefix' and (rel == x or rel.startswith(x + sep))) \
                    or (forms[k] == 'suffix' and rel.endswith(x)):
                return True
        return False
    # MR03-RENDERED-SOURCE-BOOTSTRAP (DEP-MR03-LOADER-01; codex-tick606 / codex-tick610): the rendered dispatch rows are
    # owned by the rendered-output authority (rpairs, equal to the B rendered members above), never ordinary importer
    # keys, empty while the rendered kind is inactive, one obligation row each; their closures and body obligations
    # join the protected executable set beside the importers.
    if set(rimps) - set(rpairs) or set(rimps) & set(importers) or (not ron and rimps) or sorted(robls) != sorted(rimps):
        bad('%s.%s / %s.%s' % (projs[v['importers']]['at'], projs[v['importers']]['rendered_dispatch']['to'], projs[v['bodies']]['at'], projs[v['bodies']]['rendered_to']),
            'must key only declared rendered outputs %s (never an ordinary importer key), be empty while the rendered kind is inactive and carry exactly one obligation row per rendered dispatch row' % (sorted(rpairs),),
            [sorted(rimps), sorted(robls)])
    executable = set(p(ac['dispatch_closure'], list)) | set(p(ac['common'], list)) | set(importers) \
        | set(x for c in importers.values() for x in c) | set(x[0] for ws in bodies.values() for rs in ws.values() for x in rs) | {decl_rel} | set(closure) | set(rclosure) \
        | set(rendered) | set(rimps) | set(x for c in rimps.values() for x in c) | set(x[0] for ws in robls.values() for rs in ws.values() for x in rs)
    # F05-S4 GROUPS CORRECTIONS (codex-tick564 F05-GROUP-RENDERED-RETENTION-OVERLAP): the declared rendered OUTPUT
    # identities (B members marked rendered, read by _rh_eg_generated whether or not rendered.when_present is declared)
    # join the protected set beside their template closure, so a retention root or adoption manifest equal to or an
    # ancestor of a rendered output refuses, active and inactive alike; every entry-output protection above is kept.
    for what, rel in (('retention root %s.%s' % (key, ac['retention_root']), retention), ('adoption manifest %s' % (B['adoption_rel'],), adoption_rel)):
        hit = sorted(x for x in executable if x == rel or x.startswith(rel + sep))
        if not relp.fullmatch(rel) or not excluded(rel) or hit:
            bad(what, 'must be a repository-relative path under a transfer exclude and outside every executable closure, admission member and render input (L-ADO-04)', [rel, hit])
    gpaths = sorted(set(list(cpaths.values()) + [v['declaration_rel'], v['policy_path_separator']]
                        # F05-S4 ROSTER-NONPLAYBOOK: every policy input of an active rendered row is in the structural digest
                        # F05-S4 RENDER-CONTEXT: + struct_sources and context_binding (render-interface-01 s3)
                        # F05-S4 RENDER-CONTEXT-02: + kind_tests (parent successor-07 J-S07-PROFILE-KEY-ADMISSION)
                        + ([rd['context_kind'], rd['struct_roles'], rd['struct_sources'], rd['context_binding'], rd['kind_tests']] + [pseparator.join([o, f]) for o in rd['outputs'] for f in (of, tf)] if ron else [])))
    iface_base = _rh_get(root, v['interface']['base'])[1]
    files = p(v['interface']['files'], dict)
    if not isinstance(iface_base, str) or not relp.fullmatch(iface_base):
        bad('document %s %s' % (v['document'], v['interface']['base']), 'must be a repository-relative path', iface_base)
    iface = sorted(iface_base + sep + f for f in files)
    # spec P5 never_generated_rel: the declared never-generated rels + every entry-dir family guard closure (the closure
    # of every B member key -- guard members only; runner requires / entry_closure / route_includes are NOT in it)
    nevers = [p(x, str) for x in v['never_generated']]
    # F05-S4 ROSTER-NONPLAYBOOK: a rendered member is no B-guarded entry (no importer key, no guard closure)
    bmem = [(d, f) for d in sorted(_members) for f in sorted(_members[d]) if (d + sep + f) not in rendered]
    guards = [x for d, f in bmem for x in importers[d + sep + f]] if all((d + sep + f) in importers for d, f in bmem) else None
    if guards is None or set(nevers + guards) & (set(gen) | set(rendered)):
        bad('%s.%s / published_views.%s.importers' % (key, v['never_generated'], name),
            'must give every B-guarded member an importer closure and never name a generated or rendered member',
            [sorted(set(nevers + (guards or [])) & (set(gen) | set(rendered))), guards is None])
    return {'schema_version': v['schema_version'],
            'names_family': ptext[v['names_family']],
            'source_keys': list(skeys),
            'row_keys': sorted(list(skeys) + list(v['derived_row_keys'])),
            'roster_source_rel': docs[v['roster_document']]['rel'],
            'roster_source_sha256': docs[v['roster_document']]['sha256'],
            'roster': roster,
            'retire': copy.deepcopy(retire_rows),
            'retire_roles': retire_roles,
            'records': copy.deepcopy(records),
            'ownership': copy.deepcopy(b('ownership', dict)),
            'policy_path_separator': pseparator,
            'struct_roles': struct_roles,
            'struct_policy_paths': gpaths,
            # MR03 (DEP-MR03-LOADER-01): + the secondary destinations (_rh_pj_secondary), RESOLVED too
            'excluded_paths': sorted([pseparator.join([projs[n]['at'], projs[n]['to']]) for n in projs]
                                     + [pseparator.join([projs[n]['at'], s]) for n in projs for s in _rh_pj_secondary(n, projs[n])]),
            # F05-S4 RENDER-CONTEXT-02: while the rendered kind is active, the declared entry shape and permitted kinds
            # are digest-bound with struct_sources (the inactive digest input is unchanged)
            'structural_inputs_sha256': _digest(dict([('struct_policy_paths', dict((x, p(x)) for x in gpaths)), ('documents', dict((n, d['sha256']) for n, d in sorted(docs.items())))]
                                                     + ([('rendered_source_entry', {'fields': copy.deepcopy(rd['source_entry_fields']), 'kinds': list(rd['source_kinds']), 'test_names': list(rd['kind_test_names'])})] if ron else []))),
            'never_generated_rel': sorted(set(nevers + guards)),
            'interface_rel': iface,
            'interface_entries_rel': sorted(set(gen) & set(iface)),
            'body_rel': sorted(set(x[0] for ws in bodies.values() for rs in ws.values() for x in rs)),
            'closure': closure,
            # F05-S4 ROSTER-NONPLAYBOOK: the published rendered rows' output rels and their render closure ([] while
            # rendered.when_present is undeclared: this profile owns no rendered output; the rows are omitted above)
            'rendered_rel': sorted(r[out_k] for r in roster if r[out_k] in rendered),
            'rendered_closure': rclosure,
            # F05-S4 RENDER-CONTEXT: the projected <K> (context_binding) and the render struct_roles the generator
            # compares bound[context][<K>] with ({} while rendered.when_present is undeclared, as rendered_closure [])
            'rendered_context_binding': copy.deepcopy(rbind),
            'rendered_struct_roles': copy.deepcopy(rstruct),
            # F05-S4 RENDER-CONTEXT-02: the declaration-owned struct_sources entry key set (replaces the generator's
            # literal [fact, path]); [] while rendered.when_present is undeclared
            'rendered_source_entry_keys': sorted(rd['source_entry_fields'].values()) if ron else [],
            'adoption': copy.deepcopy(adoption)}


_RH_BASE_KEYS = frozenset(('schema_version', 'policy', 'policy_sha256', 'adapter', 'host_scoped_paths',
                           'scope_invariant_sha256', 'shared_artifact_inputs_sha256'))
_RH_SCOPED_KEYS = frozenset(('scope', 'binding', 'scope_sha256', 'scopes', 'scopes_sha256'))


def _rh_verify_entry(where, sec, keys, schema, admission):
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
    # C1-RECIPE-PUB-02 (codex-tick886 Q_R2_PROV_02): the generation bindings re-derive from the entry's OWN policy, its
    # (just verified) class key and the protected admission record; an edited or stale binding refuses.
    gbk = _rh_gb_decl(schema)['to']
    if not _leaf_equal(sec[gbk], _rh_generation_bindings(sec['policy'], sec, schema, where, admission)):
        raise ValueError('lme: published %s.%s is not the binding its own policy, class key and the admission record derive (registry generation_binding)' % (where, gbk))
    trk = _rh_tr_decl(schema)['to']
    if not _leaf_equal(sec[trk], _rh_toolchain_renderers(sec['policy'], schema, where)):
        raise ValueError(schema['toolchain_rendering_errors']['readback'] % (where, trk))


def lme_verify_resolved_structure(resolved, registry, *, documents, admission):
    """C1-INVOCATION-CONTEXT-01 L8-02 (codex 896 DEV-L7-03): the NARROW structural verification of a published
    lme_resolved (the body lme_verify_resolved carried through L7); it never claims completeness: the complete
    verification is lme_verify_resolved, which runs this check and then the source binding.
    F05-S3 LR-15: `documents` / `admission` are the SAME resolver outputs the projection read (required keyword
    arguments; a call without them is a TypeError). They are re-admitted here (_rh_documents: rel re-derivation +
    admitted digest before parse), the ACTIVE view set is the one the section's own policy publishes, and every
    document-kind projected leaf re-derives from the section's policy with its projected destinations stripped.
    C1-TYPED-OUTPUT-REVISION (codex 022716). Validates the ACTUAL published lme_resolved -- not a recompute
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
        if documents != {} or admission is not None:
            raise ValueError('lme: published lme_resolved carries no %s section; the document reader outputs must be an empty mapping and null; got %r / %r' % (
                key, sorted(documents) if isinstance(documents, dict) else _rh_kind(documents), _rh_kind(admission)))
        return True
    sec = resolved[key]
    scoped = isinstance(sec, dict) and 'scope' in sec
    if not isinstance(sec, dict) or 'policy' not in sec or not isinstance(sec['policy'], dict):
        raise ValueError('lme: published %s must be a mapping carrying a policy mapping; got %r' % (key, _rh_kind(sec)))
    docs = _rh_documents(sec['policy'], schema, key, documents, admission)
    want_views = _rh_published_views(sec['policy'], schema, key, docs)
    gbk = _rh_gb_decl(schema)['to']   # C1-RECIPE-PUB-02: the generation-binding key of the section and of every scope entry
    trk = _rh_tr_decl(schema)['to']
    _rh_verify_entry(key, sec, _RH_BASE_KEYS | set(want_views) | {gbk, trk} | (_RH_SCOPED_KEYS if scoped else frozenset()), schema, admission)
    # F05 LV-4: every published view re-derives from the section's OWN policy + the registry (type-aware), so a view
    # edited after resolve, or a pre-supplied section carrying a stale view, refuses. F05-S3: only the ACTIVE set.
    for name, want_v in sorted(want_views.items()):
        if not _leaf_equal(sec[name], want_v):
            raise ValueError('lme: published %s.%s is not the view its own policy and the registry derive (published_views.%s)' % (key, name, name))
    # F05-S3 LR-15: the document-kind projected leaves re-derive from the admitted documents. EXACTLY the leaves each
    # projection writes are stripped -- lookup_merge: at.to.<role> for every role of at.from (at.to also holds authored
    # producer-only roles, which stay); every other kind: at.to (it refuses an authored `to`) -- and the projections
    # (and partitions) re-applied; the document-kind leaves are compared here, select_tree below (the rest are digest-bound).
    projs = schema['policy_projections']
    dests = []
    for n in sorted(projs):
        pj = projs[n]
        if pj['kind'] in _RH_PJ_GATED and 'when' in pj and not _rh_contract_active(sec['policy'], schema, pj['when'], 'policy_projections.%s.when' % (n,)):
            continue   # F05-S4: gated and inactive -> it wrote nothing
        if pj['kind'] == 'lookup_merge':
            fsel, sel = _rh_get(sec['policy'], '%s.%s' % (pj['at'], pj['from']))
            if not fsel or not isinstance(sel, dict):
                raise ValueError('lme: published %s.policy.%s.%s must be a mapping (policy_projections.%s)' % (key, pj['at'], pj['from'], n))
            dests += ['%s.%s.%s' % (pj['at'], pj['to'], r) for r in sorted(sel)]
        else:
            dests.append('%s.%s' % (pj['at'], pj['to']))
            dests += ['%s.%s' % (pj['at'], s) for s in _rh_pj_secondary(n, pj)]   # MR03 (codex-tick612 F1)
    again = _rh_project_policy(_rh_without(sec['policy'], dests), schema, key, docs[0], docs[1])[0]
    # MR03 (codex-tick612 F1): the secondary destinations (_rh_pj_secondary) are compared exactly like the primary one
    for n, d in sorted((n, '%s.%s' % (projs[n]['at'], s)) for n in projs if projs[n]['kind'] in _RH_DOC_KIND_SHAPES
                       for s in [projs[n]['to']] + _rh_pj_secondary(n, projs[n])):
        (fh, have), (fw, want_l) = _rh_get(sec['policy'], d), _rh_get(again, d)
        if fh != fw or (fh and not _leaf_equal(have, want_l)):
            raise ValueError('lme: published %s.policy.%s is not the leaf the admitted documents derive (policy_projections.%s); got %r' % (key, d, n, have if fh else '<absent>'))
    want = schema['projection_schema_version']
    if not _leaf_equal(sec['schema_version'], want):
        raise ValueError('lme: published %s.schema_version is %r (%s); the registry declares %r (%s)' % (
            key, sec['schema_version'], type(sec['schema_version']).__name__, want, type(want).__name__))
    # C1-RECIPE-PUB-01 (OW-H11-C1-01-PUB; codex-tick883 SR290_09): every select_tree object re-derives through the SAME
    # _rh_pj_select_tree from its own policy with that object stripped: the section's policy here and, when scoped, every
    # scope entry's policy below (each class's own selected recipe). An object edited after resolve refuses.
    stp, stn = _rh_patterns(schema)[0], sorted(n for n in projs if projs[n]['kind'] == 'select_tree')

    def _st_back(where, p):
        for n in stn:
            d = '%s.%s' % (projs[n]['at'], projs[n]['to'])
            fh, have = _rh_get(p, d)
            if not fh or not _leaf_equal(have, _rh_pj_select_tree(n, projs[n], _rh_without(p, [d]), key, stp)):
                raise ValueError('lme: published %s.policy.%s is not the object its own policy derives (policy_projections.%s); got %r' % (where, d, n, _rh_kind(have) if fh else '<absent>'))
    _st_back(key, sec['policy'])
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
        _rh_verify_entry('%s.scopes.%s' % (key, where), ent, set(_RH_SCOPE_ENTRY) | {'kind', 'id', 'scope_sha256', gbk, trk}, schema, admission)
        ident = {'kind': ent['kind'], 'id': ent['id']}
        if ent['scope_sha256'] != _digest({'scope': ident, 'binding': binding, 'policy_sha256': ent['policy_sha256']}):
            raise ValueError('lme: published %s.scopes.%s.scope_sha256 is not bound to its scope/binding/policy' % (key, where))
        _st_back('%s.scopes.%s' % (key, where), ent['policy'])
    if sec['scopes_sha256'] != _digest(scopes):
        raise ValueError('lme: published %s.scopes_sha256 is not the digest of its actual scopes' % (key,))
    # GRAPH-SHARED-CONTRACT (codex-tick304): the bound target inputs are present exactly when the controller scope's
    # policy declares them, cover exactly the bound targets, and re-type to themselves (no undeclared role, no value
    # of another type).
    tdecl = _rh_target_inputs(scopes['controller']['policy'], schema, key)
    if bool(tdecl) != ('target_inputs' in dep):
        raise ValueError('lme: published %s.binding.deployment.target_inputs must be present exactly when the policy declares target inputs' % (key,))
    if tdecl:
        ti = dep['target_inputs']
        tnames = dict((r, tdecl[r]['var']) for r in sorted(tdecl))
        if not isinstance(ti, dict) or sorted(ti) != sorted(dep.get('targets') or []) or any(not isinstance(v, dict) for v in ti.values()) \
                or not _leaf_equal(_rh_bind_target_inputs(tdecl, {'inputs': {'vars': tnames, 'values': ti}}, sorted(ti), schema, key), ti):
            raise ValueError('lme: published %s.binding.deployment.target_inputs must map every bound target to its declared, typed inputs' % (key,))
    me = sec['scope']
    mine = scopes['controller'] if isinstance(me, dict) and me.get('kind') == 'controller' else \
        scopes['targets'].get(me.get('id')) if isinstance(me, dict) else None
    if not isinstance(mine, dict) or not _leaf_equal({'kind': mine['kind'], 'id': mine['id']}, me) \
            or not _leaf_equal({k: mine[k] for k in _RH_SCOPE_ENTRY + (gbk, trk)}, {k: sec[k] for k in _RH_SCOPE_ENTRY + (gbk, trk)}) \
            or sec['scope_sha256'] != mine['scope_sha256']:
        raise ValueError('lme: published %s is not its own scope entry %r of scopes' % (key, me))
    return True


def lme_verify_resolved(resolved, registry, *, documents, admission, source):
    """C1-INVOCATION-CONTEXT-01 L8-02 (codex 896 DEV-L7-03 join; SR-302-05): the ONE complete verification of a
    published lme_resolved. documents / admission are the SAME resolver outputs the projection read; source is REQUIRED
    (a call without it is a TypeError) and must carry exactly the registry source_binding.verification.source_fields
    keys: the published binding, the authoritative captures, the manifests dir and the record blocks. Applicability
    follows the DECLARED verification.requirement (the closed word list admits required only), never the presence of
    evidence: lme_verify_resolved_structure runs, then lme_verify_source_binding re-derives the binding from the same
    resolved object and admission. Nothing downgrades to configuration-only verification. Returns True; raises otherwise."""
    sb = _sb_decl(registry)[0]
    sf = sb['verification']['source_fields']
    if not isinstance(source, Mapping) or sorted(source) != sorted(sf.values()):
        _sb_refuse(sb, 'the complete verification requires %s with exactly %s; nothing downgrades to configuration-only verification' % (
            sb['verification']['source_arg'], sorted(sf.values())), sorted(source) if isinstance(source, Mapping) else _rh_kind(source))
    lme_verify_resolved_structure(resolved, registry, documents=documents, admission=admission)
    lme_verify_source_binding(source[sf['binding']], resolved, registry, captures=source[sf['captures']], admission=admission,
                              manifests_dir=source[sf['manifests_dir']], record_blocks=source[sf['record_blocks']])
    return True


# F05-S3 LR-14: the resolve.yml DOCUMENT READER. Ansible reads the bytes (lookup ansible.builtin.file with the declared
# read options); these filters only decide WHAT may be read and admit what was read, through the SAME
# _rh_documents_admit the projection uses. scope = the resolver output _lme_rh_scope ({} = no policy declared); the
# policy is this host's own composition scope.composed[scope.self] (_rh_scoped proves it equals the projected one).
def _rh_reader_policy(scope, schema):
    key = schema['policy_key']
    if scope == {}:
        return key, None
    if not isinstance(scope, dict) or 'self' not in scope or 'composed' not in scope or not isinstance(scope['composed'], dict) \
            or scope['self'] not in scope['composed'] or not isinstance(scope['composed'][scope['self']], dict) \
            or key not in scope['composed'][scope['self']] or not isinstance(scope['composed'][scope['self']][key], dict):
        raise ValueError('lme: remote-harness scope context must carry this host\'s composition composed[self].%s (a mapping) for the document reader; got %r' % (
            key, sorted(scope) if isinstance(scope, dict) else _rh_kind(scope)))
    return key, scope['composed'][scope['self']][key]


def lme_rh_documents_active(scope, schema):
    """True exactly when the document channel's declaration_contract view is active for this host's policy (the ONE
    activity rule; no policy declared -> False). resolve.yml binds _lme_rh_admission to rh_src_admission only then."""
    # C1 s11 L11-07 (records-c1-framework-29): the channel, its reader-input names included, is admitted on EVERY
    # call, before the no-policy return, so a colliding or unprotected declaration refuses before any document access.
    ch = _rh_document_channel(schema)
    key, pol = _rh_reader_policy(scope, schema)
    if pol is None:
        return False
    return _rh_contract_active(pol, schema, ch['when'], 'remote_harness_schema.document_channel.when')


def lme_rh_document_plan(scope, schema, *, admission):
    """{names: the admission order (primaries, then dependents), read: {lstrip, rstrip} -- the policy value at
    document_channel.read, each a bool (contract body_domain admits only false)}. Inactive or no policy: names [] and
    read {} -- nothing is read -- and `admission` must be None. Active: `admission` must be the protected record."""
    key, pol = _rh_reader_policy(scope, schema)
    if pol is None:
        if admission is not None:
            raise ValueError('lme: no %s policy is declared; resolver output %s must be null; got %r' % (key, _rh_document_channel(schema)['admission']['fact'], _rh_kind(admission)))
        return {'names': [], 'read': {}}
    active, _out, order, _nxt = _rh_documents_admit(pol, schema, key, {}, admission, True)
    if not active:
        return {'names': [], 'read': {}}
    ch = _rh_document_channel(schema)
    fr, rd = _rh_get(pol, ch['read'])
    if not fr or not isinstance(rd, dict) or sorted(rd) != ['lstrip', 'rstrip'] or any(not isinstance(x, bool) for x in rd.values()):
        _rh_doc_refuse(ch, key, ch['read'], 'must be exactly {lstrip, rstrip} of bools (the declared exact-byte read options)', rd if fr else '<absent>')
    return {'names': list(order), 'read': {'lstrip': rd['lstrip'], 'rstrip': rd['rstrip']}}


def lme_rh_document_next_rel(documents, scope, schema, *, admission):
    """records-staged-reader-01: the admitted rels of the NEXT LEVEL as {name: rel}, each derived and full-matched
    BEFORE the reader builds a path, stats, Git-admits or reads it (OD-S3-01 a). `documents` = the documents read so
    far (a prefix of the order, each re-admitted). Empty once every name is carried; append refuses beyond it."""
    key, pol = _rh_reader_policy(scope, schema)
    if pol is None:
        raise ValueError('lme: no %s policy is declared; the document reader reads nothing' % (key,))
    active, _out, order, nxt = _rh_documents_admit(pol, schema, key, documents, admission, True)
    if not active:
        raise ValueError('lme: the document reader asked for a document beyond the admission order %s (carried %s)' % (
            order, sorted(documents) if isinstance(documents, dict) else _rh_kind(documents)))
    return dict(nxt)


def lme_rh_document_append(documents, text, name, scope, schema, *, admission):
    """documents + {name: {rel, text}}, returned only after the extended prefix is admitted (name-to-rel binding,
    membership in the reading-stage admission and the admitted digest of the exact text, BEFORE the strict parse).
    `name` is the reader's loop item: the first name of the next level. The loader re-admits the complete set."""
    key, pol = _rh_reader_policy(scope, schema)
    if pol is None:
        raise ValueError('lme: no %s policy is declared; the document reader reads nothing' % (key,))
    _a, _o, order, nxt = _rh_documents_admit(pol, schema, key, documents, admission, True)
    nn, nr = next(iter(nxt)) if nxt else (None, None)
    if nn != name:
        raise ValueError('lme: the document reader appended %r; the next document of the admission order %s is %r' % (name, order, nn))
    grown = dict(documents)
    grown[nn] = {'rel': nr, 'text': text}
    _rh_documents_admit(pol, schema, key, grown, admission, True)
    return grown


def lme_remote_harness_overridden_paths(composed, declared, override, schema, *, documents, admission):
    """Audit view (not revision-bound): sorted dotted leaf paths the operator override set; same validation (LR-16:
    the same documents/admission; a projected destination supplied by an override refuses as an authored `to`)."""
    return _rh_validate(composed, declared, override, schema, documents=documents, admission=admission)[1]


# C1-H11 (records-c1-h11-yaml-receipts-01; codex 855 / 860 / 865 / 868 / 870): the ONE renderer and the ONE whole-document
# admitter of every record in lme_global.record_schemas. The record names its serialization policy, which must equal
# _REC_POLICY (the one policy this code implements; any other refuses). Admission = ASCII text, one document parsed by
# _rh_yaml_load_unique (unique keys, no second document), exact declared keys and types, and byte equality with the
# canonical rendering of the parsed value. Refusals name the record, the key path and declaration words, never a value.
_REC_POLICY = {
    'encoding': 'ascii', 'serialization': 'yaml', 'key_order': 'schema_keys', 'duplicate_keys': 'refuse',
    'terminator': '\n', 'documents': 'single', 'indent': 2, 'string_style': 'single_quoted',
    'string_domain': 'printable_ascii', 'int_style': 'decimal', 'bool_style': 'lowercase',
    'null_values': 'refuse', 'empty_forms': {'mapping': '{}', 'sequence': '[]'}, 'key_style': 'plain',
    'keyed_key_style': 'single_quoted', 'keyed_order': 'sorted', 'canonical': 'render_equal'}
_REC_KEY = re.compile(r'[a-z][a-z0-9_]*\Z')
_REC_TEXT = re.compile(r'[ -~]+\Z')
_REC_HEX40 = re.compile(r'[0-9a-f]{40}\Z')
_REC_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_REC_STR_TAG = 'tag:yaml.org,2002:str'
_REC_KEY_TYPES = ('str', 'hex40', 'hex64')


def _rec_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


_REC_SCALARS = {
    'str': lambda v: isinstance(v, str) and bool(_REC_TEXT.match(v)),
    'hex40': lambda v: isinstance(v, str) and bool(_REC_HEX40.match(v)),
    'hex64': lambda v: isinstance(v, str) and bool(_REC_HEX64.match(v)),
    'int': _rec_int,
    'nonneg_int': lambda v: _rec_int(v) and v >= 0,
    'posint': lambda v: _rec_int(v) and v > 0,
    'bool': lambda v: isinstance(v, bool),
}


def _rec_refuse(name, at, why):
    raise ValueError('lme: record %s at %s: %s' % (name, '/'.join(at) if at else '(root)', why))


def _rec_same(a, b):
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return set(a) == set(b) and all(_rec_same(a[k], b[k]) for k in a)
    return a == b


def _rec_spec_ok(spec, blocks):
    if isinstance(spec, str):
        return spec in _REC_SCALARS
    if not isinstance(spec, dict) or len(spec) != 1:
        return False
    form, arg = list(spec.items())[0]
    if form == 'enum':
        return (isinstance(arg, list) and len(arg) > 0
                and all(type(e) is int or _REC_SCALARS['str'](e) for e in arg))
    if form == 'block':
        return isinstance(arg, str) and arg in blocks
    if form == 'list':
        return _rec_spec_ok(arg, blocks)
    if form == 'keyed':
        return (isinstance(arg, dict) and set(arg) == {'key', 'value'} and arg['key'] in _REC_KEY_TYPES
                and _rec_spec_ok(arg['value'], blocks))
    return False


def _rec_decl(schemas, policies, tags, name):
    import yaml
    if not isinstance(name, str) or not _REC_KEY.match(name):
        _rec_refuse('(unnamed)', (), 'the record name must be a declared plain word')
    if not isinstance(schemas, dict) or set(schemas) != {'blocks', 'records'}:
        _rec_refuse(name, (), 'record_schemas must carry exactly blocks and records')
    blocks, records = schemas['blocks'], schemas['records']
    if not isinstance(blocks, dict) or not isinstance(records, dict) or name not in records:
        _rec_refuse(name, (), 'no such record in record_schemas.records')
    rec = records[name]
    if (not isinstance(rec, dict) or set(rec) != {'policy', 'root'} or not isinstance(rec['root'], str)
            or rec['root'] not in blocks or not isinstance(rec['policy'], str)):
        _rec_refuse(name, (), 'a record declaration is exactly {policy, root}, root a declared block')
    if (not isinstance(policies, dict) or rec['policy'] not in policies
            or not _rec_same(policies[rec['policy']], _REC_POLICY)):
        _rec_refuse(name, (), 'serialization policy %s differs from the policy this renderer implements' % rec['policy'])
    for bname in blocks:
        b = blocks[bname]
        ok = (isinstance(bname, str) and isinstance(b, dict) and set(b) == {'keys', 'types'}
              and isinstance(b['keys'], list) and isinstance(b['types'], dict) and len(b['keys']) > 0
              and all(isinstance(k, str) and bool(_REC_KEY.match(k)) for k in b['keys'])
              and len(set(b['keys'])) == len(b['keys']) and set(b['keys']) == set(b['types'])
              and all(_rec_spec_ok(b['types'][k], blocks) for k in b['keys']))
        if not ok:
            _rec_refuse(name, ('blocks', str(bname)), 'a block is {keys, types}: unique plain keys, one declared type each')
    _rh_yaml_roles_bound(tags)
    probe = _rh_yaml_unique_loader(tags)('')
    try:
        bad = sorted(set(k for b in blocks.values() for k in b['keys']
                         if probe.resolve(yaml.ScalarNode, k, (True, False)) != _REC_STR_TAG))
    finally:
        probe.dispose()
    if bad:
        _rec_refuse(name, ('blocks',), 'declared keys %s do not resolve as plain strings' % bad)
    return blocks, {'block': rec['root']}


def _rec_check(v, t, blocks, name, at):
    if isinstance(t, str):
        if not _REC_SCALARS[t](v):
            _rec_refuse(name, at, 'value is not of declared type %s' % t)
        return
    form, arg = list(t.items())[0]
    if form == 'enum':
        if not any(type(v) is type(e) and v == e for e in arg):
            _rec_refuse(name, at, 'value outside the declared enum')
    elif form == 'list':
        if not isinstance(v, list):
            _rec_refuse(name, at, 'value is not a sequence')
        for i, e in enumerate(v):
            _rec_check(e, arg, blocks, name, at + (str(i),))
    elif form == 'keyed':
        if not isinstance(v, dict) or not all(_REC_SCALARS[arg['key']](k) for k in v):
            _rec_refuse(name, at, 'value is not a mapping keyed by %s' % arg['key'])
        for k in sorted(v):
            _rec_check(v[k], arg['value'], blocks, name, at + (k,))
    else:
        keys = blocks[arg]['keys']
        if not isinstance(v, dict) or not all(isinstance(k, str) for k in v) or set(v) != set(keys):
            _rec_refuse(name, at, 'mapping keys differ from the declared key list of block %s' % arg)
        for k in keys:
            _rec_check(v[k], blocks[arg]['types'][k], blocks, name, at + (k,))


def _rec_q(s):
    return "'" + s.replace("'", "''") + "'"


def _rec_node(v, t, blocks):
    """('', lines) for a non-empty mapping or sequence, lines at relative indent 0; (text, ()) otherwise."""
    pad = ' ' * _REC_POLICY['indent']
    if isinstance(t, dict) and 'block' in t:
        b = blocks[t['block']]
        return '', _rec_pairs([(k, v[k], b['types'][k]) for k in b['keys']], blocks)
    if isinstance(t, dict) and 'keyed' in t:
        if len(v) == 0:
            return _REC_POLICY['empty_forms']['mapping'], ()
        return '', _rec_pairs([(_rec_q(k), v[k], t['keyed']['value']) for k in sorted(v)], blocks)
    if isinstance(t, dict) and 'list' in t:
        if len(v) == 0:
            return _REC_POLICY['empty_forms']['sequence'], ()
        lines = []
        for e in v:
            text, sub = _rec_node(e, t['list'], blocks)
            lines.extend(['- ' + sub[0]] + [pad + s for s in sub[1:]] if sub else ['- ' + text])
        return '', tuple(lines)
    if isinstance(v, bool):
        return ('true' if v else 'false'), ()
    if isinstance(v, int):
        return '%d' % v, ()
    return _rec_q(v), ()


def _rec_pairs(pairs, blocks):
    pad = ' ' * _REC_POLICY['indent']
    lines = []
    for key, v, t in pairs:
        text, sub = _rec_node(v, t, blocks)
        lines.extend([key + ':'] + [pad + s for s in sub] if sub else [key + ': ' + text])
    return tuple(lines)


def lme_render_record(value, schemas, policies, tags, name):
    """C1-H11: the canonical text of declared record name over value, the only writer path of every declared record.
    Refuses (ValueError) a declaration other than the implemented policy or a value whose keys or types differ."""
    blocks, root = _rec_decl(schemas, policies, tags, name)
    _rec_check(value, root, blocks, name, ())
    return '\n'.join(_rec_node(value, root, blocks)[1]) + _REC_POLICY['terminator']


def lme_admit_record(text, schemas, policies, tags, name):
    """C1-H11 (codex 860 :82-85): whole-document admission of one declared record. A non-ASCII text, a parse,
    duplicate-key or second-document failure, any key or type difference, and any byte difference from the canonical
    rendering (order, quoting, comments, trailing content, terminator) refuse. Returns the admitted parsed value."""
    blocks, root = _rec_decl(schemas, policies, tags, name)
    if not isinstance(text, str) or not text.isascii():
        _rec_refuse(name, (), 'document is not %s text' % _REC_POLICY['encoding'])
    parsed, failure = _rh_yaml_load_unique(text, tags)
    if failure:
        _rec_refuse(name, (), 'document refused by the admitted loader (%s)' % (failure[0],))
    _rec_check(parsed, root, blocks, name, ())
    if lme_render_record(parsed, schemas, policies, tags, name) != text:
        _rec_refuse(name, (), 'document bytes differ from the canonical rendering')
    return parsed


def lme_manifest_strict(text, rel, parse):
    """DKJ-01: the ONE strict construction of a manifest or record text read outside the document channel. parse is the
    registry document_channel.parse, re-admitted here (shape, exact text fields, role binding: _rh_doc_parse_decl); the
    exact text is parsed by _rh_yaml_load_unique and a failure raises the declared document_channel.parse diagnostic for
    rel (metadata only), outside any handler. Returns the constructed document."""
    if not isinstance(text, str) or not isinstance(rel, str) or not rel:
        raise ValueError('lme: lme_manifest_strict takes the exact text (a string) and a non-empty rel (a string); got %s / %s' % (_rh_kind(text), _rh_kind(rel)))
    _rh_doc_parse_decl(parse)
    parsed, failure = _rh_yaml_load_unique(text, parse['tags'])
    if failure:
        raise ValueError('lme: %s' % (_rh_doc_parse_text(parse, rel, failure),))
    return parsed


# C1-PROFILE-IDENTITY-02 / C1-SOURCE-BINDING-01 (codex 892 Q1-A, source_edition_join; codex 894; SR-301-02):
# lme_profile_load_identity is retired (resolve.yml binds each native load to its retained capture). The registry
# profile_identity node keys and fields, the source_binding node keys and the roles of one binding and of one
# expectation row.
_PROFILE_IDENTITY_KEYS = frozenset(('var', 'global_var', 'fields', 'digest_algorithm', 'digest_of', 'encoding', 'refusal'))
_PROFILE_IDENTITY_FIELDS = ['path', 'sha256', 'capture_path']
_SB_KEYS = frozenset(('var', 'fields', 'expectation_fields', 'manifests_rel', 'edition_from', 'edition_regex_from',
                      'applicability', 'admission_absent', 'verification', 'refusal'))
# C1-INVOCATION-CONTEXT-01 L8-01 (codex 896 DEV-L7-03): the source_binding.verification node keys, its closed
# requirement words, the complete verifier's keyword argument name (an interface constant compared with the declared
# source_arg) and the roles of its source mapping.
_SB_VERIFICATION_KEYS = frozenset(('requirement', 'requirements', 'source_arg', 'source_fields'))
_SB_VERIFICATION_REQUIREMENTS = ['required']
_SB_SOURCE_ARG = 'source'
_SB_SOURCE_FIELDS = frozenset(('binding', 'captures', 'manifests_dir', 'record_blocks'))
_SB_FIELDS = frozenset(('applicability', 'root', 'commit', 'members', 'expectations'))
_SB_EXPECTATION_FIELDS = frozenset(('scope', 'class_key', 'role', 'binding_sha256'))


def _sb_decl(registry):
    """C1-SOURCE-BINDING-01: (source_binding, profile_identity) of registry remote_harness_schema, admitted at every
    use. source_binding: exactly _SB_KEYS; fields, expectation_fields and applicability exactly their roles mapped to
    distinct var_name words; manifests_rel a safe relative path; var, edition_from, edition_regex_from and refusal
    non-empty strings; admission_absent null. profile_identity: exactly _PROFILE_IDENTITY_KEYS of non-empty strings
    with fields _PROFILE_IDENTITY_FIELDS, digest_of exact_file_bytes and a guaranteed digest algorithm. Raises."""
    schema = registry.get('remote_harness_schema') if isinstance(registry, Mapping) else None
    if not isinstance(schema, Mapping) or 'source_binding' not in schema or 'profile_identity' not in schema:
        raise ValueError('lme: registry remote_harness_schema.source_binding and profile_identity must be declared (C1-SOURCE-BINDING-01)')
    sb, pi = schema['source_binding'], schema['profile_identity']
    pats = _rh_patterns(schema)[0]
    maps = (('fields', _SB_FIELDS), ('expectation_fields', _SB_EXPECTATION_FIELDS), ('applicability', _RH_GB_APPLICABILITY))
    if not isinstance(sb, Mapping) or set(sb) != _SB_KEYS or sb['admission_absent'] is not None or 'var_name' not in pats \
            or any(not isinstance(sb[k], str) or not sb[k] for k in ('var', 'manifests_rel', 'edition_from', 'edition_regex_from', 'refusal')) \
            or not _rh_safe_rel(sb['manifests_rel']) \
            or any(not isinstance(sb[k], Mapping) or set(sb[k]) != r for k, r in maps) \
            or any(not isinstance(w, str) or not pats['var_name'].fullmatch(w) for k, r in maps for w in sb[k].values()) \
            or any(len(set(sb[k].values())) != len(r) for k, r in maps):
        raise ValueError('lme: registry remote_harness_schema.source_binding must carry exactly %s (fields %s, expectation_fields %s and applicability %s each mapped to distinct var_name words; admission_absent null); got %r' % (
            sorted(_SB_KEYS), sorted(_SB_FIELDS), sorted(_SB_EXPECTATION_FIELDS), sorted(_RH_GB_APPLICABILITY), sb))
    if not isinstance(pi, Mapping) or set(pi) != _PROFILE_IDENTITY_KEYS or pi['fields'] != _PROFILE_IDENTITY_FIELDS \
            or any(not isinstance(pi[k], str) or not pi[k] for k in sorted(_PROFILE_IDENTITY_KEYS - {'fields'})) \
            or pi['var'] == pi['global_var'] or pi['digest_of'] != 'exact_file_bytes' \
            or pi['digest_algorithm'] not in hashlib.algorithms_guaranteed:
        raise ValueError('lme: registry remote_harness_schema.profile_identity must be exactly %s of non-empty strings with distinct var and global_var, fields %s, digest_of exact_file_bytes and a guaranteed digest algorithm; got %r' % (
            sorted(_PROFILE_IDENTITY_KEYS), _PROFILE_IDENTITY_FIELDS, pi))
    # C1-INVOCATION-CONTEXT-01 L8-01: verification is exactly _SB_VERIFICATION_KEYS; requirements the closed word list,
    # requirement one of them; source_arg the complete verifier's keyword; source_fields exactly _SB_SOURCE_FIELDS mapped
    # to distinct var_name words.
    vf = sb['verification']
    if not isinstance(vf, Mapping) or set(vf) != _SB_VERIFICATION_KEYS or vf['requirements'] != _SB_VERIFICATION_REQUIREMENTS \
            or not isinstance(vf['requirement'], str) or vf['requirement'] not in vf['requirements'] \
            or vf['source_arg'] != _SB_SOURCE_ARG or not isinstance(vf['source_fields'], Mapping) \
            or set(vf['source_fields']) != _SB_SOURCE_FIELDS \
            or any(not isinstance(w, str) or not pats['var_name'].fullmatch(w) for w in vf['source_fields'].values()) \
            or len(set(vf['source_fields'].values())) != len(_SB_SOURCE_FIELDS):
        raise ValueError('lme: registry remote_harness_schema.source_binding.verification must be exactly %s: requirements %s, requirement one of them, source_arg %r and source_fields %s mapped to distinct var_name words; got %r' % (
            sorted(_SB_VERIFICATION_KEYS), _SB_VERIFICATION_REQUIREMENTS, _SB_SOURCE_ARG, sorted(_SB_SOURCE_FIELDS), vf))
    return sb, pi


def _sb_refuse(sb, what, got):
    raise ValueError('lme: %s: %s; got %r' % (sb['refusal'], what, got))


def lme_source_binding(resolved, registry, *, captures, admission, manifests_dir, record_blocks):
    """C1-SOURCE-BINDING-01 (codex 892 source_edition_join; answers HOLE-PUB2-ADMISSION-EDITION-TIE; SR-301-02): the ONE
    source-admission binding of a resolve invocation under the registry source_binding.fields words, published by
    resolve.yml beside (never inside) lme_resolved, so outside policy_sha256 and the revision payload. captures is
    exactly {<profile_identity.global_var>: <global identity>, <profile_identity.var>: <profile identity>}, each
    exactly profile_identity.fields. root = manifests_dir (normalized) with its trailing /<manifests_rel> removed;
    members = {<source path relative to root>: <capture sha256>}: the key is the SOURCE path, never capture_path (a
    harness capture lives inside the leased run directory and is never required below root). Without the policy_key
    section: not_applicable, admission must be admission_absent, commit null, expectations empty. With it: applies;
    the section policy names the admission members container, observed field and digest algorithm
    (document_channel.admission; the algorithm must be profile_identity.digest_algorithm); every member digest must
    be the admission record's observed digest for its rel; commit is the admission record value under the field named
    at edition_from, full-matching the pattern at edition_regex_from; record_blocks[generation_binding.provenance_block]
    must carry exactly the provenance_fields keys with its role key enum equal to the role list at roles_from;
    expectations = one row per scope entry (controller, then targets sorted; scope null for an unscoped section) and
    role: scope {kind, id}, class_key, role and binding_sha256 = the digest of that generation binding. No fallback:
    any mismatch raises the declared refusal."""
    import posixpath
    sb, pi = _sb_decl(registry)
    schema = registry['remote_harness_schema']
    f, ef, ap = sb['fields'], sb['expectation_fields'], sb['applicability']
    tail = '/' + sb['manifests_rel']
    mdir = posixpath.normpath(manifests_dir) if isinstance(manifests_dir, str) and manifests_dir else ''
    if not mdir.endswith(tail) or len(mdir) == len(tail):
        _sb_refuse(sb, 'the manifests dir must end with %s below a checkout root' % (tail,), manifests_dir)
    root = mdir[:-len(tail)]
    names = [pi['global_var'], pi['var']]
    if not isinstance(captures, Mapping) or sorted(captures) != sorted(names):
        _sb_refuse(sb, 'captures must carry exactly the published identities %s' % (names,),
                   sorted(captures) if isinstance(captures, Mapping) else _rh_kind(captures))
    hexlen = hashlib.new(pi['digest_algorithm']).digest_size * 2
    members = {}
    for m in names:
        c = captures[m]
        if not isinstance(c, Mapping) or set(c) != set(_PROFILE_IDENTITY_FIELDS) \
                or any(not isinstance(c[k], str) or not c[k] for k in _PROFILE_IDENTITY_FIELDS) \
                or not re.fullmatch('[0-9a-f]{%d}' % (hexlen,), c['sha256']):
            _sb_refuse(sb, 'identity %s must be exactly %s of non-empty strings with a %s hex digest' % (m, _PROFILE_IDENTITY_FIELDS, pi['digest_algorithm']),
                       sorted(c) if isinstance(c, Mapping) else _rh_kind(c))
        src = posixpath.normpath(c['path'])
        rel = src[len(root) + 1:] if src.startswith(root + '/') else None
        if not _rh_safe_rel(rel) or rel in members:
            _sb_refuse(sb, 'identity %s must name a distinct source file below the checkout root %s (the member key is the source path, never the capture path)' % (m, root), c['path'])
        members[rel] = c['sha256']
    if not isinstance(resolved, Mapping):
        _sb_refuse(sb, 'lme_resolved must be a mapping', _rh_kind(resolved))
    key = schema.get('policy_key')
    if not key or key not in resolved:
        if admission != sb['admission_absent']:
            _sb_refuse(sb, 'lme_resolved carries no %s section, so the admission must be the declared absent form' % (key,), _rh_kind(admission))
        return {f['applicability']: ap['not_applicable'], f['root']: root, f['commit']: None, f['members']: members, f['expectations']: []}
    sec = resolved[key]
    pol = sec.get('policy') if isinstance(sec, Mapping) else None
    if not isinstance(pol, Mapping):
        _sb_refuse(sb, 'the published %s section must carry a policy mapping' % (key,), _rh_kind(sec))
    ch = _rh_document_channel(schema)
    am = ch['admission']
    want = (('members', am['members']), ('observed', am['observed']), ('algorithm', ch['digest_algorithm']),
            ('edition field', sb['edition_from']), ('edition pattern', sb['edition_regex_from']))
    got = [_rh_get(pol, p) for _n, p in want]
    if any(not fd or not isinstance(v, str) or not v for fd, v in got) or got[2][1] != pi['digest_algorithm']:
        _sb_refuse(sb, 'the %s policy must name %s as non-empty strings, the algorithm equal to profile_identity.digest_algorithm %s' % (
            key, ', '.join('%s (%s)' % (n, p) for n, p in want), pi['digest_algorithm']), [v if fd else '<absent>' for fd, v in got])
    mk, ok, efld, erx = got[0][1], got[1][1], got[3][1], got[4][1]
    if not isinstance(admission, Mapping) or not isinstance(admission.get(mk), Mapping):
        _sb_refuse(sb, 'the protected source-admission record must carry a %r mapping; nothing stands in for it' % (mk,),
                   sorted(admission) if isinstance(admission, Mapping) else _rh_kind(admission))
    adm = admission[mk]
    for rel in sorted(members):
        ent = adm.get(rel)
        if not isinstance(ent, Mapping) or ent.get(ok) != members[rel]:
            _sb_refuse(sb, 'member %s: the engine-consumed capture digest is not the admitted observed digest' % (rel,),
                       'unadmitted' if not isinstance(ent, Mapping) else 'digest differs')
    commit = admission.get(efld)
    if not isinstance(commit, str) or not re.fullmatch(erx, commit):
        _sb_refuse(sb, 'the admission record %s must full-match the declared edition pattern' % (efld,), _rh_kind(commit))
    gb = _rh_gb_decl(schema)
    gf, pf = gb['fields'], gb['provenance_fields']
    blk = record_blocks.get(gb['provenance_block']) if isinstance(record_blocks, Mapping) else None
    froles, roles = _rh_get(pol, gb['roles_from'])
    rkeys = sorted(k for k in pf if pf[k] == 'role')
    if not isinstance(blk, Mapping) or not isinstance(blk.get('keys'), list) or sorted(blk['keys']) != sorted(pf) \
            or not isinstance(blk.get('types'), Mapping) or len(rkeys) != 1 or not froles \
            or not _leaf_equal(blk['types'].get(rkeys[0]), {'enum': roles}):
        _sb_refuse(sb, 'record block %s must carry exactly the generation_binding.provenance_fields keys and its role key enum must be the role list at %s (HOLE-RT3-PROV-FIELD-MAP)' % (
            gb['provenance_block'], gb['roles_from']), sorted(blk['keys']) if isinstance(blk, Mapping) and isinstance(blk.get('keys'), list) else _rh_kind(blk))
    if 'scope' in sec:
        scopes = sec.get('scopes')
        if not isinstance(scopes, Mapping) or not isinstance(scopes.get('targets'), Mapping):
            _sb_refuse(sb, 'the scoped %s section must carry scopes {controller, targets}' % (key,), _rh_kind(scopes))
        ents = [scopes.get('controller')] + [scopes['targets'][t] for t in sorted(scopes['targets'])]
        rows = [({'kind': e.get('kind'), 'id': e.get('id')} if isinstance(e, Mapping) else None, e) for e in ents]
    else:
        rows = [(None, sec)]
    exp = []
    for ident, ent in rows:
        bs = ent.get(gb['to']) if isinstance(ent, Mapping) else None
        if not isinstance(bs, Mapping):
            _sb_refuse(sb, 'every scope entry must carry its generation bindings %s' % (gb['to'],), ident)
        for role in sorted(bs):
            b = bs[role]
            if not isinstance(b, Mapping) or b.get(gf['role']) != role or not isinstance(b.get(gf['class_key']), str):
                _sb_refuse(sb, 'generation binding %s of scope %r must name its role and a class key' % (role, ident), _rh_kind(b))
            exp.append({ef['scope']: ident, ef['class_key']: b[gf['class_key']], ef['role']: role, ef['binding_sha256']: _digest(b)})
    return {f['applicability']: ap['applies'], f['root']: root, f['commit']: commit, f['members']: members, f['expectations']: exp}


def lme_verify_source_binding(binding, resolved, registry, *, captures, admission, manifests_dir, record_blocks):
    """C1-SOURCE-BINDING-01 (codex 892: publication and verification re-derive the join independently): re-derives the
    binding from the captures, the protected admission record, the actual lme_resolved and the record blocks (required
    keyword arguments; a call without them is a TypeError) and requires the published binding to equal it type-aware.
    Returns True; raises otherwise."""
    want = lme_source_binding(resolved, registry, captures=captures, admission=admission, manifests_dir=manifests_dir,
                              record_blocks=record_blocks)
    if not _leaf_equal(binding, want):
        sb = _sb_decl(registry)[0]
        _sb_refuse(sb, 'published %s is not the binding the captures, the admission record and lme_resolved derive' % (sb['var'],),
                   sorted(binding) if isinstance(binding, Mapping) else _rh_kind(binding))
    return True


def lme_invocation_root(anchor_dir, capture_rel, explicit_root, refusal):
    """C1-INVOCATION-CONTEXT-01 L8-04 (codex 894 capture_root; SR-309-05): the ordinary capture root of the invocation
    context, computed before the global manifest is consumed. explicit_root (the lme_invocation_root input) is null or
    an absolute path in normal form below /; when given it is the root. Otherwise the root is anchor_dir (the checkout
    clone_directory names, absolute) normalized LEXICALLY (never link-resolved, never derived from an inventory
    location) joined with capture_rel, a relative path of plain segments. refusal is the declared words.refusal. Raises
    '<refusal>: ...' on any other input; never falls back."""
    import posixpath
    if not isinstance(refusal, str) or not refusal:
        raise ValueError('lme: lme_invocation_root requires the declared refusal word; got %r' % (_rh_kind(refusal),))

    def bad(what, got):
        raise ValueError('lme: %s: %s; got %r' % (refusal, what, got))
    if explicit_root is not None:
        if not isinstance(explicit_root, str) or not explicit_root.startswith('/') or explicit_root.startswith('//') \
                or explicit_root == '/' or posixpath.normpath(explicit_root) != explicit_root:
            bad('an explicit invocation root must be an absolute path in normal form below /', explicit_root)
        return explicit_root
    if not isinstance(anchor_dir, str) or not anchor_dir.startswith('/'):
        bad('the checkout anchor must be an absolute path', anchor_dir)
    # F942 / SR-319-01: capture_rel is admitted by the shared relative-path grammar _rh_safe_rel (a non-empty string,
    # not absolute, normpath-stable, no '.' or '..' component), never by a private copy of it.
    if not _rh_safe_rel(capture_rel):
        bad('capture_rel must be a relative path of plain segments', capture_rel)
    anchor = posixpath.normpath(anchor_dir)
    if anchor == '/' or anchor.startswith('//'):
        bad('the checkout anchor must name a directory below /', anchor_dir)
    return posixpath.join(anchor, capture_rel)


# C1-INVOCATION-CONTEXT-01 L8-05: the registry cluster_topology node keys, its host word roles, and the published
# field and member field keys in order (interface constants the declaration must equal).
_CT_KEYS = frozenset(('var', 'required_by_profiles', 'group', 'host_words', 'host_word_absent', 'declared_seed_word',
                      'declared_seed_forms', 'seed_endpoint', 'fields', 'member_fields', 'absent', 'refusal'))
_CT_HOST_WORDS = frozenset(('publish', 'node_name', 'initial_master'))
_CT_FIELDS = ['group', 'initial_master', 'publish_host', 'seed_hosts', 'members']
_CT_MEMBER_FIELDS = ['host', 'publish_host', 'node_name', 'initial_master']
# C1-INVOCATION-CONTEXT-01 codex 900 / SR-317-01 (supersedes SR-315-01): the host word roles that carry a declared
# absent value in host_word_absent (role -> the kind its present or declared absent value must have); every other role
# is required on every member.
_CT_ABSENT_ROLES = (('initial_master', bool),)
# codex 900 / SR-317-02 (supersedes SR-315-02): the declared seed forms (form name -> the Python kind it dispatches
# on), the option keys of the string form and the keys of a one-character bracket pair (wrapper, seed_endpoint); every
# character is read from the declaration only.
_CT_SEED_FORM_KINDS = (('list', list), ('string', str))
_CT_SEED_FORMS = frozenset(n for n, _k in _CT_SEED_FORM_KINDS)
_CT_SEED_STRING_KEYS = frozenset(('wrapper', 'separator', 'strip_chars'))
_CT_PAIR_KEYS = frozenset(('open', 'close'))


def _ct_pair_ok(p):
    """A declared bracket pair: exactly _CT_PAIR_KEYS, each one character, the two distinct."""
    return isinstance(p, Mapping) and set(p) == _CT_PAIR_KEYS \
        and all(isinstance(p[k], str) and len(p[k]) == 1 for k in _CT_PAIR_KEYS) and p['open'] != p['close']


def _ct_entry_ok(s, ep, strip_chars):
    """One seed entry under the declared seed_endpoint pair ep: a non-empty string with no strip_chars character at
    either end, at most one open and one close, the open (when present) its first character and the close after it
    with something between. Brackets inside an entry are endpoint syntax and are kept."""
    return isinstance(s, str) and len(s) > 0 and s == s.strip(strip_chars) \
        and s.count(ep['open']) == s.count(ep['close']) and s.count(ep['open']) <= 1 \
        and (ep['open'] not in s or (s.startswith(ep['open']) and s.index(ep['close']) > 1))


def _ct_seed_readings(d, sfs, ep):
    """The well-formed readings of a seed string d under the declared string form sfs: the unwrapped reading, and the
    wrapped reading when d's first character is wrapper.open and its last wrapper.close (one character removed at
    each end, only around the whole string). Each reading splits on separator and strips strip_chars from both ends of
    every entry; a reading is kept only when every entry is well formed under ep."""
    w = sfs['wrapper']
    cands = [d]
    if len(d) >= 2 and d.startswith(w['open']) and d.endswith(w['close']):
        cands.append(d[1:-1])
    readings = []
    for c in cands:
        got = [s.strip(sfs['strip_chars']) for s in c.split(sfs['separator'])]
        if all(_ct_entry_ok(s, ep, sfs['strip_chars']) for s in got):
            readings.append(got)
    return readings


def lme_cluster_topology(hostvars, groups, decl, profile):
    """C1-INVOCATION-CONTEXT-01 L8-05 (codex 896 storage_and_secrets; SR-302-15 PH-SEED-HOSTS / PH-PUBLISH-HOST;
    codex 900 SR-317-01/02, superseding SR-315-01/02): the cluster topology of registry
    remote_harness_schema.cluster_topology (decl), derived from B-declared inventory words only. decl is exactly
    _CT_KEYS with fields _CT_FIELDS, member_fields _CT_MEMBER_FIELDS, host_words roles _CT_HOST_WORDS, host_word_absent
    exactly the _CT_ABSENT_ROLES roles with values of their kinds, declared_seed_forms exactly _CT_SEED_FORMS (list
    carries no options; string carries exactly _CT_SEED_STRING_KEYS: a wrapper pair, a non-empty separator that is no
    bracket character, and a non-empty strip_chars string) and seed_endpoint a pair. When profile is not in
    required_by_profiles the result is decl absent. Otherwise: the group is declared and lists one or more distinct
    members (inventory order); every member carries the publish and node_name words (non-empty strings, each distinct
    across members); the initial_master word, when present, must be a bool (null or any other kind refuses) and when
    omitted takes the declared host_word_absent value; exactly one member is the initial master; seed_hosts = the
    members' publish values in group order; publish_host = the initial master's publish value. A member carrying
    declared_seed_word must carry exactly the seed set in one declared form, dispatched on its kind (any other kind
    refuses): an empty, duplicate, malformed or ambiguous (both string readings well formed) value refuses. No
    first-host fallback, no defaulted read. Returns the fields mapping; raises '<refusal>: ...' otherwise."""
    if not isinstance(decl, Mapping) or set(decl) != _CT_KEYS or decl['fields'] != _CT_FIELDS \
            or decl['member_fields'] != _CT_MEMBER_FIELDS or not isinstance(decl['host_words'], Mapping) \
            or set(decl['host_words']) != _CT_HOST_WORDS \
            or any(not isinstance(decl[k], str) or not decl[k] for k in ('var', 'group', 'declared_seed_word', 'refusal')) \
            or any(not isinstance(w, str) or not w for w in decl['host_words'].values()) \
            or not isinstance(decl['required_by_profiles'], list) \
            or any(not isinstance(p, str) or not p for p in decl['required_by_profiles']):
        raise ValueError('lme: registry remote_harness_schema.cluster_topology must be exactly %s with fields %s, member_fields %s and host_words %s; got %r' % (
            sorted(_CT_KEYS), _CT_FIELDS, _CT_MEMBER_FIELDS, sorted(_CT_HOST_WORDS), sorted(decl) if isinstance(decl, Mapping) else _rh_kind(decl)))
    sfm, ep, hwa = decl['declared_seed_forms'], decl['seed_endpoint'], decl['host_word_absent']
    if not isinstance(sfm, Mapping) or set(sfm) != _CT_SEED_FORMS or not isinstance(sfm['list'], Mapping) or len(sfm['list']) != 0 \
            or not isinstance(sfm['string'], Mapping) or set(sfm['string']) != _CT_SEED_STRING_KEYS \
            or not _ct_pair_ok(sfm['string']['wrapper']) or not _ct_pair_ok(ep) \
            or not isinstance(sfm['string']['separator'], str) or not sfm['string']['separator'] \
            or sfm['string']['separator'] in (ep['open'], ep['close'], sfm['string']['wrapper']['open'], sfm['string']['wrapper']['close']) \
            or not isinstance(sfm['string']['strip_chars'], str) or not sfm['string']['strip_chars']:
        raise ValueError('lme: registry remote_harness_schema.cluster_topology.declared_seed_forms must be exactly %s (list without options; string exactly %s: a one-character open / close wrapper pair, a non-empty separator that is no bracket character and a non-empty strip_chars string) and seed_endpoint a one-character open / close pair; got %r' % (
            sorted(_CT_SEED_FORMS), sorted(_CT_SEED_STRING_KEYS), [sfm, ep]))
    if not isinstance(hwa, Mapping) or set(hwa) != set(r for r, _k in _CT_ABSENT_ROLES) \
            or any(not isinstance(hwa[r], k) for r, k in _CT_ABSENT_ROLES):
        raise ValueError('lme: registry remote_harness_schema.cluster_topology.host_word_absent must be exactly the roles %s with values of their kinds; got %r' % (
            [r for r, _k in _CT_ABSENT_ROLES], hwa))
    if not isinstance(profile, str) or not profile:
        raise ValueError('lme: %s: the selected profile must be a non-empty string; got %r' % (decl['refusal'], _rh_kind(profile)))
    if profile not in decl['required_by_profiles']:
        return decl['absent']

    def bad(what, got):
        raise ValueError('lme: %s: %s; got %r' % (decl['refusal'], what, got))
    hw, f, mf, sfs = decl['host_words'], decl['fields'], decl['member_fields'], sfm['string']
    required = sorted(hw[r] for r in hw if r not in hwa)
    if not isinstance(groups, Mapping) or decl['group'] not in groups:
        bad('group %s must be declared' % (decl['group'],), _rh_kind(groups))
    members = groups[decl['group']]
    if not isinstance(members, list) or not members or any(not isinstance(h, str) or not h for h in members) \
            or len(set(members)) != len(members):
        bad('group %s must list one or more distinct members' % (decl['group'],), _rh_kind(members))
    if not isinstance(hostvars, Mapping):
        bad('hostvars must be the inventory host variables', _rh_kind(hostvars))
    rows, hvs, seen = [], {}, {'publish': set(), 'node_name': set()}
    for h in members:
        if h not in hostvars:
            bad('member %s has no host vars' % (h,), h)
        hv = hostvars[h]
        if not isinstance(hv, Mapping) or any(w not in hv for w in required):
            bad('member %s must carry every required host word %s' % (h, required), _rh_kind(hv))
        hvs[h] = hv
        vals = {}
        for role in ('publish', 'node_name'):
            v = hv[hw[role]]
            if not isinstance(v, str) or not v.strip() or v in seen[role]:
                bad('member %s must carry a non-empty %s distinct across members' % (h, hw[role]), _rh_kind(v))
            seen[role].add(v)
            vals[role] = v
        # SR-317-01: presence by membership; an omitted word takes the declared absent value; a present value (null
        # included) is checked as given and never replaced.
        if hw['initial_master'] in hv:
            im = hv[hw['initial_master']]
        else:
            im = hwa['initial_master']
        if not isinstance(im, bool):
            bad('member %s %s, when present, must be a bool' % (h, hw['initial_master']), _rh_kind(im))
        rows.append({mf[0]: h, mf[1]: vals['publish'], mf[2]: vals['node_name'], mf[3]: im})
    masters = [r for r in rows if r[mf[3]]]
    if len(masters) != 1:
        bad('exactly one member of group %s must resolve %s true (no first-host fallback)' % (decl['group'], hw['initial_master']), [r[mf[0]] for r in masters])
    seeds = [r[mf[1]] for r in rows]
    for h in members:
        if decl['declared_seed_word'] in hvs[h]:
            d = hvs[h][decl['declared_seed_word']]
            form = [n for n, k in _CT_SEED_FORM_KINDS if isinstance(d, k)]
            if len(form) != 1:
                bad('member %s %s must be one of the declared seed forms %s' % (h, decl['declared_seed_word'], sorted(_CT_SEED_FORMS)), _rh_kind(d))
            if form[0] == 'string':
                readings = _ct_seed_readings(d, sfs, ep)
                if len(readings) != 1:
                    bad('member %s %s must have exactly one well-formed reading (%d found: empty, malformed or ambiguous)' % (h, decl['declared_seed_word'], len(readings)), d)
                got = readings[0]
            else:
                got = d
                if not all(_ct_entry_ok(s, ep, sfs['strip_chars']) for s in got):
                    bad('member %s %s entries must be well-formed non-empty endpoints' % (h, decl['declared_seed_word']), d)
            if len(set(got)) != len(got) or sorted(got) != sorted(seeds):
                bad('member %s %s must be exactly the derived seed set %s without duplicates' % (h, decl['declared_seed_word'], seeds), d)
    return {f[0]: decl['group'], f[1]: masters[0][mf[0]], f[2]: masters[0][mf[1]], f[3]: seeds, f[4]: rows}


# C1-INVOCATION-CONTEXT-01 SR-320-07 (codex 902 SR-320-01; SR-320-06 G14-01): the registry
# remote_harness_schema.template_detection node keys, its start-string role keys, the reason word of an override-header
# detection (the node key itself) and the position words of a detected global position. The detection RULE is
# ansible-core 2.19.11 _jinja_bits.py is_possibly_template (:955-960, pinned in the node by_core): a string is a possible
# template when it starts with the override header or contains any start string (:134-142). The words themselves are
# declared ONCE in the global in split-character form (SR-321-04 / Codex 905: the decoding contract is the declared
# remote_harness_schema.split_character_form, which template_detection.word_form names); a declared word is decoded by
# joining its characters with that node's declared separator, which every caller passes EXPLICITLY by pointer (no
# private separator, no implicit join default), so this module carries no detection literal and no separator literal.
# SR-321-04 (Codex 904 Option A; MAIN 947): the node declares ONE shared predicate (the rule above) and its relation
# to each declared leg's own rule (predicate.relation_by_core: exact on 2.19.11, a conservative superset on 2.17), and
# per leg the pinned source identity (by_core.<core>.source_pins). The relation words are declared data, not checked
# against a literal here; their key set must be exactly the by_core key set.
_TD_KEYS = frozenset(('word_form', 'start_strings', 'override_header', 'predicate', 'by_core'))
_TD_PREDICATE_KEYS = frozenset(('consumers', 'relation_by_core'))
_TD_LEG_PINS = 'source_pins'
_TD_START_KEYS = frozenset(('block', 'variable', 'comment'))
_TD_HEADER_REASON = 'override_header'
_TD_POSITIONS = ('value', 'key')


def _td_word(chars, separator, where, bad):
    """one declared detection word: a non-empty list of one-character strings, decoded by joining them with the
    declared separator (the caller passes split_character_form.separator by pointer)"""
    if not isinstance(chars, list) or not chars or not all(isinstance(c, str) and len(c) == 1 for c in chars):
        bad('%s must be a non-empty list of one-character strings' % (where,))
    return separator.join(chars)


def _td_decl(detection, separator, refusal):
    """the validated detection words: ([(start role, word)] sorted by role, override header word)"""
    if not isinstance(refusal, str) or not refusal:
        raise ValueError('lme: template detection takes a non-empty refusal word; got %s' % (_rh_kind(refusal),))

    def bad(msg):
        raise ValueError('lme: %s: template_detection %s' % (refusal, msg))
    if not isinstance(separator, str):
        bad('decoding takes the declared split_character_form separator as a string; got %s' % (_rh_kind(separator),))
    if not isinstance(detection, dict) or set(detection) != _TD_KEYS:
        bad('must be a mapping with exactly the keys %s' % (sorted(_TD_KEYS),))
    if not isinstance(detection['word_form'], str) or not detection['word_form']:
        bad('word_form must name the declared decoding contract node')
    legs = detection['by_core']
    if not isinstance(legs, dict) or not legs or not all(isinstance(k, str) and k for k in legs):
        bad('by_core must be a non-empty mapping keyed by ansible-core version words (the per-leg detection rule)')
    for leg in sorted(legs):
        if not isinstance(legs[leg], dict) or _TD_LEG_PINS not in legs[leg]:
            bad('by_core %s must be a mapping declaring %s' % (leg, _TD_LEG_PINS))
        pins = legs[leg][_TD_LEG_PINS]
        if not isinstance(pins, dict) or not pins \
                or not all(isinstance(k, str) and k and isinstance(v, str) and v for k, v in pins.items()):
            bad('by_core %s %s must be a non-empty mapping of source paths to digests' % (leg, _TD_LEG_PINS))
    pred = detection['predicate']
    if not isinstance(pred, dict) or set(pred) != _TD_PREDICATE_KEYS:
        bad('predicate must be a mapping with exactly the keys %s' % (sorted(_TD_PREDICATE_KEYS),))
    if not isinstance(pred['consumers'], list) or not pred['consumers'] \
            or not all(isinstance(c, str) and c for c in pred['consumers']):
        bad('predicate consumers must be a non-empty list of filter names')
    rel = pred['relation_by_core']
    if not isinstance(rel, dict) or set(rel) != set(legs) or not all(isinstance(w, str) and w for w in rel.values()):
        bad('predicate relation_by_core must name one relation word for exactly the by_core legs %s' % (sorted(legs),))
    starts = detection['start_strings']
    if not isinstance(starts, dict) or set(starts) != _TD_START_KEYS:
        bad('start_strings must be a mapping with exactly the keys %s' % (sorted(_TD_START_KEYS),))
    words = [(k, _td_word(starts[k], separator, 'start_strings %s' % (k,), bad)) for k in sorted(starts)]
    if len(set(w for _, w in words)) != len(words):
        bad('start_strings must decode to distinct words')
    return words, _td_word(detection['override_header'], separator, _TD_HEADER_REASON, bad)


def _td_reasons(value, words, header):
    """the detection reasons of one value (is_possibly_template :960): the override-header reason when a string starts
    with the header, then each start role whose word it contains; [] for a non-string or an undetected string"""
    if not isinstance(value, str):
        return []
    found = [r for r in (_TD_HEADER_REASON,) if value.startswith(header)]
    return found + [k for k, w in words if w in value]


def _td_scan(v, path, words, header, out):
    reasons = _td_reasons(v, words, header)
    if reasons:
        out.append({'path': path, 'position': _TD_POSITIONS[0], 'reasons': reasons})
    if isinstance(v, dict):
        for k in v:
            key_reasons = _td_reasons(k, words, header)
            if key_reasons:
                out.append({'path': path + [k], 'position': _TD_POSITIONS[1], 'reasons': key_reasons})
            _td_scan(v[k], path + [k], words, header, out)
    elif isinstance(v, (list, tuple)):
        for i in range(len(v)):
            _td_scan(v[i], path + [i], words, header, out)


def lme_template_positions(data, detection, separator, refusal):
    """C1-INVOCATION-CONTEXT-01 SR-320-06 / codex 902 (D): the global invariant scan. data is the RAW strict parse of a
    capture (lme_manifest_strict), never a loaded fact, so no value is templated by this walk. Returns every position
    whose string value or string mapping key the declared detection rule detects, as {path: typed components (mapping
    keys as parsed, list indices as ints), position: value or key, reasons: [detection words' roles]}; [] when none.
    The declaration node itself is scanned with the rest of the data (it must pass its own invariant). separator is
    the declared split_character_form separator (SR-321-04 / Codex 905), passed by pointer; the rule applied is the ONE
    shared predicate (exact on 2.19.11, a conservative superset on 2.17)."""
    words, header = _td_decl(detection, separator, refusal)
    out = []
    _td_scan(data, [], words, header, out)
    return out


def _rpc_walk(r, f, path, str_keys, words, header, out, bad):
    kr, kf = _canonical_kind(r), _canonical_kind(f)
    if kr != kf:
        bad(path, 'raw kind %s, fact kind %s' % (kr, kf))
    if kr == 'dict':
        # keys only: iterating a mapping's keys evaluates no value
        rk = set((_canonical_kind(k), k) for k in r)
        fk = set((_canonical_kind(k), k) for k in f)
        if rk != fk:
            bad(path, 'mapping key sets differ (raw %r, fact %r)' % (sorted(rk, key=repr), sorted(fk, key=repr)))
        children = [(k, isinstance(k, str)) for k in r]
    elif kr == 'list':
        if len(r) != len(f):
            bad(path, 'sequence lengths differ (raw %d, fact %d)' % (len(r), len(f)))
        children = [(i, True) for i in range(len(r))]
    else:
        if not _leaf_equal(r, f):
            bad(path, 'the %s fact value is not the raw value' % (kr,))
        return
    for c, typed in children:
        here = path + [c]
        reasons = _td_reasons(r[c], words, header)
        if reasons:
            # a skipped position: its fact value is never read (a list is indexed per selected index, never iterated)
            if not (str_keys and typed):
                bad(here, 'a possible-template position under a non-string mapping key cannot be reported as typed path components')
            out.append({'path': here, 'reasons': reasons})
            continue
        _rpc_walk(r[c], f[c], here, str_keys and typed, words, header, out, bad)


def lme_raw_partial_correspondence(raw, fact, detection, separator, refusal):
    """C1-INVOCATION-CONTEXT-01 SR-320-07 (codex 902 SR-320-01; DEV-E12-06-PROFILE-RAW stays PARTIAL): a scoped PARTIAL
    correspondence guard between the RAW strict parse of the consumed profile capture bytes (raw; lme_manifest_strict)
    and the loaded profile fact (fact). Traversal is driven by raw: at every inspected position the kinds must match
    (_canonical_kind), a mapping must have exactly the raw key set (type-aware keys), a sequence exactly the raw length
    with each index compared in order, and a scalar must be type-aware equal (_leaf_equal). ONLY a position whose raw
    value the declared detection rule (template_detection; is_possibly_template) detects is skipped; its fact value is
    never read, every other list index and nested container is inspected, and a list is indexed per selected index.
    Returns the excluded positions as [{path: typed components (mapping keys as strings, list indices as ints),
    reasons: [detection roles]}]; refuses with refusal otherwise. NOT a full binding (OW-C1-FULL-BYTE-BINDING): the
    skipped values and kinds are not established, and a template substituted at a raw non-template position may
    evaluate to the expected value and pass. Per-leg limits (SR-321-04): on 2.19 the fact arrives lazily and a skipped
    position's fact value is never read here; on 2.17 the caller's variable reference has already rendered the whole
    fact recursively, so this filter receives a rendered copy and only non-template positions are compared. Neither leg
    protects the later profile_overlay.lme_global compositions of resolve.yml, which read every overlay value."""
    words, header = _td_decl(detection, separator, refusal)

    def bad(path, msg):
        raise ValueError('lme: %s: (SR-320-07 raw-guided PARTIAL correspondence) at %r: %s' % (refusal, path, msg))
    if _td_reasons(raw, words, header):
        bad([], 'the raw root is a possible template')
    out = []
    _rpc_walk(raw, fact, [], True, words, header, out, bad)
    return out


def lme_capture_text_bound(text, expected_checksum, algorithm, encoding, refusal):
    """C1-INVOCATION-CONTEXT-01 SR-321-01 (seat SEAT-W2C-01): binds ONE read of a capture's exact text to the capture
    stat checksum before anything parses or guards it. text is the exact text of that read (a file lookup with nothing
    stripped); expected_checksum the registered capture stat checksum; algorithm the digest algorithm word that stat
    used (lme_invocation_words.digest_algorithm, which SR-320-04 / E12-05 bind to profile_identity.digest_algorithm);
    encoding the declared profile_identity.encoding; refusal the declared profile_identity.refusal. The digest of text
    encoded by encoding must equal expected_checksum. Returns text unchanged (the same object, so the chain that follows
    consumes exactly the bound read); raises '<refusal>: ...' otherwise. It narrows, and does not close,
    OW-C1-FULL-BYTE-BINDING: the native include_vars load still reads the capture separately."""
    if not isinstance(refusal, str) or not refusal:
        raise ValueError('lme: lme_capture_text_bound requires the declared refusal word; got %s' % (_rh_kind(refusal),))

    def bad(what, got):
        raise ValueError('lme: %s: (SR-321-01 capture text binding) %s; got %r' % (refusal, what, got))
    if not isinstance(algorithm, str) or algorithm not in hashlib.algorithms_guaranteed:
        bad('the digest algorithm must be a guaranteed hashlib algorithm word', algorithm)
    if not isinstance(encoding, str) or not encoding:
        bad('the declared encoding must be a non-empty string', _rh_kind(encoding))
    if not isinstance(expected_checksum, str) or not expected_checksum:
        bad('the capture stat checksum must be a non-empty string', _rh_kind(expected_checksum))
    if not isinstance(text, str):
        bad('the capture text must be a string', _rh_kind(text))
    try:
        got = hashlib.new(algorithm, text.encode(encoding)).hexdigest()
    except (LookupError, UnicodeError, TypeError) as exc:
        bad('the capture text cannot be digested by the declared algorithm under the declared encoding', type(exc).__name__)
    if got != expected_checksum:
        bad('the %s digest of the exact capture text read here is not the capture stat checksum' % (algorithm,), [got, expected_checksum])
    return text


def lme_doc_admit_text(text, parse, rel):
    """records-dk03-launch-01 (codex-tick764 / 765 DK03 option A): the narrow adapter of the first-entry ingress guard
    (templates/registry_ingress.j2 and its macro). text: the ONE captured text (the ingress declaration; the registry
    text after its digest equals the admitted identity); parse: the document_channel.parse contract carried by the
    admitted launch record (rh_source_bootstrap.context); rel: the admitted repository-relative identity for the
    diagnostic. It runs the SAME DK03 parser as the document channel -- _rh_doc_parse_decl (shape and parser role
    binding, before the text is read), _rh_yaml_load_unique, _rh_doc_parse_text -- and raises the declared text outside
    any handler. No second parser, no manifest reload, no resolve.
    C1-SR323-J-INGRESS-FILTER (G first-operation-03 J-INGRESS-FILTER): restored unchanged from the C1 s-lineage L
    (s11 d97ac55e :7997-8012) -- the r-lineage L dropped it while registry_ingress.j2 :10 (bc1b631c) and the ingress
    macro (s12 :56) still call it; its three helpers are byte-identical in this L."""
    _rh_doc_parse_decl(parse)
    if not isinstance(text, str) or not isinstance(rel, str) or not rel:
        raise ValueError('lme: lme_doc_admit_text takes the captured text and a non-empty admitted rel; got %s / %s' % (
            type(text).__name__, type(rel).__name__))
    parsed, failure = _rh_yaml_load_unique(text, parse['tags'])
    if failure:
        raise ValueError('lme: %s' % (_rh_doc_parse_text(parse, rel, failure),))
    return parsed


def _lme_ev_refusal(adm, reason, ordinal=None, name=None):
    node, code = adm
    fmt = node['parser']['diagnostics']
    fields = fmt['fields']
    metadata = {fields['refusal']: code, fields['ordinal']: ordinal, fields['name']: name}
    shown = [fmt['metadata'].format(key=k, value=metadata[k])
             for k in node['diagnostics']['allow'] if k in metadata and metadata[k] is not None]
    return ValueError(fmt['format'].format(code=code, text=node['texts'][reason],
                                         metadata=fmt['separator'].join(shown)))


def _lme_ev_admission(node, policy):
    """Bind the declared parser to the current generation before examining caller data."""
    from ansible.release import __version__ as running_core
    from ansible.parsing.vault import VaultSecretsContext
    failed = False
    try:
        references = [node['arg_flags_from'], node['refusal_from'],
                      *node['toolchain'].values(), node['file']['path_rule_from'],
                      node['file']['retain_impl_from'], *node['file']['roots_from']]
        if not all(isinstance(p, str) and p and _rh_get(policy, p)[0] for p in references):
            raise ValueError()
        code = _rh_get(policy, node['refusal_from'])[1]
        adm = (node, code)
        parser = node['parser']
        if (not isinstance(code, str) or not code
                or _rh_get(policy, node['toolchain']['core_from'])[1] != running_core
                or not _rec_int(parser['ordinal_start']) or parser['ordinal_start'] != 1
                or parser['binding'] != 'pinned_ansible'
                or parser['duplicate_keys'] != 'refuse_within_argument'
                or parser['non_string_keys'] != 'refuse_at_every_depth'
                or parser['merge_collisions'] != 'refuse' or parser['recursive_aliases'] != 'refuse'):
            raise ValueError()
        # This is a binding to the pinned Ansible dispatch, never a configurable alternative grammar.
        if (parser['syntax'] != {'file_prefix': '@', 'bare_path_prefixes': ['/', '.'],
                                 'mapping_prefixes': ['[', '{'], 'raw_params': '_raw_params'}
                or parser['encoding'] != 'utf-8' or parser['decode_errors'] != ['strict', 'surrogateescape']
                or parser['path']['separator'] != '/' or parser['path']['forbidden_segments'] != ['', '.', '..']):
            raise ValueError()
        _rh_yaml_roles_bound(parser['tags'])
        for dotted in node['protected_name_sources']['policy_scalar_paths']:
            found, name = _rh_get(policy, dotted)
            if not found or not isinstance(name, str) or not name:
                raise ValueError()
        for dotted in node['protected_name_sources']['policy_glob_paths']:
            found, names = _rh_get(policy, dotted)
            if not found or not isinstance(names, list) or not all(isinstance(n, str) and n for n in names):
                raise ValueError()
        # Check diagnostic construction without ever carrying caller content into an error.
        _lme_ev_refusal(adm, 'configuration')
    except Exception:
        failed = True
    if failed:
        try:
            refusal = _lme_ev_refusal((node, _rh_get(policy, node['refusal_from'])[1]), 'configuration')
        except Exception:
            refusal = ValueError()
        raise refusal
    context = VaultSecretsContext.current(optional=True)
    if context is not None and context.secrets:
        raise _lme_ev_refusal(adm, 'vault_variant')
    return adm


def _lme_ev_values(values, adm):
    node, _ = adm
    parser = node['parser']
    kinds, syntax = parser['kinds'], parser['syntax']
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise _lme_ev_refusal(adm, 'configuration')
    dispatched = []
    for ordinal, value in enumerate(values, start=parser['ordinal_start']):
        if not value:
            kind, payload = kinds['skip'], value
        elif value.startswith(syntax['file_prefix']):
            kind, payload = kinds['file'], value[len(syntax['file_prefix']):]
        elif value.startswith(tuple(syntax['bare_path_prefixes'])):
            kind, payload = kinds['bare_path'], value
        elif value.startswith(tuple(syntax['mapping_prefixes'])):
            kind, payload = kinds['mapping'], value
        else:
            kind, payload = kinds['kv'], value
        dispatched.append((ordinal, kind, payload))
    return dispatched


def _lme_ev_mapping_check(payload, parser):
    """Check authored keys before pinned construction can collapse or display them.

    JSON uses its own key semantics first, just as Ansible from_yaml does. YAML
    keys are constructed by an instance of the pinned Ansible loader. Values,
    including lazy vault values, are left to DataLoader.load after this check.
    No global parser, constructor, config or display state is changed.
    """
    from ansible.parsing.yaml.loader import AnsibleLoader
    from ansible._internal._json._profiles import _legacy
    import yaml

    def pairs(items):
        result = {}
        for key, value in items:
            if not isinstance(key, str) or key in result:
                raise ValueError()
            result[key] = value
        return result

    # A syntax failure may be YAML. A duplicate-key failure must not fall back.
    try:
        json.loads(payload, cls=_legacy.Decoder, object_pairs_hook=pairs)
        return
    except json.JSONDecodeError:
        pass
    loader = AnsibleLoader(payload)
    try:
        root = loader.get_single_node()
        visited, active = set(), set()

        def visit(current):
            if id(current) in active:
                raise ValueError()
            if id(current) in visited:
                return
            active.add(id(current))
            if isinstance(current, yaml.MappingNode):
                if sum(key.tag == parser['tags']['merge']['tag'] for key, _ in current.value) > 1:
                    raise ValueError()
                for key, value in current.value:
                    visit(key)
                    visit(value)
                # Flatten using the pinned implementation, then reject collisions,
                # including merge collisions, before its warning-producing constructor.
                loader.flatten_mapping(current)
                seen = set()
                for key, _ in current.value:
                    if not isinstance(key, yaml.ScalarNode):
                        raise ValueError()
                    # Vault keys would decrypt during hashing; never construct one.
                    if key.tag not in loader.yaml_constructors:
                        raise ValueError()
                    if loader.yaml_constructors[key.tag] == loader.construct_yaml_vault.__func__:
                        raise ValueError()
                    name = loader.construct_object(key)
                    if not isinstance(name, str) or name in seen:
                        raise ValueError()
                    seen.add(name)
            elif isinstance(current, yaml.SequenceNode):
                for child in current.value:
                    visit(child)
            active.remove(id(current))
            visited.add(id(current))

        visit(root)
    finally:
        loader.dispose()


def _lme_ev_parse(payload, kind, parser):
    from ansible.parsing.dataloader import DataLoader
    from ansible.parsing.splitter import parse_kv, split_args
    if kind == parser['kinds']['kv']:
        seen, raw = set(), False
        for token in split_args(payload):
            parsed = parse_kv(token)
            keys = set(parsed)
            raw_key = parser['syntax']['raw_params']
            if raw_key in keys and parse_kv(token, check_raw=True) == parsed:
                keys.remove(raw_key)
                raw = True
            if seen.intersection(keys):
                raise ValueError()
            seen.update(keys)
        if raw and parser['syntax']['raw_params'] in seen:
            raise ValueError()
        data = parse_kv(payload)
    else:
        _lme_ev_mapping_check(payload, parser)
        data = DataLoader().load(payload, show_content=False)
    if not isinstance(data, Mapping) or not all(isinstance(key, str) for key in data):
        raise ValueError()
    return data


def _lme_ev_retained_bytes(path, digest, node, policy, ordinal):
    """Read only the retained bytes; every path component is opened without following links."""
    import os
    import stat
    parser = node['parser']
    separator = parser['path']['separator']
    if not isinstance(path, str) or not isinstance(digest, str) or not os.path.isabs(path) or os.path.normpath(path) != path:
        return None
    parts = path.split(separator)[1:]
    suffix = node['file']['snapshot']['rel'].replace(node['file']['placeholders']['ordinal'], str(ordinal))
    if not parts or any(p in parser['path']['forbidden_segments'] for p in parts) or not path.endswith(separator + suffix):
        return None
    rule = _rh_get(policy, node['file']['path_rule_from'])[1]
    if not re.fullmatch(rule['regex'], path) or re.search(rule['forbidden_segment_regex'], path):
        return None
    failed, data, parent_fd = False, None, None
    try:
        parent_fd = os.open(separator, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in parts[:-1]:
            child_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        with os.fdopen(fd, 'rb') as held:
            observed = os.fstat(held.fileno())
            if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != os.getuid()
                    or stat.S_IMODE(observed.st_mode) != int(node['file']['snapshot']['mode'], 8)):
                failed = True
            else:
                data = held.read()
    except (OSError, ValueError):
        failed = True
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
    algorithm = _rh_get(policy, node['file']['retain_impl_from'])[1]['fixed']['digest']
    if failed or data is None or hashlib.new(algorithm, data).hexdigest() != digest:
        return None
    return data


def lme_extra_var_files(values, node, policy):
    """Return the existing route's ordered ordinal/path carrier; install nothing."""
    adm = _lme_ev_admission(node, policy)
    kinds = node['parser']['kinds']
    ordinal_key, path_key, _ = node['file']['snapshot_record']
    out = []
    for ordinal, kind, payload in _lme_ev_values(values, adm):
        if kind == kinds['bare_path']:
            raise _lme_ev_refusal(adm, 'parse', ordinal)
        if kind == kinds['file']:
            if not payload:
                raise _lme_ev_refusal(adm, 'file_kind', ordinal)
            out.append({ordinal_key: ordinal, path_key: payload})
    return out


def lme_extra_var_admit(values, node, policy, protected, snapshots):
    """Admit argument ordinals only; Ansible retains final merge and override ownership."""
    import fnmatch
    from ansible.parsing.vault import is_encrypted
    from ansible._internal._display_utils import DeferredWarningContext
    adm = _lme_ev_admission(node, policy)
    if not isinstance(protected, list) or not protected or not all(isinstance(p, str) and p for p in protected):
        raise _lme_ev_refusal(adm, 'configuration')
    protected = set(protected)
    sources = node['protected_name_sources']
    protected.update(_rh_get(policy, dotted)[1] for dotted in sources['policy_scalar_paths'])
    globs = [name for dotted in sources['policy_glob_paths'] for name in _rh_get(policy, dotted)[1]]
    parser, kinds = node['parser'], node['parser']['kinds']
    dispatched = _lme_ev_values(values, adm)
    ordinal_key, path_key, digest_key = node['file']['snapshot_record']
    if not isinstance(snapshots, list) or not all(
            isinstance(s, Mapping) and set(s) == set(node['file']['snapshot_record'])
            and _rec_int(s[ordinal_key]) for s in snapshots):
        raise _lme_ev_refusal(adm, 'configuration')
    held = {s[ordinal_key]: s for s in snapshots}
    files = {o for o, kind, _ in dispatched if kind == kinds['file']}
    if len(held) != len(snapshots) or set(held) != files:
        raise _lme_ev_refusal(adm, 'configuration')
    admitted = []
    for ordinal, kind, payload in dispatched:
        if kind == kinds['skip']:
            continue
        if kind == kinds['bare_path']:
            raise _lme_ev_refusal(adm, 'parse', ordinal)
        if kind == kinds['file']:
            snap = held[ordinal]
            payload = _lme_ev_retained_bytes(snap[path_key], snap[digest_key], node, policy, ordinal)
            if payload is None:
                raise _lme_ev_refusal(adm, 'file_snapshot', ordinal)
            if is_encrypted(payload):
                raise _lme_ev_refusal(adm, 'vault_file', ordinal)
            try:
                payload = payload.decode(parser['encoding'], errors=parser['decode_errors'][0])
            except UnicodeDecodeError:
                payload = payload.decode(parser['encoding'], errors=parser['decode_errors'][1])
        failed, hit = False, None
        try:
            # Parser warnings can include source values even when exceptions are
            # redacted. Keep them in this invocation-local context, never in the
            # outer Ansible task result or display singleton.
            with DeferredWarningContext(variables={}):
                data = _lme_ev_parse(payload, kind, parser)
            for key in data:
                if key in protected or any(fnmatch.fnmatchcase(key, pattern) for pattern in globs):
                    # Only a declaration-owned exact name may appear in diagnostics.
                    hit = key if key in protected else None
                    failed = 'protected'
                    break
        except Exception:
            failed = 'parse'
        # Raise after the handler: no parser exception, source, value or chained context escapes.
        if failed:
            raise _lme_ev_refusal(adm, failed, ordinal, hit)
        admitted.append(ordinal)
    return admitted


class FilterModule(object):
    def filters(self):
        return {
            'lme_extra_var_files': lme_extra_var_files,
            'lme_extra_var_admit': lme_extra_var_admit,
            'strict_enable_bool': strict_enable_bool,
            'lme_service_typed_inputs': lme_service_typed_inputs,
            'lme_project_remote_harness': lme_project_remote_harness,
            'lme_remote_harness_overridden_paths': lme_remote_harness_overridden_paths,
            'lme_verify_resolved': lme_verify_resolved,
            'lme_verify_resolved_structure': lme_verify_resolved_structure,
            'lme_invocation_root': lme_invocation_root,
            'lme_cluster_topology': lme_cluster_topology,
            'lme_template_positions': lme_template_positions,
            'lme_raw_partial_correspondence': lme_raw_partial_correspondence,
            'lme_capture_text_bound': lme_capture_text_bound,
            'lme_rh_documents_active': lme_rh_documents_active,
            'lme_rh_document_plan': lme_rh_document_plan,
            'lme_rh_document_next_rel': lme_rh_document_next_rel,
            'lme_rh_document_append': lme_rh_document_append,
            'lme_rh_connection_values': lme_rh_connection_values,
            'lme_rh_proxy_outcome': lme_rh_proxy_outcome,
            'lme_admit_record': lme_admit_record,
            'lme_render_record': lme_render_record,
            'lme_manifest_strict': lme_manifest_strict,
            'lme_doc_admit_text': lme_doc_admit_text,   # records-dk03-launch-01: the sole DK03 guard adapter (C1-SR323 restored)
            'lme_source_binding': lme_source_binding,
            'lme_verify_source_binding': lme_verify_source_binding,
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
