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
    mode = userns.get('mode', 'auto')
    if mode == 'share_with':
        return 'container:lme-%s' % userns['service']
    if mode == 'auto_unpinned':
        return 'auto'
    # mode == auto (pinned id-mapping)
    base = _slot_base(userns.get('slot'), lme_global)
    size = int(lme_global['slot_size'])
    return 'auto:uidmapping=0:%d:%d,gidmapping=0:%d:%d' % (base, size, base, size)


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


def is_enabled(enabled_when, flags=None):
    """True iff every flag in enabled_when is truthy in `flags`. The sentinel
    'always' is a no-op (an always-on unit), NOT a variable lookup -- so
    enabled_when:[always] renders, and an empty/omitted list also renders."""
    flags = flags or {}
    if not enabled_when:
        return True
    for f in enabled_when:
        if f == 'always':
            continue
        if not flags.get(f, False):
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


class FilterModule(object):
    def filters(self):
        return {
            'render_userns': render_userns,
            'userns_base': userns_base,
            'cert_owner': cert_owner,
            'svc_unit': svc_unit,
            'unit_refs': unit_refs,
            'wanted_by': wanted_by,
            'render_port': render_port,
            'render_volume': render_volume,
            'podman_args': podman_args,
            'is_enabled': is_enabled,
            'jvm_opts': jvm_opts,
            'mem_derive': mem_derive,
        }
