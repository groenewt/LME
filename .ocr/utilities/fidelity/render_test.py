#!/usr/bin/env python3
import sys, os, glob, yaml
sys.path.insert(0, '/home/tristan/gitters/LME/ansible/roles/podman/filter_plugins')
import lme_manifests as F
from jinja2 import Environment, FileSystemLoader

ROOT = '/home/tristan/gitters/LME'
TPL = os.path.join(ROOT, 'ansible/templates/units')

def combine(a, b, recursive=True):
    """Mimic ansible combine(recursive=True): dicts merge, everything else (incl lists) replaced."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return b
    out = dict(a)
    for k, v in b.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict) and recursive:
            out[k] = combine(out[k], v, recursive)
        else:
            out[k] = v
    return out

glob_data = yaml.safe_load(open(os.path.join(ROOT, 'manifests/global.yml')))['lme_global']

def load_profile(name):
    p = yaml.safe_load(open(os.path.join(ROOT, f'manifests/profiles/{name}.yml')))
    return p['profile_overlay']

def build_services(profile_name):
    prof = load_profile(profile_name)
    lme_global = combine(glob_data, prof.get('lme_global') or {})
    services = {}
    kinds = {}
    for f in sorted(glob.glob(os.path.join(ROOT, 'manifests/services/*.yml'))):
        s = yaml.safe_load(open(f))
        sid = s['id']
        s = combine(s, (prof.get('services') or {}).get(sid, {}))
        services[sid] = s
        kinds[sid] = s['kind']
    return lme_global, services, kinds, prof.get('vars', {})

env = Environment(loader=FileSystemLoader(TPL), trim_blocks=True, lstrip_blocks=True,
                  keep_trailing_newline=True)
env.filters.update(F.FilterModule().filters())

def render(sid, profile='default', flags=None):
    lme_global, services, kinds, pvars = build_services(profile)
    svc = services[sid]
    tpl = env.get_template(f"{svc['kind']}.j2")
    return tpl.render(service=svc, lme_global=lme_global, kinds=kinds, flags=flags or {})

if __name__ == '__main__':
    which = sys.argv[1] if len(sys.argv) > 1 else 'elasticsearch'
    profile = sys.argv[2] if len(sys.argv) > 2 else 'default'
    print(render(which, profile))
