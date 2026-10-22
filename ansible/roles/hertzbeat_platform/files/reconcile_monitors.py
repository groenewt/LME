#!/usr/bin/env python3
"""Reconcile inventory-owned native monitors over verified HTTPS; never log payloads."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import ssl
import sys
import urllib.parse
import urllib.request
import uuid


MANAGED_APPS = frozenset({'linux', 'postgresql', 'http', 'https', 'jvm', 'mysql', 'redis',
                          'elasticsearch', 'lme-service-ssh', 'lme-elasticsearch-rest',
                          'lme-elasticsearch-jmx'})


def validated_run_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value):
        raise ValueError('explicit run identity required')
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("redirect rejected")


def private_text(path):
    file = Path(path)
    if not file.is_file() or file.stat().st_mode & 0o077:
        raise ValueError("runtime secret requires owner-only regular file")
    return file.read_text().strip()


def prepare(specification, run_id):
    """Validate every desired monitor before making the first API mutation."""
    run_id = validated_run_id(run_id)
    result = []
    identities = set()
    for entry in specification:
        identity = str(uuid.UUID(entry['service_id']))
        revision = str(uuid.UUID(entry['revision']))
        if identity in identities:
            raise ValueError("duplicate managed monitor identity")
        identities.add(identity)
        dto = copy.deepcopy(entry['definition'])
        monitor = dto['monitor']
        # Collector ownership is resolved upstream. Explicit allowlist excludes Windows sources.
        if monitor['app'] not in MANAGED_APPS:
            raise ValueError("unsupported native collector family")
        if type(monitor.get('intervals')) is not int or monitor['intervals'] < 10:
            raise ValueError("invalid collector interval")
        monitor.setdefault('labels', {}).update({'lme.managed': 'true', 'lme.service_id': identity,
                                               'lme.revision': revision, 'lme.run_id': run_id})
        params = dto['params']
        for param in params:
            if 'secret_file' in param:
                param['paramValue'] = private_text(param.pop('secret_file'))
                param['type'] = 2
        values = {param['field']: param.get('paramValue') for param in params}
        if monitor['app'] in {'jvm', 'https', 'lme-elasticsearch-rest', 'lme-elasticsearch-jmx'} and values.get('ssl') != 'true':
            raise ValueError("secure collector requires explicit ssl=true")
        if monitor['app'] in {'jvm', 'lme-elasticsearch-jmx'} and not (values.get('username') and values.get('password')):
            raise ValueError("JMX authentication required")
        if monitor['app'] == 'lme-service-ssh':
            if not (values.get('username') and values.get('privateKey')):
                raise ValueError("SSH public key authentication required")
            uuid.UUID(values['serviceToken'])
        result.append(dto)
    return result


def reconcile(desired, request, apply=False, *, run_id):
    run_id = validated_run_id(run_id)
    for dto in desired:
        if dto['monitor']['labels'].get('lme.run_id') != run_id:
            raise ValueError("desired monitor belongs to another run")
    counters = {'created': 0, 'updated': 0, 'unchanged': 0, 'deleted': 0}
    existing = {}
    # Query all supported families, including families removed from the desired set.
    for app in sorted(MANAGED_APPS):
        for monitor in request('GET', '/api/monitors/' + urllib.parse.quote(app)):
            labels = monitor.get('labels') or {}
            if labels.get('lme.managed') != 'true' or labels.get('lme.run_id') != run_id:
                continue
            identity = str(uuid.UUID(labels.get('lme.service_id')))
            if type(monitor.get('id')) is not int or monitor['id'] <= 0:
                raise ValueError('invalid owned monitor ID')
            if identity in existing:
                raise ValueError("duplicate existing managed monitor identity")
            existing[identity] = monitor
    for dto in desired:
        monitor = dto['monitor']
        prior = existing.get(monitor['labels']['lme.service_id'])
        # Credentials are masked by the API; an inventory revision explicitly signals rotation.
        if prior and all(prior.get(key) == value for key, value in monitor.items() if key != 'id'):
            counters['unchanged'] += 1
            continue
        operation = 'updated' if prior else 'created'
        if apply:
            payload = copy.deepcopy(dto)
            if prior:
                payload['monitor']['id'] = prior['id']
            request('PUT' if prior else 'POST', '/api/monitor', payload)
        counters[operation] += 1
    # Delete only after all desired writes succeeded. Re-read ownership immediately
    # before deletion so a changed catalogue entry cannot be removed using stale labels.
    identities = {dto['monitor']['labels']['lme.service_id'] for dto in desired}
    for identity in sorted(existing.keys() - identities):
        prior = existing[identity]
        if apply:
            current = request('GET', '/api/monitor/' + str(prior['id']))['monitor']
            labels = current.get('labels') or {}
            if current.get('id') != prior['id'] or any(labels.get(key) != value for key, value in {
                    'lme.managed': 'true', 'lme.run_id': run_id, 'lme.service_id': identity}.items()):
                raise ValueError('stale monitor ownership changed')
            request('DELETE', '/api/monitor/' + str(prior['id']))
        counters['deleted'] += 1
    return counters


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--ca-file', required=True)
    auth = parser.add_mutually_exclusive_group(required=True)
    auth.add_argument('--token-file')
    auth.add_argument('--authorization-file')
    parser.add_argument('--allow-loopback', action='store_true')
    parser.add_argument('--desired-file', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    url = urllib.parse.urlsplit(args.url)
    local = args.allow_loopback and url.scheme == 'http' and url.hostname in {'127.0.0.1', '::1'}
    if (url.scheme != 'https' and not local) or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("verified HTTPS API origin required")
    authorization = private_text(args.authorization_file) if args.authorization_file else 'Bearer ' + private_text(args.token_file)
    if not authorization or '\n' in authorization or '\r' in authorization:
        raise ValueError("invalid runtime authorization")
    desired = prepare(json.loads(Path(args.desired_file).read_text()), args.run_id)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(
        context=ssl.create_default_context(cafile=args.ca_file)), NoRedirect())

    def request(method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(args.url.rstrip('/') + path, data=body, method=method,
                                     headers={'Authorization': authorization, 'Content-Type': 'application/json'})
        with opener.open(req, timeout=30) as response:
            document = json.load(response)
        if document.get('code') != 0:
            raise ValueError("HertzBeat API rejected operation")
        return document.get('data')

    print(json.dumps({'apply': args.apply, **reconcile(desired, request, args.apply, run_id=args.run_id)}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Exception strings and HTTP bodies can include URLs, credentials or monitor labels.
        print('monitor reconciliation failed: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
