#!/usr/bin/env python3
"""Invoke native HertzBeat detection for explicitly owned, deployed monitor IDs."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import time
from urllib.parse import urlsplit
from uuid import UUID


TEMPLATES = {
    'lme-service-ssh': 'e8a05d726933ed66dbb54ae8ba3a001b9cd5212c88344bb0a3e06c81809a5cad',
    'lme-elasticsearch-rest': 'd8f31eaad6263dd4974d85f17b2d4b9ba68aa6eed8320b536dc1dd482db2be7c',
    'lme-elasticsearch-jmx': '5eca036dc910f1bae06423930743f9e4d3ce872f3cd521732224b9bb63fe3d17',
}
GROUPS = {'lme-service-ssh': 'service_status', 'lme-elasticsearch-rest': 'cluster_health',
          'lme-elasticsearch-jmx': 'threads'}
MAX_BODY = 1024 * 1024


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key')
        value[key] = item
    return value


def private_text(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise ValueError('authorization requires an owner-only regular file')
        value = stream.read(16385)
    if len(value) > 16384:
        raise ValueError('authorization exceeds bound')
    text = value.decode().strip()
    if not text.startswith(('Basic ', 'Bearer ')) or '\r' in text or '\n' in text:
        raise ValueError('invalid authorization')
    return text


class NativeApi:
    def __init__(self, settings, deadline):
        origin = urlsplit(settings['origin'])
        if (origin.scheme != 'https' or not origin.hostname or origin.username or origin.password
                or origin.path not in ('', '/') or origin.query or origin.fragment):
            raise ValueError('verified HTTPS origin required')
        self.host, self.port = origin.hostname, origin.port or 443
        self.context = ssl.create_default_context(cafile=settings['ca_file'])
        self.authorization = private_text(settings['authorization_file'])
        self.deadline = deadline

    def request(self, method, path, value=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('native probe deadline exceeded')
        body = None if value is None else json.dumps(value, allow_nan=False).encode()
        if body is not None and len(body) > MAX_BODY:
            raise ValueError('native request exceeds bound')
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.context,
                                          timeout=min(30, remaining))
        try:
            conn.request(method, path, body=body,
                         headers={'Authorization': self.authorization, 'Content-Type': 'application/json'})
            tls = {'version': conn.sock.version(), 'cipher': conn.sock.cipher()[0],
                   'peer_certificate_sha256': hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()}
            response = conn.getresponse()
            if response.getheader('Content-Encoding') not in (None, 'identity'):
                raise ValueError('encoded native response rejected')
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                raise ValueError('native response exceeds bound')
            document = json.loads(raw, object_pairs_hook=unique)
            if not isinstance(document, dict) or type(document.get('code')) is not int:
                raise ValueError('invalid native response')
            return response.status, document, tls
        finally:
            conn.close()


def validate_config(config):
    if not isinstance(config, dict) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', config.get('run_id', '')):
        raise ValueError('run identity required')
    monitors = config.get('monitors')
    if not isinstance(monitors, list) or not 1 <= len(monitors) <= 128:
        raise ValueError('bounded nonempty monitor roster required')
    identities = set()
    for expected in monitors:
        if not isinstance(expected, dict) or type(expected.get('id')) is not int or not 0 < expected['id'] < 2**63:
            raise ValueError('exact native monitor ID required')
        if expected['id'] in identities:
            raise ValueError('duplicate monitor ID')
        identities.add(expected['id'])
        UUID(expected['service_id']); UUID(expected['revision'])
        if expected.get('app') not in TEMPLATES or not re.fullmatch(r'(physical|guest):(graph|trixie|silmaril)', expected.get('source_id', '')):
            raise ValueError('monitor is outside approved native source families')
        if not re.fullmatch(r'[A-Za-z0-9.-]+', expected.get('host', '')):
            raise ValueError('exact native target required')
        ports = {'lme-service-ssh': {22, 2223}, 'lme-elasticsearch-rest': {9200}, 'lme-elasticsearch-jmx': {19010}}
        if type(expected.get('port')) is not int or expected['port'] not in ports[expected['app']]:
            raise ValueError('native target port is not approved')
        if expected['app'] != 'lme-service-ssh' and expected['source_id'] != 'guest:graph':
            raise ValueError('Elasticsearch probes require the exact placed guest')
        if expected['app'] == 'lme-service-ssh':
            UUID(expected['service_token'])
        outcome = expected.get('expect', 'detect_success')
        if outcome not in ('detect_success', 'detect_failed'):
            raise ValueError('unsupported expected native outcome')
        if outcome == 'detect_failed' and expected.get('failure_category') not in (
                'ssh_host_key', 'certificate', 'hostname', 'authentication'):
            raise ValueError('negative transport fixture requires an explicit failure category')
    return monitors


def check_monitor(dto, expected, run_id):
    if not isinstance(dto, dict) or not isinstance(dto.get('monitor'), dict) or not isinstance(dto.get('params'), list):
        raise ValueError('native monitor DTO missing')
    monitor = dto['monitor']
    labels = monitor.get('labels') or {}
    if (monitor.get('id') != expected['id'] or monitor.get('app') != expected['app']
            or labels.get('lme.run_id') != run_id or labels.get('lme.managed') != 'true' or labels.get('lme.service_id') != expected['service_id']
            or labels.get('lme.revision') != expected['revision'] or labels.get('host.name') != expected['source_id']):
        raise ValueError('native monitor ownership or source differs')
    params = {}
    for param in dto['params']:
        if not isinstance(param, dict) or not isinstance(param.get('field'), str) or param['field'] in params:
            raise ValueError('invalid native parameter projection')
        params[param['field']] = param.get('paramValue')
    if params.get('host') != expected['host'] or str(params.get('port')) != str(expected['port']):
        raise ValueError('native monitor destination differs')
    if not params.get('username'):
        raise ValueError('native authentication principal is absent')
    if expected['app'] == 'lme-service-ssh':
        if params.get('serviceToken') != expected['service_token'] or not params.get('privateKey'):
            raise ValueError('forced-command identity or SSH credential absent')
    elif not params.get('password'):
        raise ValueError('native authentication credential is absent')
    if params.get('ssl') not in (None, 'true', True):
        raise ValueError('native transport downgrade requested')
    # Send back the unmodified stored destination and masked secret parameters. Native
    # validate(dto, null) restores those credentials only for the matching persisted ID.
    return {'monitor': monitor, 'params': dto['params'], 'collector': dto.get('collector')}


def failure_category(message):
    text = message.lower() if isinstance(message, str) else ''
    for category, markers in (
            ('ssh_host_key', ('host key', 'server key', 'known_hosts', 'known hosts')),
            ('hostname', ('subject alternative', 'hostname', 'no name matching')),
            ('certificate', ('pkix', 'certificate', 'sslhandshake', 'tls handshake', 'unknown_ca', 'bad_certificate')),
            ('authentication', ('authentication', 'credentials', 'auth fail', 'password', 'access denied')),
            ('timeout', ('timeout', 'timed out'))):
        if any(marker in text for marker in markers):
            return category
    return 'other'


def run(config):
    monitors = validate_config(config)
    seconds = config.get('deadline_seconds', 300)
    if type(seconds) is not int or not 1 <= seconds <= 600:
        raise ValueError('bounded deadline required')
    api = NativeApi(config['api'], time.monotonic() + seconds)
    started = time.time_ns() // 1_000_000
    templates, requests = {}, []
    # Resolve and verify every ID/template before starting a transient collection.
    for expected in monitors:
        app = expected['app']
        if app not in templates:
            status, document, _ = api.request('GET', '/api/apps/' + app + '/define/yml')
            if status != 200 or document['code'] != 0 or not isinstance(document.get('data'), str):
                raise ValueError('native template retrieval failed')
            digest = hashlib.sha256(document['data'].encode()).hexdigest()
            if digest != TEMPLATES[app]:
                raise ValueError('deployed native template differs from qualified source')
            templates[app] = digest
        status, document, _ = api.request('GET', '/api/monitor/' + str(expected['id']))
        if status != 200 or document['code'] != 0:
            raise ValueError('native monitor retrieval failed')
        requests.append((expected, check_monitor(document.get('data'), expected, config['run_id'])))
    results = []
    for expected, dto in requests:
        begin = time.time_ns() // 1_000_000
        status, document, tls = api.request('POST', '/api/monitor/detect', dto)
        code = document['code']
        success = status == 200 and code == 0 and document.get('msg') == 'Detect success.' and document.get('data') is None
        category = None if success else failure_category(document.get('msg'))
        failed = status == 400 and code == 2
        matched = success if expected.get('expect', 'detect_success') == 'detect_success' else failed and category == expected['failure_category']
        results.append({'monitor_id': expected['id'], 'service_id': expected['service_id'],
                        'source_id': expected['source_id'], 'app': expected['app'],
                        'target': {'host': expected['host'], 'port': expected['port']},
                        'template_sha256': templates[expected['app']],
                        'native_detect': {'http_status': status, 'code': code,
                                          'msg': 'Detect success.' if success else None,
                                          'failure_category': category, 'error_detail_redacted': not success},
                        'priority_zero_group': GROUPS[expected['app']],
                        'started_at': begin, 'completed_at': time.time_ns() // 1_000_000,
                        'api_tls': tls, 'collector_negotiated_transport': None,
                        'sample_fields': None, 'matches_expectation': bool(matched)})
    return {'schema_version': 1, 'kind': 'hertzbeat-native-detect', 'run_id': config['run_id'],
            'started_at': started, 'completed_at': time.time_ns() // 1_000_000,
            'passed': all(row['matches_expectation'] for row in results), 'results': results,
            'limitations': ['Native detect returns no collector TLS version, cipher, SSH host-key fingerprint or sample values.',
                            'Use independently queried native history for samples and the deployed artifact record for collector code identity.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    try:
        with Path(args.config).open() as stream:
            config = json.load(stream, object_pairs_hook=unique)
        result = run(config)
        print(json.dumps(result, allow_nan=False, sort_keys=True))
        return 0 if result['passed'] else 1
    except Exception as error:
        print(json.dumps({'passed': False, 'error': type(error).__name__}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
