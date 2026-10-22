"""Validate JDBC security parameters without exposing configuration or secrets."""
from urllib.parse import parse_qsl, urlsplit


def verified_jdbc(value):
    try:
        if not isinstance(value, str) or not value.startswith('jdbc:postgresql://'):
            return False
        uri = urlsplit(value[5:])
        pairs = parse_qsl(uri.query, strict_parsing=True)
        options = dict(pairs)
        allowed = {'sslmode', 'sslrootcert', 'sslcert', 'sslkey', 'ApplicationName',
                   'connectTimeout', 'socketTimeout', 'targetServerType', 'tcpKeepAlive'}
        if (not uri.hostname or uri.username or uri.password or uri.fragment
                or uri.path != '/hertzbeat' or len(options) != len(pairs)
                or not options.keys() <= allowed or options.get('sslmode') != 'verify-full'):
            return False
        for key in ('sslrootcert', 'sslcert', 'sslkey'):
            if key in options and (not options[key].startswith(('/run/secrets/hertzbeat/', '/run/secrets/hertzbeat-pg/'))
                                   or '..' in options[key].split('/')):
                return False
        return bool(options.get('sslrootcert'))
    except (ValueError, TypeError):
        return False


class FilterModule:
    def filters(self):
        return {'hertzbeat_verified_jdbc': verified_jdbc}
