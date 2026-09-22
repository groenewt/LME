"""Authenticated bounded HTTP admission, single request at a time per source node."""
import hmac
import ipaddress
import json
import sqlite3
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from .delivery import private_secret
from .spool import Spool, Conflict, QuotaExceeded, MAX_BATCH_BYTES, validate_destinations


def open_spool(config):
    return Spool(config['spool_path'],source_node=config['source_node'],**config.get('quotas',{}))


def admission_server(config):
    cfg=config['ingress'];bind=cfg.get('bind','127.0.0.1')
    address=ipaddress.ip_address(bind)
    if address.is_unspecified or address.is_multicast or not (address.is_loopback or address.is_private or address in ipaddress.ip_network('100.64.0.0/10')):
        raise ValueError('ingress requires explicit private/loopback IP')
    tls=bool(cfg.get('tls_cert_file') and cfg.get('tls_key_file'))
    if not address.is_loopback and not tls:
        raise ValueError('nonloopback admission requires TLS')
    if bool(cfg.get('tls_cert_file'))!=bool(cfg.get('tls_key_file')):
        raise ValueError('both TLS certificate and key required')
    validate_destinations(config['destinations'])
    private_secret(cfg['token_file'])
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):
            pass  # no request body/auth logs; aggregate state is available via status.

        def setup(self):
            super().setup();self.connection.settimeout(10)

        def respond(self,status,payload):
            data=json.dumps(payload).encode()
            self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(data)));self.send_header('Connection','close')
            self.end_headers();self.wfile.write(data);self.close_connection=True

        def do_GET(self):
            if self.path!='/metrics':
                self.respond(404,{'error':'unknown endpoint'});return
            if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+private_secret(cfg['token_file'])):
                self.respond(401,{'error':'authentication required'});return
            spool=open_spool(config)
            try:
                status=spool.status()
            finally:
                spool.close()
            lines=[]
            for name in ('records','archived_records','pending_bytes','archive_bytes'):
                lines.extend(['# TYPE lme_telemetry_'+name+' gauge','lme_telemetry_'+name+' '+str(status[name])])
            lines.append('# TYPE lme_telemetry_obligations gauge')
            for row in status['obligations']:
                labels='{destination="'+row['destination']+'",state="'+row['state']+'"}'
                lines.append('lme_telemetry_obligations'+labels+' '+str(row['count']))
            data=('\n'.join(lines)+'\n').encode()
            self.send_response(200);self.send_header('Content-Type','text/plain; version=0.0.4')
            self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)

        def do_POST(self):
            if self.path!='/v1/logs':
                self.respond(404,{'error':'unknown endpoint'});return
            expected='Bearer '+private_secret(cfg['token_file'])
            if not hmac.compare_digest(self.headers.get('Authorization',''),expected):
                self.respond(401,{'error':'authentication required'});return
            if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length',[]))!=1:
                self.respond(400,{'error':'one Content-Length required; chunked unsupported'});return
            try:
                length=int(self.headers['Content-Length'])
                if not 0<length<=MAX_BATCH_BYTES:
                    self.respond(413,{'error':'request exceeds 1MiB'});return
                if self.headers.get_content_type()!='application/json':
                    self.respond(415,{'error':'application/json required'});return
                raw=self.rfile.read(length)
                if len(raw)!=length:
                    self.respond(400,{'error':'incomplete request'});return
                payload=json.loads(raw)
                if not isinstance(payload,dict) or set(payload)-{'records','record','checkpoint'} or ('records' in payload)==('record' in payload):
                    raise ValueError('exactly one of records or record required')
                records=payload['records'] if 'records' in payload else [payload['record']]
                spool=open_spool(config)
                try:
                    result=spool.admit(records,config['destinations'],payload.get('checkpoint'))
                finally:
                    spool.close()
                self.respond(202,result)
            except Conflict:
                self.respond(409,{'error':'event collision or checkpoint regression'})
            except QuotaExceeded:
                self.respond(507,{'error':'durable quota exhausted; retry same batch'})
            except (ValueError,TypeError,UnicodeError,RecursionError):
                self.respond(400,{'error':'invalid typed log batch'})
            except (OSError,sqlite3.Error):
                self.respond(503,{'error':'durable admission unavailable; retry same batch'})
    if address.version==6:
        import socket
        class IPv6Server(HTTPServer):
            address_family=socket.AF_INET6
        server=IPv6Server((bind,cfg.get('port',9469)),Handler)
    else:
        server=HTTPServer((bind,cfg.get('port',9469)),Handler)
    if tls:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cfg['tls_cert_file'],cfg['tls_key_file'])
        server.socket=context.wrap_socket(server.socket,server_side=True)
    return server
