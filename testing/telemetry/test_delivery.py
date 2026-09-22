"""HTTPS product-shaped stub contracts; no destination live-verification claim."""
import copy
import hashlib
import json
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from test_spool import record
from lme_telemetry.spool import Spool
try:
    from lme_telemetry.delivery import Elastic, HertzBeat, Malcolm, work_once
    from lme_telemetry.server import admission_server
except ImportError:
    Elastic = None


class DeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(); cls.root=Path(cls.tmp.name)
        cls.cert=cls.root/'cert.pem'; cls.key=cls.root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(cls.key),'-out',str(cls.cert),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        cls.auth=cls.root/'auth'; cls.auth.write_text('Bearer synthetic-only'); cls.auth.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.assertIsNotNone(Elastic,'destination adapters must be implemented')
        self.requests=[]; self.stored=None; self.reject=False; self.tamper=False; self.partial=False
        case=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self): self.handle_request()
            def do_GET(self): self.handle_request()
            def handle_request(self):
                body=self.rfile.read(int(self.headers.get('Content-Length',0)))
                case.requests.append((self.command,self.path,body,self.headers.get('Authorization')))
                if self.path=='/_bulk':
                    lines=body.splitlines(); case.stored=json.loads(lines[1]); status=429 if case.reject else 201
                    result={'errors':case.reject,'items':[{'index':{'status':status}}]}
                elif '/_search' in self.path:
                    doc=copy.deepcopy(case.stored)
                    if doc and case.tamper: doc['lme']['body']['value']=99
                    result={'hits':{'hits':[] if doc is None else [{'_source':doc}]}}
                elif self.path=='/api/otlp/v1/logs':
                    case.stored=json.loads(body)['resourceLogs'][0]['scopeLogs'][0]['logRecords'][0]['body']['stringValue']
                    result={'partialSuccess':{'rejectedLogRecords':'1'}} if case.partial else {}
                elif self.path.startswith('/api/observability/logs?'):
                    result={'code':0,'data':{'content':[] if case.stored is None else [{'body':case.stored}]}}
                elif self.path=='/mapi/document':
                    doc={'lme':record(),'event':{'id':'event-1','hash':hashlib.sha256(json.dumps(record(),sort_keys=True,separators=(',',':')).encode()).hexdigest()},'host':{'name':'graph'}}
                    if case.tamper: doc['lme']['body']['value']=99
                    result={'results':[{'_source':doc}]}
                else: result={}
                data=json.dumps(result).encode(); self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        self.server=HTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.cert,self.key)
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.cfg=dict(origin=f'https://localhost:{self.server.server_port}',ca_file=str(self.cert),auth_file=str(self.auth),read_auth_file=str(self.auth),index='lme-typed-logs')
        self.local=tempfile.TemporaryDirectory();self.addCleanup(self.local.cleanup)
        self.spool=Spool(Path(self.local.name)/'spool.db',source_node='graph',reserve_bytes=0);self.addCleanup(self.spool.close)

    def test_bulk_item_rejection_does_not_verify_even_when_http200(self):
        self.spool.admit([record()],['elastic']);self.reject=True
        work_once(self.spool,{'elastic':Elastic(self.cfg)})
        self.assertEqual(self.spool.obligations('event-1'),{'elastic':'pending'})
        self.assertEqual(self.spool.status()['archived_records'],0)

    def test_readback_recomputes_content_and_retry_survives_restart(self):
        self.spool.admit([record()],['elastic']);self.tamper=True
        work_once(self.spool,{'elastic':Elastic(self.cfg)})
        self.assertEqual(self.spool.obligations('event-1'),{'elastic':'accepted'})
        self.spool.db.execute('UPDATE obligations SET next_attempt=0')
        self.tamper=False
        work_once(self.spool,{'elastic':Elastic(self.cfg)})
        self.assertEqual(self.spool.obligations('event-1'),{'elastic':'verified'})
        self.assertTrue(all(r[3]=='Bearer synthetic-only' for r in self.requests))

    def test_hertzbeat_partial_acceptance_and_real_query_shape(self):
        self.spool.admit([record()],['hertzbeat']);self.partial=True
        work_once(self.spool,{'hertzbeat':HertzBeat(self.cfg)})
        self.assertEqual(self.spool.obligations('event-1'),{'hertzbeat':'pending'})
        self.spool.db.execute('UPDATE obligations SET next_attempt=0');self.partial=False
        work_once(self.spool,{'hertzbeat':HertzBeat(self.cfg)})
        self.assertEqual(self.spool.obligations('event-1'),{'hertzbeat':'verified'})
        self.assertTrue(any(r[0]=='GET' and r[1].startswith('/api/observability/logs?') and 'search=event-1' in r[1] for r in self.requests))

    def test_missing_removed_sink_does_not_drop_obligations(self):
        self.spool.admit([record()],['elastic','hertzbeat'])
        result=work_once(self.spool,{'elastic':Elastic(self.cfg)})
        self.assertEqual(self.spool.obligations('event-1'),{'elastic':'verified','hertzbeat':'pending'})
        self.assertEqual(result['missing_adapters'],['hertzbeat'])

    def test_invalid_tls_hostname_fails_closed(self):
        self.cfg['origin']=self.cfg['origin'].replace('localhost','127.0.0.1')
        self.spool.admit([record()],['elastic'])
        work_once(self.spool,{'elastic':Elastic(self.cfg)})
        self.assertEqual(self.spool.obligations('event-1'),{'elastic':'pending'})
        self.assertEqual(self.requests,[])

    def test_malcolm_readback_requests_host_documents(self):
        self.cfg.update(tcp_host='localhost',tcp_port=5045)
        sink=Malcolm(self.cfg)
        self.assertEqual(sink.readback(record()),record())
        payload=json.loads(self.requests[-1][2])
        self.assertEqual(payload['doctype'],'host')
        self.assertEqual(payload,{'doctype':'host','limit':2,'filter':{
            'event.id':'event-1','event.hash':hashlib.sha256(json.dumps(record(),sort_keys=True,separators=(',',':')).encode()).hexdigest(),'host.name':'graph'}})

    def test_ingress_auth_batch_ack_and_source_identity(self):
        path=Path(self.local.name)/'ingress.db'
        cfg={'spool_path':str(path),'source_node':'graph','destinations':['elastic'],'ingress':{'bind':'127.0.0.1','port':0,'token_file':str(self.auth)}}
        server=admission_server(cfg);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        url=f'http://127.0.0.1:{server.server_port}/v1/logs'
        payload=json.dumps({'records':[record()],'checkpoint':{'source':'journal','offset':42}}).encode()
        with self.assertRaises(HTTPError) as err:
            urlopen(Request(url,payload,method='POST'))
        self.assertEqual(err.exception.code,401)
        req=Request(url,payload,{'Authorization':'Bearer Bearer synthetic-only','Content-Type':'application/json'})
        with urlopen(req) as response:
            self.assertEqual(response.status,202);self.assertEqual(json.load(response)['ack'],'local_fsync')
        wrong=record('wrong');wrong['source_node']='silmaril'
        with self.assertRaises(HTTPError) as err:
            urlopen(Request(url,json.dumps({'records':[wrong]}).encode(),{'Authorization':'Bearer Bearer synthetic-only','Content-Type':'application/json'}))
        self.assertEqual(err.exception.code,400)
        s=Spool(path,source_node='graph');self.addCleanup(s.close)
        self.assertEqual(s.checkpoint('journal'),42);self.assertEqual(s.status()['records'],1)

    def test_ingress_rejects_wildcard_and_unprotected_private_address(self):
        for bind in ('0.0.0.0','192.168.1.20'):
            with self.assertRaises(ValueError):
                admission_server({'ingress':{'bind':bind,'port':0,'token_file':str(self.auth)}})

    def test_malcolm_tls_send_delivers_native_json_and_never_self_verifies(self):
        import socket
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        self.addCleanup(listener.close)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.cert,self.key)
        received=[]
        def receive():
            raw,_=listener.accept()
            with context.wrap_socket(raw,server_side=True) as conn:
                with conn.makefile('rb') as stream:
                    received.append(stream.readline())
        thread=threading.Thread(target=receive,daemon=True);thread.start()
        self.cfg.update(tcp_host='localhost',tcp_port=listener.getsockname()[1])
        Malcolm(self.cfg).send(record());thread.join(3)
        self.assertFalse(thread.is_alive())
        doc=json.loads(received[0]);self.assertEqual(doc['lme'],record())
        self.assertEqual(doc['event']['module'],'lme')
        self.assertEqual(doc['event']['hash'],hashlib.sha256(json.dumps(record(),sort_keys=True,separators=(',',':')).encode()).hexdigest())

    def test_bulk_ids_are_namespaced_by_node(self):
        Elastic(self.cfg).send(record())
        metadata=json.loads(self.requests[-1][2].splitlines()[0])
        self.assertEqual(metadata['index']['_id'],'graph:event-1')

    def test_ingress_exposes_authenticated_aggregate_native_metrics(self):
        cfg={'spool_path':str(Path(self.local.name)/'spool.db'),'source_node':'graph','destinations':['elastic'],
             'ingress':{'bind':'127.0.0.1','port':0,'token_file':str(self.auth)}}
        self.spool.admit([record()],['elastic'])
        server=admission_server(cfg);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        req=Request(f'http://127.0.0.1:{server.server_port}/metrics',headers={'Authorization':'Bearer Bearer synthetic-only'})
        with urlopen(req) as response:
            body=response.read().decode()
        self.assertIn('lme_telemetry_records 1',body)
        self.assertIn('lme_telemetry_obligations{destination="elastic",state="pending"} 1',body)
        self.assertNotIn('event-1',body)

    def test_native_metric_outbox_issues_receipt_only_for_real_matching_projection(self):
        from test_native_metrics import fixture, returned
        from lme_telemetry.native_metrics import NativeElastic, verify_outbox
        import struct
        import uuid
        root=Path(self.local.name)/'native';root.mkdir();identifier=str(uuid.uuid4())
        def utf(value):
            data=value.encode('ascii');return struct.pack('>H',len(data))+data
        payload=json.dumps(fixture()).encode()
        (root/(identifier+'.accepted')).write_bytes(struct.pack('>i',2)+utf('https://local.example:14418/v1/metrics')+utf('/missing/snapshotted-write-authorization')+struct.pack('>i',1)+utf('elastic')+struct.pack('>i',len(payload))+payload)
        self.stored=returned()
        result=verify_outbox(root,{'elastic':NativeElastic(self.cfg)})
        self.assertEqual(result,{'verified':1,'pending':0})
        receipt=json.loads((root/'readbacks'/(identifier+'.elastic.json')).read_text())
        self.assertEqual(receipt['payload'],fixture())
        (root/'readbacks'/(identifier+'.elastic.json')).unlink()
        self.stored['hertzbeat']['linux']['cpu']['usage']=98.0
        result=verify_outbox(root,{'elastic':NativeElastic(self.cfg)})
        self.assertEqual(result,{'verified':0,'pending':1})
        self.assertEqual(list((root/'readbacks').iterdir()),[])

    def test_malcolm_readback_rejects_copied_hash_with_changed_canonical_payload(self):
        self.cfg.update(tcp_host='localhost',tcp_port=5045)
        self.tamper=True
        self.assertIsNone(Malcolm(self.cfg).readback(record()))

    def test_hertzbeat_readback_has_exact_source_resource_filter(self):
        from urllib.parse import parse_qs, urlsplit
        self.stored=json.dumps(record())
        self.assertEqual(HertzBeat(self.cfg).readback(record()),record())
        query=parse_qs(urlsplit(self.requests[-1][1]).query)
        self.assertEqual(query['resource'],["host.name = 'graph'"])
