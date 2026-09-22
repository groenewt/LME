"""Product transports. Only canonical data recovered through query proves readback."""
from datetime import datetime
import json
import hashlib
import os
from pathlib import Path
import socket
import ssl
import stat
from urllib.parse import urlencode, urlsplit, quote
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler, ProxyHandler
from .spool import canonical, SEVERITIES


class DeliveryError(RuntimeError):
    pass


def private_secret(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('secret must be a private regular file (0600 or stricter)')
        data = os.read(fd, 16385)
    finally:
        os.close(fd)
    if not data or len(data)>16384:
        raise ValueError('empty or oversized secret')
    value=data.decode().strip()
    if not value or '\n' in value or '\r' in value:
        raise ValueError('secret must be one nonempty line')
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise DeliveryError('redirect refused')


class Transport:
    def __init__(self, cfg):
        self.cfg=cfg
        self.origin=cfg['origin'].rstrip('/')
        url=urlsplit(self.origin)
        if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path:
            raise ValueError('sink origin must be a credential-free HTTPS origin')
        self.context=ssl.create_default_context(cafile=cfg.get('ca_file'))
        if cfg.get('client_cert_file'):
            self.context.load_cert_chain(cfg['client_cert_file'],cfg['client_key_file'])
        self.timeout=cfg.get('timeout_seconds',10)
        if type(self.timeout) not in (int,float) or not 0<self.timeout<=60:
            raise ValueError('timeout_seconds must be in (0,60]')
        self.opener=build_opener(ProxyHandler({}),HTTPSHandler(context=self.context),NoRedirect())

    def request(self,path,body=None,*,read=False,content_type='application/json'):
        auth=private_secret(self.cfg['read_auth_file' if read else 'auth_file'])
        if not auth.startswith(('Bearer ','Basic ','ApiKey ')):
            raise ValueError('auth_file must contain complete Authorization header value')
        data=body if isinstance(body,bytes) else (json.dumps(body,allow_nan=False).encode() if body is not None else None)
        req=Request(self.origin+path,data,{'Authorization':auth,'Content-Type':content_type,'Accept':'application/json'})
        with self.opener.open(req,timeout=self.timeout) as response:
            if response.status not in (200,201,202):
                raise DeliveryError('unexpected transport status')
            raw=response.read(4*1024*1024+1)
        if len(raw)>4*1024*1024:
            raise DeliveryError('query response exceeds bounded limit')
        return json.loads(raw) if raw else {}


def document(record):
    return {'@timestamp':record.get('occurred_at',record['observed_at']),
            'event':{'id':record['event_id'],'kind':'event','dataset':record.get('dataset','lme.'+record['kind'])},
            'host':{'name':record['source_node']},'log':{'level':record['severity'].lower()},'lme':record}


class Elastic(Transport):
    def __init__(self,cfg):
        super().__init__(cfg)
        self.index=cfg['index']
        if not isinstance(self.index,str) or not self.index or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in self.index):
            raise ValueError('index must be a fixed lowercase index name')

    def send(self,record):
        # Stable index + id makes replay idempotent. This targets a regular index, not a data stream.
        metadata={'index':{'_index':self.index,'_id':record['source_node']+':'+record['event_id']}}
        data=(json.dumps(metadata)+'\n'+json.dumps(document(record),allow_nan=False)+'\n').encode()
        result=self.request('/_bulk',data,content_type='application/x-ndjson')
        items=result.get('items',[])
        if len(items)!=1 or not 200<=items[0].get('index',{}).get('status',0)<300 or result.get('errors') is not False:
            raise DeliveryError('bulk item not accepted')

    def readback(self,record):
        response=self.request('/'+quote(self.index,safe='')+'/_search',{'size':2,'query':{'ids':{'values':[record['source_node']+':'+record['event_id']]}}},read=True)
        for hit in response.get('hits',{}).get('hits',[]):
            candidate=hit.get('_source',{}).get('lme')
            if candidate and candidate.get('event_id')==record['event_id']:
                return candidate
        return None


class HertzBeat(Transport):
    def send(self,record):
        timestamp=int(datetime.fromisoformat(record.get('occurred_at',record['observed_at']).replace('Z','+00:00')).timestamp()*1e9)
        log = {'timeUnixNano':str(timestamp),
               'severityNumber':1+4*SEVERITIES.index(record['severity']),
               'severityText':record['severity'],'body':{'stringValue':canonical(record).decode()},
               'attributes':[{'key':'lme.event_id','value':{'stringValue':record['event_id']}}]}
        resource = {'attributes':[
            {'key':'service.name','value':{'stringValue':'lme-typed-logs'}},
            {'key':'host.name','value':{'stringValue':record['source_node']}}]}
        payload = {'resourceLogs':[{'resource':resource,'scopeLogs':[
            {'scope':{'name':'lme.telemetry','version':'1.0.0'},'logRecords':[log]}]}]}
        result=self.request('/api/otlp/v1/logs',payload)
        partial=result.get('partialSuccess',{})
        if int(partial.get('rejectedLogRecords',0)) or partial.get('errorMessage'):
            raise DeliveryError('OTLP partial success; record remains pending')
        # Product failure wrappers must not be interpreted as OTLP success.
        if 'code' in result and result['code']!=0:
            raise DeliveryError('HertzBeat rejected admission')

    def readback(self,record):
        stamp=int(datetime.fromisoformat(record.get('occurred_at',record['observed_at']).replace('Z','+00:00')).timestamp()*1000)
        for page in range(5):
            query=urlencode({'start':max(0,stamp-1000),'end':stamp+1000,'search':record['event_id'],'pageIndex':page,'pageSize':200,'resource':"host.name = '"+record['source_node'].replace("'","''")+"'"})
            result=self.request('/api/observability/logs?'+query,read=True)
            if result.get('code')!=0:
                raise DeliveryError('HertzBeat query failed')
            rows=result.get('data',{}).get('content',[])
            for row in rows:
                body=row.get('body')
                try:
                    candidate=json.loads(body) if isinstance(body,str) else body
                except (ValueError,TypeError):
                    continue
                if isinstance(candidate,dict) and candidate.get('event_id')==record['event_id']:
                    return candidate
            if len(rows)<200:
                break
        return None


class Malcolm(Transport):
    def __init__(self,cfg):
        super().__init__(cfg)
        self.host=cfg['tcp_host'];self.port=cfg.get('tcp_port',5045)
        if not isinstance(self.host,str) or not self.host or type(self.port) is not int or not 1<=self.port<=65535:
            raise ValueError('invalid Malcolm TCP address')

    def send(self,record):
        payload=document(record)
        payload['event']['module']='lme'
        payload['event']['hash']=hashlib.sha256(canonical(record)).hexdigest()
        with socket.create_connection((self.host,self.port),timeout=self.timeout) as raw:
            with self.context.wrap_socket(raw,server_hostname=self.host) as connection:
                connection.sendall(json.dumps(payload,allow_nan=False).encode()+b'\n')
        # A completed TLS write has no application receipt; readback is still mandatory.

    def readback(self,record):
        expected=canonical(record)
        digest=hashlib.sha256(expected).hexdigest()
        result=self.request('/mapi/document',{'doctype':'host','limit':2,
                            'filter':{'event.id':record['event_id'],'event.hash':digest,
                                      'host.name':record['source_node']}},read=True)
        for hit in result.get('results',[]):
            source=hit.get('_source',{})
            candidate=source.get('lme')
            if (source.get('host',{}).get('name')!=record['source_node'] or
                source.get('event',{}).get('id')!=record['event_id'] or
                source.get('event',{}).get('hash')!=digest):
                continue
            try:
                if canonical(candidate)==expected:
                    return candidate
            except (ValueError,TypeError,UnicodeError):
                continue
        return None



def work_once(spool,adapters,*,limit=100):
    counts={'verified':0,'retry':0,'missing_adapters':[]}
    required={r[0] for r in spool.db.execute("SELECT DISTINCT destination FROM obligations WHERE state!='verified'")}
    counts['missing_adapters']=sorted(required-adapters.keys())
    for destination,sink in adapters.items():
        for row in spool.due(destination,limit=limit):
            record=json.loads(row['payload'])
            try:
                if row['state']=='pending':
                    sink.send(record)
                    spool.accept(row['event_id'],destination)
                returned=sink.readback(record)
                if not spool.verify(row['event_id'],destination,returned):
                    # Resend after query misses, including crashes between send and acceptance.
                    # Stable IDs make Elastic idempotent; HB/Malcolm may retain duplicates.
                    if row['state']=='accepted':
                        sink.send(record)
                    raise DeliveryError('canonical readback absent or differs')
                counts['verified']+=1
            except (OSError,ValueError,RuntimeError,KeyError,TypeError) as exc:
                # Never store remote error bodies or exception strings that may contain credentials.
                spool.retry(row['event_id'],destination,type(exc).__name__)
                counts['retry']+=1
    return counts
