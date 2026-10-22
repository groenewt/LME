"""Read native ES ECS gauges and issue content-bearing HB outbox receipts.

Only the source-owned gauge contract is supported. No log substitutions, caller
hashes or fabricated units/scope metadata may qualify native delivery.
"""
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import struct
import stat
from urllib.parse import urlsplit
import uuid
from .delivery import Elastic, DeliveryError

RESOURCE_MAPPING={'service.instance.id':'service.node.name','host.name':'host.name'}


def field(document,path):
    if path in document:
        return document[path]
    current=document
    for part in path.split('.'):
        if not isinstance(current,dict) or part not in current:
            raise ValueError('native queried field missing')
        current=current[part]
    return current


def equivalent(left,right):
    def normalize(value):
        if isinstance(value,dict):
            return {k:normalize(v) for k,v in sorted(value.items())}
        if isinstance(value,list):
            return sorted([normalize(v) for v in value],key=lambda v:json.dumps(v,sort_keys=True))
        return value
    return json.dumps(normalize(left),sort_keys=True,allow_nan=False)==json.dumps(normalize(right),sort_keys=True,allow_nan=False)


def timestamp_nanos(value):
    match=re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z',value)
    if not match:
        raise ValueError('queried native timestamp requires UTC nanosecond form')
    seconds=int(datetime.fromisoformat(match[1]+'+00:00').timestamp())
    return str(seconds*10**9+int((match[2] or '').ljust(9,'0')))


def iso_nanos(value):
    seconds,nanos=divmod(int(value),10**9)
    return datetime.fromtimestamp(seconds,timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')+f'.{nanos:09d}Z'


def attributes_from_source(attributes,doc,mapping=None):
    result=[]
    for attr in attributes:
        name=attr['key'];value=field(doc,(mapping or {}).get(name,name))
        if not isinstance(value,str):
            raise ValueError('native label type differs')
        result.append({'key':name,'value':{'stringValue':value}})
    return result


def reconstruct_gauge(resource,scope,metric,point,doc):
    if set(metric)-{'name','unit','gauge'} or set(scope)!={'name'} or set(resource)!={'attributes'}:
        raise ValueError('unsupported native metric envelope')
    if set(point)!={'asDouble','timeUnixNano','attributes'} or 'gauge' not in metric:
        raise ValueError('only source-owned native gauges are supported')
    unit=field(doc,'lme.metric.unit');kind=field(doc,'lme.metric.type');scope_name=field(doc,'lme.scope.name')
    if kind!='gauge' or not isinstance(unit,str) or not isinstance(scope_name,str):
        raise ValueError('native metadata missing or invalid')
    value=field(doc,metric['name'])
    if type(value) not in (int,float) or not math.isfinite(value):
        raise ValueError('native gauge must be finite numeric')
    # Metric name is the actual queried field path, not an unrelated stored digest.
    reconstructed={'name':metric['name'],'unit':unit,'gauge':{'dataPoints':[{
        'asDouble':float(value),'timeUnixNano':timestamp_nanos(field(doc,'@timestamp')),
        'attributes':attributes_from_source(point['attributes'],doc)}]}}
    return {'resource':{'attributes':attributes_from_source(resource['attributes'],doc,RESOURCE_MAPPING)},
            'scope':{'name':scope_name},'metric':reconstructed}


class NativeElastic(Elastic):
    def read_metrics(self,payload):
        retrieved={'resourceMetrics':[]}
        points=0
        consumed=set()
        for rm in payload['resourceMetrics']:
            new_rm={'resource':None,'scopeMetrics':[]}
            for sm in rm['scopeMetrics']:
                new_sm={'scope':None,'metrics':[]}
                for metric in sm['metrics']:
                    new_metric=None
                    for point in metric['gauge']['dataPoints']:
                        points+=1
                        if points>1000:
                            raise ValueError('native query budget exceeded')
                        filters=[{'term':{'@timestamp':iso_nanos(point['timeUnixNano'])}}, {'exists':{'field':metric['name']}}]
                        for attr in rm['resource']['attributes']+point['attributes']:
                            key=RESOURCE_MAPPING.get(attr['key'],attr['key'])
                            filters.append({'term':{key:attr['value']['stringValue']}})
                        response=self.request('/'+self.index+'/_search',{'size':20,'query':{'bool':{'filter':filters}}},read=True)
                        matched=None
                        for hit in response.get('hits',{}).get('hits',[]):
                            try:
                                # A native document may contain several metric fields,
                                # but its one scalar field proves only one occurrence.
                                identity=(hit.get('_index',self.index),hit.get('_id') or
                                          json.dumps(hit['_source'],sort_keys=True,allow_nan=False),metric['name'])
                                if identity in consumed:continue
                                candidate=reconstruct_gauge(rm['resource'],sm['scope'],metric,point,hit['_source'])
                                if (equivalent(candidate['resource'],rm['resource']) and equivalent(candidate['scope'],sm['scope']) and
                                    equivalent(candidate['metric'],dict(metric,gauge={'dataPoints':[point]}))):
                                    matched=candidate;consumed.add(identity);break
                            except (ValueError,KeyError,TypeError):
                                continue
                        if matched is None:
                            raise DeliveryError('native metric query has no matching content')
                        new_rm['resource']=matched['resource'];new_sm['scope']=matched['scope']
                        if new_metric is None:
                            new_metric=matched['metric']
                        else:
                            new_metric['gauge']['dataPoints'].extend(matched['metric']['gauge']['dataPoints'])
                    if new_metric is None:
                        raise ValueError('empty native gauge')
                    new_sm['metrics'].append(new_metric)
                new_rm['scopeMetrics'].append(new_sm)
            retrieved['resourceMetrics'].append(new_rm)
        if not points or not equivalent(payload,retrieved):
            raise DeliveryError('native metric envelope does not match query reconstruction')
        return retrieved


MAX_NATIVE_PAYLOAD = 1024 * 1024
MAX_NATIVE_ENVELOPE = MAX_NATIVE_PAYLOAD + 131072


def _modified_utf(raw):
    # DataOutputStream.writeUTF uses modified UTF-8: NUL is C0 80 and supplementary
    # characters are encoded as two UTF-16 surrogate code units, never four bytes.
    if any(byte >= 0xf0 for byte in raw):
        raise ValueError('invalid Java modified UTF-8')
    try:
        value=raw.replace(b'\xc0\x80',b'\0').decode('utf-8','surrogatepass')
        return value.encode('utf-16-le','surrogatepass').decode('utf-16-le')
    except UnicodeError as exc:
        raise ValueError('invalid Java modified UTF-8') from exc


def _unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate native JSON field')
        result[key]=value
    return result


def _reject_constant(value):
    raise ValueError('nonfinite native JSON value')


def _finite_float(value):
    result=float(value)
    if not math.isfinite(result):raise ValueError('nonfinite native JSON value')
    return result


def read_outbox(path, *, metadata=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>MAX_NATIVE_ENVELOPE:
            raise ValueError('native outbox must be a bounded regular file')
        def integer():
            raw=stream.read(4)
            if len(raw)!=4:raise ValueError('truncated native outbox')
            return struct.unpack('>i',raw)[0]
        def utf():
            raw=stream.read(2)
            if len(raw)!=2:raise ValueError('truncated native UTF')
            length=struct.unpack('>H',raw)[0]
            raw=stream.read(length)
            if len(raw)!=length:raise ValueError('truncated native UTF')
            return _modified_utf(raw)
        version=integer()
        if version not in (1,2):raise ValueError('unsupported native outbox version')
        endpoint=utf()
        parsed=urlsplit(endpoint)
        if (parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or
            parsed.query or parsed.fragment or any(ord(c)<32 for c in endpoint)):
            raise ValueError('invalid native admission route')
        if version==2:
            # This is a snapshotted WRITE credential reference, not a readback grant.
            # Consume it only as envelope metadata. Never open, log, or reuse it.
            authorization_reference=utf()
            if authorization_reference and (not authorization_reference.startswith('/') or any(ord(c)<32 for c in authorization_reference)):
                raise ValueError('invalid native authorization reference')
        count=integer()
        if not 1<=count<=2:raise ValueError('invalid native sink count')
        sinks=[utf() for _ in range(count)]
        if len(set(sinks))!=count or set(sinks)-{'elastic','hertzbeat'}:raise ValueError('invalid native sinks')
        length=integer()
        if not 0<length<=MAX_NATIVE_PAYLOAD:raise ValueError('native payload exceeds1MiB')
        raw=stream.read(length)
        if len(raw)!=length or stream.read(1):raise ValueError('invalid native payload framing')
        payload=json.loads(raw,parse_constant=_reject_constant,parse_float=_finite_float,object_pairs_hook=_unique_object)
        if not isinstance(payload,dict):raise ValueError('native payload must be an object')
        if metadata:
            return {'version':version,'endpoint':endpoint,'sinks':sinks,'payload':payload}
        return sinks,payload


def inspect_outbox_routes(directory,limit=256):
    """Read bounded actual queued headers; never return/open write auth references."""
    if type(limit) is not int or not 1<=limit<=1000:raise ValueError('invalid route inspection bound')
    directory=Path(directory)
    if directory.is_symlink() or not directory.is_dir():raise ValueError('native outbox directory required')
    records=[];errors=0;truncated=False
    with os.scandir(directory) as entries:
        for entry in entries:
            if not entry.name.endswith(('.pending','.accepted')):continue
            if len(records)+errors>=limit:truncated=True;break
            try:
                identifier=str(uuid.UUID(Path(entry.name).stem))
                envelope=read_outbox(entry.path,metadata=True)
                names=set()
                for resource in envelope['payload']['resourceMetrics']:
                    host=[a['value']['stringValue'] for a in resource['resource']['attributes'] if a['key']=='host.name']
                    if len(host)!=1:raise ValueError('native resource requires one source')
                    names.add(host[0])
                if len(names)!=1:raise ValueError('native envelope requires one source')
                records.append({'id':identifier,'stage':Path(entry.name).suffix[1:],
                    'version':envelope['version'],'endpoint':envelope['endpoint'],'sinks':envelope['sinks'],
                    'source_node':next(iter(names))})
            except FileNotFoundError:
                continue # A concurrent source-owned rename/retirement is not corruption.
            except (ValueError,OSError,KeyError,TypeError,RecursionError):errors+=1
    return {'records':records,'errors':errors,'truncated':truncated}


class NativeSourceAdapters:
    """Read grants are selected from configured source ownership, never write refs."""
    def __init__(self,sources):
        self.sources=sources

    def select(self,sink,payload):
        names=set()
        try:
            resources=payload['resourceMetrics']
            if not resources:return None
            for resource in resources:
                attrs=[attr['value']['stringValue'] for attr in resource['resource']['attributes'] if attr['key']=='host.name']
                if len(attrs)!=1 or not isinstance(attrs[0],str):return None
                names.add(attrs[0])
        except (KeyError,TypeError):
            return None
        if len(names)!=1:return None
        return self.sources.get(next(iter(names)),{}).get(sink)


def verify_outbox(directory,adapters,limit=100):
    directory=Path(directory);receipts=directory/'readbacks'
    receipts.mkdir(mode=0o700,exist_ok=True)
    counts={'verified':0,'pending':0}
    for path in sorted(directory.glob('*.accepted'))[:limit]:
        try:
            identifier=str(uuid.UUID(path.stem))
            sinks,payload=read_outbox(path)
        except (OSError,ValueError,TypeError,RecursionError):
            counts['pending']+=1
            continue
        for sink in sinks:
            adapter=adapters.select(sink,payload) if isinstance(adapters,NativeSourceAdapters) else adapters.get(sink)
            if adapter is None:
                counts['pending']+=1;continue
            target=receipts/f'{identifier}.{sink}.json'
            try:
                returned=adapter.read_metrics(payload)
                if not equivalent(payload,returned):
                    raise DeliveryError('native receipt differs from admitted payload')
                receipt={'id':identifier,'sink':sink,'payload':returned}
                tmp=receipts/f'.{identifier}.{sink}.{os.getpid()}.tmp'
                fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                try:
                    with os.fdopen(fd,'w') as stream:
                        json.dump(receipt,stream,allow_nan=False,separators=(',',':'));stream.flush();os.fsync(stream.fileno())
                    os.replace(tmp,target)
                    fd=os.open(receipts,os.O_RDONLY|os.O_DIRECTORY)
                    try:os.fsync(fd)
                    finally:os.close(fd)
                finally:
                    tmp.unlink(missing_ok=True)
                counts['verified']+=1
            except (OSError,ValueError,RuntimeError,KeyError,TypeError):
                counts['pending']+=1
    return counts
