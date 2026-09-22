import copy
import unittest
try:
    from lme_telemetry.native_metrics import reconstruct_gauge, equivalent
except ImportError:
    reconstruct_gauge=None


def fixture():
    attrs=lambda d:[{'key':k,'value':{'stringValue':v}} for k,v in d.items()]
    return {'resourceMetrics':[{'resource':{'attributes':attrs({'host.id':'trixie','host.name':'trixie','service.name':'hertzbeat-native','service.instance.id':'12','hertzbeat.app':'linux','lme.origin':'hertzbeat-native'})},'scopeMetrics':[{'scope':{'name':'org.apache.hertzbeat.native'},'metrics':[{'name':'hertzbeat.linux.cpu.usage','unit':'%','gauge':{'dataPoints':[{'asDouble':12.5,'timeUnixNano':'1790078400123456789','attributes':attrs({'hertzbeat.field.core':'0','lme.metric.unit':'%','lme.metric.type':'gauge','lme.scope.name':'org.apache.hertzbeat.native'})}]}}]}]}]}


def returned():
    return {'@timestamp':'2026-09-22T12:00:00.123456789Z','host':{'id':'trixie','name':'trixie','hostname':'trixie'},'service':{'name':'hertzbeat-native','node':{'name':'12'}},'hertzbeat':{'app':'linux','field':{'core':'0'},'linux':{'cpu':{'usage':12.5}}},'lme':{'origin':'hertzbeat-native','metric':{'unit':'%','type':'gauge'},'scope':{'name':'org.apache.hertzbeat.native'}}}


class NativeMetricTests(unittest.TestCase):
    def test_reconstructs_values_units_scope_and_nanos_from_native_es_source(self):
        self.assertIsNotNone(reconstruct_gauge,'native metric query reconstruction missing')
        expected=fixture(); resource=expected['resourceMetrics'][0];scope=resource['scopeMetrics'][0];metric=scope['metrics'][0];point=metric['gauge']['dataPoints'][0]
        got=reconstruct_gauge(resource['resource'],scope['scope'],metric,point,returned())
        self.assertEqual(got['metric'],metric)
        self.assertEqual(got['resource'],resource['resource'])
        self.assertEqual(got['scope'],scope['scope'])

    def test_missing_unit_or_changed_value_cannot_verify_original(self):
        self.assertIsNotNone(reconstruct_gauge,'native metric query reconstruction missing')
        expected=fixture();resource=expected['resourceMetrics'][0];scope=resource['scopeMetrics'][0];metric=scope['metrics'][0];point=metric['gauge']['dataPoints'][0]
        doc=returned();del doc['lme']['metric']['unit']
        with self.assertRaises(ValueError):reconstruct_gauge(resource['resource'],scope['scope'],metric,point,doc)
        doc=returned();doc['hertzbeat']['linux']['cpu']['usage']=99.0
        got=reconstruct_gauge(resource['resource'],scope['scope'],metric,point,doc)
        self.assertFalse(equivalent(got['metric'],metric))

class NativeOutboxVersionTests(unittest.TestCase):
    def test_java_writeutf_v1_v2_envelopes_preserve_payload_and_never_open_authref(self):
        import json
        import subprocess
        import tempfile
        from pathlib import Path
        from lme_telemetry.native_metrics import read_outbox
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);payload=root/'payload.json';payload.write_text(json.dumps(fixture()))
            source=root/'Emit.java'
            source.write_text('''import java.io.*; import java.nio.file.*;
class Emit { public static void main(String[] a) throws Exception {
  int v=Integer.parseInt(a[0]); byte[] p=Files.readAllBytes(Path.of(a[2]));
  try(DataOutputStream d=new DataOutputStream(Files.newOutputStream(Path.of(a[1])))) {
    d.writeInt(v); d.writeUTF("https://graph.example.ts.net:14418/v1/metrics");
    if(v==2) d.writeUTF(a[3]);
    d.writeInt(1);d.writeUTF("elastic");d.writeInt(p.length);d.write(p);
  }
}}''')
            subprocess.run(['javac',str(source)],check=True,capture_output=True)
            for version,reference in ((1,""),(2,"/does-not-exist/α-source-authorization"),(2,"")):
                target=root/f'v{version}.accepted'
                subprocess.run(['java','-cp',str(root),'Emit',str(version),str(target),str(payload),reference],check=True,capture_output=True)
                self.assertEqual(read_outbox(target),(['elastic'],fixture()))

    def test_v2_rejects_truncation_trailing_bytes_nonfinite_and_invalid_routes(self):
        import json
        import struct
        import tempfile
        from pathlib import Path
        from lme_telemetry.native_metrics import read_outbox
        utf=lambda s:struct.pack('>H',len(s.encode()))+s.encode()
        def envelope(payload,endpoint='https://source.example:14418/v1/metrics'):
            return struct.pack('>i',2)+utf(endpoint)+utf('/missing/auth')+struct.pack('>i',1)+utf('elastic')+struct.pack('>i',len(payload))+payload
        good=envelope(json.dumps(fixture()).encode())
        bad=[good[:n] for n in (0,3,6,30,len(good)-1)]+[good+b'x',envelope(b'{"x":NaN}'),envelope(b'{"x":1e999}'),envelope(b'{}','http://insecure/v1/metrics'),envelope(b'{}','https://u:secret@example/v1/metrics'),envelope(b'{}','https://example/v1/metrics?token=secret')]
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'bad.accepted'
            for payload in bad:
                path.write_bytes(payload)
                with self.assertRaises(ValueError):read_outbox(path)

    def test_unknown_source_never_uses_another_sources_read_adapter(self):
        from lme_telemetry.native_metrics import NativeSourceAdapters
        adapter=object()
        routes=NativeSourceAdapters({'physical:graph':{'elastic':adapter}})
        self.assertIsNone(routes.select('elastic',fixture()))
        expected=fixture()
        for attr in expected['resourceMetrics'][0]['resource']['attributes']:
            if attr['key']=='host.name':attr['value']['stringValue']='physical:graph'
        self.assertIs(routes.select('elastic',expected),adapter)
        mixed=copy.deepcopy(expected);mixed['resourceMetrics']+=fixture()['resourceMetrics']
        self.assertIsNone(routes.select('elastic',mixed))

class NativeMultiplicityTests(unittest.TestCase):
    def test_one_native_document_cannot_retire_two_identical_points(self):
        from lme_telemetry.native_metrics import NativeElastic
        from lme_telemetry.delivery import DeliveryError
        payload=fixture();points=payload['resourceMetrics'][0]['scopeMetrics'][0]['metrics'][0]['gauge']['dataPoints']
        points.append(copy.deepcopy(points[0]))
        adapter=object.__new__(NativeElastic);adapter.index='metrics'
        hits=[{'_index':'metrics','_id':'one','_source':returned()}]
        adapter.request=lambda *args,**kwargs:{'hits':{'hits':hits}}
        with self.assertRaises(DeliveryError):adapter.read_metrics(payload)
        hits.append({'_index':'metrics','_id':'two','_source':returned()})
        self.assertTrue(equivalent(payload,adapter.read_metrics(payload)))

    def test_one_document_can_prove_distinct_native_metric_fields(self):
        from lme_telemetry.native_metrics import NativeElastic
        payload=fixture();metrics=payload['resourceMetrics'][0]['scopeMetrics'][0]['metrics']
        other=copy.deepcopy(metrics[0]);other['name']='hertzbeat.linux.cpu.idle';metrics.append(other)
        doc=returned();doc['hertzbeat']['linux']['cpu']['idle']=12.5
        adapter=object.__new__(NativeElastic);adapter.index='metrics'
        adapter.request=lambda *args,**kwargs:{'hits':{'hits':[{'_index':'metrics','_id':'one','_source':doc}]}}
        self.assertTrue(equivalent(payload,adapter.read_metrics(payload)))

class NativeRouteObservationTests(unittest.TestCase):
    def test_route_observation_uses_actual_v2_bytes_without_auth_reference(self):
        import json,struct,tempfile,uuid
        from pathlib import Path
        from lme_telemetry.native_metrics import inspect_outbox_routes
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);identifier=str(uuid.uuid4());payload=json.dumps(fixture()).encode()
            def utf(text):
                raw=text.encode();return struct.pack('>H',len(raw))+raw
            (root/(identifier+'.pending')).write_bytes(struct.pack('>i',2)+utf('https://graph.example.ts.net:14418/v1/metrics')+utf('/missing/write-auth-reference')+struct.pack('>i',1)+utf('elastic')+struct.pack('>i',len(payload))+payload)
            result=inspect_outbox_routes(root)
            self.assertEqual(result['errors'],0)
            self.assertEqual(result['records'][0]['source_node'],'trixie')
            self.assertEqual(result['records'][0]['sinks'],['elastic'])
            self.assertNotIn('write-auth-reference',json.dumps(result))
