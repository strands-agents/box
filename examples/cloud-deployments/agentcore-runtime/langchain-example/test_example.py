"""Offline graph/provider and negative-evidence tests. Production has no fake fallback."""
import contextlib, copy, importlib.util, io, json
from pathlib import Path
import sys, types, unittest
from unittest.mock import patch
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import agent
spec = importlib.util.spec_from_file_location("runner", HERE / "run-demo.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
from langchain.agents.middleware.types import ModelResponse
from langchain_core.messages import AIMessage
MODEL, REGION, PORT = "us.anthropic.claude-sonnet-4-6", "us-west-2", 43210
FACTS = {"resolution": "dispatch", "order_id": 42, "confirmation_id": "dispatch-42-001", "item": "Adjustable desk lamp", "quantity": 1, "estimated_delivery": "2026-11-05", "refund_issued": False}
SERVICE = {"requests": [{"method":"GET","path":"/orders/42","status":200}, {"method":"GET","path":"/orders/42/eligibility","status":200}, {"method":"POST","path":"/orders/42/dispatch","status":201}], "effects":[runner.EFFECT], "resolution":runner.EFFECT, "effect_counts":{"dispatch":1,"refund":0}, "order":{"item":FACTS["item"],"quantity":1,"replacement_estimated_delivery":FACTS["estimated_delivery"]}}

class FakeClient:
    def __init__(self):
        self.requests=[]
        self.responses=["read_order","dispatch_replacement",None,"check_eligibility","dispatch_replacement",None,"dispatch_replacement",None,"request_refund",None,"FINAL"]
    def converse(self, **kwargs):
        self.requests.append(kwargs)
        value=self.responses.pop(0); i=len(self.requests)
        content=[{"toolUse":{"toolUseId":f"tool-{i}","name":value,"input":{}}}] if value and value!="FINAL" else [{"text":json.dumps(FACTS) if value=="FINAL" else "Diagnostic phase response."}]
        return {"output":{"message":{"role":"assistant","content":content}}, "usage":{"inputTokens":30+i,"outputTokens":10,"totalTokens":40+i}, "stopReason":"tool_use" if value and value!="FINAL" else "end_turn", "ResponseMetadata":{"RequestId":f"offline-provider-{i}","HTTPStatusCode":200,"RetryAttempts":0}}
class FakeResponse:
    def __init__(self,status,body,refused=False): self.status,self.body,self.refused=status,body,refused
    def read(self,size): return json.dumps(self.body).encode()[:size]
    def getheader(self,name): return "refused" if name=="x-strands-box-egress" and self.refused else None
class FakeConnection:
    replies=[]; requests=[]
    def __init__(self,*args,**kwargs): pass
    def request(self,method,url,body=None,headers=None): self.requests.append({"method":method,"url":url,"body":body,"headers":headers})
    def getresponse(self): return self.replies.pop(0)
    def close(self): pass

def baseline():
    client=FakeClient()
    model=agent.ChatBedrockConverse(model=MODEL,region_name=REGION,client=client,bedrock_client=object(),disable_streaming=True,streaming=False,cache=False)
    shipment=agent.ShipmentTools(f"http://127.0.0.1:{PORT}","http://127.0.0.1:12345")
    FakeConnection.requests=[]
    FakeConnection.replies=[FakeResponse(200,SERVICE["order"]),FakeResponse(403,{"error":"policy"},True),FakeResponse(200,{"eligible":True}),FakeResponse(201,dict(FACTS,effect_id=FACTS["confirmation_id"])),FakeResponse(403,{"error":"policy"},True),FakeResponse(403,{"error":"policy"},True)]
    with patch.object(agent.http.client,"HTTPConnection",FakeConnection), contextlib.redirect_stdout(io.StringIO()): workload=agent.run(model,shipment)
    workload["same_process_finished"]=True
    decisions=[]
    def add(event,host,port,method,path,verdict,rule):
        decisions.append({"strands.box.policy.principal":"agent:self","strands.box.policy.action":"http:request","strands.box.policy.resource":f"{host}:{port}{path}","strands.box.policy.verdict":verdict,"strands.box.policy.rule":rule,"http.request.method":method,"server.address":host,"server.port":port,"timestamp_ns":(event["started_ns"]+event["ended_ns"])//2,"strands.box.request.id":"offline-box-"+str(len(decisions))})
    for e,x in zip(workload["steps"],runner.EXPECTED_STEPS): add(e,"127.0.0.1",PORT,x[2],x[3],"deny" if x[5] else "permit",x[6])
    for e in workload["calls"]: add(e,f"bedrock-runtime.{REGION}.amazonaws.com",443,"POST",f"/model/{MODEL}/converse","permit","langchain_model_request")
    decisions.sort(key=lambda x:x["timestamp_ns"])
    return workload,copy.deepcopy(SERVICE),decisions,client

class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.base=baseline()
    def checks(self,w,s,d): return runner.verify(w,s,d,0,2,False,MODEL,REGION,PORT)
    def test_real_graph_and_provider_offline(self):
        w,s,d,c=self.base; checks=self.checks(w,s,d)
        self.assertTrue(all(checks.values()),[k for k,v in checks.items() if not v])
        self.assertEqual(w["model_calls"],11); self.assertEqual(len(c.requests),11)
        self.assertTrue(all("toolConfig" in x for x in c.requests))
        self.assertEqual([p["model_calls"] for p in w["phases"]],[3,3,2,2,1])
        self.assertEqual(len(FakeConnection.requests),6)
        self.assertEqual(FakeConnection.requests[1]["headers"]["Idempotency-Key"],"replacement-42")
        self.assertGreater(len(c.requests[-1]["messages"]),len(c.requests[0]["messages"]))
    def test_exact_policy_bindings(self):
        changes={"strands.box.policy.principal":"agent:other","strands.box.policy.action":"net:connect","strands.box.policy.resource":"127.0.0.1:43210/orders/43/dispatch","strands.box.policy.verdict":"permit","strands.box.policy.rule":"other","http.request.method":"GET","server.address":"localhost","server.port":123}
        for field,value in changes.items():
            with self.subTest(field=field):
                w,s,d,_=copy.deepcopy(self.base)
                next(x for x in d if x["strands.box.policy.verdict"]=="deny")[field]=value
                self.assertFalse(all(self.checks(w,s,d).values()))
    def test_model_evidence_mutations(self):
        mutations=[lambda w,s,d:w["calls"][0]["usage"].update(input_tokens=0),lambda w,s,d:w["phases"][0]["usage"].update(output_tokens=0),lambda w,s,d:w["phases"][0].update(model_calls=0),lambda w,s,d:w["calls"][0].update(http_status=500),lambda w,s,d:w["calls"][0].update(provider_request_id=w["calls"][1]["provider_request_id"]),lambda w,s,d:w["calls"][0].update(model="wrong"),lambda w,s,d:w["calls"][0].update(ended_ns=w["calls"][0]["started_ns"]),lambda w,s,d:w["calls"].pop(),lambda w,s,d:d.append(copy.deepcopy(d[-1])),lambda w,s,d:d[-1].update({"strands.box.policy.resource":"wrong"}),lambda w,s,d:d[-1].update({"server.address":"unexpected.example"}),lambda w,s,d:w["steps"][0].update(tool_call_id="invented"),lambda w,s,d:w["steps"][0].update(phase="reply"),lambda w,s,d:w["calls"][0]["tool_calls"].append(copy.deepcopy(w["calls"][0]["tool_calls"][0]))]
        for i,mutate in enumerate(mutations):
            with self.subTest(case=i):
                w,s,d,_=copy.deepcopy(self.base); mutate(w,s,d)
                self.assertFalse(all(self.checks(w,s,d).values()))
    def test_final_fact_mutations(self):
        values=[dict(FACTS,refund_issued=True),dict(FACTS,quantity=True),dict(FACTS,order_id=43),dict(FACTS,confirmation_id="fake"),dict(FACTS,item="wrong"),dict(FACTS,estimated_delivery="tomorrow"),dict(FACTS,guarantee="permanent")]
        texts=[json.dumps(v) for v in values]+["Refund succeeded. "+json.dumps(FACTS),json.dumps(FACTS)[:-1]+',"refund_issued":true}',"{}","null"]
        for text in texts:
            with self.subTest(text=text):
                w,s,d,_=copy.deepcopy(self.base); w["final_facts_text"]=w["phases"][-1]["answer"]=text
                self.assertFalse(all(self.checks(w,s,d).values()))
    def test_receiver_and_effect_mutations(self):
        for field in ("requests","effects"):
            w,s,d,_=copy.deepcopy(self.base); s[field].append(copy.deepcopy(s[field][-1]))
            self.assertFalse(all(self.checks(w,s,d).values()))
        w,s,d,_=copy.deepcopy(self.base); s["effect_counts"]["refund"]=1
        self.assertFalse(all(self.checks(w,s,d).values()))
    def test_malformed_and_timeout(self):
        self.assertFalse(all(self.checks({}, {}, []).values()))
        self.assertFalse(all(runner.verify(*self.base[:3],0,211,True,MODEL,REGION,PORT).values()))
    def test_trusted_customer_rendering(self):
        reply=runner.customer_reply(FACTS)
        self.assertIn(FACTS["confirmation_id"],reply)
        self.assertIn("No refund was issued.",reply)

class GuardTests(unittest.TestCase):
    def setUp(self):
        self.shipment=agent.ShipmentTools(f"http://127.0.0.1:{PORT}","http://127.0.0.1:12345")
        self.guard=agent.EvidenceMiddleware(self.shipment)
    def test_multi_tool_rejected_before_execution(self):
        msg=AIMessage(content="",tool_calls=[{"id":"a","name":"read_order","args":{}},{"id":"b","name":"read_order","args":{}}])
        with self.assertRaisesRegex(RuntimeError,"Multiple tool calls"): self.guard.wrap_model_call(None,lambda _:ModelResponse(result=[msg]))
        self.assertEqual(self.shipment.attempts,0)
    def test_missing_usage_rejected(self):
        with self.assertRaisesRegex(RuntimeError,"token usage"): self.guard.wrap_model_call(None,lambda _:ModelResponse(result=[AIMessage(content="hello")]))
    def test_model_budget_blocks_call(self):
        self.guard.attempts=agent.MAX_MODEL_CALLS
        with self.assertRaisesRegex(RuntimeError,"budget"): self.guard.wrap_model_call(None,lambda _:self.fail("Handler should not run"))
    def test_tool_budget_blocks_request(self):
        self.shipment.attempts=agent.MAX_TOOL_CALLS
        with self.assertRaisesRegex(RuntimeError,"budget"): self.shipment.read_order()
    def test_concurrent_tool_lock(self):
        self.guard.tool_lock.acquire()
        with self.assertRaisesRegex(RuntimeError,"Concurrent"): self.guard.wrap_tool_call(None,lambda _:self.fail("Handler should not run"))
        self.guard.tool_lock.release()
    def test_unmatched_tool_rejected(self):
        request=types.SimpleNamespace(tool_call={"id":"x","name":"read_order","args":{}})
        with self.assertRaisesRegex(RuntimeError,"does not match"): self.guard.wrap_tool_call(request,lambda _:self.fail("Handler should not run"))
    def test_service_url_validation(self):
        for service in ("http://example.com:80","http://127.0.0.1:80?x=1","http://user@127.0.0.1:80"):
            with self.assertRaises(ValueError): agent.ShipmentTools(service,"http://127.0.0.1:12345")
    def test_no_broad_library_grant(self):
        with self.assertRaises(ValueError): runner.read_grants({"library_dirs":["/usr"]},HERE/"vendor",HERE/"evidence")
    def test_duplicate_start_rejected(self):
        self.assertEqual(runner.parse_agent_output('LANGCHAIN_START {"pid":1}\nLANGCHAIN_START {"pid":1}\nLANGCHAIN_RESULT {"pid":1}'),{})

if __name__=="__main__": unittest.main(verbosity=2)
