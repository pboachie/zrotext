"""Copied local draft review, maintained differential, explicit-only synthetic POST."""
import argparse,base64,importlib.util,json,socket,ssl,subprocess,tempfile,threading
from pathlib import Path
spec=importlib.util.spec_from_file_location('save',Path(__file__).with_name('test-template-save.py'));save=importlib.util.module_from_spec(spec);spec.loader.exec_module(save)
PIN='059556de2fe314ec0d88833a8d3e4d6ee41a8066'
def main():
 p=argparse.ArgumentParser();p.add_argument('--producer',type=Path,required=True);p.add_argument('--authoring-oracle',type=Path,required=True)
 g=p.add_mutually_exclusive_group(required=True);g.add_argument('--binary');g.add_argument('--command-file',type=Path);a=p.parse_args()
 for folder,pin in [(a.producer,save.cold.PIN),(a.authoring_oracle,PIN)]:
  assert subprocess.check_output(['git','-C',str(folder),'rev-parse','HEAD'],text=True).strip()==pin
  assert not subprocess.check_output(['git','-C',str(folder),'status','--porcelain'],text=True).strip()
 f=json.loads(subprocess.check_output(['node',str(a.producer/'sdk/native/sealed-candidate/python/owner-template-interop.mjs')],text=True,encoding='utf-8'))
 argv=[a.binary] if a.binary else json.loads(a.command_file.read_text(encoding='utf-8'));assert isinstance(argv,list) and argv and all(isinstance(x,str) and x and '\0' not in x for x in argv)
 cases=[];native=[];count=0
 with tempfile.TemporaryDirectory(prefix='zrotext-authoring-') as tmp:
  folder=Path(tmp);roots=save.cold.tls.certificates(folder)
  with save.cold.tls.Server((socket.gethostbyname('localhost'),0),save.Handler) as server:
   ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(folder/'cert.pem',folder/'key.pem');server.socket=ctx.wrap_socket(server.socket,server_side=True)
   threading.Thread(target=server.serve_forever,daemon=True).start();origin='https://'+server.server_address[0]+':'+str(server.server_address[1])
   def run(expected=True,oracle=None,**changes):
    nonlocal count
    server.calls=[];server.responses=[dict(network=True),{}] if changes.get('PriorUnknown') else [{}];server.envelope=f['envelope'];server.deadline_ms=4000
    value=dict(Fixture=f,Origin=origin,Roots=roots,Cookie='synthetic-owner=opaque',CSRF='synthetic-csrf',Enabled=True,TimeoutMS=4000,ValidForMS=10000,Now=[10000],Mode='',Template=f['content']['template'],Values=f['content']['values'],CustodyLive=True,Decision=True,Repeat=1);value.update(changes)
    out=subprocess.run(argv,input=json.dumps(value),text=True,encoding='utf-8',capture_output=True,timeout=20,check=True);r=json.loads(out.stdout)
    assert r['accepted']==([expected] if value['Repeat']==1 else [expected,False]),(count,changes,r)
    assert len(server.calls)==(int(value.get('PriorUnknown',False))+(1 if value.get('Commit') and (expected or value.get('PriorSaved') or value.get('PriorUnknown') or value.get('ForeignReview')) and not value.get('ProbeExpired') else 0)),(count,changes,r,len(server.calls))
    assert f['preview']['text'] not in out.stdout
    if value.get('ProbeExpired'):assert not r['ack'] and not r['fresh'] and not r['read']
    if value.get('Commit') and (expected or value.get('PriorSaved') or value.get('PriorUnknown') or value.get('ForeignReview')) and not value.get('ProbeExpired'):
     assert r['ack'];method,path,headers,wire=server.calls[-1];assert method=='POST' and path=='/v1/owner/workflow/templates' and headers['idempotency-key']==save.REQUEST
     check=json.loads(subprocess.check_output(['node',str(a.producer/'sdk/native/sealed-candidate/python/template-interop.mjs'),'--consume'],input=json.dumps(dict(fixture=f,envelope=base64.b64encode(wire).decode(),expectedCanonical=f['canonical'])),text=True,encoding='utf-8'));assert check['verified']
    if value.get('ReviewSleepMS') or value.get('CurrentSleepAt'):assert r['elapsed']<value['TimeoutMS']/1000+.6
    if oracle is not None:cases.append(oracle);native.append(dict(accepted=expected,reviewed=r['reviewed'],metadata=r['metadata'],posts=0))
    count+=1;return r
   try:
    run(oracle={});run(Commit=True);run(Commit=True,Repeat=2);run(Commit=True,ReviewBlock=True);run(Commit=True,ProbeExpired=True,ValidForMS=100,DelayMS=150)
    run(False,PriorSaved=True,Commit=True);run(False,PriorUnknown=True,Commit=True)
    run(False,ForeignReview=True,ReviewBlock=True,Decision=False,Commit=True)
    run(False,ForeignReview=True,ReviewBlock=True,Decision=True,Commit=True)
    run(False,ForeignReview=True,ReviewBlock=True,Decision=True,CurrentFailAt=4,Commit=True)
    run(False,oracle=dict(decision=False),Decision=False)
    for name,key in [('EpochChanged','epochChanged'),('RevisionChanged','revisionChanged'),('CustodyLost','custodyLost'),('OwnerLost','ownerLost'),('CSRFChanged','csrfChanged')]:run(False,oracle={key:True},**{name:True})
    run(False,oracle=dict(custodyLive=False),CustodyLive=False)
    run(False,oracle=dict(template='{{__proto__}}',values={}),Template='{{__proto__}}',Values={})
    for at in range(1,7):run(False,CurrentFailAt=at)
    for at in [2,4,6]:run(False,ClientCloseAt=at)
    run(False,ReviewSleepMS=400,TimeoutMS=100,SettleMS=450,Repeat=2)
    run(False,CurrentSleepAt=4,SleepMS=400,TimeoutMS=100,SettleMS=450,Repeat=2)
    run(False,CurrentSleepAt=6,SleepMS=400,TimeoutMS=100,SettleMS=450,Repeat=2)
   finally:server.shutdown()
 actual=json.loads(subprocess.check_output(['node',str(a.authoring_oracle/'sdk/native/sealed-candidate/python/template-authoring-interop.mjs')],input=json.dumps(dict(fixture=f,cases=cases)),text=True,encoding='utf-8'))
 assert actual==native,(actual,native)
 print(f'{count} native authoring controls passed; {len(cases)} maintained draft differentials passed; explicit commits independently opened')
if __name__=='__main__':main()
