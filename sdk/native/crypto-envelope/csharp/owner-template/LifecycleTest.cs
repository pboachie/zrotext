using Zrotext.Candidate;
internal static class LifecycleTest {
 internal static void Run(string origin,OwnerTemplate.Binding binding,byte[] template,Func<OwnerTemplate.Session> sessions,string roots){
  using var entered=new CountdownEvent(8);using var settled=new CountdownEvent(8);using var release=new ManualResetEventSlim();var clients=new List<OwnerTemplate>();var threads=new List<Thread>();var failures=new System.Collections.Concurrent.ConcurrentQueue<Exception>();
  ThreadPool.GetMinThreads(out int oldWorkers,out int oldIo);ThreadPool.SetMinThreads(Math.Max(8,oldWorkers),oldIo);
  OwnerTemplate.Current Blocked(){entered.Signal();try{if(!release.Wait(10000))throw new Exception("Callback release missing");throw new OwnerTemplate.Failure("synthetic");}finally{settled.Signal();}}
  try{
   for(int i=0;i<8;i++)clients.Add(new(origin,binding,template,Blocked,sessions,true,10000,roots));
   foreach(var client in clients){var thread=new Thread(()=>{try{client.ReadLatest();failures.Enqueue(new Exception("Closed client returned snapshot"));}catch(OwnerTemplate.Failure){}catch(Exception error){failures.Enqueue(error);}});threads.Add(thread);thread.Start();}
   if(!entered.Wait(8000))throw new Exception("Workers did not enter callbacks");Expect(clients[0],"busy");foreach(var client in clients)client.Dispose();
   foreach(var thread in threads)if(!thread.Join(2000))throw new Exception("Close did not settle foreground");if(!failures.IsEmpty)throw new AggregateException(failures);
   bool recovered=false;using var ninth=new OwnerTemplate(origin,binding,template,()=>{recovered=true;throw new OwnerTemplate.Failure("synthetic");},sessions,true,10000,roots);Expect(ninth,"capacity");release.Set();var watch=System.Diagnostics.Stopwatch.StartNew();
   for(;;){try{ninth.ReadLatest();throw new Exception("Unexpected snapshot");}catch(OwnerTemplate.Failure error){if((error.Code=="owner_changed" || error.Code=="closed") && recovered)break;if(error.Code!="capacity" || watch.ElapsedMilliseconds>3000)throw;Thread.Sleep(5);}}
  }finally{release.Set();foreach(var client in clients)client.Dispose();foreach(var thread in threads)thread.Join(2000);settled.Wait(10000);ThreadPool.SetMinThreads(oldWorkers,oldIo);}
 }
 private static void Expect(OwnerTemplate client,string code){try{client.ReadLatest();throw new Exception("Expected "+code);}catch(OwnerTemplate.Failure error){if(error.Code!=code)throw;}}
}
