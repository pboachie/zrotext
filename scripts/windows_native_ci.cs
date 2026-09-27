// SPDX-License-Identifier: AGPL-3.0-only
// CI fixture only. Compile checks may run locally; Run is called only after
// the PowerShell fixture has verified the disposable GitHub-hosted VM guards.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace ZrotextCi {
public static class Native {
    public static string Stage = "not-started";
    public static int ErrorCode;
    static void Check(bool ok, string stage) {
        if (!ok) { Stage = stage; ErrorCode = Marshal.GetLastWin32Error(); throw new InvalidOperationException("native fixture refused"); }
    }
    [StructLayout(LayoutKind.Sequential)] struct Startup {
        public int cb; public IntPtr reserved, desktop, title;
        public int x,y,xsize,ysize,xchars,ychars,fill,flags;
        public short show,reservedSize; public IntPtr reservedBytes,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct Process { public IntPtr process,thread; public uint pid,tid; }
    [StructLayout(LayoutKind.Sequential)] struct SidAttributes { public IntPtr sid; public uint attributes; }
    [StructLayout(LayoutKind.Sequential)] struct TokenGroupsFirst { public uint count; public SidAttributes first; }
    [StructLayout(LayoutKind.Sequential)] struct BasicLimit {
        public long processTime,jobTime; public uint flags;
        public UIntPtr minimum,maximum; public uint processes;
        public UIntPtr affinity; public uint priority,scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong readOps,writeOps,otherOps,readBytes,writeBytes,otherBytes; }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit {
        public BasicLimit basic; public IoCounters io;
        public UIntPtr processMemory,jobMemory,peakProcess,peakJob;
    }
    [StructLayout(LayoutKind.Sequential)] struct Accounting {
        public long user,kernel,thisUser,thisKernel;
        public uint faults,totalProcesses,activeProcesses,terminatedProcesses;
    }
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LogonUserW(string user,string domain,IntPtr password,int type,int provider,out IntPtr token);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessWithTokenW(IntPtr token,int logon,string app,StringBuilder command,int flags,IntPtr environment,string cwd,ref Startup startup,out Process process);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr buffer,int length,out int needed);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool ProcessIdToSessionId(uint pid,out uint session);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenThreadToken(IntPtr thread,uint access,bool self,out IntPtr token);
    [DllImport("wtsapi32.dll",SetLastError=true)] static extern bool WTSQuerySessionInformationW(IntPtr server,uint session,int kind,out IntPtr buffer,out uint bytes);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr buffer);
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr attributes,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref ExtendedLimit value,int length);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out Accounting value,int length,IntPtr needed);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint tid);
    [DllImport("user32.dll",SetLastError=true)] static extern bool GetUserObjectSecurity(IntPtr handle,ref uint info,byte[] buffer,uint length,out uint needed);
    [DllImport("user32.dll",SetLastError=true)] static extern bool SetUserObjectSecurity(IntPtr handle,ref uint info,byte[] buffer);
    [DllImport("userenv.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool DeleteProfileW(string sid,string path,string computer);

    static T Token<T>(IntPtr token,int kind,Func<IntPtr,int,T> inspect) {
        int needed;
        GetTokenInformation(token,kind,IntPtr.Zero,0,out needed);
        Check(needed>0 && needed<=65536,"token-size");
        IntPtr memory=Marshal.AllocHGlobal(needed);
        try { int actual; Check(GetTokenInformation(token,kind,memory,needed,out actual) && actual<=needed,"token-query"); return inspect(memory,actual); }
        finally { Marshal.FreeHGlobal(memory); }
    }
    static int Scalar(IntPtr token,int kind) { return Token(token,kind,(p,n)=>{Check(n==4,"token-scalar-size");return Marshal.ReadInt32(p);}); }
    static string User(IntPtr token) { return Token(token,1,(p,n)=>{Check(n>=IntPtr.Size,"token-user-size");return new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value;}); }
    static string LogonSid(IntPtr token) {
        return Token(token,2,(p,n)=>{
            int count=Marshal.ReadInt32(p), start=(int)Marshal.OffsetOf(typeof(TokenGroupsFirst),"first"), width=Marshal.SizeOf(typeof(SidAttributes));
            Check(count>=0 && count<1024 && start+(long)count*width<=n,"token-groups-size");
            string found=null;
            for(int i=0;i<count;i++) {
                var group=Marshal.PtrToStructure<SidAttributes>(IntPtr.Add(p,start+i*width));
                if((group.attributes & 0xc0000000u)==0xc0000000u) {Check(found==null,"unique-logon-sid");found=new SecurityIdentifier(group.sid).Value;}
            }
            Check(found!=null,"logon-sid-present");return found;
        });
    }
    static RawSecurityDescriptor Descriptor(IntPtr handle) {
        uint info=4, needed;
        GetUserObjectSecurity(handle,ref info,null,0,out needed);
        Check(needed>0 && needed<=65536,"desktop-dacl-size");
        byte[] bytes=new byte[needed];
        Check(GetUserObjectSecurity(handle,ref info,bytes,needed,out needed),"desktop-dacl-read");
        var descriptor=new RawSecurityDescriptor(bytes,0);
        Check(descriptor.DiscretionaryAcl!=null,"desktop-dacl-present");return descriptor;
    }
    static string AceKey(GenericAce ace) {byte[] bytes=new byte[ace.BinaryLength];ace.GetBinaryForm(bytes,0);return Convert.ToBase64String(bytes);}
    static bool FixtureAce(GenericAce ace,HashSet<string> sids) {var known=ace as KnownAce;return known!=null && sids.Contains(known.SecurityIdentifier.Value);}
    static RawAcl WithoutFixture(RawAcl source,HashSet<string> sids) {
        var result=new RawAcl(source.Revision,source.Count);
        foreach(GenericAce ace in source) if(!FixtureAce(ace,sids)) result.InsertAce(result.Count,ace);
        return result;
    }
    public static void TestAclFilter() {
        var before=new RawSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GR;;;BU)(D;;GW;;;S-1-5-5-1-2)(A;;GR;;;SY)");
        var sids=new HashSet<string>{"S-1-5-32-545","S-1-5-5-1-2"};
        var filtered=WithoutFixture(before.DiscretionaryAcl,sids);
        Check(filtered.Count==2,"pure-acl-filter-count");
        Check(AceKey(filtered[0])==AceKey(before.DiscretionaryAcl[0]) && AceKey(filtered[1])==AceKey(before.DiscretionaryAcl[3]),"pure-acl-preserve-unrelated-order");
        Check(WithoutFixture(filtered,sids).Count==2,"pure-acl-filter-idempotent");
        Check(before.DiscretionaryAcl.Count==4,"pure-acl-source-unchanged");
    }
    static void CleanDesktop(IntPtr handle,RawSecurityDescriptor before,HashSet<string> sids) {
        var current=Descriptor(handle);
        var acl=WithoutFixture(current.DiscretionaryAcl,sids);
        bool changed=acl.Count!=current.DiscretionaryAcl.Count;
        var unrelated=new Dictionary<string,int>();
        foreach(GenericAce ace in acl) {string key=AceKey(ace);unrelated[key]=unrelated.ContainsKey(key)?unrelated[key]+1:1;}
        // Preserve all current unrelated ACEs; do not restore a stale whole DACL.
        current.DiscretionaryAcl=acl;
        byte[] bytes=new byte[current.BinaryLength];current.GetBinaryForm(bytes,0);
        uint info=4;if(changed)Check(SetUserObjectSecurity(handle,ref info,bytes),"desktop-dacl-cleanup");
        var after=Descriptor(handle);
        var remaining=new Dictionary<string,int>();
        foreach(GenericAce ace in after.DiscretionaryAcl) {
            Check(!FixtureAce(ace,sids),"desktop-fixture-ace-removed");
            string key=AceKey(ace);remaining[key]=remaining.ContainsKey(key)?remaining[key]+1:1;
        }
        Check(remaining.Count==unrelated.Count,"desktop-unrelated-ace-count");
        foreach(var pair in unrelated) Check(remaining.ContainsKey(pair.Key)&&remaining[pair.Key]==pair.Value,"desktop-unrelated-ace-preserved");
        foreach(GenericAce ace in before.DiscretionaryAcl) {
            string key=AceKey(ace);Check(remaining.ContainsKey(key)&&remaining[key]>0,"desktop-original-ace-preserved");remaining[key]--;
        }
    }
    public static bool ParentElevated() {
        IntPtr token;Check(OpenProcessToken(GetCurrentProcess(),8,out token),"parent-token");
        try{return Scalar(token,20)!=0;}finally{CloseHandle(token);}
    }
    public static void CheckSession() {
        uint session;Check(ProcessIdToSessionId(GetCurrentProcessId(),out session)&&session!=0,"nonzero-session");
        foreach(int kind in new[]{8,16}) {
            IntPtr memory=IntPtr.Zero;uint bytes;
            try {Check(WTSQuerySessionInformationW(IntPtr.Zero,session,kind,out memory,out bytes),"active-local-session-query");Check(bytes==(kind==8?4u:2u) && (kind==8?Marshal.ReadInt32(memory):Marshal.ReadInt16(memory))==0,"active-local-session-value");}
            finally{if(memory!=IntPtr.Zero)WTSFreeMemory(memory);}
        }
    }
    public static void CheckWorker(string expectedSid) {
        IntPtr token;Check(OpenProcessToken(GetCurrentProcess(),8,out token),"worker-token");
        try {Check(Scalar(token,20)==0 && Scalar(token,8)==1 && User(token)==expectedSid,"worker-standard-primary-identity");}
        finally {CloseHandle(token);}
        IntPtr thread;
        bool impersonating=OpenThreadToken(GetCurrentThread(),8,true,out thread);
        int error=Marshal.GetLastWin32Error();
        if(impersonating)CloseHandle(thread);
        Check(!impersonating && error==1008,"worker-no-impersonation");
        CheckSession();
    }
    public static void DeleteProfile(string sid) {Check(DeleteProfileW(sid,null,null),"profile-cleanup");}

    public static int Run(string user,string expectedSid,SecureString password,string executable,string command,string environment,string cwd) {
        Check(command.Length<1024 && command.IndexOf('\0')<0,"command-bound");
        IntPtr passwordBuffer=IntPtr.Zero,tokenHandle=IntPtr.Zero,env=IntPtr.Zero,job=IntPtr.Zero;
        Process process=new Process(); bool assigned=false; bool cleanup=true; bool desktopAccessMayChange=false;
        IntPtr station=IntPtr.Zero,desktop=IntPtr.Zero;
        RawSecurityDescriptor stationBefore=null,desktopBefore=null;
        HashSet<string> fixtureSids=null;
        try {
            passwordBuffer=Marshal.SecureStringToGlobalAllocUnicode(password);
            try{Check(LogonUserW(user,".",passwordBuffer,2,0,out tokenHandle),"fixture-logon");}
            finally{Marshal.ZeroFreeGlobalAllocUnicode(passwordBuffer);passwordBuffer=IntPtr.Zero;}
            Check(Scalar(tokenHandle,8)==1 && Scalar(tokenHandle,20)==0 && User(tokenHandle)==expectedSid,"fixture-standard-primary-identity");
            fixtureSids=new HashSet<string>{expectedSid,LogonSid(tokenHandle)};
            station=GetProcessWindowStation();desktop=GetThreadDesktop(GetCurrentThreadId());
            Check(station!=IntPtr.Zero && desktop!=IntPtr.Zero,"desktop-handles");
            stationBefore=Descriptor(station);desktopBefore=Descriptor(desktop);
            foreach(GenericAce ace in stationBefore.DiscretionaryAcl) Check(!FixtureAce(ace,fixtureSids),"station-no-preexisting-fixture-ace");
            foreach(GenericAce ace in desktopBefore.DiscretionaryAcl) Check(!FixtureAce(ace,fixtureSids),"desktop-no-preexisting-fixture-ace");
            job=CreateJobObjectW(IntPtr.Zero,null);Check(job!=IntPtr.Zero,"job-create");
            var limits=new ExtendedLimit();limits.basic.flags=0x2000;
            Check(SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(typeof(ExtendedLimit))),"job-kill-on-close");
            env=Marshal.StringToHGlobalUni(environment);
            var startup=new Startup{cb=Marshal.SizeOf(typeof(Startup)),flags=1,show=0};
            desktopAccessMayChange=true;
            Check(CreateProcessWithTokenW(tokenHandle,0,executable,new StringBuilder(command),0x414,env,cwd,ref startup,out process),"worker-create-suspended");
            Check(AssignProcessToJobObject(job,process.process),"worker-job-assign");assigned=true;
            Check(ResumeThread(process.thread)!=0xffffffff,"worker-resume");
            Check(WaitForSingleObject(process.process,300000)==0,"worker-timeout");
            uint code;Check(GetExitCodeProcess(process.process,out code),"worker-exit-query");
            Check(code<=int.MaxValue,"worker-exit-bound");return (int)code;
        } finally {
            if(passwordBuffer!=IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(passwordBuffer);
            if(job!=IntPtr.Zero && assigned) {
                cleanup &= TerminateJobObject(job,99);
                bool empty=false;
                for(int i=0;i<100;i++){Accounting value;if(QueryInformationJobObject(job,1,out value,Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero)&&value.activeProcesses==0){empty=true;break;}Thread.Sleep(100);}
                cleanup &= empty;
            } else if(process.process!=IntPtr.Zero) {cleanup &= TerminateProcess(process.process,99);cleanup &= WaitForSingleObject(process.process,10000)==0;}
            if(process.thread!=IntPtr.Zero) cleanup &= CloseHandle(process.thread);
            if(process.process!=IntPtr.Zero) cleanup &= CloseHandle(process.process);
            if(job!=IntPtr.Zero) cleanup &= CloseHandle(job);
            if(env!=IntPtr.Zero) Marshal.FreeHGlobal(env);
            if(desktopAccessMayChange && desktopBefore!=null) {try{CleanDesktop(desktop,desktopBefore,fixtureSids);}catch{cleanup=false;}}
            if(desktopAccessMayChange && stationBefore!=null) {try{CleanDesktop(station,stationBefore,fixtureSids);}catch{cleanup=false;}}
            if(tokenHandle!=IntPtr.Zero) cleanup &= CloseHandle(tokenHandle);
            Check(cleanup,"native-cleanup");
        }
    }
}
}
