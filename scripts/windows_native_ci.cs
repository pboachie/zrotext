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
    const int LogonWithProfile = 1;
    public static string Stage = "not-started";
    public static int ErrorCode;
    public static string LaunchState = "not-started", ResumeState = "not-attempted", WaitState = "not-attempted", ExitState = "not-queried";
    public static string ProbeState = "not-started", CleanupState = "not-started";
    static uint PhaseTimeout(int phase) {if(phase==0)return 30000;if(phase==1)return 300000;throw new ArgumentOutOfRangeException();}
    static bool ProbeComplete(uint code,uint active) {return code==0 && active==0;}
    static string CleanupTarget(bool job,bool assigned,bool process) {return job&&assigned?"job":process?"process":"none";}
    static string ProbeCommand(string executable) {
        if(String.IsNullOrEmpty(executable) || executable.IndexOfAny(new[]{'\0','\r','\n','"'})>=0 || executable.EndsWith("\\") || executable.Length>=1000)throw new ArgumentException("Invalid probe executable.");
        return "\""+executable+"\" --list";
    }
    static string ResumeClass(uint value) {return value==0xffffffff?"failed":value==0?"zero":value==1?"one":"greater-than-one";}
    static string WaitClass(uint value) {return value==0?"signaled":value==258?"timeout":"failed";}
    static string ExitClass(bool queried,uint value) {return !queried?"query-failed":value==0?"zero":value==259?"still-active-code":"other";}
    public static string JobState = "not-observed", NoWindowProbeState = "not-started";
    // Fixed classes only: never report arbitrary process names or paths.
    static readonly string[] KnownImages = {"conhost.exe","openconsole.exe","werfault.exe","wermgr.exe","csrss.exe","consent.exe"};
    static string ImageClass(string image,string probe) {
        if(String.IsNullOrEmpty(image))return "unreadable";
        string name=System.IO.Path.GetFileName(image).ToLowerInvariant();
        if(name==System.IO.Path.GetFileName(probe).ToLowerInvariant())return "probe";
        return Array.IndexOf(KnownImages,name)>=0?name:"other";
    }
    // NTSTATUS/exit codes are fixed numeric classes, not user data.
    static string ExitCodeClass(uint code) {return code==0?"zero":code==259?"still-active-code":"0x"+code.ToString("x8");}
    public static void TestDiagnostics() {
        Check(LogonWithProfile==1,"pure-fixture-profile-policy");
        Check(ResumeClass(0)=="zero" && ResumeClass(1)=="one" && ResumeClass(2)=="greater-than-one" && ResumeClass(0xffffffff)=="failed","pure-resume-classes");
        Check(WaitClass(0)=="signaled" && WaitClass(258)=="timeout" && WaitClass(0xffffffff)=="failed","pure-wait-classes");
        Check(ExitClass(false,0)=="query-failed" && ExitClass(true,0)=="zero" && ExitClass(true,259)=="still-active-code" && ExitClass(true,1)=="other","pure-exit-classes");
        Check(PhaseTimeout(0)==30000 && PhaseTimeout(1)==300000,"pure-phase-bounds");
        bool invalidPhase=false;try{PhaseTimeout(2);}catch(ArgumentOutOfRangeException){invalidPhase=true;}Check(invalidPhase,"pure-phase-refusal");
        Check(ProbeComplete(0,0) && !ProbeComplete(1,0) && !ProbeComplete(0,1),"pure-probe-gate");
        Check(CleanupTarget(true,true,true)=="job" && CleanupTarget(true,true,false)=="job" && CleanupTarget(true,false,true)=="process" && CleanupTarget(false,false,true)=="process" && CleanupTarget(true,false,false)=="none","pure-owned-cleanup-selection");
        Check(ProbeCommand("fixture suite.exe")=="\"fixture suite.exe\" --list","pure-probe-command");
        Check(ImageClass(@"fixture\bin\Suite.EXE",@"x\suite.exe")=="probe" && ImageClass(@"System32\conhost.exe","suite.exe")=="conhost.exe" && ImageClass(@"System32\WerFault.exe","suite.exe")=="werfault.exe","pure-image-known-classes");
        Check(ImageClass(@"Tools\unrelated-tool.exe","suite.exe")=="other" && ImageClass("","suite.exe")=="unreadable" && ImageClass(null,"suite.exe")=="unreadable","pure-image-other-classes");
        Check(ExitCodeClass(0)=="zero" && ExitCodeClass(259)=="still-active-code" && ExitCodeClass(0xc0000142)=="0xc0000142" && ExitCodeClass(1)=="0x00000001","pure-exit-code-classes");
        foreach(string value in new[]{"","bad\"arg","bad\narg","bad\0arg","trailing\\",new string('x',1000)}) {
            bool rejected=false;try{ProbeCommand(value);}catch(ArgumentException){rejected=true;}Check(rejected,"pure-probe-argument-refusal");
        }
        // A cleanup failure must not erase the first failing operation.
        try {try{Check(false,"pure-first-failure");}finally{Check(false,"pure-cleanup-failure");}}catch(InvalidOperationException){}
        bool firstPreserved=Stage=="pure-first-failure";Stage="not-started";ErrorCode=0;
        Check(firstPreserved,"pure-first-failure-preserved");
    }
    static void Check(bool ok, string stage) {
        if (!ok) { if(Stage=="not-started"){Stage = stage; ErrorCode = Marshal.GetLastWin32Error();} throw new InvalidOperationException("native fixture refused"); }
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
    [DllImport("kernel32.dll",SetLastError=true,EntryPoint="QueryInformationJobObject")] static extern bool QueryJobList(IntPtr job,int kind,IntPtr buffer,int length,IntPtr needed);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr process,uint flags,StringBuilder name,ref uint size);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    [DllImport("user32.dll")] static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll")] static extern IntPtr GetThreadDesktop(uint tid);
    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetUserObjectInformationW(IntPtr handle,int index,StringBuilder buffer,int length,out int needed);
    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenWindowStationW(string name,bool inherit,uint access);
    [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenDesktopW(string name,uint flags,bool inherit,uint access);
    [DllImport("user32.dll",SetLastError=true)] static extern bool CloseWindowStation(IntPtr handle);
    [DllImport("user32.dll",SetLastError=true)] static extern bool CloseDesktop(IntPtr handle);
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
    // Window station and desktop rights granted only to the fixture logon SID
    // for the duration of Run, then removed by CleanDesktop.
    const uint StationGrant = 0x37f;     // WINSTA_ALL_ACCESS
    const uint DesktopGrant = 0x000f01ff; // DESKTOP_ALL_ACCESS incl. standard rights
    static RawAcl WithFixtureGrant(RawAcl source,string sid,uint mask) {
        var result=new RawAcl(source.Revision,source.Count+1);
        foreach(GenericAce ace in source) result.InsertAce(result.Count,ace);
        result.InsertAce(result.Count,new CommonAce(AceFlags.None,AceQualifier.AccessAllowed,unchecked((int)mask),new SecurityIdentifier(sid),false,null));
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
        // The grant appends exactly one allow ACE for the logon SID, keeps every
        // existing ACE in order, and is fully removed by the cleanup filter.
        var granted=WithFixtureGrant(filtered,"S-1-5-5-1-2",DesktopGrant);
        Check(granted.Count==filtered.Count+1,"pure-acl-grant-count");
        for(int i=0;i<filtered.Count;i++) Check(AceKey(granted[i])==AceKey(filtered[i]),"pure-acl-grant-preserves-existing");
        var grant=granted[granted.Count-1] as CommonAce;
        Check(grant!=null && grant.AceQualifier==AceQualifier.AccessAllowed && grant.SecurityIdentifier.Value=="S-1-5-5-1-2" && unchecked((uint)grant.AccessMask)==DesktopGrant && grant.AceFlags==AceFlags.None,"pure-acl-grant-shape");
        var restored=WithoutFixture(granted,sids);
        Check(restored.Count==filtered.Count,"pure-acl-grant-removed-count");
        for(int i=0;i<filtered.Count;i++) Check(AceKey(restored[i])==AceKey(filtered[i]),"pure-acl-grant-removed-exactly");
        Check(filtered.Count==2,"pure-acl-grant-source-unchanged");
    }
    static string ObjectName(IntPtr handle) {
        int needed;
        GetUserObjectInformationW(handle,2,null,0,out needed);
        Check(needed>2 && needed<=512,"desktop-name-size");
        var name=new StringBuilder(needed/2);
        Check(GetUserObjectInformationW(handle,2,name,needed,out needed),"desktop-name-read");
        string value=name.ToString();
        Check(value.Length>0 && value.Length<128 && value.IndexOfAny(new[]{'\\','\0'})<0,"desktop-name-shape");
        return value;
    }
    static void Grant(IntPtr handle,string sid,uint mask,string stage) {
        var current=Descriptor(handle);
        current.DiscretionaryAcl=WithFixtureGrant(current.DiscretionaryAcl,sid,mask);
        byte[] bytes=new byte[current.BinaryLength];current.GetBinaryForm(bytes,0);
        uint info=4;Check(SetUserObjectSecurity(handle,ref info,bytes),stage);
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
    static string JobImages(IntPtr job,string probe) {
        const int max=32;
        int length=8+max*IntPtr.Size;
        IntPtr buffer=Marshal.AllocHGlobal(length);
        try {
            if(!QueryJobList(job,3,buffer,length,IntPtr.Zero))return "list-failed";
            int listed=Math.Min(Marshal.ReadInt32(buffer,4),max);
            var classes=new List<string>();
            for(int i=0;i<listed;i++) {
                uint pid=(uint)Marshal.ReadIntPtr(buffer,8+i*IntPtr.Size).ToInt64();
                string image=null;
                IntPtr handle=OpenProcess(0x1000,false,pid);
                if(handle!=IntPtr.Zero) {
                    try {var name=new StringBuilder(1024);uint size=(uint)name.Capacity;if(QueryFullProcessImageNameW(handle,0,name,ref size))image=name.ToString();}
                    finally {CloseHandle(handle);}
                }
                classes.Add(ImageClass(image,probe));
            }
            classes.Sort(StringComparer.Ordinal);
            return listed==0?"empty":String.Join(",",classes);
        } finally {Marshal.FreeHGlobal(buffer);}
    }
    static bool EmptyJob(IntPtr job) {
        for(int i=0;i<100;i++){Accounting value;if(QueryInformationJobObject(job,1,out value,Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero)&&value.activeProcesses==0)return true;Thread.Sleep(100);}
        return false;
    }
    // Diagnostic only: the same probe without a console. Its result never
    // gates the run; it tells console startup failures apart from others.
    static string NoWindowProbe(IntPtr token,string probe,string command,IntPtr env,string cwd,IntPtr desktopPath,IntPtr job) {
        var startup=new Startup{cb=Marshal.SizeOf(typeof(Startup)),desktop=desktopPath};
        Process p;
        if(!CreateProcessWithTokenW(token,LogonWithProfile,probe,new StringBuilder(command),0x08000404,env,cwd,ref startup,out p))return "create-failed-"+Marshal.GetLastWin32Error();
        try {
            if(!AssignProcessToJobObject(job,p.process)){TerminateProcess(p.process,99);WaitForSingleObject(p.process,10000);return "assign-failed";}
            if(ResumeThread(p.thread)==0xffffffff){TerminateJobObject(job,99);EmptyJob(job);return "resume-failed";}
            if(WaitForSingleObject(p.process,30000)!=0){string images=JobImages(job,probe);TerminateJobObject(job,99);return "timeout["+images+"]"+(EmptyJob(job)?"":"-not-emptied");}
            uint code;if(!GetExitCodeProcess(p.process,out code))return "exit-query-failed";
            if(!EmptyJob(job)){TerminateJobObject(job,99);EmptyJob(job);return "exit-"+ExitCodeClass(code)+"-job-not-empty";}
            return "exit-"+ExitCodeClass(code);
        } finally {CloseHandle(p.thread);CloseHandle(p.process);}
    }
    public static void DeleteProfile(string sid) {Check(DeleteProfileW(sid,null,null),"profile-cleanup");}

    public static int Run(string user,string expectedSid,SecureString password,string executable,string command,string environment,string cwd,string probeExecutable) {
        Stage="not-started";ErrorCode=0;ProbeState="not-started";CleanupState="not-started";
        LaunchState="not-started";ResumeState="not-attempted";WaitState="not-attempted";ExitState="not-queried";
        JobState="not-observed";NoWindowProbeState="not-started";
        Check(command.Length<1024 && command.IndexOf('\0')<0,"command-bound");
        string probeCommand=ProbeCommand(probeExecutable);
        IntPtr passwordBuffer=IntPtr.Zero,tokenHandle=IntPtr.Zero,env=IntPtr.Zero,job=IntPtr.Zero;
        Process process=new Process(); bool assigned=false; bool cleanup=true; bool desktopAccessMayChange=false;
        IntPtr station=IntPtr.Zero,desktop=IntPtr.Zero,desktopPath=IntPtr.Zero;
        RawSecurityDescriptor stationBefore=null,desktopBefore=null;
        HashSet<string> fixtureSids=null;
        try {
            passwordBuffer=Marshal.SecureStringToGlobalAllocUnicode(password);
            try{Check(LogonUserW(user,".",passwordBuffer,2,0,out tokenHandle),"fixture-logon");}
            finally{Marshal.ZeroFreeGlobalAllocUnicode(passwordBuffer);passwordBuffer=IntPtr.Zero;}
            Check(Scalar(tokenHandle,8)==1 && Scalar(tokenHandle,20)==0 && User(tokenHandle)==expectedSid,"fixture-standard-primary-identity");
            string logonSid=LogonSid(tokenHandle);
            fixtureSids=new HashSet<string>{expectedSid,logonSid};
            IntPtr currentStation=GetProcessWindowStation(),currentDesktop=GetThreadDesktop(GetCurrentThreadId());
            Check(currentStation!=IntPtr.Zero && currentDesktop!=IntPtr.Zero,"desktop-handles");
            string stationName=ObjectName(currentStation),desktopName=ObjectName(currentDesktop);
            // CreateProcessWithTokenW does not grant the new logon access to the
            // caller's window station and desktop; without it the child's console
            // cannot start. Open writable handles by name for a scoped grant.
            station=OpenWindowStationW(stationName,false,0x60000);Check(station!=IntPtr.Zero,"station-open-dacl");
            desktop=OpenDesktopW(desktopName,0,false,0x60000);Check(desktop!=IntPtr.Zero,"desktop-open-dacl");
            stationBefore=Descriptor(station);desktopBefore=Descriptor(desktop);
            foreach(GenericAce ace in stationBefore.DiscretionaryAcl) Check(!FixtureAce(ace,fixtureSids),"station-no-preexisting-fixture-ace");
            foreach(GenericAce ace in desktopBefore.DiscretionaryAcl) Check(!FixtureAce(ace,fixtureSids),"desktop-no-preexisting-fixture-ace");
            desktopAccessMayChange=true;
            Grant(station,logonSid,StationGrant,"station-grant");
            Grant(desktop,logonSid,DesktopGrant,"desktop-grant");
            desktopPath=Marshal.StringToHGlobalUni(stationName+"\\"+desktopName);
            job=CreateJobObjectW(IntPtr.Zero,null);Check(job!=IntPtr.Zero,"job-create");
            var limits=new ExtendedLimit();limits.basic.flags=0x2000;
            Check(SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(typeof(ExtendedLimit))),"job-kill-on-close");
            env=Marshal.StringToHGlobalUni(environment);
            NoWindowProbeState=NoWindowProbe(tokenHandle,probeExecutable,probeCommand,env,cwd,desktopPath,job);
            for(int phase=0;phase<2;phase++) {
            bool probing=phase==0;
            if(probing)ProbeState="running";
            var startup=new Startup{cb=Marshal.SizeOf(typeof(Startup)),desktop=desktopPath,flags=1,show=0};
            Check(CreateProcessWithTokenW(tokenHandle,LogonWithProfile,probing?probeExecutable:executable,new StringBuilder(probing?probeCommand:command),0x414,env,cwd,ref startup,out process),probing?"probe-create-suspended":"worker-create-suspended");
            LaunchState="created-suspended";
            Check(AssignProcessToJobObject(job,process.process),"worker-job-assign");assigned=true;
            LaunchState="job-assigned";
            uint resumed=ResumeThread(process.thread);ResumeState=ResumeClass(resumed);
            Check(resumed!=0xffffffff,"worker-resume");
            uint waited=WaitForSingleObject(process.process,PhaseTimeout(phase));WaitState=WaitClass(waited);
            Check(waited==0,probing?"probe-timeout":"worker-timeout");
            uint code;Check(GetExitCodeProcess(process.process,out code),"worker-exit-query");
            if(!probing){Check(code<=int.MaxValue,"worker-exit-bound");return (int)code;}
            ExitState=ExitClass(true,code);
            Accounting probeAccounting;
            Check(QueryInformationJobObject(job,1,out probeAccounting,Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero),"probe-job-query");
            // An attached conhost still alive is a probe/cleanup failure, not
            // evidence about PowerShell. Do not start phase two in that case.
            Check(ProbeComplete(code,probeAccounting.activeProcesses),"probe-exit-or-job-not-empty");
            Check(CloseHandle(process.thread),"probe-thread-close");process.thread=IntPtr.Zero;
            Check(CloseHandle(process.process),"probe-process-close");process.process=IntPtr.Zero;
            process=new Process();assigned=false;ProbeState="passed";
            LaunchState="not-started";ResumeState="not-attempted";WaitState="not-attempted";ExitState="not-queried";
            }
            throw new InvalidOperationException("Invalid native phase.");
        } finally {
            if(ProbeState=="running")ProbeState="failed";
            // Observe before terminating the owned job. Code 259 alone does not
            // establish liveness; interpret it alongside the wait result.
            if(process.process!=IntPtr.Zero) {uint observed;bool queried=GetExitCodeProcess(process.process,out observed);ExitState=ExitClass(queried,observed);}
            if(passwordBuffer!=IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(passwordBuffer);
            string cleanupTarget=CleanupTarget(job!=IntPtr.Zero,assigned,process.process!=IntPtr.Zero);
            if(cleanupTarget=="job") {
                if(WaitState=="timeout")JobState=JobImages(job,probeExecutable);
                cleanup &= TerminateJobObject(job,99);
                bool empty=false;
                for(int i=0;i<100;i++){Accounting value;if(QueryInformationJobObject(job,1,out value,Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero)&&value.activeProcesses==0){empty=true;break;}Thread.Sleep(100);}
                cleanup &= empty;
            } else if(cleanupTarget=="process") {cleanup &= TerminateProcess(process.process,99);cleanup &= WaitForSingleObject(process.process,10000)==0;}
            if(process.thread!=IntPtr.Zero) cleanup &= CloseHandle(process.thread);
            if(process.process!=IntPtr.Zero) cleanup &= CloseHandle(process.process);
            if(job!=IntPtr.Zero) cleanup &= CloseHandle(job);
            if(env!=IntPtr.Zero) Marshal.FreeHGlobal(env);
            if(desktopAccessMayChange && desktopBefore!=null) {try{CleanDesktop(desktop,desktopBefore,fixtureSids);}catch{cleanup=false;}}
            if(desktopAccessMayChange && stationBefore!=null) {try{CleanDesktop(station,stationBefore,fixtureSids);}catch{cleanup=false;}}
            if(desktop!=IntPtr.Zero) cleanup &= CloseDesktop(desktop);
            if(station!=IntPtr.Zero) cleanup &= CloseWindowStation(station);
            if(desktopPath!=IntPtr.Zero) Marshal.FreeHGlobal(desktopPath);
            if(tokenHandle!=IntPtr.Zero) cleanup &= CloseHandle(tokenHandle);
            CleanupState=cleanup?"passed":"failed";
            Check(cleanup,"native-cleanup");
        }
    }
}
}
