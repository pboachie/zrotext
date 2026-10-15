using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
namespace Zrotext.Candidate;
/// <summary>Host-selected trusted installed native parser asset. No parser callback.</summary>
public sealed class ContactOrigin {
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Predicate(byte[] input,nuint length);
    private readonly IntPtr library;
    private readonly Predicate predicate;
    public ContactOrigin(string artifactDirectory){
        string name=OperatingSystem.IsWindows()?"zrotext_contact_origin.dll":OperatingSystem.IsMacOS()?"libzrotext_contact_origin.dylib":"libzrotext_contact_origin.so";
        library=NativeLibrary.Load(Path.GetFullPath(Path.Combine(artifactDirectory,name)));
        predicate=Marshal.GetDelegateForFunctionPointer<Predicate>(NativeLibrary.GetExport(library,"zrotext_contact_origin_v1"));
    }
    public bool Accepts(string value){
        if(value is null || value.Length<9 || value.Length>512)return false;
        foreach(char c in value)if(c<33 || c>126)return false;
        byte[] bytes=Encoding.ASCII.GetBytes(value);return predicate(bytes,(nuint)bytes.Length)==1;
    }
}
