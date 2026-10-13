using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace Zrotext.Candidate;

/// <summary>Locally qualified PCP signing for historical contact fields only.</summary>
public sealed class ProtectedContactSigner:IDisposable {
    private const string Provider="Microsoft Platform Crypto Provider",Prefix="zrotext-managed-csharp-contact-p256-";
    private const uint Silent=0x40;
    private static readonly BigInteger Order=new(Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),true,true);
    private readonly object gate=new();private Handle provider=new(),key=new();private bool qualified,created,closed;
    public string Alias{get;private set;}="";
    private ProtectedContactSigner(){}
    private static void Need(bool value){if(!value)throw new CryptographicException("Protected signer refused");}
    private static void Check(uint status){if(status!=0)throw new CryptographicException($"Native signer refused ({status:x8})");}
    private sealed class Handle:SafeHandleZeroOrMinusOneIsInvalid {
        public Handle():base(true){} protected override bool ReleaseHandle()=>Native.NCryptFreeObject(handle)==0;
    }
    private static class Native {
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)]internal static extern uint NCryptOpenStorageProvider(out Handle handle,string name,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)]internal static extern uint NCryptIsAlgSupported(Handle provider,string algorithm,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)]internal static extern uint NCryptCreatePersistedKey(Handle provider,out Handle key,string algorithm,string name,uint legacy,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)]internal static extern uint NCryptOpenKey(Handle provider,out Handle key,string name,uint legacy,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)]internal static extern uint NCryptGetProperty(Handle handle,string name,byte[] output,int length,out int size,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)]internal static extern uint NCryptSetProperty(Handle handle,string name,byte[] input,int length,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll")]internal static extern uint NCryptFinalizeKey(Handle key,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)]internal static extern uint NCryptExportKey(Handle key,IntPtr exportKey,string type,IntPtr parameters,byte[]? output,int length,out int size,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll")]internal static extern uint NCryptSignHash(Handle key,IntPtr padding,byte[] digest,int digestLength,byte[] output,int outputLength,out int size,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll")]internal static extern uint NCryptDeleteKey(Handle key,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll")]internal static extern uint NCryptFreeObject(IntPtr handle);
    }
    private static uint Property(Handle handle,string name){var bytes=new byte[4];Check(Native.NCryptGetProperty(handle,name,bytes,4,out int size,0));Need(size==4);return BinaryPrimitives.ReadUInt32LittleEndian(bytes);}
    private static Handle Start(){
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Windows PCP required");
        Check(Native.NCryptOpenStorageProvider(out Handle value,Provider,0));
        try{Need((Property(value,"Impl Type")&1)!=0);Check(Native.NCryptIsAlgSupported(value,"ECDSA_P256",0));return value;}
        catch{value.Dispose();throw;}
    }
    public static void Probe(){using var value=Start();}
    public static ProtectedContactSigner Create(Action<string> recordAndFlush){
        ArgumentNullException.ThrowIfNull(recordAndFlush);var value=new ProtectedContactSigner();
        try{value.provider=Start();value.Alias=Prefix+Guid.NewGuid().ToString("D");recordAndFlush(value.Alias);
            Check(Native.NCryptCreatePersistedKey(value.provider,out value.key,"ECDSA_P256",value.Alias,0,Silent));value.created=true;
            Check(Native.NCryptSetProperty(value.key,"Export Policy",new byte[4],4,0));Check(Native.NCryptFinalizeKey(value.key,Silent));value.Qualify();return value;
        }catch{try{if(value.created && !value.key.IsInvalid)value.DeleteCreated();}finally{value.Dispose();}throw;}
    }
    public static ProtectedContactSigner Open(string alias,byte[] expectedPublic){
        Need(alias.StartsWith(Prefix,StringComparison.Ordinal) && Guid.TryParseExact(alias[Prefix.Length..],"D",out var id) && alias==Prefix+id.ToString("D"));
        byte[] expected=(byte[])expectedPublic.Clone();using var point=HpkeRecipient.Point(expected);var value=new ProtectedContactSigner();
        try{value.provider=Start();value.Alias=alias;Check(Native.NCryptOpenKey(value.provider,out value.key,alias,0,Silent));value.Qualify();Need(CryptographicOperations.FixedTimeEquals(value.PublicPoint(),expected));return value;}
        catch{value.Dispose();throw;}
    }
    private byte[] PublicRaw(){
        Need(!closed);byte[] blob=new byte[72];Check(Native.NCryptExportKey(key,IntPtr.Zero,"ECCPUBLICBLOB",IntPtr.Zero,blob,72,out int size,Silent));
        Need(size==72 && BinaryPrimitives.ReadUInt32LittleEndian(blob)==0x31534345 && BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(4))==32);
        var point=new byte[65];point[0]=4;blob.AsSpan(8).CopyTo(point.AsSpan(1));using var checkedPoint=HpkeRecipient.Point(point);return point;
    }
    public byte[] PublicPoint(){lock(gate){Need(qualified && !closed);return PublicRaw();}}
    private void Qualify(){
        Need(Property(key,"Export Policy")==0);uint status=Native.NCryptExportKey(key,IntPtr.Zero,"ECCPRIVATEBLOB",IntPtr.Zero,null,0,out _,Silent);Need(status is 0x80090010 or 0x8009000a);
        byte[] challenge=RandomNumberGenerator.GetBytes(32),signature=SignDigest(challenge);using var point=HpkeRecipient.Point(PublicRaw());using var verifier=ECDsa.Create(point.ExportParameters(false));
        Need(verifier.VerifyHash(challenge,signature,DSASignatureFormat.IeeeP1363FixedFieldConcatenation));qualified=true;
    }
    private byte[] SignDigest(byte[] digest){
        Need(!closed && digest.Length==32);var raw=new byte[64];Check(Native.NCryptSignHash(key,IntPtr.Zero,digest,32,raw,64,out int size,Silent));Need(size==64);
        var r=new BigInteger(raw.AsSpan(0,32),true,true);var s=new BigInteger(raw.AsSpan(32,32),true,true);Need(r>0 && r<Order && s>0 && s<Order);
        if(s>Order/2){byte[] low=(Order-s).ToByteArray(true,true);Array.Clear(raw,32,32);low.CopyTo(raw,64-low.Length);}return raw;
    }
    internal byte[] SignField(byte[] input,Action live){lock(gate){
        Need(qualified && !closed);byte[] unsigned=ContactField.Unsigned(input),domain=Encoding.ASCII.GetBytes("ZT/contact-field/commitment/v1\0"),transcript=new byte[domain.Length+4+unsigned.Length];
        domain.CopyTo(transcript,0);BinaryPrimitives.WriteInt32BigEndian(transcript.AsSpan(domain.Length,4),unsigned.Length);unsigned.CopyTo(transcript,domain.Length+4);
        try{live();byte[] signature=SignDigest(SHA256.HashData(transcript));using var point=HpkeRecipient.Point(PublicRaw());using var verifier=ECDsa.Create(point.ExportParameters(false));Need(verifier.VerifyData(transcript,signature,HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation));return signature;}
        finally{CryptographicOperations.ZeroMemory(unsigned);CryptographicOperations.ZeroMemory(transcript);}
    }}
    public void DeleteCreated(){lock(gate){Need(created && !closed && !key.IsInvalid);Check(Native.NCryptDeleteKey(key,0));key.SetHandleAsInvalid();created=qualified=false;Dispose();}}
    public void Dispose(){lock(gate){if(closed)return;closed=true;qualified=false;key.Dispose();provider.Dispose();}}
}
