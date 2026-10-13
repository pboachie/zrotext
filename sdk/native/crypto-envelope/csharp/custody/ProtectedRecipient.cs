using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Zrotext.Candidate;

/// <summary>Locally qualified Windows PCP recipient. No remote attestation or software fallback.</summary>
public sealed class ProtectedRecipient:IDisposable {
    private const string Provider="Microsoft Platform Crypto Provider",Prefix="zrotext-managed-csharp-p256-";
    private const uint Silent=0x40;
    private readonly object gate=new();private Handle provider=new(),key=new();private NativeAdapter? adapter;
    private bool qualified,closed,created;public string Alias{get;private set;}="";
    private ProtectedRecipient() {}
    private static void Need(bool value){if(!value)throw new CryptographicException("Protected recipient refused");}
    private static void Check(uint status){if(status!=0)throw new CryptographicException($"Native custody operation refused ({status:x8})");}
    private sealed class Handle:SafeHandleZeroOrMinusOneIsInvalid {
        public Handle():base(true){}
        protected override bool ReleaseHandle()=>Native.NCryptFreeObject(handle)==0;
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
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)]internal static extern uint NCryptImportKey(Handle provider,IntPtr importKey,string type,IntPtr parameters,out Handle key,byte[] input,int length,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll")]internal static extern uint NCryptSecretAgreement(Handle key,Handle peer,out Handle agreement,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll",CharSet=CharSet.Unicode)]internal static extern uint NCryptDeriveKey(Handle agreement,string kdf,IntPtr parameters,byte[] output,int length,out int size,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll")]internal static extern uint NCryptDeleteKey(Handle key,uint flags);
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ncrypt.dll")]internal static extern uint NCryptFreeObject(IntPtr handle);
    }
    private static uint Property(Handle handle,string name){var value=new byte[4];Check(Native.NCryptGetProperty(handle,name,value,4,out int size,0));Need(size==4);return BinaryPrimitives.ReadUInt32LittleEndian(value);}
    private static Handle Start(){
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Windows PCP required");
        Check(Native.NCryptOpenStorageProvider(out Handle handle,Provider,0));
        try{Need((Property(handle,"Impl Type")&1)!=0);Check(Native.NCryptIsAlgSupported(handle,"ECDH_P256",0));return handle;}
        catch{handle.Dispose();throw;}
    }
    /// <summary>Read-only capability probe. Success is not key qualification.</summary>
    public static void Probe(){using var handle=Start();}
    /// <summary>Callback must durably record and flush the generated alias before key creation.</summary>
    public static ProtectedRecipient Create(Action<string> recordPendingAlias){
        ArgumentNullException.ThrowIfNull(recordPendingAlias);var value=new ProtectedRecipient();
        try{
            value.provider=Start();value.Alias=Prefix+Guid.NewGuid().ToString("D");recordPendingAlias(value.Alias);
            Check(Native.NCryptCreatePersistedKey(value.provider,out value.key,"ECDH_P256",value.Alias,0,Silent));value.created=true;
            Check(Native.NCryptSetProperty(value.key,"Export Policy",new byte[4],4,0));Check(Native.NCryptFinalizeKey(value.key,Silent));value.Qualify();return value;
        }catch{
            try{if(value.created && !value.key.IsInvalid)value.DeleteCreated();}finally{value.Dispose();}
            throw;
        }
    }
    public static ProtectedRecipient Open(string alias,byte[] independentlyExpectedPublic){
        Need(alias.StartsWith(Prefix,StringComparison.Ordinal) && Guid.TryParseExact(alias[Prefix.Length..],"D",out var id) && alias==Prefix+id.ToString("D"));
        var expected=(byte[])independentlyExpectedPublic.Clone();using var checkedPoint=HpkeRecipient.Point(expected);var value=new ProtectedRecipient();
        try{value.provider=Start();value.Alias=alias;Check(Native.NCryptOpenKey(value.provider,out value.key,alias,0,Silent));value.Qualify();Need(CryptographicOperations.FixedTimeEquals(value.PublicPoint(),expected));return value;}
        catch{value.Dispose();throw;}
    }
    private byte[] PublicRaw(){
        Need(!closed);var blob=new byte[72];Check(Native.NCryptExportKey(key,IntPtr.Zero,"ECCPUBLICBLOB",IntPtr.Zero,blob,blob.Length,out int size,Silent));
        Need(size==72 && BinaryPrimitives.ReadUInt32LittleEndian(blob)==0x314b4345 && BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(4))==32);
        var point=new byte[65];point[0]=4;blob.AsSpan(8,64).CopyTo(point.AsSpan(1));using var checkedPoint=HpkeRecipient.Point(point);return point;
    }
    public byte[] PublicPoint(){lock(gate){Need(qualified && !closed);return PublicRaw();}}
    private void Qualify(){
        Need(Property(key,"Export Policy")==0);uint status=Native.NCryptExportKey(key,IntPtr.Zero,"ECCPRIVATEBLOB",IntPtr.Zero,null,0,out _,Silent);
        Need(status is 0x80090010 or 0x8009000a);var point=PublicRaw();adapter=new NativeAdapter(this,point);
        using var peer=ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);using var publicKey=HpkeRecipient.Point(point);
        byte[]? expected=null,actual=null;
        try{expected=peer.DeriveRawSecretAgreement(publicKey.PublicKey);actual=Exchange(peer.PublicKey);Need(expected.Length==32 && CryptographicOperations.FixedTimeEquals(expected,actual));qualified=true;}
        finally{if(expected is not null)CryptographicOperations.ZeroMemory(expected);if(actual is not null)CryptographicOperations.ZeroMemory(actual);}
    }
    private byte[] Exchange(ECDiffieHellmanPublicKey peer){
        lock(gate){
            Need(!closed);var parameters=peer.ExportParameters();Need(parameters.Curve.Oid.Value==ECCurve.NamedCurves.nistP256.Oid.Value && parameters.Q.X?.Length==32 && parameters.Q.Y?.Length==32);
            var blob=new byte[72];BinaryPrimitives.WriteUInt32LittleEndian(blob,0x314b4345);BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(4),32);parameters.Q.X!.CopyTo(blob,8);parameters.Q.Y!.CopyTo(blob,40);
            Check(Native.NCryptImportKey(provider,IntPtr.Zero,"ECCPUBLICBLOB",IntPtr.Zero,out Handle imported,blob,72,Silent));
            using(imported){Check(Native.NCryptSecretAgreement(key,imported,out Handle agreement,Silent));using(agreement){
                var raw=new byte[32];bool success=false;
                // TRUNCATE accepts flags zero; SILENT is used on key operations above.
                try{Check(Native.NCryptDeriveKey(agreement,"TRUNCATE",IntPtr.Zero,raw,32,out int size,0));Need(size==32);Array.Reverse(raw);success=true;return raw;}
                finally{if(!success)CryptographicOperations.ZeroMemory(raw);}
            }}
        }
    }
    private sealed class NativeAdapter: ECDiffieHellman {
        private readonly ProtectedRecipient owner;private readonly ECDiffieHellman publicKey;
        internal NativeAdapter(ProtectedRecipient owner,byte[] point){this.owner=owner;publicKey=HpkeRecipient.Point(point);}
        public override ECDiffieHellmanPublicKey PublicKey=>publicKey.PublicKey;
        public override ECParameters ExportParameters(bool includePrivateParameters){Need(!includePrivateParameters);return publicKey.ExportParameters(false);}
        public override byte[] DeriveRawSecretAgreement(ECDiffieHellmanPublicKey otherPartyPublicKey){Need(owner.qualified && !owner.closed);return owner.Exchange(otherPartyPublicKey);}
        public override byte[] DeriveKeyMaterial(ECDiffieHellmanPublicKey otherPartyPublicKey)=>throw new NotSupportedException("Raw qualified agreement only");
        public override void ImportParameters(ECParameters parameters)=>throw new NotSupportedException("No private import");
        protected override void Dispose(bool disposing){if(disposing)publicKey.Dispose();base.Dispose(disposing);}
    }
    public string OpenProfile02(byte[] input,ManifestChain.Verified manifest,long now,int role,byte[] recipientId,SealedReader02.ICurrentSelection current){
        lock(gate){Need(qualified && !closed);return SealedReader02.Open(input,manifest,now,role,recipientId,adapter!,current);}
    }
    public string OpenHistoricalArchive02(byte[] input,ManifestChain.Verified historical,ManifestChain.Verified currentManifest,long now,byte[] recipientId,SealedReader02.ICurrentSelection current){
        lock(gate){Need(qualified && !closed);return SealedReader02.OpenHistoricalArchive(input,historical,currentManifest,now,recipientId,adapter!,current);}
    }
    public string OpenElected03(byte[] input,ManifestChain.Verified manifest,Election03.Proof proof,ElectedReader03.IAuthoritySource source,byte[] message,string peer){
        lock(gate){Need(qualified && !closed);return ElectedReader03.OpenSoftware(input,manifest,proof,source,message,peer,adapter!);}
    }
    /// <summary>Only this instance's fresh creation may be deleted. Opening an existing alias never grants deletion.</summary>
    public void DeleteCreated(){lock(gate){Need(created && !closed && !key.IsInvalid);Check(Native.NCryptDeleteKey(key,0));key.SetHandleAsInvalid();created=false;qualified=false;Dispose();}}
    public void Dispose(){lock(gate){if(closed)return;closed=true;qualified=false;adapter?.Dispose();key.Dispose();provider.Dispose();}}
}
