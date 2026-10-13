using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
namespace Zrotext.Candidate;
/// <summary>Opaque request framing only, not credentials, review or send authority.</summary>
public static class TemplateStore {
 public const string ContentType="application/vnd.zrotext.workflow-template.v1";
 internal static void Need(bool b){if(!b)throw new CryptographicException("Template contract refused");}
 internal static long Number(byte[] b,int at)=>BinaryPrimitives.ReadInt64BigEndian(b.AsSpan(at,8));
 internal static bool Same(byte[] a,byte[] b)=>CryptographicOperations.FixedTimeEquals(a,b);
 internal static string Hex(byte[] b)=>Convert.ToHexString(b).ToLowerInvariant();
 internal static string Uuid(byte[] b){var s=Hex(b);return s[..8]+"-"+s[8..12]+"-"+s[12..16]+"-"+s[16..20]+"-"+s[20..];}
 internal static EncryptedTemplate.Scope Parse(byte[] wire){Need(wire.Length>=308 && wire.Length<=33075 && wire[222]==4 && BinaryPrimitives.ReadInt32BigEndian(wire.AsSpan(287,4))==wire.Length-291);return new(wire[..222]);}
 public sealed class SaveRequest {
  private readonly byte[] body;private readonly string request,digest;private readonly int expected;
  public SaveRequest(EncryptedTemplate.Scope scope,string requestId,int expectedRevision,byte[] envelope){
   Need(Regex.IsMatch(requestId,"\\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\z") && requestId.Replace("-","")!=new string('0',32) && expectedRevision>=0 && expectedRevision<=127);
   var aad=scope.Aad();Need(Number(aad,94)==expectedRevision+1 && envelope.Length>=308 && envelope.Length<=33075);var copy=(byte[])envelope.Clone();Need(Same(copy[..222],aad) && BinaryPrimitives.ReadInt32BigEndian(copy.AsSpan(287,4))==copy.Length-291);body=copy;request=requestId;expected=expectedRevision;digest=Hex(SHA256.HashData(copy));
  }
  public byte[] Body()=>(byte[])body.Clone();public string Path=>"/v1/owner/workflow/templates";public int Revision=>expected+1;public string EncryptedDigest=>digest;
  public IReadOnlyDictionary<string,string> Headers()=>new System.Collections.ObjectModel.ReadOnlyDictionary<string,string>(new Dictionary<string,string>{{"content-type",ContentType},{"idempotency-key",request},{"x-zrotext-template-revision",expected.ToString(System.Globalization.CultureInfo.InvariantCulture)}});
  public int Receipt(byte[] wire){Need(wire.Length<=256 && Same(wire,Encoding.ASCII.GetBytes("{\"revision\":"+Revision.ToString(System.Globalization.CultureInfo.InvariantCulture)+"}")));return Revision;}
 }
}
