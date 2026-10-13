using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
namespace Zrotext.Candidate;
// Exactly one TLS connection/request; no HttpClient automatic GET replay.
internal sealed class OwnerTemplateTransport:IDisposable {
 private readonly Uri endpoint;private readonly X509Certificate2Collection additional=new();private readonly object gate=new();private TcpClient? active;private bool closed,certificatesDisposed;
 internal OwnerTemplateTransport(string origin,long timeoutMs,string additionalRootsPem){
  try{if(timeoutMs<1 || timeoutMs>10000 || !origin.StartsWith("https://",StringComparison.Ordinal) || origin.Any(c=>c<=32 || c>=127 || "\\?#@".Contains(c)) || origin[8..].Contains('/') || !Uri.TryCreate(origin,UriKind.Absolute,out var uri) || uri.Host.Length==0)throw new OwnerTemplate.Failure("invalid_request");endpoint=uri;
   if(additionalRootsPem.Length!=0){additional.ImportFromPem(additionalRootsPem);if(additional.Count==0)throw new OwnerTemplate.Failure("invalid_request");}
  }catch{foreach(var cert in additional)cert.Dispose();throw new OwnerTemplate.Failure("invalid_request");}
 }
    private bool VerifyCertificate(object _, X509Certificate? certificate, X509Chain? supplied, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None) return true;
        if (errors != SslPolicyErrors.RemoteCertificateChainErrors || certificate is null || additional.Count == 0) return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(additional);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
        if (supplied is not null)
            foreach (var element in supplied.ChainElements) chain.ChainPolicy.ExtraStore.Add(element.Certificate);
        using var leaf = new X509Certificate2(certificate);
        return chain.Build(leaf);
    }


 internal byte[] Get(string path,OwnerTemplate.Session session,int budgetMs){
  using var cancel=new CancellationTokenSource(budgetMs);using var tcp=new TcpClient();
  lock(gate){if(closed)throw new OwnerTemplate.Failure("closed");active=tcp;}
  try{
   tcp.ConnectAsync(endpoint.Host,endpoint.Port,cancel.Token).AsTask().GetAwaiter().GetResult();using var stream=new SslStream(tcp.GetStream(),false,VerifyCertificate);
   stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions{TargetHost=endpoint.Host,EnabledSslProtocols=SslProtocols.Tls12|SslProtocols.Tls13},cancel.Token).GetAwaiter().GetResult();
   var request=Encoding.ASCII.GetBytes("GET "+path+" HTTP/1.1\r\nHost: "+endpoint.Authority+"\r\nAccept: "+TemplateStore.ContentType+"\r\nCookie: "+session.Cookie+"\r\nX-Zrotext-CSRF: "+session.Csrf+"\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n");
   stream.WriteAsync(request,cancel.Token).AsTask().GetAwaiter().GetResult();
   int headerBytes=0;
   string Line(){using var line=new MemoryStream();byte[] one=new byte[1];for(;;){if(stream.ReadAsync(one,cancel.Token).AsTask().GetAwaiter().GetResult()!=1)throw new IOException();headerBytes++;if(headerBytes>16384 || line.Length>=4096)throw new IOException();if(one[0]==13){if(stream.ReadAsync(one,cancel.Token).AsTask().GetAwaiter().GetResult()!=1 || one[0]!=10)throw new IOException();headerBytes++;return Encoding.ASCII.GetString(line.ToArray());}if(one[0]<32 || one[0]>126)throw new IOException();line.WriteByte(one[0]);}}
   string status=Line();if(!System.Text.RegularExpressions.Regex.IsMatch(status,"\\AHTTP/1\\.[01] [0-9]{3}(?: .*)?\\z"))throw new IOException();int code=int.Parse(status.AsSpan(9,3),System.Globalization.CultureInfo.InvariantCulture);
   var headers=new Dictionary<string,List<string>>(StringComparer.OrdinalIgnoreCase);
   for(;;){var line=Line();if(line.Length==0)break;int colon=line.IndexOf(':');if(colon<=0 || line[..colon].Any(c=>!char.IsAsciiLetterOrDigit(c) && c!='-'))throw new IOException();string key=line[..colon],value=line[(colon+1)..].Trim(' ');if(!headers.TryGetValue(key,out var values)){values=new();headers.Add(key,values);}values.Add(value);}
   if(code>=300 && code<400)throw new OwnerTemplate.Failure("response_unknown",true);if(code==401 || code==403)throw new OwnerTemplate.Failure("owner_changed");
   if(code!=200 || !headers.TryGetValue("Content-Type",out var content) || !content.SequenceEqual(new[]{TemplateStore.ContentType}))throw new OwnerTemplate.Failure("read_refused");
   using var output=new MemoryStream();byte[] buffer=new byte[4096];
   void Exact(int count){while(count>0){int n=stream.ReadAsync(buffer.AsMemory(0,Math.Min(count,buffer.Length)),cancel.Token).AsTask().GetAwaiter().GetResult();if(n==0 || output.Length+n>33075)throw new IOException();output.Write(buffer,0,n);count-=n;}}
   bool length=headers.TryGetValue("Content-Length",out var lengths),transfer=headers.TryGetValue("Transfer-Encoding",out var transfers);if(length && transfer)throw new IOException();
   if(length){if(lengths!.Count!=1 || lengths[0].Length==0 || lengths[0].Any(c=>c<'0' || c>'9') || !int.TryParse(lengths[0],out int size) || size>33075)throw new IOException();Exact(size);}
   else if(transfer){if(transfers!.Count!=1 || !transfers[0].Equals("chunked",StringComparison.OrdinalIgnoreCase))throw new IOException();for(;;){string line=Line(),hex=line.Split(';')[0];if(hex.Length<1 || hex.Length>8 || !int.TryParse(hex,System.Globalization.NumberStyles.AllowHexSpecifier,System.Globalization.CultureInfo.InvariantCulture,out int size) || size<0 || size>33075-output.Length)throw new IOException();if(size==0){if(Line().Length!=0)throw new IOException();break;}Exact(size);if(Line().Length!=0)throw new IOException();}}
   else{for(;;){int n=stream.ReadAsync(buffer,cancel.Token).AsTask().GetAwaiter().GetResult();if(n==0)break;if(output.Length+n>33075)throw new IOException();output.Write(buffer,0,n);}}
   return output.ToArray();
  }catch(OwnerTemplate.Failure){throw;}catch{throw new OwnerTemplate.Failure("read_refused");}
  finally{lock(gate){if(ReferenceEquals(active,tcp))active=null;if(closed)ClearCertificates();}}
 }
 private void ClearCertificates(){if(!certificatesDisposed){certificatesDisposed=true;foreach(var certificate in additional)certificate.Dispose();}}
 public void Dispose(){lock(gate){closed=true;active?.Dispose();if(active is null)ClearCertificates();}}
}
