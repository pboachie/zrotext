package org.zrotext.candidate;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.*;
/** One explicit TLS connection and HTTP request, without automatic GET replay. */
final class OwnerTemplateTransport implements AutoCloseable {
 private final URI endpoint;private final SSLContext ssl;private final Object gate=new Object();private Socket active;private boolean closed;
    /** Additional roots must be independently trusted application CA configuration. */
    OwnerTemplateTransport(String origin, long timeoutMs, String additionalRootsPem) throws OwnerTemplate.Failure {
        try {
            if (timeoutMs < 1 || timeoutMs > 10000 || !origin.startsWith("https://") || origin.chars().anyMatch(c -> c <= 32 || c >= 127 || "\\?#".indexOf(c) >= 0)) throw new OwnerTemplate.Failure("invalid_request");
            URI uri = new URI(origin);
            if (uri.getHost() == null || uri.getRawUserInfo() != null || !(uri.getRawPath().isEmpty() || uri.getRawPath().equals("/"))) throw new OwnerTemplate.Failure("invalid_request");
            this.endpoint = new URI(origin);

            SSLContext ssl = SSLContext.getInstance("TLS");
            TrustManagerFactory platform = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            platform.init((KeyStore)null);
            X509TrustManager system = trust(platform);
            X509TrustManager extra = null;
            if (!additionalRootsPem.isEmpty()) {
                KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType()); store.load(null, null);
                var certificates = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(additionalRootsPem.getBytes(StandardCharsets.US_ASCII)));
                if (certificates.isEmpty()) throw new OwnerTemplate.Failure("invalid_request");
                int i = 0; for (var certificate : certificates) store.setCertificateEntry("additional-" + i++, certificate);
                TrustManagerFactory configured = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); configured.init(store); extra = trust(configured);
            }
            final X509TrustManager added = extra;
            ssl.init(null, new TrustManager[] { new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return system.getAcceptedIssuers(); }
                public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException { system.checkClientTrusted(c, a); }
                public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {
                    try { system.checkServerTrusted(c, a); }
                    catch (CertificateException error) { if (added == null) throw error; added.checkServerTrusted(c, a); }
                }
            }}, null);
            this.ssl=ssl;
        } catch (Exception error) { throw new OwnerTemplate.Failure("invalid_request"); }
    }
    private static X509TrustManager trust(TrustManagerFactory f) throws GeneralSecurityException {
        for (TrustManager t : f.getTrustManagers()) if (t instanceof X509TrustManager x) return x;
        throw new GeneralSecurityException();
    }

 byte[] get(String path,OwnerTemplate.Session session,long budgetMs)throws OwnerTemplate.Failure{return exchange(path,session,budgetMs,null);}
 byte[] post(TemplateStore.SaveRequest request,OwnerTemplate.Session session,long budgetMs)throws OwnerTemplate.Failure{return exchange(request.path(),session,budgetMs,request);}
 private byte[] exchange(String path,OwnerTemplate.Session session,long budgetMs,TemplateStore.SaveRequest request)throws OwnerTemplate.Failure{
  int limit=request==null?33075:256;
  long deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(budgetMs);
  Socket socket=new Socket();
  synchronized(gate){if(closed)throw new OwnerTemplate.Failure("closed");active=socket;}
  try{
   socket.connect(new InetSocketAddress(endpoint.getHost(),endpoint.getPort()<0?443:endpoint.getPort()),remaining(deadline));
   try(var secure=(SSLSocket)ssl.getSocketFactory().createSocket(socket,endpoint.getHost(),endpoint.getPort()<0?443:endpoint.getPort(),true)){
    synchronized(gate){if(closed)throw new IOException();active=secure;}
    SSLParameters params=new SSLParameters();params.setEndpointIdentificationAlgorithm("HTTPS");params.setProtocols(new String[]{"TLSv1.3","TLSv1.2"});secure.setSSLParameters(params);secure.setSoTimeout(remaining(deadline));secure.startHandshake();
    var output=secure.getOutputStream();byte[] payload=request==null?new byte[0]:request.body();var head=new StringBuilder(request==null?"GET ":"POST ").append(path).append(" HTTP/1.1\r\nHost: ").append(endpoint.getRawAuthority()).append("\r\nAccept: ").append(request==null?TemplateStore.CONTENT_TYPE:"application/json").append("\r\nCookie: ").append(session.cookie()).append("\r\nX-Zrotext-CSRF: ").append(session.csrf()).append("\r\nCache-Control: no-store\r\nConnection: close\r\n");
    if(request!=null){for(var h:request.headers().entrySet())head.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");head.append("Content-Length: ").append(payload.length).append("\r\n");}head.append("\r\n");output.write(head.toString().getBytes(StandardCharsets.US_ASCII));output.write(payload);output.flush();
    var input=new Parser(secure,deadline);String status=input.line();if(!status.matches("HTTP/1\\.[01] [0-9]{3}(?: .*)?"))throw new IOException();int code=Integer.parseInt(status.substring(9,12));var headers=new TreeMap<String,List<String>>(String.CASE_INSENSITIVE_ORDER);
    for(;;){String line=input.line();if(line.isEmpty())break;int colon=line.indexOf(':');if(colon<=0 || !line.substring(0,colon).matches("[A-Za-z0-9-]+"))throw new IOException();headers.computeIfAbsent(line.substring(0,colon),k->new ArrayList<>()).add(line.substring(colon+1).trim());}
    if(code>=300 && code<400)throw new OwnerTemplate.Failure("response_unknown",true);if(code==401 || code==403)throw new OwnerTemplate.Failure("owner_changed");var types=headers.getOrDefault("Content-Type",List.of());if(code!=200 || types.size()!=1 || !(request==null?types.get(0).equals(TemplateStore.CONTENT_TYPE):types.get(0).matches("(?i)application/json(?:\\s*;\\s*charset=utf-8)?")))throw new OwnerTemplate.Failure("read_refused");
    boolean length=headers.containsKey("Content-Length"),transfer=headers.containsKey("Transfer-Encoding");if(length && transfer)throw new IOException();var body=new ByteArrayOutputStream();
    if(length){var values=headers.get("Content-Length");if(values.size()!=1 || !values.get(0).matches("[0-9]+"))throw new IOException();int size=Integer.parseInt(values.get(0));if(size>limit)throw new IOException();input.exact(body,size);}
    else if(transfer){var values=headers.get("Transfer-Encoding");if(values.size()!=1 || !values.get(0).equalsIgnoreCase("chunked"))throw new IOException();for(;;){String hex=input.line().split(";",2)[0];if(!hex.matches("[0-9a-fA-F]{1,8}"))throw new IOException();long size=Long.parseLong(hex,16);if(size>limit-body.size())throw new IOException();if(size==0){if(!input.line().isEmpty())throw new IOException();break;}input.exact(body,(int)size);if(!input.line().isEmpty())throw new IOException();}}
    else{for(int value;(value=input.read())!=-1;){if(body.size()>=limit)throw new IOException();body.write(value);}}
    remaining(deadline);return body.toByteArray();
   }
  }catch(OwnerTemplate.Failure error){throw error;}catch(Exception error){throw new OwnerTemplate.Failure("read_refused");}
  finally{try{socket.close();}catch(IOException ignored){}synchronized(gate){active=null;}}
 }
 private static int remaining(long deadline)throws IOException{long left=deadline-System.nanoTime();if(left<=0)throw new IOException();return (int)Math.max(1,Math.min(Integer.MAX_VALUE,TimeUnit.NANOSECONDS.toMillis(left)));}
 private static final class Parser {
  final SSLSocket socket;final InputStream input;final long deadline;int headers;
  Parser(SSLSocket socket,long deadline)throws IOException{this.socket=socket;this.deadline=deadline;input=socket.getInputStream();}
  int read()throws IOException{socket.setSoTimeout(remaining(deadline));return input.read();}
  String line()throws IOException{var bytes=new ByteArrayOutputStream();for(;;){int value=read();if(++headers>16384 || bytes.size()>=4096)throw new IOException();if(value==13){if(read()!=10)throw new IOException();headers++;return bytes.toString(StandardCharsets.US_ASCII);}if(value<32 || value>126)throw new IOException();bytes.write(value);}}
  void exact(ByteArrayOutputStream out,int count)throws IOException{byte[] buffer=new byte[4096];while(count>0){socket.setSoTimeout(remaining(deadline));int n=input.read(buffer,0,Math.min(count,buffer.length));if(n<1 || out.size()+n>33075)throw new IOException();out.write(buffer,0,n);count-=n;}}
 }
 @Override public void close(){synchronized(gate){closed=true;if(active!=null)try{active.close();}catch(IOException ignored){}}}
}
