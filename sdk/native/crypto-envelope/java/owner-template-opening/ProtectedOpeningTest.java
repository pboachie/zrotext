package org.zrotext.candidate;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.util.*;

public final class ProtectedOpeningTest {
    private ProtectedOpeningTest(){}
    private static void receipt(Path path,String text,boolean create)throws Exception {
        try(var stream=FileChannel.open(path,StandardOpenOption.WRITE,create?StandardOpenOption.CREATE_NEW:StandardOpenOption.TRUNCATE_EXISTING)){
            var bytes=StandardCharsets.UTF_8.encode(text);while(bytes.hasRemaining())stream.write(bytes);stream.force(true);
        }
    }
    public static void main(String[] args)throws Exception {
        if(args.length==1 && args[0].equals("--probe")){try{ProtectedRecipient.probe();System.out.println("{\"available\":true}");}catch(GeneralSecurityException error){System.out.println("{\"available\":false}");}return;}
        if(args.length==0){OwnerTemplateOpeningTest.run(null);return;}
        if(args.length!=1 || !args[0].equals("--hardware"))throw new IllegalArgumentException("Unsupported arguments");
        ProtectedRecipient.probe();Path path=Path.of(System.getProperty("java.io.tmpdir"),"zrotext-managed-template-owned-"+UUID.randomUUID()+".json");ProtectedRecipient owner=null;
        try{
            owner=ProtectedRecipient.create(name->receipt(path,"{\"pending_alias\":\""+name+"\"}",true));
            System.out.println("{\"public\":\""+HexFormat.of().formatHex(owner.publicPoint())+"\"}");System.out.flush();try(var recipient=ProtectedRecipient.open(owner.alias(),owner.publicPoint())){OwnerTemplateOpeningTest.run(recipient);}
        }finally{
            if(owner!=null){
                String name=owner.alias();byte[] point;
                try{point=owner.publicPoint();}finally{owner.deleteCreated();}
                try(var reopened=ProtectedRecipient.open(name,point)){reopened.publicPoint();throw new AssertionError("Deleted key reopened");}catch(GeneralSecurityException expected){/* Exact owned deletion verified. */}
                receipt(path,"{\"owned_key_deleted\":true}",false);System.out.println("{\"owned_key_deleted\":true}");System.out.flush();owner.close();
            }
        }
    }
}
