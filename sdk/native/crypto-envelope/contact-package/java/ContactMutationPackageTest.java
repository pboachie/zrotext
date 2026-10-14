package org.zrotext.consumer;
import org.zrotext.candidate.*;
import com.google.gson.*;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
/** Synthetic native acceptance only; excluded from runtime archive inventories. */
final class ContactMutationPackageTest {
    private ContactMutationPackageTest(){}
    private static byte[] d(JsonObject f,String name){return Base64.getDecoder().decode(f.get(name).getAsString());}
    private record Plan(ContactField.Statement statement,byte[] unsigned,long legacy,ContactField.Mutation.Transition previous,ContactField.Statement previousStatement,List<ContactField.Verified> fields){}
    private static ContactField.Mutation.Transition call(ProtectedContactSigner key,ContactField.Expected e,Plan p,AtomicBoolean cancelled)throws GeneralSecurityException{return ContactField.Mutation.produceProtected(key,p.statement(),e,p.unsigned(),p.legacy(),p.previous(),p.previousStatement(),p.fields(),cancelled);}
    static JsonObject run(ProtectedContactSigner key,JsonObject fixture,JsonArray outputs,ContactOrigin parser)throws Exception{
        JsonObject f=fixture.deepCopy(),encoded=new JsonObject();String[] names={"name","notes","replacement"};for(int i=0;i<3;i++){String bytes=outputs.get(i).getAsJsonObject().get("bytes").getAsString();f.addProperty(names[i],bytes);encoded.addProperty(names[i],bytes);}
        var x=new ContactMutationTest.Fixture(f,parser);JsonObject mutations=new JsonObject();ContactField.Mutation.Transition previous=null;ContactField.Statement ps=null;int refused=0;
        for(String name:List.of("create","update","clear","converted")){
            if(name.equals("create")||name.equals("converted")){previous=null;ps=null;}var st=x.statement(name);byte[] u=Arrays.copyOf(d(f,name),304),statement=st.bytes();int at=40+Short.toUnsignedInt(ByteBuffer.wrap(statement,38,2).getShort())+24;
            System.arraycopy(statement,at+32,u,118,32);System.arraycopy(st.digest(),0,u,150,32);if(previous!=null)System.arraycopy(previous.mutation().digest(),0,u,70,32);
            String[] slots=name.equals("clear")?new String[]{null,"replacement"}:name.equals("update")?new String[]{"name","replacement"}:new String[]{"name","notes"};
            for(int i=0;i<2;i++)if(slots[i]!=null){var field=x.fields.get(slots[i]);u[222+41*i]=1;System.arraycopy(field.bytes(),38,u,223+41*i,8);System.arraycopy(field.digest(),0,u,231+41*i,32);}
            var plan=new Plan(st,u,name.equals("converted")?7:0,previous,ps,x.replacements(name));
            var value=call(key,x.expected,plan,new AtomicBoolean());
            var borrowed=ProtectedContactSigner.open(key.alias(),key.publicPoint());try{
                try{borrowed.deleteCreated();throw new IllegalStateException("Borrowed deletion accepted");}catch(GeneralSecurityException expectedFailure){/* Expected. */}
                borrowed.close();try{call(borrowed,x.expected,plan,new AtomicBoolean());throw new IllegalStateException("Closed mutation accepted");}catch(GeneralSecurityException expectedFailure){refused++;}
            }finally{borrowed.close();}
            try{call(key,x.expected,plan,new AtomicBoolean(true));throw new IllegalStateException("Cancelled mutation accepted");}catch(GeneralSecurityException expectedFailure){refused++;}
            byte[] contact=d(f,"contact");contact[0]^=1;var foreign=new ContactField.Expected(d(f,"account"),f.get("origin").getAsString(),d(f,"fingerprint"),contact,d(f,"routing"),parser);
            try{call(key,foreign,plan,new AtomicBoolean());throw new IllegalStateException("Foreign mutation accepted");}catch(GeneralSecurityException expectedFailure){refused++;}
            mutations.addProperty(name,Base64.getEncoder().encodeToString(value.mutation().bytes()));previous=value;ps=st;
        }
        JsonObject result=new JsonObject();result.add("fields",encoded);result.add("mutations",mutations);result.addProperty("refusals",refused);return result;
    }
}
