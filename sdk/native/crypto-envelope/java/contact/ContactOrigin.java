package org.zrotext.candidate;

import com.sun.jna.Function;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;

/** Pinned native parser asset. The host owns the trusted installed artifact directory. */
public final class ContactOrigin {
    private final NativeLibrary library;
    private final Function predicate;
    public ContactOrigin(Path artifactDirectory) throws Exception {
        String os=System.getProperty("os.name");
        String name=os.startsWith("Windows")?"zrotext_contact_origin.dll":os.startsWith("Mac")?"libzrotext_contact_origin.dylib":"libzrotext_contact_origin.so";
        Path path=artifactDirectory.toRealPath().resolve(name).toRealPath();
        library=NativeLibrary.getInstance(path.toString(),Map.of());
        predicate=library.getFunction("zrotext_contact_origin_v1");
    }
    public boolean accepts(String value){
        if(value==null || value.length()<9 || value.length()>512)return false;
        for(int i=0;i<value.length();i++)if(value.charAt(i)<33 || value.charAt(i)>126)return false;
        byte[] bytes=value.getBytes(StandardCharsets.US_ASCII);
        Object size=Native.SIZE_T_SIZE==8?(Object)Long.valueOf(bytes.length):Integer.valueOf(bytes.length);
        return predicate.invokeInt(new Object[]{bytes,size})==1;
    }
}
