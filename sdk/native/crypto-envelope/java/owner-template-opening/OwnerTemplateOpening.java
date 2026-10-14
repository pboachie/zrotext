package org.zrotext.candidate;

/** Dedicated current opening lifecycle. Closing it closes the client, never the caller's key. */
public final class OwnerTemplateOpening implements AutoCloseable {
 private final OwnerTemplate.Opening implementation;
 public OwnerTemplateOpening(OwnerTemplate client,String origin,OwnerTemplate.Binding binding,byte[] template,OwnerTemplate.CurrentSource current,OwnerTemplate.SessionSource session,boolean enabled,long timeoutMs,String additionalRootsPem)throws OwnerTemplate.Failure {
  implementation=new OwnerTemplate.Opening(client,origin,binding,template,current,session,enabled,timeoutMs,additionalRootsPem);
 }
 public OwnerTemplate.OpenedPreview openLatest(ProtectedRecipient recipient)throws OwnerTemplate.Failure{if(recipient==null)throw new OwnerTemplate.Failure("invalid_request");return implementation.open(recipient::publicPoint,recipient);}
 /** Explicit candidate software custody; this overload makes no protected-key claim. */
 public OwnerTemplate.OpenedPreview openLatestSoftware(java.security.PrivateKey key,byte[] publicPoint)throws OwnerTemplate.Failure{return implementation.openLatestSoftware(key,publicPoint);}
 @Override public void close(){implementation.close();}
 public void invalidate(){close();}
}
