# frozen_string_literal: true
require_relative 'owner_template'
require_relative '../custody/protected_recipient'
module ZrotextCandidate
 class OwnerTemplate
  # Local preview only. Frozen strings cannot promise physical secure erasure.
  OpenedPreview=Struct.new(:preview,:revision,:encrypted_digest,:matches_pending,keyword_init:true) do
   def initialize(**values);super;freeze;end
   def request_acknowledged = false
  end
  # Owns its dedicated client's close lifecycle, never deletion of the caller's key.
  class Opening
   READ=OwnerTemplate.instance_method(:read_latest)
   CLOSE=OwnerTemplate.instance_method(:close)
   private_constant :READ,:CLOSE
   def initialize(client:,**options)
    raise Failure unless client.instance_of?(OwnerTemplate) && client.instance_variable_get(:@origin)==options[:origin] && client.instance_variable_get(:@binding)==options[:binding] && client.instance_variable_get(:@template)==options[:template_id]
    @client=client;@guard=OwnerTemplate.new(**options);close unless options[:enabled]==true
   rescue StandardError
    CLOSE.bind_call(client) if client.instance_of?(OwnerTemplate)
    raise Failure.new('invalid_request'),cause:nil
   end
   def close;CLOSE.bind_call(@guard);CLOSE.bind_call(@client);end
   alias invalidate close
   def open_latest(recipient)
    raise Failure.new('invalid_request') unless recipient.instance_of?(ProtectedRecipient)
    open_current(-> { recipient.public_point },recipient.method(:open_content))
   end
   # Explicit candidate software custody, never protected.
   def open_latest_software(key)
    raise Failure.new('invalid_request') unless key.is_a?(OpenSSL::PKey::EC) && key.private?
    open_current(-> { key.public_key.to_octet_string(:uncompressed) },HpkeRecipient.software_content(key))
   end
   private
   def client_live
    @client.instance_variable_get(:@mutex).synchronize { raise Failure.new('closed') if @client.instance_variable_get(:@closed) }
   end
   def open_current(point,recipient)
    result=@guard.send(:execute) do |work|
     wire=nil
     begin
      @guard.send(:live,work);client_live;pk=point.call.b.dup;HpkeRecipient.point(pk);session=@guard.send(:credentials,work);@guard.send(:authorize,work,nil,session)
      binding=@guard.instance_variable_get(:@binding);selected=@guard.instance_variable_get(:@prior).key_records.find { |k| k.getbyte(0)==2 && k.byteslice(1,32)==binding.reader(1) }
      raise Failure unless selected && selected.byteslice(33,65)==pk
      snapshot=READ.bind_call(@client);@guard.send(:live,work);client_live;scope=snapshot.scope;wire=snapshot.envelope;@guard.send(:authorize,work,scope,session)
      authority=EncryptedTemplate::Authority.new(manifest:@guard.instance_variable_get(:@prior),now_ms:@guard.instance_variable_get(:@now))
      content=EncryptedTemplate.open(scope,wire,recipient,-> { authority })
      client_live;@guard.send(:live,work);raise Failure unless point.call==pk
      @guard.send(:authorize,work,scope,session);preview=content.preview;@guard.send(:authorize,work,scope,session);client_live;raise Failure unless point.call==pk;@guard.send(:live,work)
      OpenedPreview.new(preview:preview,revision:TemplateStore.number(scope.aad,94),encrypted_digest:snapshot.encrypted_digest.freeze,matches_pending:snapshot.matches_pending)
     rescue StandardError
      close;raise
     ensure
      wire&.replace("\x00".b*wire.bytesize)
     end
    end
    client_live;result
   rescue StandardError => error
    close;raise (error.is_a?(Failure) ? error : Failure.new('refused')),cause:nil
   end
  end
 end
end
