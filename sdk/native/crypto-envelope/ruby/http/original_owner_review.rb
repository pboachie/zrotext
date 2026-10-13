# frozen_string_literal: true
require_relative 'original_current'

module ZrotextCandidate
  class OriginalCurrentClient
    class OwnerReviewIntent
      def initialize(bytes) = (@bytes=bytes.b.dup.freeze;freeze)
      def bytes = @bytes.dup
      private_class_method :new
    end
    class OwnerReviewResult
      attr_reader :event,:consumption,:active_request,:authority
      def initialize(event,consumption,active,authority)
        @event=event.dup.freeze;@consumption=consumption.dup.freeze;@active_request=active&.dup&.freeze;@authority=authority;freeze
      end
      private_class_method :new
    end
    # No network or persistence. Caller must sync these bytes before any effect.
    def prepare_owner_review(event:,request:,active_request:nil)
      event=owner_id(event);request=owner_id(request);active=active_request && owner_id(active_request)
      restore_owner_review("ZTOR\x01".b+@root.point+@scope.checkpoint_binding+event+request+[active ? 1 : 0].pack('C')+(active || "\x00".b*16))
    rescue StandardError
      raise OriginalHTTP::Failure.new, cause:nil
    end
    def restore_owner_review(bytes)
      need(bytes.is_a?(String));b=bytes.b.dup
      need(b.bytesize==151 && b.byteslice(0,5)=="ZTOR\x01".b && b.byteslice(5,65)==@root.point && b.byteslice(70,32)==@scope.checkpoint_binding)
      owner_id(b.byteslice(102,16));owner_id(b.byteslice(118,16));flag=b.getbyte(134)
      need([0,1].include?(flag) && (flag.zero? == (b.byteslice(135,16)=="\x00".b*16)))
      OwnerReviewIntent.send(:new,b)
    rescue StandardError
      raise OriginalHTTP::Failure.new, cause:nil
    end
    def consume_owner_review(credential:,intent:,clock:) = owner_review(credential,intent,clock,true)
    # A failed status never proves that the saved identity was not consumed.
    def status_owner_review(credential:,intent:,clock:) = owner_review(credential,intent,clock,false)
    private
    def owner_id(value)
      need(value.is_a?(String) && value.bytesize==16);b=value.b.dup;need(b.bytes.any? { |v| v!=0 });b
    end
    def owner_uuid(bytes)
      h=bytes.unpack1('H*');[h[0,8],h[8,4],h[12,4],h[16,4],h[20,12]].join('-')
    end
    def owner_review(credential,intent,clock,effect)
      acquired=false;dispatched=false
      need(intent.instance_of?(OwnerReviewIntent) && clock.respond_to?(:call));owned=restore_owner_review(intent.bytes).bytes;credential=credential.dup.freeze
      need(@lock.try_lock);acquired=true;before=current_locked(credential,clock)
      event=owned.byteslice(102,16);request=owned.byteslice(118,16);active=owned.getbyte(134)==1 ? owned.byteslice(135,16) : nil
      fields=effect ? {event_id:owner_uuid(event),request_id:owner_uuid(request),active_request_id:active && owner_uuid(active)} : {consumption_id:owner_uuid(request)}
      wire=@transport.exchange(credential:credential,method:effect ? 'consume' : 'status',accepted_manifest_version:before.authority.manifest.version,**fields)
      dispatched=effect
      r=object(JSON.parse(wire.untrusted_json,object_class:OriginalHTTP::UniqueObject,max_nesting:64),%w[event_id consumption_id disposition active_request_id action])
      need(r['event_id']==owner_uuid(event) && r['consumption_id']==owner_uuid(request) && r['disposition']=='owner_review' && r['action'].nil? && r['active_request_id']==(active && owner_uuid(active)))
      after=current_locked(credential,clock);OwnerReviewResult.send(:new,event,request,active,after)
    rescue OriginalHTTP::Failure => error
      raise OriginalHTTP::Failure.new(dispatched || error.unknown), cause:nil
    rescue StandardError
      raise OriginalHTTP::Failure.new(dispatched), cause:nil
    ensure
      @lock.unlock if acquired
    end
  end
end
