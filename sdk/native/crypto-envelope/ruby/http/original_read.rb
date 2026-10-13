# frozen_string_literal: true
require_relative 'original_current'

module ZrotextCandidate
  class OriginalCurrentClient
    class Read
      attr_reader :plaintext,:event,:envelope_digest,:accepted_manifest_version,:authority
      def initialize(plaintext,event,digest,baseline,authority)
        @plaintext=plaintext;@event=event.dup.freeze;@envelope_digest=digest.dup.freeze
        @accepted_manifest_version=baseline;@authority=authority;freeze
      end
      private_class_method :new
    end
    # The explicit software path does not establish protected custody.
    def read_software(credential:,event:,recipient:,clock:,baseline:0)
      read_with_recipient(credential:credential,event:event,recipient:HpkeRecipient.software(recipient),clock:clock,baseline:baseline)
    end
    # An injected recipient is trusted application code, not a custody claim.
    def read_with_recipient(credential:,event:,recipient:,clock:,baseline:0)
      acquired=false;plain=nil;transferred=false
      need(clock.respond_to?(:call) && recipient.respond_to?(:call) && @lock.try_lock);acquired=true
      need(event.is_a?(String) && event.bytesize==16 && event.bytes.any? { |b| b!=0 })
      event=event.b.dup.freeze;credential=credential.dup.freeze
      need(baseline.is_a?(Integer) && baseline.between?(0,SAFE))
      saved=saved_at(clock);latest=saved.history.last
      first=saved.history.find { |m| latest.version-m.version<32 && (baseline.zero? || baseline==m.version) };need(first)
      text=event.unpack1('H*');event_text=[text[0,8],text[8,4],text[12,4],text[16,4],text[20,12]].join('-')
      wire=@transport.exchange(credential:credential,method:'read',event_id:event_text,accepted_manifest_version:first.version)
      r=object(JSON.parse(wire.untrusted_json,object_class:OriginalHTTP::UniqueObject,max_nesting:64),%w[event_id accepted_at_ms envelope_b64 historical_manifest_version statement_b64 approval_signature_b64 installation_signature_b64 activation_manifest_version proof])
      need(r['event_id']==event_text);initial=accept_proof(r['proof'],saved,first,clock)
      snap=@checkpoint.snapshot(@scope,@last)
      if snap.revision!=@revision
        @failed=true;need(false)
      end
      historical_version=integer(r['historical_manifest_version']);need(historical_version>=first.version)
      activation_version=integer(r['activation_manifest_version']);accepted=integer(r['accepted_at_ms']);need(accepted<=@last+30000)
      historical=snap.history.find { |m| m.version==historical_version };activation=snap.history.find { |m| m.version==activation_version };need(historical && activation)
      activation=at(activation.bytes,activation,accepted)
      selection=OriginalReplyReader.verify_selection(encoded(r['statement_b64'],1536),encoded(r['approval_signature_b64'],64),encoded(r['installation_signature_b64'],64),activation,accepted,@scope)
      envelope=encoded(r['envelope_b64'],34082);authority=initial.authority;once=true
      source=lambda do
        if once
          once=false
        else
          authority=current_locked(credential,clock).authority
        end
        authority
      end
      plain=OriginalReplyReader.open_with_recipient(envelope,event,historical,selection,@scope,recipient,source)
      result=Read.send(:new,plain,event,OpenSSL::Digest::SHA256.digest(envelope),first.version,authority)
      transferred=true;result
    rescue StandardError
      raise OriginalHTTP::Failure.new, cause: nil
    ensure
      plain&.replace("\x00".b*plain.bytesize) unless transferred
      @lock.unlock if acquired
    end
    private
    def encoded(value,maximum)
      need(value.is_a?(String) && value.bytesize<=((maximum+2)/3)*4)
      bytes=Base64.strict_decode64(value);need(bytes.bytesize<=maximum && Base64.strict_encode64(bytes)==value);bytes
    end
  end
end
