# frozen_string_literal: true
require_relative 'original_owner_review'

module ZrotextCandidate
  # Immutable canonical descriptor; its digest is a binding, never permission.
  class WorkflowAction
    FIELDS=%w[account_id action_id authority_generation commitment content_digest content_ref content_version expires_at line_id not_before purpose_id recipient_id revision routine_id timezone window_id].freeze
    NUMBERS=%w[authority_generation content_version expires_at not_before revision].freeze
    def self.parse(json)
      raise unless json.is_a?(String) && json.bytesize<=4096
      fields=JSON.parse(json,object_class:OriginalHTTP::UniqueObject,max_nesting:4)
      raise unless fields.is_a?(Hash) && fields.keys.sort==FIELDS
      owned={}
      FIELDS.each do |name|
        value=fields.fetch(name)
        if NUMBERS.include?(name)
          value=value.to_i if value.is_a?(Float) && value.finite? && value==value.to_i
          raise unless value.is_a?(Integer) && value.between?(name=='not_before' ? 0 : 1,9_007_199_254_740_991)
        else
          raise unless value.is_a?(String) && value.bytesize.between?(1,128) && value.ascii_only?
          value=value.dup.freeze
        end
        owned[name]=value
      end
      raise unless /\A[0-9a-f]{64}\z/.match?(owned['content_digest']) && owned['not_before']<owned['expires_at'] && %w[informational sensitive].include?(owned['commitment'])
      new(owned.freeze)
    rescue StandardError
      raise OriginalHTTP::Failure.new, cause:nil
    end
    def initialize(fields)
      @fields=fields;@canonical=JSON.generate(fields,ascii_only:true).gsub("\x7f",'\u007f').freeze;freeze
    end
    private_class_method :new
    def canonical = @canonical.dup
    def digest = Digest::SHA256.hexdigest(@canonical)
    def [](name) = @fields.fetch(name)
    def production!
      %w[account_id action_id line_id recipient_id purpose_id content_ref routine_id].each { |n| OriginalHTTP.uuid!(@fields[n]) }
      raise OriginalHTTP::Failure.new unless @fields['revision']<=128
      self
    end
  end
  class OriginalCurrentClient
    class ProposalIntent
      def initialize(bytes,descriptor) = (@bytes=bytes.b.dup.freeze;@descriptor=descriptor;freeze)
      def bytes = @bytes.dup
      attr_reader :descriptor
      private_class_method :new
    end
    class ProposalResult
      attr_reader :event,:consumption,:active_request,:authority,:action
      def initialize(event,consumption,active,authority,action)
        @event=event.dup.freeze;@consumption=consumption.dup.freeze;@active_request=active.dup.freeze;@authority=authority;@action=action;freeze
      end
      private_class_method :new
    end
    def prepare_proposal(event:,request:,active_request:,descriptor:)
      need(descriptor.instance_of?(WorkflowAction));descriptor.production!
      raw=prepare_owner_review(event:event,request:request,active_request:owner_id(active_request)).bytes
      raw[0,5]="ZTOP\x01".b;restore_proposal(raw+descriptor.canonical)
    rescue StandardError
      raise OriginalHTTP::Failure.new, cause:nil
    end
    def restore_proposal(bytes)
      need(bytes.is_a?(String));raw=bytes.b.dup;need(raw.bytesize.between?(152,4096) && raw.byteslice(0,5)=="ZTOP\x01".b && raw.getbyte(134)==1)
      prefix=raw.byteslice(0,151);prefix[0,5]="ZTOR\x01".b;restore_owner_review(prefix)
      canonical=raw.byteslice(151..);descriptor=WorkflowAction.parse(canonical).production!
      need(descriptor.canonical.b==canonical && descriptor['account_id']==owner_uuid(@scope.account) && descriptor['line_id']==owner_uuid(@scope.line))
      ProposalIntent.send(:new,raw,descriptor)
    rescue StandardError
      raise OriginalHTTP::Failure.new, cause:nil
    end
    def consume_proposal(credential:,output_credential:,intent:,clock:) = proposal(credential,output_credential,intent,clock,true)
    def status_proposal(credential:,intent:,clock:) = proposal(credential,nil,intent,clock,false)
    private
    def proposal(credential,output,intent,clock,effect)
      acquired=false;dispatched=false
      need(intent.instance_of?(ProposalIntent) && clock.respond_to?(:call));owned=restore_proposal(intent.bytes);raw=owned.bytes;descriptor=owned.descriptor
      credential=credential.dup.freeze
      if effect;OriginalHTTP.output_credential!(output);output=output.dup.freeze;end
      need(@lock.try_lock);acquired=true;before=current_locked(credential,clock)
      event=raw.byteslice(102,16);request=raw.byteslice(118,16);active=raw.byteslice(135,16)
      version=before.authority.manifest.version
      wire=if effect
        @transport.exchange_proposal(credential:credential,output_credential:output,descriptor:descriptor.canonical,method:'consume',accepted_manifest_version:version,event_id:owner_uuid(event),request_id:owner_uuid(request),active_request_id:owner_uuid(active))
      else
        @transport.exchange(credential:credential,method:'status',accepted_manifest_version:version,consumption_id:owner_uuid(request))
      end
      dispatched=effect
      r=object(JSON.parse(wire.untrusted_json,object_class:OriginalHTTP::UniqueObject,max_nesting:64),%w[event_id consumption_id disposition active_request_id action])
      need(r['event_id']==owner_uuid(event) && r['consumption_id']==owner_uuid(request) && r['active_request_id']==owner_uuid(active))
      action=nil
      if r['disposition']=='owner_review';need(r['action'].nil?)
      else
        need(r['disposition']=='proposal');a=object(r['action'],%w[account_id action_id revision binding_digest])
        need(a['account_id']==descriptor['account_id'] && a['action_id']==descriptor['action_id'] && integer(a['revision'])==descriptor['revision'] && a['binding_digest']==descriptor.digest)
        action=descriptor
      end
      ProposalResult.send(:new,event,request,active,current_locked(credential,clock),action)
    rescue OriginalHTTP::Failure => error
      raise OriginalHTTP::Failure.new(dispatched || error.unknown), cause:nil
    rescue StandardError
      raise OriginalHTTP::Failure.new(dispatched), cause:nil
    ensure
      @lock.unlock if acquired
    end
  end
end
