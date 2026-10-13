# frozen_string_literal: true
require_relative 'owner_template'
module ZrotextCandidate
 class OwnerTemplate
  # Independently maintained host lease, not protected-provider qualification.
  DraftState=Struct.new(:epoch,:revision,:custody_live,keyword_init:true) do
   def initialize(**values);super;freeze;end
  end
  DraftReview=Struct.new(:request_id,:expected_revision,:scope,:epoch,:draft_revision,:content,:preview,keyword_init:true) do
   def initialize(**values);super;self.request_id=request_id.dup.freeze;freeze;end
  end
  # One immutable reviewed draft lifetime; explicit caller commit remains separate.
  class Authoring
   attr_reader :client
   def initialize(draft:,draft_review:,ciphertext_review:,**options)
    raise Failure unless draft.respond_to?(:call) && draft_review.respond_to?(:call) && ciphertext_review.respond_to?(:call)
    @draft=draft;@review=draft_review;@client=OwnerTemplate.new(**options.merge(review:ciphertext_review));@guard=OwnerTemplate.new(**options.merge(review:nil));@used=false
   rescue StandardError
    @client&.close;raise Failure.new('invalid_request'),cause:nil
   end
   def close;@guard.close;@client.close;end
   alias invalidate close
   def prepare(request_id,expected_revision,scope,content,epoch,draft_revision)
    raise Failure.new('invalid_draft') unless content.instance_of?(TemplateContent) && scope.instance_of?(EncryptedTemplate::Scope)
    canonical=content.canonical
    begin;raise Failure.new('invalid_draft') unless canonical.bytesize<=32768;captured=TemplateContent.parse(canonical)
    ensure;canonical.replace("\x00".b*canonical.bytesize);end
    request=request_id.is_a?(String) ? request_id.dup.freeze : request_id
    ticket=@guard.send(:execute) do |work|
     @client.instance_variable_get(:@mutex).synchronize {raise Failure.new('pending_draft') if @used || @client.instance_variable_get(:@saved) || @client.instance_variable_get(:@pending)}
     wire=nil;owned=nil
     begin
      raise Failure.new('invalid_draft') unless epoch.is_a?(Integer) && epoch.between?(1,2**63-1) && draft_revision.is_a?(Integer) && draft_revision.between?(1,2**63-1) && expected_revision.is_a?(Integer) && expected_revision.between?(0,127) && TemplateStore.number(scope.aad,94)==expected_revision+1 && request.is_a?(String) && /\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/.match?(request)
      session=@guard.send(:credentials,work);preview=captured.preview;current(work,scope,session,epoch,draft_revision)
      raise Failure.new('review_declined') unless true.equal?(@review.call(DraftReview.new(request_id:request,expected_revision:expected_revision,scope:scope,epoch:epoch,draft_revision:draft_revision,content:captured,preview:preview)))
      current(work,scope,session,epoch,draft_revision);authority=EncryptedTemplate::Authority.new(manifest:@guard.instance_variable_get(:@prior),now_ms:@guard.instance_variable_get(:@now));wire=EncryptedTemplate.seal(scope,captured,-> {authority});current(work,scope,session,epoch,draft_revision)
      prepared=@client.prepare_save(scope,request,expected_revision,wire);owned=prepared;current(work,scope,session,epoch,draft_revision)
      @client.instance_variable_get(:@mutex).synchronize do
       saved=@client.instance_variable_get(:@saved)
       raise Failure.new('closed') if @client.instance_variable_get(:@closed) || !saved || !saved[:ticket].equal?(prepared)
       saved[:deadline]=[saved[:deadline],work[:deadline]].min
       @client.instance_variable_set(:@lifetime_deadline,[@client.instance_variable_get(:@lifetime_deadline),work[:deadline]].min)
      end
      work[:finish]=-> { @used=true;Thread.new {sleep([work[:deadline]-Process.clock_gettime(Process::CLOCK_MONOTONIC),0].max);close} }
      prepared
     rescue StandardError=>error
      raise Failure.new('pending_draft') if error.is_a?(Failure) && %w[pending_write busy].include?(error.code)
      abort_owned(owned);raise
     ensure
      wire&.replace("\x00".b*wire.bytesize)
     end
    end
    @client.instance_variable_get(:@mutex).synchronize {raise Failure.new('closed') if @client.instance_variable_get(:@closed)}
    ticket
   rescue Failure=>error
    abort_owned(nil) unless %w[busy capacity pending_draft].include?(error.code)
    raise
   end
   private
   def abort_owned(owned)
    @guard.close
    mutex=@client.instance_variable_get(:@mutex)
    mutex.synchronize do
     saved=@client.instance_variable_get(:@saved)
     return if (saved && !saved[:ticket].equal?(owned)) || (@client.instance_variable_get(:@busy) && !owned)
     @client.instance_variable_set(:@closed,true)
     @client.instance_variable_set(:@saved,nil) unless @client.instance_variable_get(:@busy)
     @client.instance_variable_get(:@changed).broadcast
    end
   end
   def check_draft(work,epoch,revision)
    @guard.send(:live,work);d=@draft.call;@guard.send(:live,work)
    raise Failure.new('draft_changed') unless d.instance_of?(DraftState) && d.epoch==epoch && d.revision==revision && true.equal?(d.custody_live)
   end
   def current(work,scope,session,epoch,revision)
    check_draft(work,epoch,revision);@guard.send(:authorize,work,scope,session);check_draft(work,epoch,revision)
    raise Failure.new('owner_changed') unless @guard.send(:credentials,work)==session
    @guard.send(:live,work)
   end
  end
 end
end
