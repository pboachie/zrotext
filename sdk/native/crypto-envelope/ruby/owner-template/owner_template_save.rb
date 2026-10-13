# frozen_string_literal: true
module ZrotextCandidate
 class OwnerTemplate
  Review=Struct.new(:request_id,:expected_revision,:scope,:encrypted_digest,keyword_init:true) do
   def initialize(**values);super(**values.transform_values { |v| v.is_a?(String) ? v.dup.freeze : v });freeze;end
  end
  Pending=Struct.new(:request_id,:template_id,:revision,:encrypted_digest,keyword_init:true) do
   def initialize(**values);super(**values.transform_values { |v| v.is_a?(String) ? v.dup.freeze : v });freeze;end
  end
  Acknowledgement=Struct.new(:identity) do
   def initialize(identity);super;freeze;end
   def state = 'acknowledged_saved_revision'
  end
  def pending = @mutex.synchronize { @pending }
  def prepare_save(scope,request_id,expected_revision,envelope)
   raise Failure.new('invalid_request') unless envelope.is_a?(String) && envelope.bytesize.between?(308,33075)
   wire=envelope.b.dup;captured=EncryptedTemplate::Scope.new(scope.aad);identity=request_id.is_a?(String) ? request_id.dup.freeze : request_id
   execute do |work|
    raise Failure.new('pending_write') if @saved || @pending
    raise Failure.new('invalid_request') unless @review
    owned=nil
    begin
     request=TemplateStore::SaveRequest.new(captured,identity,expected_revision,wire);TemplateStore.parse(wire)
     session=credentials(work);owned={ticket:Object.new.freeze,request:request,request_id:identity,scope:captured,session:session,deadline:work[:deadline],attempts:0,verifies:0,unknown:false};@saved=owned
     authorize(work,captured,session);save_deadline(owned,work);HpkeRecipient.point(wire.byteslice(222,65))
     @review.call(Review.new(request_id:identity,expected_revision:expected_revision,scope:captured,encrypted_digest:request.encrypted_digest))
     authorize(work,captured,session);save_deadline(owned,work);owned[:ticket]
    rescue StandardError=>error
     @mutex.synchronize { forget_locked(owned) } if owned
     raise(error.is_a?(Failure) ? error : Failure.new('invalid_request'))
    end
   end
  end
  def commit(ticket) = post_saved(ticket,false)
  def retry_unknown(ticket) = post_saved(ticket,true)
  def verify_unknown(ticket) = latest_saved(ticket,true)
  def read_latest = latest_saved(nil,false)
  private
  def identity_of(record)
   Pending.new(request_id:record[:request_id],template_id:TemplateStore.uuid(record[:scope].aad.byteslice(70,16)),revision:record[:request].revision,encrypted_digest:record[:request].encrypted_digest)
  end
  # Called only by the owner of this exact record, under the foreground gate.
  def forget_locked(record)
   return unless @saved.equal?(record)
   @saved=nil;@pending=nil
  end
  def save_deadline(record,work)
   @mutex.synchronize { work[:deadline]=[work[:deadline],record[:deadline]].min;record[:deadline]=work[:deadline];@changed.broadcast };live(work)
  end
  def saved_ticket(ticket,work)
   record=@saved;raise Failure.new('invalid_request') unless record && record[:ticket].equal?(ticket)
   save_deadline(record,work);record
  end
  def post_saved(ticket,retry_unknown)
   execute do |work|
    record=saved_ticket(ticket,work)
    raise Failure.new('invalid_request') if retry_unknown ? !record[:unknown] : record[:attempts]!=0
    raise Failure.new('attempts_exhausted',record[:unknown]) if record[:attempts]>=3
    authorize(work,record[:scope],record[:session]);save_deadline(record,work)
    @mutex.synchronize { record[:attempts]+=1;record[:unknown]=true;@pending=identity_of(record) }
    unless credentials(work)==record[:session];close;raise Failure.new('owner_changed');end
    body=exchange(work,record[:session],record[:request]);record[:request].receipt(body)
    authorize(work,record[:scope],record[:session]);save_deadline(record,work)
    revision=record[:request].revision;digest=record[:request].encrypted_digest
    raise Failure.new('response_unknown',true) if revision==@head && digest!=@head_digest
    result=Acknowledgement.new(identity_of(record))
    work[:finish]=lambda do
     if revision>=@head;@head=revision;@head_digest=digest;end
     forget_locked(record)
    end
    result
   end
  end
  def latest_saved(ticket,verify)
   execute do |work|
    record=verify ? saved_ticket(ticket,work) : @saved
    raise Failure.new('invalid_request') if verify && !record[:unknown]
    if record
     save_deadline(record,work)
     if record[:unknown]
      raise Failure.new('attempts_exhausted',true) if record[:verifies]>=3
      record[:verifies]+=1
     end
    end
    result=read_work(work,record && record[:session])
    if record
     save_deadline(record,work)
     result=Snapshot.new(result.scope,result.envelope,result.encrypted_digest,result.envelope==record[:request].body)
    end
    result
   end
  end
 end
end
