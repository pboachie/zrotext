# frozen_string_literal: true
require_relative 'template_store'
require 'net/http'
require 'uri'
require 'timeout'
module ZrotextCandidate
 class OwnerTemplate
  class Failure < StandardError
   attr_reader :code,:unknown
   def initialize(code='read_refused',unknown=false);@code=code;@unknown=unknown;super('Owner template '+code);end
  end
  class Binding
   attr_reader :generation,:peer
   def initialize(account:,device:,line:,interval:,session:,generation:,peer:,phone_reader:,archive_reader:)
    @ids=[account,device,line,interval,session].map { |v| OwnerTemplate.bytes(v,16).freeze }.freeze
    @readers=[phone_reader,archive_reader].map { |v| OwnerTemplate.bytes(v,32).freeze }.freeze
    raise Failure unless generation.is_a?(Integer) && generation.between?(1,2**63-1) && peer.is_a?(String) && /\A\+[1-9][0-9]{1,14}\z/.match?(peer)
    @generation=generation;@peer=peer.dup.freeze;freeze
   end
   def id(at) = @ids.fetch(at).dup
   def reader(at) = @readers.fetch(at).dup
   def ==(other) = other.instance_of?(Binding) && @ids==other.instance_variable_get(:@ids) && @readers==other.instance_variable_get(:@readers) && generation==other.generation && peer==other.peer
  end
  Current=Struct.new(:binding,:manifest,:now_ms,:valid_for_ms,:owner_live,:consent_live,:active,keyword_init:true) do
   def initialize(**values);super;freeze;end
  end
  Session=Struct.new(:origin,:cookie,:csrf,keyword_init:true) do
   def initialize(**values);super(**values.transform_values { |v| v.is_a?(String) ? v.dup.freeze : v });freeze;end
   def inspect = '#<OwnerTemplate::Session redacted>'
  end
  class Snapshot
   def initialize(scope,wire,digest,matches=false);@scope=scope;@wire=wire.dup.freeze;@digest=digest.freeze;@matches=matches;freeze;end
   def scope = @scope
   def envelope = @wire.dup
   def encrypted_digest = @digest
   def request_acknowledged = false
   def matches_pending = @matches
  end
  ADMISSION=SizedQueue.new(8)
  8.times { ADMISSION.push(true) }
  private_constant :ADMISSION
  def self.bytes(value,size)
   raise Failure unless value.is_a?(String) && value.bytesize==size && value.bytes.any?(&:positive?)
   value.b.dup
  end
  def initialize(origin:,binding:,template_id:,current:,session:,enabled:false,timeout_ms:10000,additional_roots_pem:'',review:nil)
   raise Failure unless origin.is_a?(String) && origin.ascii_only? && !origin.match?(/[\x00-\x20\x7f\\?#@]/)
   uri=URI.parse(origin);raise Failure unless uri.scheme=='https' && uri.host && uri.host==uri.host.downcase && uri.path.empty? && !uri.userinfo
   raise Failure unless binding.instance_of?(Binding) && current.respond_to?(:call) && session.respond_to?(:call) && [true,false].include?(enabled) && timeout_ms.is_a?(Integer) && timeout_ms.between?(1,10000)
   @origin=origin.dup.freeze;@binding=binding;@template=self.class.bytes(template_id,16).freeze;@current=current;@session=session;@timeout=timeout_ms/1000.0
   @uri=URI.parse(origin+'/v1/owner/workflow/templates/'+TemplateStore.uuid(@template));@store=OpenSSL::X509::Store.new;@store.set_default_paths
   unless additional_roots_pem.empty?
    certs=additional_roots_pem.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m);raise Failure if certs.empty?
    certs.each { |pem| @store.add_cert(OpenSSL::X509::Certificate.new(pem)) }
   end
   raise Failure unless review.nil? || review.respond_to?(:call)
   @review=review;@saved=nil;@pending=nil
   @mutex=Mutex.new;@changed=ConditionVariable.new;@closed=!enabled;@busy=false;@now=0;@prior=nil;@head=0;@head_digest=nil
  rescue StandardError
   raise Failure.new('invalid_request'),cause:nil
  end
  def close
   @mutex.synchronize { @closed=true;@saved=nil unless @busy;@changed.broadcast }
  end
  def read_latest = execute { |work| read_work(work) }
  private
  def release_work_locked(work)
   return unless work[:done] && work[:foreground] && !work[:released]
   work[:released]=true;@busy=false;@saved=nil if @closed;ADMISSION.push(true);@changed.broadcast
  end
  def classify(error)
   return error if error.is_a?(Failure) && %w[invalid_request pending_write busy capacity].include?(error.code)
   return Failure.new('response_unknown',true) if @pending
   error.is_a?(Failure) ? error : Failure.new
  end
  def execute
   work=nil
   @mutex.synchronize do
    raise Failure.new('busy') if @busy
    raise classify(Failure.new('closed')) if @closed
    begin;ADMISSION.pop(true);rescue ThreadError;raise Failure.new('capacity');end
    @busy=true;work={deadline:monotonic+@timeout,done:false,foreground:false,released:false,value:nil,error:nil,finish:nil}
   end
   begin
    Thread.new do
     begin
      value=yield(work);@mutex.synchronize { work[:value]=value }
     rescue StandardError => error
      @mutex.synchronize { work[:error]=classify(error) }
     ensure
      @mutex.synchronize { work[:done]=true;release_work_locked(work);@changed.broadcast }
     end
    end
   rescue StandardError
    @mutex.synchronize { @busy=false };ADMISSION.push(true);raise Failure.new
   end
   begin
    @mutex.synchronize do
     loop do
      raise classify(Failure.new('closed')) if @closed
      if monotonic>=work[:deadline];@closed=true;@changed.broadcast;raise classify(Failure.new('deadline'));end
      if work[:done]
       raise work[:error] if work[:error]
       work[:finish]&.call
       return work[:value]
      end
      @changed.wait(@mutex,[work[:deadline]-monotonic,0].max)
     end
    end
   ensure
    @mutex.synchronize { work[:foreground]=true;release_work_locked(work) }
   end
  end
  def monotonic = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  def live(work)
   @mutex.synchronize do
    raise classify(Failure.new('closed')) if @closed
    if monotonic>=work[:deadline];@closed=true;@changed.broadcast;raise classify(Failure.new('deadline'));end
   end
  end
  def remaining(work);live(work);@mutex.synchronize { work[:deadline]-monotonic };end
  def credentials(work)
   live(work);s=@session.call;live(work)
   raise Failure unless s.instance_of?(Session) && s.origin==@origin && s.cookie.is_a?(String) && s.cookie.bytesize.between?(1,4096) && s.cookie.include?('=') && /\A[\x20-\x7e]+\z/.match?(s.cookie) && s.csrf.is_a?(String) && s.csrf.bytesize.between?(1,256) && /\A[\x21-\x7e]+\z/.match?(s.csrf)
   s
  end
  def active(key,now,permission) = key.getbyte(148)==1 && TemplateStore.number(key,132)<=now && now<TemplateStore.number(key,140) && (key.byteslice(130,2).unpack1('n')&permission)!=0
  def authorize(work,scope,session)
   live(work);started=monotonic;a=@current.call;live(work)
   raise Failure unless a.instance_of?(Current) && a.binding==@binding && a.owner_live==true && a.consent_live==true && a.active==true && a.now_ms.is_a?(Integer) && a.now_ms>0 && a.now_ms>=@now && a.valid_for_ms.is_a?(Integer) && a.valid_for_ms.between?(1,60000) && a.manifest.instance_of?(ManifestChain::Verified) && a.manifest.profile==2
   m=ManifestChain.continue_chain(a.manifest.bytes,a.manifest,2,a.now_ms)
   raise Failure unless m.account==@binding.id(0)
   if @prior
    raise Failure unless m.root_point==@prior.root_point && m.enrolled_root_point==@prior.enrolled_root_point && m.generation==@prior.generation && m.version>=@prior.version && (m.version!=@prior.version || m.digest==@prior.digest)
   end
   reader=m.key_records.find { |k| k.getbyte(0)==2 && k.byteslice(1,32)==@binding.reader(1) && active(k,a.now_ms,8) }
   phone=m.key_records.find { |k| k.getbyte(0)==4 && k.byteslice(98,16)==@binding.id(1) && k.byteslice(114,16)==@binding.id(2) && active(k,a.now_ms,2) && k.byteslice(130,2).unpack1('n')==2 }
   raise Failure unless reader && phone
   expiry=[m.expires_ms,TemplateStore.number(reader,140),TemplateStore.number(phone,140)].min
   if scope
    aad=scope.aad
    [6,22,38,54].each_with_index { |at,i| raise Failure unless aad.byteslice(at,16)==@binding.id(i) }
    raise Failure unless aad.byteslice(70,16)==@template && TemplateStore.number(aad,86)==@binding.generation && aad.byteslice(158,32)==@binding.reader(1) && TemplateStore.number(aad,110)==m.generation && TemplateStore.number(aad,118)==m.version && aad.byteslice(190,32)==m.digest && aad.byteslice(126,32)==OpenSSL::Digest::SHA256.digest(@binding.peer)
    expires=TemplateStore.number(aad,102);raise Failure unless expires>a.now_ms && expires-a.now_ms<=30*86400000;expiry=[expiry,expires].min
   end
   duration=[a.valid_for_ms,expiry-a.now_ms].min;raise Failure unless duration>0
   @mutex.synchronize { work[:deadline]=[work[:deadline],started+duration/1000.0].min;@changed.broadcast }
   raise Failure unless credentials(work)==session
   live(work);@prior=m;@now=a.now_ms
  rescue StandardError
   close;raise Failure.new('owner_changed'),cause:nil
  end
  def exchange(work,session,request=nil)
   http=Net::HTTP.new(@uri.host,@uri.port,nil);http.use_ssl=true;http.min_version=OpenSSL::SSL::TLS1_2_VERSION;http.verify_mode=OpenSSL::SSL::VERIFY_PEER;http.verify_hostname=true;http.cert_store=@store;http.max_retries=0
   wait=remaining(work);http.open_timeout=http.read_timeout=http.write_timeout=wait
   message=request ? Net::HTTP::Post.new(request.path) : Net::HTTP::Get.new(@uri.request_uri);message['Accept']=request ? 'application/json' : TemplateStore::CONTENT_TYPE;
   if request;request.headers.each { |key,value| message[key]=value };message.body=request.body;end
   message['X-Zrotext-CSRF']=session.csrf;message['Cookie']=session.cookie;message['Cache-Control']='no-store'
   limit=request ? 256 : 33075;wire=+''.b
   Timeout.timeout(wait) do
    http.start do |connection|
     connection.request(message) do |response|
      if [401,403].include?(response.code.to_i);close;raise Failure;end
      types=response.get_fields('content-type');valid_type=types && types.size==1 && (request ? /\Aapplication\/json(?:\s*;\s*charset=utf-8)?\z/i.match?(types.first) : types.first==TemplateStore::CONTENT_TYPE)
      raise Failure unless response.code=='200' && valid_type
      raise Failure if response.content_length && response.content_length>limit
      response.read_body { |chunk| raise Failure if wire.bytesize+chunk.bytesize>limit;wire<<chunk;live(work) }
     end
    end
   end
   wire
  end
  def read_work(work,expected=nil)
   session=credentials(work);unless !expected || session==expected;close;raise Failure;end
   authorize(work,nil,session)
   unless credentials(work)==session;close;raise Failure;end
   wire=exchange(work,session)
   live(work);scope=TemplateStore.parse(wire);revision=TemplateStore.number(scope.aad,94);raise Failure if revision<@head
   authorize(work,scope,session);HpkeRecipient.point(wire.byteslice(222,65));digest=OpenSSL::Digest::SHA256.hexdigest(wire);authorize(work,scope,session)
   raise Failure if revision==@head && digest!=@head_digest
   live(work);@head=revision;@head_digest=digest;Snapshot.new(scope,wire,digest)
  end
 end
end

require_relative 'owner_template_save'
