# frozen_string_literal: true
require_relative 'manifest_chain'
require_relative 'signed_envelope'
require_relative '../../crypto-candidate/ruby/candidate_body'

module ZrotextCandidate
  # Callback-based grant integration; no HTTP proof or durable accepted-history claim.
  module OriginalReplyReader
    DISCLOSURE='With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser and the explicitly listed customer-controlled readers. Stop closes new capture and transfer; retained encrypted content is deleted separately.'
    module_function
    def need(value) = (raise ArgumentError,'Original reply refused' unless value)
    def number(value,at) = value.byteslice(at,8).unpack1('Q>')
    def fixed(value,size)
      need(value.is_a?(String) && value.bytesize==size && value.bytes.any? { |b| b!=0 });value.b.dup.freeze
    end
    class Scope
      attr_reader :account,:device,:line,:interval,:connector,:grant,:reader,:peer
      def initialize(account,device,line,interval,connector,grant,reader,peer)
        @account,@device,@line,@interval,@connector,@grant=[account,device,line,interval,connector,grant].map { |v| OriginalReplyReader.fixed(v,16) }
        @reader=OriginalReplyReader.fixed(reader,32);OriginalReplyReader.need(peer.is_a?(String) && /\A\+[1-9][0-9]{1,14}\z/.match?(peer));@peer=peer.dup.freeze;freeze
      end
      def ==(other) = other.instance_of?(Scope) && [:account,:device,:line,:interval,:connector,:grant,:reader,:peer].all? { |k| public_send(k)==other.public_send(k) }
    end
    class Selection
      attr_reader :scope,:archive,:readers,:activation
      def initialize(scope,archive,readers,activation)
        @scope=scope;@archive=archive.dup.freeze;@readers=readers.map { |v| v.dup.freeze }.freeze;@activation=activation;freeze
      end
      private_class_method :new
    end
    Authority=Struct.new(:scope,:revision,:now_ms,:expires_ms,:manifest,keyword_init:true)
    class Cursor
      attr_reader :at
      def initialize(bytes) = (@bytes=bytes;@at=0)
      def take(count)
        OriginalReplyReader.need(count>=0 && count<=@bytes.bytesize-@at);out=@bytes.byteslice(@at,count);@at+=count;out
      end
      def id(count) = OriginalReplyReader.fixed(take(count),count)
      def positive
        n=take(8).unpack1('Q>');OriginalReplyReader.need(n.between?(1,2**63-1));n
      end
      def octet = take(1).getbyte(0)
      def text
        value=take(octet);OriginalReplyReader.need(value.bytes.all? { |v| v.between?(33,126) });value
      end
    end
    def key(manifest,role,id)
      result=manifest.key_records.find { |k| k.getbyte(0)==role && k.byteslice(1,32)==id };need(result);result
    end
    def active(k,now,scope) = need(k.getbyte(148)==1 && number(k,132)<=now && now<number(k,140) && (k.byteslice(130,2).unpack1('n')&scope)!=0)
    def signature(point,input,domain,body)
      need(input.bytesize==64);ManifestChain.signature(point,input.b.dup,domain,body)
    end
    def verify_selection(input,approval,installation,activation,accepted_ms,scope)
      need(input.bytesize.between?(380,1536) && activation.instance_of?(ManifestChain::Verified) && activation.profile==2 && scope.instance_of?(Scope));raw=input.b.dup;p=Cursor.new(raw)
      need(p.take(5)=="ZTCA\x02".b);account=p.id(16);device=p.id(16);line=p.id(16);p.positive;interval=p.id(16);p.id(16);p.id(16);p.id(32)
      expires=p.positive;peer=p.text;content=p.text;disclosure=p.take(32);archive=p.id(32);signer=p.id(32);generation=p.positive;previous=p.positive;p.id(32);version=p.positive;digest=p.id(32);p.positive;p.positive;site=p.text;instance=p.text
      count=p.octet;need(count.between?(1,6));readers=[];connectors=[];grants=[];chosen=false
      count.times do
        connector=p.id(16);grant=p.id(16);reader=p.id(32);need(readers.empty? || readers.last<reader);need(!connectors.include?(connector) && !grants.include?(grant));chosen||=connector==scope.connector && grant==scope.grant && reader==scope.reader;connectors<<connector;grants<<grant;readers<<reader
      end
      need(p.at==raw.bytesize && chosen && content=='conversation-content-v1' && disclosure==OpenSSL::Digest::SHA256.digest(DISCLOSURE) && site.bytesize.between?(1,64) && instance.bytesize.between?(1,64) && version==previous+1 && accepted_ms.is_a?(Integer) && accepted_ms>0 && accepted_ms<expires && peer==scope.peer && account==scope.account && device==scope.device && line==scope.line && interval==scope.interval)
      verified=ManifestChain.continue_chain(activation.bytes,activation,2,accepted_ms);need(verified.generation==generation && verified.version==version && verified.digest==digest && verified.account==scope.account)
      signing=key(verified,4,signer);active(signing,accepted_ms,2);need(signing.byteslice(98,16)==scope.device && signing.byteslice(114,16)==scope.line)
      signature(signing.byteslice(33,65),approval,'zrotext/conversation/approve/v2',raw);signature(signing.byteslice(33,65),installation,'zrotext/conversation/install/v2',raw)
      Selection.send(:new,scope,archive,readers,verified)
    end
    def authority(value,scope)
      need(value.instance_of?(Authority));revision=value.revision&.dup;now=value.now_ms;expires=value.expires_ms;manifest=value.manifest
      need(value.scope==scope && revision.is_a?(String) && revision.bytesize.between?(1,128) && now.is_a?(Integer) && expires.is_a?(Integer) && now>0 && now<expires && expires<2**63 && manifest.instance_of?(ManifestChain::Verified) && manifest.profile==2)
      Authority.new(scope:scope,revision:revision.freeze,now_ms:now,expires_ms:expires,manifest:ManifestChain.continue_chain(manifest.bytes,manifest,2,now)).freeze
    end
    def open_software(input,event,historical,selection,scope,recipient,source)
      open_with_recipient(input,event,historical,selection,scope,HpkeRecipient.software(recipient),source)
    end
    # Generic callable unwrap adapters do not establish hardware qualification.
    def open_with_recipient(input,expected_event,historical,selection,scope,recipient,source)
      need(input.bytesize.between?(426,34082) && historical.instance_of?(ManifestChain::Verified) && historical.profile==2 && selection.instance_of?(Selection) && selection.scope==scope && recipient.respond_to?(:call) && source.respond_to?(:call));b=input.b.dup;event=fixed(expected_event,16)
      need(b.getbyte(4)==2 && b.getbyte(5)==2 && b.byteslice(26,16)==event);initial=authority(source.call,scope);current=initial.manifest
      need(historical.account==scope.account && current.account==scope.account && historical.generation==current.generation && current.generation==selection.activation.generation && historical.enrolled_root_point==current.enrolled_root_point && current.enrolled_root_point==selection.activation.enrolled_root_point && historical.descends_from(selection.activation) && current.descends_from(historical))
      observed=number(b,146);need(observed>0 && observed<=initial.now_ms && observed<historical.expires_ms && (historical.issued_ms<=observed || historical.issued_ms-observed<=300000) && b.byteslice(10,16)==scope.account && b.byteslice(42,16)==scope.device && b.byteslice(58,16)==scope.line && number(b,74)==historical.version && b.byteslice(82,32)==historical.digest)
      signer=key(historical,4,b.byteslice(114,32));active(signer,observed,2);need(signer.byteslice(98,16)==scope.device && signer.byteslice(114,16)==scope.line);envelope=SignedEnvelope.verify(b,2,signer.byteslice(33,65));prefix=10+b.byteslice(8,2).unpack1('n');ending=prefix+16+b.byteslice(prefix+12,4).unpack1('N')
      need(b.byteslice(179,prefix-179)==scope.peer && b.getbyte(ending)==1+selection.readers.size)
      b.getbyte(ending).times do |i|
        at=ending+1+146*i;role=i.zero? ? 2 : 3;id=i.zero? ? selection.archive : selection.readers[i-1];need(b.getbyte(at)==role && b.byteslice(at+1,32)==id);active(key(historical,role,id),observed,8)
      end
      selected=key(current,3,scope.reader);active(selected,initial.now_ms,8);cek=nil;plain=nil;transferred=false
      begin
        cek=recipient.call(selected.byteslice(33,65),envelope.encapsulated(3,scope.reader),envelope.wrap_info(3,scope.reader),envelope.wrap_aad(3,scope.reader),envelope.wrapped_key(3,scope.reader));plain=Zrotext::CandidateBody.open(content_key:cek,nonce:envelope.nonce,verified_aad:envelope.body_aad,ciphertext:envelope.body_ciphertext);after=authority(source.call,scope)
        need(after.revision==initial.revision && after.now_ms>=initial.now_ms && after.now_ms<initial.expires_ms && after.now_ms<number(selected,140) && after.manifest.generation==current.generation && after.manifest.version==current.version && after.manifest.root_point==current.root_point && after.manifest.enrolled_root_point==current.enrolled_root_point && after.manifest.digest==current.digest);transferred=true;plain
      ensure
        plain&.replace("\x00".b*plain.bytesize) unless transferred
        cek&.replace("\x00".b*cek.bytesize)
      end
    end
    private_class_method :key,:active,:signature,:authority
  end
end
