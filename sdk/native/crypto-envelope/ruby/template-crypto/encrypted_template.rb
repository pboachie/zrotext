# frozen_string_literal: true
require_relative '../template/template_content'
require_relative '../manifest_chain'
module ZrotextCandidate
  # Client-only ZTWT01; no persistence, network, approval or send authority.
  module EncryptedTemplate
    DOMAIN="ZT/workflow-template/hpke/v1\x00".b.freeze
    class Failure < StandardError
      def initialize = super('Encrypted template refused')
    end
    module_function
    def need(b) = (raise Failure unless b)
    def number(b,at) = b.byteslice(at,8).unpack1('Q>')
    class Scope
      def initialize(expected_aad)
        EncryptedTemplate.need(expected_aad.is_a?(String) && expected_aad.bytesize==222);b=expected_aad.b.dup
        EncryptedTemplate.need(b.byteslice(0,6)=="ZTWT\x01\x01".b)
        [6,22,38,54,70].each { |at| EncryptedTemplate.need(b.byteslice(at,16).bytes.any?(&:positive?)) }
        [86,94,102,110,118].each { |at| EncryptedTemplate.need(EncryptedTemplate.number(b,at).between?(1,2**63-1)) }
        EncryptedTemplate.need(EncryptedTemplate.number(b,94)<=128)
        [126,158,190].each { |at| EncryptedTemplate.need(b.byteslice(at,32).bytes.any?(&:positive?)) }
        @aad=b.freeze;freeze
      end
      def self.capture(account:,device:,line:,interval:,template:,binding:,revision:,expires:,trust:,version:,peer_digest:,reader:,manifest_digest:)
        ids=[account,device,line,interval,template];digests=[peer_digest,reader,manifest_digest];numbers=[binding,revision,expires,trust,version]
        EncryptedTemplate.need(ids.all? { |v| v.is_a?(String) && v.bytesize==16 } && digests.all? { |v| v.is_a?(String) && v.bytesize==32 } && numbers.all? { |v| v.is_a?(Integer) && v.between?(1,2**63-1) })
        new("ZTWT\x01\x01".b+ids.map(&:b).join+numbers.pack('Q>5')+digests.map(&:b).join)
      end
      def aad = @aad.dup
    end
    Authority=Struct.new(:manifest,:now_ms,keyword_init:true) do
      def initialize(**values);super;freeze;end
    end
    def active(key,now,permission) = key.getbyte(148)==1 && number(key,132)<=now && now<number(key,140) && (key.byteslice(130,2).unpack1('n')&permission)!=0
    def authorize(authority,aad)
      need(authority.instance_of?(Authority) && authority.manifest.instance_of?(ManifestChain::Verified) && authority.manifest.profile==2 && authority.now_ms.is_a?(Integer) && authority.now_ms.between?(1,2**63-1))
      m=ManifestChain.continue_chain(authority.manifest.bytes,authority.manifest,2,authority.now_ms);expires=number(aad,102)
      need(expires>authority.now_ms && expires-authority.now_ms<=(30*86400000) && m.account==aad.byteslice(6,16) && m.generation==number(aad,110) && m.version==number(aad,118) && m.digest==aad.byteslice(190,32))
      reader=nil;signer=false;m.key_records.each do |key|
        reader=key.byteslice(33,65) if key.getbyte(0)==2 && key.byteslice(1,32)==aad.byteslice(158,32) && active(key,authority.now_ms,8)
        signer=true if key.getbyte(0)==4 && key.byteslice(98,16)==aad.byteslice(22,16) && key.byteslice(114,16)==aad.byteslice(38,16) && active(key,authority.now_ms,2) && key.byteslice(130,2).unpack1('n')==2
      end
      need(reader && signer);reader
    end
    def final_check(before,point,aad,source)
      after=source.call;current=authorize(after,aad);need(after.now_ms>=before.now_ms && point==current && before.manifest.root_point==after.manifest.root_point && before.manifest.enrolled_root_point==after.manifest.enrolled_root_point)
    end
    # Source consults current permission/selection; signed history alone is insufficient.
    def seal(scope,content,source)
      aad=scope.aad;plain=content.canonical;need(plain.bytesize.between?(1,32768));before=source.call;point=authorize(before,aad)
      wrapped=HpkeRecipient.seal_content(point,DOMAIN+aad,aad,plain);need(wrapped.bytesize==65+plain.bytesize+16)
      output=aad+wrapped.byteslice(0,65)+[wrapped.bytesize-65].pack('N')+wrapped.byteslice(65..);final_check(before,point,aad,source);output
    rescue StandardError
      raise Failure, cause:nil
    ensure
      plain&.replace("\x00".b*plain.bytesize)
    end
    def open(scope,envelope,recipient,source)
      need(envelope.is_a?(String) && envelope.bytesize.between?(308,33075));wire=envelope.b.dup;aad=scope.aad
      need(wire.byteslice(0,222)==aad && wire.byteslice(287,4).unpack1('N')==wire.bytesize-291);before=source.call;point=authorize(before,aad)
      plain=recipient.call(point,wire.byteslice(222,65),DOMAIN+aad,aad,wire.byteslice(291..));need(plain.bytesize.between?(1,32768));final_check(before,point,aad,source);TemplateContent.parse(plain)
    rescue StandardError
      raise Failure, cause:nil
    ensure
      plain&.replace("\x00".b*plain.bytesize)
    end
    def digest(envelope)
      need(envelope.is_a?(String) && envelope.bytesize.between?(308,33075));OpenSSL::Digest::SHA256.digest(envelope.b.dup)
    end
    private_class_method :authorize,:active,:final_check
  end
end
