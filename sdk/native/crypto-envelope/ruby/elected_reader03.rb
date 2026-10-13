# frozen_string_literal: true
require_relative 'election03'
require_relative 'signed_envelope'
require_relative '../../crypto-candidate/ruby/candidate_body'
module ZrotextCandidate
  module ElectedReader03
    module_function
    def need(value) = (raise ArgumentError,'Elected reader refused' unless value)
    def number(b,at) = b.byteslice(at,8).unpack1('Q>')
    def find(records,role,id)
      value=records.find { |r| r.getbyte(0)==role && r.byteslice(1,32)==id };need(value);value
    end
    def active(r,when_ms) = need(r.getbyte(148)==1 && number(r,132)<=when_ms && when_ms<number(r,140))
    def open_software(input,manifest,proof,source,expected_message,expected_peer,recipient)
      open_with_recipient(input,manifest,proof,source,expected_message,expected_peer,HpkeRecipient.software(recipient))
    end
    # Trusted callable unwrap adapter; no custody claim follows from this interface.
    def open_with_recipient(input,manifest,proof,source,expected_message,expected_peer,recipient)
      b=input.b.dup;message=expected_message.b.dup;peer=expected_peer.dup
      need(b.bytesize.between?(557,34213) && message.bytesize==16 && message.bytes.any? { |v| v!=0 })
      record,now=source.call;authority=Election03.require_current(proof,manifest,record,now)
      need(b.getbyte(4)==3 && b.getbyte(5)==1 && b.byteslice(10,16)==authority.field('accountId') && b.byteslice(26,16)==message && b.byteslice(42,16)==authority.field('deviceId') && b.byteslice(58,16)==authority.field('lineId'))
      need(number(b,74)==manifest.version && b.byteslice(82,32)==manifest.digest);records=manifest.key_records
      signer=find(records,5,b.byteslice(114,32));active(signer,now);need(signer.byteslice(114,16)==authority.field('lineId'))
      envelope=SignedEnvelope.verify(b,3,signer.byteslice(33,65));prefix=10+b.byteslice(8,2).unpack1('n');need(b.byteslice(164,prefix-164)==peer)
      observed=number(b,146);expires=number(b,154)
      need(observed>0 && observed<=now && observed>=manifest.issued_ms && now<expires && expires<=manifest.expires_ms && expires<=authority.number('permissionExpiresAtMs'));active(signer,observed);need(expires<=number(signer,140))
      ending=prefix+16+b.byteslice(prefix+12,4).unpack1('N');elected=authority.field('selectedReaderKeyId');selected=nil
      b.getbyte(ending).times do |i|
        at=ending+1+146*i;role=b.getbyte(at);id=b.byteslice(at+1,32);key=find(records,role,id);active(key,now);active(key,observed)
        need((key.byteslice(130,2).unpack1('n')&4)!=0 && expires<=number(key,140))
        if role==1
          need(id==elected && key.byteslice(98,16)==authority.field('deviceId') && key.byteslice(114,16)==authority.field('lineId'));selected=key
        end
      end
      need(selected);cek=nil
      begin
        cek=recipient.call(selected.byteslice(33,65),envelope.encapsulated(1,elected),envelope.wrap_info(1,elected),envelope.wrap_aad(1,elected),envelope.wrapped_key(1,elected))
        result=Zrotext::CandidateBody.open(content_key:cek,nonce:envelope.nonce,verified_aad:envelope.body_aad,ciphertext:envelope.body_ciphertext)
        after,later=source.call;need(later>=now && later<expires);Election03.require_current(proof,manifest,after,later);result
      ensure
        cek&.replace("\x00".b*cek.bytesize)
      end
    end
  end
end
