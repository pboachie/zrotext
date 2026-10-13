# frozen_string_literal: true
require_relative 'manifest_chain'
require_relative 'signed_envelope'
require_relative '../../crypto-candidate/ruby/candidate_body'

module ZrotextCandidate
  module SealedReader02
    module_function
    def need(value) = (raise ArgumentError,'Reader authority refused' unless value)
    def number(bytes,at) = bytes.byteslice(at,8).unpack1('Q>')
    def find(records,role,id)
      record=records.find { |r| r.getbyte(0)==role && r.byteslice(1,32)==id }
      need(record);record
    end
    def active(record,now) = need(record.getbyte(148)==1 && number(record,132)<=now && now<number(record,140))
    def open(input,manifest,now,recipient_role,recipient_id,recipient,current)
      open_with_recipient(input,manifest,now,recipient_role,recipient_id,HpkeRecipient.software(recipient),current)
    end
    def open_historical_archive(input,historical,selected,now,recipient_id,recipient,current)
      open_historical_with_recipient(input,historical,selected,now,recipient_id,HpkeRecipient.software(recipient),current)
    end
    # Trusted callable unwrap adapter; this interface does not attest hardware custody.
    def open_with_recipient(input,manifest,now,role,id,recipient,current)
      open_bound(input,manifest,manifest,now,role,id,recipient,current,false)
    end
    def open_historical_with_recipient(input,historical,selected,now,id,recipient,current)
      open_bound(input,historical,selected,now,2,id,recipient,current,true)
    end
    def open_bound(input,manifest,selected_manifest,now,recipient_role,recipient_id,recipient,current,historical)
      need(manifest.instance_of?(ManifestChain::Verified) && manifest.profile==2 && selected_manifest.instance_of?(ManifestChain::Verified) && selected_manifest.profile==2 && selected_manifest.descends_from(manifest) && now>=selected_manifest.comparison_ms && now<selected_manifest.expires_ms)
      b=input.b.dup;id=recipient_id.b.dup;need(b.bytesize.between?(426,36864) && id.bytesize==32)
      kind=b.getbyte(5);need([1,2].include?(kind) && (!historical || kind==2));records=manifest.key_records
      signer=find(records,kind==1 ? 5 : 4,b.byteslice(114,32));active(signer,now) unless historical
      envelope=SignedEnvelope.verify(b,2,signer.byteslice(33,65))
      need(b.byteslice(10,16)==manifest.account && number(b,74)==manifest.version && b.byteslice(82,32)==manifest.digest)
      need(signer.byteslice(114,16)==b.byteslice(58,16));need(signer.byteslice(98,16)==b.byteslice(42,16)) if kind==2
      observed=number(b,146);need(observed>0 && observed<=now && observed>=manifest.issued_ms && observed<manifest.expires_ms);active(signer,observed)
      need(now<number(b,154) && number(b,154)<=manifest.expires_ms) if kind==1
      prefix=10+b.byteslice(8,2).unpack1('n');ending=prefix+16+b.byteslice(prefix+12,4).unpack1('N');count=b.getbyte(ending);selected=nil
      count.times do |i|
        at=ending+1+146*i;role=b.getbyte(at);wrap_id=b.byteslice(at+1,32);record=find(records,role,wrap_id);active(record,now) unless historical
        active(record,observed)
        scope=record.byteslice(130,2).unpack1('n');need((scope & (kind==1 ? 4 : 8))!=0)
        need(kind==1 && record.byteslice(98,16)==b.byteslice(42,16) && record.byteslice(114,16)==b.byteslice(58,16)) if role==1
        selected=record if role==recipient_role && wrap_id==id
      end
      need(selected);live=find(selected_manifest.key_records,recipient_role,id);active(live,now)
      need((live.byteslice(130,2).unpack1('n') & (kind==1 ? 4 : 8))!=0 && live.byteslice(33,65)==selected.byteslice(33,65))
      need(current.call(selected_manifest.account,selected_manifest.version,selected_manifest.digest,b.dup));cek=nil
      begin
        cek=recipient.call(selected.byteslice(33,65),envelope.encapsulated(recipient_role,id),envelope.wrap_info(recipient_role,id),envelope.wrap_aad(recipient_role,id),envelope.wrapped_key(recipient_role,id))
        result=Zrotext::CandidateBody.open(content_key:cek,nonce:envelope.nonce,verified_aad:envelope.body_aad,ciphertext:envelope.body_ciphertext)
        need(current.call(selected_manifest.account,selected_manifest.version,selected_manifest.digest,b.dup));result
      ensure
        cek&.replace("\x00".b*cek.bytesize)
      end
    end
    private_class_method :open_bound
  end
end
