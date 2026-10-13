# frozen_string_literal: true
require_relative '../signed_envelope'
require_relative '../custody/protected_signer'

module ZrotextCandidate
  # Fresh candidate bytes only; comparison is not a live transport grant.
  module Compose02
    module_function
    def need(value) = (raise ArgumentError,'Profile02 composition refused' unless value)
    def label(value) = value.b+"\x00".b
    def sha(value) = OpenSSL::Digest::SHA256.digest(value)
    def number(bytes,at) = bytes.byteslice(at,8).unpack1('Q>')
    def encrypt(key,nonce,text,aad)
      cipher=OpenSSL::Cipher.new('aes-256-gcm').encrypt
      cipher=OpenSSL::Cipher.new('aes-128-gcm').encrypt if key.bytesize==16
      cipher.key=key;cipher.iv=nonce;cipher.auth_data=aad
      cipher.update(text)+cipher.final+cipher.auth_tag(16)
    end
    def wrap(point,cek,info,aad)
      ephemeral=OpenSSL::PKey::EC.generate('prime256v1');enc=ephemeral.public_key.to_octet_string(:uncompressed);buffers=[]
      keep=->(v) { buffers<<v;v }
      dh=keep.call(ephemeral.derive(HpkeRecipient.point(point)));need(dh.bytesize==32)
      prk=keep.call(HpkeRecipient.extract(HpkeRecipient::KEM,''.b,'eae_prk',dh))
      shared=keep.call(HpkeRecipient.expand(HpkeRecipient::KEM,prk,'shared_secret',enc+point,32))
      context="\x00".b+HpkeRecipient.extract(HpkeRecipient::SUITE,''.b,'psk_id_hash',''.b)+HpkeRecipient.extract(HpkeRecipient::SUITE,''.b,'info_hash',info)
      schedule=keep.call(HpkeRecipient.extract(HpkeRecipient::SUITE,shared,'secret',''.b))
      key=keep.call(HpkeRecipient.expand(HpkeRecipient::SUITE,schedule,'key',context,16))
      nonce=keep.call(HpkeRecipient.expand(HpkeRecipient::SUITE,schedule,'base_nonce',context,12))
      enc+encrypt(key,nonce,cek,aad)
    ensure
      buffers&.each { |b| b.replace("\x00".b*b.bytesize) }
    end
    def fresh(manifest:,now_ms:,message:,device:,line:,observed_ms:,expires_ms:,peer:,content:,signer:,recipients:)
      need(manifest.instance_of?(ManifestChain::Verified) && manifest.profile==2 && signer.instance_of?(ProtectedSigner))
      need([message,device,line].all? { |v| v.instance_of?(String) && v.bytesize==16 })
      message,device,line=[message,device,line].map { |v| v.b.dup }
      need([now_ms,observed_ms,expires_ms].all? { |v| v.instance_of?(Integer) && v.between?(0,2**63-1) })
      need(observed_ms<expires_ms && expires_ms-observed_ms<=900000)
      current=ManifestChain.continue_chain(manifest.bytes,manifest,2,now_ms)
      need(peer.instance_of?(String) && /\A\+[1-9][0-9]{1,14}\z/.match?(peer));peer=peer.dup
      need(content.instance_of?(String) && content.length.between?(1,32768))
      text=content.encode('UTF-8').b
      begin
        valid=text.force_encoding('UTF-8').valid_encoding?;text.force_encoding('ASCII-8BIT')
        need(valid && text.bytesize.between?(1,32768) && !text.include?("\x00".b) && !text.start_with?("\xef\xbb\xbf".b))
        need(recipients.instance_of?(Array) && recipients.length.between?(2,8))
        requested=recipients.map { |v| need(v.instance_of?(Array) && v.length==2 && v[0].instance_of?(Integer) && v[0].between?(1,3) && v[1].instance_of?(String) && v[1].bytesize==32);[v[0],v[1].b.dup] }.sort
        need(requested.uniq.length==requested.length && requested.count { |role,_| role==1 }==1 && requested.count { |role,_| role==2 }==1)
        keys=current.key_records;public=signer.public_point;signer_id=sha(label('ZTSE/key/v1')+[257].pack('n')+public)
        key=keys.find { |k| k.getbyte(0)==5 && k.byteslice(1,32)==signer_id }
        need(key && key.getbyte(148)==1 && number(key,132)<=now_ms && now_ms<number(key,140) && key.byteslice(130,2).unpack1('n')==1 && key.byteslice(114,16)==line && key.byteslice(33,65)==public)
        targets=requested.map do |role,id|
          k=keys.find { |v| v.getbyte(0)==role && v.byteslice(1,32)==id }
          need(k && k.getbyte(148)==1 && number(k,132)<=now_ms && now_ms<number(k,140) && (k.byteslice(130,2).unpack1('n')&4)!=0)
          need(k.byteslice(98,16)==device && k.byteslice(114,16)==line) if role==1
          [role,id,k.byteslice(33,65)]
        end
        fields=current.account+message+device+line+[current.version].pack('Q>')+current.digest+signer_id+[observed_ms,expires_ms].pack('Q>2')+[1,peer.bytesize].pack('C2')+peer.b
        prefix="ZTSE\x02\x01\x00\x00".b+[fields.bytesize].pack('n')+fields
        cek=SecureRandom.random_bytes(32);nonce=SecureRandom.random_bytes(12)
        body=encrypt(cek,nonce,text,label('ZTSE/body/v2')+prefix)
        wraps=targets.map { |role,id,point| [role].pack('C')+id+wrap(point,cek,label('ZTSE/wrap/v2')+prefix+[role].pack('C')+id,''.b) }
        unsigned=prefix+nonce+[body.bytesize].pack('N')+body+[wraps.length].pack('C')+wraps.join.b
        envelope=unsigned+signer.sign_envelope02(unsigned);SignedEnvelope.verify(envelope,2,public);envelope
      ensure
        text.replace("\x00".b*text.bytesize);cek&.replace("\x00".b*cek.bytesize)
      end
    end
    private_class_method :need,:label,:sha,:number,:encrypt,:wrap
  end
end
