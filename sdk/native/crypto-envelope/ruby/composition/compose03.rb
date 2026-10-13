# frozen_string_literal: true
require_relative '../elected_reader03'
require_relative '../custody/protected_signer'

module ZrotextCandidate
  module Compose03
    module_function
    def need(value) = (raise ArgumentError,'Candidate composition refused' unless value)
    def label(value) = value.b+"\x00".b
    def sha(value) = OpenSSL::Digest::SHA256.digest(value)
    def number(bytes,at) = bytes.byteslice(at,8).unpack1('Q>')
    def capture(manifest:,proof:,authority:,message:,observed_ms:,expires_ms:,peer:,content:,signer:,recipients:)
      need(message.instance_of?(String) && message.bytesize==16 && recipients.instance_of?(Array) && recipients.length.between?(2,8))
      copied=recipients.map { |r| need(r.instance_of?(Array) && r.length==2 && r[0].instance_of?(Integer) && r[1].instance_of?(String) && r[1].bytesize==32);[r[0],r[1].b.dup.freeze].freeze }.freeze
      need(peer.instance_of?(String) && content.instance_of?(String) && content.length.between?(1,32768) && signer.instance_of?(ProtectedSigner))
      {manifest:manifest,proof:proof,authority:authority,message:message.b.dup.freeze,observed_ms:observed_ms,expires_ms:expires_ms,peer:peer.dup.freeze,content:content.dup.freeze,signer:signer,recipients:copied}.freeze
    end
    def find(keys,role,id)
      result=keys.find { |k| k.getbyte(0)==role && k.byteslice(1,32)==id };need(result);result
    end
    def authorize(r)
      record,now=r[:authority].call
      bound=Election03.require_current(r[:proof],r[:manifest],record,now)
      observed,expires=r.values_at(:observed_ms,:expires_ms)
      need([observed,expires].all? { |n| n.instance_of?(Integer) && n.between?(1,2**63-1) })
      need(r[:message].bytes.any? { |b| b!=0 } && observed<=now && now<expires && expires-observed<=900000)
      need(/\A\+[1-9][0-9]{1,14}\z/.match?(r[:peer]) && r[:content].length.between?(1,32768))
      text=r[:content].encode('UTF-8').b
      transferred=false
      begin
        valid=text.force_encoding('UTF-8').valid_encoding?;text.force_encoding('ASCII-8BIT')
        need(valid && text.bytesize.between?(1,32768) && !text.include?("\x00".b) && !text.start_with?("\xef\xbb\xbf".b))
        public=r[:signer].public_point
        signer_id=sha(label('ZTSE/key/v1')+[257].pack('n')+public)
        keys=r[:manifest].key_records;signer=find(keys,5,signer_id)
        need(signer.getbyte(148)==1 && number(signer,132)<=observed && now<number(signer,140) && signer.byteslice(130,2).unpack1('n')==1 && signer.byteslice(114,16)==bound.field('lineId') && signer.byteslice(33,65)==public)
        requested=r[:recipients].sort_by { |role,id| [role,id] }
        need(requested.all? { |role,_| role.between?(1,3) } && requested.uniq.length==requested.length && requested.count { |role,_| role==1 }==1 && requested.count { |role,_| role==2 }==1)
        deadline=[r[:manifest].expires_ms,number(signer,140),bound.number('permissionExpiresAtMs')].min
        targets=requested.map do |role,id|
          k=find(keys,role,id)
          need(k.getbyte(148)==1 && number(k,132)<=observed && now<number(k,140) && (k.byteslice(130,2).unpack1('n')&4)!=0)
          need(id==bound.field('selectedReaderKeyId') && k.byteslice(98,16)==bound.field('deviceId') && k.byteslice(114,16)==bound.field('lineId')) if role==1
          deadline=[deadline,number(k,140)].min
          [role,id,k.byteslice(33,65).freeze].freeze
        end.freeze
        need(expires<=deadline)
        fields=bound.field('accountId')+r[:message]+bound.field('deviceId')+bound.field('lineId')+[bound.number('manifestVersion')].pack('Q>')+bound.field('manifestDigest')+signer_id+[observed,expires].pack('Q>2')+[1,r[:peer].bytesize].pack('C2')+r[:peer].b
        prefix="ZTSE\x03\x01\x00\x00".b+[fields.bytesize].pack('n')+fields
        intent=sha(label('ZTSE/native-outbound-intent/v1')+prefix+sha(text)+targets.map { |role,id,p| [role].pack('C')+id+p }.join.b+bound.field('bindingId')+[bound.number('bindingGeneration')].pack('Q>')+bound.field('electionCommitment')+bound.field('electionBundleSha256'))
        plan={prefix:prefix.freeze,text:text,targets:targets,public:public.freeze,intent:intent.freeze,now:now}.freeze
        transferred=true;plan
      ensure
        text.replace("\x00".b*text.bytesize) unless transferred
      end
    end
    def recheck(r,plan,floor=plan[:now])
      latest=authorize(r)
      need(latest[:now]>=floor && latest[:intent]==plan[:intent]);latest[:now]
    ensure
      latest&.fetch(:text)&.replace("\x00".b*latest[:text].bytesize)
    end
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
    def compose(r,plan,floor=plan[:now],&checkpoint)
      cek=SecureRandom.random_bytes(32);nonce=SecureRandom.random_bytes(12)
      body=encrypt(cek,nonce,plan[:text],label('ZTSE/body/v3')+plan[:prefix])
      wraps=plan[:targets].map do |role,id,point|
        suffix=plan[:prefix]+[role].pack('C')+id
        [role].pack('C')+id+wrap(point,cek,label('ZTSE/wrap/v3')+suffix,label('ZTSE/wrap-aad/v3')+suffix)
      end
      unsigned=plan[:prefix]+nonce+[body.bytesize].pack('N')+body+[wraps.length].pack('C')+wraps.join.b
      envelope=unsigned+r[:signer].sign_envelope03(unsigned)
      SignedEnvelope.verify(envelope,3,plan[:public]);checked=recheck(r,plan,floor);checkpoint&.call(checked)
      envelope
    ensure
      cek&.replace("\x00".b*cek.bytesize)
    end
    def fresh(**inputs)
      r=capture(**inputs);plan=authorize(r);compose(r,plan)
    ensure
      plan&.fetch(:text)&.replace("\x00".b*plan[:text].bytesize)
    end
    def read(file,size)
      value=file.read(size);need(value && value.bytesize==size);value
    end
    def compose_or_replay(path,root_pin,fingerprint,**inputs)
      pin=root_pin.b.dup;fp=fingerprint.b.dup;trust=ManifestChain::RootPin.enroll(pin,fp)
      r=capture(**inputs);plan=authorize(r)
      need(trust.account==r[:manifest].account && trust.point==r[:manifest].root_point)
      header='ZTJ4'.b+pin+fp;identity=plan[:prefix].byteslice(10,64)
      need(!File.symlink?(path))
      created=false
      begin
        file=File.open(path,File::RDWR|File::CREAT|File::EXCL,0o600);created=true
      rescue Errno::EEXIST
        file=File.open(path,File::RDWR)
      end
      begin
        file.binmode
        locked=false
        100.times { locked=file.flock(File::LOCK_EX|File::LOCK_NB);break if locked;sleep 0.05 }
        need(locked)
        if created
          clock=[plan[:now]].pack('Q>');file.write(header+clock+sha(header+clock));file.flush;file.fsync
        end
        need(file.size.between?(header.bytesize+40,10000000));file.rewind;need(read(file,header.bytesize)==header)
        clock=read(file,8);need(read(file,32)==sha(header+clock));floor=clock.unpack1('Q>');need(floor.between?(1,2**63-1) && plan[:now]>=floor)
        checkpoint=->(now) do
          need(now>=floor)
          if now>floor
            position=file.pos;clock=[now].pack('Q>');file.seek(header.bytesize);file.write(clock+sha(header+clock));file.flush;file.fsync;file.seek(position);floor=now
          end
        end
        checkpoint.call(plan[:now])
        count=0;stored=nil
        while file.pos<file.size
          count+=1;need(count<=256 && file.size-file.pos>=132)
          leading=read(file,100);size=leading.byteslice(96,4).unpack1('N');need(size.between?(557,34213) && file.size-file.pos>=size+32)
          envelope=read(file,size);need(read(file,32)==sha(leading+envelope))
          next unless leading.byteslice(0,64)==identity
          need(stored.nil? && leading.byteslice(64,32)==plan[:intent]);SignedEnvelope.verify(envelope,3,plan[:public]);need(envelope.byteslice(0,plan[:prefix].bytesize)==plan[:prefix])
          ending=plan[:prefix].bytesize+16+envelope.byteslice(plan[:prefix].bytesize+12,4).unpack1('N');need(envelope.getbyte(ending)==plan[:targets].length)
          plan[:targets].each_with_index { |(role,id,_),i| need(envelope.getbyte(ending+1+146*i)==role && envelope.byteslice(ending+2+146*i,32)==id) }
          stored=envelope
        end
        checkpoint.call(recheck(r,plan,floor));return stored if stored
        need(count<256);envelope=compose(r,plan,floor,&checkpoint);record=identity+plan[:intent]+[envelope.bytesize].pack('N')+envelope
        file.write(record);file.write(sha(record));file.flush;file.fsync;checkpoint.call(recheck(r,plan,floor));envelope
      ensure
        file.close
      end
    ensure
      plan&.fetch(:text)&.replace("\x00".b*plan[:text].bytesize)
    end
    private_class_method :need,:label,:sha,:number,:capture,:find,:authorize,:recheck,:encrypt,:wrap,:compose,:read
  end
end
