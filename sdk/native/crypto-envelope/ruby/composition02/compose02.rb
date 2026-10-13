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
    def authorize(manifest:,now_ms:,message:,device:,line:,observed_ms:,expires_ms:,peer:,content:,signer:,recipients:)
      need(manifest.instance_of?(ManifestChain::Verified) && manifest.profile==2 && signer.instance_of?(ProtectedSigner))
      need([message,device,line].all? { |v| v.instance_of?(String) && v.bytesize==16 })
      message,device,line=[message,device,line].map { |v| v.b.dup }
      need([now_ms,observed_ms,expires_ms].all? { |v| v.instance_of?(Integer) && v.between?(0,2**63-1) })
      need(observed_ms<expires_ms && expires_ms-observed_ms<=900000)
      current=ManifestChain.continue_chain(manifest.bytes,manifest,2,now_ms)
      need(peer.instance_of?(String) && /\A\+[1-9][0-9]{1,14}\z/.match?(peer));peer=peer.dup
      need(content.instance_of?(String) && content.length.between?(1,32768))
      text=content.encode('UTF-8').b;transferred=false
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
        intent=sha(label('ZTSE/native-outbound02-intent/v1')+prefix+sha(text)+targets.map { |role,id,point| [role].pack('C')+id+point }.join.b)
        plan={prefix:prefix,text:text,targets:targets,public:public,intent:intent,now:now_ms};transferred=true;plan
      ensure
        text.replace("\x00".b*text.bytesize) unless transferred
      end
    end
    def capture(**inputs)
      r=inputs.dup
      [:message,:device,:line,:peer,:content].each { |key| need(r[key].instance_of?(String));r[key]=r[key].dup.freeze }
      need(r[:recipients].instance_of?(Array))
      r[:recipients]=r[:recipients].map { |v| need(v.instance_of?(Array) && v.length==2 && v[1].instance_of?(String));[v[0],v[1].b.dup.freeze].freeze }.freeze
      r.freeze
    end
    def compose(r,plan)
        cek=SecureRandom.random_bytes(32);nonce=SecureRandom.random_bytes(12)
        body=encrypt(cek,nonce,plan[:text],label('ZTSE/body/v2')+plan[:prefix])
        wraps=plan[:targets].map { |role,id,point| [role].pack('C')+id+wrap(point,cek,label('ZTSE/wrap/v2')+plan[:prefix]+[role].pack('C')+id,''.b) }
        unsigned=plan[:prefix]+nonce+[body.bytesize].pack('N')+body+[wraps.length].pack('C')+wraps.join.b
        envelope=unsigned+r[:signer].sign_envelope02(unsigned);SignedEnvelope.verify(envelope,2,plan[:public]);envelope
    ensure
      cek&.replace("\x00".b*cek.bytesize)
    end
    def fresh(**inputs)
      r=capture(**inputs);plan=authorize(**r);compose(r,plan)
    ensure
      plan&.fetch(:text)&.replace("\x00".b*plan[:text].bytesize)
    end
    def recheck(r,plan,source,floor)
      need(source.respond_to?(:call));selected,now=source.call
      need(selected.instance_of?(ManifestChain::Verified) && now.instance_of?(Integer) && now.between?(1,2**63-1))
      need(now>=floor && now>=r[:now_ms] && r[:observed_ms]>0 && r[:observed_ms]<=now && now<r[:expires_ms])
      need(selected.profile==2 && selected.generation==r[:manifest].generation && selected.descends_from(r[:manifest]))
      current=ManifestChain.continue_chain(selected.bytes,selected,2,now);keys=current.key_records
      signer=keys.find { |k| k.getbyte(0)==5 && k.byteslice(1,32)==plan[:prefix].byteslice(114,32) }
      need(signer && signer.getbyte(148)==1 && number(signer,132)<=now && now<number(signer,140) && signer.byteslice(130,2).unpack1('n')==1 && signer.byteslice(114,16)==r[:line] && signer.byteslice(33,65)==plan[:public])
      plan[:targets].each do |role,id,point|
        key=keys.find { |k| k.getbyte(0)==role && k.byteslice(1,32)==id }
        need(key && key.getbyte(148)==1 && number(key,132)<=now && now<number(key,140) && (key.byteslice(130,2).unpack1('n')&4)!=0 && key.byteslice(33,65)==point)
        need(key.byteslice(98,16)==r[:device] && key.byteslice(114,16)==r[:line]) if role==1
      end
      now
    end
    def read(file,size)
      value=file.read(size);need(value && value.bytesize==size);value
    end
    def compose_or_replay(path,root_pin,fingerprint,current:,**inputs)
      pin=root_pin.b.dup;fp=fingerprint.b.dup;trust=ManifestChain::RootPin.enroll(pin,fp)
      r=capture(**inputs);plan=authorize(**r)
      recheck(r,plan,current,plan[:now]);need(trust.account==r[:manifest].account && trust.point==r[:manifest].enrolled_root_point)
      header='ZTJ2'.b+pin+fp;identity=plan[:prefix].byteslice(10,64)
      need(!File.symlink?(path))
      created=false
      begin
        file=File.open(path,File::RDWR|File::BINARY|File::CREAT|File::EXCL,0o600);created=true
      rescue Errno::EEXIST
        file=File.open(path,File::RDWR|File::BINARY)
      end
      begin
        file.binmode
        locked=false
        100.times { locked=file.flock(File::LOCK_EX|File::LOCK_NB);break if locked;sleep 0.05 }
        need(locked)
        if created
          clock=[recheck(r,plan,current,plan[:now])].pack('Q>');file.write(header+clock+sha(header+clock));file.flush;file.fsync
        end
        need(file.size.between?(header.bytesize+40,10000000));file.rewind;need(read(file,header.bytesize)==header)
        clock=read(file,8);need(read(file,32)==sha(header+clock));floor=clock.unpack1('Q>');need(floor.between?(1,2**63-1))
        checkpoint=->(now) do
          need(now>=floor)
          if now>floor
            position=file.pos;clock=[now].pack('Q>');file.seek(header.bytesize);file.write(clock+sha(header+clock));file.flush;file.fsync;file.seek(position);floor=now
          end
        end
        checkpoint.call(recheck(r,plan,current,plan[:now]))
        count=0;stored=nil
        while file.pos<file.size
          count+=1;need(count<=256 && file.size-file.pos>=132)
          leading=read(file,100);size=leading.byteslice(96,4).unpack1('N');need(size.between?(557,34213) && file.size-file.pos>=size+32)
          envelope=read(file,size);need(read(file,32)==sha(leading+envelope))
          next unless leading.byteslice(0,64)==identity
          need(stored.nil? && leading.byteslice(64,32)==plan[:intent]);SignedEnvelope.verify(envelope,2,plan[:public]);need(envelope.byteslice(0,plan[:prefix].bytesize)==plan[:prefix])
          ending=plan[:prefix].bytesize+16+envelope.byteslice(plan[:prefix].bytesize+12,4).unpack1('N');need(envelope.getbyte(ending)==plan[:targets].length)
          plan[:targets].each_with_index { |(role,id,_),i| need(envelope.getbyte(ending+1+146*i)==role && envelope.byteslice(ending+2+146*i,32)==id) }
          stored=envelope
        end
        checkpoint.call(recheck(r,plan,current,floor));return stored if stored
        need(count<256);envelope=compose(r,plan);checkpoint.call(recheck(r,plan,current,floor));record=identity+plan[:intent]+[envelope.bytesize].pack('N')+envelope
        file.write(record);file.write(sha(record));file.flush;file.fsync;checkpoint.call(recheck(r,plan,current,floor));envelope
      ensure
        file.close
      end
    ensure
      plan&.fetch(:text)&.replace("\x00".b*plan[:text].bytesize)
    end
    private_class_method :need,:label,:sha,:number,:capture,:authorize,:recheck,:encrypt,:wrap,:compose,:read
  end
end
