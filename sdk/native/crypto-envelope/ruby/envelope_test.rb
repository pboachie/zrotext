# frozen_string_literal: true
require_relative 'signed_envelope'
checks=0;rows=0
reject=lambda do |&attempt|
  begin
    attempt.call
  rescue ArgumentError,OpenSSL::OpenSSLError
    checks+=1
    next
  end
  raise 'Invalid envelope accepted'
end
$stdin.each_line do |line|
  f=line.chomp.split("\t",-1);raise 'Fixture fields' unless f.length==9
  profile=f[1].to_i;role=f[5].to_i
  bytes,signer,body_aad=[f[2],f[3],f[4]].map{|value|[value].pack('H*')};id=[f[6]].pack('H*')
  signed=ZrotextCandidate::SignedEnvelope.verify(bytes,profile,signer)
  raise 'Transcript mismatch' unless signed.body_aad==body_aad && signed.wrap_info(role,id)==[f[7]].pack('H*') && signed.wrap_aad(role,id)==[f[8]].pack('H*')
  checks+=3;rows+=1
  if profile==3
    zero_message=bytes.dup;zero_message[26,16]="\x00".b*16
    begin
      ZrotextCandidate::SignedEnvelope.verify(zero_message,profile,signer)
      raise 'Zero message accepted'
    rescue ArgumentError=>error
      raise unless error.message=='Profile03 message identity'
      checks+=1
    end
  end
  copied=signed.bytes;copied.replace('');raise 'Mutable snapshot' unless signed.bytes==bytes;checks+=1
  [0,4,5,6,7,8,9,10,74,114,146,154,162,bytes.bytesize-65,bytes.bytesize-1].each do |at|
    changed=bytes.dup;changed.setbyte(at,changed.getbyte(at)^1)
    reject.call{ZrotextCandidate::SignedEnvelope.verify(changed,profile,signer)}
  end
  reject.call{ZrotextCandidate::SignedEnvelope.verify(bytes,profile==2 ? 3 : 2,signer)}
  reject.call{ZrotextCandidate::SignedEnvelope.verify(bytes.byteslice(0,bytes.bytesize-1),profile,signer)}
  reject.call{ZrotextCandidate::SignedEnvelope.verify(bytes+"\x00".b,profile,signer)}
  reject.call{signed.wrap_info(role,"\x00".b*32)}
  high=bytes.dup;scalar=ZrotextCandidate::SignedEnvelope::ORDER-bytes.byteslice(-32,32).unpack1('H*').to_i(16)
  high[-32,32]=[scalar.to_s(16).rjust(64,'0')].pack('H*');reject.call{ZrotextCandidate::SignedEnvelope.verify(high,profile,signer)}
  bytes.replace('');raise 'Caller mutation changed verified bytes' unless signed.body_aad==body_aad;checks+=1
end
raise 'Missing fixture coverage' if rows<3
puts "Ruby envelope: #{checks} checks on #{rows} rows passed"
