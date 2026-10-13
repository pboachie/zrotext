# frozen_string_literal: true
require 'base64'
require_relative 'compose02'
include ZrotextCandidate
$checks=0
def check(value) = (raise 'Composition02 assertion' unless value; $checks+=1)
def refuses
  yield
rescue ArgumentError,OpenSSL::OpenSSLError,EncodingError
  $checks+=1
else
  raise 'Invalid composition02 accepted'
end
def emit(value) = puts('ENVELOPE '+Base64.strict_encode64(value))
if ARGV==['--probe']
  begin;ProtectedSigner.probe;rescue ArgumentError,Fiddle::DLError;exit 77;end
  exit
end
raise ArgumentError,'Pending receipt required' unless ARGV.length==1
receipt=ARGV[0];owner=nil;deleted=false
begin
  owner=ProtectedSigner.create { |name| File.open(receipt,File::WRONLY|File::CREAT|File::EXCL,0o600) { |f| f.write(name+"\n");f.flush;f.fsync } }
  point=owner.public_point;puts point.unpack1('H*');STDOUT.flush
  f=STDIN.read.lines.to_h { |line| name,hex=line.strip.split("\t");[name,[hex].pack('H*')] }
  manifest=ManifestChain.genesis02(f.fetch('manifest'),ManifestChain::RootPin.enroll(f.fetch('rootPin'),f.fetch('fingerprint')),10000)
  r={manifest:manifest,now_ms:10000,message:'1'.b*16,device:f.fetch('device'),line:f.fetch('line'),observed_ms:10000,expires_ms:20000,peer:'+12',content:'Native composed02 🌱',signer:owner,recipients:manifest.key_records.select { |k| [1,2].include?(k.getbyte(0)) }.map { |k| [k.getbyte(0),k.byteslice(1,32)] }}
  first=Compose02.fresh(**r);second=Compose02.fresh(**r);check(first!=second);emit(first);emit(second)
  emit(Compose02.fresh(**r.merge(message:"\0".b*16,observed_ms:0,expires_ms:1)))
  [{message:''},{device:''},{line:"\0".b*16},{device:"\0".b*16},{now_ms:100000},{now_ms:9999},{observed_ms:-1},{expires_ms:10000},{expires_ms:910001},{peer:'+01'},{content:''},{content:"\ufeffbad"},{content:"bad\0"},{content:"\xed\xa0\x80".b.force_encoding('UTF-8')},{content:'x'*32769},{recipients:r[:recipients].take(1)},{recipients:[r[:recipients][0]]*2},{recipients:[[1,"\0".b*32],r[:recipients][1]]}].each { |change| refuses { Compose02.fresh(**r.merge(change)) } }
  refuses { owner.sign_envelope03(first.byteslice(0,first.bytesize-64)) };refuses { owner.sign_envelope02("\0".b*493) }
  owner.delete_created;deleted=true;refuses { Compose02.fresh(**r) };File.delete(receipt)
  puts "QUALIFIED: #{$checks} native Ruby profile02 composition checks passed; owned key deleted"
ensure
  if owner
    begin;unless deleted;owner.delete_created;File.delete(receipt);end;ensure;owner.close;end
  end
end

