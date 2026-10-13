# frozen_string_literal: true
require_relative 'protected_recipient'
require_relative '../manifest_chain'

module ZrotextCandidate
  # Locally qualified native signing; not election or transport authority.
  class ProtectedSigner < ProtectedRecipient
    def self.alias_prefix = 'zrotext-managed-ruby-sign-p256-'
    def call(*) = raise(ArgumentError,'Signing custody cannot unwrap recipient secrets')
    def sign_envelope03(unsigned) = sign_profile(unsigned,3)
    def sign_envelope02(unsigned) = sign_profile(unsigned,2)
    private
    def sign_profile(unsigned,profile)
      @lock.synchronize do
        need(@qualified && !@closed && unsigned.bytesize.between?(493,34149))
        captured=unsigned.b.dup
        need(captured.byteslice(0,8)=="ZTSE".b+[profile,1,0,0].pack('C4'))
        signature=sign_digest(OpenSSL::Digest::SHA256.digest("ZTSE/sign/v#{profile}\x00".b+[captured.bytesize].pack('N')+captured))
        ManifestChain.signature(public_raw,signature,"ZTSE/sign/v#{profile}",captured)
        signature
      end
    end
    private
    def algorithm = 'ECDSA_P256'
    def public_magic = 0x31534345
    def qualify
      point=qualify_policy
      challenge=SecureRandom.random_bytes(32)
      signature=sign_digest(challenge)
      r=signature.byteslice(0,32).unpack1('H*').to_i(16)
      s=signature.byteslice(32,32).unpack1('H*').to_i(16)
      der=OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(r),OpenSSL::ASN1::Integer.new(s)]).to_der
      need(HpkeRecipient.point(point).verify_raw(nil,der,challenge))
      @qualified=true
    end
    def sign_digest(digest)
      need(!@closed && digest.bytesize==32)
      output="\x00".b*64; size=size_buffer
      check(native('NCryptSignHash',@key,0,digest,32,output,64,size,SILENT))
      need(size.unpack1('L<')==64)
      r=output.byteslice(0,32).unpack1('H*').to_i(16)
      s=output.byteslice(32,32).unpack1('H*').to_i(16)
      order=ManifestChain::ORDER
      need(r>0 && r<order && s>0 && s<order)
      [r.to_s(16).rjust(64,'0')+[s,order-s].min.to_s(16).rjust(64,'0')].pack('H*')
    end
  end
end
