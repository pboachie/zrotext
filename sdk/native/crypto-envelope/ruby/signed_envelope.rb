# frozen_string_literal: true
require_relative 'hpke_recipient'

module ZrotextCandidate
  # Signature-verified component only: manifest and current authority remain independent.
  class SignedEnvelope
    ORDER = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'.to_i(16)
    attr_reader :profile, :kind
    def self.require_valid(condition)
      raise ArgumentError, 'Invalid candidate envelope' unless condition
    end
    def self.domain(label) = label.b + "\x00".b
    def self.u64(bytes, at)
      value = bytes.byteslice(at,8).unpack1('Q>')
      require_valid(value < 2**63)
      value
    end
    def self.verify(input, expected_profile, trusted_signer)
      require_valid([2,3].include?(expected_profile) && input.bytesize.between?(426,36864))
      bytes=input.b.dup; signer=trusted_signer.b.dup
      require_valid(bytes.byteslice(0,4)=='ZTSE' && bytes.getbyte(4)==expected_profile && bytes.byteslice(6,2)=="\x00\x00".b)
      kind=bytes.getbyte(5)
      require_valid([1,2].include?(kind) && (expected_profile!=3 || kind==1))
      raise ArgumentError,'Profile03 message identity' if expected_profile==3 && bytes.byteslice(26,16)=="\x00".b*16
      require_valid(bytes.bytesize<=(kind==1 ? 34213 : 34082))
      size=bytes.byteslice(8,2).unpack1('n')
      require_valid(size.between?(kind==1 ? 157 : 172,kind==1 ? 170 : 185))
      prefix_end=10+size;peer_at=10+(kind==1 ? 153 : 168);peer_length=bytes.getbyte(peer_at)
      require_valid(peer_length.between?(3,16) && size==(kind==1 ? 154 : 169)+peer_length)
      require_valid(/\A\+[1-9][0-9]{1,14}\z/n.match?(bytes.byteslice(peer_at+1,peer_length)))
      u64(bytes,74);observed=u64(bytes,146)
      if kind==1
        expires=u64(bytes,154)
        require_valid(bytes.getbyte(162)==1 && expires>observed && expires-observed<=900000)
      else
        require_valid(bytes.byteslice(26,16)==bytes.byteslice(154,16) && u64(bytes,170)>0)
      end
      length=bytes.byteslice(prefix_end+12,4).unpack1('N');require_valid(length.between?(17,32784))
      body_end=prefix_end+16+length;require_valid(body_end<bytes.bytesize)
      count=bytes.getbyte(body_end);require_valid(count.between?(kind==1 ? 2 : 1,kind==1 ? 8 : 7))
      unsigned_end=body_end+1+146*count;require_valid(unsigned_end+64==bytes.bytesize)
      devices=0;archives=0;previous=nil
      count.times do |i|
        at=body_end+1+146*i;role=bytes.getbyte(at);require_valid(role.between?(1,3))
        ordering=bytes.byteslice(at,33);require_valid(previous.nil? || previous<ordering);previous=ordering
        HpkeRecipient.point(bytes.byteslice(at+33,65))
        devices+=1 if role==1;archives+=1 if role==2
      end
      require_valid(devices==(kind==1 ? 1 : 0) && archives==1)
      raw=bytes.byteslice(unsigned_end,64)
      r=raw.byteslice(0,32).unpack1('H*').to_i(16);s=raw.byteslice(32,32).unpack1('H*').to_i(16)
      require_valid(r>0 && r<ORDER && s>0 && s<=ORDER/2)
      public_key=HpkeRecipient.point(signer)
      identity=OpenSSL::Digest::SHA256.digest(domain('ZTSE/key/v1')+"\x01\x01".b+signer)
      require_valid(identity==bytes.byteslice(114,32))
      signature=OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(r),OpenSSL::ASN1::Integer.new(s)]).to_der
      transcript=domain("ZTSE/sign/v#{expected_profile}")+[unsigned_end].pack('N')+bytes.byteslice(0,unsigned_end)
      require_valid(public_key.verify('SHA256',signature,transcript))
      new(bytes.freeze,expected_profile,kind,prefix_end,body_end,count).freeze
    end
    def initialize(bytes,profile,kind,prefix_end,body_end,count)
      @bytes=bytes;@profile=profile;@kind=kind;@prefix_end=prefix_end;@body_end=body_end;@count=count
    end
    private_class_method :new
    def bytes = @bytes.dup
    def protected_bytes = @bytes.byteslice(10,@prefix_end-10)
    def nonce = @bytes.byteslice(@prefix_end,12)
    def body_ciphertext = @bytes.byteslice(@prefix_end+16,@body_end-@prefix_end-16)
    def body_aad = self.class.domain("ZTSE/body/v#{@profile}")+@bytes.byteslice(0,@prefix_end)
    def wrap(role,identity)
      self.class.require_valid(identity.bytesize==32)
      @count.times do |i|
        at=@body_end+1+146*i
        return at if @bytes.getbyte(at)==role && @bytes.byteslice(at+1,32)==identity
      end
      raise ArgumentError,'Recipient wrap missing'
    end
    private :wrap
    def suffix(role,identity)
      at=wrap(role,identity);@bytes.byteslice(0,@prefix_end)+@bytes.byteslice(at,33)
    end
    private :suffix
    def wrap_info(role,identity) = self.class.domain("ZTSE/wrap/v#{@profile}")+suffix(role,identity)
    def wrap_aad(role,identity)
      value=suffix(role,identity);@profile==2 ? ''.b : self.class.domain('ZTSE/wrap-aad/v3')+value
    end
    def encapsulated(role,identity) = @bytes.byteslice(wrap(role,identity)+33,65)
    def wrapped_key(role,identity) = @bytes.byteslice(wrap(role,identity)+98,48)
  end
end
