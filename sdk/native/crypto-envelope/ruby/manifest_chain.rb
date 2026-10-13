# frozen_string_literal: true
require_relative 'hpke_recipient'

module ZrotextCandidate
  # Historical provenance, not live authority or durable selection.
  module ManifestChain
    ORDER='ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'.to_i(16)
    module_function
    def need(value) = (raise ArgumentError,'Candidate manifest refused' unless value)
    def domain(value) = value.b+"\x00".b
    def sha(value) = OpenSSL::Digest::SHA256.digest(value)
    def zero(value) = value.bytes.all?(&:zero?)
    def number(value,at)
      result=value.byteslice(at,8).unpack1('Q>');need(result<2**63);result
    end
    def window(issued,expires,now)
      need(now.is_a?(Integer) && now.between?(1,2**63-1) && issued>0 && expires>issued && expires-issued<=86400000 && now<expires)
      need(issued<=now || issued-now<=300000)
    end
    def signature(point,raw,label,unsigned)
      r=raw.byteslice(0,32).unpack1('H*').to_i(16);s=raw.byteslice(32,32).unpack1('H*').to_i(16)
      need(r>0 && r<ORDER && s>0 && s<=ORDER/2)
      der=OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(r),OpenSSL::ASN1::Integer.new(s)]).to_der
      need(HpkeRecipient.point(point).verify('SHA256',der,domain(label)+[unsigned.bytesize].pack('N')+unsigned))
    end
    class RootPin
      def initialize(account,point)
        @account=account.freeze;@point=point.freeze;freeze
      end
      private_class_method :new
      def account = @account.dup
      def point = @point.dup
      # Compared fingerprint must arrive through an independently authenticated owner channel.
      def self.enroll(input,compared_fingerprint)
        ManifestChain.need(input.bytesize==94 && compared_fingerprint.bytesize==32)
        bytes=input.b.dup;compared=compared_fingerprint.b.dup
        ManifestChain.need(bytes.byteslice(0,5)=="ZTRP\x02".b && !ManifestChain.zero(bytes.byteslice(5,16)) && ManifestChain.number(bytes,21)==1)
        HpkeRecipient.point(bytes.byteslice(29,65))
        ManifestChain.need(ManifestChain.sha(ManifestChain.domain('ZTSE/root-pin/v2')+bytes)==compared)
        new(bytes.byteslice(5,16),bytes.byteslice(29,65))
      end
    end
    class Verified
      attr_reader :profile,:predecessor,:version,:issued_ms,:expires_ms,:comparison_ms
      def initialize(bytes,profile,predecessor,version,issued,expires,comparison,digest,account,root,previous)
        @bytes=bytes.freeze;@profile=profile;@predecessor=predecessor;@version=version;@issued_ms=issued;@expires_ms=expires;@comparison_ms=comparison
        @digest=digest.freeze;@account=account.freeze;@root=root.freeze;@previous=previous.freeze;freeze
      end
      private_class_method :new
      def bytes = @bytes.dup
      def digest = @digest.dup
      def account = @account.dup
      def root_point = @root.dup
      def previous = @previous.dup
      def key_records
        at=@profile==2 ? 151 : 153
        Array.new(@bytes.getbyte(at-1)){|i|@bytes.byteslice(at+149*i,149)}
      end
    end
    def parse(input,profile,now)
      need([2,3].include?(profile));offset=profile==2 ? 0 : 2
      need(input.bytesize.between?(364+offset,9751+offset));bytes=input.b.dup
      need(bytes.byteslice(0,5)=='ZTMA'.b+[profile].pack('C'));predecessor=profile==2 ? 2 : bytes.getbyte(6)
      need(profile==2 || bytes.getbyte(5)==3 && [2,3].include?(predecessor))
      count=bytes.getbyte(150+offset);need(count.between?(1,64) && bytes.bytesize==215+offset+149*count)
      account=bytes.byteslice(5+offset,16);root=bytes.byteslice(85+offset,65);previous=bytes.byteslice(53+offset,32)
      generation=number(bytes,21+offset);version=number(bytes,29+offset);issued=number(bytes,37+offset);expires=number(bytes,45+offset)
      need(!zero(account) && generation==1 && version>0);window(issued,expires,now);HpkeRecipient.point(root)
      last=nil;points={};owners=0;archives=0
      count.times do |i|
        at=151+offset+149*i;role=bytes.getbyte(at);state=bytes.getbyte(at+148);scope=bytes.byteslice(at+130,2).unpack1('n')
        id=bytes.byteslice(at+1,32);point=bytes.byteslice(at+33,65);device=bytes.byteslice(at+98,16);line=bytes.byteslice(at+114,16);ordering=bytes.byteslice(at,33)
        from=number(bytes,at+132);until_ms=number(bytes,at+140);need(role.between?(1,6));expected=[0,4,12,4,2,1,0]
        need(role==3 ? [4,8,12].include?(scope) : scope==expected[role])
        device_bound=[1,4].include?(role);line_bound=device_bound || role==5
        need(device_bound ? !zero(device) : zero(device));need(line_bound ? !zero(line) : zero(line))
        need(from<=until_ms && [1,2].include?(state));need(last.nil? || last<ordering);last=ordering
        HpkeRecipient.point(point);need(id==sha(domain('ZTSE/key/v1')+(role<=3 ? "\x00\x10".b : "\x01\x01".b)+point))
        need(!points[point]);points[point]=true
        if role==6
          owners+=1;need(point==root && state==1 && from<=issued && until_ms>=expires)
        end
        archives+=1 if role==2 && state==1
      end
      need(owners==1 && archives==1);unsigned=bytes.byteslice(0,bytes.bytesize-64)
      signature(root,bytes.byteslice(-64,64),"ZTSE/manifest/v#{profile}",unsigned)
      Verified.send(:new,bytes,profile,predecessor,version,issued,expires,now,sha(unsigned),account,root,previous)
    end
    private_class_method :parse
    def genesis02(input,pin,now)
      need(pin.instance_of?(RootPin));value=parse(input,2,now)
      need(value.account==pin.account && value.root_point==pin.point && value.version==1 && zero(value.previous));value
    end
    def continue_chain(input,prior,expected_profile,now)
      need(prior.instance_of?(Verified) && now.is_a?(Integer) && now>=prior.comparison_ms && !(prior.profile==3 && expected_profile==2))
      window(prior.issued_ms,prior.expires_ms,now) if prior.profile==2 && expected_profile==3
      value=parse(input,expected_profile,now);need(value.account==prior.account && value.root_point==prior.root_point)
      return value if value.profile==prior.profile && value.version==prior.version && value.digest==prior.digest
      need(prior.version<2**63-1 && value.version==prior.version+1 && value.previous==prior.digest)
      need(value.profile==2 || value.predecessor==prior.profile);value
    end
  end
end
