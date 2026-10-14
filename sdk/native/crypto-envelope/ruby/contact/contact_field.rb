# frozen_string_literal: true
require_relative '../manifest_chain'
require_relative 'contact_origin'
module ZrotextCandidate
  # Owned historical integrity only; no installed contact access or current grant.
  module ContactField
    @admission=Mutex.new
    @outstanding=0
    class Cancellation
      def initialize = (@lock=Mutex.new;@cancelled=false)
      def cancel = @lock.synchronize{@cancelled=true}
      def cancelled? = @lock.synchronize{@cancelled}
    end
    module_function
    def need(value) = (raise ArgumentError,'Contact historical integrity refused' unless value)
    def fixed(value,size)
      need(value.instance_of?(String) && value.bytesize==size && value.bytes.any?{|b|b!=0});value.b.dup
    end
    def number(bytes,at)
      value=bytes.byteslice(at,8).unpack1('Q>');need(value.between?(1,2**63-1));value
    end
    def sha(bytes) = OpenSSL::Digest::SHA256.digest(bytes)
    def domain(value) = value.b+"\x00".b
    class Statement
      def initialize(values)
        @values=values.transform_values{|v|v.instance_of?(String) ? v.dup.freeze : v}.freeze;freeze
      end
      private_class_method :new
      def bytes = @values.fetch(:bytes).dup
      def digest = @values.fetch(:digest).dup
      def identity = @values.transform_values{|v|v.instance_of?(String) ? v.dup : v}.freeze
    end
    def verify_statement(input,accepted,account:,origin:,root_fingerprint:,parser:)
      need(input.instance_of?(String) && input.bytesize.between?(314,817) && accepted.instance_of?(ManifestChain::Verified) && accepted.profile==2 && accepted.generation==1)
      b=input.b.dup;account=fixed(account,16);root_fingerprint=fixed(root_fingerprint,32)
      need(parser.instance_of?(ContactOrigin) && parser.accepts?(origin) && b.byteslice(0,6)=="ZTKA\x01\x03".b)
      n=b.byteslice(38,2).unpack1('n');need(n.between?(9,512) && b.bytesize==305+n)
      actual_origin=b.byteslice(40,n);need(parser.accepts?(actual_origin) && actual_origin==origin)
      at=40+n;need(number(b,at)==1);version=number(b,at+8);generation=number(b,at+16);at+=24
      fp=fixed(b.byteslice(at,32),32);md=fixed(b.byteslice(at+32,32),32);reader=fixed(b.byteslice(at+64,32),32);point=fixed(b.byteslice(at+96,65),65);at+=161
      issued=number(b,at);finish=number(b,at+8);need(finish>issued && finish-issued<=86400000)
      fixed(b.byteslice(6,16),16);fixed(b.byteslice(22,16),16);HpkeRecipient.point(point)
      need(reader==sha(domain('ZTSE/key/v1')+"\x00\x10".b+point) && b.byteslice(22,16)==account && accepted.account==account && version==accepted.version && md==accepted.digest && issued>=accepted.issued_ms && finish<=accepted.expires_ms)
      keys=accepted.key_records.select{|k|k.getbyte(148)==1 && k.byteslice(132,8).unpack1('Q>')<=issued && issued<k.byteslice(140,8).unpack1('Q>')}
      selected=keys.find{|k|k.getbyte(0)==2 && k.byteslice(1,32)==reader};root_record=keys.find{|k|k.getbyte(0)==6}
      need(selected && root_record && selected.byteslice(130,2).unpack1('n')==12 && root_record.byteslice(130,2).unpack1('n')==0 && selected.byteslice(33,65)==point && finish<=selected.byteslice(140,8).unpack1('Q>') && finish<=root_record.byteslice(140,8).unpack1('Q>'))
      root=root_record.byteslice(33,65);pin="ZTRP\x02".b+account+[1].pack('Q>')+root
      need(fp==root_fingerprint && fp==sha(domain('ZTSE/root-pin/v2')+pin))
      ManifestChain.signature(root,b.byteslice(-64,64),'ZT/contact-reader/authorization/v1',b.byteslice(0,b.bytesize-64))
      Statement.send(:new,{bytes:b,digest:sha(b),account:account,origin:origin,root_fingerprint:fp,manifest:md,reader:reader,point:point,root:root,writer:root_record.byteslice(1,32),version:version,reader_generation:generation})
    end
    class Verified
      def initialize(bytes)
        @bytes=bytes.dup.freeze;@digest=ContactField.sha(bytes).freeze;freeze
      end
      private_class_method :new
      def bytes = @bytes.dup
      def digest = @digest.dup
    end
    class Expected
      attr_reader :origin
      def initialize(account:,origin:,root_fingerprint:,contact:,routing:,parser:)
        @account=ContactField.fixed(account,16).freeze;@fingerprint=ContactField.fixed(root_fingerprint,32).freeze;@contact=ContactField.fixed(contact,16).freeze;@routing=ContactField.fixed(routing,32).freeze
        ContactField.need(parser.instance_of?(ContactOrigin) && parser.accepts?(origin));@origin=origin.dup.freeze;freeze
      end
      def account = @account.dup
      def fingerprint = @fingerprint.dup
      def contact = @contact.dup
      def routing = @routing.dup
    end
    def bound(unsigned,statement,expected)
      need(statement.instance_of?(Statement) && expected.instance_of?(Expected));s=statement.identity
      need(s[:account]==expected.account && s[:root_fingerprint]==expected.fingerprint && s[:origin]==expected.origin)
      need(unsigned.byteslice(6,16)==s[:account] && unsigned.byteslice(22,16)==expected.contact && unsigned.byteslice(166,32)==expected.routing && number(unsigned,54)==s[:version] && number(unsigned,62)==s[:reader_generation] && unsigned.byteslice(70,32)==s[:reader] && unsigned.byteslice(102,32)==s[:manifest] && unsigned.byteslice(134,32)==s[:digest] && unsigned.byteslice(214,32)==s[:writer])
    end
    def produce_software(key,statement,expected,input,cancelled: Cancellation.new)
      need(key.instance_of?(OpenSSL::PKey::EC))
      produce(statement,expected,input,cancelled) do |captured,live|
        need(key.private? && key.group.curve_name=='prime256v1')
        need(key.check_key && key.public_key.to_octet_string(:uncompressed)==statement.identity[:root])
        transcript=domain('ZT/contact-field/commitment/v1')+[captured.bytesize].pack('N')+captured
        begin
          live.call;signature=OpenSSL::ASN1.decode(key.sign('SHA256',transcript));r,s=signature.value.map{|v|v.value.to_i}
          need(r>0 && r<ManifestChain::ORDER && s>0 && s<ManifestChain::ORDER)
          [r.to_s(16).rjust(64,'0')+[s,ManifestChain::ORDER-s].min.to_s(16).rjust(64,'0')].pack('H*')
        ensure
          transcript.replace("\x00".b*transcript.bytesize)
        end
      end
    end
    def produce_protected(key,statement,expected,input,cancelled: Cancellation.new)
      need(key.instance_of?(ProtectedContactSigner) && statement.instance_of?(Statement))
      produce(statement,expected,input,cancelled){|captured,live|need(key.public_point==statement.identity[:root]);live.call;key.send(:sign_field,captured,live)}
    end
    def produce(statement,expected,input,cancelled,prepared:false,check:nil,finish:nil,&signer)
      captured=prepared ? input.b.dup : unsigned(input);transferred=false
      begin
        check ? check.call(captured) : bound(captured,statement,expected);need(cancelled.instance_of?(Cancellation))
        stopped=Cancellation.instance_method(:cancelled?).bind(cancelled)
        need(!stopped.call)
        admitted=@admission.synchronize do
          if @outstanding<4 then @outstanding+=1;true else false end
        end
        need(admitted);deadline=Process.clock_gettime(Process::CLOCK_MONOTONIC)+10;queue=Queue.new
        live=->{need(!stopped.call && Process.clock_gettime(Process::CLOCK_MONOTONIC)<deadline)}
        begin
          Thread.new do
            signature=signed=nil
            begin
              live.call;signature=signer.call(captured,live);live.call;signed=captured+signature
              result=finish ? finish.call(signed) : verify(signed,statement,contact:expected.contact,routing:expected.routing);live.call;queue<<[true,result]
            rescue StandardError
              queue<<[false,nil]
            ensure
              [captured,signature,signed].compact.each{|b|b.replace("\x00".b*b.bytesize)}
              @admission.synchronize{@outstanding-=1}
            end
          end
          transferred=true
        rescue Exception
          @admission.synchronize{@outstanding-=1};raise
        end
        loop do
          live.call
          begin
            success,result=queue.pop(true);need(success);live.call;return result
          rescue ThreadError
            sleep(0.01)
          end
        end
      ensure
        captured.replace("\x00".b*captured.bytesize) unless transferred
      end
    end
    private_class_method :produce,:bound
    def unsigned(input)
      need(input.instance_of?(String) && input.bytesize.between?(332,2379));b=input.b.dup
      need(b.byteslice(0,5)=="ZTCO\x01".b && [1,2].include?(b.getbyte(5)))
      [6,22,198].each{|at|fixed(b.byteslice(at,16),16)};[70,102,134,166,214].each{|at|fixed(b.byteslice(at,32),32)}
      [38,46,54,62].each{|at|number(b,at)};need(number(b,46)==1);HpkeRecipient.point(b.byteslice(246,65))
      n=b.byteslice(311,4).unpack1('N');need(n.between?(17,b.getbyte(5)==1 ? 272 : 2064) && b.bytesize==315+n);b
    end
    def verify(input,statement,contact:,routing:)
      need(input.instance_of?(String) && input.bytesize.between?(396,2443) && statement.instance_of?(Statement))
      b=input.b.dup;u=unsigned(b.byteslice(0,b.bytesize-64));contact=fixed(contact,16);routing=fixed(routing,32);s=statement.identity
      need(u.byteslice(6,16)==s[:account] && u.byteslice(22,16)==contact && u.byteslice(166,32)==routing && number(u,54)==s[:version] && number(u,62)==s[:reader_generation] && u.byteslice(70,32)==s[:reader] && u.byteslice(102,32)==s[:manifest] && u.byteslice(134,32)==s[:digest] && u.byteslice(214,32)==s[:writer])
      ManifestChain.signature(s[:root],b.byteslice(-64,64),'ZT/contact-field/commitment/v1',u);Verified.send(:new,b)
    end
  end
end
