# frozen_string_literal: true
require_relative 'contact_field'
module ZrotextCandidate
  # Historical signed transitions; no persistence or current permission.
  module ContactMutation
    module_function
    def need(v) = ContactField.need(v)
    def n(b,at) = b.byteslice(at,8).unpack1('Q>')
    def zero(b) = b.bytes.all?(&:zero?)
    def expected(st,e)
      need(st.instance_of?(ContactField::Statement) && e.instance_of?(ContactField::Expected));s=st.identity
      need(s[:account]==e.account && s[:origin]==e.origin && s[:root_fingerprint]==e.fingerprint);s
    end
    def unsigned(input)
      need(input.instance_of?(String) && input.bytesize==304);b=input.b.dup
      need(b.byteslice(0,5)=="ZTCM\x01".b)
      [6,22,54].each{|at|ContactField.fixed(b.byteslice(at,16),16)}
      [118,150,182].each{|at|ContactField.fixed(b.byteslice(at,32),32)}
      [38,46,102,110,214].each{|at|need(n(b,at)<=2**63-1)}
      need(n(b,46)>0 && n(b,102)==1 && n(b,110)>0)
      case b.getbyte(5)
      when 1,3
        need(n(b,38)==0 && n(b,46)==1 && zero(b.byteslice(70,32)))
        need(b.getbyte(5)==1 ? n(b,214)==0 : n(b,214)>0)
      when 2
        need(n(b,38).between?(1,2**63-2) && n(b,46)==n(b,38)+1 && !zero(b.byteslice(70,32)) && n(b,214)==0)
      else need(false)
      end
      [222,263].each do |at|
        tag=b.getbyte(at);revision=n(b,at+1);digest=b.byteslice(at+9,32)
        need(revision<=n(b,46));need(tag==0 ? revision==0 && zero(digest) : tag==1 && revision>0 && !zero(digest))
      end
      b
    end
    def bound(b,st,e,legacy)
      s=expected(st,e);need(legacy.instance_of?(Integer) && legacy.between?(0,2**63-1) && n(b,214)==legacy)
      need(b.byteslice(6,16)==e.account && b.byteslice(22,16)==e.contact && b.byteslice(182,32)==e.routing && n(b,110)==s[:version] && b.byteslice(118,32)==s[:manifest] && b.byteslice(150,32)==s[:digest]);s
    end
    class Verified
      def initialize(bytes,statement)
        @bytes=bytes.dup.freeze;@digest=ContactField.sha(bytes).freeze;@statement=statement;freeze
      end
      private_class_method :new
      attr_reader :statement
      def bytes = @bytes.dup
      def digest = @digest.dup
    end
    class Transition
      def initialize(mutation,fields)
        @mutation=mutation;@fields=fields.dup.freeze;freeze
      end
      private_class_method :new
      attr_reader :mutation
      def field(kind)
        ContactField.need([1,2].include?(kind));@fields[kind-1]
      end
    end
    def verify(input,statement,expected,legacy:0)
      need(input.instance_of?(String) && input.bytesize==368);b=input.b.dup;u=unsigned(b.byteslice(0,304));s=bound(u,statement,expected,legacy)
      ManifestChain.signature(s[:root],b.byteslice(304,64),'ZT/contact-field/mutation/v1',u)
      Verified.send(:new,b,statement)
    end
    def fields(previous,b,statement,replacements)
      need(previous.nil? || previous.instance_of?(Transition));need(replacements.instance_of?(Array) && replacements.size<=2)
      supplied={};replacements.each do |f|
        need(f.instance_of?(ContactField::Verified));kind=f.bytes.getbyte(5);need([1,2].include?(kind) && !supplied.key?(kind));supplied[kind]=f
      end
      s=statement.identity
      if previous
        p=previous.mutation.bytes;ps=previous.mutation.statement.identity
        need(b.getbyte(5)==2 && n(b,38)==n(p,46) && b.byteslice(70,32)==previous.mutation.digest && b.byteslice(6,32)==p.byteslice(6,32) && b.byteslice(182,32)==p.byteslice(182,32))
        need(s[:origin]==ps[:origin] && s[:root_fingerprint]==ps[:root_fingerprint] && s[:version]>=ps[:version] && (s[:version]!=ps[:version] || s[:manifest]==ps[:manifest]))
        need(s[:reader_generation]>=ps[:reader_generation] && (s[:reader_generation]!=ps[:reader_generation] || s[:reader]==ps[:reader] && s[:point]==ps[:point]))
      else
        need(b.getbyte(5)!=2)
      end
      used=0;out=[nil,nil]
      [222,263].each_with_index do |at,i|
        next if b.getbyte(at)==0
        if n(b,at+1)==n(b,46)
          f=supplied[i+1];need(f);v=f.bytes
          need(f.digest==b.byteslice(at+9,32) && n(v,38)==n(b,46) && v.byteslice(198,16)==b.byteslice(54,16) && v.byteslice(6,32)==b.byteslice(6,32) && n(v,46)==1)
          need(n(v,54)==s[:version] && n(v,62)==s[:reader_generation] && v.byteslice(70,32)==s[:reader] && v.byteslice(102,32)==s[:manifest] && v.byteslice(134,32)==s[:digest] && v.byteslice(166,32)==b.byteslice(182,32) && v.byteslice(214,32)==s[:writer])
          out[i]=f;used+=1
        else
          need(previous && b.byteslice(at,41)==previous.mutation.bytes.byteslice(at,41) && previous.field(i+1));out[i]=previous.field(i+1)
        end
      end
      need(used==replacements.size);out
    end
    def transition(previous,mutation,replacements)
      need(mutation.instance_of?(Verified));Transition.send(:new,mutation,fields(previous,mutation.bytes,mutation.statement,replacements))
    end
    def produce(key,protected_key,statement,e,input,legacy,previous,previous_statement,replacements,cancelled)
      captured=unsigned(input);owned=replacements.dup.freeze
      check=->(u) do
        bound(u,statement,e,legacy)
        if previous
          need(previous.instance_of?(Transition));expected(previous_statement,e);need(previous.mutation.statement.bytes==previous_statement.bytes)
        else need(previous_statement.nil?) end
        fields(previous,u,statement,owned)
      end
      finish=->(signed){transition(previous,verify(signed,statement,e,legacy:legacy),owned)}
      ContactField.send(:produce,statement,e,captured,cancelled,prepared:true,check:check,finish:finish) do |u,live|
        if protected_key
          need(key.public_point==statement.identity[:root]);live.call;key.send(:sign_mutation,u,live)
        else
          need(key.private? && key.group.curve_name=='prime256v1' && key.check_key && key.public_key.to_octet_string(:uncompressed)==statement.identity[:root])
          transcript=ContactField.domain('ZT/contact-field/mutation/v1')+[u.bytesize].pack('N')+u
          begin
            live.call;signature=OpenSSL::ASN1.decode(key.sign('SHA256',transcript));r,s=signature.value.map{|v|v.value.to_i};need(r>0 && r<ManifestChain::ORDER && s>0 && s<ManifestChain::ORDER)
            [r.to_s(16).rjust(64,'0')+[s,ManifestChain::ORDER-s].min.to_s(16).rjust(64,'0')].pack('H*')
          ensure transcript.replace("\x00".b*transcript.bytesize) end
        end
      end
    ensure
      captured&.replace("\x00".b*captured.bytesize)
    end
    def produce_software(key,statement,expected,input,legacy:0,previous:nil,previous_statement:nil,replacements:[],cancelled:ContactField::Cancellation.new)
      need(key.instance_of?(OpenSSL::PKey::EC));produce(key,false,statement,expected,input,legacy,previous,previous_statement,replacements,cancelled)
    end
    def produce_protected(key,statement,expected,input,legacy:0,previous:nil,previous_statement:nil,replacements:[],cancelled:ContactField::Cancellation.new)
      need(key.instance_of?(ProtectedContactSigner));produce(key,true,statement,expected,input,legacy,previous,previous_statement,replacements,cancelled)
    end
    private_class_method :expected,:bound,:fields,:produce
  end
end
