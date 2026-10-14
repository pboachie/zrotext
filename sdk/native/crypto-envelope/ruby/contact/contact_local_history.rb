# frozen_string_literal: true
require_relative '../manifest_chain'
require_relative 'contact_field'
require_relative 'contact_mutation'
require 'digest/sha2'
require 'stringio'
module ZrotextCandidate
  # Application-owned contact local history with independently reverified signed root history.
  class ContactLocalHistory
    CAPACITY=256
    HISTORY_LIMIT=64
    MAX_BYTES=16_000_000
    ORIGIN_MAX=512
    LIFETIME_SECONDS=1800
    class Refused<StandardError;end
    class Token
      def initialize(owner,row)
        @owner=owner;@row=row.dup.freeze;freeze
      end
      def matches?(session) = @owner.equal?(session)
      def row_bytes = @row.dup
    end
    Slot=Struct.new(:tag,:seal_revision,:digest)
    Stamp=Struct.new(:version,:digest,:anchor_digest,:time)
    class Metadata
      attr_reader :contact_id,:revision,:digest,:request_id,:routing_digest,:name,:notes,:statement_digest,:manifest_version,:manifest_digest,:reader_id,:reader_generation,:root_writer_id,:comparison_ms,:root_stamp
      def initialize(contact_id:,revision:,digest:,request_id:,routing_digest:,name:,notes:,statement_digest:,manifest_version:,manifest_digest:,reader_id:,reader_generation:,root_writer_id:,comparison_ms:,root_stamp:)
        @contact_id=contact_id.dup.freeze;@revision=revision;@digest=digest.dup.freeze;@request_id=request_id.dup.freeze;@routing_digest=routing_digest.dup.freeze
        @name=name;@notes=notes;@statement_digest=statement_digest.dup.freeze;@manifest_version=manifest_version;@manifest_digest=manifest_digest.dup.freeze
        @reader_id=reader_id.dup.freeze;@reader_generation=reader_generation;@root_writer_id=root_writer_id.dup.freeze;@comparison_ms=comparison_ms;@root_stamp=root_stamp;freeze
      end
      # revision,digest,request,routing,name,notes,statement,manifestVersion,manifestDigest,reader,readerGeneration,rootWriter,comparison,stamp(version,digest,anchor,time)
      def encode
        [@revision].pack('Q>')+@digest+@request_id+@routing_digest+
          [@name.tag].pack('C')+[@name.seal_revision].pack('Q>')+@name.digest+
          [@notes.tag].pack('C')+[@notes.seal_revision].pack('Q>')+@notes.digest+
          @statement_digest+[@manifest_version].pack('Q>')+@manifest_digest+@reader_id+[@reader_generation].pack('Q>')+@root_writer_id+[@comparison_ms].pack('Q>')+
          [@root_stamp.version].pack('Q>')+@root_stamp.digest+@root_stamp.anchor_digest+[@root_stamp.time].pack('Q>')
      end
    end
    class Lookup
      def initialize(token,metadata,reason)
        @token=token;@metadata=metadata;@reason=reason;freeze
      end
      def accepted? = !@metadata.nil?
      def reason = @reason
      def metadata = @metadata
      def token
        @token
      end
    end

    @permits=Mutex.new
    @outstanding=0
    class << self
      def need(value,reason='refused')
        raise Refused,"Contact local history: #{reason}" unless value
      end
      def sha(bytes) = Digest::SHA256.digest(bytes)
      def u64(bytes,at)
        value=bytes.byteslice(at,8).unpack1('Q>');need(value.between?(1,2**63-1),'corrupt');value
      end
      def fixed(bytes,size)
        need(bytes.instance_of?(String) && bytes.bytesize==size && bytes.bytes.any?{|b|b!=0},'corrupt');bytes
      end
      def decode_metadata(io,contact_id)
        revision=u64(io.read(8),0);digest=fixed(io.read(32),32);request=fixed(io.read(16),16);routing=fixed(io.read(32),32)
        name=decode_slot(io,revision);notes=decode_slot(io,revision)
        statement=fixed(io.read(32),32);manifest_version=u64(io.read(8),0);manifest=fixed(io.read(32),32)
        reader=fixed(io.read(32),32);reader_generation=u64(io.read(8),0);writer=fixed(io.read(32),32);comparison=u64(io.read(8),0)
        stamp_version=u64(io.read(8),0);stamp_digest=io.read(32);anchor=io.read(32);stamp_time=u64(io.read(8),0)
        need(stamp_version>=1 && stamp_time>=1,'corrupt')
        Metadata.new(contact_id:contact_id,revision:revision,digest:digest,request_id:request,routing_digest:routing,name:name,notes:notes,statement_digest:statement,
          manifest_version:manifest_version,manifest_digest:manifest,reader_id:reader,reader_generation:reader_generation,root_writer_id:writer,comparison_ms:comparison,
          root_stamp:Stamp.new(stamp_version,stamp_digest,anchor,stamp_time))
      end
      def decode_slot(io,revision)
        tag=io.getbyte;seal=io.read(8).unpack1('Q>');digest=io.read(32)
        need([0,1].include?(tag) && seal<=revision,'corrupt')
        need(tag==0 ? seal==0 && digest.bytes.all?{|b|b==0} : seal>0 && digest.bytes.any?{|b|b!=0},'corrupt')
        Slot.new(tag,seal,digest)
      end
    end

    def initialize(path,pin,fingerprint,account,origin,maximum_records,reduction)
      ContactLocalHistory.need(pin.instance_of?(String) && pin.bytesize==94 && fingerprint.instance_of?(String) && fingerprint.bytesize==32)
      ContactLocalHistory.need(account.instance_of?(String) && account.bytesize==16 && account.bytes.any?{|b|b!=0})
      origin_bytes=origin.b.dup
      ContactLocalHistory.need(origin_bytes.bytesize.between?(1,ORIGIN_MAX) && origin_bytes.bytes.all?{|b|b>32&&b<127})
      ContactLocalHistory.need(maximum_records.between?(1,CAPACITY))
      @trust=ManifestChain::RootPin.enroll(pin.dup,fingerprint.dup)
      @path=File.expand_path(path);@maximum=maximum_records;@reduction=reduction
      @account=account.dup.freeze;@origin=origin.dup.freeze
      @header="ZTLH1".b+pin.dup+fingerprint.dup+account.dup+[origin_bytes.bytesize].pack('n')+origin_bytes+[maximum_records].pack('N')
      @closed=false;@expiry=Process.clock_gettime(Process::CLOCK_MONOTONIC)+LIFETIME_SECONDS
      ContactLocalHistory.instance_variable_get(:@permits).synchronize do
        ContactLocalHistory.need(ContactLocalHistory.instance_variable_get(:@outstanding)<4,'storage unavailable')
        ContactLocalHistory.instance_variable_set(:@outstanding,ContactLocalHistory.instance_variable_get(:@outstanding)+1)
      end
    end
    private_class_method :new

    def self.create(path,pin,fingerprint,account,origin,maximum_records,history,now)
      result=new(path,pin,fingerprint,account,origin,maximum_records,false)
      begin
        ContactLocalHistory.need(!File.exist?(result.send(:history_path)),'refused')
        saved=result.send(:capture,history);result.send(:verify_history,saved)
        File.open(result.send(:history_path),'wb',0600) do |file|
          file.flock(File::LOCK_EX);file.write(result.instance_variable_get(:@header))
          result.send(:append,file,{history:saved,rows:{}})
        end
      rescue Exception
        result.send(:release_permit);raise
      end
      result
    end
    def self.open(path,pin,fingerprint,account,origin,maximum_records,reduction:false)
      result=new(path,pin,fingerprint,account,origin,maximum_records,reduction)
      begin
        ContactLocalHistory.need(!reduction || File.exist?(result.send(:history_path)),'unobserved')
        result.send(:access){|file,state,history|}
      rescue Exception
        result.send(:release_permit);raise
      end
      result
    end

    def lookup(contact_id)
      ContactLocalHistory.need(contact_id.instance_of?(String) && contact_id.bytesize==16 && contact_id.bytes.any?{|b|b!=0})
      access do |file,state,history|
        row=state[:rows][contact_id]
        return Lookup.new(nil,nil,'unobserved') if row.nil?
        grant=Token.new(self,row_bytes(row))
        return Lookup.new(grant,nil,'local_stop') unless row[:accepted]
        return Lookup.new(grant,nil,'reduction_only') if @reduction
        Lookup.new(grant,row[:metadata],'available')
      end
    end

    def accept(expected,history,transition,statement)
      ContactLocalHistory.need(!@reduction,'reduction_only')
      ContactLocalHistory.need(transition.is_a?(ContactMutation::Transition) && statement.is_a?(ContactField::Statement))
      s=statement.identity
      ContactLocalHistory.need(s[:account]==@account && s[:origin]==@origin,'root_mismatch')
      mutation=transition.mutation.bytes;unsigned=mutation.byteslice(0,304)
      ContactLocalHistory.need(mutation.bytesize==368 && unsigned.byteslice(118,32)==s[:manifest] && unsigned.byteslice(110,8).unpack1('Q>')==s[:version])
      digest=self.class.send(:sha,mutation);revision=unsigned.byteslice(46,8).unpack1('Q>')
      n=s[:bytes].byteslice(38,2).unpack1('n');issued=s[:bytes].byteslice(225+n,8).unpack1('Q>')
      proposed=unsigned.byteslice(22,16)
      prior_row=expected.nil? ? nil : expected_row(expected)
      saved=capture(history)
      access do |file,state,chain|
        ContactLocalHistory.need(saved.size>=state[:history].size && state[:history].each_index.all?{|i|saved[i][:comparison]==state[:history][i][:comparison] && saved[i][:bytes]==state[:history][i][:bytes]},'history_missing')
        verified=verify_history(saved)
        bound=verified.each_index.find{|i|verified[i].version==s[:version] && verified[i].digest==s[:manifest]}
        ContactLocalHistory.need(!bound.nil? && saved[bound][:comparison]<=issued,'history_missing')
        metadata=Metadata.new(contact_id:proposed,revision:revision,digest:digest,request_id:unsigned.byteslice(54,16),routing_digest:unsigned.byteslice(182,32),
          name:Slot.new(unsigned.getbyte(222),unsigned.byteslice(223,8).unpack1('Q>'),unsigned.byteslice(231,32)),
          notes:Slot.new(unsigned.getbyte(263),unsigned.byteslice(264,8).unpack1('Q>'),unsigned.byteslice(272,32)),
          statement_digest:s[:digest],manifest_version:s[:version],manifest_digest:s[:manifest],reader_id:s[:reader],reader_generation:s[:reader_generation],
          root_writer_id:s[:writer],comparison_ms:issued,root_stamp:Stamp.new(verified[bound].version,verified[bound].digest,verified[bound].bytes.byteslice(53,32),saved[bound][:comparison]))
        old=state[:rows][proposed]
        operation=unsigned.getbyte(5);previous_digest=unsigned.byteslice(70,32)
        if old.nil?
          ContactLocalHistory.need(expected.nil?,'stale local CAS')
          ContactLocalHistory.need([1,3].include?(operation) && revision==1,'cold update')
          ContactLocalHistory.need(state[:rows].size<@maximum,'storage unavailable')
          rows=state[:rows].dup;rows[proposed]={contact_id:proposed,accepted:true,metadata:metadata}
          verify_rows(rows,verified,saved);append(file,{history:saved,rows:rows})
          return Lookup.new(Token.new(self,proposed+"".b+metadata.encode),metadata,'available')
        end
        ContactLocalHistory.need(!prior_row.nil? && prior_row==row_bytes(old),'stale local CAS')
        ContactLocalHistory.need(old[:accepted],'local_stop')
        if old[:metadata].revision==revision
          ContactLocalHistory.need(row_bytes(old)==row_bytes({contact_id:proposed,accepted:true,metadata:metadata_with_stamp(metadata,old[:metadata].root_stamp)}),'fork')
          return Lookup.new(Token.new(self,row_bytes(old)),old[:metadata],'available')
        end
        ContactLocalHistory.need(operation==2 && old[:metadata].revision<2**63-1 && revision==old[:metadata].revision+1,'fork')
        ContactLocalHistory.need(previous_digest==old[:metadata].digest,'fork')
        ContactLocalHistory.need(metadata.routing_digest==old[:metadata].routing_digest,'fork')
        ContactLocalHistory.need(metadata.manifest_version>old[:metadata].manifest_version || metadata.manifest_version==old[:metadata].manifest_version && metadata.manifest_digest==old[:metadata].manifest_digest,'fork')
        ContactLocalHistory.need(metadata.reader_generation>old[:metadata].reader_generation || metadata.reader_generation==old[:metadata].reader_generation && metadata.reader_id==old[:metadata].reader_id,'fork')
        rows=state[:rows].dup;rows[proposed]={contact_id:proposed,accepted:true,metadata:metadata}
        verify_rows(rows,verified,saved);append(file,{history:saved,rows:rows})
        Lookup.new(Token.new(self,proposed+"".b+metadata.encode),metadata,'available')
      end
    end

    def mark_unavailable(expected)
      prior=expected_row(expected);contact=prior.byteslice(0,16)
      access do |file,state,history|
        old=state[:rows][contact]
        ContactLocalHistory.need(!old.nil? && prior==row_bytes(old),'stale local CAS')
        return Lookup.new(Token.new(self,row_bytes(old)),nil,'local_stop') unless old[:accepted]
        rows=state[:rows].dup;rows[contact]={contact_id:contact,accepted:false}
        append(file,{history:state[:history],rows:rows})
        Lookup.new(Token.new(self,contact+"\x02".b),nil,'local_stop')
      end
    end

    def close
      return if @closed
      @closed=true;release_permit
    end
    private
    def release_permit
      ContactLocalHistory.instance_variable_get(:@permits).synchronize{ContactLocalHistory.instance_variable_set(:@outstanding,ContactLocalHistory.instance_variable_get(:@outstanding)-1)}
    end
    def real_now
      (Time.now.to_f*1000).to_i
    end
    def live
      ContactLocalHistory.need(!@closed && Process.clock_gettime(Process::CLOCK_MONOTONIC)<@expiry,'closed')
    end
    def expected_row(token)
      ContactLocalHistory.need(token.instance_of?(Token) && token.matches?(self),'invalid local token');token.row_bytes
    end
    def row_bytes(row) = row[:accepted] ? row[:contact_id]+"\x01".b+row[:metadata].encode : row[:contact_id]+"\x02".b
    def metadata_with_stamp(m,stamp)
      Metadata.new(contact_id:m.contact_id,revision:m.revision,digest:m.digest,request_id:m.request_id,routing_digest:m.routing_digest,name:m.name,notes:m.notes,statement_digest:m.statement_digest,
        manifest_version:m.manifest_version,manifest_digest:m.manifest_digest,reader_id:m.reader_id,reader_generation:m.reader_generation,root_writer_id:m.root_writer_id,comparison_ms:m.comparison_ms,root_stamp:stamp)
    end
    def capture(history)
      ContactLocalHistory.need(history.is_a?(Array) && history.size.between?(1,HISTORY_LIMIT))
      history.map do |m|
        ContactLocalHistory.need(m.is_a?(ManifestChain::Verified) && m.profile==2 && m.generation==1)
        {comparison:m.comparison_ms,bytes:m.bytes}
      end
    end
    def verify_history(rows)
      ContactLocalHistory.need(rows.size.between?(1,HISTORY_LIMIT))
      verified=[];previous=nil
      rows.each do |row|
        ContactLocalHistory.need(row[:comparison].between?(1,2**63-1) && row[:bytes].bytesize.between?(364,9751))
        m=ManifestChain.send(:original_accepted02,row[:bytes],@trust,previous,row[:comparison])
        ContactLocalHistory.need(m.generation==1 && m.version==verified.size+1 && m.account==@account,'corrupt')
        verified<<m;previous=m
      end
      verified
    end
    def encode_state(state)
      body=[state[:history].size].pack('N')
      state[:history].each{|m|body+=[m[:comparison]].pack('Q>')+[m[:bytes].bytesize].pack('N')+m[:bytes]}
      body+=[state[:rows].size].pack('N')
      state[:rows].each_value{|row|body+=row_bytes(row)}
      body
    end
    def append(file,state)
      raw=encode_state(state);length=[raw.bytesize].pack('N')
      ContactLocalHistory.need(file.size+4+raw.bytesize+32<=MAX_BYTES,'storage unavailable')
      file.seek(file.size);file.write(length+raw+self.class.send(:sha,@header+length+raw));file.fsync
    end
    def load_state(file)
      ContactLocalHistory.need(file.size>=@header.bytesize+4+12+364+32+4 && file.size<=MAX_BYTES,'corrupt')
      file.seek(0);ContactLocalHistory.need(file.read(@header.bytesize)==@header,'root_mismatch')
      state=nil;verified=nil
      while file.pos<file.size
        ContactLocalHistory.need(file.size-file.pos>=4,'corrupt');length=file.read(4).unpack1('N')
        ContactLocalHistory.need(length>=12+364 && length<=20+HISTORY_LIMIT*(12+9751)+CAPACITY*230 && file.size-file.pos>=length+32,'corrupt')
        body=file.read(length);ContactLocalHistory.need(file.read(32)==self.class.send(:sha,@header+[length].pack('N')+body),'corrupt')
        io=StringIO.new(body);count=io.read(4).unpack1('N')
        ContactLocalHistory.need(count.between?(1,HISTORY_LIMIT),'corrupt')
        saved=[];count.times do
          comparison=io.read(8).unpack1('Q>');size=io.read(4).unpack1('N');bytes=io.read(size)
          ContactLocalHistory.need(comparison.between?(1,2**63-1) && size.between?(364,9751) && bytes.bytesize==size,'corrupt')
          saved<<{comparison:comparison,bytes:bytes}
        end
        verified=verify_history(saved)
        rows={};row_count=io.read(4).unpack1('N');ContactLocalHistory.need(row_count<=CAPACITY,'corrupt')
        row_count.times do
          contact_id=io.read(16);ContactLocalHistory.need(contact_id.bytesize==16 && contact_id.bytes.any?{|b|b!=0} && !rows.key?(contact_id),'corrupt')
          state_byte=io.getbyte
          if state_byte==2 then rows[contact_id]={contact_id:contact_id,accepted:false}
          elsif state_byte==1 then rows[contact_id]={contact_id:contact_id,accepted:true,metadata:self.class.decode_metadata(io,contact_id)}
          else ContactLocalHistory.need(false,'corrupt');end
        end
        ContactLocalHistory.need(io.eof?,'corrupt')
        verify_rows(rows,verified,saved)
        unless state.nil?
          ContactLocalHistory.need(saved.size>=state[:history].size && state[:history].each_index.all?{|i|saved[i][:comparison]==state[:history][i][:comparison] && saved[i][:bytes]==state[:history][i][:bytes]},'corrupt')
          state[:rows].each do |id,row|
            fresh=rows[id];ContactLocalHistory.need(!fresh.nil?,'corrupt')
            next unless row[:accepted]
            next unless fresh[:accepted]
            ContactLocalHistory.need(fresh[:metadata].revision>=row[:metadata].revision,'corrupt')
            ContactLocalHistory.need(fresh[:metadata].revision>row[:metadata].revision || fresh[:metadata].encode==row[:metadata].encode,'corrupt')
          end
        end
        state={history:saved,rows:rows}
      end
      ContactLocalHistory.need(!state.nil?,'unobserved')
      [state,verified]
    end
    def verify_rows(rows,verified,saved)
      ContactLocalHistory.need(rows.values.count{|r|r[:accepted]}<=@maximum,'corrupt')
      rows.each_value do |row|
        next unless row[:accepted]
        m=row[:metadata]
        at=verified.each_index.find{|i|verified[i].version==m.manifest_version && verified[i].digest==m.manifest_digest}
        ContactLocalHistory.need(!at.nil? && saved[at][:comparison]<=m.comparison_ms,'history_missing')
        manifest=verified[at]
        reader=manifest.key_records.find{|k|k.getbyte(0)==2 && k.byteslice(1,32)==m.reader_id && k.byteslice(132,8).unpack1('Q>')<=m.comparison_ms && m.comparison_ms<k.byteslice(140,8).unpack1('Q>')}
        writer=manifest.key_records.find{|k|k.getbyte(0)==6 && k.byteslice(1,32)==m.root_writer_id}
        ContactLocalHistory.need(!reader.nil? && !writer.nil?,'history_missing')
        head=verified[-1]
        ContactLocalHistory.need(head.version>m.root_stamp.version || head.version==m.root_stamp.version && head.digest==m.root_stamp.digest,'history_missing')
      end
    end
    def history_path = @path
    def access
      live
      ContactLocalHistory.need(File.exist?(@path),'unobserved')
      File.open(@path,'r+b') do |file|
        acquired=false
        100.times{acquired=file.flock(File::LOCK_EX|File::LOCK_NB);break if acquired;sleep(0.05)}
        ContactLocalHistory.need(acquired,'storage unavailable')
        state,verified=load_state(file)
        yield(file,state,verified)
      end
    end
  end
end
