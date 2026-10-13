# frozen_string_literal: true
require_relative '../original_reply_reader'

module ZrotextCandidate
  # Trusted-path append transactions. Torn writes refuse; hostile whole-file rollback is outside scope.
  class OriginalReplyCheckpoint
    CAPACITY=64
    TRANSACTIONS=256
    MAX_BYTES=16000000
    Snapshot=Struct.new(:revision,:comparison_ms,:history,keyword_init:true)
    def initialize(path,pin,fingerprint,scope)
      @path=File.expand_path(path);root=pin.b.dup;compared=fingerprint.b.dup;@trust=ManifestChain::RootPin.enroll(root,compared)
      need(root.byteslice(5,16)==scope.account);@header=("ZTO1".b+root+compared+scope.checkpoint_binding).freeze
    end
    private_class_method :new
    def self.create(path,pin,fingerprint,scope,history,now)
      result=new(path,pin,fingerprint,scope);rows=result.send(:capture,history);result.send(:verify,rows,now)
      File.open(result.instance_variable_get(:@path),File::RDWR|File::CREAT|File::EXCL,0600) do |file|
        file.binmode;file.flock(File::LOCK_EX);file.write(result.instance_variable_get(:@header));result.send(:append,file,[1,now,rows])
      end
      result
    end
    def self.open(path,pin,fingerprint,scope)
      result=new(path,pin,fingerprint,scope);result.send(:access) { |_file,state| result.send(:verify,state[2],state[1]) };result
    end
    # Read/reverify without advancing durable time. Accept before exposing output.
    def snapshot(scope,now)
      need(scope.checkpoint_binding==@header.byteslice(-32,32))
      access do |_file,state|
        need(now.is_a?(Integer) && now>=state[1]);Snapshot.new(revision:state[0],comparison_ms:state[1],history:verify(state[2],now)).freeze
      end
    end
    # Trusted freshness callback runs under exclusive ownership before one flushed append.
    def accept(scope,history,expected_revision,now,&fence)
      need(fence && scope.checkpoint_binding==@header.byteslice(-32,32));proposed=capture(history)
      access do |file,state|
        need(expected_revision==state[0] && state[0]<TRANSACTIONS && now.is_a?(Integer) && now>=state[1] && proposed.size>=state[2].size);verify(proposed,now)
        state[2].each_with_index do |old,i|
          need(old[1].byteslice(0,old[1].bytesize-64)==proposed[i][1].byteslice(0,proposed[i][1].bytesize-64));proposed[i]=old
        end
        before=verify(proposed,now);checked=fence.call(before.last,now);need(checked.is_a?(Integer) && checked>=now);verified=verify(proposed,checked);next_state=[state[0]+1,checked,proposed];append(file,next_state)
        Snapshot.new(revision:next_state[0],comparison_ms:checked,history:verified).freeze
      end
    end
    private
    def need(value) = (raise ArgumentError,'Original history refused' unless value)
    def sha(value) = OpenSSL::Digest::SHA256.digest(value)
    def capture(history)
      need(history.is_a?(Array) && history.size.between?(1,CAPACITY))
      history.map { |m| need(m.instance_of?(ManifestChain::Verified) && m.profile==2 && m.generation==1);[m.comparison_ms,m.bytes.freeze].freeze }
    end
    def verify(rows,now)
      need(now.is_a?(Integer) && now.between?(1,2**63-1) && rows.size.between?(1,CAPACITY));history=[];previous=nil
      rows.each do |time,raw|
        need(time.between?(1,now) && raw.bytesize.between?(364,9751));m=previous ? ManifestChain.continue_chain(raw,previous,2,time) : ManifestChain.genesis02(raw,@trust,time)
        need(m.generation==1 && m.version==history.size+1);history<<m;previous=m
      end
      history[-1]=ManifestChain.continue_chain(previous.bytes,previous,2,now);history.freeze
    end
    def read(file,count)
      value=file.read(count);need(value && value.bytesize==count);value
    end
    def decode(bytes)
      revision,now,count=bytes.byteslice(0,20).unpack('Q>Q>N');need(revision.between?(1,TRANSACTIONS) && now.between?(1,2**63-1) && count.between?(1,CAPACITY));at=20;rows=[]
      count.times do
        need(bytes.bytesize-at>=12);time,length=bytes.byteslice(at,12).unpack('Q>N');at+=12;need(length.between?(364,9751) && bytes.bytesize-at>=length);rows<<[time,bytes.byteslice(at,length).freeze].freeze;at+=length
      end
      need(at==bytes.bytesize);verify(rows,now);[revision,now,rows]
    end
    def load(file)
      need(file.size.between?(@header.bytesize+432,MAX_BYTES));file.rewind;need(read(file,@header.bytesize)==@header);state=nil
      while file.pos<file.size
        length=read(file,4);count=length.unpack1('N');need(count.between?(396,20+CAPACITY*(12+9751)) && file.size-file.pos>=count+32);body=read(file,count);need(read(file,32)==sha(@header+length+body));following=decode(body)
        need(following[0]==(state ? state[0]+1 : 1))
        if state
          need(following[1]>=state[1] && following[2].size>=state[2].size);state[2].each_with_index { |old,i| need(old==following[2][i]) }
        end
        state=following
      end
      need(state);state
    end
    def append(file,state)
      body=[state[0],state[1],state[2].size].pack('Q>Q>N')+state[2].map { |time,raw| [time,raw.bytesize].pack('Q>N')+raw }.join
      length=[body.bytesize].pack('N');record=length+body+sha(@header+length+body);need(file.size+record.bytesize<=MAX_BYTES);file.seek(0,IO::SEEK_END);need(file.write(record)==record.bytesize);file.flush;file.fsync
    end
    def access
      need(File.lstat(@path).file? && !File.symlink?(@path))
      File.open(@path,File::RDWR) do |file|
        file.binmode;locked=false
        100.times { locked=file.flock(File::LOCK_EX|File::LOCK_NB);break if locked;sleep 0.05 }
        need(locked);yield file,load(file)
      end
    end
  end
end
