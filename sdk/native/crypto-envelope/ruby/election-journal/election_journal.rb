# frozen_string_literal: true
require_relative '../election03'
module ZrotextCandidate
  # Trusted private path; checksummed incomplete append refuses rather than recovering a half-pair.
  class ElectionJournal
    class Expectations
      attr_reader :core,:device,:owner,:accepted,:digest
      def initialize(expected_core,accepted_record,device_point,owner_point)
        raise ArgumentError,'Election expectations refused' unless expected_core.bytesize==500 && device_point.bytesize==65 && owner_point.bytesize==65 && accepted_record.instance_of?(Hash) && accepted_record.length<=32
        @core=expected_core.b.dup.freeze;@device=device_point.b.dup.freeze;@owner=owner_point.b.dup.freeze;HpkeRecipient.point(@device);HpkeRecipient.point(@owner)
        encoded=[]
        @accepted=accepted_record.to_h do |key,item|
          raise ArgumentError,'Election record field refused' unless key.instance_of?(String) && /\A[A-Za-z][A-Za-z0-9]{0,63}\z/.match?(key)
          if item.instance_of?(String)
            raise ArgumentError,'Election record width refused' unless [16,32].include?(item.bytesize)
            captured=item.b.dup.freeze;value=[0,captured.bytesize].pack('C2')+captured
          else
            raise ArgumentError,'Election record number refused' unless item.instance_of?(Integer) && item.between?(1,2**63-1)
            captured=item;value=[1].pack('C')+[item].pack('Q>')
          end
          encoded<<[key.bytesize].pack('C')+key.b+value;[key.dup.freeze,captured]
        end.freeze
        @digest=OpenSSL::Digest::SHA256.digest(@core+@device+@owner+encoded.sort.join.b).freeze;freeze
      end
    end
    def initialize(path,pin,fingerprint,expectations)
      need(expectations.nil? || expectations.instance_of?(Expectations));@expected=expectations
      @pin=pin.b.dup.freeze;@fingerprint=fingerprint.b.dup.freeze
      @trust=ManifestChain::RootPin.enroll(@pin,@fingerprint);@path=File.expand_path(path)
      @header=('ZTE3'.b+@pin+@fingerprint).freeze
    end
    def accept(manifest,expected_revision,now_ms,bundle:nil)
      raw=manifest.b.dup;change=bundle&.b&.dup
      access(now_ms) do |file,revision,current,advance|
        need(expected_revision.instance_of?(Integer) && revision==expected_revision && revision<256)
        need(change.nil? || change.bytesize==628 && @expected)
        change=change+@expected.digest if change
        value=step(raw,change,current,now_ms)
        change||=''.b;record=[revision+1,now_ms,change.bytesize,raw.bytesize].pack('Q>2N2')+change+raw
        advance.call(now_ms);file.write(record);file.write(sha(record));file.flush;file.fsync
        [revision+1,*value]
      end
    end
    def snapshot(now_ms)
      access(now_ms) do |_file,revision,current,advance|
        value=current && ManifestChain.continue_chain(current[0].bytes,current[0],current[0].profile,now_ms)
        advance.call(now_ms);[revision,value,current && current[1]]
      end
    end
    private
    def need(v) = (raise ArgumentError,'Election journal refused' unless v)
    def sha(v) = OpenSSL::Digest::SHA256.digest(v)
    def read(file,size)
      value=file.read(size);need(value && value.bytesize==size);value
    end
    def step(raw,election,current,now)
      need(raw.bytesize.between?(364,9753) && [2,3].include?(raw.getbyte(4)))
      unless current
        need(election.nil? && raw.getbyte(4)==2);return [ManifestChain.genesis02(raw,@trust,now),nil]
      end
      prior,proof=current
      if election
        need(election.bytesize==660 && @expected && prior.profile==2 && raw.getbyte(4)==3 && proof.nil? && election.byteslice(628,32)==@expected.digest && @expected.accepted['acceptedAtMs']==now)
        proof=Election03.verify(election.byteslice(0,628),@expected.core,@expected.accepted,prior,prior.bytes,raw,@expected.device,@expected.owner)
        return [proof.accepted_manifest,proof]
      end
      need(raw.getbyte(4)==prior.profile)
      value=ManifestChain.continue_chain(raw,prior,raw.getbyte(4),now);need(value.version==prior.version+1);[value,proof]
    end
    def access(now)
      need(now.instance_of?(Integer) && now.between?(1,2**63-1) && !File.symlink?(@path))
      created=false
      begin
        file=File.open(@path,File::RDWR|File::CREAT|File::EXCL,0o600);created=true
      rescue Errno::EEXIST
        file=File.open(@path,File::RDWR)
      end
      begin
        file.binmode;locked=false
        100.times { locked=file.flock(File::LOCK_EX|File::LOCK_NB);break if locked;sleep 0.05 };need(locked)
        if created
          clock=[0].pack('Q>');file.write(@header+clock+sha(@header+clock));file.flush;file.fsync
        end
        need(file.size.between?(@header.bytesize+40,3000000));file.rewind;need(read(file,@header.bytesize)==@header)
        clock=read(file,8);need(read(file,32)==sha(@header+clock));floor=clock.unpack1('Q>');need(floor<=now)
        advance=->(value) do
          need(value>=floor)
          if value>floor
            position=file.pos;clock=[value].pack('Q>');file.seek(@header.bytesize);file.write(clock+sha(@header+clock));file.flush;file.fsync;file.seek(position);floor=value
          end
        end
        current=nil;revision=0;comparison=0
        while file.pos<file.size
          need(revision<256 && file.size-file.pos>=56)
          prefix=read(file,24);next_revision,time,change_size,size=prefix.unpack('Q>2N2')
          need(next_revision==revision+1 && time>=comparison && time<=floor && [0,660].include?(change_size) && size.between?(364,9753) && file.size-file.pos>=change_size+size+32)
          change=read(file,change_size);raw=read(file,size);need(read(file,32)==sha(prefix+change+raw))
          current=step(raw,change_size==0 ? nil : change,current,time);revision=next_revision;comparison=time
        end
        yield file,revision,current,advance
      ensure
        file.close
      end
    end
  end
end
