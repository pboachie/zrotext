# frozen_string_literal: true
require_relative '../manifest_chain'
module ZrotextCandidate
  # Trusted private path; checksummed incomplete append refuses rather than recovering a half-pair.
  class RootJournal
    def initialize(path,pin,fingerprint,approved_roots)
      need(approved_roots.instance_of?(Hash) && approved_roots.length<=256)
      @pin=pin.b.dup.freeze;@fingerprint=fingerprint.b.dup.freeze
      @trust=ManifestChain::RootPin.enroll(@pin,@fingerprint);@path=File.expand_path(path)
      @approvals=approved_roots.to_h do |generation,point|
        need(generation.instance_of?(Integer) && generation.between?(2,2**63-1) && point.bytesize==65)
        value=point.b.dup.freeze;HpkeRecipient.point(value);[generation,value]
      end.freeze
      @header=('ZTC2'.b+@pin+@fingerprint).freeze
    end
    def accept(manifest,expected_revision,now_ms,transition:nil)
      raw=manifest.b.dup;change=transition&.b&.dup
      access(now_ms) do |file,revision,current,advance|
        need(expected_revision.instance_of?(Integer) && revision==expected_revision && revision<256)
        value=step(raw,change,current,now_ms)
        change||=''.b;record=[revision+1,now_ms,change.bytesize,raw.bytesize].pack('Q>2N2')+change+raw
        advance.call(now_ms);file.write(record);file.write(sha(record));file.flush;file.fsync
        [revision+1,value]
      end
    end
    def snapshot(now_ms)
      access(now_ms) do |_file,revision,current,advance|
        value=current && ManifestChain.continue_chain(current.bytes,current,2,now_ms)
        advance.call(now_ms);[revision,value]
      end
    end
    private
    def need(v) = (raise ArgumentError,'Root journal refused' unless v)
    def sha(v) = OpenSSL::Digest::SHA256.digest(v)
    def read(file,size)
      value=file.read(size);need(value && value.bytesize==size);value
    end
    def step(raw,transition,current,now)
      need(raw.bytesize.between?(364,9751) && raw.getbyte(4)==2)
      unless current
        need(transition.nil?);return ManifestChain.genesis02(raw,@trust,now)
      end
      if transition
        need(transition.bytesize==343)
        generation=transition.byteslice(29,8).unpack1('Q>');approved=@approvals[generation];need(approved)
        return ManifestChain.rotate02(transition,raw,current,approved,now)
      end
      value=ManifestChain.continue_chain(raw,current,2,now);need(value.version==current.version+1);value
    end
    def access(now)
      need(now.instance_of?(Integer) && now.between?(1,2**63-1) && !File.symlink?(@path))
      created=false
      begin
        file=File.open(@path,File::RDWR|File::BINARY|File::CREAT|File::EXCL,0o600);created=true
      rescue Errno::EEXIST
        file=File.open(@path,File::RDWR|File::BINARY)
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
          need(next_revision==revision+1 && time>=comparison && time<=floor && [0,343].include?(change_size) && size.between?(364,9751) && file.size-file.pos>=change_size+size+32)
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
