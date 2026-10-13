# frozen_string_literal: true
require_relative 'original_http'
require_relative '../original-history/original_reply_checkpoint'

module ZrotextCandidate
  # Authenticated snapshot only; callers still need fresh authority around effects.
  class OriginalCurrentClient
    class Verified
      attr_reader :authority
      def initialize(authority) = (@authority = authority.freeze; freeze)
      private_class_method :new
    end
    FIELDS = %w[account_id interval_id device_id line_id connector_id read_grant_id reader_id root_generation authority_revision expires_at_ms observed_at_ms current_manifest_version current_manifest_digest manifest_chain].freeze
    SAFE = 9_007_199_254_740_991
    def initialize(transport:, checkpoint:, pin:, fingerprint:, scope:, now:)
      need(transport.instance_of?(OriginalHTTP) && checkpoint.instance_of?(OriginalReplyCheckpoint) && scope.instance_of?(OriginalReplyReader::Scope))
      integer(now); @transport=transport; @checkpoint=checkpoint; @scope=scope; @root=ManifestChain::RootPin.enroll(pin,fingerprint)
      saved=checkpoint.snapshot(scope,now); at(saved.history.first.bytes,nil,saved.history.first.comparison_ms)
      @revision=saved.revision; @last=now; @failed=false; @lock=Mutex.new
    rescue StandardError
      raise OriginalHTTP::Failure.new, cause: nil
    end

    def current(credential:, clock:)
      acquired=false
      need(clock.respond_to?(:call) && @lock.try_lock); acquired=true; need(!@failed)
      current_locked(credential,clock)
    rescue StandardError
      raise OriginalHTTP::Failure.new, cause: nil
    ensure
      @lock.unlock if acquired
    end

    private
    def sample(clock)
      value=integer(clock.call); need(value>=@last); @last=value; value
    end
    def saved_at(clock)
      need(!@failed); saved=@checkpoint.snapshot(@scope,sample(clock))
      if saved.revision!=@revision
        @failed=true; need(false)
      end
      saved
    end
    def current_locked(credential,clock)
      saved=saved_at(clock); latest=saved.history.last
      wire=@transport.exchange(credential:credential,method:'current',accepted_manifest_version:latest.version)
      accept_proof(JSON.parse(wire.untrusted_json,object_class:OriginalHTTP::UniqueObject,max_nesting:64),saved,latest,clock)
    end
    def accept_proof(value,saved,first,clock)
      p=object(value,FIELDS)
      now=sample(clock); observed=integer(p['observed_at_ms']); expires=integer(p['expires_at_ms'])
      fresh=lambda { |time| need(time<expires && time<=observed+30000 && observed<=time+30000) }
      fresh.call(now)
      {'account_id'=>:account,'device_id'=>:device,'line_id'=>:line,'interval_id'=>:interval,'connector_id'=>:connector,'read_grant_id'=>:grant}.each do |field,key|
        value=p[field]; OriginalHTTP.uuid!(value); need([value.delete('-')].pack('H*')==@scope.public_send(key))
      end
      need(p['reader_id']==@scope.reader.unpack1('H*') && integer(p['authority_revision'])==1)
      chain=p['manifest_chain']; need(chain.is_a?(Array) && chain.size.between?(1,32))
      latest=saved.history.last; history=saved.history.dup; previous=first
      chain.each_with_index do |row,index|
        entry=object(row,%w[version accepted_at_ms manifest_b64]); version=integer(entry['version']); accepted=integer(entry['accepted_at_ms'])
        need(accepted<=now+30000 && version==(index.zero? ? first.version : previous.version+1))
        encoded=entry['manifest_b64']; need(encoded.is_a?(String) && encoded.length<=13004)
        bytes=Base64.strict_decode64(encoded); need(bytes.bytesize<=9751 && Base64.strict_encode64(bytes)==encoded)
        current=at(bytes,previous,accepted)
        need(current.version==version && current.generation==latest.generation && current.root_point==latest.root_point)
        cached=saved.history.find { |m| m.version==version }
        if cached
          need(current.digest==cached.digest)
        else
          need(version>latest.version); history<<current
        end
        previous=current
      end
      need(previous.version>=latest.version && integer(p['current_manifest_version'])==previous.version && integer(p['root_generation'])==latest.generation && p['current_manifest_digest']==previous.digest.unpack1('H*') && history.size<=64)
      now=sample(clock); fresh.call(now); at(previous.bytes,previous,now)
      fence=lambda { |manifest,floor| time=sample(clock); need(time>=floor); fresh.call(time); at(manifest.bytes,manifest,time); time }
      @failed=true
      committed=@checkpoint.accept(@scope,history,@revision,now,&fence)
      after=sample(clock); need(after>=committed.comparison_ms); fresh.call(after); at(committed.history.last.bytes,committed.history.last,after)
      committed=@checkpoint.accept(@scope,committed.history,committed.revision,after,&fence) if after>committed.comparison_ms
      @revision=committed.revision; @last=committed.comparison_ms; @failed=false
      Verified.send(:new,OriginalReplyReader::Authority.new(scope:@scope,revision:'1',now_ms:@last,expires_ms:expires,manifest:committed.history.last))
    end
    def need(value) = (raise OriginalHTTP::Failure unless value)
    def integer(value)
      need(value.is_a?(Integer) && value.between?(1,SAFE)); value
    end
    def object(value,fields)
      need(value.is_a?(Hash) && value.keys.sort==fields.sort); value
    end
    def at(bytes,previous,time) = ManifestChain.send(:original_accepted02,bytes,@root,previous,time)
  end
end
