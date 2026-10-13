# frozen_string_literal: true
require_relative 'original_current'

module ZrotextCandidate
  class OriginalCurrentClient
    PageCursor=Struct.new(:event_id,:accepted_at_ms,keyword_init:true)
    class Page
      attr_reader :events,:next_cursor,:authority
      def initialize(events,cursor,authority)
        @events=events.freeze;@next_cursor=cursor;@authority=authority;freeze
      end
      private_class_method :new
    end
    # Discovery metadata only, never permission to consume or propose an action.
    def page(credential:,clock:,limit:,cursor:nil)
      acquired=false
      need(limit.is_a?(Integer) && limit.between?(1,32) && clock.respond_to?(:call))
      after=cursor ? page_cursor(cursor.event_id,cursor.accepted_at_ms) : nil
      need(@lock.try_lock);acquired=true;saved=saved_at(clock);latest=saved.history.last
      wirecursor=after && {event_id:after.event_id,accepted_at_ms:after.accepted_at_ms}
      wire=@transport.exchange(credential:credential,method:'page',accepted_manifest_version:latest.version,limit:limit,cursor:wirecursor)
      r=object(JSON.parse(wire.untrusted_json,object_class:OriginalHTTP::UniqueObject,max_nesting:64),%w[events next proof])
      need(r['events'].is_a?(Array) && r['events'].size<=limit);ids=[]
      rows=r['events'].map do |row|
        e=object(row,%w[event_id accepted_at_ms observed_at_ms historical_manifest_version activation_manifest_version disposition active_request_ids])
        id=page_id(e['event_id']);need(!ids.include?(id));ids<<id
        %w[accepted_at_ms observed_at_ms historical_manifest_version activation_manifest_version].each { |field| integer(e[field]) }
        current=page_cursor(id,e['accepted_at_ms'])
        need(after.nil? || current.accepted_at_ms>after.accepted_at_ms || (current.accepted_at_ms==after.accepted_at_ms && current.event_id>after.event_id));after=current
        need(%w[unassociated owner_review request_available].include?(e['disposition']) && e['active_request_ids'].is_a?(Array) && e['active_request_ids'].size<=8)
        requests=e['active_request_ids'].map { |v| page_id(v) };need(requests.uniq.size==requests.size)
        e.merge('event_id'=>id,'active_request_ids'=>requests.freeze,'disposition'=>e['disposition'].dup.freeze).freeze
      end
      next_cursor=nil
      if r['next'].nil?
        need(rows.size<limit)
      else
        c=object(r['next'],%w[event_id accepted_at_ms]);next_cursor=page_cursor(c['event_id'],c['accepted_at_ms'])
        need(rows.size==limit && next_cursor==after)
      end
      authority=accept_proof(r['proof'],saved,latest,clock)
      Page.send(:new,rows,next_cursor,authority)
    rescue StandardError
      raise OriginalHTTP::Failure.new, cause:nil
    ensure
      @lock.unlock if acquired
    end
    private
    def page_id(value)
      OriginalHTTP.uuid!(value);value.dup.freeze
    end
    def page_cursor(id,time) = PageCursor.new(event_id:page_id(id),accepted_at_ms:integer(time)).freeze
  end
end
