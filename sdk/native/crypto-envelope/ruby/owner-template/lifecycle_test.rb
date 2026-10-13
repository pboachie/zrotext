# frozen_string_literal: true
module OwnerTemplateLifecycleTest
 def self.run(origin,binding,template,session,roots)
  type=ZrotextCandidate::OwnerTemplate;entered=Queue.new;release=Queue.new;clients=[];threads=[];errors=Queue.new
  blocked=-> {entered.push(true);Timeout.timeout(10){release.pop};raise type::Failure.new('synthetic')}
  make=->(callback){type.new(origin:origin,binding:binding,template_id:template,current:callback,session:session,enabled:true,timeout_ms:10000,additional_roots_pem:roots)}
  begin
   8.times {clients<<make.call(blocked)}
   clients.each do |client|
    threads<<Thread.new do
     begin;client.read_latest;errors.push('Closed client returned snapshot');rescue type::Failure;rescue StandardError=>error;errors.push(error);end
    end
   end
   Timeout.timeout(8){8.times {entered.pop}};expect(clients.first,'busy');clients.each(&:close)
   threads.each { |t| raise 'Close did not settle foreground' unless t.join(2) };raise errors.pop unless errors.empty?
   recovered=false;ninth=make.call(-> {recovered=true;raise type::Failure.new('synthetic')});clients<<ninth;expect(ninth,'capacity');8.times {release.push(true)}
   Timeout.timeout(3) do
    loop do
     begin;ninth.read_latest;raise 'Unexpected snapshot';rescue type::Failure=>error;break if ['owner_changed','closed'].include?(error.code) && recovered;raise unless error.code=='capacity';sleep(0.005);end
    end
   end
  ensure
   8.times {release.push(true)};clients.each(&:close);threads.each { |t| t.join(2) }
  end
 end
 def self.expect(client,code)
  begin;client.read_latest;raise 'Expected '+code;rescue ZrotextCandidate::OwnerTemplate::Failure=>error;raise unless error.code==code;end
 end
end
