# frozen_string_literal: true
require 'json'
require 'base64'
require_relative 'contact_mutation'
include ZrotextCandidate
parser=ContactOrigin.new(ARGV.fetch(0))
results=JSON.parse(STDIN.read).map do |request|
  out={accepted:false,mutationVerified:false}
  begin
    f=request.fetch('fixture');d=->(key){Base64.strict_decode64(f.fetch(key))}
    pin=ManifestChain::RootPin.enroll(d.call('rootPin'),d.call('fingerprint'));m=ManifestChain.genesis02(d.call('manifest'),pin,10000);next_m=ManifestChain.continue_chain(d.call('nextManifest'),m,2,10000)
    statements={};[['statement',m],['nextStatement',next_m]].each{|name,manifest|statements[name]=ContactField.verify_statement(d.call(name),manifest,account:d.call('account'),origin:f.fetch('origin'),root_fingerprint:d.call('fingerprint'),parser:parser)}
    selected=->(name){statements.fetch(%w[update clear replacement].include?(name) ? 'nextStatement' : 'statement')}
    e=ContactField::Expected.new(account:d.call('account'),origin:f.fetch('origin'),root_fingerprint:d.call('fingerprint'),contact:d.call('contact'),routing:d.call('routing'),parser:parser)
    fields={};%w[name notes replacement].each{|name|fields[name]=ContactField.verify(d.call(name),selected.call(name),contact:d.call('contact'),routing:d.call('routing'))}
    replacements=->(name){case name;when 'create','converted' then [fields['name'],fields['notes']];when 'update' then [fields['replacement']];else [] end}
    legacy=->(name){name=='converted' ? 7 : 0}
    transition=nil;transition=->(name) do
      next nil if name=='none'
      raise 'Unknown predecessor' unless %w[create update].include?(name)
      previous=name=='update' ? transition.call('create') : nil
      ContactMutation.transition(previous,ContactMutation.verify(d.call(name),selected.call(name),e,legacy:legacy.call(name)),replacements.call(name))
    end
    key_for=->(scalar) do
      der=OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(scalar),OpenSSL::ASN1::ObjectId.new('prime256v1',0,:EXPLICIT),OpenSSL::ASN1::BitString.new(m.root_point,1,:EXPLICIT)]).to_der
      OpenSSL::PKey.read(der)
    end
    op=request.fetch('operation');name=request.fetch('mutation','create')
    if op=='produce-chain'
      outputs={};previous=ps=nil;key=key_for.call("\x00".b*31+"\x07".b)
      %w[create update clear converted].each do |which|
        previous=ps=nil if which=='converted'
        u=d.call(which).byteslice(0,304);u[70,32]=previous.mutation.digest if previous
        previous=ContactMutation.produce_software(key,selected.call(which),e,u,legacy:legacy.call(which),previous:previous,previous_statement:ps,replacements:replacements.call(which));ps=selected.call(which)
        outputs[which]=Base64.strict_encode64(previous.mutation.bytes)
      end
      out[:accepted]=true;out[:mutations]=outputs;next out
    end
    st=request['statement'] ? statements.fetch(request['statement']) : selected.call(name)
    prior=request.fetch('previous',name=='update' ? 'create' : name=='clear' ? 'update' : 'none');previous=transition.call(prior)
    fs=request.key?('replacements') ? request['replacements'].map{|v|fields[v]} : replacements.call(name)
    l=request.fetch('legacy',legacy.call(name))
    if op=='produce'
      ps=previous ? selected.call(prior) : nil;ps=request['previousStatement']=='none' ? nil : statements.fetch(request['previousStatement']) if request.key?('previousStatement')
      scalar=request.key?('scalar') ? Base64.strict_decode64(request['scalar']) : "\x00".b*31+"\x07".b
      cancel=ContactField::Cancellation.new;cancel.cancel if request['cancel']
      value=ContactMutation.produce_software(key_for.call(scalar),st,e,d.call(name).byteslice(0,304),legacy:l,previous:previous,previous_statement:ps,replacements:fs,cancelled:cancel)
      out[:bytes]=Base64.strict_encode64(value.mutation.bytes)
    else
      mutation=ContactMutation.verify(d.call(name),st,e,legacy:l);out[:mutationVerified]=true
      if op!='verify'
        value=ContactMutation.transition(previous,mutation,fs);out[:fields]={}
        %w[name notes].each_with_index{|field,i|v=value.field(i+1);out[:fields][field]=Base64.strict_encode64(v.bytes) if v}
      end
    end
    out[:accepted]=true
  rescue StandardError
    # Keep the independent mutation verification marker on transition refusal.
  end
  out
end
puts JSON.generate(results)
