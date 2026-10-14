# frozen_string_literal: true
# Test helper: only typed public producers sign contact mutations.
module MutationPackageTest
  module_function
  def run(f,outputs,parser,key)
    d=->(name){Base64.strict_decode64(f.fetch(name))};b64=->(b){Base64.strict_encode64(b)}
    pin=ZrotextCandidate::ManifestChain::RootPin.enroll(d.call('rootPin'),d.call('fingerprint'))
    m=ZrotextCandidate::ManifestChain.genesis02(d.call('manifest'),pin,10000);n=ZrotextCandidate::ManifestChain.continue_chain(d.call('nextManifest'),m,2,10000)
    statements={};[['statement',m],['nextStatement',n]].each{|name,manifest|statements[name]=ZrotextCandidate::ContactField.verify_statement(d.call(name),manifest,account:d.call('account'),origin:f['origin'],root_fingerprint:d.call('fingerprint'),parser:parser)}
    expected=ZrotextCandidate::ContactField::Expected.new(account:d.call('account'),origin:f['origin'],root_fingerprint:d.call('fingerprint'),contact:d.call('contact'),routing:d.call('routing'),parser:parser)
    fields={};encoded={};%w[name notes replacement].zip(outputs).each{|name,out|raw=Base64.strict_decode64(out[:bytes]);fields[name]=ZrotextCandidate::ContactField.verify(raw,statements[name=='replacement' ? 'nextStatement' : 'statement'],contact:d.call('contact'),routing:d.call('routing'));encoded[name]=out[:bytes]}
    mutations={};previous=ps=nil;refusals=0
    %w[create update clear converted].each do |name|
      st=statements[%w[update clear].include?(name) ? 'nextStatement' : 'statement'];s=st.identity
      previous=ps=nil if %w[create converted].include?(name)
      u=d.call(name).byteslice(0,304);u[118,32]=s[:manifest];u[150,32]=st.digest;u[70,32]=previous.mutation.digest if previous
      slots=name=='clear' ? [nil,'replacement'] : name=='update' ? ['name','replacement'] : ['name','notes']
      slots.each_with_index{|slot,i|next unless slot;field=fields[slot];u[222+i*41,41]="\x01".b+field.bytes.byteslice(38,8)+field.digest}
      replacements=name=='clear' ? [] : name=='update' ? [fields['replacement']] : [fields['name'],fields['notes']]
      args={legacy:name=='converted' ? 7 : 0,previous:previous,previous_statement:ps,replacements:replacements}
      value=ZrotextCandidate::ContactMutation.produce_protected(key,st,expected,u,**args)
      borrowed=ZrotextCandidate::ProtectedContactSigner.open(key.alias_name,key.public_point)
      begin
        begin borrowed.delete_created;raise 'borrowed deletion accepted';rescue ArgumentError;end
        borrowed.close
        begin ZrotextCandidate::ContactMutation.produce_protected(borrowed,st,expected,u,**args);raise 'closed mutation signer accepted';rescue ArgumentError;refusals+=1 end
      ensure borrowed.close end
      cancelled=ZrotextCandidate::ContactField::Cancellation.new;cancelled.cancel
      begin ZrotextCandidate::ContactMutation.produce_protected(key,st,expected,u,**args,cancelled:cancelled);raise 'cancelled mutation accepted';rescue ArgumentError;refusals+=1 end
      wrong=d.call('contact');wrong.setbyte(0,wrong.getbyte(0)^1)
      foreign=ZrotextCandidate::ContactField::Expected.new(account:d.call('account'),origin:f['origin'],root_fingerprint:d.call('fingerprint'),contact:wrong,routing:d.call('routing'),parser:parser)
      begin ZrotextCandidate::ContactMutation.produce_protected(key,st,foreign,u,**args);raise 'foreign mutation accepted';rescue ArgumentError;refusals+=1 end
      mutations[name]=b64.call(value.mutation.bytes);previous=value;ps=st
    end
    {fields:encoded,mutations:mutations,refusals:refusals}
  end
end
