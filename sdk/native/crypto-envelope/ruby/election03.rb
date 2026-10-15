# frozen_string_literal: true
require_relative 'manifest_chain'

module ZrotextCandidate
  module Election03
    AU=%w[accountId deviceId lineId oldBindingId newBindingId].freeze
    AT=%w[vaultGeneration oldBindingGeneration newBindingGeneration priorManifestVersion acceptedManifestVersion acceptedAtMs].freeze
    AD=%w[rootFingerprint oldBindingProofDigest selectedReaderKeyId priorManifestDigest priorSignedManifestSha256 acceptedManifestDigest acceptedSignedManifestSha256 electionCoreSha256 electionCommitment electionBundleSha256].freeze
    CU=%w[accountId deviceId lineId bindingId].freeze
    CT=%w[bindingGeneration vaultGeneration manifestVersion comparedAtMs permissionExpiresAtMs].freeze
    CD=%w[selectedReaderKeyId rootFingerprint manifestDigest electionCommitment electionBundleSha256].freeze
    module_function
    def need(value) = (raise ArgumentError,'Election authority refused' unless value)
    def nonzero(value) = value.bytes.any? { |b| b!=0 }
    def sha(value) = OpenSSL::Digest::SHA256.digest(value)
    def label(value) = value.b+"\x00".b
    def framed(domain,value) = label(domain)+[value.bytesize].pack('N')+value
    def num(value,at)
      n=value.byteslice(at,8).unpack1('Q>');need(n.between?(1,2**63-1));n
    end
    def record(input,uuids,times,digests,current)
      keys=uuids+times+digests+(current ? %w[profile manifestProfile] : [])
      need(input.instance_of?(Hash) && input.keys.sort==keys.sort);out={}
      keys.each do |name|
        value=input[name]
        if times.include?(name) || %w[profile manifestProfile].include?(name)
          need(value.instance_of?(Integer) && value.between?(1,2**63-1));out[name]=value
        else
          need(value.instance_of?(String));bytes=value.b.dup;need(bytes.bytesize==(uuids.include?(name) ? 16 : 32) && nonzero(bytes));out[name]=bytes.freeze
        end
      end
      need(out['profile']==3 && out['manifestProfile']==3 && out['permissionExpiresAtMs']>out['comparedAtMs']) if current
      out.freeze
    end
    private_class_method :record
    class Proof
      attr_reader :accepted_manifest
      def initialize(accepted,manifest)
        @accepted=accepted;@accepted_manifest=manifest;freeze
      end
      private_class_method :new
      def accepted = @accepted.transform_values { |v| v.instance_of?(String) ? v.dup : v }
    end
    class Current
      def initialize(record)
        @record=record;freeze
      end
      private_class_method :new
      def field(name) = @record.fetch(name).dup
      def number(name) = @record.fetch(name)
    end
    # Core, accepted record and registry signing points require independent authentication.
    def verify(bundle_input,expected_core,accepted_record,predecessor,signed02_input,signed03_input,device_input,owner_input)
      need(bundle_input.bytesize==628 && expected_core.bytesize==500 && device_input.bytesize==65 && owner_input.bytesize==65)
      bundle=bundle_input.b.dup;core=bundle.byteslice(0,500);signed02=signed02_input.b.dup;signed03=signed03_input.b.dup;device=device_input.b.dup;owner=owner_input.b.dup
      a=record(accepted_record,AU,AT,AD,false)
      need(predecessor.instance_of?(ManifestChain::Verified) && predecessor.profile==2 && signed02==predecessor.bytes && a['acceptedAtMs']>=predecessor.comparison_ms)
      need(core==expected_core && core.byteslice(0,8)=="ZTPE\x03\x01\x02\x03".b && !nonzero(core.byteslice(496,4)) && nonzero(core.byteslice(56,16)) && nonzero(core.byteslice(352,32)))
      positions=[8,24,40,72,104,136,184,224,256];names=%w[accountId deviceId lineId oldBindingId oldBindingProofDigest rootFingerprint priorManifestDigest acceptedManifestDigest selectedReaderKeyId]
      positions.zip(names).each { |at,name| need(core.byteslice(at,a[name].bytesize)==a[name]) }
      [88,96,168,176,216].zip(%w[oldBindingGeneration newBindingGeneration vaultGeneration priorManifestVersion acceptedManifestVersion]).each { |at,name| need(num(core,at)==a[name]) }
      issued=num(core,384);expires=num(core,392)
      need(issued<=a['acceptedAtMs'] && a['acceptedAtMs']<expires && expires-issued<=300000 && a['newBindingGeneration']>a['oldBindingGeneration'] && a['vaultGeneration']==1 && a['priorManifestVersion']<2**63-1 && a['acceptedManifestVersion']==a['priorManifestVersion']+1)
      [400,432,464].each { |at| need(nonzero(core.byteslice(at,32))) }
      [signed02,signed03,core,bundle,framed('ZTSE/line/payload-profile/commitment/v1',core)].zip(%w[priorSignedManifestSha256 acceptedSignedManifestSha256 electionCoreSha256 electionBundleSha256 electionCommitment]).each { |value,name| need(sha(value)==a[name]) }
      manifest=ManifestChain.continue_chain(signed03,predecessor,3,a['acceptedAtMs'])
      need(manifest.account==a['accountId'] && manifest.version==a['acceptedManifestVersion'] && manifest.digest==a['acceptedManifestDigest'] && predecessor.version==a['priorManifestVersion'] && predecessor.digest==a['priorManifestDigest'])
      root_pin="ZTRP\x02".b+manifest.account+[1].pack('Q>')+manifest.root_point;need(sha(label('ZTSE/root-pin/v2')+root_pin)==a['rootFingerprint'])
      need(sha(label('ZTSE/key/v1')+"\x01\x01".b+device)==core.byteslice(288,32) && sha(label('ZTSE/key/v1')+"\x01\x01".b+owner)==core.byteslice(320,32))
      device_signature=bundle.byteslice(500,64)
      ManifestChain.signature(device,device_signature,'ZTSE/line/payload-profile/device/v1',core)
      ManifestChain.signature(owner,bundle.byteslice(564,64),'ZTSE/line/payload-profile/owner/v1',core+sha(device_signature))
      Proof.send(:new,a,manifest)
    end
    def require_current(proof,manifest,authenticated_current,now)
      need(proof.instance_of?(Proof) && manifest.instance_of?(ManifestChain::Verified) && now.instance_of?(Integer) && now.between?(1,2**63-1))
      a=proof.accepted;c=record(authenticated_current,CU,CT,CD,true)
      need(now>=a['acceptedAtMs'] && now>=c['comparedAtMs'] && now<c['permissionExpiresAtMs'] && now>=manifest.comparison_ms && now<manifest.expires_ms)
      %w[accountId deviceId lineId bindingId selectedReaderKeyId rootFingerprint electionCommitment electionBundleSha256].zip(%w[accountId deviceId lineId newBindingId selectedReaderKeyId rootFingerprint electionCommitment electionBundleSha256]).each { |cn,an| need(c[cn]==a[an]) }
      need(c['bindingGeneration']==a['newBindingGeneration'] && c['vaultGeneration']==1 && c['manifestVersion']>=a['acceptedManifestVersion'])
      need(manifest.profile==3 && manifest.version==c['manifestVersion'] && manifest.account==c['accountId'] && manifest.digest==c['manifestDigest'] && manifest.descends_from(proof.accepted_manifest))
      Current.send(:new,c)
    end
  end
end
