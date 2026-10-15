# frozen_string_literal: true
require_relative '../template-crypto/encrypted_template'
module ZrotextCandidate
 module TemplateStore
  CONTENT_TYPE='application/vnd.zrotext.workflow-template.v1'
  module_function
  def need(b) = (raise ArgumentError,'Template contract refused' unless b)
  def number(b,at) = b.byteslice(at,8).unpack1('Q>')
  def uuid(b);s=b.unpack1('H*');[s[0,8],s[8,4],s[12,4],s[16,4],s[20,12]].join('-');end
  def parse(wire)
   need(wire.is_a?(String) && wire.bytesize.between?(308,33075) && wire.getbyte(222)==4 && wire.byteslice(287,4).unpack1('N')==wire.bytesize-291)
   EncryptedTemplate::Scope.new(wire.byteslice(0,222))
  end
  class SaveRequest
   def initialize(scope,request_id,expected_revision,envelope)
    TemplateStore.need(request_id.is_a?(String) && /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/.match?(request_id) && request_id.delete('-')!='0'*32 && expected_revision.is_a?(Integer) && expected_revision.between?(0,127))
    aad=scope.aad;TemplateStore.need(TemplateStore.number(aad,94)==expected_revision+1 && envelope.is_a?(String) && envelope.bytesize.between?(308,33075));wire=envelope.b.dup
    TemplateStore.need(wire.byteslice(0,222)==aad && wire.byteslice(287,4).unpack1('N')==wire.bytesize-291)
    @body=wire.freeze;@request=request_id.dup.freeze;@expected=expected_revision;@digest=OpenSSL::Digest::SHA256.hexdigest(wire).freeze;freeze
   end
   def body = @body.dup
   def path = '/v1/owner/workflow/templates'
   def revision = @expected+1
   def encrypted_digest = @digest
   def headers = {'content-type'=>CONTENT_TYPE,'idempotency-key'=>@request,'x-zrotext-template-revision'=>@expected.to_s}.freeze
   def receipt(wire);TemplateStore.need(wire.is_a?(String) && wire.bytesize<=256 && wire.b=='{"revision":'+revision.to_s+'}');revision;end
  end
 end
end
