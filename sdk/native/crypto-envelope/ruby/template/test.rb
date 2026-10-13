# frozen_string_literal: true
require_relative 'template_content'
require 'base64'
include ZrotextCandidate
input=JSON.parse($stdin.read)
cases=input.fetch('cases').map do |row|
  begin
    content=TemplateContent.parse(Base64.strict_decode64(row.fetch('raw')))
    before=content.canonical;changed=content.canonical;changed.setbyte(0,0);raise 'Canonical alias' unless content.canonical==before
    values=content.values;values['x']='mutated';raise 'Values alias' if content.values==values
    preview=begin;content.preview;rescue TemplateContent::Failure;nil;end
    {accepted:true,canonical:Base64.strict_encode64(content.canonical),digest:content.digest,preview:preview}
  rescue TemplateContent::Failure
    {accepted:false}
  end
end
segments=input.fetch('segments').map do |row|
  begin
    units=row.fetch('units');raise TemplateContent::Failure unless units.all? { |v| v.is_a?(Integer) && v.between?(0,65535) }
    text=units.pack('v*').force_encoding(Encoding::UTF_16LE).encode(Encoding::UTF_8);TemplateContent.estimate(text)
  rescue TemplateContent::Failure,EncodingError;nil;end
end
$stdout.write(JSON.generate(cases:cases,segments:segments))
