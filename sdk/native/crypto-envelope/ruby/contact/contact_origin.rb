# frozen_string_literal: true
require 'fiddle'
module ZrotextCandidate
  # Host-selected trusted installed parser asset, never a URL-validation callback.
  class ContactOrigin
    def initialize(directory)
      name=if /mswin|mingw/.match?(RUBY_PLATFORM) then 'zrotext_contact_origin.dll'
           elsif /darwin/.match?(RUBY_PLATFORM) then 'libzrotext_contact_origin.dylib'
           else 'libzrotext_contact_origin.so' end
      @library=Fiddle.dlopen(File.realpath(File.join(File.realpath(directory),name)))
      @predicate=Fiddle::Function.new(@library['zrotext_contact_origin_v1'],[Fiddle::TYPE_VOIDP,Fiddle::TYPE_SIZE_T],Fiddle::TYPE_INT)
      freeze
    end
    def accepts?(value)
      value.instance_of?(String) && value.bytesize.between?(9,512) && value.bytes.all?{|b|b.between?(33,126)} && @predicate.call(value,value.bytesize)==1
    end
  end
end
